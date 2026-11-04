"""Offline build evidence, separate from candidate identity and publication.

Inputs are stored once, not copied into every split Geo conflict. Fixed-width
network-order bounds and a span index support exact point/range lookups for
both address families; no floating point address index is used.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict
import datetime as dt
import functools
import gzip
import hashlib
import heapq
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import subprocess
import urllib.parse


_SECRET_KEYS = ('GITHUB_TOKEN', 'GH_TOKEN', 'RULES_PUBLISH_TOKEN', 'MAXMIND_LICENSE_KEY', 'IPINFO_TOKEN', 'IP2LOCATION_TOKEN')
_SECRET_FIELD = re.compile(r'(?i)(?:^(?:auth|authorization|proxy-authorization|cookie)$|(?:^|[_-])(?:password|passwd|secret|token|api[_-]?key|license[_-]?key)(?:$|[_-]))')
_URL = re.compile(r'https?://[^\s<>"\']+')
_CREDENTIAL = re.compile(r'(?i)(Bearer\s+|(?:token|password|license_key|secret)\s*[=:]\s*)[^\s,;]+')
_AUTHORIZATION = re.compile(r'(?i)(?:proxy-)?authorization\s*:\s*[^\r\n]*')


def clean(value, *, secrets=None):
    """Redact once per object, not an environment lookup for every nested string."""
    if secrets is None:
        secrets = tuple(v for key in _SECRET_KEYS if (v := os.environ.get(key)) and len(v) >= 4)
    def url(match):
        try:
            u = urllib.parse.urlsplit(match.group())
            return urllib.parse.urlunsplit((u.scheme, u.hostname or '', u.path, '', ''))
        except ValueError:
            return '[redacted-url]'
    def visit(item):
        if isinstance(item, dict):
            return {str(k): '[redacted]' if _SECRET_FIELD.search(str(k)) else visit(v) for k, v in item.items()}
        if isinstance(item, (list, tuple, set)):
            return [visit(v) for v in item]
        if isinstance(item, Path): return item.name
        if not isinstance(item, str): return item
        if 'http://' in item or 'https://' in item: item = _URL.sub(url, item)
        low = item.lower()
        if any(word in low for word in ('bearer', 'token', 'password', 'license_key', 'secret')):
            item = _CREDENTIAL.sub(r'\1[redacted]', item)
        if 'authorization' in low: item = _AUTHORIZATION.sub('Authorization: [redacted]', item)
        for secret in secrets: item = item.replace(secret, '[redacted]')
        return item
    return visit(value)


def json_write(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(clean(value), ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    temporary.replace(path)


def _blob(value):
    return int(value).to_bytes(16, 'big')


def span(start, end):
    return (end - start + 1).bit_length() - 1


def cidr_count(family, start, end):
    # Exact minimal CIDR count without constructing address/prefix objects.
    count = 0
    while start <= end:
        block = start & -start if start else 1 << (32 if family == 4 else 128)
        remaining = 1 << ((end - start + 1).bit_length() - 1)
        start += min(block, remaining); count += 1
    return count


def best_effort(method):
    @functools.wraps(method)
    def call(self, *args, **kwargs):
        if self.broken:
            return None
        try:
            return method(self, *args, **kwargs)
        except Exception as error:
            self.broken = True
            self.state['diagnostic_errors'].append({'operation': method.__name__, 'type': type(error).__name__})
            return None
    return call


class BuildRecord:
    """One appendable diagnostic record shared by acquisition and batch build."""
    def __init__(self, directory):
        self.directory = Path(directory); self.directory.mkdir(parents=True, exist_ok=True)
        summary = self.directory / 'summary.json'
        self.state = json.loads(summary.read_text()) if summary.exists() else {
            'schema': 1, 'started_at': dt.datetime.now(dt.timezone.utc).isoformat(),
            'status': 'started', 'publication': {'status': 'not-started'}, 'diagnostic_errors': [], 'stages': []}
        self.broken = False
        self.secrets = tuple(v for key in _SECRET_KEYS if (v := os.environ.get(key)) and len(v) >= 4)
        self.pending = defaultdict(list)
        self.pending_count = 0
        self.geo_counts = defaultdict(Counter)
        self.geo_combinations = Counter()
        self.geo_combination_intervals = Counter()
        self.geo_combination_prefixes = Counter()
        self.geo_conflict_regions = defaultdict(Counter)
        self.largest = defaultdict(list)
        self.connection = sqlite3.connect(self.directory / 'trace.sqlite3')
        self.connection.execute('PRAGMA cache_size=-8192')
        self.connection.execute('PRAGMA temp_store=FILE')
        self.connection.executescript('''
          CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT);
          CREATE TABLE IF NOT EXISTS source_event(source TEXT,stage TEXT,status TEXT,details TEXT);
          CREATE TABLE IF NOT EXISTS domain_event(id INTEGER PRIMARY KEY,product TEXT,source TEXT,kind TEXT,value TEXT,stage TEXT,status TEXT,reason TEXT,details TEXT);
          CREATE TABLE IF NOT EXISTS geo_input(id INTEGER PRIMARY KEY,family INTEGER,span INTEGER,start BLOB,end BLOB,source TEXT,lineage TEXT,country TEXT,semantics TEXT DEFAULT 'country-estimate',raw_fields TEXT);
          CREATE TABLE IF NOT EXISTS geo_issue(id INTEGER PRIMARY KEY,family INTEGER,span INTEGER,start BLOB,end BLOB,status TEXT,details TEXT);
          CREATE TABLE IF NOT EXISTS route_input(id INTEGER PRIMARY KEY,family INTEGER,span INTEGER,start BLOB,end BLOB,source TEXT,status TEXT,observed INTEGER,origin_prefix_length INTEGER,details TEXT);
          CREATE TABLE IF NOT EXISTS route_origin(asn INTEGER,input_id INTEGER);
          CREATE TABLE IF NOT EXISTS product(name TEXT PRIMARY KEY,details TEXT);
          CREATE TABLE IF NOT EXISTS output_domain(product TEXT,kind TEXT,value TEXT);
          CREATE TABLE IF NOT EXISTS output_ip(product TEXT,family INTEGER,span INTEGER,start BLOB,end BLOB);
          CREATE TABLE IF NOT EXISTS geo_change(id INTEGER PRIMARY KEY,family INTEGER,span INTEGER,start BLOB,end BLOB,before TEXT,after TEXT,status TEXT);
          CREATE TABLE IF NOT EXISTS domain_change(product TEXT,predicate TEXT,status TEXT,covering_predicate TEXT);
          CREATE TABLE IF NOT EXISTS domain_ip_event(event_id INTEGER PRIMARY KEY,family INTEGER,span INTEGER,start BLOB,end BLOB);
        ''')
        if 'semantics' not in {r[1] for r in self.connection.execute('PRAGMA table_info(geo_input)')}:
            self.connection.execute("ALTER TABLE geo_input ADD COLUMN semantics TEXT DEFAULT 'country-estimate'")
        if 'raw_fields' not in {r[1] for r in self.connection.execute('PRAGMA table_info(geo_input)')}:
            self.connection.execute('ALTER TABLE geo_input ADD COLUMN raw_fields TEXT')
        if 'details' not in {r[1] for r in self.connection.execute('PRAGMA table_info(geo_issue)')}:
            self.connection.execute('ALTER TABLE geo_issue ADD COLUMN details TEXT')
        if 'origin_prefix_length' not in {r[1] for r in self.connection.execute('PRAGMA table_info(route_input)')}:
            self.connection.execute('ALTER TABLE route_input ADD COLUMN origin_prefix_length INTEGER')
        self.next_route = self.connection.execute('SELECT COALESCE(MAX(id),0) FROM route_input').fetchone()[0]
        self.state['python'] = platform.python_version()

    def _add(self, table, row):
        self.pending[table].append(row); self.pending_count += 1
        if self.pending_count >= 4096:
            self.flush()

    @best_effort
    def flush(self):
        for table, rows in self.pending.items():
            if rows:
                columns = {'route_input':'id,family,span,start,end,source,status,observed,origin_prefix_length,details',
                           'domain_event': 'product,source,kind,value,stage,status,reason,details',
                           'geo_input': 'family,span,start,end,source,lineage,country,semantics,raw_fields',
                           'geo_issue': 'family,span,start,end,status,details',
                           'geo_change': 'family,span,start,end,before,after,status'}.get(table)
                target = table + (f'({columns})' if columns else '')
                self.connection.executemany(f'INSERT INTO {target} VALUES({",".join("?" for _ in rows[0])})', rows)
                rows.clear()
        self.connection.commit(); self.pending_count = 0

    @best_effort
    def metadata(self, key, value):
        self.connection.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)', (key, json.dumps(clean(value), sort_keys=True)))

    @best_effort
    def inputs(self, snapshot, config_dir=None):
        sources = [{k: v for k, v in source.items() if k not in {'auth'}} for source in snapshot.get('sources', [])]
        self.state['sources'] = clean(sources)
        self.state['snapshot_time'] = snapshot.get('created_at')
        self.metadata('sources', sources)
        if config_dir:
            configuration = []
            for path in sorted(Path(config_dir).glob('*.json')):
                raw = path.read_bytes()
                configuration.append({'file': path.name, 'sha256': hashlib.sha256(raw).hexdigest()})
                value = json.loads(raw)
                json_write(self.directory / 'effective-config' / path.name, value)
                self.metadata(path.name, value)
            self.state['configuration'] = configuration
        repo = Path(__file__).resolve().parents[1]
        def git(*args):
            return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.DEVNULL)
        try:
            self.state['source_commit'] = git('rev-parse', 'HEAD').decode().strip()
            diff = git('diff', '--binary', 'HEAD')
            self.state['source_dirty'] = bool(diff)
            self.state['source_diff_sha256'] = hashlib.sha256(diff).hexdigest()
        except (OSError, subprocess.CalledProcessError):
            self.state['source_commit'] = 'unavailable'
        # Bind actual Python bytes too, including untracked implementation files.
        self.state['implementation'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                        for p in sorted(Path(__file__).parent.glob('*.py'))}
        self.save()

    @best_effort
    def stage(self, name, status, **details):
        if status == 'started' and name in {'snapshot', 'build', 'build-domains', 'publish'}:
            self.state['status'] = 'running'
            self.state.pop('finished_at', None)
        self.state['stages'].append(clean({'name': name, 'status': status, 'at': dt.datetime.now(dt.timezone.utc).isoformat(), **details}))
        self.state['current_stage'] = name
        self.save()

    @best_effort
    def source_event(self, source_id, stage, status, **stats):
        self._add('source_event', (source_id, stage, status, json.dumps(clean(stats, secrets=self.secrets), sort_keys=True)))

    @best_effort
    def domain_event(self, item):
        item = clean(item, secrets=self.secrets)
        predicate = item.get('predicate', item.get('rule', ''))
        kind, _, value = predicate.partition(',')

        self._add('domain_event', (item.get('group'), item.get('source'), kind, value,
                  item.get('stage'), item.get('status'), item.get('reason'), json.dumps(item, sort_keys=True)))

    @best_effort
    def geo_input(self, rec):
        raw = getattr(rec,'raw_fields',None)
        self._add('geo_input', (rec.version, span(rec.start, rec.end), _blob(rec.start), _blob(rec.end), rec.source, rec.lineage, rec.country, rec.semantics,
                               json.dumps(clean(raw,secrets=self.secrets),sort_keys=True) if raw is not None else None))

    @best_effort
    def geo_decision(self, detail):
        family = detail['family']; state = detail['status']
        a = detail.get('start_int'); b = detail.get('end_int')
        if a is None: a = int(ipaddress.ip_address(detail['start']))
        if b is None: b = int(ipaddress.ip_address(detail['end']))
        size = b - a + 1
        counts = self.geo_counts[str(family)]
        counts[state + '_intervals'] += 1; counts[state + '_addresses'] += size
        assigned = detail.get('region_id') is not None
        dissent = detail.get('region_disagreement', False) or detail.get('country_disagreement', False)
        if assigned and not dissent: return
        decision = {key: detail.get(key) for key in ('selected_source', 'selected_country', 'region_id', 'source_order',
                    'country_disagreement', 'region_disagreement')}
        decision['assigned'] = assigned
        self._add('geo_issue', (family, span(a, b), _blob(a), _blob(b), state,
                               json.dumps(clean(decision,secrets=self.secrets),sort_keys=True)))
        if detail.get('region_disagreement') or state == 'conflicting-regions':
            # Region-combination summary is bounded; the index remains lossless.
            signature = '|'.join(s + ':' + ','.join(str(x) for x in v)
                                 for s, v in sorted(detail.get('source_regions', {}).items()))
            key = (family, signature)
            if key not in self.geo_combinations and len(self.geo_combinations) >= 2048:
                key = (family, '[other combinations; query complete index]')
            self.geo_combinations[key] += size
            self.geo_combination_intervals[key] += 1
            prefix_count = cidr_count(family,a,b)
            self.geo_combination_prefixes[key] += prefix_count
            for region in {region for regions in detail.get('source_regions', {}).values() for region in regions}:
                stats = self.geo_conflict_regions[f'ipv{family}/region-{region}']
                stats['addresses'] += size;stats['decision_intervals'] += 1;stats['interval_cidr_sum'] += prefix_count
        item = (size, family, a, b, state)
        samples = self.largest[(family, state)]
        if len(samples) < 12: heapq.heappush(samples, item)
        elif item > samples[0]: heapq.heapreplace(samples, item)
        for country in ('CN','RU'):
            if any(country in values for values in detail.get('sources', {}).values()):
                focus = self.largest[(family, state, country)]
                if len(focus)<6:heapq.heappush(focus,item)
                elif item>focus[0]:heapq.heapreplace(focus,item)

    @best_effort
    def route_input(self, rec, status, reason):
        self.next_route += 1; identifier = self.next_route
        info = asdict(rec); info['reason'] = reason
        observed = getattr(rec, 'origin_prefix_length', None) is not None
        self._add('route_input', (identifier, rec.version, span(rec.start, rec.end), _blob(rec.start), _blob(rec.end),
                  rec.source, status, int(observed), getattr(rec,'origin_prefix_length',None), json.dumps(clean(info,secrets=self.secrets), sort_keys=True)))
        for asn in getattr(rec, 'asns', ()): self._add('route_origin', (asn, identifier))

    @best_effort
    def route_outputs(self, groups):
        for asn, prefixes in groups.items():
            for text in prefixes: self.output_ip('asn/' + str(asn), text)

    @best_effort
    def retained_asn(self, path, base_version):
        from .ardb import read_database
        self.stage('retained-asn-index','started',base_version=base_version,meaning='Index existing binary outputs; no new source parsing or BGP observation')
        self.route_outputs(read_database(path,'asn'))
        self.stage('retained-asn-index','completed',base_version=base_version)

    @best_effort
    def geo_change(self, family, start, end, before, after, status):
        self._add('geo_change', (family, span(start, end), _blob(start), _blob(end), before, after, status))

    @best_effort
    def domain_change(self, product, predicate, status, covering_predicate=None):
        self._add('domain_change', (product, predicate, status, covering_predicate))

    def output_ip(self, product, text):
        net = ipaddress.ip_network(text)
        a, b = int(net.network_address), int(net.broadcast_address)
        self._add('output_ip', (product, net.version, span(a, b), _blob(a), _blob(b)))

    @best_effort
    def product_outputs(self, groups, catalogue):
        from .domains import parse_rule_line
        for name, lines in groups.items():
            self.connection.execute('INSERT OR REPLACE INTO product VALUES(?,?)', (name, json.dumps(clean(catalogue.get(name, {})), sort_keys=True)))
            for line in lines:
                rule = parse_rule_line(line)
                if rule.kind in {'IP-CIDR', 'IP-CIDR6'}: self.output_ip(name, rule.value)
                else: self._add('output_domain', (name, rule.kind, rule.value))

    @best_effort
    def manifest(self, manifest, baseline=None):
        self.state['candidate'] = {k: manifest.get(k) for k in ('data_version', 'summary', 'product_coverage', 'product_catalogue', 'generation_context')}
        if baseline and (Path(baseline) / 'manifest.json').exists():
            old = json.loads((Path(baseline) / 'manifest.json').read_text())
            self.state['comparison_baseline'] = {k: old.get(k) for k in ('data_version', 'publication', 'summary')}
            self.state['comparison_baseline']['publication_recorded'] = bool(old.get('publication'))
            if old.get('publication'):self.state['previous_published'] = self.state['comparison_baseline']
        self.save()

    def finish(self, status, **details):
        self.state.update(clean({'status': status, 'finished_at': dt.datetime.now(dt.timezone.utc).isoformat(), **details}))
        if self.state.get('implementation'):
            final = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(__file__).parent.glob('*.py'))}
            self.state['implementation_changed_during_run'] = final != self.state['implementation']
            if self.state['implementation_changed_during_run']: self.state['implementation_at_finish'] = final
        self._finish_index()
        if self.state['diagnostic_errors']: self.state['evidence_complete'] = False
        self.save()

    @best_effort
    def _finish_index(self):
        self.flush()
        if self.geo_counts: self.state['geo_decisions'] = {k: dict(v) for k, v in self.geo_counts.items()}
        if self.geo_combinations: self.state['geo_source_region_combinations'] = [{'family': k[0], 'combination': k[1], 'addresses': n,
            'decision_intervals': self.geo_combination_intervals[k], 'interval_cidr_sum': self.geo_combination_prefixes[k]}
                                                       for k, n in self.geo_combinations.most_common()]
        if self.geo_conflict_regions:
            self.state['conflict_claimant_regions_nonadditive'] = {k:dict(v) for k,v in self.geo_conflict_regions.items()}
            self.state['conflict_region_note'] = 'A conflict may involve several claimed regions. These overlap; do not sum as distinct output coverage.'
        if self.largest: self.state['largest_conflict_or_unknown_ranges_sample'] = [{'family': f, 'start': str((ipaddress.IPv4Address if f == 4 else ipaddress.IPv6Address)(a)),
            'end': str((ipaddress.IPv4Address if f == 4 else ipaddress.IPv6Address)(b)), 'status': state,
            'addresses': n, 'cidr_count': cidr_count(f, a, b)} for bucket in self.largest.values()
            for n, f, a, b, state in sorted(bucket, reverse=True)]
        self.state['source_processing'] = [{'source': s, 'stage': stage, 'status': status, **json.loads(data)}
            for s, stage, status, data in self.connection.execute('SELECT source,stage,status,details FROM source_event')]
        for identifier, text in self.connection.execute("SELECT id,value FROM domain_event WHERE kind IN ('IP-CIDR','IP-CIDR6') AND id NOT IN (SELECT event_id FROM domain_ip_event)"):
            try:
                net = ipaddress.ip_network(text, strict=True)
            except ValueError:
                continue
            a,b = int(net.network_address),int(net.broadcast_address)
            self.connection.execute('INSERT INTO domain_ip_event VALUES(?,?,?,?,?)',(identifier,net.version,span(a,b),_blob(a),_blob(b)))
        for table in ('geo_input', 'geo_issue', 'route_input', 'output_ip', 'geo_change', 'domain_ip_event'):
            self.connection.execute(f'CREATE INDEX IF NOT EXISTS {table}_lookup ON {table}(family,span,start)')
        self.connection.executescript('''
          CREATE INDEX IF NOT EXISTS domain_lookup ON domain_event(kind,value);
          CREATE INDEX IF NOT EXISTS domain_product ON domain_event(product);
          CREATE INDEX IF NOT EXISTS domain_source ON domain_event(source);
          CREATE INDEX IF NOT EXISTS final_domain ON output_domain(kind,value);
          CREATE INDEX IF NOT EXISTS final_product ON output_ip(product);
          CREATE INDEX IF NOT EXISTS route_asn ON route_origin(asn);
          CREATE INDEX IF NOT EXISTS domain_change_product ON domain_change(product);
        ''')
        self.connection.commit()
        self.bgp_summary()

    @best_effort
    def bgp_summary(self):
        """Association with actual non-default BGP observations, never ASN ownership or location proof."""
        context = self.state.get('candidate', {}).get('generation_context') or {}
        if context.get('mode')=='domains-only':
            self.state['bgp']={'applicable':False,'scope':'Retained regional IP lists and ASN database; BGP observations were not recomputed in this domain-only refresh.',
                               'retained_ip_base':context.get('retained_ip_base')}
            return
        from bisect import bisect_left
        union = {4: [], 6: []}
        for family, a, b in self.connection.execute("SELECT family,start,end FROM route_input WHERE observed=1 AND origin_prefix_length>0 ORDER BY family,start"):
            a, b = int.from_bytes(a, 'big'), int.from_bytes(b, 'big')
            rows = union[family]
            if rows and a <= rows[-1][1] + 1: rows[-1] = (rows[-1][0], max(rows[-1][1], b))
            else: rows.append((a, b))
        ends = {f: [b for a, b in rows] for f, rows in union.items()}
        def overlap(family, a, b):
            index = bisect_left(ends[family], a); size = 0
            while index < len(union[family]) and union[family][index][0] <= b:
                x, y = union[family][index]; size += min(b, y) - max(a, x) + 1; index += 1
            return size
        regions, issues = defaultdict(Counter), defaultdict(Counter)
        for product, family, a, b in self.connection.execute("SELECT product,family,start,end FROM output_ip WHERE product LIKE 'region/%'"):
            a, b = int.from_bytes(a, 'big'), int.from_bytes(b, 'big'); n = overlap(family, a, b)
            bucket = regions[product + '/ipv' + str(family)]
            bucket['prefixes'] += 1; bucket['addresses'] += b - a + 1
            bucket['intersects_observed_bgp_prefixes'] += int(n > 0)
            bucket['observed_bgp_addresses'] += n; bucket['not_observed_bgp_addresses'] += b - a + 1 - n
        for family, a, b, status in self.connection.execute('SELECT family,start,end,status FROM geo_issue'):
            a, b = int.from_bytes(a, 'big'), int.from_bytes(b, 'big'); n = overlap(family, a, b)
            bucket = issues['ipv' + str(family) + '/' + status]
            bucket['decision_intervals'] += 1; bucket['interval_cidr_sum'] += cidr_count(family, a, b)
            bucket['addresses'] += b - a + 1; bucket['observed_bgp_addresses'] += n
            bucket['not_observed_bgp_addresses'] += b - a + 1 - n
        for sample in self.state.get('largest_conflict_or_unknown_ranges_sample', []):
            sample['observed_bgp_addresses'] = overlap(sample['family'], int(ipaddress.ip_address(sample['start'])), int(ipaddress.ip_address(sample['end'])))
        # Bounded examples are enriched from the same exact input index used by
        # explain, without duplicating every source range in millions of issues.
        from .explain import ranges
        previous_factory = self.connection.row_factory
        try:
            self.connection.row_factory = sqlite3.Row
            row = self.connection.execute("SELECT value FROM metadata WHERE key='regions.json'").fetchone()
            registry = json.loads(row[0]) if row else {'regions': []}
            mapping = {cc: r['key'] for r in registry['regions'] for cc in r['countries']}
            for sample in self.state.get('largest_conflict_or_unknown_ranges_sample', []):
                point = int(ipaddress.ip_address(sample['start']))
                evidence = ranges(self.connection,'geo_input',sample['family'],point,point,limit=20)
                for item in evidence['records']:item['normalized_region']=mapping.get(item.get('country'))
                sample['source_values_at_start'] = evidence
                sample['scope'] = 'Representative input at interval start; use complete index for other points. Not a physical-location verification.'
        finally:self.connection.row_factory = previous_factory
        default_rows = {str(f): n for f,n in self.connection.execute('SELECT family,COUNT(*) FROM route_input WHERE observed=1 AND origin_prefix_length=0 GROUP BY family')}
        self.state['bgp'] = {'scope': 'Original non-default prefix observations in this fixed snapshot, including special-ASN observations; derived IPtoASN and forwarding defaults are excluded from the association mask. Broad non-default observations are preserved, not assertions of exclusive ASN ownership. No observed route is not proof of no global announcement or no reachability. BGP is not location truth.',
                            'default_forwarding_observations':default_rows,
                            'regions': {k: dict(v) for k, v in regions.items()}, 'issues': {k: dict(v) for k, v in issues.items()},
                            'observed_union_prefixes': {str(f): len(v) for f, v in union.items()},
                            'interval_cidr_sum_note': 'Sum of exact CIDRs per decision interval, not deduplicated global route or output prefix count.'}

    def save(self):
        json_write(self.directory / 'summary.json', self.state)
        lines = ['# AirRoute 构建记录', '', f"状态：{self.state['status']}",
                 f"源码：{self.state.get('source_commit', '尚未记录')}（含本地修改：{self.state.get('source_dirty', False)}）",
                 f"开始：{self.state.get('started_at')}；结束：{self.state.get('finished_at', '未结束')}",
                 f"候选：{self.state.get('candidate', {}).get('data_version', '未生成')}；发布：{self.state.get('publication', {}).get('status')}",
                 '', '## 数据源', '', '| 来源 | 获取状态 | 版本 |', '|---|---|---|']
        for s in self.state.get('sources', []): lines.append(f"| {s['id']} | {s.get('status')} | {s.get('version', '—')} |")
        lines += ['', '解析统计见 summary.json 的 source_processing（物理行、展开选择器、MRT peer 声明分开计数，不可相加）。']
        issues = [s for s in self.state.get('source_processing', []) if s['status'] in {'empty', 'failed', 'download-failed', 'missing-credentials', 'missing-configuration'}]
        if issues:
            lines += ['', '## 来源异常', ''] + [f"- {s['source']} / {s['stage']}: {s['status']}" for s in issues[:40]]
        candidate = self.state.get('candidate', {})
        if candidate:
            summary = candidate.get('summary') or {}
            lines += ['', '## 候选结果', '', '```json', json.dumps(summary, ensure_ascii=False, sort_keys=True), '```',
                      '', '| 集合 | 域名规则 | IPv4 CIDR | IPv6 CIDR |', '|---|---:|---:|---:|']
            for key in ('region/cn-ip','region/cn-domain','region/ru','region/europe','special/lan','special/realip','category/ai'):
                profile = (candidate.get('product_coverage') or {}).get(key)
                if profile:
                    lines.append(f"| {key} | {profile.get('domain_predicates',0)} | {profile.get('ipv4_cidrs',0)} | {profile.get('ipv6_cidrs',0)} |")
        lines += ['', '## 阶段', ''] + [f"- {s['name']}: {s['status']}" for s in self.state.get('stages', [])]
        if self.state.get('error'): lines += ['', '错误：' + str(self.state['error'])]
        if self.state.get('implementation_changed_during_run'):
            lines += ['', '注意：本地执行期间实现文件发生过变化；请对照 summary.json 中开始/结束的文件摘要。本次本地记录不能冒充不可变源码的 CI 验收。']
        comparison = self.directory / 'comparison.json'
        if comparison.exists():
            value = json.loads(comparison.read_text())
            label = '含发布元数据的基线' if value.get('baseline', {}).get('publication_recorded') else '未核实发布状态的比较基线'
            lines += ['', '## 与基线比较', '',
                      f"{label}：{value.get('baseline', {}).get('data_version')}；本次候选：{value.get('candidate', {}).get('data_version')}。",
                      '详见 comparison.json；规则行减少不等于语义覆盖减少。']
            for name, diff in value.get('semantic_products', {}).get('products', {}).items():
                removed = diff.get('old_domain_predicates_not_fully_retained', 0)
                changes = diff.get('ip_changes', {})
                if removed or any(changes.get(f'ipv{f}', {}).get('removed_addresses', 0) for f in (4,6)):
                    if len(lines) < 130:
                        lines.append(f"- {name}: 未完整保留的旧域名谓词 {removed}；IP 地址变化见比较明细。")
        lines += ['', '完整冲突/未知区间及规则处理记录见 trace.sqlite3；样本不代表全部证据。',
                  'comparison.json 区分候选与此前已发布产物。地域 .list 与 special/asn.ardb 的最终结果不受诊断影响。',
                  '原始下载归档不保留；位置、路由和服务归属是不同事实。']
        lines += ['旧 auxiliary 报告中的 bgp-visible 是混合 ASN 并集；summary.bgp 才是本次原始 BGP 宣告关联，且不能证明物理地域。']
        if self.state['diagnostic_errors']: lines += ['', '诊断不完整：' + json.dumps(self.state['diagnostic_errors'])]
        (self.directory / 'overview.md').write_text('\n'.join(lines) + '\n')

    def close(self):
        self.flush()
        try: self.save()
        finally: self.connection.close()


def set_status(directory, status, reason='', workflow_status=None, preserve_publication=False):
    existing = (Path(directory) / 'summary.json').exists()
    record = BuildRecord(directory)
    try:
        interrupted = False
        if not existing:
            record.state['status'] = 'not-started'
            record.state['finished_at'] = dt.datetime.now(dt.timezone.utc).isoformat()
        if workflow_status:
            record.state['workflow_status'] = workflow_status
            if record.state['status'] == 'running' and workflow_status in {'failure','cancelled','skipped'}:
                record.state['status'] = 'interrupted'
                record.state['finished_at'] = dt.datetime.now(dt.timezone.utc).isoformat()
                interrupted = True
            if record.state['status'] in {'acquisition-success','acquisition-failed'}:
                record.state['generation_status'] = 'not-started'
        if not preserve_publication:
            record.state['publication'] = {'status': status, 'reason': clean(reason)}
        else:
            record.state['publication']['workflow_reason'] = clean(reason)
            if interrupted and any(s['name']=='publish' for s in record.state['stages']):
                record.state['publication']['status'] = 'unconfirmed'
                record.state['publication']['recovery'] = 'preserve the exact pending journal; interrupted send is not proof of success or failure'
            elif record.state['publication'].get('status') == 'not-started':
                record.state['publication']['status'] = status
        if interrupted:
            record.finish('interrupted', evidence_complete=False)
        record.save()
    finally: record.close()


def pack(directory, output, max_bytes=512 * 1024 * 1024):
    """Keep reports and lossless SQLite gzip within a documented artifact budget."""
    directory, output = Path(directory), Path(output)
    if output.resolve().is_relative_to(directory.resolve()):
        raise ValueError('diagnostic output must be outside the record directory')
    if output.exists() and any(output.iterdir()):
        raise ValueError('diagnostic package directory must be empty')
    output.mkdir(parents=True, exist_ok=True)
    index = {'schema': 1, 'budget_bytes': max_bytes, 'included': [], 'excluded': [], 'complete': True}
    summary = directory / 'summary.json'
    if summary.exists():
        state = json.loads(summary.read_text())
        index['build_status'] = state.get('status')
        index['evidence_complete'] = state.get('evidence_complete', False)
    total = 0
    for path in sorted(directory.rglob('*'), key=lambda p: (p.name not in {'summary.json', 'overview.md'}, p.as_posix())):
        if not path.is_file() or path.is_symlink(): continue
        relative = path.relative_to(directory)
        if path.suffix not in {'.json', '.md', '.sqlite3', '.gz'}: continue
        compress = path.suffix == '.sqlite3' or (path.name != 'summary.json' and path.stat().st_size > 1024 * 1024)
        target = output / (str(relative) + ('.gz' if compress else ''))
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.name.endswith('.gz'):
            with path.open('rb') as src, target.open('wb') as dst:
                with gzip.GzipFile(fileobj=dst, mode='wb', compresslevel=6, mtime=0) as z: shutil.copyfileobj(src, z, 1024 * 1024)
        else: shutil.copyfile(path, target)
        size = target.stat().st_size
        if total + size > max_bytes:
            target.unlink(); index['excluded'].append({'path': str(relative), 'reason': 'artifact-budget-exceeded', 'original_bytes': path.stat().st_size})
            index['complete'] = False; continue
        total += size
        with target.open('rb') as stream: digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        index['included'].append({'path': target.relative_to(output).as_posix(), 'bytes': size, 'sha256': digest})
    index['bytes'] = total
    json_write(output / 'artifact-index.json', index)
    return index


def open_record(directory, command=None):
    """A diagnostic failure must not replace the original operation's result."""
    try:
        record = BuildRecord(directory)
        if command in {'build','build-domains','snapshot'} and any(s['name'] in {'build','build-domains'} for s in record.state.get('stages', [])):
            record.close()
            raise ValueError('a record directory may contain only one generation; use a fresh directory')
        return record
    except Exception:
        import sys
        print('warning: build diagnostic directory could not be initialized', file=sys.stderr)
        return None


def collect(record, candidate, baseline=None):
    """Collect already-produced reports and compare even a rejected candidate."""
    if record is None: return
    candidate = Path(candidate)
    try:
        for path in (candidate / 'reports').glob('*.json'):
            # Only preexisting summary reports. Full conflict JSONL is indexed
            # losslessly in trace.sqlite3, not duplicated in this artifact.
            value = json.loads(path.read_text())
            json_write(record.directory / 'reports' / path.name, value)
        manifest = candidate / 'manifest.json'
        if manifest.exists():
            value = json.loads(manifest.read_text()); record.manifest(value, baseline)
            json_write(record.directory / 'candidate-manifest.json', value)
        if baseline and manifest.exists() and (Path(baseline) / 'manifest.json').exists():
            from .record_compare import compare_build
            json_write(record.directory / 'comparison.json', compare_build(candidate, Path(baseline), trace=record))
    except Exception as error:
        record.state['diagnostic_errors'].append({'operation': 'collect-or-compare', 'type': type(error).__name__})
