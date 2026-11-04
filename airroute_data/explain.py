"""Read-only, bounded queries over one build's diagnostic index."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import sqlite3

from .domains import domain_match, normalize_rule
from .record import _blob


def ranges(connection, table, family, start, end, limit=100, offset=0, product_prefix=None, source_scope=None):
    allowed = {'geo_input', 'geo_issue', 'route_input', 'output_ip', 'geo_change', 'domain_ip_event'}
    if table not in allowed: raise ValueError('invalid trace table')
    if source_scope not in (None,'formal','comparison') or source_scope is not None and table!='route_input':
        raise ValueError('invalid input provenance scope')
    if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is None:
        return {'records': [], 'has_more': False, 'next_offset': None}
    found = []; skip = offset
    for size in range((32 if family == 4 else 128) + 1):
        # For this span class, length < 2**(size+1). This lower bound avoids
        # scanning every interval that starts before a high IPv6 address.
        lower = max(0, start - (1 << (size + 1)) + 2)
        extra = ' AND product LIKE ?' if product_prefix is not None else ''
        if source_scope is not None: extra += " AND status" + ("=" if source_scope=='formal' else "!=") + "'formal-input'"
        params = (family, size, _blob(lower), _blob(end), _blob(start))
        if product_prefix is not None: params += (product_prefix + '%',)
        rows = connection.execute(f'SELECT rowid AS record_id,* FROM {table} WHERE family=? AND span=? AND start>=? AND start<=? AND end>=?{extra} ORDER BY start,rowid LIMIT ?',
            (*params, skip + limit + 1))
        for row in rows:
            if skip: skip -= 1; continue
            record = dict(row)
            kind = ipaddress.IPv4Address if family == 4 else ipaddress.IPv6Address
            for key in ('start', 'end'):
                record[key] = str(kind(int.from_bytes(record[key], 'big')))
            if record.get('details'): record['details'] = json.loads(record['details'])
            if table=='geo_input':
                record['original_fields_recorded'] = record.get('raw_fields') is not None
                if record.get('raw_fields'):record['raw_fields'] = json.loads(record['raw_fields'])
            found.append(record)
            if len(found) > limit:
                return {'records': found[:limit], 'has_more': True, 'next_offset': offset + limit}
    return {'records': found, 'has_more': False, 'next_offset': None}


def _metadata(connection, key, default):
    row = connection.execute('SELECT value FROM metadata WHERE key=?', (key,)).fetchone()
    return json.loads(row[0]) if row else default


def _page(rows, limit, offset):
    rows = list(rows)
    return {'records': rows[offset:offset+limit], 'has_more': len(rows) > offset+limit,
            'next_offset': offset+limit if len(rows) > offset+limit else None}


def explain(directory, *, domain=None, ip=None, asn=None, product=None, limit=100, offset=0):
    if sum(x is not None for x in (domain, ip, asn, product)) != 1:
        raise ValueError('choose exactly one domain, IP/prefix, ASN or product')
    if not 1 <= limit <= 1000 or offset < 0: raise ValueError('limit must be 1..1000 and offset nonnegative')
    root = Path(directory)
    # Explicit decompression by user avoids silently expanding a large artifact.
    connection = sqlite3.connect((root / 'trace.sqlite3').resolve().as_uri() + '?mode=ro', uri=True)
    connection.row_factory = sqlite3.Row
    try:
        summary = json.loads((root / 'summary.json').read_text())
        generation_context = summary.get('candidate', {}).get('generation_context') or {}
        result = {'build_status': summary['status'], 'candidate_version': summary.get('candidate', {}).get('data_version'),
                  'publication': summary.get('publication'), 'diagnostic_errors': summary.get('diagnostic_errors'),
                  'pagination': 'Each section is separately bounded; has_more is not a total count. Repeat with next_offset.',
                  'raw_archive_boundary': 'Original downloaded archives are not in this record. Successful rows retain semantic values and source references, not verbatim input bytes.'}
        result['generation_context'] = generation_context
        if ip is not None:
            network = ipaddress.ip_network(ip, strict=False)
            a, b = int(network.network_address), int(network.broadcast_address)
            result['query'] = str(network)
            for table in ('geo_input', 'geo_issue', 'route_input', 'output_ip', 'geo_change'):
                result[table] = ranges(connection, table, network.version, a, b, limit, offset)
            refs = ranges(connection, 'domain_ip_event', network.version, a, b, limit, offset)
            refs['records'] = [json.loads(connection.execute('SELECT details FROM domain_event WHERE id=?',(r['event_id'],)).fetchone()[0]) for r in refs['records']]
            result['rule_events'] = refs
            registry = _metadata(connection, 'regions.json', {'regions': []})
            mapping = {cc: r['key'] for r in registry['regions'] for cc in r['countries']}
            records = result['geo_input']['records']
            policy = _metadata(connection,'geo-policy.json',{})
            comparison_only = policy.get('comparison_only_address_families',{})
            for row in records:
                row['normalized_region'] = mapping.get(row.get('country'))
                row['comparison_only_for_family'] = network.version in comparison_only.get(row['source'],())
            eligibility = None
            eligibility_report = _metadata(connection,'address-eligibility',None)
            if eligibility_report is not None:
                from .address_space import AddressEligibility
                eligibility = AddressEligibility.from_report(eligibility_report)
            if a == b:
                if eligibility is not None: result['address_eligibility'] = eligibility.explain(network.version,a)
                # A bounded ASN/output page must never change the point's Geo
                # decision; query the disjoint regional/unknown records alone.
                regions = [r['product'] for r in ranges(connection,'output_ip',network.version,a,b,limit=2,product_prefix='region/')['records']]
                unknown = ranges(connection,'geo_issue',network.version,a,b,limit=2)['records']
                result['recorded_geo_decision'] = {'regions': regions, 'unknown_reasons': sorted({r['status'] for r in unknown if not (r.get('details') or {}).get('assigned')}),
                    'recorded_conflicts': [r for r in unknown if (r.get('details') or {}).get('assigned')],
                    'scope': 'recorded' if regions or unknown else
                             'excluded-by-frozen-IANA-geo-policy' if eligibility is not None and not result['address_eligibility']['geo_eligible'] else
                             'no-decision-recorded-or-incomplete-build'}
            if a == b and not result['geo_input']['has_more'] and offset == 0:
                selected = []
                for row in records:
                    left, right = int(ipaddress.ip_address(row['start'])), int(ipaddress.ip_address(row['end']))
                    superseded = any(other['source'] == row['source'] and
                        int(ipaddress.ip_address(other['start'])) >= left and int(ipaddress.ip_address(other['end'])) <= right and
                        (other['start'], other['end']) != (row['start'], row['end']) for other in records)
                    row['superseded_by_own_source_more_specific'] = superseded
                    row['ignored_non_location_evidence'] = row.get('semantics','country-estimate') != 'country-estimate'
                    if not superseded and not row['ignored_non_location_evidence']: selected.append(row)
                result['selected_source_records'] = selected
                order = policy.get('source_order', [])
                countries_by_source = {}
                for row in selected:
                    if row.get('country'):
                        countries_by_source.setdefault(row['source'],set()).add(row['country'])
                by_source = {sid:{mapping[country] for country in countries if country in mapping} for sid,countries in countries_by_source.items()}
                chosen = next((sid for sid in order if network.version not in comparison_only.get(sid,()) and
                    len(by_source.get(sid,()))==1 and all(country in mapping for country in countries_by_source[sid])),None)
                geo_eligible = result.get('address_eligibility',{}).get('geo_eligible')
                if geo_eligible is False: chosen=None
                result['source_selection'] = {'configured_order': order, 'comparison_only_sources':[sid for sid,families in comparison_only.items() if network.version in families], 'selected_source': chosen,
                    'selected_region': next(iter(by_source[chosen])) if chosen else None,
                    'geo_eligible':geo_eligible,
                    'per_source_countries':{sid:sorted(countries) for sid,countries in countries_by_source.items()},
                    'policy': 'fixed-primary-then-gap-fill; other-source dissent is retained, not a veto',
                    'complete': not result['geo_input']['has_more'],
                    'note': 'Selected from normalized current-source ranges at this point; same-source ambiguous overlapping regions are skipped, not arbitrarily resolved.'}
            if a == b and generation_context.get('mode') != 'domains-only':
                # Formal provider selection is independent from BGP comparisons,
                # and more-specific unknown/special values still shadow parents.
                formal = ranges(connection,'route_input',network.version,a,b,limit=1000,source_scope='formal')
                candidates = formal['records']; chosen = []
                if candidates:
                    width = min(row['details']['end']-row['details']['start'] for row in candidates)
                    chosen = [row for row in candidates if row['details']['end']-row['details']['start']==width]
                def origins(row):
                    info=row['details']
                    return info.get('compiled_asns') if info.get('compiled_asns') is not None else info['asns']
                formal_origins = sorted({number for row in chosen for number in origins(row)})
                eligible = result.get('address_eligibility',{}).get('asn_eligible')
                if eligible is False: formal_origins=[]
                stored = ranges(connection,'output_ip',network.version,a,b,limit=1000,product_prefix='asn/')
                result['asn_point_selection'] = {
                    'input_complete':not formal['has_more'],
                    'policy':'single-formal-provider-longest-prefix-before-asn-filtering',
                    'formal_sources':sorted({row['source'] for row in candidates}),
                    'selected_input_ids':[row['id'] for row in chosen],
                    'expected_asns_from_recorded_inputs':formal_origins if not formal['has_more'] else None,
                    'stored_asns':sorted({int(row['product'].split('/')[1]) for row in stored['records']}),
                    'stored_complete':not stored['has_more'], 'address_eligibility_recorded':eligible is not None,
                    'meaning':'Only formal provider inputs contribute to special/asn.ardb. Unknown/private more-specific records shadow the parent; BGP/IPtoASN below are comparison-only.'}
                observations = ranges(connection,'route_input',network.version,a,b,limit=1000,source_scope='comparison')
                views = {}
                if not observations['has_more'] and eligible is not False:
                    for row in observations['records']:
                        info=row['details']
                        if info.get('semantics')!='routing-origin' or info.get('origin_prefix_length')==0 or info.get('reason')=='outside-asn-address-eligibility': continue
                        if row['status'] not in {'accepted','observed-only'}: continue
                        width=info['end']-info['start']
                        for view in info.get('views') or [row['source']+'/'+(info.get('collector') or row['source'])]:
                            old=views.get(view)
                            if old is None or width<old[0]: views[view]=(width,set(origins(row)),{row['id']})
                            elif width==old[0]: old[1].update(origins(row));old[2].add(row['id'])
                result['asn_comparison'] = {
                    'input_complete':not observations['has_more'], 'comparison_only':True,
                    'asns_from_comparison_observations': sorted({number for _,values,_ in views.values() for number in values}) if not observations['has_more'] else None,
                    'view_count':len(views),
                    'views_sample':[{'view':view,'original_span':width,'selected_asns':sorted(values),'selected_input_ids':sorted(ids)}
                                    for view,(width,values,ids) in sorted(views.items())[:100]],
                    'view_samples_complete':len(views)<=100,
                    'meaning':'Per-real-peer/independent aggregate comparison. This neither fills nor overrides the formal ASN database and does not establish physical location.'}
            if generation_context.get('mode')=='domains-only':
                result['ip_provenance_scope']='Regional IP lists and special/asn.ardb retained from retained_ip_base; original IP source rows and observations were not re-parsed in this run. Consult the recorded source version/time and retained base build record.'
                result['asn_point_selection']={'applicable':False,'reason':'retained ASN database; no new routing inputs'}
            result['scope'] = 'Prefix queries list overlapping records and may span different decisions. No single sampled IP proves a whole prefix. BGP observations are route_input observed=1; non-default observations form the association mask. Forwarding defaults are reported separately, not treated as ASN ownership of all addresses.'
        elif asn is not None:
            number = int(str(asn).removeprefix('AS'))
            if not 0 < number < 2**32: raise ValueError('invalid ASN')
            for field, condition in (('formal_inputs',"r.status='formal-input'"),('comparison_inputs',"r.status!='formal-input'")):
                rows = connection.execute('SELECT r.id,r.source,r.status,r.observed,r.details FROM route_input r JOIN route_origin a ON a.input_id=r.id WHERE a.asn=? AND '+condition+' ORDER BY r.id LIMIT ? OFFSET ?', (number,limit+1,offset)).fetchall()
                result[field] = _page([dict(row) | {'details':json.loads(row['details'])} for row in rows],limit,0)
                result[field]['next_offset']=offset+limit if len(rows)>limit else None
            result['output_prefixes'] = _page([dict(r) | {'start': str(ipaddress.ip_address(int.from_bytes(r['start'],'big'))) if r['family']==4 else str(ipaddress.IPv6Address(int.from_bytes(r['start'],'big'))),
                'end': str((ipaddress.IPv4Address if r['family']==4 else ipaddress.IPv6Address)(int.from_bytes(r['end'],'big')))} for r in connection.execute('SELECT product,family,start,end FROM output_ip WHERE product=? ORDER BY family,start LIMIT ? OFFSET ?', ('asn/'+str(number), limit+1, offset))], limit, 0)
            result['output_prefixes']['next_offset'] = offset+limit if result['output_prefixes']['has_more'] else None
            refs = connection.execute("SELECT product,kind,value FROM output_domain WHERE kind='IP-ASN' AND value IN (?,?) ORDER BY product LIMIT ? OFFSET ?", (str(number),'AS'+str(number),limit+1,offset)).fetchall()
            result['rule_references'] = _page([dict(r) for r in refs],limit,0)
            result['rule_references']['next_offset'] = offset+limit if result['rule_references']['has_more'] else None
        elif product is not None:
            row = connection.execute('SELECT details FROM product WHERE name=?', (product,)).fetchone()
            result['product'] = json.loads(row[0]) if row else None
            result['stages'] = [dict(r) for r in connection.execute('SELECT stage,status,reason,COUNT(*) AS event_count FROM domain_event WHERE product=? GROUP BY stage,status,reason', (product,))]
            result['events'] = {'records': [json.loads(r[0]) for r in connection.execute('SELECT details FROM domain_event WHERE product=? ORDER BY id LIMIT ? OFFSET ?', (product, limit+1, offset))]}
            result['events'].update(has_more=len(result['events']['records'])>limit, next_offset=offset+limit if len(result['events']['records'])>limit else None)
            result['events']['records'] = result['events']['records'][:limit]
        else:
            rule = normalize_rule('DOMAIN', domain)
            parts = rule.value.split('.'); ancestors = ['.'.join(parts[i:]) for i in range(len(parts))]
            placeholders = ','.join('?' for _ in ancestors)
            clause = f"((kind='DOMAIN' AND value=?) OR (kind='DOMAIN-SUFFIX' AND value IN ({placeholders})) OR kind IN ('DOMAIN-KEYWORD','DOMAIN-REGEX'))"
            params = (rule.value, *ancestors)
            def matching(table, select):
                for row in connection.execute(f'SELECT {select} FROM {table} WHERE {clause}', params):
                    r = dict(row)
                    try:
                        if domain_match(normalize_rule(r['kind'], r['value']),rule.value): yield r
                    except ValueError:
                        continue
            events = matching('domain_event', '*')
            page = []; skipped = 0
            for event in events:
                if skipped < offset: skipped += 1; continue
                page.append(json.loads(event['details']))
                if len(page)>limit: break
            result['events'] = {'records': page[:limit], 'has_more':len(page)>limit, 'next_offset':offset+limit if len(page)>limit else None}
            outputs = list(matching('output_domain', '*'))
            result['final_matching_rules'] = _page(outputs, limit, offset)
            result['unparsed_text_mentions'] = [json.loads(row[0]) for row in connection.execute(
                "SELECT details FROM domain_event WHERE kind='UNSUPPORTED' AND value LIKE ? ORDER BY id LIMIT ? OFFSET ?", ('%'+rule.value+'%',limit,offset))]
            result['unparsed_note'] = 'Text mentions in rejected unsupported expressions, not a claim that the expression would match this domain.'
            result['meaning'] = 'Matching predicates/events, including exclusions and covering final rules; absence from another source is not negative evidence. Earlier retained stages are not final admission. Concrete hostname regex matching is separate from the conservative set-containment proof used by compaction.'
        result['source_states'] = summary.get('sources', [])
        return result
    finally:
        connection.close()
