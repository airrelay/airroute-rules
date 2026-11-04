"""Isolated IPv6 diagnosis using production parsing/fusion; never publishes."""
from __future__ import annotations

import argparse
import bisect
from collections import Counter
import heapq
import ipaddress
import json
from pathlib import Path
import time

from airroute_data.ardb import read_database
from airroute_data.geo import fuse_country, parse_source
from airroute_data.pipeline import usable_sources, write_json


def intervals(groups):
    rows = []
    for group, prefixes in groups.items():
        for prefix in prefixes:
            net = ipaddress.ip_network(prefix)
            if net.version == 6:
                rows.append((int(net.network_address), int(net.broadcast_address), group))
    rows.sort()
    for left, right in zip(rows, rows[1:]):
        if left[1] >= right[0]:
            raise ValueError('overlapping published Geo regions')
    return rows


def overlaps(rows, ends, start, end):
    out = Counter()
    index = bisect.bisect_left(ends, start)
    while index < len(rows) and rows[index][0] <= end:
        a, b, region = rows[index]
        out[region] += min(end, b) - max(start, a) + 1
        index += 1
    return out


def analyze(path, registry, previous, current):
    mapping = {cc: r['key'] for r in registry['regions'] for cc in r['countries']}
    old_rows, new_rows = intervals(previous), intervals(current)
    old_ends, new_ends = [r[1] for r in old_rows], [r[1] for r in new_rows]
    old_totals, new_totals, unchanged, relabeled = Counter(), Counter(), Counter(), Counter()
    for a, b, region in old_rows:
        old_totals[region] += b - a + 1
        hit = overlaps(new_rows, new_ends, a, b)
        unchanged[region] += hit.pop(region, 0)
        relabeled[region] += sum(hit.values())
    for a, b, region in new_rows:
        new_totals[region] += b - a + 1
    conflict_total = 0
    old_pair_total = 0
    old_published_conflict = Counter()
    dissent = Counter()
    signatures = Counter()
    largest = []
    conflict_intervals = 0
    with Path(path).open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['family'] != 6 or row['status'] != 'conflicting-regions':
                continue
            a, b = int(ipaddress.IPv6Address(row['start'])), int(ipaddress.IPv6Address(row['end']))
            size = b - a + 1
            conflict_total += size
            conflict_intervals += 1
            regions = {sid: {mapping.get(cc, 'unmapped') for cc in countries}
                       for sid, countries in row['sources'].items()}
            old = regions.get('dbip', set())
            agrees = len(old) == 1 and old == regions.get('iplocate')
            if agrees:
                old_pair_total += size
                opposing = tuple(sorted(sid for sid, values in regions.items() if values and values != old))
                signatures[','.join(opposing)] += size
                for sid in opposing:
                    dissent[sid] += size
            old_hit = overlaps(old_rows, old_ends, a, b)
            old_published_conflict.update(old_hit)
            sample = {**row, 'addresses': size, 'old_pair_agrees': agrees,
                      'previous_published_overlap': dict(old_hit)}
            # Start/end tie-breakers are deterministic, independent of JSON dict order.
            item = (size, a, b, sample)
            if len(largest) < 20:
                heapq.heappush(largest, item)
            elif item[:3] > largest[0][:3]:
                heapq.heapreplace(largest, item)
    return {
        'previous_ipv6_addresses': sum(old_totals.values()),
        'current_ipv6_addresses': sum(new_totals.values()),
        'previous_by_region_id': dict(old_totals), 'current_by_region_id': dict(new_totals),
        'retained_same_region': dict(unchanged), 'reassigned_to_other_region': dict(relabeled),
        'removed_to_unknown': {k: n - unchanged[k] - relabeled[k] for k, n in old_totals.items()},
        'conflicting_addresses': conflict_total, 'conflicting_intervals': conflict_intervals,
        'old_two_source_agreement_but_five_source_conflict_addresses': old_pair_total,
        'previous_published_now_conflicting_by_region_id': dict(old_published_conflict),
        'dissent_against_old_pair_by_source_nonadditive': dict(dissent),
        'dissent_source_combinations': dict(signatures.most_common()),
        'largest_conflicts': [row for _, _, _, row in sorted(largest, key=lambda x: x[:3], reverse=True)],
        'note': 'Address-weighted coverage is not routed/active host count or accuracy. Old pair agreement is a counterfactual, not truth.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--previous', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    snapshot = json.loads(args.snapshot.read_text())
    sources, _ = usable_sources(args.snapshot, snapshot)
    sources = [s for s in sources if s['id'] in {'dbip', 'iplocate', 'maxmind', 'ipinfo', 'ip2location'}]
    if len(sources) != 5:
        raise ValueError('diagnosis requires all five sources')
    registry = json.loads(Path('config/regions.json').read_text())
    started = time.monotonic()
    rows = (r for s in sources for r in parse_source(s['format'], s['path'], s) if r.version == 6)
    details = args.output.parent / 'ipv6-issues.jsonl'
    result = fuse_country(rows, registry, details_path=details)
    write_json(args.output / 'fusion-report.json', result['report'])
    previous = read_database(args.previous, 'geo', allowed_geo_ids=[r['id'] for r in registry['regions']])
    report = analyze(details, registry, previous, result['groups'])
    # Check original parsed source intervals at the largest conflicts, no network lookup.
    samples = report['largest_conflicts']
    points = sorted((int(ipaddress.IPv6Address(row['start'])), i) for i, row in enumerate(samples))
    values = [point for point, _ in points]
    for sample in samples:
        sample['original_source_ranges_at_start'] = {}
    for source in sources:
        for record in parse_source(source['format'], source['path'], source):
            if record.version != 6:
                continue
            begin = bisect.bisect_left(values, record.start)
            finish = bisect.bisect_right(values, record.end)
            for _, i in points[begin:finish]:
                bucket = samples[i]['original_source_ranges_at_start'].setdefault(source['id'], [])
                bucket.append({'start': str(ipaddress.IPv6Address(record.start)),
                               'end': str(ipaddress.IPv6Address(record.end)), 'country': record.country})
                if len(bucket) > 16:
                    raise ValueError('unexpected source overlap; inspect raw source locally')
    report['source_snapshot'] = [{k: s[k] for k in ('id', 'sha256', 'version', 'fetched_at') if k in s} for s in sources]
    report['elapsed_seconds'] = round(time.monotonic() - started, 3)
    report['production_policy_unchanged'] = True
    write_json(args.output / 'diagnosis.json', report)
    print(json.dumps({k: report[k] for k in ('previous_ipv6_addresses', 'current_ipv6_addresses',
                     'conflicting_addresses', 'old_two_source_agreement_but_five_source_conflict_addresses', 'elapsed_seconds')}))


if __name__ == '__main__':
    main()
