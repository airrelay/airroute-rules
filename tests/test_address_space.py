import copy
import csv
import hashlib
import ipaddress
from pathlib import Path
import tempfile
import unittest

from airroute_data.address_space import AddressEligibility
from airroute_data.acquire import tree_digest


def address(text):
    return int(ipaddress.ip_address(text))


def sources(root):
    """Explicit synthetic registries; never a fallback for production inputs."""
    rows = {
        "iana-alloc-v4": (['Prefix', 'Designation', 'Status [1]'], [
            ['000/8', 'Reserved', 'RESERVED'], ['001/8', 'RIR', 'ALLOCATED'],
            ['010/8', 'Private', 'RESERVED'], ['192/8', 'RIR', 'LEGACY'],
            ['198/8', 'RIR', 'LEGACY'], ['224.0.0.0/4', 'Multicast', 'RESERVED']]),
        "iana-alloc-v6": (['Prefix', 'Designation', 'Status'], [
            ['2000::/3', 'Synthetic parent', 'ALLOCATED'],
            ['3000::/5', 'Synthetic future space', 'RESERVED'],
            ['3100::/8', 'Synthetic exception', 'ALLOCATED'],
            ['4000::/32', 'Synthetic future allocation', 'ALLOCATED']]),
        "iana-special-v4": (['Address Block', 'Name', 'Globally Reachable', 'Destination', 'Forwardable'], [
            ['192.0.0.0/24 [2]', 'Protocol assignments', 'False', 'False', 'False'],
            ['192.0.0.9/32', 'PCP anycast', 'True', 'True', 'True'],
            ['192.0.0.10/32', 'TURN anycast', 'True', 'True', 'True'],
            ['192.0.0.170/32, 192.0.0.171/32', 'NAT64 discovery', 'False', 'False', 'False'],
            ['192.0.2.0/24', 'Documentation', 'False', 'False', 'False'],
            ['198.18.0.0/15', 'Benchmark', 'False', 'True', 'True']]),
        "iana-special-v6": (['Address Block', 'Name', 'Globally Reachable', 'Destination', 'Forwardable'], [
            ['2001::/23', 'Protocol assignments', 'False [1]', 'False [1]', 'False [1]'],
            ['2001:3::/32', 'AMT', 'True', 'True', 'True'],
            ['2001::/32', 'Teredo', 'N/A [2]', 'True', 'True'],
            ['2002::/16', '6to4', 'N/A [3]', 'True', 'True'],
            ['64:ff9b::/96', 'Translation', 'True', 'True', 'True'],
            ['fc00::/7', 'ULA', 'False [4]', 'True', 'True'],
            ['2001:db8::/32', 'Documentation', 'False', 'False', 'False']]),
    }
    result = []
    for sid, (header, data) in rows.items():
        path = root / (sid + '.csv')
        with path.open('w', newline='') as stream:
            writer = csv.writer(stream); writer.writerow(header); writer.writerows(data)
        result.append({'id': sid, 'status': 'available', 'path': str(path),
                       'sha256': tree_digest(path)[0],
                       'version': 'synthetic-v1', 'fetched_at': '2026-11-04T00:00:00Z'})
    return result


class AddressEligibilityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.inputs = sources(Path(self.directory.name))
        self.eligibility = AddressEligibility.from_sources(self.inputs)

    def point(self, method, ip):
        parsed = ipaddress.ip_address(ip)
        return bool(list(getattr(self.eligibility, method)(parsed.version, int(parsed), int(parsed))))

    def test_asn_nested_positive_exceptions_are_not_geo(self):
        for ip in ('192.0.0.9', '192.0.0.10', '2001:3::1', '64:ff9b::1'):
            with self.subTest(ip=ip):
                self.assertTrue(self.point('asn_intervals', ip))
                self.assertFalse(self.point('geo_intervals', ip))
        for ip in ('192.0.0.8', '192.0.0.11', '192.0.0.170', '2001::1', '2002::1'):
            with self.subTest(ip=ip):
                self.assertFalse(self.point('asn_intervals', ip))
                self.assertFalse(self.point('geo_intervals', ip))
        self.assertEqual(list(self.eligibility.asn_intervals(4, address('192.0.0.0'), address('192.0.0.255'))),
                         [(address('192.0.0.9'), address('192.0.0.10'))])

    def test_iana_allocation_boundaries_replace_fixed_ipv6_aggregate(self):
        self.assertFalse(self.point('geo_intervals', '3001::1'))
        self.assertTrue(self.point('geo_intervals', '3100::1'))
        # Synthetic future IANA allocation outside 2000::/3 must not be lost to
        # a hardcoded approximation of currently allocated address space.
        self.assertTrue(self.point('geo_intervals', '4000::1'))
        self.assertFalse(self.point('geo_intervals', '4001::1'))
        self.assertTrue(self.point('geo_intervals', '1.1.1.1'))
        self.assertFalse(self.point('geo_intervals', '2.1.1.1'))

    def test_special_non_geographic_ranges_and_shared_space(self):
        for ip in ('0.0.0.1', '10.0.0.1', '192.0.2.1', '198.18.0.1', '224.0.0.1', '2001:db8::1', 'fc00::1', 'ff02::1'):
            with self.subTest(ip=ip):
                self.assertFalse(self.point('geo_intervals', ip))
                self.assertFalse(self.point('asn_intervals', ip))

    def test_exact_intersections_do_not_expand_query_range(self):
        start, end = address('192.0.0.8'), address('192.0.0.9')
        self.assertEqual(list(self.eligibility.asn_intervals(4, start, end)), [(end, end)])
        for family, a, b in ((4, -1, 10), (4, 10, 9), (4, 0, 2**32), (5, 0, 1)):
            with self.subTest(family=family, a=a, b=b), self.assertRaises(ValueError):
                list(self.eligibility.geo_intervals(family, a, b))

    def test_snapshot_identity_and_lpm_reasons_are_in_report(self):
        info = self.eligibility.explain(4, address('192.0.0.9'))
        self.assertEqual(info['allocation']['status'], 'LEGACY')
        self.assertEqual(info['special']['prefix'], '192.0.0.9/32')
        self.assertTrue(info['asn_eligible']); self.assertFalse(info['geo_eligible'])
        self.assertEqual({s['id'] for s in self.eligibility.report['sources']}, {s['id'] for s in self.inputs})
        self.assertTrue(all(s['source_tree_sha256'] and s['file_sha256'] and s['version'] == 'synthetic-v1' for s in self.eligibility.report['sources']))

    def test_snapshot_tree_digest_and_file_digest_have_distinct_semantics(self):
        for source in self.inputs:
            metadata = next(item for item in self.eligibility.report['sources'] if item['id'] == source['id'])
            self.assertEqual(metadata['source_tree_sha256'], source['sha256'])
            self.assertEqual(metadata['file_sha256'], hashlib.sha256(Path(source['path']).read_bytes()).hexdigest())
            self.assertNotEqual(metadata['source_tree_sha256'], metadata['file_sha256'])

    def test_fetch_timestamp_does_not_change_stable_manifest_contract(self):
        again = copy.deepcopy(self.inputs)
        for source in again: source['fetched_at'] = '2026-12-31T23:59:59Z'
        self.assertEqual(AddressEligibility.from_sources(again).report, self.eligibility.report)
        self.assertTrue(all('fetched_at' not in item for item in self.eligibility.report['sources']))

    def test_missing_failed_or_corrupt_registry_never_uses_hidden_baseline(self):
        with self.assertRaisesRegex(ValueError, 'missing required'):
            AddressEligibility.from_sources(self.inputs[:-1])
        bad = copy.deepcopy(self.inputs); bad[0]['status'] = 'unavailable'
        with self.assertRaisesRegex(ValueError, 'missing required'):
            AddressEligibility.from_sources(bad)
        bad = copy.deepcopy(self.inputs); bad[0]['sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            AddressEligibility.from_sources(bad)

    def test_malformed_flags_prefixes_and_empty_input_fail(self):
        first = self.inputs[0]
        path = Path(first['path'])
        for contents in ('Prefix,Designation,Status\n',
                         'Prefix,Designation,Status\n1.1.1.1/24,RIR,ALLOCATED\n',
                         'Prefix,Designation,Status\n001/8,RIR,MAYBE\n'):
            with self.subTest(contents=contents):
                path.write_text(contents)
                first.pop('sha256', None)
                with self.assertRaises(ValueError): AddressEligibility.from_sources(self.inputs)

    def test_self_contained_report_roundtrip_and_tampering(self):
        report = self.eligibility.report
        restored = AddressEligibility.from_report(report)
        self.assertEqual(restored.geo_domains, self.eligibility.geo_domains)
        self.assertEqual(restored.asn_domains, self.eligibility.asn_domains)
        changes = [
            lambda r: r.update(schema=2),
            lambda r: r['sources'].pop(),
            lambda r: r['allocation_entries'][0].update(start=1),
            lambda r: r['allocation_entries'][0].update(eligible=True),
            lambda r: r['special_entries'][0].update(globally_reachable='True'),
            lambda r: r['special_entries'][0].pop('globally_reachable'),
            lambda r: r['geo']['6'].update(addresses=r['geo']['6']['addresses'] + 1),
        ]
        for change in changes:
            bad = copy.deepcopy(report); change(bad)
            with self.subTest(change=change), self.assertRaises(ValueError):
                AddressEligibility.from_report(bad)


if __name__ == '__main__':
    unittest.main()
