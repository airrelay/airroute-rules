"""Trace sinks describe existing predicates without changing products/reports."""
from pathlib import Path
import tempfile
import unittest

from airroute_data.domains import CompactionWitness, RuleError, build_domains, normalize_rule
from airroute_data.special import build_special


class Sink:
    def __init__(self):
        self.domain = []
        self.source = []

    def domain_event(self, item):
        self.domain.append(item)

    def source_event(self, sid, stage, status, **stats):
        self.source.append({"source": sid, "stage": stage, "status": status, **stats})


class DomainTraceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def source(self, text, sid="community", format="surge"):
        path = self.root / (sid + '.list')
        path.write_text(text)
        return {"id": sid, "path": str(path), "format": format, "status": "available", "lineage": sid}

    def dlc(self, files):
        path = self.root / 'dlc' / 'data'
        path.mkdir(parents=True)
        for name, content in files.items():
            (path / name).write_text(content)
        return {"id": "dlc", "path": str(path.parent), "format": "dlc", "status": "available"}

    def test_full_compaction_stream_does_not_change_reports(self):
        source = self.source('DOMAIN-SUFFIX,example.cn\nDOMAIN,www.example.cn\n'
                             'DOMAIN-SUFFIX,sub.example.cn\nAND,((DOMAIN,bad.example))\n')
        products = {"schema": 1, "groups": [{"id": "region/cn", "selectors": [{"source": "community"}]}]}
        before = build_domains([source], products)
        sink = Sink()
        self.assertEqual(before, build_domains([source], products, trace=sink))
        covered = next(x for x in sink.domain if x['predicate'] == 'DOMAIN,www.example.cn' and x['stage'] == 'compaction')
        self.assertEqual(covered['status'], 'covered')
        self.assertEqual(covered['covering_predicate'], 'DOMAIN-SUFFIX,example.cn')
        self.assertTrue(any(x['status'] == 'reject' and x['stage'] == 'parse-normalize' for x in sink.domain))
        parsed = next(x for x in sink.source if x['stage'] == 'domain-selector-parse')
        self.assertEqual((parsed['read_lines'], parsed['parsed_records'], parsed['rejected_records']), (4, 3, 1))
        self.assertIn('not unique physical', parsed['count_scope'])

    def test_dlc_includes_attributes_membership_and_missing_selector(self):
        source = self.dlc({'base': 'full:a.example @keep\nfull:b.example\nunknown-type:bad.example\n',
                           'chosen': 'include:base\n'})
        products = {"schema": 1, "groups": [
            {"id": "region/cn", "selectors": []},
            {"id": "service/test", "selectors": [{"source": "dlc", "category": "chosen", "attributes": ['keep']}]},
            {"id": "category/test", "includes": ["service/test"], "selectors": [{"source": "missing"}]}]}
        sink = Sink()
        self.assertEqual(build_domains([source], products), build_domains([source], products, trace=sink))
        self.assertTrue(any(x['stage'] == 'include-and-attributes' and x['status'] == 'filtered' for x in sink.domain))
        self.assertTrue(any(x['stage'] == 'membership' and x['child'] == 'service/test' for x in sink.domain))
        source_parse = next(x for x in sink.source if x['stage'] == 'domain-source-parse')
        self.assertEqual((source_parse['read_lines'], source_parse['parsed_records'], source_parse['include_records'], source_parse['rejected_records']), (4, 2, 1, 1))
        self.assertTrue(any(x['source'] == 'missing' and x['status'] == 'unavailable' for x in sink.source))

    def test_empty_and_failed_required_selector_are_preserved(self):
        source = self.source('# empty source\n')
        products = {"schema": 1, "groups": [{"id": "region/cn", "selectors": [{"source": "community", "required": True}]}]}
        sink = Sink()
        with self.assertRaisesRegex(RuleError, 'required selector'):
            build_domains([source], products, trace=sink)
        self.assertTrue(any(x['status'] == 'empty' for x in sink.source))
        self.assertTrue(any(x['status'] == 'failed' for x in sink.source))

    def test_cn_service_scope_rejections_have_terminal_trace(self):
        source = self.dlc({'cn': 'domestic.example\nkeyword:china\n', 'service': 'domestic.example\nforeign.example\n'})
        products = {"schema": 1, "groups": [
            {"id": "region/cn", "selectors": [{"source": "dlc", "category": "cn"}]},
            {"id": "service/test", "selectors": [{"source": "dlc", "category": "service"}]}]}
        sink = Sink()
        self.assertEqual(build_domains([source], products), build_domains([source], products, trace=sink))
        self.assertTrue(any(x['stage'] == 'regional-scope' and x['predicate'] == 'DOMAIN-KEYWORD,china' for x in sink.domain))
        self.assertTrue(any(x['stage'] == 'cross-market' and x['predicate'] == 'DOMAIN-SUFFIX,domestic.example' and x['status'] == 'pending' for x in sink.domain))

    def test_witnesses_cover_strict_subdomains_keywords_and_merged_cidrs(self):
        pairs = [('DOMAIN,www.example.cn', ['DOMAIN-SUFFIX,example.cn']),
                 ('DOMAIN,x.strict.example', [r'DOMAIN-REGEX,^.+\.strict\.example$']),
                 ('DOMAIN-SUFFIX,foo-key.example', ['DOMAIN-KEYWORD,key']),
                 ('IP-CIDR,1.0.0.128/25', ['IP-CIDR,1.0.0.0/24']),
                 ('IP-CIDR6,2400::80/121', ['IP-CIDR6,2400::/120'])]
        for original, final in pairs:
            with self.subTest(original=original):
                self.assertEqual(CompactionWitness(final).covering(normalize_rule(*original.split(',', 1))), final[0])
        witness = CompactionWitness(['DOMAIN,example.cn'])
        self.assertIsNone(witness.covering(normalize_rule('DOMAIN-SUFFIX', 'example.cn')))

    def test_special_config_realip_defaults_and_full_reference_exclusions(self):
        source = self.source('payload:\n' + ''.join(f'  - "+.unrelated{i}.example"\n' for i in range(1005)),
                             sid='metacubex-private', format='mihomo')
        sink = Sink()
        before = build_special([source])
        self.assertEqual(before, build_special([source], trace=sink))
        self.assertTrue(any(x['group'] == 'special/lan' and x['stage'] == 'maintained-configuration' and x['evidence'] for x in sink.domain))
        rejects = [x for x in sink.domain if x['source_id'] == 'metacubex-private' and x['stage'] == 'reference-scope']
        self.assertEqual(len(rejects), 1005)
        self.assertEqual(len(before[1]['excluded']), 1000)
        self.assertTrue(any(x['group'] == 'dns/realip' and x['stage'] == 'compaction' for x in sink.domain))

    def test_special_selector_parse_failure_and_exact_endpoint_provenance(self):
        source = self.dlc({'category-ntp': 'full:ntp.clock.example\nclock.example\n', 'private': 'home.arpa\n'})
        sink = Sink()
        self.assertEqual(build_special([source]), build_special([source], trace=sink))
        self.assertTrue(any(x['stage'] == 'scope' and x['predicate'] == 'DOMAIN,ntp.clock.example' and x['status'] == 'accept' and x['snapshot'] for x in sink.domain))
        self.assertTrue(any(x['stage'] == 'scope' and x['predicate'] == 'DOMAIN-SUFFIX,clock.example' and x['status'] == 'excluded' for x in sink.domain))
        self.assertTrue(any(x['stage'] == 'special-selector' and x['status'] == 'failed' for x in sink.source))


if __name__ == '__main__':
    unittest.main()
