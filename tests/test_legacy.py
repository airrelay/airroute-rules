import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from airroute_data.domains import RuleError
from airroute_data.legacy import audit_legacy, legacy_projection


class LegacyDomainTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.body = ("# synthetic fixed output\nDOMAIN,api.mainland.example\n"
                     "DOMAIN-SUFFIX,service.example\nDOMAIN-SUFFIX,pending.example\n"
                     "DOMAIN,customer.cloud.example\nDOMAIN-SUFFIX,cn\nIP-CIDR,1.0.1.0/24\n")
        self.path = self.root / 'cn.list'
        self.path.write_text(self.body)
        self.config = {'schema': 1, 'group': 'region/cn', 'source': {
            'id': 'legacy-cn', 'version': 'fixed', 'path': 'cn.list',
            'sha256': hashlib.sha256(self.body.encode()).hexdigest(), 'records': 6, 'domain_records': 5},
            'sample_limit_per_reason': 1,
            'reviewed_dispositions': [{'predicate': 'DOMAIN-SUFFIX,cn', 'disposition': 'inapplicable',
                'reason': 'whole TLD shortcut', 'evidence': ['explicit product contract']}],
            'shared_infrastructure': [{'root': 'cloud.example', 'evidence': ['synthetic shared host catalogue']}]}
        self.sources = [{'id': 'legacy-cn', 'version': 'fixed', 'path': str(self.path),
                         'status': 'available', 'lineage': 'unknown-legacy-output'}]
        self.groups = {'region/cn': ['DOMAIN,api.mainland.example', 'DOMAIN-SUFFIX,service.example']}

    def audit(self, **kw):
        return audit_legacy(self.groups, self.sources, self.config, **kw)

    def test_coverage_is_descriptive_and_provenance_unknown(self):
        report=self.audit()
        self.assertEqual(report['source_records'],6)
        self.assertEqual(report['counts']['retained-exact'],2)
        self.assertEqual(report['counts']['pending-verification'],3)
        self.assertEqual(report['counts']['outside-domain-scope'],1)
        self.assertTrue(all(row['upstream_provenance']=='unknown' for row in report['records']))
        self.assertNotIn('protected_rules',report)
        self.assertNotIn('validation',report)

    def test_provable_suffix_coverage(self):
        self.groups['region/cn'][0]='DOMAIN-SUFFIX,mainland.example'
        row=next(row for row in self.audit()['records'] if row['rule']=='DOMAIN,api.mainland.example')
        self.assertEqual(row['covered_by'],'DOMAIN-SUFFIX,mainland.example')

    def test_valid_tld_is_not_a_migration_veto(self):
        self.groups['region/cn'].append('DOMAIN-SUFFIX,cn')
        row=next(row for row in self.audit()['records'] if row['rule']=='DOMAIN-SUFFIX,cn')
        self.assertEqual(row['disposition'],'retained-exact')

    def test_missing_optional_corpus(self):
        report=audit_legacy(self.groups,[],self.config)
        self.assertEqual(report['status'],'missing-optional')

    def test_corrupt_present_input_fails(self):
        self.path.write_text('changed')
        with self.assertRaisesRegex(RuleError,'checksum'):
            self.audit()

    def test_streaming_and_compact_projection(self):
        target=self.root/'records.jsonl'
        report=self.audit(records_path=target)
        self.assertEqual(len(target.read_text().splitlines()),6)
        self.assertNotIn('records',report)
        self.assertEqual(legacy_projection(report)['counts'],report['counts'])
