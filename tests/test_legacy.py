import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from airroute_data.domains import RuleError
from airroute_data.legacy import audit_legacy, guard_legacy, legacy_projection


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

    def test_complete_dispositions_do_not_forge_old_provenance(self):
        report = self.audit()
        self.assertEqual(report['source_records'], 6)
        self.assertEqual(report['domain_records'], 5)
        self.assertEqual(report['counts']['retained-exact'], 2)
        self.assertEqual(report['counts']['pending-verification'], 1)
        self.assertEqual(report['counts']['shared-dependency'], 1)
        self.assertEqual(report['counts']['inapplicable'], 1)
        self.assertEqual(report['counts']['outside-domain-scope'], 1)
        self.assertTrue(all(r['upstream_provenance'] == 'unknown' for r in report['records']))
        self.assertIn('not disproof', next(r['reason'] for r in report['records'] if r['disposition'] == 'pending-verification'))
        self.assertIn('legacy-cn', report['source']['id'])

    def test_legitimate_suffix_can_cover_exact_child_without_text_match(self):
        self.groups['region/cn'][0] = 'DOMAIN-SUFFIX,mainland.example'
        report = self.audit()
        record = next(r for r in report['records'] if r['rule'] == 'DOMAIN,api.mainland.example')
        self.assertEqual(record['disposition'], 'covered-semantically')
        self.assertEqual(record['covered_by'], 'DOMAIN-SUFFIX,mainland.example')
        self.assertIn(record['rule'], report['protected_rules'])

    def test_exact_child_cannot_claim_retention_of_old_suffix(self):
        self.groups['region/cn'][1] = 'DOMAIN,api.service.example'
        report = self.audit()
        record = next(r for r in report['records'] if r['rule'] == 'DOMAIN-SUFFIX,service.example')
        self.assertEqual(record['disposition'], 'pending-verification')

    def test_fixed_source_cannot_disappear_change_commit_or_change_bytes(self):
        for sources in ([], [{**self.sources[0], 'status': 'unavailable'}],
                        [{**self.sources[0], 'version': 'moving-head'}]):
            with self.subTest(sources=sources), self.assertRaises(RuleError):
                audit_legacy(self.groups, sources, self.config)
        self.path.write_text(self.body + 'DOMAIN,new.example\n')
        with self.assertRaisesRegex(RuleError, 'checksum'):
            self.audit()

    def test_no_silent_loss_of_previously_retained_predicate(self):
        previous = legacy_projection(self.audit())
        self.groups['region/cn'].pop()
        with self.assertRaisesRegex(RuleError, 'previously retained legacy domain coverage lost'):
            self.audit(previous_report=previous)

    def test_semantically_covering_previous_rule_does_not_regress(self):
        previous = legacy_projection(self.audit())
        self.groups['region/cn'][0] = 'DOMAIN-SUFFIX,mainland.example'
        self.audit(previous_report=previous)

    def test_specific_review_with_evidence_can_correct_previous_retention(self):
        previous = legacy_projection(self.audit())
        self.groups['region/cn'].pop()
        self.config['reviewed_dispositions'].append({'predicate': 'DOMAIN-SUFFIX,service.example',
            'disposition': 'inapplicable', 'reason': 'specific evidenced correction', 'evidence': ['fixture correction source']})
        self.audit(previous_report=previous)
        self.config['reviewed_dispositions'][-1].pop('evidence')
        with self.assertRaisesRegex(RuleError, 'evidence'):
            self.audit(previous_report=previous)

    def test_new_shared_label_cannot_waive_previous_retention(self):
        self.groups['region/cn'].append('DOMAIN,customer.cloud.example')
        previous = legacy_projection(self.audit())
        self.groups['region/cn'].pop()
        with self.assertRaisesRegex(RuleError, 'previously retained legacy domain coverage lost'):
            self.audit(previous_report=previous)

    def test_broad_root_does_not_falsify_migration_coverage(self):
        for bad in ('DOMAIN-SUFFIX,cn', 'DOMAIN-SUFFIX,cloud.example'):
            self.groups['region/cn'].append(bad)
            with self.subTest(bad=bad), self.assertRaisesRegex(RuleError, 'unsafe broad predicate'):
                self.audit()
            self.groups['region/cn'].pop()

    def test_projection_rechecked_against_actual_rules(self):
        report = self.audit(); projection = legacy_projection(report)
        self.assertNotIn('records', projection)
        self.assertNotIn('samples_by_reason', projection)
        guard_legacy(projection, groups=self.groups, config=self.config)
        self.groups['region/cn'].append('DOMAIN,new.example')
        with self.assertRaisesRegex(RuleError, 'does not match actual'):
            guard_legacy(projection, groups=self.groups, config=self.config)

    def test_streamed_records_are_complete_and_path_independent(self):
        outputs = []
        for name in ('one', 'two'):
            p = self.root / name / 'legacy.jsonl'
            report = self.audit(records_path=p)
            self.assertNotIn('records', report)
            self.assertEqual(report['records_file'], 'legacy.jsonl')
            self.assertEqual(len(p.read_text().splitlines()), 6)
            outputs.append((report, p.read_bytes()))
        self.assertEqual(outputs[0], outputs[1])

    def test_endpoint_under_shared_root_can_be_retained_with_current_evidence(self):
        self.groups['region/cn'].append('DOMAIN,customer.cloud.example')
        report = self.audit()
        record = next(r for r in report['records'] if r['rule'] == 'DOMAIN,customer.cloud.example')
        self.assertEqual(record['disposition'], 'retained-exact')
        self.assertFalse(record['reviewed'])

    def test_projection_cannot_hide_missing_disposition_rows(self):
        report = legacy_projection(self.audit())
        report['counts']['pending-verification'] = 0
        with self.assertRaisesRegex(RuleError, 'counts are incomplete'):
            guard_legacy(report, groups=self.groups, config=self.config)

    def test_rehashed_output_and_forged_projection_cannot_hide_broad_root(self):
        report = legacy_projection(self.audit())
        self.groups['region/cn'].append('DOMAIN-SUFFIX,cn')
        report['unsafe_covering_predicates'] = []
        report['output_domain_sha256'] = hashlib.sha256('\n'.join(sorted(self.groups['region/cn'])).encode()).hexdigest()
        with self.assertRaisesRegex(RuleError, 'unsafe broad predicate'):
            guard_legacy(report, groups=self.groups, config=self.config)

    def test_duplicate_reviewed_predicate_rejected(self):
        self.config['reviewed_dispositions'].append(copy.deepcopy(self.config['reviewed_dispositions'][0]))
        with self.assertRaisesRegex(RuleError, 'duplicate legacy reviewed disposition'):
            self.audit()

    def test_strict_wildcard_does_not_retain_old_apex(self):
        self.body = 'DOMAIN,mainland.example\nDOMAIN-REGEX,^.+\\.mainland\\.example$\n'
        self.path.write_text(self.body)
        self.config['source'].update(sha256=hashlib.sha256(self.body.encode()).hexdigest(), records=2, domain_records=2)
        self.groups['region/cn'] = [r'DOMAIN-REGEX,^.+\.mainland\.example$']
        first = self.audit()
        self.assertEqual(first['counts']['retained-exact'], 1)
        self.assertEqual(first['counts']['pending-verification'], 1)
        self.groups['region/cn'] = ['DOMAIN-SUFFIX,mainland.example']
        second = self.audit(previous_report=legacy_projection(first))
        self.assertEqual(second['counts']['covered-semantically'], 2)


if __name__ == '__main__':
    unittest.main()
