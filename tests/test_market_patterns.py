"""Exclusion is proven containment; cross-product overlap does not delete rules."""
import tempfile
from pathlib import Path
import unittest
from airroute_data.domains import CoverageIndex, build_domains, normalize_rule, validate_domain_groups

class MarketPatternTests(unittest.TestCase):
    def test_unknown_regex_root_intersection_is_not_containment(self):
        index = CoverageIndex([normalize_rule('DOMAIN-SUFFIX','shared.example')])
        for pattern in (r'^tenant\.(shared|other)\.example$', r'^api[0-9]+\.shared\.example$'):
            self.assertFalse(index.covers(normalize_rule('DOMAIN-REGEX',pattern)))
        self.assertTrue(index.covers(normalize_rule('DOMAIN-REGEX',r'^.+\.shared\.example$')))

    def test_exact_exclusion_removes_only_proven_whole_predicate(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'rules.list'
            path.write_text('DOMAIN,host.shared.example\nDOMAIN-SUFFIX,example\nDOMAIN-REGEX,^api[0-9]+\\.shared\\.example$\n')
            groups,report=build_domains([{'id':'source','path':str(path),'format':'surge'}],
                {'schema':1,'groups':[{'id':'region/cn-domain','selectors':[{'source':'source','exclude_roots':['shared.example']}]}]})
            self.assertNotIn('DOMAIN,host.shared.example',groups['region/cn-domain'])
            self.assertIn('DOMAIN-SUFFIX,example',groups['region/cn-domain'])
            self.assertEqual(len(report['quarantined']),1)

    def test_shared_cn_and_global_patterns_need_no_exception_registry(self):
        validate_domain_groups({'region/cn-domain':['DOMAIN-KEYWORD,mainland','DOMAIN,cn.service.example'],
                               'provider/global':['DOMAIN-SUFFIX,service.example']})

if __name__ == '__main__':
    unittest.main()
