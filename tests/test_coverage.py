"""Semantic coverage is descriptive; output contracts remain enforceable."""
import json
from pathlib import Path
import tempfile
import unittest
from airroute_data.coverage import compare_product, guard_products, profiles
from airroute_data.domains import CoverageIndex, minimize, normalize_rule


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def baseline(self, groups, sources=()):
        files=[]
        for name,rows in groups.items():
            path=self.root/(name+'.list');path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('\n'.join(rows)+'\n');files.append({'path':name+'.list'})
        (self.root/'manifest.json').write_text(json.dumps({'files':files,'source_snapshot':list(sources)}))
        return self.root

    def test_text_difference_is_not_a_coverage_gap(self):
        diff=compare_product(['DOMAIN,api.example.com','DOMAIN-SUFFIX,assets.example.com'],['DOMAIN-SUFFIX,example.com'])
        self.assertEqual(diff['retained_domain_predicates'],2)
        self.assertEqual(diff['old_domain_predicates_not_fully_retained'],0)

    def test_exact_child_does_not_prove_parent_suffix(self):
        self.assertEqual(compare_product(['DOMAIN-SUFFIX,example.com'],['DOMAIN,api.example.com'])['retained_domain_predicates'],0)

    def test_strict_wildcard_preserves_apex_boundary_and_compacts_children(self):
        regex=normalize_rule('DOMAIN-REGEX',r'^.+\.example\.com$');index=CoverageIndex([regex])
        self.assertFalse(index.covers(normalize_rule('DOMAIN','example.com')))
        self.assertTrue(index.covers(normalize_rule('DOMAIN','a.example.com')))
        self.assertEqual(len(minimize([regex,normalize_rule('DOMAIN','a.example.com')])),1)
        self.assertEqual(len(minimize([regex,normalize_rule('DOMAIN','example.com')])),2)

    def test_historical_domain_loss_is_reported_not_blocked(self):
        before={'category/a':['DOMAIN-SUFFIX,a.example'],'category/b':['DOMAIN-SUFFIX,b.example']}
        result=guard_products({'category/a':[],'category/b':before['category/b']},{},
            {'per_product':{'minimum_domain_retention':1,'minimum_domains':{'category/a':100}}},self.baseline(before))
        self.assertEqual(result['comparison']['category/a']['old_domain_predicates_not_fully_retained'],1)

    def test_ipv6_address_change_is_exact_and_not_a_gate(self):
        before={'region/cn-ip':['IP-CIDR6,2400::/24']};after={'region/cn-ip':['IP-CIDR6,2400::/64']}
        result=guard_products(after,{}, {'per_product':{'minimum_address_retention':1}},self.baseline(before))
        loss=result['comparison']['region/cn-ip']['ip_changes']['ipv6']['removed_addresses']
        self.assertEqual(loss,2**104-2**64)

    def test_no_missing_optional_source_or_required_domain_quantity_gate(self):
        guard_products({}, {'source_snapshot':[{'id':'old','status':'missing-credentials'}]},
            {'per_product':{'required_sources':{'category/a':['old']},'required_domain_coverage':{'category/a':['DOMAIN,a.example']},
                            'minimum_addresses':{'region/cn-ip':{'4':1000000}}}})

    def test_growth_and_same_size_replacement_are_reported_not_blocked(self):
        before={'region/ru':['IP-CIDR,1.0.0.0/24']};after={'region/ru':['IP-CIDR,2.0.0.0/16']}
        result=guard_products(after,{}, {'per_product':{'maximum_address_growth':1.01,'minimum_address_retention':1}},self.baseline(before))
        change=result['comparison']['region/ru']['ip_changes']['ipv4']
        self.assertEqual(change,{'retained_addresses':0,'added_addresses':65536,'removed_addresses':256})

    def test_manifest_metrics_are_still_verified(self):
        with self.assertRaisesRegex(ValueError,'coverage disagrees'):
            guard_products({}, {'product_coverage':{'fake':{}}},{})
        rows={'provider/a':['DOMAIN,a.example']}
        guard_products(rows,{'product_coverage':profiles(rows)}, {})

    def test_process_and_asn_membership_is_not_lost_in_domain_statistics(self):
        diff=compare_product(['PROCESS-NAME,GameClient','IP-ASN,13335'],['IP-ASN,13335'])
        self.assertEqual(diff['old_domain_predicates'],0)
        self.assertEqual(diff['removed_other_examples'],['PROCESS-NAME,GameClient'])
        self.assertEqual(diff['retained_other_predicates'],1)

    def test_generated_list_rejects_all_modifiers_and_route_actions(self):
        from airroute_data.validation import parse_list
        path=self.root/'rules.list'
        for text in ['DOMAIN,a.example,no-resolve','IP-CIDR,1.2.3.0/24,no-resolve',
                     'IP-CIDR6,2001:4860::/48,no-resolve','IP-ASN,13335,no-resolve',
                     'IP-CIDR,1.2.3.0/24,DIRECT','IP-ASN,13335,no-resolve,PROXY']:
            path.write_text(text+'\n')
            with self.subTest(text=text),self.assertRaises(ValueError):parse_list(path)
            with self.subTest(profile=text),self.assertRaises(ValueError):profiles({'provider/a':[text]})

    def test_known_upstream_modifier_is_removed_during_conversion(self):
        from airroute_data.domains import parse_third_party
        rows,rejected=parse_third_party('IP-CIDR,1.2.3.0/24,no-resolve\nIP-ASN,13335,no-resolve\n','surge')
        self.assertEqual([r.text for r in rows],['IP-CIDR,1.2.3.0/24','IP-ASN,13335'])
        self.assertEqual(rejected,[])

    def test_optional_baseline_rules_missing_does_not_prevent_core_validation(self):
        baseline=self.baseline({'provider/a':['DOMAIN,a.example']})
        (baseline/'provider/a.list').unlink()
        self.assertEqual(guard_products({}, {}, {},baseline)['comparison'],{})


if __name__=='__main__':unittest.main()
