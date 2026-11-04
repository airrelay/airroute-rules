"""Catalogue contracts use product semantics, never historical quantity floors."""
import json
from pathlib import Path
import tempfile
import unittest
from airroute_data.coverage import guard_products,profiles,compare_directories


class CatalogueQualityTests(unittest.TestCase):
    def test_required_product_presence_does_not_invent_minimum_rows(self):
        manifest={'product_catalogue':{'provider/a':{'required_output':True,'content_types':['domain']}}}
        guard_products({'provider/a':[]},manifest,{})
        with self.assertRaisesRegex(ValueError,'required product is missing'):
            guard_products({},manifest,{})

    def test_optional_product_and_binary_catalogue_need_no_list(self):
        guard_products({}, {'product_catalogue':{'provider/optional':{'required_output':False,'content_types':['domain']},
            'special/asn':{'content_types':['asn'],'required_output':True}}},{})

    def test_domain_product_rejects_ip_even_with_consistent_metrics(self):
        rows={'special/realip':['IP-CIDR,1.1.1.0/24']}
        with self.assertRaisesRegex(ValueError,'content violates declared product types'):
            guard_products(rows, {'product_coverage':profiles(rows),'product_catalogue':{
                'special/realip':{'content_types':['domain']}}},{})

    def test_unregistered_output_and_unknown_type_fail(self):
        with self.assertRaisesRegex(ValueError,'absent from catalogue'):
            guard_products({'provider/a':['DOMAIN,a.example']},{'product_catalogue':{}},{})
        with self.assertRaisesRegex(ValueError,'invalid declared content types'):
            guard_products({}, {'product_catalogue':{'provider/a':{'content_types':['UA']}}},{})

    def test_category_contains_service_by_semantics_not_text(self):
        rows={'provider/a':['DOMAIN,api.a.example','IP-CIDR,1.1.1.0/24','IP-CIDR6,2001:db8::/64'],
              'category/a':['DOMAIN-SUFFIX,a.example','IP-CIDR,1.1.1.0/25','IP-CIDR,1.1.1.128/25','IP-CIDR6,2001:db8::/64']}
        catalogue={name:{'content_types':['domain','ipv4','ipv6']} for name in rows}
        catalogue['category/a']['includes']=['provider/a']
        guard_products(rows,{'product_catalogue':catalogue},{})
        rows['category/a']=['DOMAIN,api.a.example','IP-CIDR,1.1.1.0/25']
        with self.assertRaisesRegex(ValueError,'does not semantically include'):
            guard_products(rows,{'product_catalogue':catalogue},{})

    def test_category_membership_cannot_drop_process_or_asn_predicates(self):
        for line in ['PROCESS-NAME,GameClient','IP-ASN,13335']:
            with self.subTest(line=line),self.assertRaisesRegex(ValueError,'does not semantically include'):
                guard_products({'provider/a':[line],'category/a':[]},{'product_catalogue':{
                    'provider/a':{'content_types':['non-ip']},
                    'category/a':{'content_types':['non-ip'],'includes':['provider/a']}}},{})

    def test_missing_configured_member_and_cycles_fail(self):
        with self.assertRaisesRegex(ValueError,'included product is missing'):
            guard_products({'category/a':[]},{'product_catalogue':{'category/a':{'includes':['provider/missing']}}},{})
        with self.assertRaisesRegex(ValueError,'membership cycle'):
            guard_products({'category/a':[],'category/b':[]},{'product_catalogue':{
                'category/a':{'includes':['category/b']},'category/b':{'includes':['category/a']}}},{})

    def test_missing_optional_member_is_not_core_input_failure(self):
        guard_products({'category/a':[]},{'product_catalogue':{
            'category/a':{'includes':['provider/optional']},'provider/optional':{'required_output':False}}},{})

    def test_new_product_volume_is_not_an_artificial_gate(self):
        rows={'provider/new':['DOMAIN,a.example']}
        guard_products(rows,{}, {'per_product':{'minimum_domains':{'provider/new':100000},
            'required_domain_coverage':{'provider/new':['DOMAIN,unrelated.example']}}})

    def test_route_coverage_distinguishes_realip_and_duplicate_memberships(self):
        with tempfile.TemporaryDirectory() as d:
            roots=[]
            for label,groups in [('before',{'provider/a':['DOMAIN,a.example']}),
                                 ('after',{'provider/a':['DOMAIN,a.example'],'category/a':['DOMAIN,a.example'],
                                           'special/realip':['DOMAIN,compat.example']})]:
                root=Path(d)/label;root.mkdir();files=[]
                for name,rows in groups.items():
                    p=root/(name+'.list');p.parent.mkdir(exist_ok=True);p.write_text('\n'.join(rows)+'\n');files.append({'path':name+'.list'})
                (root/'manifest.json').write_text(json.dumps({'data_version':label,'summary':{},'files':files,'source_snapshot':[]}));roots.append(root)
            report=compare_directories(*roots)
            self.assertEqual(report['domain_language_by_purpose']['routing']['after']['domain_predicates'],1)
            self.assertEqual(report['domain_language_by_purpose']['realip']['new_domain_predicates_not_previously_covered'],1)


if __name__=='__main__':unittest.main()
