"""Product configuration and literal upstream semantics, no identity admission gates."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from airroute_data.domains import build_domains,load_products
ROOT=Path(__file__).resolve().parents[1]


class CatalogueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.products=load_products(ROOT/'config/products.json');cls.groups={g['id']:g for g in cls.products['groups']}

    def test_requested_categories_remain_real_configured_products(self):
        names={'ai','development','packages','cloud-platform','cloud-storage','productivity','collaboration','conferencing',
               'social','messaging','video-on-demand','live-streaming','audio','gaming','education','media','search','maps','shopping','finance','ru-services'}
        for name in names:
            group=self.groups['category/'+name]
            self.assertTrue(group.get('selectors') or group.get('includes'));self.assertTrue(group.get('purpose'))

    def test_company_and_service_targets_share_provider_category_without_alias_products(self):
        providers={'apple','google','microsoft','meta','amazon','adobe','samsung','sony','naver','kakao','yandex','vk'}
        services={'openai','claude','gemini','perplexity','github','gitlab','docker-hub','huggingface','icloud','google-drive','onedrive',
                  'dropbox','microsoft365','notion','telegram','discord','whatsapp','signal','slack','teams','zoom','x','reddit',
                  'facebook','instagram','youtube','netflix','disney-plus','prime-video','max','spotify','apple-music','steam',
                  'epic-games','battle-net','xbox','playstation','nintendo'}
        members={name for g in self.groups.values() if g['id'].startswith('category/') for name in g.get('includes',[])}
        for name in providers|services:self.assertIn('provider/'+name,self.groups)
        self.assertTrue({'provider/'+name for name in services}<=members)
        self.assertFalse(any(name.startswith(('service/','dns/')) for name in self.groups))
        self.assertIn('provider/teams',self.groups['category/collaboration']['includes'])
        self.assertIn('provider/teams',self.groups['category/conferencing']['includes'])

    def test_removed_generic_admission_limits_are_not_hidden_in_selectors(self):
        for group in self.groups.values():
            for selector in group.get('selectors',[]):
                for key in ('owned_roots','bounded_service','domain_only'):
                    self.assertNotIn(key,selector,(group['id'],key))
                self.assertFalse(set(selector.get('attributes',[]))&{'-cn','!cn'})

    def build_rows(self,rows,groups,cn=False):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);(root/'upstream.list').write_text('\n'.join(rows)+'\n')
        return build_domains([{'id':'community','format':'surge','path':str(root/'upstream.list')}],
            {'schema':1,'groups':[{'id':'region/cn-domain','selectors':[{'source':'community'}] if cn else []},*groups]})

    def test_mature_list_retains_exact_suffix_keyword_regex_and_service_ip(self):
        rows=['DOMAIN,endpoint.shared.example','DOMAIN-SUFFIX,shared.example','DOMAIN-KEYWORD,brand',
              r'DOMAIN-REGEX,^api[0-9]+\.example$','IP-CIDR,1.2.3.0/24','IP-CIDR6,2001:4860::/48',
              'USER-AGENT,Unsupported*']
        output,report=self.build_rows(rows,[{'id':'provider/example','selectors':[{'source':'community','mode':'primary'}]}])
        self.assertIn('DOMAIN-SUFFIX,shared.example',output['provider/example'])
        self.assertIn('DOMAIN-KEYWORD,brand',output['provider/example'])
        self.assertIn(r'DOMAIN-REGEX,^api[0-9]+\.example$',output['provider/example'])
        self.assertIn('IP-CIDR,1.2.3.0/24',output['provider/example'])
        self.assertIn('IP-CIDR6,2001:4860::/48',output['provider/example'])
        self.assertFalse(any('USER-AGENT' in row for row in output['provider/example']))
        self.assertTrue(report['quarantined'])

    def test_cn_membership_does_not_remove_global_category_member(self):
        output,_=self.build_rows(['DOMAIN-SUFFIX,mainland.example'],[
            {'id':'provider/example','selectors':[{'source':'community'}]},
            {'id':'category/example','includes':['provider/example'],'selectors':[{'source':'community'}]}],cn=True)
        self.assertIn('DOMAIN-SUFFIX,mainland.example',output['region/cn-domain'])
        self.assertIn('DOMAIN-SUFFIX,mainland.example',output['provider/example'])
        self.assertIn('DOMAIN-SUFFIX,mainland.example',output['category/example'])

    def test_legacy_mapping_targets_only_current_products(self):
        mapping=json.loads((ROOT/'config/catalogue-migration.json').read_text())
        entries=mapping['entries'];self.assertEqual(len(entries),mapping['source']['entries'])
        self.assertEqual(len({r['legacy_id'] for r in entries}),len(entries))
        special=json.loads((ROOT/'config/special.json').read_text())
        targets=set(self.groups)|{g['id'] for g in special['groups']}
        registry=json.loads((ROOT/'config/regions.json').read_text())
        targets|={'region/'+('cn-ip' if r['key']=='cn' else r['key']) for r in registry['regions']}
        for row in entries:
            self.assertIn(row['status'],{'retain','merge','deprecate','gap'});self.assertTrue(row['reason'])
            if row['status'] in {'retain','merge'}:self.assertTrue(set(row['targets'])<=targets,row)


if __name__=='__main__':unittest.main()
