"""Product intent and adversarial scope checks, independent of live downloads."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from airroute_data.domains import build_domains, load_products

ROOT = Path(__file__).resolve().parents[1]


class CatalogueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.products = load_products(ROOT / 'config/products.json')
        cls.groups = {g['id']: g for g in cls.products['groups']}

    def test_requested_use_categories_are_actual_required_products(self):
        expected = {'ai', 'development', 'packages', 'cloud-platform', 'cloud-storage',
                    'productivity', 'collaboration', 'conferencing', 'social', 'messaging',
                    'video-on-demand', 'live-streaming', 'audio', 'gaming', 'education',
                    'media', 'search', 'maps', 'shopping', 'finance', 'ru-services'}
        for name in expected:
            group = self.groups['category/' + name]
            self.assertTrue(group['required_output'])
            self.assertTrue(group.get('selectors') or group.get('includes'))
            self.assertTrue(group.get('purpose'))
            self.assertTrue(group.get('content_types'))

    def test_requested_providers_and_services_are_never_silent_gaps(self):
        providers = {'apple', 'google', 'microsoft', 'meta', 'amazon', 'adobe', 'samsung',
                     'sony', 'naver', 'kakao', 'yandex', 'vk'}
        services = {'openai', 'claude', 'gemini', 'perplexity', 'github', 'gitlab',
                    'docker-hub', 'huggingface', 'icloud', 'google-drive', 'onedrive',
                    'dropbox', 'microsoft365', 'notion', 'telegram', 'discord',
                    'whatsapp', 'signal', 'slack', 'teams', 'zoom', 'x', 'reddit',
                    'facebook', 'instagram', 'youtube', 'netflix', 'disney-plus',
                    'prime-video', 'max', 'spotify', 'apple-music', 'steam',
                    'epic-games', 'battle-net', 'xbox', 'playstation', 'nintendo'}
        for prefix, names in [('provider', providers), ('service', services)]:
            for name in names:
                group = self.groups[prefix + '/' + name]
                self.assertTrue(group['required_output'])
                self.assertTrue(group['selectors'])
                self.assertTrue(group.get('purpose'))

    def test_every_independent_service_remains_in_a_use_category(self):
        members = {name for group in self.groups.values()
                   if group['id'].startswith('category/')
                   for name in group.get('includes', [])}
        services = {name for name in self.groups if name.startswith('service/')}
        self.assertEqual(services - members, set())
        self.assertIn('service/teams', self.groups['category/collaboration']['includes'])
        self.assertIn('service/teams', self.groups['category/conferencing']['includes'])

    def test_named_supplemental_service_lists_have_a_real_bounded_admission(self):
        count = 0
        for group in self.groups.values():
            if not group['id'].startswith('service/'):
                continue
            for selector in group.get('selectors', []):
                if selector['source'] == 'blackmatrix':
                    count += 1
                    self.assertEqual(selector.get('mode'), 'primary')
                    self.assertTrue(selector['owned_roots'])
                    self.assertTrue(selector['domain_only'])
                    self.assertTrue(selector['bounded_service'])
        self.assertGreater(count, 20)

    def _scoped_build(self, name, selector_source, files):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for file, content in files.items():
            target = root / file
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        selected = deepcopy(self.groups[name])
        selected['selectors'] = [s for s in selected['selectors'] if s['source'] == selector_source]
        selected.pop('includes', None)
        products = {'schema': 1, 'groups': [{'id': 'region/cn', 'selectors': []}, selected]}
        sources = [{'id': selector_source, 'format': 'dlc' if selector_source == 'dlc' else 'surge', 'path': str(root)}]
        groups, report = build_domains(sources, products)
        self.assertEqual(report['unavailable_selectors'], [])
        return groups[name], report

    def test_drive_named_list_does_not_bypass_shared_platform_risk(self):
        rows, report = self._scoped_build('service/google-drive', 'blackmatrix', {
            'rule/Surge/GoogleDrive/GoogleDrive.list':
                'DOMAIN-SUFFIX,drive.google.com\nDOMAIN-SUFFIX,docs.google.com\n'
                'DOMAIN-SUFFIX,googleusercontent.com\nDOMAIN,www.googleapis.com\n'
                'USER-AGENT,Google.Drive*\nPROCESS-NAME,BackupandSync\n',
        })
        self.assertEqual(set(rows), {'DOMAIN-SUFFIX,drive.google.com', 'DOMAIN-SUFFIX,docs.google.com'})
        self.assertGreaterEqual(len(report['quarantined']), 4)

    def test_cloud_control_plane_excludes_customer_hosts(self):
        rows, _ = self._scoped_build('category/cloud-platform', 'dlc', {
            'data/aws': 'aws.amazon.com\namazonaws.com\ncloudfront.net\nfull:customer.s3.amazonaws.com\n',
            'data/azure': 'full:azure.microsoft.com\nazurewebsites.net\n',
            'data/digitalocean': 'digitalocean.com\ndigitaloceanspaces.com\n',
            'data/vultr': 'vultr.com\n',
        })
        self.assertIn('DOMAIN-SUFFIX,aws.amazon.com', rows)
        self.assertIn('DOMAIN,azure.microsoft.com', rows)
        self.assertNotIn('DOMAIN-SUFFIX,amazonaws.com', rows)
        self.assertNotIn('DOMAIN-SUFFIX,cloudfront.net', rows)
        self.assertNotIn('DOMAIN-SUFFIX,digitaloceanspaces.com', rows)
        self.assertFalse(any('customer.' in row or 'azurewebsites' in row for row in rows))

    def test_google_provider_does_not_identify_arbitrary_cloud_tenants(self):
        rows, _ = self._scoped_build('provider/google', 'dlc', {
            'data/google': 'google.com\nappspot.com\ncloudfunctions.net\nfirebaseapp.com\nfirebaseio.com\nrun.app\nweb.app\nfull:unrelated-customer.appspot.com\nfull:unrelated-customer.web.app\n',
        })
        self.assertEqual(rows, ['DOMAIN-SUFFIX,google.com'])

    def test_disney_plus_is_not_the_corporate_parks_collection(self):
        rows, _ = self._scoped_build('service/disney-plus', 'dlc', {
            'data/disney': 'disneyplus.com\ndssott.com\ndisneylandparis.com\ndisneycareers.com\nshopdisney.com\n',
        })
        self.assertEqual(set(rows), {'DOMAIN-SUFFIX,disneyplus.com', 'DOMAIN-SUFFIX,dssott.com'})

    def test_legacy_directory_checklist_is_explicit_and_not_an_import_promise(self):
        migration = json.loads((ROOT / 'config/catalogue-migration.json').read_text())
        rows = migration['entries']
        self.assertEqual(len(rows), migration['source']['entries'])
        self.assertEqual(len({row['legacy_id'] for row in rows}), len(rows))
        self.assertGreater(len(rows), 300)
        special = json.loads((ROOT / 'config/special.json').read_text())
        targets = set(self.groups) | {g['id'] for g in special['groups']}
        regions = json.loads((ROOT / 'config/regions.json').read_text())
        targets |= {'region/' + r['key'] for r in regions['regions']}
        for row in rows:
            self.assertIn(row['status'], {'retain', 'merge', 'deprecate', 'gap'})
            self.assertTrue(row['reason'])
            if row['status'] in {'retain', 'merge'}:
                self.assertTrue(row['targets'])
                self.assertTrue(set(row['targets']) <= targets, row)
