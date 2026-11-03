"""Regional source identities and fixed migration corpus; no target/network queries."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from airroute_data.acquire import _github_commit, acquire_sources, verify_snapshot

ROOT = Path(__file__).resolve().parents[1]
LEGACY_REF = '20a3b237005292e60b62603e934b3972348366b4'


class RegionalSourceTests(unittest.TestCase):
    def setUp(self):
        self.config = ROOT / 'config/sources.json'
        self.sources = {s['id']: s for s in json.loads(self.config.read_text())['sources']}

    def test_selected_cn_companions_are_real_explicit_paths_not_ip_only_lists(self):
        required = {
            'blackmatrix': {'rule/Surge/China/China_Domain.list', 'rule/Surge/ChinaMax/ChinaMax_Domain.list'},
            'acl4ssr': {'Clash/ChinaDomain.list', 'Clash/ChinaMedia.list'},
            'sukka': {'List/non_ip/domestic.conf', 'List/non_ip/domestic_cdn.conf'},
        }
        for sid, paths in required.items():
            with self.subTest(source=sid):
                self.assertLessEqual(paths, set(self.sources[sid]['paths']))
                self.assertEqual(self.sources[sid]['role'], 'domains')
                self.assertTrue(self.sources[sid]['domain_role'])
                self.assertTrue(self.sources[sid]['shared_upstream_risk'])
        self.assertNotIn('List/non_ip/direct.conf', self.sources['sukka']['paths'])

    def test_legacy_reference_is_frozen_and_not_an_identity_or_geo_vote(self):
        source = self.sources['legacy-cn']
        self.assertEqual(source['ref'], LEGACY_REF)
        self.assertEqual(source['repo'], 'airrelay/rules')
        self.assertEqual(source['paths'], ['region/cn.list'])
        self.assertEqual(source['role'], 'legacy-domain-reference')
        self.assertEqual(source['domain_role'], 'frozen-semantic-baseline')
        self.assertIn('unknown', source['lineage'])
        self.assertIn('unknown', source['field_semantics'])
        self.assertNotIn('requires_env', source)
        with patch('airroute_data.acquire._request') as network:
            self.assertEqual(_github_commit(source['repo'], source['ref'], {}), LEGACY_REF)
        network.assert_not_called()

    def test_domain_baseline_can_be_acquired_without_country_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / 'fixture'
            fixture.mkdir()
            raw = b'DOMAIN,market.example\nIP-CIDR,1.0.1.0/24\n'
            (fixture / 'legacy-cn').write_bytes(raw)
            with patch.dict('os.environ', {}, clear=True), patch('airroute_data.acquire._request') as network:
                snapshot = acquire_sources(self.config, root / 'snapshot', fixture_dir=fixture, source_ids=['legacy-cn'])
            network.assert_not_called()
            baseline = next(s for s in snapshot['sources'] if s['id'] == 'legacy-cn')
            self.assertEqual(baseline['status'], 'available')
            self.assertEqual(baseline['role'], 'legacy-domain-reference')
            self.assertEqual(baseline['ref'], LEGACY_REF)
            self.assertEqual(hashlib.sha256((root / 'snapshot' / baseline['path']).read_bytes()).hexdigest(), hashlib.sha256(raw).hexdigest())
            self.assertTrue(all(s['status'] == 'not-selected' for s in snapshot['sources'] if s['id'] != 'legacy-cn'))
            verify_snapshot(root / 'snapshot')

    def test_country_access_requirements_remain_independent(self):
        self.assertEqual({sid for sid, s in self.sources.items() if s['role'] == 'country'},
                         {'maxmind', 'dbip', 'ipinfo', 'ip2location', 'iplocate'})
        self.assertEqual(self.sources['dlc']['domain_role'], 'classification-primary')
        self.assertFalse(self.sources['legacy-cn'].get('country'))


if __name__ == '__main__':
    unittest.main()
