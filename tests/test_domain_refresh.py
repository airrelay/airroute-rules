"""Domain refresh keeps validated IP releases intact; entirely offline fixtures."""
import hashlib
import json
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from airroute_data.acquire import acquire_sources
from airroute_data.pipeline import build_domain_candidate
from airroute_data.publish import _public_manifest
from airroute_data.validation import file_digest, validate_candidate


class DomainRefreshTests(unittest.TestCase):
    def setUp(self):
        from tests.test_pipeline import PipelineTests, ROOT
        self.fixture = PipelineTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f = self.fixture
        self.repo_root = ROOT

    def baseline(self, special=False):
        if special:
            shutil.copyfile(self.repo_root / 'config/special.json', self.f.config / 'special.json')
        base, manifest = self.f.run_build('base')
        # Exercise the actual flat release inventory, with internal reports absent.
        public = _public_manifest(manifest)
        shutil.rmtree(base / 'reports')
        (base / 'README.md').unlink()
        (base / 'manifest.json').write_text(json.dumps(public))
        return base, public

    def snapshot(self):
        (self.f.fixture / 'dlc/data/cn-identity').write_text('domain:mainland.example\nfull:only.mainland.example\nfull:new.mainland-market.example\n')
        current = self.f.root / 'domain-input'
        acquire_sources(self.f.source_config, current, fixture_dir=self.f.fixture, source_ids=['dlc'])
        return current / 'snapshot.json'

    def test_mixed_market_memberships_need_no_exclusion_proof(self):
        target, manifest = self.f.run_build()
        self.assertIn('mainland.example', (target/'category/example.list').read_text())
        self.assertTrue(validate_candidate(target)['valid'])

    def test_domain_only_needs_no_geo_inputs_or_parsers_and_preserves_source_versions(self):
        base, old = self.baseline(special=True)
        snapshot = self.snapshot()
        target = self.f.root / 'refreshed'
        with patch('airroute_data.geo.fuse_country', side_effect=AssertionError('Geo was recomputed')), \
             patch('airroute_data.routing.fuse_asn', side_effect=AssertionError('ASN was recomputed')), \
             patch('airroute_data.routing.fuse_routes', side_effect=AssertionError('BGP comparisons were recomputed')):
            manifest = build_domain_candidate(snapshot, target, self.f.config, baseline=base)
        for name in ('special/asn.ardb', 'regions.json'):
            self.assertEqual((base / name).read_bytes(), (target / name).read_bytes())
        for path in (base / 'region').glob('*.list'):
            ips = lambda p: [line for line in p.read_text().splitlines() if line.startswith('IP-CIDR')]
            self.assertEqual(ips(path), ips(target / 'region' / path.name))
        self.assertIn('DOMAIN,new.mainland-market.example', (target / 'region/cn-domain.list').read_text())
        self.assertTrue((target / 'special/realip.list').is_file())
        old_sources = {s['id']: s for s in old['source_snapshot']}
        new_sources = {s['id']: s for s in manifest['source_snapshot']}
        self.assertEqual(old_sources['country-a'], new_sources['country-a'])
        self.assertNotEqual(old_sources['dlc']['version'], new_sources['dlc']['version'])
        context = manifest['generation_context']
        self.assertEqual(context['retained_ip_base']['data_version'], old['data_version'])
        self.assertEqual(context['retained_ip_base']['manifest_sha256'], file_digest(base / 'manifest.json'))
        self.assertTrue(validate_candidate(target)['valid'])

    def test_domain_refresh_rejects_corrupt_base_and_changed_registry(self):
        base, _ = self.baseline()
        snapshot = self.snapshot()
        original = (base / 'special/asn.ardb').read_bytes()
        (base / 'special/asn.ardb').write_bytes(original + b'bad')
        with self.assertRaisesRegex(ValueError, 'digest/length mismatch'):
            build_domain_candidate(snapshot, self.f.root / 'bad', self.f.config, baseline=base)
        self.assertFalse((self.f.root / 'bad').exists())
        (base / 'special/asn.ardb').write_bytes(original)
        registry_path = self.f.config / 'regions.json'
        registry = json.loads(registry_path.read_text()); registry['version'] = 'changed'
        registry_path.write_text(json.dumps(registry))
        with self.assertRaisesRegex(ValueError, 'cannot change the Geo region registry'):
            build_domain_candidate(snapshot, self.f.root / 'bad-registry', self.f.config, baseline=base)

    def test_new_country_snapshot_is_not_claimed_as_recomputed_geo(self):
        base, old = self.baseline()
        (self.f.fixture / 'country-a').write_text('network,country_code\n8.8.8.0/24,US\n')
        current = self.f.root / 'all-new-inputs'
        acquire_sources(self.f.source_config, current, fixture_dir=self.f.fixture)
        manifest = build_domain_candidate(current / 'snapshot.json', self.f.root / 'reuse', self.f.config, baseline=base)
        for name in ('country-a', 'country-b', 'maxmind-asn', 'routes', 'iana-alloc-v4', 'iana-alloc-v6', 'iana-special-v4', 'iana-special-v6'):
            before = next(s for s in old['source_snapshot'] if s['id'] == name)
            after = next(s for s in manifest['source_snapshot'] if s['id'] == name)
            self.assertEqual(before, after)

    def test_repeated_refresh_does_not_chain_versions_or_grow_attribution(self):
        base, _ = self.baseline()
        snapshot = self.snapshot()
        first = self.f.root / 'first'
        one = build_domain_candidate(snapshot, first, self.f.config, baseline=base)
        second = self.f.root / 'second'
        two = build_domain_candidate(snapshot, second, self.f.config, baseline=first)
        self.assertEqual(one['data_version'], two['data_version'])
        self.assertEqual(one['generation_context'], two['generation_context'])
        self.assertEqual((first / 'ATTRIBUTION.md').read_bytes(), (second / 'ATTRIBUTION.md').read_bytes())

    def test_validation_rechecks_claimed_binary_base_and_retained_sources(self):
        base, _ = self.baseline()
        target = self.f.root / 'refresh'
        manifest = build_domain_candidate(self.snapshot(), target, self.f.config, baseline=base)
        manifest['generation_context']['retained_ip_base']['files']['special/asn.ardb']['sha256'] = '0' * 64
        (target / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'changed retained IP base'):
            validate_candidate(target)
        manifest['generation_context']['retained_ip_base']['files']['special/asn.ardb']['sha256'] = file_digest(target / 'special/asn.ardb')
        next(s for s in manifest['source_snapshot'] if s['id'] == 'country-a')['version'] = 'not-the-base'
        (target / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'misrepresents retained IP sources'):
            validate_candidate(target)

    def test_legacy_reports_are_compact_semantic_comparisons_not_absolute_old_truth(self):
        body = 'DOMAIN,api.mainland.example\nDOMAIN-SUFFIX,unsupported.example\n'
        path = self.f.fixture / 'legacy-cn'; path.write_text(body)
        config = json.loads(self.f.source_config.read_text())
        config['sources'].append({'id': 'legacy-cn', 'role': 'legacy-domain-reference', 'format': 'surge',
                                  'lineage': 'unknown', 'publish_allowed': True})
        self.f.source_config.write_text(json.dumps(config))
        self.f.snapshot = self.f.root / 'with-legacy'
        snapshot = acquire_sources(self.f.source_config, self.f.snapshot, fixture_dir=self.f.fixture)
        source = next(s for s in snapshot['sources'] if s['id'] == 'legacy-cn')
        legacy = {'schema': 1, 'group': 'region/cn-domain', 'source': {'id': 'legacy-cn', 'version': source['version'],
                  'path': 'unused', 'sha256': hashlib.sha256(body.encode()).hexdigest(), 'records': 2, 'domain_records': 2}}
        (self.f.config / 'legacy-domains.json').write_text(json.dumps(legacy))
        target, manifest = self.f.run_build()
        report = json.loads((target / 'reports/legacy-region-cn-domain-domains.json').read_text())
        self.assertNotIn('records', report)
        self.assertEqual(report['counts']['covered-semantically'], 1)
        self.assertEqual(report['counts']['pending-verification'], 1)
        self.assertEqual(manifest['legacy_coverage']['region/cn-domain']['counts'], report['counts'])
        self.assertFalse(list((target / 'reports').glob('legacy*.jsonl')))
        self.assertEqual(report['samples_by_reason'][next(k for k in report['samples_by_reason'] if k.startswith('pending'))][0]['upstream_provenance'], 'unknown')


if __name__ == '__main__':
    unittest.main()
