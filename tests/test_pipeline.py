"""End-to-end frozen synthetic inputs; no target measurements or paid services."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from airroute_data.acquire import acquire_sources
from airroute_data.pipeline import build
from airroute_data.validation import file_digest, validate_candidate


ROOT = Path(__file__).resolve().parents[1]


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = self.root / "fixture"
        self.fixture.mkdir()
        a = "network,country_code\n1.0.1.0/24,CN\n2.2.2.0/24,RU\n1.1.1.0/24,AU\n2001:4860:1::/48,US\n"
        b = "network,country_code\n1.0.1.0/24,CN\n2.2.2.0/24,RU\n1.1.1.0/25,AU\n1.1.1.128/25,SG\n2001:4860:1::/48,US\n"
        (self.fixture / "country-a").write_text(a)
        (self.fixture / "country-b").write_text(b)
        (self.fixture / "routes").write_text("1\t1.0.1.0/24\t5\n2\t1.0.1.0/24\t5\n3\t2.2.2.0/24\t5\n4\t2001:4860:1::/48\t5\n")
        asn = self.fixture / "maxmind-asn"
        asn.mkdir()
        (asn / "GeoLite2-ASN-Blocks-IPv4.csv").write_text(
            "network,autonomous_system_number,autonomous_system_organization\n"
            "1.0.1.0/24,13335,Fixture Cloud\n2.2.2.0/24,15169,Fixture Search\n1.1.1.0/24,13335,Fixture Cloud\n")
        (asn / "GeoLite2-ASN-Blocks-IPv6.csv").write_text(
            "network,autonomous_system_number,autonomous_system_organization\n2001:4860:1::/48,15169,Fixture Search\n")
        (self.fixture / "cn-reference").write_text("1.0.1.0/24\n1.1.1.0/24\n")
        tree = self.fixture / "dlc" / "data"
        tree.mkdir(parents=True)
        (tree / "category-ntp").write_text("full:time.fixture.example\n")
        (tree / "category-stun").write_text("full:stun.fixture.example\n")
        (tree / "private").write_text("domain:local\ndomain:home.arpa\n")
        (tree / "cn-identity").write_text("domain:mainland.example\nfull:only.mainland.example\n")
        (tree / "service").write_text("domain:overseas.example\ndomain:mainland.example\nregexp:^(?:api|web)\\.foreign\\.example$\n")
        sources = [{"id": "country-a", "role": "country", "format": "country-csv", "lineage": "publisher-a", "address_families":[4,6]},
                   {"id": "country-b", "role": "country", "format": "country-csv", "lineage": "publisher-b", "address_families":[4,6]},
                   {"id": "routes", "role": "routing", "format": "ris-whois", "lineage": "ris", "address_families":[4,6]},
                   {"id": "cn-reference", "role": "cn-reference", "format": "cidr-list", "lineage": "routing-reference", "country": "CN", "address_families":[4]},
                   {"id": "dlc", "role": "domains", "format": "dlc", "lineage": "dlc"}]
        sources.append({"id":"maxmind-asn","role":"asn","format":"maxmind-asn-csv", "lineage":"maxmind-geolite-asn",
                        "address_families":[4,6],"required":True})
        from input_fixtures import write_iana_fixture
        sources.extend(write_iana_fixture(self.fixture))
        for source in sources:source.update(publish_allowed=True, license="synthetic fixtures")
        self.source_config = self.root / "sources.json"
        self.source_config.write_text(json.dumps({"schema": 1, "sources": sources}))
        self.config = self.root / "config"
        self.config.mkdir()
        shutil.copyfile(ROOT / "config/regions.json", self.config / "regions.json")
        q = json.loads((ROOT / "config/quality.json").read_text())
        q.pop("per_product", None)
        (self.config / "quality.json").write_text(json.dumps(q))
        (self.config / "geo-policy.json").write_text(json.dumps({"schema":1,"primary_source":"country-a","source_order":["country-a","country-b"]}))
        (self.config / "products.json").write_text(json.dumps({"schema": 1, "groups": [
            {"id": "region/cn-domain", "selectors": [{"source": "dlc", "category": "cn-identity", "required": True}]},
            {"id": "category/example", "selectors": [{"source": "dlc", "category": "service"}]}]}))
        self.snapshot = self.root / "snapshot"
        acquire_sources(self.source_config, self.snapshot, fixture_dir=self.fixture)

    def refresh_snapshot(self,name):
        self.snapshot=self.root/name
        acquire_sources(self.source_config,self.snapshot,fixture_dir=self.fixture)

    def run_build(self, name="candidate", **kwargs):
        target = self.root / name
        return target, build(self.snapshot / "snapshot.json", target, self.config, **kwargs)

    def test_full_pipeline_reproducible_geo_list_moas_cn_exclusion(self):
        target, manifest = self.run_build()
        other, repeated = self.run_build("same-input")
        self.assertEqual(manifest, repeated)
        self.assertEqual(manifest["summary"]["country_lineages"], 2)
        cn = (target / "region/cn-domain.list").read_text()
        self.assertIn("DOMAIN-SUFFIX,mainland.example", cn)
        self.assertNotIn("IP-CIDR", cn)
        self.assertIn("IP-CIDR,1.0.1.0/24", (target / "region/cn-ip.list").read_text())
        self.assertIn("mainland.example", (target / "category/example.list").read_text())
        self.assertFalse((target / "geo.ardb").exists())
        self.assertFalse((target / "region/cn.list").exists())
        from airroute_data.ardb import read_database
        asn = read_database(target / "special/asn.ardb", "asn")
        self.assertIn("1.0.1.0/24", asn[13335])
        self.assertNotIn(1,asn)
        self.assertNotIn(2,asn)
        self.assertIn("2001:4860:1::/48",asn[15169])
        self.assertEqual(manifest["summary"]["asn_expected_families"],[4,6])
        self.assertEqual(manifest["summary"]["asn_input_families"],[4,6])
        report = json.loads((target / "reports/geo.json").read_text())
        issues = "".join((target / "reports" / part["path"]).read_text() for part in report["issue_files"])
        self.assertIn('"region_disagreement": true', issues)
        self.assertIn("missing-all-sources", issues)
        validate_candidate(target)

    def test_changed_input_rejected_before_calculation(self):
        frozen = self.snapshot / "sources/country-a/content"
        frozen.write_text("changed")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.run_build()

    def test_no_change_ignores_acquisition_wall_clock(self):
        target, one = self.run_build()
        metadata = self.snapshot / "snapshot.json"
        snapshot = json.loads(metadata.read_text())
        snapshot["created_at"] = "2099-01-01T00:00:00Z"
        for source in snapshot["sources"]:source["fetched_at"] = snapshot["created_at"]
        metadata.write_text(json.dumps(snapshot))
        _, two = self.run_build("clock-change")
        self.assertEqual(one["data_version"], two["data_version"])

    def test_corrupt_binary_or_list_even_rehashed_cannot_publish(self):
        target, manifest = self.run_build()
        p = target / "region/cn-ip.list"
        p.write_text(p.read_text().replace("1.0.1.0/24", "1.0.0.0/23"))
        for record in manifest["files"]:
            if record["path"] == "region/cn-ip.list":
                record.update(bytes=p.stat().st_size, sha256=file_digest(p))
        (target / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "summary|coverage"):
            validate_candidate(target)

    def test_enabled_participating_source_failure_is_not_silently_skipped(self):
        metadata=self.snapshot/"snapshot.json";snapshot=json.loads(metadata.read_text())
        snapshot["sources"][1]["status"]="unavailable";metadata.write_text(json.dumps(snapshot))
        with self.assertRaisesRegex(ValueError,"country-b.*not available"):
            self.run_build("missing-fallback")
        snapshot["sources"][1]["status"]="available";snapshot["sources"][0]["status"]="download-failed"
        metadata.write_text(json.dumps(snapshot))
        with self.assertRaisesRegex(ValueError,"country-a.*not available"):
            self.run_build("missing-primary")


    def test_formal_asn_requires_ipv6_file_even_when_bgp_has_ipv6(self):
        (self.fixture/'maxmind-asn/GeoLite2-ASN-Blocks-IPv6.csv').unlink()
        self.refresh_snapshot('missing-formal-v6')
        with self.assertRaisesRegex(ValueError,'IPv6|IPv4.*IPv6|both'):
            self.run_build('missing-formal-candidate')

    def test_frozen_iana_eligibility_distinguishes_geo_and_asn(self):
        path=self.fixture/'country-a'
        path.write_text(path.read_text()+'192.0.0.9/32,CN\n4000::/48,US\n')
        path=self.fixture/'maxmind-asn/GeoLite2-ASN-Blocks-IPv4.csv'
        path.write_text(path.read_text()+'192.0.0.9/32,13335,Fixture Anycast\n')
        path=self.fixture/'maxmind-asn/GeoLite2-ASN-Blocks-IPv6.csv'
        path.write_text(path.read_text()+'4000::/48,15169,Fixture Future Allocation\n')
        self.refresh_snapshot('eligibility-snapshot')
        target,manifest=self.run_build('eligibility-candidate')
        from airroute_data.ardb import read_database
        asn=read_database(target/'special/asn.ardb','asn')
        self.assertIn('192.0.0.9/32',asn[13335])
        self.assertNotIn('192.0.0.9',(target/'region/cn-ip.list').read_text())
        self.assertIn('IP-CIDR6,4000::/48',(target/'region/us.list').read_text())
        self.assertIn('4000::/48',asn[15169])
        self.assertTrue(manifest['address_eligibility']['geo'])
        self.assertTrue(validate_candidate(target)['valid'])


    def test_selected_auxiliary_file_missing_is_fatal_without_required_flag(self):
        path = self.config / "products.json"
        config = json.loads(path.read_text())
        config["auxiliary_views"] = [{"source": "dlc", "id": "missing-view", "path": "missing.list",
            "format": "surge-cidr-reference", "country": "CN", "address_families": [4]}]
        path.write_text(json.dumps(config))
        with self.assertRaisesRegex(ValueError, "participating auxiliary view.*missing-view"):
            self.run_build()

    def test_history_volume_does_not_block_valid_output(self):
        baseline, _ = self.run_build()
        manifest = json.loads((baseline / "manifest.json").read_text())
        manifest["summary"]["asn_prefixes"] *= 100
        (baseline / "manifest.json").write_text(json.dumps(manifest))
        target, result = self.run_build("changed", baseline=baseline)
        self.assertTrue(validate_candidate(target)["valid"])

    def test_output_does_not_overwrite_previous_candidate(self):
        target, _ = self.run_build()
        before = (target / "manifest.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "empty"):
            self.run_build()
        self.assertEqual(before, (target / "manifest.json").read_bytes())

    def test_auxiliary_product_views_and_bgp_visibility_are_compared_without_voting(self):
        reference = self.fixture / "bm"
        reference.mkdir()
        (reference / "china.list").write_text("IP-CIDR,1.0.1.0/24,no-resolve\nDOMAIN-SUFFIX,shared.example\nAND,((IP-CIDR,8.8.8.0/24),(DOMAIN,other.example))\n")
        sources = json.loads(self.source_config.read_text())
        sources["sources"].append({"id": "bm", "role": "domains", "format": "surge", "lineage": "bm", "publish_allowed": True})
        self.source_config.write_text(json.dumps(sources))
        self.snapshot = self.root / "aux-snapshot"
        acquire_sources(self.source_config, self.snapshot, fixture_dir=self.fixture)
        config = self.config / "products.json"
        products = json.loads(config.read_text())
        products["auxiliary_views"] = [{"source": "bm", "id": "bm-cn-ip", "path": "china.list", "format": "surge-cidr-reference", "country": "CN", "address_families":[4]}]
        config.write_text(json.dumps(products))
        target, _ = self.run_build()
        audit = json.loads((target / "reports/auxiliary.json").read_text())
        self.assertEqual(audit["input_rows"]["bm-cn-ip"], 1)
        self.assertEqual(audit["sources"]["bm-cn-ip"]["ipv4_region_cn_addresses"], 256)
        self.assertEqual(audit["sources"]["bgp-visible"]["ipv4_region_ru_addresses"], 256)
        self.assertNotIn("8.8.8.0/24", (target / "region/cn-ip.list").read_text())


if __name__ == "__main__":
    unittest.main()
