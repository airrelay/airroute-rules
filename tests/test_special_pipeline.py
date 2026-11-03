import json
from pathlib import Path
import shutil
import unittest

from airroute_data.publish import _public_manifest
from airroute_data.validation import file_digest, validate_candidate


class SpecialPipelineTests(unittest.TestCase):
    def candidate(self):
        # Reuse the same small frozen dual-stack/MOAS pipeline fixture rather
        # than downloading anything or constructing a second test framework.
        from test_pipeline import PipelineTests, ROOT
        fixture = PipelineTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        shutil.copyfile(ROOT / "config/special.json", fixture.config / "special.json")
        return fixture.run_build()

    def test_full_candidate_and_flat_export_include_special_dns_separately(self):
        root, manifest = self.candidate()
        self.assertIn("dns/realip", manifest["product_catalogue"])
        self.assertIn("special/lan", manifest["product_catalogue"])
        public = _public_manifest(manifest)
        names = {r["path"] for r in public["files"]}
        self.assertIn("dns/realip.list", names)
        self.assertIn("special/lan.list", names)
        self.assertNotIn("reports/special.json", names)
        self.assertNotIn("versions", names)
        self.assertTrue(all(s.startswith(("DOMAIN,", "DOMAIN-SUFFIX,")) for s in
                            (root / "dns/realip.list").read_text().splitlines()))
        self.assertEqual(validate_candidate(root)["valid"], True)

    def test_publication_rechecks_lan_fakeip_even_with_updated_digest(self):
        root, manifest = self.candidate()
        path = root / "special/lan.list"
        path.write_text(path.read_text() + "IP-CIDR,198.18.0.0/15\n")
        for r in manifest["files"]:
            if r["path"] == "special/lan.list":
                r.update(bytes=path.stat().st_size, sha256=file_digest(path))
        (root / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "LAN contains"):
            validate_candidate(root)

    def test_rehashed_geo_cannot_assign_documentation_space(self):
        from airroute_data.ardb import read_database, write_database
        root, manifest = self.candidate()
        path = root / "geo.ardb"
        groups = read_database(path, "geo", allowed_geo_ids=range(1, 17))
        groups[1].append("3fff::/20")
        write_database(path, "geo", groups, allowed_geo_ids=range(1, 17))
        for record in manifest["files"]:
            if record["path"] == "geo.ardb":
                record.update(bytes=path.stat().st_size, sha256=file_digest(path))
        (root / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "non-geographic special address"):
            validate_candidate(root)


    def test_publication_rejects_rehashed_missing_lan_baseline(self):
        for removed in ("IP-CIDR,172.16.0.0/12", "DOMAIN-SUFFIX,home.arpa"):
            with self.subTest(removed=removed):
                root, manifest = self.candidate()
                path = root / "special/lan.list"
                path.write_text("\n".join(row for row in path.read_text().splitlines() if row != removed) + "\n")
                for record in manifest["files"]:
                    if record["path"] == "special/lan.list":
                        record.update(bytes=path.stat().st_size, sha256=file_digest(path))
                (root / "manifest.json").write_text(json.dumps(manifest))
                with self.assertRaisesRegex(ValueError, "mandatory .* coverage is missing"):
                    validate_candidate(root)

    def test_publication_rejects_rehashed_missing_realip_baseline(self):
        root, manifest = self.candidate()
        path = root / "dns/realip.list"
        path.write_text("\n".join(row for row in path.read_text().splitlines() if row != "DOMAIN,ipv4only.arpa") + "\n")
        for record in manifest["files"]:
            if record["path"] == "dns/realip.list":
                record.update(bytes=path.stat().st_size, sha256=file_digest(path))
        (root / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "mandatory domain coverage is missing"):
            validate_candidate(root)


if __name__ == "__main__":
    unittest.main()
