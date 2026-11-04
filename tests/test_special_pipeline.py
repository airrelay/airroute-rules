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

    def test_full_candidate_and_flat_export_include_special_and_realip(self):
        root, manifest = self.candidate()
        self.assertIn("special/realip", manifest["product_catalogue"])
        self.assertIn("special/lan", manifest["product_catalogue"])
        public = _public_manifest(manifest)
        names = {r["path"] for r in public["files"]}
        self.assertIn("special/realip.list", names)
        self.assertIn("special/lan.list", names)
        self.assertNotIn("reports/special.json", names)
        self.assertNotIn("versions", names)
        self.assertTrue(all(s.startswith(("DOMAIN,", "DOMAIN-SUFFIX,", "DOMAIN-KEYWORD,")) for s in
                            (root / "special/realip.list").read_text().splitlines()))
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

    def test_manifest_and_lists_reject_content_mismatch(self):
        root, manifest = self.candidate()
        path = root / "special/realip.list"
        path.write_text(path.read_text() + "DOMAIN,new.example\n")
        with self.assertRaises(ValueError):
            validate_candidate(root)

    def test_realip_merged_output_has_no_legacy_dns_paths(self):
        root, manifest = self.candidate()
        names = {row["path"] for row in _public_manifest(manifest)["files"]}
        self.assertIn("special/realip.list", names)
        self.assertFalse(any(name.startswith("dns/") for name in names))
        self.assertFalse(any("realip-optional" in name for name in names))


if __name__ == "__main__":
    unittest.main()
