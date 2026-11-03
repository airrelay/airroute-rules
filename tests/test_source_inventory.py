"""Production source wiring, not a substitute for real acquisition evidence."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from airroute_data.acquire import acquire_sources


ROOT = Path(__file__).resolve().parents[1]


class SourceInventoryTests(unittest.TestCase):
    def setUp(self):
        self.config = ROOT / "config/sources.json"
        self.sources = {s["id"]: s for s in json.loads(self.config.read_text())["sources"]}

    def test_missing_provider_credentials_are_reported_without_network_or_sample_fallback(self):
        protected = [s["id"] for s in self.sources.values() if s.get("role") == "country" and s.get("requires_env")]
        self.assertEqual(set(protected), {"maxmind", "ipinfo", "ip2location"})
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {}, clear=True), mock.patch("airroute_data.acquire._request") as network:
            snapshot = acquire_sources(self.config, Path(directory) / "snapshot", source_ids=protected)
        network.assert_not_called()
        for source in snapshot["sources"]:
            if source["id"] in protected:
                self.assertEqual(source["status"], "missing-credentials")
                self.assertNotIn("path", source)
                self.assertNotIn("sha256", source)
            else:
                self.assertEqual(source["status"], "not-selected")

    def test_every_configured_selected_file_is_actually_acquired(self):
        products = json.loads((ROOT / "config/products.json").read_text())
        for group in products["groups"]:
            for selector in group.get("selectors", []):
                if "source" not in selector:
                    continue
                source = self.sources[selector["source"]]
                if selector.get("path") and source.get("transport") == "github_files":
                    self.assertIn(selector["path"], source["paths"], (group["id"], selector))
        for view in products.get("auxiliary_views", []):
            self.assertIn(view["path"], self.sources[view["source"]]["paths"])

    def test_geolocation_and_auxiliary_semantics_remain_separate(self):
        countries = {s["id"] for s in self.sources.values() if s.get("role") == "country"}
        self.assertEqual(countries, {"maxmind", "dbip", "ipinfo", "ip2location", "iplocate"})
        for sid in countries:
            source = self.sources[sid]
            self.assertEqual(source["address_families"], [4, 6])
            self.assertTrue(source["field_semantics"])
            self.assertTrue(source["documentation"].startswith("https://"))
        for sid in ("iana-special-v4", "iana-special-v6"):
            self.assertEqual(self.sources[sid]["role"], "special-reference")
        # Fetching a noncommercial reference does not authorize its use in
        # public derivatives, nor count as a sixth geolocation input.
        self.assertFalse(self.sources["cn-17mon"]["publish_allowed"])
        self.assertEqual(self.sources["cn-17mon"]["role"], "cn-reference")
        # The generated compatibility list documents its upstream ancestry;
        # it must never become a sixth physical-country input or extra vote.
        compat = self.sources["dustinwin-fakeip"]
        self.assertNotIn(compat["role"], {"country", "geo"})
        self.assertTrue(any("category-ntp" in url for url in compat["upstream_references"]))
        self.assertTrue(any("ShellCrash" in url for url in compat["upstream_references"]))


if __name__ == "__main__":
    unittest.main()
