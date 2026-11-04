"""Production source wiring, not a substitute for real acquisition evidence."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from airroute_data.acquire import AcquisitionError, acquire_sources


ROOT = Path(__file__).resolve().parents[1]


class SourceInventoryTests(unittest.TestCase):
    def setUp(self):
        self.config = ROOT / "config/sources.json"
        self.sources = {s["id"]: s for s in json.loads(self.config.read_text())["sources"]}

    def test_enabled_missing_credentials_fail_without_network_or_fallback(self):
        protected = [s["id"] for s in self.sources.values()
                     if s.get("role") in {"country", "asn"} and s.get("requires_env")]
        self.assertEqual(set(protected), {"maxmind", "maxmind-asn", "ipinfo", "ip2location"})
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {}, clear=True), mock.patch("airroute_data.acquire._request") as network:
            for sid in protected:
                output = Path(directory) / sid
                with self.subTest(source=sid), self.assertRaisesRegex(AcquisitionError, sid + ": missing-credentials"):
                    acquire_sources(self.config, output, source_ids=[sid])
                snapshot = json.loads((output / "snapshot.json").read_text())
                self.assertEqual(snapshot["status"], "failed")
                failed = next(s for s in snapshot["sources"] if s["id"] == sid)
                self.assertEqual(failed["status"], "missing-credentials")
                self.assertNotIn("path", failed)
                self.assertNotIn("sha256", failed)
                self.assertTrue(failed["missing_env"])
                self.assertTrue(all(s["status"] == "not-selected" for s in snapshot["sources"] if s["id"] != sid))
        network.assert_not_called()

    def test_disabled_or_unselected_credentials_do_not_participate(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {}, clear=True), mock.patch("airroute_data.acquire._request") as network:
            root = Path(directory)
            config = root / "sources.json"
            config.write_text(json.dumps({"schema": 1, "sources": [{**self.sources["maxmind-asn"], "enabled": False}]}))
            disabled = acquire_sources(config, root / "disabled")
            self.assertEqual(disabled["status"], "complete")
            self.assertEqual(disabled["sources"][0]["status"], "disabled")
            unselected = acquire_sources(self.config, root / "unselected", source_ids=[])
            self.assertEqual(unselected["status"], "complete")
            self.assertTrue(all(s["status"] == "not-selected" for s in unselected["sources"]))
        network.assert_not_called()

    def test_official_asn_source_is_separate_from_country_and_bgp_inputs(self):
        source = self.sources["maxmind-asn"]
        self.assertEqual(source["role"], "asn")
        self.assertEqual(source["format"], "maxmind-asn-csv")
        self.assertEqual(source["address_families"], [4, 6])
        self.assertIn("/GeoLite2-ASN-CSV/", source["url"])
        self.assertIn("maxmind.com", source["documentation"])
        self.assertEqual(source["requires_env"], self.sources["maxmind"]["requires_env"])
        self.assertTrue(source.get("enabled", True))
        self.assertTrue(source["publish_allowed"])
        self.assertEqual({s["id"] for s in self.sources.values() if s["role"] == "asn"}, {"maxmind-asn"})
        policy = json.loads((ROOT / "config/geo-policy.json").read_text())
        self.assertNotIn("maxmind-asn", policy["source_order"])

    def test_four_live_iana_registries_have_distinct_nongeographic_roles(self):
        expected = {
            "iana-special-v4": ("special-reference", "iana-special-csv", 4, "iana-ipv4-special-registry"),
            "iana-special-v6": ("special-reference", "iana-special-csv", 6, "iana-ipv6-special-registry"),
            "iana-alloc-v4": ("address-space-reference", "iana-ipv4-allocation-csv", 4, "ipv4-address-space"),
            "iana-alloc-v6": ("address-space-reference", "iana-ipv6-allocation-csv", 6, "ipv6-unicast-address-assignments"),
        }
        policy = json.loads((ROOT / "config/geo-policy.json").read_text())
        for sid, (role, parser, family, registry) in expected.items():
            source = self.sources[sid]
            with self.subTest(source=sid):
                self.assertEqual(source["role"], role)
                self.assertEqual(source["format"], parser)
                self.assertEqual(source["address_families"], [family])
                self.assertTrue(source["url"].startswith("https://www.iana.org/assignments/" + registry + "/"))
                self.assertTrue(source["url"].endswith(".csv"))
                self.assertTrue(source.get("enabled", True))
                self.assertFalse(source.get("requires_env"))
                self.assertNotIn(sid, policy["source_order"])

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
