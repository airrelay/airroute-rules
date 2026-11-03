"""Russian-market selectors preserve named classifications without TLD unions."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from airroute_data.domains import CoverageIndex, DLC, RuleError, build_domains, load_products, normalize_rule

ROOT = Path(__file__).resolve().parents[1]


class RegionalDomainTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.fragment = json.loads((ROOT / "config/regional-domains.json").read_text())
        self.ru_groups = deepcopy([g for g in self.fragment["groups"]
                                   if g["id"] in {"region/ru", "category/ru-services"}])
        self.selector = next(g for g in self.ru_groups if g["id"] == "category/ru-services")["selectors"][0]
        files = {
            "cn": "ccb.com\ncn.shared.example\n",
            "tld-ru": "ru\nsu\nmoscow\nxn--p1ai\n",
            "category-ru": "include:tld-ru\ninclude:mts-ru\ninclude:rostelecom\ninclude:megafon\ninclude:t2-ru\n"
                "include:category-bank-ru\nbeeline.ru\npochta.ru\nmcc250.pub.3gppnetwork.org\n"
                "new-market-service.example\nru.com\nru.net\nadriver.ru @ads\nmetrics.example @telemetry\n"
                "my.games\nknightspeak.com\nvkcloud.kz\nyandexcloud.net\n"
                "full:bank.storage.yandexcloud.net\nshared.example\nfull:ru.shared.example\n",
            "mts-ru": "mts.ru @mobile\nfull:ims.mts.ru @mobile\n",
            "rostelecom": "rt.ru\n",
            "megafon": "megafon.ru\n",
            "t2-ru": "tele2.ru\n",
            "category-bank-ru": "ru.ccb.com\nbank.example\n",
        }
        for name, text in files.items():
            (self.data / name).write_text(text)
        self.source = {"id": "dlc", "format": "dlc", "path": str(self.root), "status": "available", "lineage": "dlc"}

    def build(self, sources=None):
        products = {"schema": 1, "groups": [
            {"id": "region/cn", "selectors": [{"source": "dlc", "category": "cn"}]}, *self.ru_groups]}
        return build_domains(sources or [self.source], products)

    def test_include_subtree_exclusion_keeps_named_members_and_attrs(self):
        dlc = DLC(self.root)
        rows = dlc.expand("category-ru", self.selector["attributes"], exclude_categories=self.selector["exclude_categories"])
        text = {r.text for r in rows}
        self.assertNotIn("DOMAIN-SUFFIX,ru", text)
        self.assertNotIn("DOMAIN-SUFFIX,su", text)
        self.assertNotIn("DOMAIN-SUFFIX,moscow", text)
        self.assertIn("DOMAIN-SUFFIX,mts.ru", text)
        self.assertIn("mobile", next(r.attrs for r in rows if r.value == "mts.ru"))
        self.assertNotIn("DOMAIN-SUFFIX,adriver.ru", text)
        self.assertNotIn("DOMAIN-SUFFIX,metrics.example", text)

    def test_excluded_and_full_expansion_have_separate_caches(self):
        dlc = DLC(self.root)
        clean = {r.text for r in dlc.expand("category-ru", exclude_categories=["tld-ru"])}
        full = {r.text for r in dlc.expand("category-ru")}
        self.assertNotIn("DOMAIN-SUFFIX,ru", clean)
        self.assertIn("DOMAIN-SUFFIX,ru", full)
        self.assertEqual(clean, {r.text for r in dlc.expand("category-ru", exclude_categories=["tld-ru"])})

    def test_registry_overlay_preserves_other_products(self):
        products = load_products(ROOT / "config/products.json")
        groups = {g["id"]: g for g in products["groups"]}
        self.assertIn("provider/apple", groups)
        self.assertEqual(groups["category/ru-services"]["selectors"][0]["category"], "category-ru")
        self.assertIn("category/ru-services", groups["region/ru"]["includes"])
        self.assertEqual(len([g for g in products["groups"] if g["id"] == "region/cn"]), 1)

    def test_new_primary_classification_and_operators_do_not_require_old_identity(self):
        groups, _ = self.build()
        index = CoverageIndex(normalize_rule(*line.split(",", 1)) for line in groups["region/ru"])
        for domain in ("mts.ru", "rt.ru", "megafon.ru", "tele2.ru", "beeline.ru", "pochta.ru",
                       "mcc250.pub.3gppnetwork.org", "new-market-service.example"):
            self.assertTrue(index.covers(normalize_rule("DOMAIN", domain)), domain)
        self.assertEqual(groups["region/ru"], groups["category/ru-services"])
        for domain in ("unrelated.ru", "unrelated.su", "unrelated.moscow", "unknown.ru.com", "unknown.ru.net"):
            self.assertFalse(index.covers(normalize_rule("DOMAIN", domain)), domain)

    def test_exact_shared_endpoint_not_promoted_to_entire_cloud(self):
        groups, _ = self.build()
        self.assertIn("DOMAIN,bank.storage.yandexcloud.net", groups["region/ru"])
        self.assertNotIn("DOMAIN-SUFFIX,yandexcloud.net", groups["region/ru"])
        index = CoverageIndex(normalize_rule(*line.split(",", 1)) for line in groups["region/ru"])
        self.assertFalse(index.covers(normalize_rule("DOMAIN", "different-tenant.storage.yandexcloud.net")))

    def test_declared_market_overlap_is_preserved_and_reported_without_precedence(self):
        groups, report = self.build()
        self.assertIn("DOMAIN-SUFFIX,ccb.com", groups["region/cn"])
        self.assertIn("DOMAIN-SUFFIX,ru.ccb.com", groups["region/ru"])
        self.assertIn("unresolved-positive-overlap", json.dumps(report))
        # A separate broad conflict must not swallow its independently known
        # narrow Russian endpoint before the CN exclusion is applied.
        self.assertNotIn("DOMAIN-SUFFIX,shared.example", groups["region/ru"])
        self.assertIn("DOMAIN,ru.shared.example", groups["region/ru"])

    def test_source_self_conflicts_are_deferred_not_silently_expanded(self):
        groups, report = self.build()
        index = CoverageIndex(normalize_rule(*line.split(",", 1)) for line in groups["region/ru"])
        for domain in ("my.games", "knightspeak.com", "vkcloud.kz"):
            self.assertFalse(index.covers(normalize_rule("DOMAIN", domain)))
        self.assertIn("my.games", json.dumps(report))
        decision = next(d for d in self.fragment["decisions"] if d["id"] == "mixed-global-source-context")
        self.assertEqual(decision["status"], "pending-market-reclassification")

    def test_critical_ru_source_failure_is_not_an_empty_success(self):
        with self.assertRaisesRegex(RuleError, "required selector.*ru-services"):
            self.build([{**self.source, "status": "unavailable"}])


if __name__ == "__main__":
    unittest.main()
