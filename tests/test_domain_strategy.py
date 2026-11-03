"""Offline market-domain strategy regressions, independent of Geo credentials."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from airroute_data.domains import (
    CoverageIndex, DLC, RuleError, build_domains, load_products, normalize_rule,
    validate_domain_groups,
)

ROOT = Path(__file__).resolve().parents[1]


class DomainStrategyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dlc = self.root / "dlc"
        (self.dlc / "data").mkdir(parents=True)
        self.source("dlc", self.dlc, "dlc")

    def source(self, name, path, format="surge"):
        if not hasattr(self, "sources"):
            self.sources = []
        self.sources.append({"id": name, "path": str(path), "format": format,
                             "status": "available", "lineage": name})

    def dlc_file(self, name, text):
        (self.dlc / "data" / name).write_text(text, encoding="utf-8")

    def third_party(self, name, text):
        path = self.root / (name + ".list")
        path.write_text(text, encoding="utf-8")
        self.source(name, path)

    def build(self, cn_selectors, *groups, **cn_fields):
        return build_domains(self.sources, {"schema": 1, "groups": [
            {"id": "region/cn", "selectors": cn_selectors, **cn_fields}, *groups]})

    @staticmethod
    def index(lines):
        return CoverageIndex(normalize_rule(*line.split(",", 1)) for line in lines)

    def test_primary_and_mature_supplement_can_add_new_cn_domains(self):
        self.dlc_file("cn", "new-primary.example\n")
        self.third_party("chinamax", "DOMAIN-SUFFIX,new-supplement.example\n")
        groups, report = self.build([
            {"source": "dlc", "category": "cn", "mode": "primary"},
            {"source": "chinamax", "mode": "primary"},
        ])
        self.assertEqual(set(groups["region/cn"]), {
            "DOMAIN-SUFFIX,new-primary.example", "DOMAIN-SUFFIX,new-supplement.example"})
        self.assertNotIn("reference_decisions", report)
        self.assertFalse(any("identity-catalogue" in x["reason"] for x in report["quarantined"]))

    def test_actual_cn_selectors_do_not_restore_identity_gate(self):
        products = load_products(ROOT / "config/products.json")
        cn = next(g for g in products["groups"] if g["id"] == "region/cn")
        mature = [s for s in cn["selectors"] if s["source"] in {"blackmatrix", "acl4ssr", "sukka"}]
        self.assertTrue(mature)
        self.assertTrue(any("ChinaMax" in s.get("path", "") for s in mature))
        for selector in mature:
            self.assertEqual(selector.get("mode", "primary"), "primary", selector)
            self.assertNotIn("identity_catalogues", selector)

    def test_russian_tld_subtree_removal_preserves_named_classes(self):
        self.dlc_file("tld-ru", "ru\nsu\nmoscow\n")
        self.dlc_file("operators", "mts.ru\nfull:ims.mts.ru\n")
        self.dlc_file("category-ru", "include:tld-ru\ninclude:operators\nbeeline.ru\n")
        library = DLC(self.dlc)
        scoped = library.expand("category-ru", exclude_categories=["tld-ru"])
        full = library.expand("category-ru")
        self.assertEqual({r.text for r in scoped}, {
            "DOMAIN-SUFFIX,mts.ru", "DOMAIN,ims.mts.ru", "DOMAIN-SUFFIX,beeline.ru"})
        self.assertIn("DOMAIN-SUFFIX,ru", {r.text for r in full})
        index = CoverageIndex(scoped)
        self.assertFalse(index.covers(normalize_rule("DOMAIN", "unrelated.ru")))
        self.assertFalse(index.covers(normalize_rule("DOMAIN", "unrelated.su")))

    def test_precise_cloud_dependency_never_promotes_shared_parent(self):
        self.third_party("chinamax", "DOMAIN-SUFFIX,cloudfront.net\nDOMAIN,tenant.cloudfront.net\n")
        groups, report = self.build([{"source": "chinamax", "mode": "primary"}],
                                    shared_roots=["cloudfront.net"])
        self.assertEqual(groups["region/cn"], ["DOMAIN,tenant.cloudfront.net"])
        index = self.index(groups["region/cn"])
        for domain in ("other.cloudfront.net", "nested.tenant.cloudfront.net"):
            self.assertFalse(index.covers(normalize_rule("DOMAIN", domain)))
        self.assertTrue(any(q["reason"] == "shared-parent-needs-precise-endpoint"
                            for q in report["quarantined"]))

    def test_reason_samples_are_bounded_per_source_not_by_global_prefix(self):
        # A large earlier rejection category must not hide a later source's
        # representative sample. No unbounded trace ledger is necessary.
        self.third_party("first", "".join(f"DOMAIN-SUFFIX,bad{i}.example\n" for i in range(1005)))
        self.third_party("later", "DOMAIN-SUFFIX,cloudfront.net\nDOMAIN,new-market.example\n")
        groups, report = self.build([
            {"source": "first", "exclude_roots": ["example"]},
            {"source": "later", "shared_roots": ["cloudfront.net"]},
        ])
        first = [q for q in report["quarantined"] if q["source"].startswith("first:")]
        later = [q for q in report["quarantined"] if q["source"].startswith("later:")]
        self.assertEqual(len(first), 12)
        self.assertEqual(len(later), 1)
        self.assertEqual(sum(v for k, v in report["quarantine_counts"].items()
                             if k.startswith("first:")), 1005)
        self.assertEqual(groups["region/cn"], ["DOMAIN,new-market.example"])
        json.dumps(report)  # The bounded report remains JSON serializable.

    def test_semantic_compaction_keeps_exact_hosts_exact(self):
        self.third_party("mature", "DOMAIN-SUFFIX,bank.example\nDOMAIN,login.bank.example\n"
                         "DOMAIN,exact-only.example\nDOMAIN,exact-only.example\n")
        groups, report = self.build([{"source": "mature"}])
        self.assertEqual(set(groups["region/cn"]), {
            "DOMAIN-SUFFIX,bank.example", "DOMAIN,exact-only.example"})
        self.assertFalse(self.index(groups["region/cn"]).covers(
            normalize_rule("DOMAIN", "sub.exact-only.example")))
        buckets = report["decisions"]["region/cn"]
        compactions = [value for phases in buckets.values() for key, value in
                       phases.get("compaction", {}).items() if key.startswith("covered:")]
        self.assertEqual(sum(x["count"] for x in compactions), 2)

    def test_cn_ru_overlap_requires_exact_predicate_and_provenance(self):
        self.dlc_file("cn", "ccb.com\ncn.shared.example\n")
        self.dlc_file("ru", "ru.ccb.com\nother.ccb.com\nshared.example\nfull:ru.shared.example\n")
        exception = {"predicate": "DOMAIN-SUFFIX,ru.ccb.com", "source": "dlc:ru",
                     "reason": "Explicit Russian-market branch; no implicit routing precedence."}
        ru = {"id": "region/ru", "selectors": [{"source": "dlc", "category": "ru"}],
              "cn_market_overlaps": [exception]}
        groups, report = self.build([{"source": "dlc", "category": "cn"}], ru)
        self.assertIn(exception["predicate"], groups["region/ru"])
        self.assertNotIn("DOMAIN-SUFFIX,other.ccb.com", groups["region/ru"])
        self.assertNotIn("DOMAIN-SUFFIX,shared.example", groups["region/ru"])
        self.assertIn("DOMAIN,ru.shared.example", groups["region/ru"])
        self.assertEqual(len(report["market_conflicts"]), 1)
        self.assertEqual(report["market_conflicts"][0]["status"], "unresolved-positive-overlap")
        with self.assertRaisesRegex(RuleError, "CN/overseas domain overlap"):
            validate_domain_groups(groups)
        validate_domain_groups(groups, market_overlaps={"region/ru": [exception]})
        wrong = deepcopy(ru)
        wrong["cn_market_overlaps"][0]["source"] = "dlc:wrong-origin"
        wrong_groups, wrong_report = self.build([{"source": "dlc", "category": "cn"}], wrong)
        self.assertNotIn(exception["predicate"], wrong_groups["region/ru"])
        self.assertFalse(wrong_report["market_conflicts"])

    def test_mixed_market_patterns_cannot_bypass_top_level_exclusion(self):
        self.dlc_file("cn", "keyword:alipay\n")
        self.dlc_file("ru", "ru\nyandex\nmts.ru\n")
        products = {"schema": 1, "policy": {"cn_exclusion": "named-mainland-services; report mixed-market overlaps"},
            "groups": [{"id": "region/cn", "selectors": [{"source": "dlc", "category": "cn"}]},
                       {"id": "region/ru", "selectors": [{"source": "dlc", "category": "ru"}]}]}
        groups, report = build_domains(self.sources, products)
        self.assertEqual(groups["region/ru"], ["DOMAIN-SUFFIX,mts.ru"])
        with self.assertRaisesRegex(RuleError, "top-level shortcut"):
            validate_domain_groups({"region/cn": [], "region/ru": ["DOMAIN-SUFFIX,ru"]},
                market_overlaps={"region/ru": [{"predicate": "DOMAIN-SUFFIX,ru", "source": "fixture", "reason": "tamper"}]})
        self.assertEqual(sum(x["reason"] == "TLD alone is not service identity" for x in report["quarantined"]), 2)

    def test_missing_required_source_or_selector_is_a_failure(self):
        with self.assertRaisesRegex(RuleError, "required selector.*source unavailable"):
            self.build([{"source": "absent", "required": True}])
        with self.assertRaisesRegex(RuleError, "required selector"):
            self.build([{"source": "dlc", "category": "missing", "required": True}])


if __name__ == "__main__":
    unittest.main()
