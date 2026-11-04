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
            {"id": "region/cn-domain", "selectors": cn_selectors, **cn_fields}, *groups]})

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
        self.assertEqual(set(groups["region/cn-domain"]), {
            "DOMAIN-SUFFIX,new-primary.example", "DOMAIN-SUFFIX,new-supplement.example"})
        self.assertNotIn("reference_decisions", report)
        self.assertFalse(any("identity-catalogue" in x["reason"] for x in report["quarantined"]))

    def test_actual_cn_selectors_do_not_restore_identity_gate(self):
        products = load_products(ROOT / "config/products.json")
        cn = next(g for g in products["groups"] if g["id"] == "region/cn-domain")
        mature = [s for s in cn["selectors"] if s["source"] in {"blackmatrix", "acl4ssr", "sukka"}]
        self.assertTrue(mature)
        self.assertTrue(any("ChinaMax" in s.get("path", "") for s in mature))
        for selector in mature:
            self.assertEqual(selector.get("mode", "primary"), "primary", selector)
            self.assertNotIn("identity_catalogues", selector)

    def test_global_category_configuration_includes_cn_parts_without_filter_gates(self):
        products=load_products(ROOT/"config/products.json")
        groups={g["id"]:g for g in products["groups"]}
        for group,category in [("category/ai","category-ai-cn"),("category/cloud-storage","category-netdisk-cn"),
                               ("category/social","category-social-media-cn"),("category/education","category-scholar-cn")]:
            self.assertTrue(any(s.get("category")==category for s in groups[group]["selectors"]))
        for group in groups.values():
            for selector in group.get("selectors",[]):
                self.assertFalse({"-cn","-!cn","!cn"}&set(selector.get("attributes",[])))
                self.assertFalse({"owned_roots","bounded_service","domain_only","shared_roots"}&selector.keys())

    def test_cn_official_catalogue_can_include_non_cn_dependency(self):
        path=self.root/"official.json"
        path.write_text(json.dumps([{"id":1,"serviceArea":"Common","urls":["shared.service.example","*.tenant.global.example"]}]))
        self.source("official",path,"official-json")
        groups,report=self.build([{"source":"official","format":"official-json","adapter":"microsoft365"}])
        self.assertIn("DOMAIN,shared.service.example",groups["region/cn-domain"])
        self.assertFalse(report["quarantined"])

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

    def test_precise_cloud_dependency_keeps_original_scope(self):
        self.third_party("chinamax", "DOMAIN,tenant.cloudfront.net\n")
        groups, report = self.build([{"source": "chinamax", "mode": "primary"}])
        self.assertEqual(groups["region/cn-domain"], ["DOMAIN,tenant.cloudfront.net"])
        index = self.index(groups["region/cn-domain"])
        for domain in ("other.cloudfront.net", "nested.tenant.cloudfront.net"):
            self.assertFalse(index.covers(normalize_rule("DOMAIN", domain)))
        self.assertFalse(report["quarantined"])

    def test_reason_samples_are_bounded_per_source_not_by_global_prefix(self):
        # A large earlier rejection category must not hide a later source's
        # representative sample. No unbounded trace ledger is necessary.
        self.third_party("first", "".join(f"DOMAIN-SUFFIX,bad{i}.example\n" for i in range(1005)))
        self.third_party("later", "DOMAIN-SUFFIX,cloudfront.net\nDOMAIN,new-market.example\n")
        groups, report = self.build([
            {"source": "first", "exclude_roots": ["example"]},
            {"source": "later", "exclude_roots": ["cloudfront.net"]},
        ])
        first = [q for q in report["quarantined"] if q["source"].startswith("first:")]
        later = [q for q in report["quarantined"] if q["source"].startswith("later:")]
        self.assertEqual(len(first), 12)
        self.assertEqual(len(later), 1)
        self.assertEqual(sum(v for k, v in report["quarantine_counts"].items()
                             if k.startswith("first:")), 1005)
        self.assertEqual(groups["region/cn-domain"], ["DOMAIN,new-market.example"])
        json.dumps(report)  # The bounded report remains JSON serializable.

    def test_semantic_compaction_keeps_exact_hosts_exact(self):
        self.third_party("mature", "DOMAIN-SUFFIX,bank.example\nDOMAIN,login.bank.example\n"
                         "DOMAIN,exact-only.example\nDOMAIN,exact-only.example\n")
        groups, report = self.build([{"source": "mature"}])
        self.assertEqual(set(groups["region/cn-domain"]), {
            "DOMAIN-SUFFIX,bank.example", "DOMAIN,exact-only.example"})
        self.assertFalse(self.index(groups["region/cn-domain"]).covers(
            normalize_rule("DOMAIN", "sub.exact-only.example")))
        buckets = report["decisions"]["region/cn-domain"]
        compactions = [value for phases in buckets.values() for key, value in
                       phases.get("compaction", {}).items() if key.startswith("covered:")]
        self.assertEqual(sum(x["count"] for x in compactions), 2)

    def test_cn_and_ru_service_overlap_is_preserved_without_exceptions(self):
        self.dlc_file("cn", "ccb.com\ncn.shared.example\n")
        self.dlc_file("ru", "ru.ccb.com\nother.ccb.com\nshared.example\nfull:ru.shared.example\n")
        ru = {"id": "category/ru-services", "selectors": [{"source": "dlc", "category": "ru"}]}
        groups, report = self.build([{"source": "dlc", "category": "cn"}], ru)
        index = self.index(groups["category/ru-services"])
        for host in ("ru.ccb.com", "other.ccb.com", "ru.shared.example"):
            self.assertTrue(index.covers(normalize_rule("DOMAIN",host)))
        self.assertFalse(report["quarantined"])
        validate_domain_groups(groups)

    def test_valid_top_level_upstream_rules_are_preserved(self):
        self.dlc_file("cn", "keyword:alipay\n")
        self.dlc_file("ru", "ru\nyandex\nmts.ru\n")
        groups, report = self.build([{"source":"dlc","category":"cn"}],
            {"id":"category/ru-services","selectors":[{"source":"dlc","category":"ru"}]})
        self.assertEqual(groups["category/ru-services"],["DOMAIN-SUFFIX,ru","DOMAIN-SUFFIX,yandex"])
        self.assertFalse(report["quarantined"])

    def test_missing_required_source_or_selector_is_a_failure(self):
        with self.assertRaisesRegex(RuleError, "required selector.*source unavailable"):
            self.build([{"source": "absent", "required": True}])
        with self.assertRaisesRegex(RuleError, "required selector"):
            self.build([{"source": "dlc", "category": "missing", "required": True}])


if __name__ == "__main__":
    unittest.main()
