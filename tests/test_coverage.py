"""Coverage oracles: predicate languages, official scopes and product regressions."""
import json
from pathlib import Path
import tempfile
import unittest

from airroute_data.coverage import compare_product, guard_products, profiles
from airroute_data.domains import (CoverageIndex, DLC, build_domains, minimize,
                                  normalize_rule, official_domains, _CNIndex)


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def baseline(self, groups, sources=()):
        files = []
        for name, rows in groups.items():
            path = self.root / (name + ".list")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(rows) + "\n")
            files.append({"path": name + ".list"})
        (self.root / "manifest.json").write_text(json.dumps({"files": files, "source_snapshot": list(sources)}))
        return self.root

    def test_text_difference_is_not_a_coverage_gap(self):
        diff = compare_product(["DOMAIN,api.example.com", "DOMAIN-SUFFIX,assets.example.com"],
                               ["DOMAIN-SUFFIX,example.com"])
        self.assertEqual(diff["retained_domain_predicates"], 2)
        self.assertEqual(diff["old_domain_predicates_not_fully_retained"], 0)

    def test_exact_child_does_not_prove_parent_suffix(self):
        diff = compare_product(["DOMAIN-SUFFIX,example.com"], ["DOMAIN,api.example.com"])
        self.assertEqual(diff["retained_domain_predicates"], 0)

    def test_strict_wildcard_preserves_apex_boundary_and_compacts_children(self):
        regex = normalize_rule("DOMAIN-REGEX", r"^.+\.example\.com$")
        index = CoverageIndex([regex])
        self.assertFalse(index.covers(normalize_rule("DOMAIN", "example.com")))
        self.assertTrue(index.covers(normalize_rule("DOMAIN", "a.example.com")))
        self.assertEqual(len(minimize([regex, normalize_rule("DOMAIN", "a.example.com")])), 1)
        self.assertEqual(len(minimize([regex, normalize_rule("DOMAIN", "example.com")])), 2)
        cn = _CNIndex([regex])
        self.assertFalse(cn.overlaps(normalize_rule("DOMAIN", "example.com")))
        self.assertTrue(cn.overlaps(normalize_rule("DOMAIN-SUFFIX", "example.com")))
        self.assertTrue(cn.overlaps(normalize_rule("DOMAIN", "a.example.com")))

    def test_hidden_empty_product_is_blocked_even_if_global_count_is_same(self):
        before = {"category/a": ["DOMAIN-SUFFIX,a.example"], "category/b": ["DOMAIN-SUFFIX,b.example"]}
        after = {"category/a": [], "category/b": ["DOMAIN-SUFFIX,b.example", "DOMAIN-SUFFIX,new.example"]}
        with self.assertRaisesRegex(ValueError, "category/a: domain language coverage collapse"):
            guard_products(after, {}, {"per_product": {} | {"minimum_domain_retention": 0.9}}, self.baseline(before))

    def test_semantically_equivalent_compaction_passes_retention(self):
        before = {"category/a": ["DOMAIN,a.example", "DOMAIN,b.a.example"]}
        guard_products({"category/a": ["DOMAIN-SUFFIX,a.example"]}, {},
                       {"per_product": {"minimum_domain_retention": 1}}, self.baseline(before))

    def test_ipv6_addresses_not_cidr_count_or_float_rounding(self):
        before = {"region/cn": ["IP-CIDR6,2400::/24"]}
        after = {"region/cn": ["IP-CIDR6,2400::/64"]}
        with self.assertRaisesRegex(ValueError, "IPv6 address coverage collapse"):
            guard_products(after, {}, {"per_product": {"minimum_address_retention": 0.85}}, self.baseline(before))

    def test_previously_used_country_source_cannot_disappear_silently(self):
        source = {"id": "country-a", "role": "country", "status": "available", "publish_allowed": True}
        with self.assertRaisesRegex(ValueError, "country source unavailable"):
            guard_products({}, {"source_snapshot": [{**source, "status": "missing-credentials"}]},
                           {"per_product": {"protect_used_country_sources": True}}, self.baseline({}, [source]))

    def test_required_official_source_and_manifest_metrics_checked(self):
        with self.assertRaisesRegex(ValueError, "required source unavailable"):
            guard_products({}, {}, {"per_product": {"required_sources": {"region/cn": ["official-cn"]}}})
        with self.assertRaisesRegex(ValueError, "coverage disagrees"):
            guard_products({}, {"product_coverage": {"fake": {}}}, {})

    def test_address_growth_of_one_region_is_blocked(self):
        before = {"region/ru": ["IP-CIDR,2.0.0.0/24"]}
        with self.assertRaisesRegex(ValueError, "abnormal address coverage growth"):
            guard_products({"region/ru": ["IP-CIDR,2.0.0.0/16"]}, {},
                           {"per_product": {"maximum_address_growth": 1.5}}, self.baseline(before))

    def test_same_size_ip_replacement_does_not_hide_address_loss(self):
        before = {"region/cn": ["IP-CIDR,1.0.0.0/24"]}
        with self.assertRaisesRegex(ValueError, "previously covered address loss"):
            guard_products({"region/cn": ["IP-CIDR,2.0.0.0/24"]}, {},
                           {"per_product": {"minimum_address_retention": 0.85}}, self.baseline(before))

    def test_fetched_but_empty_or_unparsed_required_selector_blocks(self):
        manifest = {"source_snapshot": [{"id": "official", "status": "available"}],
                    "selector_health": [{"group": "category/a", "source": "official", "input_rules": 0}]}
        with self.assertRaisesRegex(ValueError, "required selector failed or empty"):
            guard_products({}, manifest, {"per_product": {"required_sources": {"category/a": ["official"]}}})

    def test_github_dependency_is_not_automatically_service_or_ai_identity(self):
        data = {"domains": {"copilot": ["*.githubcopilot.com", "*.github.com", "*.azureedge.net", "shared.example"]}}
        rows, rejected = official_domains(data, "github-meta", {"adapter": "github-meta", "categories": ["copilot"],
                                                              "owned_roots": ["githubcopilot.com"]})
        self.assertEqual([r.text for r in rows], [r"DOMAIN-REGEX,^.+\.githubcopilot\.com$"])
        self.assertEqual(len(rejected), 3)

    def test_china_cloud_catalogue_does_not_admit_global_dependencies(self):
        data = [{"id": 1, "serviceArea": "Common", "urls": ["*.office.cn", "www.office.cn", "*.cdn.office.net"]}]
        rows, rejected = official_domains(data, "official-cn", {"adapter": "microsoft365", "regional_suffix": ".cn"})
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(rejected), 1)
        self.assertNotEqual(rows[0].kind, "DOMAIN-SUFFIX")

    def test_official_connectivity_allowlist_is_not_dependency_ownership(self):
        data = [{"id": 1, "serviceArea": "Common", "urls": ["*.office.com", "ocsp.digicert.com", "*.globalsign.com"]}]
        rows, rejected = official_domains(data, "microsoft365", {"adapter": "microsoft365", "dependency_roots": ["digicert.com", "globalsign.com"]})
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rejected), 2)
        self.assertTrue(all("not service ownership" in r["reason"] for r in rejected))

    def test_broad_reference_narrows_to_proven_identity_never_shared_parent(self):
        data = self.root / "data"; data.mkdir()
        (data / "cn").write_text("mainland.example\n")
        (data / "identity").write_text("full:service.shared.example\nkeyword:scam\n")
        reference = self.root / "reference.list"
        reference.write_text("DOMAIN-SUFFIX,shared.example\nDOMAIN-SUFFIX,scam.example\n")
        products = {"schema": 1, "groups": [
            {"id": "region/cn", "selectors": [{"source": "dlc", "category": "cn"}]},
            {"id": "category/a", "selectors": [{"source": "ref", "mode": "corroborated",
                "identity_catalogues": [{"source": "dlc", "categories": ["identity"]}]}]}]}
        groups, report = build_domains([{"id": "dlc", "format": "dlc", "path": str(self.root)},
                                       {"id": "ref", "format": "surge", "path": str(reference)}], products)
        self.assertEqual(groups["category/a"], ["DOMAIN,service.shared.example"])
        self.assertEqual(report["reference_decisions"]["category/a"]["ref"]["broad-parent-not-equivalent-to-known-children"], 1)

    def test_official_ip_catalogue_requires_matching_service_scope(self):
        source = self.root / "ips.txt"; source.write_text("91.108.4.0/22\n2001:b28:f23d::/48\n")
        products = {"schema": 1, "groups": [{"id": "region/cn", "selectors": []},
            {"id": "service/telegram", "selectors": [{"source": "official", "format": "official-cidr", "official_service_ips": True, "required": True}]}]}
        with self.assertRaisesRegex(ValueError, "not scoped"):
            build_domains([{"id": "official", "path": str(source)}], products)
        groups, _ = build_domains([{"id": "official", "path": str(source), "service": "service/telegram"}], products)
        self.assertEqual(len(groups["service/telegram"]), 2)


if __name__ == "__main__":
    unittest.main()
