"""Publication contracts use product bytes, not catalogue labels or row sums."""
import json
from pathlib import Path
import tempfile
import unittest

from airroute_data.coverage import compare_directories, guard_products, profiles


class CatalogueQualityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def baseline(self, groups):
        files = []
        for name, rows in groups.items():
            path = self.root / (name + ".list")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(rows) + "\n")
            files.append({"path": name + ".list"})
        (self.root / "manifest.json").write_text(json.dumps({"files": files}))
        return self.root

    def test_required_group_cannot_be_empty_or_hidden(self):
        manifest = {"product_catalogue": {"service/a": {"required_output": True, "content_types": ["domain"]}}}
        for groups in ({}, {"service/a": []}):
            with self.subTest(groups=groups), self.assertRaisesRegex(ValueError, "required product is missing or empty"):
                guard_products(groups, manifest, {})

    def test_optional_evidence_gap_need_not_emit_empty_file(self):
        guard_products({}, {"product_catalogue": {"region/no-domain-evidence": {
            "required_output": False, "content_types": ["domain"], "gap": "no reliable identity source"}}}, {})

    def test_declared_domain_product_rejects_ip_even_with_correct_profile(self):
        groups = {"dns/realip": ["IP-CIDR,1.1.1.0/24"]}
        manifest = {"product_coverage": profiles(groups), "product_catalogue": {
            "dns/realip": {"required_output": True, "content_types": ["domain"]}}}
        with self.assertRaisesRegex(ValueError, "content violates declared product types"):
            guard_products(groups, manifest, {})

    def test_unregistered_output_and_unknown_type_fail(self):
        with self.assertRaisesRegex(ValueError, "absent from catalogue"):
            guard_products({"service/a": ["DOMAIN,a.example"]}, {"product_catalogue": {}}, {})
        with self.assertRaisesRegex(ValueError, "invalid declared content types"):
            guard_products({}, {"product_catalogue": {"service/a": {"content_types": ["UA"]}}}, {})

    def test_category_semantically_contains_service_without_text_duplicate(self):
        groups = {"service/a": ["DOMAIN,api.a.example", "IP-CIDR,1.1.1.0/24", "IP-CIDR6,2001:db8::/64"],
                  "category/a": ["DOMAIN-SUFFIX,a.example", "IP-CIDR,1.1.1.0/25", "IP-CIDR,1.1.1.128/25", "IP-CIDR6,2001:db8::/64"]}
        catalogue = {name: {"required_output": True, "content_types": ["domain", "ipv4", "ipv6"]} for name in groups}
        catalogue["category/a"]["includes"] = ["service/a"]
        guard_products(groups, {"product_catalogue": catalogue}, {})

    def test_category_exact_host_does_not_retain_service_suffix(self):
        groups = {"service/a": ["DOMAIN-SUFFIX,a.example"], "category/a": ["DOMAIN,api.a.example"]}
        catalogue = {"service/a": {}, "category/a": {"includes": ["service/a"]}}
        with self.assertRaisesRegex(ValueError, "does not semantically include service/a"):
            guard_products(groups, {"product_catalogue": catalogue}, {})

    def test_partial_ipv4_or_ipv6_membership_fails(self):
        for child, parent in (("IP-CIDR,1.1.1.0/24", "IP-CIDR,1.1.1.0/25"),
                              ("IP-CIDR6,2001:db8::/64", "IP-CIDR6,2001:db8::/65")):
            with self.subTest(child=child), self.assertRaisesRegex(ValueError, "does not semantically include"):
                guard_products({"service/a": [child], "category/a": [parent]}, {"product_catalogue": {
                    "service/a": {}, "category/a": {"includes": ["service/a"]}}}, {})

    def test_missing_members_and_cycles_fail(self):
        with self.assertRaisesRegex(ValueError, "included product is missing"):
            guard_products({"category/a": ["DOMAIN,a.example"]}, {"product_catalogue": {
                "category/a": {"includes": ["service/missing"]}}}, {})
        groups = {"category/a": ["DOMAIN,a.example"], "category/b": ["DOMAIN,a.example"]}
        with self.assertRaisesRegex(ValueError, "membership cycle"):
            guard_products(groups, {"product_catalogue": {
                "category/a": {"includes": ["category/b"]}, "category/b": {"includes": ["category/a"]}}}, {})

    def test_unrelated_baseline_cannot_waive_new_product_floor(self):
        before = {"service/a": ["DOMAIN,a.example"]}
        groups = {**before, "service/new": ["DOMAIN,b.example"]}
        with self.assertRaisesRegex(ValueError, "service/new: empty or implausibly small"):
            guard_products(groups, {}, {"per_product": {"minimum_domains": {"service/new": 3}}}, self.baseline(before))

    def test_existing_product_compaction_uses_language_retention(self):
        before = {"service/a": ["DOMAIN-SUFFIX,a.example", "DOMAIN,api.a.example"]}
        guard_products({"service/a": ["DOMAIN-SUFFIX,a.example"]}, {},
                       {"per_product": {"minimum_domains": {"service/a": 2}}}, self.baseline(before))

    def test_downloaded_but_entirely_scope_rejected_source_is_not_healthy(self):
        manifest = {"source_snapshot": [{"id": "curated", "status": "available"}], "selector_health": [
            {"group": "service/a", "source": "curated", "input_rules": 100, "scope_admitted": 0}]}
        with self.assertRaisesRegex(ValueError, "required selector failed or empty"):
            guard_products({}, manifest, {"per_product": {"required_sources": {"service/a": ["curated"]}}})

    def test_required_source_can_be_consumed_by_included_service_with_unrelated_diagnostics(self):
        groups = {"category/work": ["DOMAIN,app.example"], "service/app": ["DOMAIN,app.example"]}
        manifest = {"source_snapshot": [{"id": "official", "status": "available"}],
            "product_catalogue": {"category/work": {"includes": ["service/app"]}, "service/app": {}},
            "selector_health": [{"source": "iana", "status": "available"},
                                {"group": "service/app", "source": "official", "scope_admitted": 1}]}
        policy = {"per_product": {"required_sources": {"category/work": ["official"]}}}
        guard_products(groups, manifest, policy)
        manifest["selector_health"][1]["scope_admitted"] = 0
        with self.assertRaisesRegex(ValueError, "required selector failed or empty"):
            guard_products(groups, manifest, policy)

    def test_route_coverage_does_not_count_dns_exceptions_or_category_copies(self):
        before = {"service/a": ["DOMAIN,a.example"]}
        after = {**before, "category/a": ["DOMAIN,a.example"], "dns/realip": ["DOMAIN,compat.example"]}
        roots = []
        for label, groups in (("before", before), ("after", after)):
            root = self.root / label
            root.mkdir()
            files = []
            for name, rows in groups.items():
                path = root / (name + ".list")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n".join(rows) + "\n")
                files.append({"path": name + ".list"})
            (root / "manifest.json").write_text(json.dumps({
                "data_version": label, "summary": {}, "source_snapshot": [], "files": files}))
            roots.append(root)
        report = compare_directories(*roots)
        purposes = report["domain_language_by_purpose"]
        self.assertEqual(purposes["routing"]["after"]["domain_predicates"], 1)
        self.assertEqual(purposes["routing"]["new_domain_predicates_not_previously_covered"], 0)
        self.assertEqual(purposes["dns"]["new_domain_predicates_not_previously_covered"], 1)

    def reviewed_policy(self, predicate="DOMAIN,brand.example"):
        return {"per_product": {"minimum_domain_retention": 0.9, "reviewed_removals": {
            "category/streaming": {"baseline_version": "approved-version", "predicates": [predicate],
                                   "reason": "Remove a whole-company brand predicate outside this service category."}}}}

    def reviewed_baseline(self):
        root = self.baseline({"category/streaming": ["DOMAIN,brand.example", "DOMAIN,play.example"]})
        manifest = json.loads((root / "manifest.json").read_text())
        manifest["data_version"] = "approved-version"
        (root / "manifest.json").write_text(json.dumps(manifest))
        return root

    def test_reviewed_exact_loss_applies_only_to_actual_loss_and_reports_reason(self):
        result = guard_products({"category/streaming": ["DOMAIN,play.example"]}, {},
                                self.reviewed_policy(), self.reviewed_baseline())
        reviewed = result["comparison"]["category/streaming"]["reviewed_removals"]
        self.assertEqual(reviewed["authorized_actual_losses"], ["DOMAIN,brand.example"])
        self.assertEqual(reviewed["effective_old_domain_predicates"], 1)
        self.assertTrue(reviewed["baseline_matches"])
        self.assertIn("whole-company", reviewed["reason"])
        # A broader configured string is not authority to remove different,
        # narrower predicates; authorizations match exact normalized old rows.
        with self.assertRaisesRegex(ValueError, "domain language coverage collapse"):
            guard_products({"category/streaming": ["DOMAIN,play.example"]}, {},
                           self.reviewed_policy("DOMAIN-SUFFIX,example"), self.reviewed_baseline())

    def test_reviewed_loss_does_not_authorize_other_losses(self):
        with self.assertRaisesRegex(ValueError, "domain language coverage collapse"):
            guard_products({"category/streaming": ["DOMAIN,brand.example"]}, {},
                           self.reviewed_policy(), self.reviewed_baseline())

    def test_reviewed_loss_does_not_bypass_future_baseline(self):
        root = self.reviewed_baseline()
        path = root / "manifest.json"
        manifest = json.loads(path.read_text()); manifest["data_version"] = "future-version"
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "domain language coverage collapse"):
            guard_products({"category/streaming": ["DOMAIN,play.example"]}, {}, self.reviewed_policy(), root)

    def test_reviewed_loss_cannot_hide_ip_coverage_loss(self):
        root = self.reviewed_baseline()
        path = root / "category/streaming.list"
        path.write_text(path.read_text() + "IP-CIDR,1.1.1.0/24\n")
        with self.assertRaisesRegex(ValueError, "IPv4 address coverage collapse"):
            guard_products({"category/streaming": ["DOMAIN,play.example"]}, {}, self.reviewed_policy(), root)


if __name__ == "__main__":
    unittest.main()
