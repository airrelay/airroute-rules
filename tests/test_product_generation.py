import json
from pathlib import Path
import tempfile
import unittest

from airroute_data.domains import RuleError, build_domains, validate_domain_groups


class ProductGenerationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        data = self.root / "data"
        data.mkdir()
        (data / "cn").write_text("mainland.example\n")
        (data / "app").write_text("full:api.app.example\nmainland.example\n")
        self.sources = [{"id": "dlc", "format": "dlc", "path": str(self.root), "lineage": "dlc"}]
        self.cn = {"id": "region/cn-domain", "selectors": [{"source": "dlc", "category": "cn"}]}

    def build(self, *groups):
        return build_domains(self.sources, {"schema": 1, "groups": [self.cn, *groups]})

    def test_membership_topological_union_keeps_cn_and_exact_members(self):
        groups, report = self.build(
            {"id": "category/work", "includes": ["provider/app"]},
            {"id": "provider/app", "selectors": [{"source": "dlc", "category": "app"}]})
        self.assertEqual(groups["category/work"], ["DOMAIN,api.app.example", "DOMAIN-SUFFIX,mainland.example"])
        self.assertEqual(groups["provider/app"], groups["category/work"])
        self.assertEqual(report["memberships"], {"category/work": ["provider/app"]})

    def test_cycle_and_unknown_member_are_errors(self):
        with self.assertRaisesRegex(RuleError, "unknown group"):
            self.build({"id": "category/work", "includes": ["provider/missing"]})
        with self.assertRaisesRegex(RuleError, "include cycle"):
            self.build({"id": "category/a", "includes": ["category/b"]},
                       {"id": "category/b", "includes": ["category/a"]})

    def test_primary_complement_preserves_upstream_scope_and_known_exclusions(self):
        file = self.root / "supplement.list"
        file.write_text("DOMAIN,extra.app.example\nDOMAIN-SUFFIX,shared.example\n"
                        "DOMAIN-SUFFIX,app.example\nDOMAIN,tenant.cloud.example\n"
                        "DOMAIN-KEYWORD,app\nIP-CIDR,1.1.1.0/24\n"
                        "AND,((DOMAIN,a.app.example),(NETWORK,UDP))\n")
        self.sources.append({"id": "supplement", "format": "surge", "path": str(file), "lineage": "dlc-derived"})
        groups, report = self.build({"id": "provider/app", "selectors": [{
            "source": "supplement", "bounded_service": True, "domain_only": True,
            "owned_roots": ["app.example", "cloud.example"], "exclude_roots": ["cloud.example"]}]})
        self.assertEqual(groups["provider/app"], ["DOMAIN-KEYWORD,app", "DOMAIN-SUFFIX,shared.example", "IP-CIDR,1.1.1.0/24"])
        self.assertEqual(report["selectors"][1]["scope_admitted"], 5)
        self.assertEqual(len(report["quarantined"]), 2)

    def test_official_ip_membership_can_propagate_but_not_tenant_ips(self):
        path = self.root / "official.txt"
        path.write_text("149.154.160.0/20\n")
        self.sources.append({"id": "official", "format": "official-cidr", "service": "provider/app", "path": str(path), "address_families":[4]})
        groups, _ = self.build(
            {"id": "category/chat", "includes": ["provider/app"]},
            {"id": "provider/app", "selectors": [{"source": "official", "official_service_ips": True}]})
        self.assertEqual(groups["category/chat"], ["IP-CIDR,149.154.160.0/20"])

    def test_official_cidr_declared_families_are_checked(self):
        path=self.root/"dual.txt"
        source={"id":"official","format":"official-cidr","service":"provider/app","path":str(path),"address_families":[4,6]}
        group={"id":"provider/app","selectors":[{"source":"official","official_service_ips":True}]}
        self.sources.append(source)
        path.write_text("149.154.160.0/20\n")
        with self.assertRaisesRegex(RuleError,"missing a declared address family"):
            self.build(group)
        path.write_text("149.154.160.0/20\n2001:db8::/32\n")
        groups,_=self.build(group)
        self.assertEqual(groups["provider/app"],["IP-CIDR,149.154.160.0/20","IP-CIDR6,2001:db8::/32"])
        source['address_families']=[4]
        with self.assertRaisesRegex(RuleError,"outside declared"):
            self.build(group)
        source.pop('address_families')
        with self.assertRaisesRegex(RuleError,"address_families contract"):
            self.build(group)

    def test_empty_required_product_fails_and_special_is_not_overseas(self):
        groups,report=self.build({"id": "category/empty", "required_output": True})
        self.assertEqual(groups["category/empty"],[])
        self.assertEqual(report["groups"]["category/empty"]["status"],"empty")
        validate_domain_groups({"region/cn-domain": ["DOMAIN-SUFFIX,mainland.example"],
                                "special/realip": ["DOMAIN,ntp.mainland.example"]})

    def test_adobe_upstream_dependencies_are_retained_without_claiming_ownership(self):
        products = json.loads((Path(__file__).resolve().parents[1] / "config/products.json").read_text())
        group = next(g for g in products["groups"] if g["id"] == "provider/adobe")
        (self.root / "data/adobe").write_text("adobe.com\nfull:crl.versign.net\nfull:ocsp.digicert.com\n")
        groups, report = self.build(group)
        self.assertEqual(groups["provider/adobe"], ["DOMAIN,crl.versign.net", "DOMAIN,ocsp.digicert.com", "DOMAIN-SUFFIX,adobe.com"])
        self.assertEqual(report["selectors"][1]["scope_rejected"], 0)


if __name__ == "__main__":
    unittest.main()
