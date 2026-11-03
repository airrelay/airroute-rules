import copy
from pathlib import Path
import tempfile
import unittest

from airroute_data.domains import RuleError
from airroute_data.special import build_special, load_special_config, validate_special_groups


class SpecialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def source(self, sid, text, suffix=".list"):
        path = self.root / (sid + suffix)
        path.write_text(text, encoding="utf-8")
        return {"id": sid, "path": str(path), "lineage": "shared-DLC"}

    def dlc(self):
        root = self.root / "dlc" / "data"
        root.mkdir(parents=True)
        (root / "category-ntp").write_text("full:ntp.clock.example\nclock.example\nkeyword:time\n")
        (root / "category-stun").write_text("full:stun.voice.example\nvoice.example\n")
        (root / "private").write_text("home.arpa\nlan\nexample\nts.net\nfull:router.public.example\n10.in-addr.arpa\n")
        return {"id": "dlc", "path": str(root.parent), "lineage": "shared-DLC"}

    def test_real_output_is_nonempty_and_reproducible_without_network(self):
        a, report = build_special([])
        b, again = build_special([])
        self.assertEqual(a, b)
        self.assertEqual(report, again)
        self.assertEqual(len(a), 15)
        self.assertTrue(all(a.values()))
        self.assertEqual(a["dns/realip"], ["DOMAIN,dns.msftncsi.com", "DOMAIN,ipv4only.arpa", "DOMAIN-SUFFIX,home.arpa", "DOMAIN-SUFFIX,local", "DOMAIN-SUFFIX,localhost"])
        self.assertTrue(report["gaps"])
        self.assertTrue(all(v["status"] == "unavailable" for v in report["registry_checks"].values()))

    def test_lan_separates_rfc6598_multicast_benchmark_nat64_and_docs(self):
        groups, _ = build_special([])
        lan = groups["special/lan"]
        for bad in ("IP-CIDR,100.64.0.0/10", "IP-CIDR,198.18.0.0/15", "IP-CIDR,224.0.0.0/4", "IP-CIDR,192.0.2.0/24", "IP-CIDR6,64:ff9b::/96"):
            self.assertNotIn(bad, lan)
        self.assertEqual(groups["special/shared"], ["IP-CIDR,100.64.0.0/10"])
        self.assertIn("IP-CIDR,198.18.0.0/15", groups["special/benchmark"])

    def test_publication_independently_rejects_fakeip_broad_lan_and_unknown_namespace(self):
        for rule in ("IP-CIDR,198.18.1.0/24", "IP-CIDR,0.0.0.0/0", "IP-CIDR,100.64.0.0/10", "DOMAIN-SUFFIX,ts.net", "DOMAIN,router.vendor.example"):
            with self.assertRaises(RuleError):
                validate_special_groups({"special/lan": [rule]})
        with self.assertRaisesRegex(RuleError, "unknown"):
            validate_special_groups({"special/private-everything": ["IP-CIDR,0.0.0.0/0"]})

    def test_realip_has_no_route_resolver_cidr_keyword_regex_or_platform_suffix(self):
        for group in ("dns/realip", "dns/realip-optional"):
            for rule in ("IP-CIDR,192.168.0.0/16", "DOMAIN-KEYWORD,ntp", "DOMAIN-REGEX,.*", "DOMAIN-SUFFIX,google.com", "DOMAIN,stun.google.com,DIRECT", "DOMAIN,*", "DOMAIN-SUFFIX,in-addr.arpa"):
                with self.assertRaises(RuleError, msg=rule):
                    validate_special_groups({group: [rule]})
        with self.assertRaises(RuleError):
            validate_special_groups({"dns/realip": ["DOMAIN,time.apple.com"]})
        self.assertTrue(validate_special_groups({"dns/realip-optional": ["DOMAIN,time.apple.com"]}))

    def test_role_catalogue_is_not_a_global_dns_exemption(self):
        groups, report = build_special([self.dlc()])
        self.assertIn("DOMAIN,ntp.clock.example", groups["special/ntp"])
        self.assertNotIn("DOMAIN-SUFFIX,clock.example", groups["special/ntp"])
        self.assertNotIn("DOMAIN,ntp.clock.example", groups["dns/realip"])
        self.assertNotIn("DOMAIN,ntp.clock.example", groups["dns/realip-optional"])
        self.assertNotIn("DOMAIN-SUFFIX,ts.net", groups["special/lan"])
        self.assertTrue(any(x["reason"].startswith("reverse-query") for x in report["excluded"]))

    def test_optional_dustinwin_uses_exact_role_records_and_reports_same_lineage(self):
        src = self.source("dustinwin-fakeip", "ntp.clock.example\nstun.voice.example\n+.google.com\n+.#bad\n*\n+.clock.example\nunrelated.example\n")
        groups, report = build_special([self.dlc(), src])
        self.assertIn("DOMAIN,ntp.clock.example", groups["dns/realip-optional"])
        self.assertIn("DOMAIN,stun.voice.example", groups["dns/realip-optional"])
        self.assertNotIn("DOMAIN,unrelated.example", groups["dns/realip-optional"])
        proof = report["provenance"]["dns/realip-optional"]["DOMAIN,ntp.clock.example"][0]
        self.assertIn("not independent corroboration", proof["reason"])
        self.assertEqual(proof["snapshot"]["lineage"], "shared-DLC")
        audit = next(x for x in report["selectors"] if x["source"] == "dustinwin-fakeip")
        self.assertGreater(audit["parse_rejected"], 0)

    def test_private_lists_do_not_turn_public_services_or_reverse_zones_into_lan(self):
        src = self.source("metacubex-private", "payload:\n  - '+.home.arpa'\n  - '+.example'\n  - '+.ts.net'\n  - '+.plex.direct'\n  - '+.10.in-addr.arpa'\n")
        groups, report = build_special([src])
        self.assertFalse(any("ts.net" in rule or "plex.direct" in rule or "in-addr.arpa" in rule for rule in groups["special/lan"]))
        self.assertTrue(any(x["rule"] == "DOMAIN-SUFFIX,ts.net" for x in report["excluded"]))

    def test_present_truncated_or_invalid_registry_fails_not_empty_success(self):
        for text in ("bad-header\nbad\n", "Address Block,Name\n", "Address Block,Name\n10.0.0.0/8,Private-Use\n"):
            with self.assertRaises(RuleError):
                build_special([self.source("iana-special-v4", text, ".csv")])

    def test_registry_snapshot_checks_all_maintained_non_multicast_prefixes(self):
        groups, _ = build_special([])
        for family in (4, 6):
            lines = {line.split(",", 1)[1] for gid, rows in groups.items() if gid not in {"special/public-dns", "special/multicast"} for line in rows if line.startswith("IP-CIDR6," if family == 6 else "IP-CIDR,")}
            text = "Address Block,Name\n" + "".join(prefix + ",Fixture assignment\n" for prefix in sorted(lines))
            src = self.source("iana-special-v" + str(family), text, ".csv")
            _, report = build_special([src])
            self.assertEqual(report["registry_checks"][src["id"]]["status"], "consistent")
            self.assertEqual(report["registry_checks"][src["id"]]["checked_prefixes"], len(lines))

    def test_unavailable_optional_category_is_reported_without_erasing_rfc_data(self):
        root = self.root / "partial"
        root.mkdir()
        (root / "private").write_text("home.arpa\n")
        groups, report = build_special([{"id": "dlc", "path": str(root)}])
        self.assertEqual(len(groups["special/lan"]), 11)
        self.assertTrue(any(x.get("selector") == "category-ntp" and x["status"] == "unavailable" for x in report["selector_health"]))

    def test_config_evidence_and_output_completeness_are_enforced(self):
        config = copy.deepcopy(load_special_config())
        config["groups"][0]["entries"][0]["evidence"] = ["invented-proof"]
        with self.assertRaisesRegex(RuleError, "evidence"):
            build_special([], config)
        with self.assertRaisesRegex(RuleError, "missing"):
            validate_special_groups({"dns/realip": ["DOMAIN,ipv4only.arpa"]}, require_complete=True)
        with self.assertRaisesRegex(RuleError, "empty"):
            validate_special_groups({"special/lan": []})

    def test_present_baselines_require_complete_semantic_coverage(self):
        groups, _ = build_special([])
        for gid, missing in (("special/lan", "IP-CIDR,172.16.0.0/12"),
                             ("special/lan", "DOMAIN-SUFFIX,home.arpa"),
                             ("dns/realip", "DOMAIN,ipv4only.arpa"),
                             ("dns/realip", "DOMAIN-SUFFIX,home.arpa"),
                             ("special/multicast", "IP-CIDR6,ff00::/8"),
                             ("special/benchmark", "IP-CIDR6,2001:2::/48")):
            with self.subTest(group=gid, missing=missing):
                rows = [r for r in groups[gid] if r != missing]
                with self.assertRaisesRegex(RuleError, "mandatory .* coverage is missing"):
                    validate_special_groups({gid: rows})

    def test_lan_coverage_accepts_equivalent_prefix_partition(self):
        groups, _ = build_special([])
        rows = [r for r in groups["special/lan"] if r != "IP-CIDR,172.16.0.0/12"]
        rows += ["IP-CIDR,172.16.0.0/13", "IP-CIDR,172.24.0.0/13"]
        self.assertTrue(validate_special_groups({"special/lan": rows}))
        rows.remove("IP-CIDR,172.24.0.0/13")
        with self.assertRaisesRegex(RuleError, "mandatory address coverage"):
            validate_special_groups({"special/lan": rows})

    def test_config_cannot_bypass_publication_safety_scopes(self):
        config = copy.deepcopy(load_special_config())
        config["groups"][0]["entries"].append({"kind": "IP-CIDR", "value": "198.18.0.0/15", "evidence": ["iana4"], "reason": "pretend benchmark is LAN"})
        with self.assertRaisesRegex(RuleError, "Fake IP"):
            build_special([], config)
