import ipaddress
import json
from pathlib import Path
import re
import tempfile
import unittest

from airroute_data.domains import DLC, RuleError, build_domains, load_products, minimize, normalize_rule, parse_third_party, validate_domain_groups, official_domains, domain_match


class DomainTests(unittest.TestCase):
    def temporary_dlc(self, files):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / "data").mkdir()
        for name, text in files.items():
            (root / "data" / name).write_text(text, encoding="utf-8")
        return root

    def test_dlc_attributes_are_filters_not_flags(self):
        root = self.temporary_dlc({
            "base": "full:a.example @cn\nb.example @!cn\nregexp:^api[0-9]+\\.example$ @cn @ads\n",
            "chosen": "include:base @cn @-ads\n",
        })
        dlc = DLC(root)
        rules = dlc.expand("chosen")
        self.assertEqual([r.text for r in rules], ["DOMAIN,a.example"])
        self.assertEqual(rules[0].attrs, frozenset({"cn"}))
        self.assertEqual([r.text for r in dlc.expand("base", ["!cn"])], ["DOMAIN-SUFFIX,b.example"])

    def test_dlc_nested_include_and_affiliation_without_file(self):
        root = self.temporary_dlc({"a": "example.com &virtual @ads\n", "b": "include:virtual @ads\n"})
        self.assertEqual(DLC(root).expand("b")[0].text, "DOMAIN-SUFFIX,example.com")

    def test_dlc_missing_and_cycle_fail_not_partial_silence(self):
        root = self.temporary_dlc({"a": "include:b\n", "b": "include:a\n"})
        with self.assertRaisesRegex(RuleError, "cycle"):
            DLC(root).expand("a")
        with self.assertRaisesRegex(RuleError, "missing"):
            DLC(root).expand("unknown")

    def test_dlc_no_prefix_means_suffix_not_keyword(self):
        root = self.temporary_dlc({"a": "Example.COM\nfull:WWW.Example.COM\nkeyword:Test\nregexp:^api\\.example$\n"})
        self.assertEqual([r.text for r in DLC(root).expand("a")], [
            "DOMAIN-SUFFIX,example.com", "DOMAIN,www.example.com", "DOMAIN-KEYWORD,test", "DOMAIN-REGEX,^api\\.example$",
        ])

    def test_unicode_literal_is_quarantined_not_redirected_by_idna2003(self):
        for value in ("straße.de", "STRAẞE.DE", "例子.中国"):
            with self.assertRaisesRegex(RuleError, "agreed IDNA mapping"):
                normalize_rule("DOMAIN", value)
        self.assertEqual(normalize_rule("DOMAIN", "XN--STRAE-OQA.DE").text, "DOMAIN,xn--strae-oqa.de")
        rules, bad = parse_third_party("DOMAIN,straße.de\nDOMAIN,strasse.de\nDOMAIN,xn--strae-oqa.de\n", "surge")
        self.assertEqual([r.text for r in rules], ["DOMAIN,strasse.de", "DOMAIN,xn--strae-oqa.de"])
        self.assertEqual(len(bad), 1)
        self.assertEqual(bad[0]["predicate"], "DOMAIN,straße.de")

    def test_v2ray_unprefixed_config_value_is_keyword(self):
        rules, bad = parse_third_party('["example.com","full:www.example.org","domain:example.net"]', "v2ray")
        self.assertFalse(bad)
        self.assertEqual([r.text for r in rules], ["DOMAIN-KEYWORD,example.com", "DOMAIN,www.example.org", "DOMAIN-SUFFIX,example.net"])

    def test_v2ray_compound_rule_not_flattened(self):
        payload = {"routing": {"rules": [{"type": "field", "domain": ["domain:example.com"], "network": "tcp", "outboundTag": "proxy"}]}}
        rules, bad = parse_third_party(json.dumps(payload), "v2ray")
        self.assertEqual(rules, [])
        self.assertIn("compound", bad[0]["reason"])

    def test_compound_and_ua_mitm_not_supported(self):
        rules, bad = parse_third_party("AND,((DOMAIN,a.example),(NETWORK,TCP))\nNOT,((DOMAIN,b.example))\nUSER-AGENT,Client*\nURL-REGEX,^https:\n", "surge")
        self.assertEqual(rules, [])
        self.assertEqual(len(bad), 4)

    def test_policy_target_omitted_no_client_exit_assumption(self):
        rules, bad = parse_third_party("DOMAIN-SUFFIX,example.com,Proxy\nIP-CIDR,192.0.2.7/24,no-resolve", "surge")
        self.assertFalse(bad)
        self.assertEqual([r.text for r in rules], ["DOMAIN-SUFFIX,example.com", "IP-CIDR,192.0.2.0/24"])

    def test_surge_domainset_leading_dot_is_significant(self):
        rules, bad = parse_third_party("# source\n.example.com\nwww.example.net\n", "surge-domainset")
        self.assertFalse(bad)
        self.assertEqual([r.text for r in rules], ["DOMAIN-SUFFIX,example.com", "DOMAIN,www.example.net"])

    def test_yaml_classical_and_ambiguous_alias(self):
        rules, bad = parse_third_party("payload:\n  - 'DOMAIN-SUFFIX,example.com'\n  - DOMAIN,www.example.net\n  - *badalias\n", "mihomo")
        self.assertEqual(len(rules), 2)
        self.assertEqual(len(bad), 1)

    def test_clash_plus_suffix_and_strict_star_are_not_conflated(self):
        rules, bad = parse_third_party("payload:\n  - '+.example.com'\n  - '*.strict.example'\n", "clash", behavior="domain")
        self.assertFalse(bad)
        self.assertEqual(rules[0].text, "DOMAIN-SUFFIX,example.com")
        strict = rules[1]
        self.assertEqual(strict.kind, "DOMAIN-REGEX")
        self.assertFalse(re.search(strict.value, "strict.example"))
        self.assertTrue(re.search(strict.value, "x.strict.example"))
        self.assertTrue(re.search(strict.value, "x.y.strict.example"))

    def test_ambiguous_surge_wildcard_and_regex_commas_quarantined(self):
        rules, bad = parse_third_party("DOMAIN-WILDCARD,*.example.com\nDOMAIN-REGEX,^x{1,3}\\.example$\n", "surge")
        self.assertEqual(rules, [])
        self.assertEqual(len(bad), 2)

    def test_unsupported_regex_never_silently_broadened(self):
        for regex in (r"^(?!foo).*example$", r"^(a)\1$", r"(?P<name>x)(?P=name)"):
            with self.assertRaises(RuleError):
                normalize_rule("DOMAIN-REGEX", regex)

    def test_core_lowercase_safe_negated_regex_shorthands_preserve_language(self):
        for operator in ("D", "S", "W"):
            original = rf"^api\{operator}+\.example$"
            rule = normalize_rule("DOMAIN-REGEX", original)
            self.assertEqual(rule.value, rf"^api[^\{operator.lower()}]+\.example$")
            self.assertEqual(dict(rule.source_details)["original_regex"],original)
            for host in ("apiabc.example","api123.example","api-a.example","api.a.example","api_.example"):
                self.assertEqual(bool(re.search(original,host)),bool(re.search(rule.value,host)))
        for operator in ("B", "A", "P"):
            with self.assertRaisesRegex(RuleError,"uppercase regex escape"):
                normalize_rule("DOMAIN-REGEX",rf"^api\{operator}+\.example$")
        with self.assertRaises(RuleError):
            normalize_rule("DOMAIN-REGEX",r"^api[\S]+\.example$")

    def test_openai_webpubsub_regex_matches_concrete_hosts_after_core_normalization(self):
        original=r"^chatgpt-async-webps-prod-\S+-\d+\.webpubsub\.azure\.com$"
        rule=normalize_rule("DOMAIN-REGEX",original)
        for host in ("chatgpt-async-webps-prod-eastus-3.webpubsub.azure.com",
                     "chatgpt-async-webps-prod-a.b-42.webpubsub.azure.com"):
            self.assertTrue(domain_match(rule,host))
            self.assertTrue(domain_match(rule,host.upper()))
        for host in ("chatgpt-async-webps-prod-eastus-x.webpubsub.azure.com",
                     "chatgpt-async-webps-prod-eastus-3.webpubsub.azure.com.evil",
                     "evil.chatgpt-async-webps-prod-eastus-3.webpubsub.azure.com"):
            self.assertFalse(domain_match(rule,host))

    def test_core_lowercase_must_not_broaden_regex_literals_or_classes(self):
        for original, host in ((r"^api[A-Z]+\.example$", "apixy.example"), (r"^API\.example$", "api.example")):
            self.assertFalse(re.search(original, host))
            self.assertTrue(re.search(original.lower(), host))
            with self.assertRaisesRegex(RuleError, "literals/classes"):
                normalize_rule("DOMAIN-REGEX", original)

    def test_cross_type_minimize_and_label_boundary(self):
        lines = [
            ("DOMAIN-SUFFIX", "example.com"), ("DOMAIN-SUFFIX", "a.example.com"),
            ("DOMAIN", "www.example.com"), ("DOMAIN", "badexample.com"),
            ("DOMAIN-KEYWORD", "abc"), ("DOMAIN-KEYWORD", "abcdef"), ("DOMAIN", "www.abcdef.net"),
            ("IP-CIDR", "192.0.2.0/25"), ("IP-CIDR", "192.0.2.128/25"),
            ("IP-CIDR6", "2001:db8::/65"), ("IP-CIDR6", "2001:db8:0:0:8000::/65"),
        ]
        rules = [r.text for r in minimize(normalize_rule(k, v) for k, v in lines)]
        self.assertEqual(rules, ["DOMAIN,badexample.com", "DOMAIN-KEYWORD,abc", "DOMAIN-SUFFIX,example.com", "IP-CIDR,192.0.2.0/24", "IP-CIDR6,2001:db8::/64"])

    def test_minimize_equivalent_on_representative_queries_and_ip_union(self):
        original = [normalize_rule(k, v) for k, v in [("DOMAIN-SUFFIX", "a.example"), ("DOMAIN", "x.a.example"), ("DOMAIN-SUFFIX", "x.a.example"), ("DOMAIN-KEYWORD", "needle"), ("DOMAIN", "needle.example")]]
        compact = minimize(original)
        def match(rules, host):
            return any((r.kind == "DOMAIN" and host == r.value) or (r.kind == "DOMAIN-SUFFIX" and (host == r.value or host.endswith("." + r.value))) or (r.kind == "DOMAIN-KEYWORD" and r.value in host) for r in rules)
        for host in ("a.example", "x.a.example", "y.x.a.example", "bada.example", "a.example.invalid", "needle.example", "www.needle.other", "none.invalid"):
            self.assertEqual(match(original, host), match(compact, host), host)
        before = [normalize_rule("IP-CIDR", "192.0.2.0/25"), normalize_rule("IP-CIDR", "192.0.2.128/26")]
        after = minimize(before)
        def addresses(rows):
            return {int(ip) for r in rows for ip in ipaddress.ip_network(r.value)}
        self.assertEqual(addresses(before), addresses(after))

    def test_cn_and_global_collections_preserve_overlap(self):
        root = self.temporary_dlc({
            "cn-test": "domain:mainland.example\nfull:cn.mixed.example\ncn\nkeyword:china\n",
            "foreign": "mainland.example\nx.mainland.example\nmixed.example\nvalid.example\nkeyword:unbounded\n",
        })
        products = {"schema": 1, "groups": [
            {"id": "region/cn-domain", "selectors": [{"source": "dlc", "category": "cn-test"}]},
            {"id": "category/test", "selectors": [{"source": "dlc", "category": "foreign"}]},
        ]}
        groups, report = build_domains([{"id": "dlc", "format": "dlc", "path": str(root)}], products)
        self.assertEqual(set(groups["region/cn-domain"]), {"DOMAIN,cn.mixed.example", "DOMAIN-SUFFIX,mainland.example", "DOMAIN-SUFFIX,cn", "DOMAIN-KEYWORD,china"})
        self.assertEqual(set(groups["category/test"]), {"DOMAIN-SUFFIX,mainland.example", "DOMAIN-SUFFIX,mixed.example", "DOMAIN-SUFFIX,valid.example", "DOMAIN-KEYWORD,unbounded"})
        self.assertFalse(report["quarantined"])

    def test_cn_boundary_not_similar_spelling(self):
        root = self.temporary_dlc({"cn-test": "a.example\n", "foreign": "bada.example\nexample.net\n"})
        products = {"schema": 1, "groups": [{"id": "region/cn-domain", "selectors": [{"source": "dlc", "category": "cn-test"}]}, {"id": "category/test", "selectors": [{"source": "dlc", "category": "foreign"}]}]}
        groups, _ = build_domains([{"id": "dlc", "format": "dlc", "path": str(root)}], products)
        self.assertEqual(len(groups["category/test"]), 2)

    def test_mature_source_preserves_shared_endpoints_ips_and_asn(self):
        root = self.temporary_dlc({"cn-test": "local.example\n", "foreign": "owned.example\n"})
        reference = root / "reference.list"
        reference.write_text("DOMAIN-SUFFIX,owned.example\nDOMAIN-SUFFIX,shared-ca.example\nIP-ASN,13335\nIP-CIDR,192.0.2.0/24\n")
        products = {"schema": 1, "groups": [{"id": "region/cn-domain", "selectors": [{"source": "dlc", "category": "cn-test"}]}, {"id": "category/test", "selectors": [{"source": "dlc", "category": "foreign"}, {"source": "ref", "shared_roots": ["shared-ca.example"]}]}]}
        groups, report = build_domains([{"id": "dlc", "format": "dlc", "path": str(root)}, {"id": "ref", "format": "surge", "path": str(reference)}], products)
        self.assertEqual(set(groups["category/test"]), {"DOMAIN-SUFFIX,owned.example", "DOMAIN-SUFFIX,shared-ca.example", "IP-CIDR,192.0.2.0/24", "IP-ASN,13335"})
        self.assertFalse(report["quarantined"])

    def test_official_wildcards_convert_without_promoting_parent_and_report_covered_raw_templates(self):
        data=[{"id":1,"serviceArea":"Common","urls":["machine.example","*.wild.example","autodiscover.*.onmicrosoft.com"]},
              {"id":2,"serviceArea":"Common","urls":["second-machine.example","*cdn.onenote.net"]},
              {"id":3,"serviceArea":"Common","urls":["*.onmicrosoft.com"]}]
        rows,bad=official_domains(data,"microsoft365",{"adapter":"microsoft365"})
        self.assertEqual(len(bad),1)
        self.assertEqual(bad[0]["record_id"],1)
        self.assertEqual(bad[0]["endpoint_index"],3)
        self.assertEqual(bad[0]["endpoint_field"],"urls")
        self.assertEqual(bad[0]["covered_by"],r"DOMAIN-REGEX,^.+\.onmicrosoft\.com$")
        self.assertIn("unsupported",bad[0]["coverage_note"])
        cdn=next(r for r in rows if dict(r.source_details)["upstream_value"]=="*cdn.onenote.net")
        for host in ("cdn.onenote.net","abc-cdn.onenote.net","nested.cdn.onenote.net"):
            self.assertTrue(domain_match(cdn,host))
        for host in ("onenote.net","cdn.onenote.net.evil","cdn.notonenote.net"):
            self.assertFalse(domain_match(cdn,host))
        strict=next(r for r in rows if dict(r.source_details)["upstream_value"]=="*.wild.example")
        self.assertTrue(domain_match(strict,"a.wild.example"))
        self.assertFalse(domain_match(strict,"wild.example"))

    def test_microsoft365_url_only_ip_only_and_combined_records_preserve_provenance(self):
        data=[{"id":10,"serviceArea":"Common","urls":["service.example"]},
              {"id":20,"serviceArea":"Exchange","ips":["203.0.113.0/24","2001:db8::/32"]},
              {"id":30,"serviceArea":"SharePoint","urls":["tenant.example"],"ips":["198.51.100.0/24"],"tcpPorts":"443"}]
        rows,bad=official_domains(data,"microsoft365",{"adapter":"microsoft365"})
        self.assertFalse(bad)
        self.assertEqual({r.text for r in rows},{"DOMAIN,service.example","DOMAIN,tenant.example","IP-CIDR,203.0.113.0/24","IP-CIDR6,2001:db8::/32","IP-CIDR,198.51.100.0/24"})
        self.assertEqual({dict(r.source_details)["record_id"] for r in rows},{10,20,30})
        for row in rows:
            details=dict(row.source_details)
            self.assertEqual(row.source,"microsoft365")
            self.assertEqual(details["endpoint_field"],"ips" if row.kind.startswith("IP-CIDR") else "urls")
            self.assertGreater(details["endpoint_index"],0)
        self.assertEqual(dict(next(r for r in rows if r.value=="198.51.100.0/24").source_details)["tcpPorts"],"443")

    def test_upstream_resolution_modifiers_are_removed_and_recorded(self):
        rows,bad=parse_third_party("IP-CIDR,1.0.0.0/25,no-resolve\nIP-CIDR,1.0.0.128/25,DIRECT,no-resolve\nIP-CIDR,1.0.0.0/24\nIP-ASN,132203,no-resolve\n","surge")
        self.assertFalse(bad)
        compact=[r.text for r in minimize(rows)]
        self.assertEqual(compact,["IP-ASN,132203","IP-CIDR,1.0.0.0/24"])
        self.assertEqual([r.removed_modifiers for r in rows],[("no-resolve",),("no-resolve",),(),("no-resolve",)])
        validate_domain_groups({"provider/test":compact})
        with self.assertRaises(RuleError):
            validate_domain_groups({"provider/test":["IP-ASN,132203,no-resolve"]})

    def test_required_selector_missing_fails_but_optional_source_reported(self):
        root = self.temporary_dlc({"a": "x.example\n"})
        products = {"schema": 1, "groups": [{"id": "region/cn-domain", "selectors": [{"source": "dlc", "category": "missing", "required": True}]}]}
        with self.assertRaisesRegex(RuleError, "required selector"):
            build_domains([{"id": "dlc", "format": "dlc", "path": str(root)}], products)
        with self.assertRaisesRegex(RuleError, "source unavailable"):
            build_domains([], products)
        products["groups"][0]["selectors"] = [{"source": "absent"}]
        _, report = build_domains([], products)
        self.assertEqual(len(report["unavailable_selectors"]), 1)

    def test_available_optional_selected_source_failure_is_fatal_and_path_safe(self):
        products={"schema":1,"groups":[{"id":"region/cn-domain","selectors":[]},
                  {"id":"category/test","selectors":[{"source":"ref","path":"missing.list"}]}]}
        errors=[]
        for path in ("/tmp/build-a/missing","/tmp/build-b/missing"):
            with self.assertRaises(RuleError) as error:
                build_domains([{"id":"ref","format":"surge","path":path}],products)
            errors.append(str(error.exception))
        self.assertEqual(errors[0],errors[1])
        self.assertNotIn("/tmp/",errors[0])
        groups,report=build_domains([{"id":"ref","format":"surge","status":"disabled"}],products)
        self.assertEqual(groups["category/test"],[])
        self.assertEqual(len(report["unavailable_selectors"]),1)

    def test_selected_available_malformed_official_json_is_not_optional_success(self):
        root=self.temporary_dlc({"cn":"local.example\n"})
        path=root/"broken.json";path.write_text("{broken")
        products={"schema":1,"groups":[{"id":"region/cn-domain","selectors":[]},
            {"id":"provider/m365","selectors":[{"source":"m365","format":"official-json","adapter":"microsoft365"}]}]}
        with self.assertRaisesRegex(RuleError,"selected selector"):
            build_domains([{"id":"m365","path":str(path),"format":"official-json"}],products)

    def test_output_validation_checks_format_and_region_types_not_identity(self):
        valid = {"region/cn-domain": ["DOMAIN-SUFFIX,cn", "DOMAIN,cn.mixed.example"],
                 "region/cn-ip": ["IP-CIDR,1.0.0.0/24"],
                 "category/test": ["DOMAIN-SUFFIX,mixed.example", "IP-ASN,13335"]}
        self.assertEqual(validate_domain_groups(valid)["rules"]["category/test"], 2)
        for invalid in ({"region/cn-domain": ["IP-CIDR,1.0.0.0/24"]},
                        {"region/ru": ["DOMAIN,example.ru"]},
                        {"category/test": ["DOMAIN-SUFFIX,example.com,no-resolve"]},
                        {"category/test": ["DOMAIN,EXAMPLE.COM"]},
                        {"category/test": ["DOMAIN,example.com", "DOMAIN,example.com"]}):
            with self.assertRaises(RuleError):
                validate_domain_groups(invalid)

    def test_valid_patterns_and_tlds_are_not_cross_collection_vetoes(self):
        strict = r"DOMAIN-REGEX,^.+\.office\.com$"
        for local in ("DOMAIN,office.com", "DOMAIN-SUFFIX,office.com", "DOMAIN-SUFFIX,com", "DOMAIN-KEYWORD,office"):
            validate_domain_groups({"region/cn-domain": [local], "provider/microsoft": [strict]})

    def test_supported_non_ip_preserves_upstream_process_and_asn(self):
        rows, rejected = parse_third_party("PROCESS-NAME,WeChat.exe\nIP-ASN,45102\nUSER-AGENT,WeChat*\n", "surge")
        self.assertEqual([r.text for r in rows], ["PROCESS-NAME,WeChat.exe", "IP-ASN,45102"])
        self.assertEqual(len(rejected), 1)
        for line in ("IP-ASN,-1", "IP-ASN,4294967296", "PROCESS-NAME,"):
            self.assertTrue(parse_third_party(line,"surge")[1])

    def test_strict_subdomain_regex_minimized_only_by_covering_suffix(self):
        strict = normalize_rule("DOMAIN-REGEX", r"^.+\.a\-b\.example$")
        for suffix in ("a-b.example", "example"):
            compact = minimize([strict, normalize_rule("DOMAIN-SUFFIX", suffix)])
            self.assertEqual([r.text for r in compact], ["DOMAIN-SUFFIX," + suffix])
        for suffix in ("child.a-b.example", "not-a-b.example"):
            compact = minimize([strict, normalize_rule("DOMAIN-SUFFIX", suffix)])
            self.assertIn(strict.text, [r.text for r in compact])

    def test_registry_validates_single_cn_and_unique_paths(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        p = Path(temp.name) / "products.json"
        p.write_text(json.dumps({"schema": 1, "groups": [{"id": "region/cn-domain"}, {"id": "region/cn-domain"}]}))
        with self.assertRaisesRegex(RuleError, "duplicate"):
            load_products(p)
        self.assertEqual(load_products(Path(__file__).parents[1] / "config/products.json")["schema"], 1)

    def test_build_deterministic_and_provenance_precedes_compaction(self):
        root = self.temporary_dlc({"a": "example.com\nfull:www.example.com\n"})
        products = {"schema": 1, "groups": [{"id": "region/cn-domain", "selectors": [{"source": "dlc", "category": "a"}]}]}
        src = [{"id": "dlc", "format": "dlc", "path": str(root)}]
        first = build_domains(src, products)
        second = build_domains(src, products)
        self.assertEqual(first, second)
        self.assertEqual(first[0]["region/cn-domain"], ["DOMAIN-SUFFIX,example.com"])
        self.assertEqual(len(first[1]["provenance"]["region/cn-domain"]), 2)


if __name__ == "__main__":
    unittest.main()
