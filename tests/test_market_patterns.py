"""CN pattern intersections concern whole predicate languages, not just apexes."""
import re
import unittest

from airroute_data.domains import RuleError, _CNIndex, normalize_rule, validate_domain_groups


class MarketPatternTests(unittest.TestCase):
    def test_keyword_matches_suffix_descendant_even_when_apex_does_not(self):
        pattern = normalize_rule("DOMAIN-KEYWORD", "mainland")
        suffix = normalize_rule("DOMAIN-SUFFIX", "service.example")
        witness = "mainland.service.example"
        self.assertNotIn(pattern.value, suffix.value)
        self.assertIn(pattern.value, witness)
        self.assertTrue(witness.endswith("." + suffix.value))
        self.assertTrue(_CNIndex([pattern]).overlaps(suffix))

    def test_regex_matches_suffix_descendant_even_when_apex_does_not(self):
        pattern = normalize_rule("DOMAIN-REGEX", r"^cn\.service\.example$")
        suffix = normalize_rule("DOMAIN-SUFFIX", "service.example")
        witness = "cn.service.example"
        self.assertIsNone(re.search(pattern.value, suffix.value))
        self.assertIsNotNone(re.search(pattern.value, witness))
        self.assertTrue(witness.endswith("." + suffix.value))
        self.assertTrue(_CNIndex([pattern]).overlaps(suffix))

    def test_exact_host_still_uses_actual_pattern_match(self):
        index = _CNIndex([normalize_rule("DOMAIN-KEYWORD", "mainland")])
        self.assertTrue(index.overlaps(normalize_rule("DOMAIN", "mainland.service.example")))
        self.assertFalse(index.overlaps(normalize_rule("DOMAIN", "elsewhere.service.example")))

    def test_publication_requires_explicit_unresolved_pattern_mark(self):
        for pattern in ("DOMAIN-KEYWORD,mainland", r"DOMAIN-REGEX,^cn\.service\.example$"):
            with self.subTest(pattern=pattern):
                groups = {"region/cn": [pattern], "service/global": ["DOMAIN-SUFFIX,service.example"]}
                with self.assertRaisesRegex(RuleError, "CN/overseas domain overlap"):
                    validate_domain_groups(groups)
                report = validate_domain_groups(groups, unresolved_pattern_groups=["service/global"])
                self.assertEqual(report["unresolved_pattern_intersections"], 1)
                self.assertEqual(report["declared_market_overlaps"], 0)

    def test_pattern_mark_does_not_bypass_known_literal_overlap(self):
        groups = {"region/cn": ["DOMAIN-KEYWORD,mainland", "DOMAIN,cn.service.example"],
                  "service/global": ["DOMAIN-SUFFIX,service.example"]}
        with self.assertRaisesRegex(RuleError, "CN/overseas domain overlap"):
            validate_domain_groups(groups, unresolved_pattern_groups=["service/global"])


if __name__ == "__main__":
    unittest.main()
