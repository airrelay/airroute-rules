import ipaddress
import json
from pathlib import Path
import random
import tempfile
import unittest

from airroute_data.record_compare import compare_build, _cidr_count, _overlay


class Sink:
    def __init__(self):
        self.geo = []
        self.domains = []

    def geo_change(self, *item):
        self.geo.append(item)

    def domain_change(self, *item):
        self.domains.append(item)


class RecordCompareTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def candidate(self, name, groups, sources=(), published=False):
        root = self.root / name
        root.mkdir()
        files = []
        for group, lines in groups.items():
            file = root / (group + ".list")
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text("\n".join(lines) + ("\n" if lines else ""))
            files.append({"path": group + ".list"})
        manifest = {"data_version": name, "files": files, "summary": {},
                    "source_snapshot": list(sources)}
        if published:
            manifest["publication"] = {"source_sha": "abc", "sequence": 1, "attempt": 1}
        (root / "manifest.json").write_text(json.dumps(manifest))
        return root

    def test_added_removed_reassigned_and_unchanged_are_distinct(self):
        old = self.candidate("old", {"region/cn": ["IP-CIDR,1.0.0.0/24"],
                                      "region/ru": ["IP-CIDR,2.0.0.0/24"]}, published=True)
        new = self.candidate("new", {"region/cn": ["IP-CIDR,1.0.0.0/25"],
                                      "region/us": ["IP-CIDR,1.0.0.128/26"],
                                      "region/ru": ["IP-CIDR,3.0.0.0/24"]})
        sink = Sink()
        report = compare_build(new, old, sink)
        states = report["geo_changes"]["families"]["ipv4"]
        self.assertEqual(states["unchanged"]["addresses"], 128)
        self.assertEqual(states["reassigned"]["addresses"], 64)
        self.assertEqual(states["removed-to-unknown"]["addresses"], 64 + 256)
        self.assertEqual(states["added"]["addresses"], 256)
        self.assertEqual(len(sink.geo), 4)
        self.assertTrue(report["baseline"]["publication_recorded"])
        self.assertEqual(report["candidate"]["role"], "unpublished-candidate")
        self.assertEqual(report, compare_build(new, old))

    def test_ipv6_wide_range_uses_exact_integers_and_canonical_prefix_counts(self):
        old = self.candidate("old", {"region/europe": ["IP-CIDR6,2808::/13"]})
        new = self.candidate("new", {"region/ru": ["IP-CIDR6,2808::/64"]})
        sink = Sink()
        report = compare_build(new, old, sink)
        states = report["geo_changes"]["families"]["ipv6"]
        self.assertEqual(states["reassigned"]["addresses"], 1 << 64)
        self.assertEqual(states["removed-to-unknown"]["addresses"], (1 << 115) - (1 << 64))
        self.assertEqual(states["removed-to-unknown"]["canonical_cidrs"], 51)
        self.assertEqual(sink.geo[0][0], 6)
        self.assertGreater(sink.geo[0][1], (1 << 64))

    def test_prefix_compaction_does_not_invent_an_ip_coverage_change(self):
        old = self.candidate("old", {"region/cn": ["IP-CIDR,1.0.0.0/25", "IP-CIDR,1.0.0.128/25"]})
        new = self.candidate("new", {"region/cn": ["IP-CIDR,1.0.0.0/24"]})
        report = compare_build(new, old)
        geo = report["geo_changes"]
        self.assertEqual(geo["changed_intervals"], 0)
        self.assertEqual(geo["families"]["ipv4"]["unchanged"]["canonical_cidrs"], 1)
        profile = report["semantic_products"]["products"]["region/cn"]
        self.assertEqual(profile["before"]["ipv4_cidrs"], 2)
        self.assertEqual(profile["after"]["ipv4_cidrs"], 1)

    def test_parent_suffix_covers_exact_predicate_without_removal(self):
        old = self.candidate("old", {"category/dev": ["DOMAIN,api.example.com"]})
        new = self.candidate("new", {"category/dev": ["DOMAIN-SUFFIX,example.com"]})
        sink = Sink()
        report = compare_build(new, old, sink)
        changes = report["domain_changes"]["products"]["category/dev"]
        self.assertEqual(changes, {"covered-by-current": 1, "added": 1})
        self.assertIn(("category/dev", "DOMAIN,api.example.com", "covered-by-current", "DOMAIN-SUFFIX,example.com"), sink.domains)
        self.assertFalse(any(row[2] == "removed" for row in sink.domains))

    def test_narrowing_suffix_to_exact_is_a_semantic_loss(self):
        old = self.candidate("old", {"category/dev": ["DOMAIN-SUFFIX,example.com"]})
        new = self.candidate("new", {"category/dev": ["DOMAIN,api.example.com"]})
        report = compare_build(new, old)
        self.assertEqual(report["domain_changes"]["products"]["category/dev"], {"removed": 1, "covered-by-baseline": 1})

    def test_source_state_version_hash_and_publication_roles_are_explicit(self):
        old = self.candidate("old", {}, [{"id": "geo", "status": "available", "version": "v1", "sha256": "a"},
                                          {"id": "gone", "status": "available"}])
        new = self.candidate("new", {}, [{"id": "geo", "status": "missing-credentials", "version": "v2", "sha256": "b"},
                                          {"id": "new", "status": "disabled"}])
        report = compare_build(new, old)
        changes = {row["source"]: row for row in report["source_changes"]}
        self.assertEqual(changes["geo"]["fields"]["status"], {"before": "available", "after": "missing-credentials"})
        self.assertEqual(changes["geo"]["fields"]["sha256"], {"before": "a", "after": "b"})
        self.assertEqual(changes["gone"]["status"], "removed")
        self.assertEqual(changes["new"]["status"], "added")
        self.assertFalse(report["baseline"]["publication_recorded"])

    def test_overlapping_regions_fail_comparison_instead_of_arbitrary_assignment(self):
        old = self.candidate("old", {"region/cn": ["IP-CIDR,1.0.0.0/24"],
                                      "region/us": ["IP-CIDR,1.0.0.0/25"]})
        new = self.candidate("new", {})
        with self.assertRaisesRegex(ValueError, "cross-region overlapping"):
            compare_build(new, old)

    def test_changed_samples_are_explicitly_bounded_but_trace_is_complete(self):
        old = self.candidate("old", {})
        lines = [f"DOMAIN,host{i}.example.com" for i in range(50)]
        new = self.candidate("new", {"service/test": lines})
        sink = Sink()
        report = compare_build(new, old, sink)
        self.assertEqual(len(sink.domains), 50)
        self.assertEqual(len(report["domain_changes"]["samples"]), 20)
        self.assertFalse(report["domain_changes"]["samples_complete"])

    def test_cidr_cover_counter_matches_ipaddress_without_per_address_expansion(self):
        for start, end in [(0, 255), (1, 255), (128, 256), ((1 << 120) + 1, (1 << 120) + (1 << 64))]:
            width = 32 if end < (1 << 32) else 128
            cls = ipaddress.IPv4Address if width == 32 else ipaddress.IPv6Address
            expected = sum(1 for _ in ipaddress.summarize_address_range(cls(start), cls(end)))
            self.assertEqual(_cidr_count(start, end, width), expected)

    def test_overlay_matches_independent_pointwise_oracle_for_both_families(self):
        rng = random.Random(31)
        for _ in range(30):
            old_rows, new_rows = [], []
            expected = {}
            for family in (4, 6):
                old = [rng.choice([None, "region/cn", "region/ru"]) for _ in range(32)]
                new = [rng.choice([None, "region/cn", "region/ru"]) for _ in range(32)]
                for values, rows in ((old, old_rows), (new, new_rows)):
                    for i, value in enumerate(values):
                        if value is not None:
                            rows.append((family, i, i, value))
                for i, (before, after) in enumerate(zip(old, new)):
                    if before is not None or after is not None:
                        expected[(family, i)] = (before, after)
            observed = {}
            for family, start, end, old, new, _status in _overlay(old_rows, new_rows):
                for value in range(start, end + 1):
                    self.assertNotIn((family, value), observed)
                    observed[(family, value)] = (old, new)
            self.assertEqual(expected, observed)


if __name__ == "__main__":
    unittest.main()
