"""Independent publication-boundary regression checks, isolated synthetic inputs."""
import copy
import json
from pathlib import Path
import unittest

import test_pipeline as fixture_module
from airroute_data.ardb import read_database, write_database
from airroute_data.pipeline import build
from airroute_data.validation import file_digest, validate_candidate


class IntegrationReviewTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_module.PipelineTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_coverage_gate_counts_are_verified_against_decoded_geo(self):
        target, manifest = self.fixture.run_build()
        for key in ("geo_v4_addresses", "geo_v6_addresses"):
            with self.subTest(key=key):
                forged = copy.deepcopy(manifest)
                forged["summary"][key] = 10**50
                (target / "manifest.json").write_text(json.dumps(forged))
                with self.assertRaisesRegex(ValueError, "summary|coverage"):
                    validate_candidate(target)

    def test_geo_overlap_across_cn_and_ru_fails_even_with_consistent_lists_and_hashes(self):
        target, manifest = self.fixture.run_build()
        groups = read_database(target / "geo.ardb", "geo")
        self.assertIn("2.2.2.0/24", groups[9])
        groups[1].append("2.2.2.0/24")
        write_database(target / "geo.ardb", "geo", groups)
        cn = target / "region" / "cn.list"
        cn.write_text(cn.read_text() + "IP-CIDR,2.2.2.0/24\n")
        for record in manifest["files"]:
            path = target / record["path"]
            record.update(bytes=path.stat().st_size, sha256=file_digest(path))
        manifest["summary"]["geo_prefixes"] += 1
        manifest["summary"]["geo_v4_addresses"] += 256
        (target / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "overlap|multiple.*region"):
            validate_candidate(target)

    def test_withheld_country_source_never_votes(self):
        path = self.fixture.snapshot / "snapshot.json"
        snapshot = json.loads(path.read_text())
        a = snapshot["sources"][0]
        b = snapshot["sources"][1]
        b["publish_allowed"] = False
        # A separate synthetic country publisher with A's estimates lets the
        # build remain useful. B's conflicting estimate must not participate.
        c = copy.deepcopy(a)
        c.update(id="country-c", lineage="publisher-c")
        snapshot["sources"].append(c)
        path.write_text(json.dumps(snapshot))
        target = self.fixture.root / "withheld"
        manifest = build(path, target, self.fixture.config)
        geo = read_database(target / "geo.ardb", "geo")
        self.assertIn("1.1.1.0/24", geo[14])
        self.assertEqual(manifest["summary"]["country_lineages"], 2)
        geo_report = json.loads((target / "reports" / "geo.json").read_text())
        self.assertNotIn("country-b", geo_report["usable_sources"])
        sources_report = json.loads((target / "reports" / "sources.json").read_text())
        self.assertTrue(any(s["id"] == "country-b" for s in sources_report["unavailable_or_withheld"]))
