"""Trace observation must never change geographical or ASN product decisions."""
import ipaddress
import json
from dataclasses import replace
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from airroute_data.geo import CountryRecord, fuse_country, parse_source as parse_country
from airroute_data.routing import (AuxiliaryRecord, RoutingRecord, audit_auxiliary, fuse_routes,
                                   parse_source as parse_routes)


REGISTRY = Path(__file__).resolve().parents[1] / "config/regions.json"


class Sink:
    def __init__(self):
        self.geo_inputs = []
        self.decisions = []
        self.routes = []
        self.sources = []

    def geo_input(self, record):
        self.geo_inputs.append(record)

    def geo_decision(self, detail):
        self.decisions.append(detail)

    def route_input(self, record, status, reason):
        self.routes.append((record, status, reason))

    def source_event(self, source, stage, status, **stats):
        self.sources.append({"source": source, "stage": stage, "status": status, **stats})


class GeoTraceTests(unittest.TestCase):
    def test_trace_preserves_all_product_decisions_and_issue_json(self):
        rows = [CountryRecord.network("1.0.0.0/24", "CN", "a"),
                CountryRecord.network("1.0.0.0/25", "CN", "b"),
                CountryRecord.network("1.0.0.128/25", "US", "b")]
        sink = Sink()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "issues.jsonl"
            before = fuse_country(rows, REGISTRY, details_path=path)
            old_bytes = path.read_bytes()
            after = fuse_country(rows, REGISTRY, details_path=path, trace=sink)
            self.assertEqual(old_bytes, path.read_bytes())
        self.assertEqual(before, after)
        self.assertEqual(rows, sink.geo_inputs)
        issue = next(r for r in sink.decisions if r["status"] == "conflicting-regions")
        self.assertEqual(issue["source_regions"], {"a": [1], "b": [11]})
        self.assertEqual(issue["start_int"], int(ipaddress.IPv4Address("1.0.0.128")))
        self.assertEqual(issue["end_int"], int(ipaddress.IPv4Address("1.0.0.255")))
        self.assertTrue(any(row["status"] == "source-agreement" for row in sink.decisions))
        self.assertTrue(any(row["status"] == "missing-all-sources" for row in sink.decisions))
        # Existing report samples must not accidentally gain diagnostic-only fields.
        self.assertFalse(any("source_regions" in row for row in after["issues"]))

    def test_ipv6_wide_interval_and_more_specific_original_ranges_retained(self):
        rows = [CountryRecord.network("2808::/13", "CH", "old"),
                CountryRecord.network("2808::/13", "UY", "new"),
                CountryRecord.network("2808::/64", "UY", "old")]
        sink = Sink()
        result = fuse_country(rows, REGISTRY, trace=sink)
        self.assertEqual(sink.geo_inputs, rows)
        accepted = next(row for row in sink.decisions if row["status"] == "source-agreement")
        self.assertEqual(accepted["sources"], {"old": ["UY"], "new": ["UY"]})
        conflicts = [row for row in sink.decisions if row["status"] == "conflicting-regions"]
        self.assertEqual(sum(row["end_int"] - row["start_int"] + 1 for row in conflicts),
                         (1 << 115) - (1 << 64))
        self.assertEqual(result["groups"], {13: ["2808::/64"]})

    def test_country_parser_rows_families_empty_and_failed_are_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "country.csv"
            path.write_text("network,country_code\n1.0.0.0/24,CN\n2400::/64,RU\n")
            sink = Sink()
            rows = list(parse_country("country-csv", path, {"id": "fixture"}, trace=sink))
            event = sink.sources[-1]
            self.assertEqual((event["records_read"], event["records_parsed"], event["ipv4_records"], event["ipv6_records"]), (2, 2, 1, 1))
            self.assertEqual(rows, list(parse_country("country-csv", path, {"id": "fixture"})))
            path.write_text("network,country_code\n")
            self.assertFalse(list(parse_country("country-csv", path, {"id": "fixture"}, trace=sink)))
            self.assertEqual(sink.sources[-1]["status"], "empty")
            path.write_text("network,country_code\n1.0.0.0/24,CN\ninvalid,RU\n")
            with self.assertRaises(ValueError):
                list(parse_country("country-csv", path, {"id": "fixture"}, trace=sink))
            event = sink.sources[-1]
            self.assertEqual(event["status"], "failed")
            self.assertEqual((event["records_read"], event["records_parsed"]), (2, 1))
            self.assertEqual(event["error_type"], "ValueError")

    def test_maxmind_lookup_rows_do_not_inflate_country_record_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "GeoLite2-Country-Locations-en.csv").write_text("geoname_id,country_iso_code\n1,CN\n2,US\n")
            (root / "GeoLite2-Country-Blocks-IPv6.csv").write_text("network,geoname_id,registered_country_geoname_id\n2400::/64,,1\n")
            sink = Sink()
            rows = list(parse_country("maxmind", root, {"id": "maxmind"}, trace=sink))
            self.assertIsNone(rows[0].country)
            event = sink.sources[-1]
            self.assertEqual((event["locations_read"], event["records_read"], event["records_parsed"]), (2, 1, 1))

    def test_raw_unknown_markers_are_preserved_without_changing_identity_or_fusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = [
                ("country-csv", "generic.csv", "network,country_code\n2400::/64,EU\n", {}),
                ("dbip", "dbip.csv", "2400::,2400::ffff,-\n", {}),
                ("ip2location", "ip2.csv", '"1","2","ZZ","Unknown"\n', {"ip_version": 6}),
            ]
            parsed = []
            for format, name, contents, extra in sources:
                path = root / name
                path.write_text(contents)
                rows = list(parse_country(format, path, {"id": name, **extra}))
                self.assertIsNone(rows[0].country)
                parsed.extend(rows)
            self.assertEqual([row.raw_fields["country_code"] for row in parsed], ["EU", "-", "ZZ"])
            stripped = [replace(row, raw_fields=None) for row in parsed]
            self.assertEqual(parsed, stripped)
            self.assertEqual([repr(row) for row in parsed], [repr(row) for row in stripped])
            self.assertEqual([hash(row) for row in parsed], [hash(row) for row in stripped])
            sink = Sink()
            self.assertEqual(fuse_country(parsed, REGISTRY, trace=sink), fuse_country(stripped, REGISTRY))
            self.assertEqual(sink.geo_inputs[0].raw_fields["country_code"], "EU")

    def test_maxmind_raw_registration_reference_does_not_become_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "GeoLite2-Country-Locations-en.csv").write_text("geoname_id,country_iso_code\n1,CN\n2,EU\n")
            (root / "GeoLite2-Country-Blocks-IPv6.csv").write_text(
                "network,geoname_id,registered_country_geoname_id\n2400::/64,,1\n2400:1::/64,2,1\n")
            rows = list(parse_country("maxmind", root, {"id": "maxmind"}))
            self.assertIsNone(rows[0].country)
            self.assertEqual(rows[0].raw_fields, {"country_code": None, "geoname_id": "", "registered_country_geoname_id": "1"})
            self.assertIsNone(rows[1].country)
            self.assertEqual(rows[1].raw_fields, {"country_code": "EU", "geoname_id": "2", "registered_country_geoname_id": "1"})
            stripped = [replace(row, raw_fields=None) for row in rows]
            sink = Sink()
            self.assertEqual(fuse_country(rows, REGISTRY, trace=sink), fuse_country(stripped, REGISTRY))

    def test_source_normalization_filter_sums_are_nonadditive_and_not_product_changes(self):
        rows = [CountryRecord.network("10.0.0.0/8", "CN", "a"),
                CountryRecord.network("1.0.0.0/24", "CN", "a"),
                CountryRecord.network("1.0.0.0/25", "CN", "a"),
                replace(CountryRecord.network("2400::/64", None, "a"), raw_fields={"country_code": "EU"}),
                CountryRecord.network("1.0.1.0/24", "CN", "a", semantics="registration")]
        sink = Sink()
        self.assertEqual(fuse_country(rows, REGISTRY, trace=sink), fuse_country(rows, REGISTRY))
        events = [row for row in sink.sources if row["stage"] == "geo-normalization"]
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["status"], "completed")
        self.assertEqual(event["ipv4_input_rows"], 4)
        self.assertEqual(event["ipv4_input_addresses_sum"], (1 << 24) + 256 + 128 + 256)
        self.assertEqual(event["ipv4_public_kept_addresses_sum"], 256 + 128)
        self.assertEqual(event["ipv4_excluded_addresses_sum"], 1 << 24)
        self.assertEqual(event["ipv4_non_country_semantics_ignored_rows"], 1)
        self.assertEqual(event["ipv4_non_country_semantics_ignored_addresses_sum"], 256)
        self.assertEqual(event["ipv6_input_rows"], 1)
        self.assertEqual(event["ipv6_country_missing_rows"], 1)
        self.assertEqual(event["ipv6_country_present_rows"], 0)
        self.assertEqual(event["ipv6_public_kept_addresses_sum"], 1 << 64)
        self.assertIn("overlap not deduplicated", event["count_scope"])

    def test_normalization_partial_input_failure_is_labeled_interrupted(self):
        def records():
            yield CountryRecord.network("1.0.0.0/24", "CN", "a")
            raise ValueError("broken next source row")
        sink = Sink()
        with self.assertRaisesRegex(ValueError, "broken next source row"):
            fuse_country(records(), REGISTRY, trace=sink)
        event = next(row for row in sink.sources if row["stage"] == "geo-normalization")
        self.assertEqual(event["status"], "interrupted")
        self.assertEqual(event["ipv4_input_rows"], 1)
        self.assertEqual(event["ipv4_public_kept_addresses_sum"], 256)


class RoutingTraceTests(unittest.TestCase):
    def test_asn_input_trace_records_originals_and_reasons_without_result_change(self):
        rows = [RoutingRecord.network("::/0", [10], "rib"),
                RoutingRecord.network("2000::/3", [20], "rib"),
                RoutingRecord.network("2400::/32", [30, 40], "rib", "peer-a", views=["peer-a", "peer-b"]),
                RoutingRecord.network("2401::/32", [50], "provider", raw_prefix_claim=False),
                AuxiliaryRecord(4, 0, 100, "rir", "registration", "CN")]
        sink = Sink()
        before = fuse_routes(rows)
        after = fuse_routes(rows, trace=sink)
        self.assertEqual(before, after)
        self.assertEqual([row for row, _, _ in sink.routes], rows)
        self.assertEqual([status for _, status, _ in sink.routes],
                         ["filtered", "quarantined", "accepted", "accepted", "ignored"])
        self.assertEqual(sink.routes[2][0].asns, (30, 40))
        self.assertEqual(sink.routes[2][0].views, ("peer-a", "peer-b"))
        self.assertIsNone(sink.routes[3][0].origin_prefix_length)

    def test_derived_asn_parser_does_not_claim_bgp_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "asn.tsv"
            path.write_text("1.0.0.0\t1.0.0.255\t0\n1.0.1.0\t1.0.1.255\t10\n")
            sink = Sink()
            rows = list(parse_routes("iptoasn-tsv", path, {"id": "provider"}, trace=sink))
            self.assertEqual(len(rows), 1)
            event = sink.sources[-1]
            self.assertEqual((event["records_read"], event["records_parsed"], event["excluded_as0_records"]), (2, 1, 1))
            self.assertEqual(event["raw_prefix_claim_records"], 0)
            self.assertEqual(event["derived_records"], 1)

    def test_grouped_mrt_payload_count_separate_from_peer_claim_count(self):
        row = RoutingRecord.network("2400::/32", [30, 40], "rib", views=["a", "b"])
        sink = Sink()
        with patch("airroute_data.routing.parse_mrt", return_value=iter([row])):
            rows = list(parse_routes("mrt-rib", "not-opened", {"id": "rib"}, trace=sink))
        self.assertEqual(rows, [row])
        event = sink.sources[-1]
        self.assertEqual(event["records_read"], 1)
        self.assertEqual(event["raw_prefix_claim_records"], 1)
        self.assertEqual(event["raw_prefix_peer_claims"], 2)

    def test_actual_mrt_binary_rows_and_within_peer_duplicate_count(self):
        def packet(subtype, payload):
            return struct.pack("!IHHI", 1, 13, subtype, len(payload)) + payload
        peer = b"\x00" + ipaddress.IPv4Address("8.8.8.8").packed + ipaddress.IPv4Address("8.8.4.4").packed + struct.pack("!H", 64500)
        peer_index = packet(1, b"\0" * 4 + struct.pack("!HH", 0, 1) + peer)
        path = bytes([2, 1]) + struct.pack("!I", 30)
        attrs = bytes([0x40, 2, len(path)]) + path
        entry = struct.pack("!HIH", 0, 1, len(attrs)) + attrs
        rib = packet(2, struct.pack("!I", 1) + bytes([24]) + bytes([1, 0, 0]) + struct.pack("!H", 2) + entry * 2)
        sink = Sink()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "view.mrt"
            path.write_bytes(peer_index + rib)
            rows = list(parse_routes("mrt-rib", path, {"id": "rib"}, trace=sink))
        self.assertEqual(len(rows), 1)
        event = sink.sources[-1]
        self.assertEqual((event["mrt_records_read"], event["mrt_rib_entries_read"], event["records_parsed"]), (2, 2, 1))
        self.assertEqual(event["raw_prefix_peer_claims"], 1)

    def test_malformed_json_candidate_is_counted_before_failure(self):
        sink = Sink()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text('{"prefix":"2400::/32","asn":10}\nnot-json\n')
            with self.assertRaises(json.JSONDecodeError):
                list(parse_routes("bgp-tools-jsonl", path, {"id": "bgp"}, trace=sink))
        event = sink.sources[-1]
        self.assertEqual(event["status"], "failed")
        self.assertEqual((event["records_read"], event["records_parsed"]), (2, 1))

    def test_auxiliary_provenance_never_traces_synthetic_asn_union_as_bgp(self):
        sink = Sink()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.csv"
            path.write_text("1.0.0.0/24,CN\n")
            source = {"id": "operator", "format": "geofeed", "path": str(path)}
            registry = json.loads(REGISTRY.read_text())
            before = audit_auxiliary([source], {1: ["1.0.0.0/24"]}, registry,
                                     routing_prefixes=["1.0.0.0/24"])
            after = audit_auxiliary([source], {1: ["1.0.0.0/24"]}, registry,
                                    routing_prefixes=["1.0.0.0/24"], trace=sink)
        self.assertEqual(before, after)
        self.assertEqual(len(sink.routes), 1)
        self.assertEqual(sink.routes[0][0].source, "operator")
        self.assertEqual(sink.routes[0][1:], ("auxiliary", "non-voting-operator-geofeed"))
        self.assertEqual(sink.sources[-1]["records_parsed"], 1)


if __name__ == "__main__":
    unittest.main()
