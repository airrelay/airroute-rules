"""Country estimates to a versioned macroregion dataset; no active measurements.

A scratch SQLite file provides a bounded-memory external event sort. It is local
batch workspace, not a daemon/database contract, and is deleted after the sweep.
"""
from __future__ import annotations

from collections import Counter, defaultdict, OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass, field
import bz2
import csv
import gzip
import ipaddress
import itertools
import json
from pathlib import Path
import sqlite3
import tempfile
from typing import Iterable, Iterator, TextIO


@dataclass(frozen=True)
class CountryRecord:
    version: int
    start: int
    end: int
    country: str | None
    source: str
    lineage: str
    semantics: str = "country-estimate"
    # Diagnostic-only source fields. They never affect identity, sorting,
    # representations, location normalization or the production event payload.
    raw_fields: dict | None = field(default=None, compare=False, repr=False)

    @classmethod
    def network(cls, network: str, country: str | None, source: str,
                lineage: str | None = None, semantics: str = "country-estimate") -> "CountryRecord":
        net = ipaddress.ip_network(network, strict=True)
        return cls(net.version, int(net.network_address), int(net.broadcast_address),
                   country, source, lineage or source, semantics)


# Explicit non-geolocatable address space. Do not invent a country for these.
# This is deliberately an exclusion policy, not a claim to mirror all IANA status.
SPECIAL = {
    4: tuple(ipaddress.ip_network(x) for x in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
        "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")),
    6: tuple(ipaddress.ip_network(x) for x in (
        "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64",
        "2001:2::/48", "2001:db8::/32", "3fff::/20", "fc00::/7", "fe80::/10", "ff00::/8")),
}


@contextmanager
def open_text(path: str | Path) -> Iterator[TextIO]:
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else bz2.open if path.suffix == ".bz2" else open
    with opener(path, "rt", encoding="utf-8-sig", newline="") as stream:
        yield stream


def country_code(value: str | None) -> str | None:
    value = (value or "").strip().upper()
    if value in ("", "-", "ZZ", "XX", "EU", "AP", "UNKNOWN", "N/A"):
        return None
    if len(value) != 2 or not value.isalpha() or not value.isascii():
        raise ValueError("invalid country code")
    return value


def bounds(start: str, end: str | None = None, version: int | None = None) -> tuple[int, int, int]:
    if "/" in start:
        net = ipaddress.ip_network(start, strict=True)
        return net.version, int(net.network_address), int(net.broadcast_address)
    def address(x: str):
        if x.isdecimal():
            number = int(x)
            return (ipaddress.IPv6Address if version == 6 else ipaddress.IPv4Address)(number)
        return ipaddress.ip_address(x)
    a, b = address(start), address(end or start)
    if a.version != b.version or int(a) > int(b):
        raise ValueError("invalid IP interval")
    return a.version, int(a), int(b)


def _meta(source: dict) -> tuple[str, str]:
    sid = str(source["id"])
    lineage = source.get("lineage", source.get("lineage_group", sid))
    if isinstance(lineage, (dict, list)):
        raise ValueError(f"{sid}: lineage must be one stable correlation-group string")
    return sid, str(lineage)


def _record(row: dict, source: dict) -> CountryRecord:
    sid, lineage = _meta(source)
    if row.get("network"):
        family, start, end = bounds(row["network"])
    else:
        family, start, end = bounds(row["start_ip"], row["end_ip"], source.get("ip_version"))
    return CountryRecord(family, start, end, country_code(row.get("country_code")), sid, lineage,
                         raw_fields={"country_code": row.get("country_code")})


def parse_source(format: str, path: str | Path, source: dict, *, trace=None) -> Iterator[CountryRecord]:
    """Parse unchanged input semantics, with optional non-product accounting.

    records_read counts non-comment candidate CSV IP rows, including a failing
    row; locations_read counts MaxMind's lookup rows separately. Neither is a
    physical text-line or unique-address count.
    """
    stats = {"records_read": 0, "locations_read": 0, "records_parsed": 0,
             "ipv4_records": 0, "ipv6_records": 0}
    status = "interrupted"
    error_type = None
    try:
        for record in _parse_source(format, path, source, _stats=stats):
            stats["records_parsed"] += 1
            stats[f"ipv{record.version}_records"] += 1
            yield record
        status = "parsed" if stats["records_parsed"] else "empty"
    except Exception as error:
        status = "failed"
        error_type = type(error).__name__
        raise
    finally:
        if trace is not None:
            trace.source_event(str(source["id"]), "parse-country", status,
                               **stats, error_type=error_type,
                               count_semantics="Candidate CSV IP rows; MaxMind location lookup rows separate. Parsed family counts are records, not distinct IPs.")


def _parse_source(format: str, path: str | Path, source: dict, *, _stats: dict) -> Iterator[CountryRecord]:
    """Parse only actual IP-country estimates; registration country never substitutes.

    IP2Location DB1 numeric IPv6 files require source.ip_version=6, because small
    IPv6 integers cannot be distinguished from IPv4 by magnitude.
    """
    path = Path(path)
    sid, lineage = _meta(source)
    if format in ("maxmind-country-csv", "maxmind"):
        files = [path] if path.is_file() else sorted(path.rglob("*.csv"))
        locations = [f for f in files if "Locations-en" in f.name]
        blocks = [f for f in files if "Blocks-IPv" in f.name]
        if not locations or not blocks:
            raise ValueError("GeoLite Country bundle needs Locations-en and Blocks-IPv4/IPv6")
        countries: dict[str, str | None] = {}
        raw_countries: dict[str, str | None] = {}
        with open_text(locations[0]) as stream:
            for row in csv.DictReader(stream):
                _stats["locations_read"] += 1
                countries[row["geoname_id"]] = country_code(row.get("country_iso_code"))
                raw_countries[row["geoname_id"]] = row.get("country_iso_code")
        for block in blocks:
            with open_text(block) as stream:
                for row in csv.DictReader(stream):
                    _stats["records_read"] += 1
                    family, start, end = bounds(row["network"])
                    # registered_country_geoname_id is registration, not location.
                    cc = countries.get(row.get("geoname_id", ""))
                    yield CountryRecord(family, start, end, cc, sid, lineage,
                        raw_fields={"country_code": raw_countries.get(row.get("geoname_id", "")),
                                    "geoname_id": row.get("geoname_id"),
                                    "registered_country_geoname_id": row.get("registered_country_geoname_id")})
        return
    if format in ("dbip-country-csv", "dbip"):
        with open_text(path) as stream:
            for row in csv.reader(stream):
                if not row or row[0].startswith("#"):
                    continue
                _stats["records_read"] += 1
                if len(row) != 3:
                    raise ValueError("DB-IP Country Lite requires exactly three columns")
                family, start, end = bounds(row[0], row[1])
                yield CountryRecord(family, start, end, country_code(row[2]), sid, lineage,
                                    raw_fields={"country_code": row[2]})
        return
    if format in ("ip2location-db1-csv", "ip2location"):
        paths = sorted(path.rglob("*.CSV")) + sorted(path.rglob("*.csv")) if path.is_dir() else [path]
        if not paths:
            raise ValueError("IP2Location bundle has no CSV")
        for csv_path in paths:
            version = source.get("ip_version")
            if not version:
                name = csv_path.name.upper()
                version = 6 if "IPV6" in name else 4
            with open_text(csv_path) as stream:
                for row in csv.reader(stream):
                    if not row or row[0].startswith("#"):
                        continue
                    _stats["records_read"] += 1
                    if len(row) < 4:
                        raise ValueError("IP2Location DB1 requires start,end,country code,country name")
                    family, start, end = bounds(row[0], row[1], version)
                    yield CountryRecord(family, start, end, country_code(row[2]), sid, lineage,
                                        raw_fields={"country_code": row[2]})
        return
    if format in ("ipinfo-lite-csv", "iplocate-country-csv", "country-csv"):
        with open_text(path) as stream:
            reader = csv.DictReader(stream)
            fields = set(reader.fieldnames or [])
            if "country_code" not in fields or not ("network" in fields or {"start_ip", "end_ip"} <= fields):
                raise ValueError(f"{format}: missing documented location-country fields")
            for row in reader:
                _stats["records_read"] += 1
                yield _record(row, source)
        return
    raise ValueError(f"unsupported country format: {format}")


def load_registry(value: str | Path | dict) -> dict:
    registry = value if isinstance(value, dict) else json.loads(Path(value).read_text())
    if registry.get("schema_version") != 1 or not registry.get("version"):
        raise ValueError("unsupported/missing region registry version")
    ids, keys, countries = set(), set(), set()
    for region in registry["regions"]:
        rid, key = region["id"], region["key"]
        if not isinstance(rid, int) or not 0 < rid < 2**32 or rid in ids or key in keys:
            raise ValueError("duplicate or invalid region id/key")
        ids.add(rid); keys.add(key)
        for cc in region["countries"]:
            if cc in countries or country_code(cc) != cc:
                raise ValueError("country has multiple regions or is invalid")
            countries.add(cc)
    return registry


def public_intervals(version: int, start: int, end: int) -> Iterator[tuple[int, int]]:
    if version == 6:
        # The producer contract covers currently allocated global-unicast space,
        # not all mathematical IPv6 values (for example 4000::/2 is unallocated).
        start = max(start, int(ipaddress.IPv6Address("2000::")))
        end = min(end, int(ipaddress.IPv6Address("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")))
        if start > end: return
    remaining = [(start, end)]
    for excluded in SPECIAL[version]:
        a, b = int(excluded.network_address), int(excluded.broadcast_address)
        if b < start: continue
        if a > end: break
        next_ranges = []
        for x, y in remaining:
            if y < a or x > b:
                next_ranges.append((x, y))
            else:
                if x < a: next_ranges.append((x, a - 1))
                if y > b: next_ranges.append((b + 1, y))
        remaining = next_ranges
    yield from remaining


def _key(value: int) -> bytes:
    # A 129th bit is required for the IPv6 end sentinel 2**128.
    return value.to_bytes(17, "big")


@contextmanager
def event_stream(records: Iterable[tuple[int, int, int, dict]]) -> Iterator[Iterator[tuple[int, int, list]]]:
    """Sort compact event indexes; never duplicate JSON in external sort runs.

    A bounded dictionary interns repeated MRT view/origin descriptions. Cache
    eviction only costs space/time; it cannot remove evidence or change results.
    This is temporary batch storage, not an online cache or persistent platform.
    """
    with tempfile.TemporaryDirectory(prefix="airroute-events-") as directory:
        connection = sqlite3.connect(str(Path(directory) / "events.sqlite3"))
        try:
            connection.execute("PRAGMA journal_mode=OFF")
            connection.execute("PRAGMA synchronous=OFF")
            connection.execute("PRAGMA cache_size=-8192")
            connection.execute("PRAGMA temp_store=FILE")
            connection.execute("CREATE TABLE event(f INTEGER,p BLOB,r INTEGER,d INTEGER,payload_id INTEGER)")
            connection.execute("CREATE TABLE payload(id INTEGER PRIMARY KEY,value TEXT NOT NULL)")
            pending, descriptions = [], []
            intern = OrderedDict()
            next_id = 0
            def flush():
                connection.executemany("INSERT INTO payload VALUES(?,?)", descriptions)
                connection.executemany("INSERT INTO event VALUES(?,?,?,?,?)", pending)
                connection.commit()
                descriptions.clear(); pending.clear()
            for rid, (family, start, end, payload) in enumerate(records):
                if family not in (4, 6) or not 0 <= start <= end < (1 << (32 if family == 4 else 128)):
                    raise ValueError("record outside address family")
                value = json.dumps(payload, separators=(",", ":"), sort_keys=True)
                identifier = intern.get(value)
                if identifier is None:
                    next_id += 1; identifier = next_id
                    intern[value] = identifier
                    descriptions.append((identifier, value))
                    if len(intern) > 32768:intern.popitem(last=False)
                else:intern.move_to_end(value)
                pending.append((family, _key(start), rid, 1, identifier))
                pending.append((family, _key(end + 1), rid, -1, None))
                if len(pending) >= 8192:
                    flush()
            if pending:flush()
            intern.clear()
            decoded = OrderedDict()
            cursor = connection.execute("SELECT f,p,r,d,payload_id FROM event ORDER BY f,p,d,r")
            def decode(identifier):
                if identifier is None:return None
                if identifier in decoded:
                    decoded.move_to_end(identifier)
                    return decoded[identifier]
                row = connection.execute("SELECT value FROM payload WHERE id=?", (identifier,)).fetchone()
                if row is None:raise ValueError("temporary event payload is missing")
                value = json.loads(row[0]); decoded[identifier] = value
                if len(decoded) > 32768:decoded.popitem(last=False)
                return value
            def grouped():
                for (family, point), rows in itertools.groupby(cursor, lambda row: (row[0], row[1])):
                    yield family, int.from_bytes(point, "big"), [(row[2], row[3], decode(row[4])) for row in rows]
            yield grouped()
        finally:
            connection.close()


def _ip(version: int, value: int) -> str:
    return str((ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address)(value))


def _append_interval(target: list[tuple[int, int, int]], version: int, start: int, end: int) -> None:
    if target and target[-1][0] == version and target[-1][2] + 1 == start:
        target[-1] = (version, target[-1][1], end)
    else:
        target.append((version, start, end))


def intervals_to_cidrs(intervals: Iterable[tuple[int, int, int]]) -> list[str]:
    result = []
    for family, start, end in intervals:
        kind = ipaddress.IPv4Address if family == 4 else ipaddress.IPv6Address
        result.extend(str(net) for net in ipaddress.summarize_address_range(kind(start), kind(end)))
    return result


def load_geo_policy(value: str | Path | dict) -> dict:
    """One explicit source order; credentials never change the selected primary."""
    policy = value if isinstance(value, dict) else json.loads(Path(value).read_text())
    order = policy.get("source_order")
    if policy.get("schema") != 1 or not isinstance(order, list) or not order:
        raise ValueError("Geo policy requires a nonempty source_order")
    if any(not isinstance(source, str) or not source for source in order) or len(set(order)) != len(order):
        raise ValueError("Geo source_order must contain unique source IDs")
    if policy.get("primary_source") != order[0]:
        raise ValueError("Geo primary_source must be first in source_order")
    return policy


def fuse_country(records: Iterable[CountryRecord], registry: str | Path | dict,
                 *, source_order: Iterable[str], details_path: str | Path | None = None,
                 trace=None) -> dict:
    """Choose the first source with a usable estimate at each exact boundary.

    More-specific intervals supersede covering intervals from that same source.
    Missing/unknown estimates fall through the fixed configured source order.
    Disagreement from another source is recorded but never erases a selected
    result. Incomparable contradictory estimates within one source cannot
    provide a single macroregion and therefore fall through to the next source.
    Routing, registration and geofeed records remain auxiliary information.
    """
    if isinstance(source_order, str):
        raise ValueError("Geo source_order must be a sequence of source IDs")
    source_order = tuple(source_order)
    if not source_order or any(not isinstance(source, str) or not source for source in source_order) or len(set(source_order)) != len(source_order):
        raise ValueError("Geo source_order must contain unique source IDs")
    primary_source = source_order[0]
    registry = load_registry(registry)
    mapping = {cc: r["id"] for r in registry["regions"] for cc in r["countries"]}
    keys = {r["id"]: r["key"] for r in registry["regions"]}
    counters: Counter = Counter()
    source_rows: Counter = Counter()
    source_valid_country_rows = defaultdict(Counter)
    source_support = defaultdict(Counter)
    usable_sources, usable_lineages = set(), set()
    coverage = {"ipv4": Counter(), "ipv6": Counter()}
    special = {"cn": Counter(), "ru": Counter()}
    grouped: dict[int, list[tuple[int, int, int]]] = defaultdict(list)
    issues, issue_total = [], 0
    excluded_addresses = Counter()
    covered = []
    def normalized():
        accounting = defaultdict(Counter) if trace is not None else None
        completed = False
        try:
            for rec in records:
                stats = None
                if trace is not None:
                    trace.geo_input(rec)
                    stats = accounting[rec.source]
                    family = f"ipv{rec.version}"
                    stats[family + "_input_rows"] += 1
                    stats[family + "_input_addresses_sum"] += rec.end - rec.start + 1
                    stats[family + ("_country_present_rows" if rec.country is not None else "_country_missing_rows")] += 1
                source_rows[rec.source] += 1
                if rec.semantics != "country-estimate":
                    if stats is not None:
                        stats[family + "_non_country_semantics_ignored_rows"] += 1
                        stats[family + "_non_country_semantics_ignored_addresses_sum"] += rec.end - rec.start + 1
                    counters["auxiliary_rows_ignored"] += 1
                    continue
                if rec.source not in source_order:
                    raise ValueError(f"country source missing from configured order: {rec.source}")
                if rec.version not in (4, 6) or rec.start > rec.end:
                    raise ValueError("invalid country record")
                kept = 0
                for start, end in public_intervals(rec.version, rec.start, rec.end):
                    kept += end - start + 1
                    if rec.country in mapping:
                        usable_sources.add(rec.source); usable_lineages.add(rec.lineage)
                    yield rec.version, start, end, {"source": rec.source, "lineage": rec.lineage,
                        "country": rec.country, "span": str(rec.end - rec.start),
                        "original_start": str(rec.start), "original_end": str(rec.end)}
                if kept and rec.country in mapping:
                    source_valid_country_rows[rec.source][f"ipv{rec.version}"] += 1
                excluded = rec.end - rec.start + 1 - kept
                excluded_addresses[f"ipv{rec.version}"] += excluded
                if stats is not None:
                    stats[family + "_public_kept_addresses_sum"] += kept
                    stats[family + "_excluded_addresses_sum"] += excluded
            completed = True
        finally:
            if trace is not None:
                for sid, stats in sorted(accounting.items()):
                    for version in (4, 6):
                        for measure in ("input_rows", "input_addresses_sum", "country_present_rows", "country_missing_rows",
                                        "public_kept_addresses_sum", "excluded_addresses_sum",
                                        "non_country_semantics_ignored_rows", "non_country_semantics_ignored_addresses_sum"):
                            stats.setdefault(f"ipv{version}_{measure}", 0)
                    trace.source_event(sid, "geo-normalization", "completed" if completed else "interrupted",
                        count_scope="per-input-row sums; overlap not deduplicated; not independent support",
                        country_count_scope="Presence means normalized country is non-null; raw missing/unknown markers are retained separately.",
                        **stats)
    output = None
    if details_path:
        details_path = Path(details_path); details_path.parent.mkdir(parents=True, exist_ok=True)
        output = details_path.open("w", encoding="utf-8")
    active: dict[int, dict] = {}
    previous, previous_family = None, None
    try:
        with event_stream(normalized()) as points:
            for family, point, changes in points:
                if previous_family != family:
                    active.clear(); previous = None
                if active and previous is not None and point > previous:
                    source_values: dict[str, list[dict]] = defaultdict(list)
                    for value in active.values(): source_values[value["source"]].append(value)
                    lineage_values: dict[str, set[str | None]] = defaultdict(set)
                    selected_sources = {}
                    for sid, values in source_values.items():
                        # Prefer truly contained more-specific intervals, not
                        # merely the shorter of two partially crossing ranges.
                        selected = [v for v in values if not any(
                            int(other["original_start"]) >= int(v["original_start"])
                            and int(other["original_end"]) <= int(v["original_end"])
                            and (other["original_start"], other["original_end"]) != (v["original_start"], v["original_end"])
                            for other in values)]
                        countries = {v["country"] for v in selected}
                        selected_sources[sid] = sorted(c for c in countries if c)
                        for value in selected: lineage_values[value["lineage"]].add(value["country"])
                    informed = {lineage: values - {None} for lineage, values in lineage_values.items() if values - {None}}
                    countries = set().union(*informed.values()) if informed else set()
                    mapped = {mapping[c] for c in countries if c in mapping}
                    unknown_codes = countries - mapping.keys()
                    source_regions = {sid: sorted({mapping[c] for c in values if c in mapping})
                                      for sid, values in selected_sources.items()}
                    region = selected_source = selected_country = None
                    for sid in source_order:
                        values = selected_sources.get(sid, [])
                        regions = source_regions.get(sid, [])
                        if len(regions) == 1 and values and all(country in mapping for country in values):
                            selected_source = sid
                            selected_country = values[0] if len(values) == 1 else None
                            region = regions[0]
                            break
                    if region is not None:
                        state = "primary-selected" if selected_source == primary_source else "fallback-selected"
                        _append_interval(grouped[region], family, previous, point - 1)
                    elif not countries:
                        state = "missing-country"
                    elif unknown_codes:
                        state = "unmapped-country"
                    else:
                        state = "ambiguous-source"
                    _append_interval(covered, family, previous, point - 1)
                    addresses = point - previous
                    fam = f"ipv{family}"
                    counters[f"{state}_segments"] += 1
                    coverage[fam][state] += addresses
                    if region is not None: coverage[fam]["assigned"] += addresses
                    else: coverage[fam]["unknown"] += addresses
                    if len(countries) > 1:
                        coverage[fam]["country-disagreement"] += addresses
                        counters["country-disagreement_segments"] += 1
                    if len(mapped) > 1:
                        coverage[fam]["region-disagreement"] += addresses
                        counters["region-disagreement_segments"] += 1
                    for sid, values in selected_sources.items():
                        support = source_support[sid]
                        support[f"{fam}_covered_addresses"] += addresses
                        if not values:
                            support[f"{fam}_missing_country_addresses"] += addresses
                        elif region is not None:
                            if source_regions[sid] == [region] and all(country in mapping for country in values):
                                support[f"{fam}_supports_output_addresses"] += addresses
                            else:
                                support[f"{fam}_dissenting_addresses"] += addresses
                        else:
                            support[f"{fam}_unresolved_addresses"] += addresses
                        if sid == selected_source:
                            support[f"{fam}_selected_addresses"] += addresses
                            support[f"{fam}_selected_intervals"] += 1
                        for cc in ("CN", "RU"):
                            if cc in values:
                                support[f"{fam}_{cc}_candidate_addresses"] += addresses
                    for cc, region_key in (("CN", "cn"), ("RU", "ru")):
                        if cc in countries:
                            special[region_key][f"{fam}_candidate_addresses"] += addresses
                            special[region_key][f"{fam}_{'assigned' if region and keys[region]==region_key else 'unresolved'}_addresses"] += addresses
                    detail = {"family": family, "start": _ip(family, previous), "end": _ip(family, point - 1),
                              "status": state, "region_id": region, "sources": selected_sources,
                              "lineages": {k: sorted(v) for k, v in informed.items()},
                              "country_disagreement": len(countries) > 1,
                              "region_disagreement": len(mapped) > 1,
                              "selected_source": selected_source, "selected_country": selected_country,
                              "source_order": list(source_order)}
                    if trace is not None:
                        trace.geo_decision({**detail,
                            "start_int": previous, "end_int": point - 1,
                            "source_regions": source_regions})
                    if region is None or detail["country_disagreement"]:
                        issue_total += 1
                        if output: output.write(json.dumps(detail, sort_keys=True) + "\n")
                        if len(issues) < 100: issues.append(detail)
                for rid, delta, payload in changes:
                    if delta < 0: active.pop(rid, None)
                    else: active[rid] = payload
                previous, previous_family = point, family
        # Explicit address-space contract: IPv4 unicast minus exclusions and the
        # currently allocated IPv6 global-unicast aggregate. Absence from all
        # sources is unknown, never overseas and never a synthetic country.
        contracts = [(4, a, b) for a, b in public_intervals(4, 0, 2**32 - 1)]
        v6 = ipaddress.ip_network("2000::/3")
        contracts += [(6, a, b) for a, b in public_intervals(6, int(v6.network_address), int(v6.broadcast_address))]
        for family, first, last in contracts:
            cursor = first
            for f, start, end in covered:
                if f != family or end < cursor: continue
                if start > last: break
                if cursor < start:
                    gap_end = min(last, start - 1)
                    detail = {"family": family, "start": _ip(family, cursor), "end": _ip(family, gap_end),
                              "status": "missing-all-sources", "region_id": None, "sources": {}, "lineages": {},
                              "country_disagreement": False}
                    if trace is not None:
                        trace.geo_decision({**detail, "start_int": cursor, "end_int": gap_end})
                    issue_total += 1
                    if output: output.write(json.dumps(detail, sort_keys=True) + "\n")
                    if len(issues) < 100: issues.append(detail)
                    coverage[f"ipv{family}"]["missing-all-sources"] += gap_end - cursor + 1
                    coverage[f"ipv{family}"]["unknown"] += gap_end - cursor + 1
                    counters["missing-all-sources_segments"] += 1
                cursor = max(cursor, end + 1)
                if cursor > last: break
            if cursor <= last:
                detail = {"family": family, "start": _ip(family, cursor), "end": _ip(family, last),
                          "status": "missing-all-sources", "region_id": None, "sources": {}, "lineages": {},
                          "country_disagreement": False}
                if trace is not None:
                    trace.geo_decision({**detail, "start_int": cursor, "end_int": last})
                issue_total += 1
                if output: output.write(json.dumps(detail, sort_keys=True) + "\n")
                if len(issues) < 100: issues.append(detail)
                coverage[f"ipv{family}"]["missing-all-sources"] += last - cursor + 1
                coverage[f"ipv{family}"]["unknown"] += last - cursor + 1
                counters["missing-all-sources_segments"] += 1
    finally:
        if output: output.close()
    groups = {rid: intervals_to_cidrs(ranges) for rid, ranges in sorted(grouped.items())}
    return {"groups": groups, "report": {
        "policy": "fixed-primary-then-ordered-gap-fill",
        "primary_source": primary_source,
        "source_order": list(source_order),
        "independence": "Sources are not votes. Shared lineage is recorded, not counted as corroboration or accuracy.",
        "coverage_scope": "IPv4 minus explicit special-space exclusions; IPv6 2000::/3 minus explicit exclusions. Every gap in this contract is reported unknown; no source information is fabricated.",
        "usable_sources": sorted(usable_sources), "usable_lineages": sorted(usable_lineages),
        "source_rows": dict(sorted(source_rows.items())),
        "source_valid_country_rows": {sid: dict(values) for sid, values in sorted(source_valid_country_rows.items())},
        "segments": dict(sorted(counters.items())),
        "source_address_support": {sid: dict(values) for sid, values in sorted(source_support.items())},
        "support_note": "Selected address contributions are exclusive across sources; supporting and dissenting coverage overlap and are not independent votes or accuracy.",
        "coverage": {k: dict(v) for k, v in coverage.items()},
        "special": {k: dict(v) for k, v in special.items()},
        "filtered_special_addresses_sum_per_source": dict(excluded_addresses),
        "group_prefixes": {keys[rid]: len(prefixes) for rid, prefixes in groups.items()},
        "issue_intervals": issue_total, "issue_sample_truncated": issue_total > len(issues),
        "registry_version": registry["version"]}, "issues": issues,
        "details_path": str(details_path) if details_path else None}
