"""Independent Geo and ASN address eligibility from frozen IANA registries.

An IANA allocation is an address-space boundary, not location evidence. Geo
omits special-purpose space; ASN expansion instead follows the special
registry's most-specific Globally Reachable flag. Raw BGP observations are not
removed by either policy. This module never fetches live registries.
"""
from __future__ import annotations

from bisect import bisect_left
import csv
import hashlib
import ipaddress
from pathlib import Path
import re


REQUIRED_SOURCES = ("iana-alloc-v4", "iana-alloc-v6", "iana-special-v4", "iana-special-v6")
_FIELDS = {"allocation": {"Prefix", "Designation", "Status"},
           "special": {"Address Block", "Name", "Globally Reachable", "Destination", "Forwardable"}}


def _unfootnote(value):
    return re.sub(r"\s*\[[^]]*\]", "", value or "").strip()


def _network(text, family):
    text = _unfootnote(text)
    # The IPv4 allocation registry uses zero-padded one-octet /8 notation.
    if family == 4 and re.fullmatch(r"\d{1,3}/8", text):
        text = f"{int(text[:-2])}.0.0.0/8"
    net = ipaddress.ip_network(text, strict=True)
    if net.version != family:
        raise ValueError("IANA address family mismatch")
    return net


def _flag(value):
    value = _unfootnote(value).lower()
    if value == "true": return True
    if value == "false": return False
    if value in ("", "n/a"): return None
    raise ValueError("invalid IANA reachability flag")


def _read(source, family, kind):
    from .acquire import tree_digest
    path = Path(source["path"])
    if not path.is_file():
        raise ValueError(f"frozen IANA input is not a file: {source['id']}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    tree_sha256, total = tree_digest(path)
    if source.get("sha256") and source["sha256"] != tree_sha256:
        raise ValueError(f"frozen IANA input digest mismatch: {source['id']}")
    parsed = []
    seen = set()
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            raise ValueError("IANA CSV header is missing")
        header = [_unfootnote(name) for name in reader.fieldnames]
        if len(set(header)) != len(header) or not _FIELDS[kind].issubset(header):
            raise ValueError(f"invalid IANA {kind} CSV columns")
        for line, raw in enumerate(reader, 2):
            if None in raw or any(value is None for value in raw.values()):
                raise ValueError(f"malformed IANA {kind} CSV row")
            row = dict(zip(header, (raw[name] for name in reader.fieldnames)))
            prefixes = [row["Prefix"]] if kind == "allocation" else row["Address Block"].split(",")
            for text in prefixes:
                net = _network(text, family)
                if str(net) in seen:
                    raise ValueError(f"duplicate IANA prefix: {net}")
                seen.add(str(net))
                item = {"family": family, "prefix": str(net), "start": int(net.network_address),
                        "end": int(net.broadcast_address), "prefix_length": net.prefixlen,
                        "source": source["id"], "line": line}
                if kind == "allocation":
                    status = _unfootnote(row["Status"]).upper()
                    if status not in {"ALLOCATED", "LEGACY", "RESERVED", "UNALLOCATED", "AVAILABLE"}:
                        raise ValueError(f"unknown IANA allocation status: {status}")
                    item.update(name=row["Designation"], status=status,
                                eligible=status in {"ALLOCATED", "LEGACY"})
                else:
                    reachable = _flag(row["Globally Reachable"])
                    destination, forwardable = _flag(row["Destination"]), _flag(row["Forwardable"])
                    if reachable is True and (destination is not True or forwardable is not True):
                        raise ValueError("inconsistent IANA globally reachable flags")
                    item.update(name=row["Name"], globally_reachable=reachable,
                                destination=destination, forwardable=forwardable,
                                rfc=row.get("RFC", ""), eligible=reachable is True)
                parsed.append(item)
    if not parsed:
        raise ValueError(f"empty required IANA registry: {source['id']}")
    # Fetch times belong in the build trace. Keeping them out of the manifest
    # eligibility contract preserves content identity for unchanged inputs.
    metadata = {key: source[key] for key in ("id", "version", "lineage") if key in source}
    metadata.update(source_tree_sha256=tree_sha256, file_sha256=digest,
                    bytes=total, parsed_prefixes=len(parsed))
    return parsed, metadata


def _union(ranges):
    result = []
    for start, end in sorted(ranges):
        if result and start <= result[-1][1] + 1:
            result[-1] = (result[-1][0], max(result[-1][1], end))
        else: result.append((start, end))
    return result


def _remove(ranges, start, end):
    result = []
    for left, right in ranges:
        if right < start or left > end: result.append((left, right))
        else:
            if left < start: result.append((left, start - 1))
            if right > end: result.append((end + 1, right))
    return result


def _overlays(ranges, entries):
    # Registry prefixes are nested or disjoint. Specific children override
    # broad parent dispositions, including TRUE inside protocol FALSE parents.
    for row in sorted(entries, key=lambda row: (row["prefix_length"], row["start"])):
        if row["eligible"]: ranges = _union([*ranges, (row["start"], row["end"])])
        else: ranges = _remove(ranges, row["start"], row["end"])
    return ranges


def _counts(family, ranges):
    cls = ipaddress.IPv4Address if family == 4 else ipaddress.IPv6Address
    return {"intervals": len(ranges), "addresses": sum(b - a + 1 for a, b in ranges),
            "cidrs": sum(sum(1 for _ in ipaddress.summarize_address_range(cls(a), cls(b))) for a, b in ranges)}


class AddressEligibility:
    @classmethod
    def from_sources(cls, sources, *, trace=None):
        by_id = {}
        for source in sources:
            if source["id"] in REQUIRED_SOURCES and source["id"] in by_id:
                raise ValueError("duplicate frozen IANA source: " + source["id"])
            by_id[source["id"]] = source
        missing = [sid for sid in REQUIRED_SOURCES if sid not in by_id or by_id[sid].get("status", "available") != "available"]
        if missing:
            raise ValueError("missing required frozen IANA address registries: " + ", ".join(missing))
        self = cls()
        self.allocations, self.special = {4: [], 6: []}, {4: [], 6: []}
        snapshots = []
        for family in (4, 6):
            for kind, prefix, destination in (("allocation", "iana-alloc-v", self.allocations),
                                               ("special", "iana-special-v", self.special)):
                source = by_id[prefix + str(family)]
                try:
                    entries, metadata = _read(source, family, kind)
                except Exception as error:
                    if trace is not None:
                        trace.source_event(source["id"], "address-eligibility-parse", "failed",
                                           error_type=type(error).__name__)
                    raise
                destination[family] = entries
                snapshots.append(metadata)
                if trace is not None:
                    trace.source_event(source["id"], "address-eligibility-parse", "parsed",
                                       **{key: value for key, value in metadata.items() if key != "id"},
                                       family=family, registry_kind=kind)
        self._build_domains(snapshots)
        return self

    @classmethod
    def from_report(cls, report):
        """Rebuild independent boundaries without access to the original files.

        Manifest entries describe the frozen IANA snapshot; this checks their
        structural/semantic consistency, not authenticity against live IANA.
        Derived eligibility flags or address totals are never taken on trust.
        """
        if not isinstance(report, dict) or report.get("schema") != 1:
            raise ValueError("unsupported address eligibility report")
        snapshots = report.get("sources")
        if not isinstance(snapshots, list) or len(snapshots) != len(REQUIRED_SOURCES):
            raise ValueError("incomplete IANA snapshot report")
        seen_sources = set()
        for source in snapshots:
            if not isinstance(source, dict) or source.get("id") not in REQUIRED_SOURCES or source["id"] in seen_sources:
                raise ValueError("unknown or duplicate IANA snapshot")
            seen_sources.add(source["id"])
            if any(not isinstance(source.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", source[key]) for key in ("source_tree_sha256", "file_sha256")) or type(source.get("bytes")) is not int or source["bytes"] <= 0:
                raise ValueError("invalid IANA snapshot digest or length")
            if type(source.get("parsed_prefixes")) is not int or source["parsed_prefixes"] <= 0:
                raise ValueError("invalid IANA snapshot parsed prefix count")
        self = cls()
        self.allocations, self.special = {4: [], 6: []}, {4: [], 6: []}
        counts = {source: 0 for source in REQUIRED_SOURCES}
        for kind, key, destination in (("allocation", "allocation_entries", self.allocations),
                                       ("special", "special_entries", self.special)):
            entries = report.get(key)
            if not isinstance(entries, list) or not entries:
                raise ValueError("missing IANA report prefix entries")
            seen = set()
            for row in entries:
                if not isinstance(row, dict) or row.get("family") not in (4, 6):
                    raise ValueError("invalid IANA report family")
                family = row["family"]
                if not isinstance(row.get("prefix"), str) or any(type(row.get(field)) is not int for field in ("start", "end", "prefix_length")):
                    raise ValueError("invalid IANA report prefix fields")
                net = _network(row.get("prefix", ""), family)
                expected = (str(net), int(net.network_address), int(net.broadcast_address), net.prefixlen)
                actual = (row["prefix"], row.get("start"), row.get("end"), row.get("prefix_length"))
                source_id = f"iana-{'alloc' if kind == 'allocation' else 'special'}-v{family}"
                if actual != expected or row.get("source") != source_id or (family, str(net)) in seen:
                    raise ValueError("inconsistent IANA report prefix")
                seen.add((family, str(net)))
                if kind == "allocation":
                    if row.get("status") not in {"ALLOCATED", "LEGACY", "RESERVED", "UNALLOCATED", "AVAILABLE"}:
                        raise ValueError("invalid IANA report allocation status")
                    eligible = row["status"] in {"ALLOCATED", "LEGACY"}
                else:
                    if not {"globally_reachable", "destination", "forwardable"}.issubset(row):
                        raise ValueError("missing IANA report reachability fields")
                    flags = [row.get(name) for name in ("globally_reachable", "destination", "forwardable")]
                    if any(flag is not None and type(flag) is not bool for flag in flags):
                        raise ValueError("invalid IANA report reachability flags")
                    if flags[0] is True and (flags[1] is not True or flags[2] is not True):
                        raise ValueError("inconsistent IANA report reachability flags")
                    eligible = flags[0] is True
                if type(row.get("eligible")) is not bool or row["eligible"] != eligible:
                    raise ValueError("IANA report eligibility disagrees with registry fields")
                destination[family].append(dict(row))
                counts[source_id] += 1
        if any(not count for count in counts.values()) or any(source.get("parsed_prefixes") != counts[source["id"]] for source in snapshots):
            raise ValueError("inconsistent IANA report parsed prefix counts")
        self._build_domains(snapshots)
        for kind in ("geo", "asn"):
            reported = report.get(kind)
            if not isinstance(reported, dict) or set(reported) != {"4", "6"}:
                raise ValueError("missing IANA report address totals")
            for counts in reported.values():
                if not isinstance(counts, dict) or set(counts) != {"intervals", "addresses", "cidrs"} or any(type(value) is not int or value < 0 for value in counts.values()):
                    raise ValueError("invalid IANA report address totals")
        if report.get("geo") != self.report["geo"] or report.get("asn") != self.report["asn"]:
            raise ValueError("IANA report address totals disagree with registry entries")
        return self

    def _build_domains(self, snapshots):
        self.geo_domains, self.asn_domains = {}, {}
        for family in (4, 6):
            base = _overlays([], self.allocations[family])
            geo = base[:]
            for row in self.special[family]: geo = _remove(geo, row["start"], row["end"])
            self.geo_domains[family] = tuple(geo)
            self.asn_domains[family] = tuple(_overlays(base, self.special[family]))
        self._ends = {"geo": {family: [end for _, end in rows] for family, rows in self.geo_domains.items()},
                      "asn": {family: [end for _, end in rows] for family, rows in self.asn_domains.items()}}
        self.report = {"schema": 1, "policy": "frozen-IANA-allocation-and-special-purpose-boundaries",
                       "geo_policy": "Allocated/legacy space minus all special-purpose space. Protocol, translation and anycast special use is not physical geography.",
                       "asn_policy": "Allocated/legacy space, then most-specific IANA special-purpose Globally Reachable TRUE/FALSE/N/A dispositions. TRUE exceptions remain eligible; FALSE and unspecified/conditional entries are excluded from client expansion, never deleted from raw BGP.",
                       "scope": "IANA allocations do not establish RIR end-user allocation, active routing, physical location or ownership.",
                       "sources": snapshots,
                       "geo": {str(family): _counts(family, rows) for family, rows in self.geo_domains.items()},
                       "asn": {str(family): _counts(family, rows) for family, rows in self.asn_domains.items()},
                       "allocation_entries": [row for family in (4, 6) for row in self.allocations[family]],
                       "special_entries": [row for family in (4, 6) for row in self.special[family]]}

    def _intersections(self, kind, family, start, end):
        if family not in (4, 6) or not 0 <= start <= end < 1 << (32 if family == 4 else 128):
            raise ValueError("address range outside family")
        domains = self.geo_domains if kind == "geo" else self.asn_domains
        index = bisect_left(self._ends[kind][family], start)
        rows = domains[family]
        while index < len(rows):
            left, right = rows[index]
            if left > end: break
            yield max(left, start), min(right, end)
            index += 1

    def geo_intervals(self, family, start, end):
        return self._intersections("geo", family, start, end)

    def asn_intervals(self, family, start, end):
        return self._intersections("asn", family, start, end)

    def explain(self, family, address):
        if family not in (4, 6) or not 0 <= address < 1 << (32 if family == 4 else 128):
            raise ValueError("address outside family")
        def most_specific(rows):
            matches = [row for row in rows if row["start"] <= address <= row["end"]]
            return max(matches, key=lambda row: row["prefix_length"], default=None)
        allocation = most_specific(self.allocations[family])
        special = most_specific(self.special[family])
        return {"allocation": allocation, "special": special,
                "geo_eligible": bool(list(self.geo_intervals(family, address, address))),
                "asn_eligible": bool(list(self.asn_intervals(family, address, address))),
                "scope": "Frozen IANA eligibility only; no location, ownership or observed route is inferred."}
