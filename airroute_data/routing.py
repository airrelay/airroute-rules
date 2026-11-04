"""Passive routing snapshots, multi-origin ASN groups and auxiliary evidence.

RIBs describe routing visibility, not target physical location. A new build reads
only its fixed current snapshots; absent/withdrawn routes from older builds are
not carried over. Incremental UPDATE files cannot be mistaken for a full RIB.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, replace
import bz2
import csv
import gzip
import heapq
import ipaddress
import json
from pathlib import Path
import re
import struct
from typing import BinaryIO, Iterable, Iterator

from .geo import bounds, country_code, event_stream, intervals_to_cidrs, open_text, public_intervals, _append_interval


@dataclass(frozen=True)
class RoutingRecord:
    version: int
    start: int
    end: int
    asns: tuple[int, ...]
    source: str
    collector: str = ""
    semantics: str = "routing-origin"
    peer_count: int | None = None
    origin_prefix_length: int | None = None
    views: tuple[str, ...] = ()
    compiled_asns: tuple[int, ...] | None = None

    @classmethod
    def network(cls, network: str, asns: Iterable[int], source: str,
                collector: str = "", *, peer_count: int | None = None,
                raw_prefix_claim: bool = True, views: Iterable[str] = ()) -> "RoutingRecord":
        family, start, end = bounds(network)
        if peer_count is not None and (isinstance(peer_count, bool) or not isinstance(peer_count, int) or peer_count < 0):
            raise ValueError("invalid routing peer count")
        # bounds() has already validated the prefix; avoid parsing each MRT
        # row twice just to retain its original length.
        original_length = (int(network.rsplit("/", 1)[1]) if "/" in network else (32 if family == 4 else 128)) if raw_prefix_claim else None
        return cls(family, start, end, valid_asns(asns), source, collector,
                   peer_count=peer_count, origin_prefix_length=original_length,
                   views=tuple(sorted(set(views))))


@dataclass(frozen=True)
class AuxiliaryRecord:
    version: int
    start: int
    end: int
    source: str
    kind: str
    country: str | None = None
    status: str = ""
    lineage: str = ""


def valid_asns(values: Iterable[int | str]) -> tuple[int, ...]:
    result = sorted({int(str(v).removeprefix("AS")) for v in values})
    if any(not 0 <= v < 2**32 for v in result):
        raise ValueError("ASN outside u32")
    return tuple(result)



# IANA Special-Purpose AS Numbers registry (last updated 2015-08-07),
# https://www.iana.org/assignments/iana-as-numbers-special-registry/
# These are standards-defined number semantics, not an ASN ownership allowlist.
IANA_ASN_REGISTRY = {
    "url": "https://www.iana.org/assignments/iana-as-numbers-special-registry/",
    "version": "2015-08-07",
    "number_registry_url": "https://www.iana.org/assignments/as-numbers/",
    "number_registry_version": "2026-06-01",
}


def asn_number_kind(number: int) -> str:
    if number == 0: return "reserved-rfc7607"
    if number == 112: return "as112-project-rfc7534"
    if number == 23456: return "as-trans-rfc6793"
    if 64496 <= number <= 64511 or 65536 <= number <= 65551:
        return "documentation-rfc5398"
    if 64512 <= number <= 65534 or 4200000000 <= number <= 4294967294:
        return "private-use-rfc6996"
    if number in (65535, 4294967295): return "reserved-rfc7300"
    if 65552 <= number <= 131071: return "reserved-iana-as-numbers"
    return "public"


def public_asns(values: Iterable[int]) -> tuple[int, ...]:
    # AS112 is a globally routed special-purpose project; do not discard it
    # merely because its number has a special-purpose registry entry.
    return tuple(v for v in valid_asns(values)
                 if asn_number_kind(v) in {"public", "as112-project-rfc7534"})


def _aggregate_view(source: str, collector: str, prefix: str, origins: Iterable[int]) -> str:
    # RISwhois has aggregate prefix/origin/peer-count rows, not peer identities.
    # Each claim is independent; a more-specific row may have come from an
    # entirely different peer and must not erase a covering aggregate claim.
    return f"{source}/{collector}/aggregate:{prefix}:" + ",".join(map(str, origins))


def _asn_set(value: str) -> tuple[int, ...]:
    # RIS dumps may publish AS sets with braces/comma separators. Do not choose
    # the first origin and silently discard the rest.
    fields = re.split(r"[\s,{}|]+", value.strip())
    return valid_asns(v for v in fields if v)


def parse_source(format: str, path: str | Path, source: dict, *, trace=None) -> Iterator[RoutingRecord | AuxiliaryRecord]:
    """Optional parser accounting, without changing ASN/auxiliary semantics.

    Candidate rows are logical rows, not physical lines. MRT rows count shared
    prefix/origin payloads after RIB peer grouping; peer claims are separate.
    """
    stats = {"records_read": 0, "records_parsed": 0, "ipv4_records": 0, "ipv6_records": 0,
             "raw_prefix_claim_records": 0, "raw_prefix_peer_claims": 0,
             "derived_records": 0, "auxiliary_records": 0, "excluded_as0_records": 0,
             "mrt_records_read": 0, "mrt_rib_entries_read": 0, "mrt_originless_entries": 0}
    status = "interrupted"
    error_type = None
    try:
        for record in _parse_source(format, path, source, _stats=stats):
            if source.get("ip_version") is not None and record.version != int(source["ip_version"]):
                raise ValueError("routing input address family differs from source contract")
            stats["records_parsed"] += 1
            stats[f"ipv{record.version}_records"] += 1
            if isinstance(record, RoutingRecord):
                if record.origin_prefix_length is not None:
                    stats["raw_prefix_claim_records"] += 1
                    stats["raw_prefix_peer_claims"] += len(record.views) if record.views else 1
                else:
                    stats["derived_records"] += 1
            else:
                stats["auxiliary_records"] += 1
            yield record
        status = "parsed" if stats["records_parsed"] else "empty"
    except Exception as error:
        status = "failed"
        error_type = type(error).__name__
        raise
    finally:
        if trace is not None:
            trace.source_event(str(source["id"]), "parse-routing", status,
                **stats, error_type=error_type,
                count_semantics="Candidate logical input rows; MRT counts payloads after within-RIB grouping, peer claims separately. Derived provider rows are not observed BGP claims.")


def _parse_source(format: str, path: str | Path, source: dict, *, _stats: dict) -> Iterator[RoutingRecord | AuxiliaryRecord]:
    path = Path(path); sid = str(source["id"])
    collector = str(source.get("collector", sid))
    if format in ("routeviews-mrt", "ris-mrt", "mrt-rib"):
        for record in parse_mrt(path, sid, collector, _stats=_stats):
            _stats["records_read"] += 1
            yield record
        return
    if format in ("ris-whois", "riswhois"):
        # Current RIS dump is a tabular origin-prefix-peercount summary. RPSL
        # blocks are also supported for captured documented whois responses.
        def aggregate(prefix, origins, peer_count=None):
            origins = valid_asns(origins)
            return RoutingRecord.network(prefix, origins, sid, collector,
                peer_count=peer_count, views=(_aggregate_view(sid, collector, prefix, origins),))
        with open_text(path) as stream:
            network, origins = None, []
            for raw in stream:
                line = raw.strip()
                if not line or line.startswith(("%", "#")):
                    if network and origins:
                        _stats["records_read"] += 1
                        yield aggregate(network, origins)
                    network, origins = None, []
                    continue
                if line.startswith(("route:", "route6:")):
                    network = line.split(":", 1)[1].strip()
                elif line.startswith("origin:"):
                    origins.extend(_asn_set(line.split(":", 1)[1]))
                elif "/" in line and not line.startswith(("descr:", "remarks:")):
                    _stats["records_read"] += 1
                    fields = line.split()
                    prefix_index = next((i for i, field in enumerate(fields) if "/" in field), None)
                    if prefix_index is None: continue
                    if prefix_index == 0 and len(fields) > 1:
                        prefix, asn = fields[0], fields[1]
                    elif prefix_index > 0:
                        prefix, asn = fields[prefix_index], " ".join(fields[:prefix_index])
                    else: raise ValueError("RIS dump has no origin")
                    peer_count = int(fields[prefix_index + 1]) if prefix_index > 0 and len(fields) > prefix_index + 1 else (
                        int(fields[2]) if prefix_index == 0 and len(fields) > 2 else None)
                    yield aggregate(prefix, _asn_set(asn), peer_count)
            if network and origins:
                _stats["records_read"] += 1
                yield aggregate(network, origins)
        return
    if format in ("iptoasn-tsv", "iptoasn"):
        with open_text(path) as stream:
            for fields in csv.reader(stream, delimiter="\t"):
                if not fields or fields[0].startswith("#"): continue
                _stats["records_read"] += 1
                if len(fields) < 3: raise ValueError("IPtoASN needs first IP, last IP, ASN")
                family, start, end = bounds(fields[0], fields[1], source.get("ip_version"))
                if fields[2] == "0":
                    _stats["excluded_as0_records"] += 1
                    continue  # Dataset explicitly says not announced.
                yield RoutingRecord(family, start, end, _asn_set(fields[2]), sid, collector)
        return
    if format in ("iplocate-asn-csv", "bgp-tools-jsonl"):
        with open_text(path) as stream:
            def json_rows():
                for line in stream:
                    if line.strip():
                        _stats["records_read"] += 1
                        yield json.loads(line)
            rows = json_rows() if format == "bgp-tools-jsonl" else csv.DictReader(stream)
            for row in rows:
                if format != "bgp-tools-jsonl":
                    _stats["records_read"] += 1
                network = row.get("network", row.get("CIDR", row.get("prefix")))
                origins = row.get("asns", row.get("ASN", row.get("asn")))
                if network is None or origins is None: raise ValueError("routing row lacks network/ASN")
                if isinstance(origins, (int, str)): origins = _asn_set(str(origins))
                yield RoutingRecord.network(network, origins, sid, collector,
                                            raw_prefix_claim=format == "bgp-tools-jsonl")
        return
    if format in ("rir-delegated", "delegated"):
        with open_text(path) as stream:
            for raw in stream:
                row = raw.strip().split("|")
                if len(row) < 7 or raw.startswith("#") or row[2] not in ("ipv4", "ipv6") or row[1] == "*": continue
                _stats["records_read"] += 1
                cc = country_code(row[1]); status = row[6]
                if row[2] == "ipv4":
                    start = int(ipaddress.IPv4Address(row[3])); end = start + int(row[4]) - 1
                    if end >= 2**32: raise ValueError("delegated IPv4 allocation overflows")
                    family = 4
                else: family, start, end = bounds(row[3] + "/" + row[4])
                yield AuxiliaryRecord(family, start, end, sid, "registration", cc, status,
                                      str(source.get("lineage", sid)))
        return
    if format in ("geofeed-csv", "geofeed"):
        with open_text(path) as stream:
            for row in csv.reader(stream):
                if not row or row[0].strip().startswith("#"): continue
                _stats["records_read"] += 1
                if len(row) < 2: raise ValueError("geofeed needs prefix and country")
                family, start, end = bounds(row[0].strip())
                yield AuxiliaryRecord(family, start, end, sid, "operator-geofeed", country_code(row[1]),
                                      "operator-assertion", str(source.get("lineage", sid)))
        return
    if format == "surge-cidr-reference":
        with open_text(path) as stream:
            for raw in stream:
                line = raw.split("#", 1)[0].strip()
                if not line or line.startswith((";", "//")): continue
                parts = [part.strip() for part in line.split(",")]
                kind = parts[0].upper()
                # Extract only top-level explicit CIDR rules. An AND/NOT line
                # containing an IP-CIDR substring is never flattened or mined.
                if kind not in ("IP-CIDR", "IP-CIDR6", "IP6-CIDR"): continue
                _stats["records_read"] += 1
                if len(parts) < 2: raise ValueError("CIDR reference rule lacks its address")
                family, start, end = bounds(parts[1])
                if family != (4 if kind == "IP-CIDR" else 6):
                    raise ValueError("CIDR reference rule has mismatched address family")
                yield AuxiliaryRecord(family, start, end, sid, "route-list",
                                      source.get("country", "CN" if source.get("role") == "cn-reference" else None), "rule-reference-only",
                                      str(source.get("lineage", sid)))
        return
    if format in ("cidr-list", "china-route-list"):
        with open_text(path) as stream:
            for raw in stream:
                line = raw.split("#", 1)[0].strip()
                if not line: continue
                _stats["records_read"] += 1
                # Reference Surge/Clash CIDR lists without policy inference.
                parts = line.split(",")
                network = parts[1].strip() if parts[0].upper() in ("IP-CIDR", "IP-CIDR6", "IP6-CIDR") and len(parts) > 1 else line
                family, start, end = bounds(network)
                yield AuxiliaryRecord(family, start, end, sid, "route-list", source.get("country", "CN" if source.get("role") == "cn-reference" or format == "china-route-list" else None),
                                      "routing-membership-only", str(source.get("lineage", sid)))
        return
    raise ValueError(f"unsupported routing/auxiliary format: {format}")


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size: raise ValueError("truncated MRT record")
    return data


def _prefix(payload: bytes, offset: int, family: int) -> tuple[str, int]:
    if offset >= len(payload): raise ValueError("truncated MRT prefix")
    bits = payload[offset]; offset += 1
    width = 4 if family == 4 else 16
    if bits > width * 8: raise ValueError("MRT prefix exceeds family")
    length = (bits + 7) // 8
    if offset + length > len(payload): raise ValueError("truncated MRT address")
    packed = payload[offset:offset+length] + b"\0" * (width - length)
    ip = (ipaddress.IPv4Address if family == 4 else ipaddress.IPv6Address)(packed)
    return str(ipaddress.ip_network(f"{ip}/{bits}", strict=True)), offset + length


def _origin_path(payload: bytes, width: int) -> tuple[int, ...]:
    offset, last = 0, ()
    while offset < len(payload):
        if offset + 2 > len(payload): raise ValueError("truncated AS_PATH segment")
        kind, count = payload[offset:offset+2]; offset += 2
        length = count * width
        if offset + length > len(payload): raise ValueError("truncated AS_PATH ASNs")
        values = [int.from_bytes(payload[i:i+width], "big") for i in range(offset, offset+length, width)]
        offset += length
        if kind == 1: last = valid_asns(values)  # AS_SET: all origins possible.
        elif kind == 2 and values: last = valid_asns([values[-1]])
        elif kind not in (3, 4): raise ValueError("unsupported AS_PATH segment kind")
        # Confederation members do not replace externally visible origin.
    return last


def _attributes(payload: bytes, as4: bool) -> tuple[int, ...]:
    offset, ordinary, fourbyte = 0, (), ()
    while offset < len(payload):
        if offset + 3 > len(payload): raise ValueError("truncated BGP attribute")
        flags, kind = payload[offset:offset+2]; offset += 2
        size_width = 2 if flags & 0x10 else 1
        if offset + size_width > len(payload): raise ValueError("truncated BGP attribute length")
        length = int.from_bytes(payload[offset:offset+size_width], "big"); offset += size_width
        value = payload[offset:offset+length]
        if len(value) != length: raise ValueError("truncated BGP attribute body")
        offset += length
        if kind == 2: ordinary = _origin_path(value, 4 if as4 else 2)
        elif kind == 17: fourbyte = _origin_path(value, 4)
    # AS4_PATH reconstructs AS_TRANS in legacy two-octet paths (RFC6793).
    if not as4 and 23456 in ordinary and fourbyte: return fourbyte
    return ordinary


def parse_mrt(path: str | Path, source: str, collector: str = "", *,
              _stats: dict | None = None) -> Iterator[RoutingRecord]:
    """Decode current TABLE_DUMP_V2 unicast RIBs, including four-byte ASN/ADD-PATH.

    Only peer-index and full RIB records are accepted. UPDATE streams must be
    replayed from a known initial RIB; this batch producer intentionally rejects
    them rather than accidentally resurrecting withdrawn routes.
    """
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else bz2.open if path.suffix == ".bz2" else open
    peers: list[tuple[bool, str, int, str]] = []
    table_view = ""
    with opener(path, "rb") as stream:
        while header := stream.read(12):
            if _stats is not None:
                _stats["mrt_records_read"] += 1
            if len(header) != 12: raise ValueError("truncated MRT header")
            _timestamp, kind, subtype, length = struct.unpack("!IHHI", header)
            if length > 64 * 1024 * 1024: raise ValueError("oversized MRT record")
            payload = _read_exact(stream, length)
            if kind != 13: raise ValueError("only TABLE_DUMP_V2 full RIB snapshots are supported")
            if subtype == 1:
                if len(payload) < 8: raise ValueError("truncated MRT peer index")
                view_len = int.from_bytes(payload[4:6], "big"); offset = 6 + view_len
                table_view = str(ipaddress.IPv4Address(payload[:4])) + ":" + payload[6:offset].hex()
                if offset + 2 > len(payload): raise ValueError("truncated MRT peer index view")
                count = int.from_bytes(payload[offset:offset+2], "big"); offset += 2; peers = []
                for _ in range(count):
                    if offset + 5 > len(payload): raise ValueError("truncated MRT peer")
                    peer_type = payload[offset]; as4 = bool(peer_type & 2)
                    if peer_type & ~3: raise ValueError("unsupported MRT peer flags")
                    size = 1 + 4 + (16 if peer_type & 1 else 4) + (4 if as4 else 2)
                    if offset + size > len(payload): raise ValueError("truncated MRT peer address/ASN")
                    addr_width = 16 if peer_type & 1 else 4
                    addr = str(ipaddress.ip_address(payload[offset+5:offset+5+addr_width]))
                    peer_asn = int.from_bytes(payload[offset+5+addr_width:offset+size], "big")
                    bgp_id = str(ipaddress.IPv4Address(payload[offset+1:offset+5]))
                    peers.append((as4, addr, peer_asn, bgp_id)); offset += size
                if offset != len(payload): raise ValueError("trailing MRT peer bytes")
                continue
            if subtype not in (2, 4, 6, 8, 10, 12):
                # IPv4/IPv6 multicast are not unicast routing membership.
                if subtype in (3, 5, 9, 11): continue
                raise ValueError("unsupported MRT RIB subtype")
            addpath = subtype in (8, 10, 12)
            if len(payload) < 4: raise ValueError("truncated MRT RIB sequence")
            offset = 4
            if subtype in (6, 12):
                if offset + 3 > len(payload): raise ValueError("truncated MRT generic AFI/SAFI")
                afi, safi = struct.unpack_from("!HB", payload, offset); offset += 3
                if afi not in (1, 2) or safi != 1: continue
                family = 4 if afi == 1 else 6
            else: family = 4 if subtype in (2, 8) else 6
            prefix, offset = _prefix(payload, offset, family)
            if offset + 2 > len(payload): raise ValueError("truncated MRT entry count")
            count = int.from_bytes(payload[offset:offset+2], "big"); offset += 2
            equivalent = defaultdict(set)
            for _ in range(count):
                if _stats is not None:
                    _stats["mrt_rib_entries_read"] += 1
                if offset + 8 + (4 if addpath else 0) > len(payload): raise ValueError("truncated MRT RIB entry")
                peer = int.from_bytes(payload[offset:offset+2], "big"); offset += 6
                if peer >= len(peers): raise ValueError("MRT RIB references unknown peer")
                if addpath: offset += 4
                attr_len = int.from_bytes(payload[offset:offset+2], "big"); offset += 2
                attrs = payload[offset:offset+attr_len]
                if len(attrs) != attr_len: raise ValueError("truncated MRT entry attributes")
                offset += attr_len
                # RFC6396 section4.3.4: TABLE_DUMP_V2 AS_PATH is always
                # four-octet, even when the peer-index ASN itself is two-octet.
                origins = _attributes(attrs, True)
                if origins:
                    _, peer_ip, peer_asn, bgp_id = peers[peer]
                    view = f"{source}/{collector}/view:{table_view}/AS{peer_asn}@{peer_ip}#{bgp_id}"
                    equivalent[origins].add(view)
                elif _stats is not None:
                    _stats["mrt_originless_entries"] += 1
            if offset != len(payload): raise ValueError("trailing MRT RIB bytes")
            # One RIB entry is bounded. Share identical prefix/origin payloads,
            # retaining every peer identity for exact per-peer LPM below.
            for origins, views in sorted(equivalent.items()):
                ordered = sorted(views)
                yield RoutingRecord.network(prefix, origins, source, ordered[0], views=ordered)


def fuse_routes(records: Iterable[RoutingRecord | AuxiliaryRecord], *, trace=None) -> dict:
    """Per-real-peer longest match, then union independent current claims.

    Aggregate RIS/provider rows have no real peer identity: the parser gives
    each independent aggregate claim its own view rather than inventing a
    common peer. Compiled ranges describe nonexclusive origin membership,
    never address ownership, physical location or actual use by all hosts.
    """
    active = {}; previous = previous_family = None
    groups = defaultdict(list); routed_union = []; counts = Counter(); collectors = set()
    source_rows = Counter(); event_records = Counter(); special = Counter(); lengths = Counter()
    widest = {4: [], 6: []}; ordinal = 0
    raw_claim_rows = Counter(); aggregate_claim_rows = Counter(); input_families = set()
    def normalized():
        nonlocal ordinal
        for rec in records:
            weight = len(rec.views) if isinstance(rec, RoutingRecord) and rec.views else 1
            source_rows[rec.source] += weight
            event_records[rec.source] += 1
            if not isinstance(rec, RoutingRecord) or rec.semantics != "routing-origin":
                if trace is not None: trace.route_input(rec, "ignored", "auxiliary-not-origin-membership")
                counts["auxiliary_rows_not_asn_membership"] += 1; continue
            origins = public_asns(rec.asns)
            marked = replace(rec, compiled_asns=origins)
            for number in rec.asns:
                kind = asn_number_kind(number)
                if kind != "public": special[f"{rec.source}/{kind}"] += weight
            if rec.origin_prefix_length is not None:
                lengths[f"ipv{rec.version}/{rec.origin_prefix_length}"] += weight
                raw_claim_rows[rec.version] += 1
                if any("/aggregate:" in view for view in rec.views): aggregate_claim_rows[rec.source] += 1
                ordinal += 1
                detail = {"source":rec.source,"collector":rec.collector,"family":rec.version,
                    "start":str((ipaddress.IPv4Address if rec.version==4 else ipaddress.IPv6Address)(rec.start)),
                    "end":str((ipaddress.IPv4Address if rec.version==4 else ipaddress.IPv6Address)(rec.end)),
                    "prefix_length":rec.origin_prefix_length,"asns":list(rec.asns),
                    "compiled_asns":list(origins),"peer_count":rec.peer_count,
                    "compiled":bool(origins) and rec.origin_prefix_length!=0}
                item=(rec.end-rec.start+1,ordinal,detail)
                if len(widest[rec.version])<12:heapq.heappush(widest[rec.version],item)
                elif item>widest[rec.version][0]:heapq.heapreplace(widest[rec.version],item)
            if rec.origin_prefix_length == 0:
                # Default forwarding reachability is retained as an observation,
                # not compiled into universal ASN membership. No other prefix
                # is rejected based on its length.
                if trace is not None: trace.route_input(marked, "observed-only", "default-forwarding-not-asn-membership")
                counts[f"ipv{rec.version}_default_forwarding_observations"] += weight
                continue
            if not origins:
                if trace is not None: trace.route_input(marked, "observed-only", "iana-nonpublic-asn-not-global-membership")
                counts[f"ipv{rec.version}_nonpublic_asn_observations"] += weight
                continue
            pieces = tuple(public_intervals(rec.version, rec.start, rec.end))
            if pieces: input_families.add(rec.version)
            if trace is not None:
                trace.route_input(marked, "accepted" if pieces else "observed-only",
                    "public-address-origin-membership" if pieces else "outside-public-address-space")
            for start, end in pieces:
                yield rec.version, start, end, {"asns": origins,
                    "views": rec.views or (f"{rec.source}/{rec.collector or rec.source}",),
                    "span": str(rec.end-rec.start), "source": rec.source}
    with event_stream(normalized()) as points:
        for family, point, changes in points:
            if family != previous_family: active.clear(); previous = None
            if active and previous is not None and point > previous:
                views = {}
                for value in active.values():
                    span = int(value["span"])
                    for view in value["views"]:
                        prior = views.get(view)
                        if prior is None or span < prior[0]: views[view] = (span, set(value["asns"]))
                        elif span == prior[0]: prior[1].update(value["asns"])
                origins = set()
                for view, (_, values) in views.items():
                    if "/aggregate:" not in view: collectors.add(view)
                    origins.update(values)
                _append_interval(routed_union, family, previous, point - 1)
                counts[f"ipv{family}_routed_addresses"] += point - previous
                if len(origins) > 1:
                    counts[f"ipv{family}_multi_origin_addresses"] += point - previous
                    counts["multi_origin_segments"] += 1
                for asn in origins: _append_interval(groups[asn], family, previous, point-1)
            for rid, delta, payload in changes:
                if delta < 0: active.pop(rid, None)
                else: active[rid] = payload
            previous, previous_family = point, family
    result = {asn: intervals_to_cidrs(ranges) for asn, ranges in sorted(groups.items())}
    family_prefixes = Counter()
    for prefixes in result.values():
        for prefix in prefixes: family_prefixes[f"ipv{6 if ':' in prefix else 4}"] += 1
    return {"groups": result, "routed_prefixes": intervals_to_cidrs(routed_union),
        "report": {"policy": "current-snapshot-real-peer-lpm-independent-aggregate-origin-union",
        "source_rows": dict(sorted(source_rows.items())), "coverage": dict(counts),
        "sort_record_rows": dict(sorted(event_records.items())),
        "source_rows_note": "Distinct prefix/origin/peer claims after within-RIB dedup; aggregate peer counts do not invent peer identities. sort_record_rows counts shared payloads.",
        "original_prefix_lengths": dict(sorted(lengths.items())),
        "widest_observations_sample": [item[2] for family in (4,6) for item in sorted(widest[family], reverse=True)],
        "widest_observations_sample_complete": all(raw_claim_rows[f] <= 12 for f in (4,6)),
        "input_families": sorted(input_families),
        "input_families_meaning": "Address families with eligible non-default public-address input and at least one global ASN, before per-real-peer LPM. Output must preserve each present family.",
        "aggregate_claim_rows":dict(sorted(aggregate_claim_rows.items())),
        "wide_prefix_policy": "No prefix-length ownership floor. Every non-default valid observation contributes only its original public address portion. Wide claims remain nonexclusive routing evidence, not proof of ownership or actual use. /0 forwarding observations remain in trace but do not compile universal ASN membership.",
        "special_asns": {"registry": IANA_ASN_REGISTRY,"observations_by_source_kind":dict(sorted(special.items())),
            "policy":"Retain raw observations. Exclude reserved, AS_TRANS, documentation and private-use numbers from global ASN output; AS112 is globally routed and retained. This is not an assertion of upstream error."},
        "collector_views": sorted(collectors), "asn_groups": len(result),
        "prefixes": sum(len(v) for v in result.values()), "family_prefixes":dict(family_prefixes),
        "meaning": "Nonexclusive current origin membership, not registration country, ownership, actual host use, physical location or RPKI geographic truth.",
        "withdrawals": "No earlier snapshot routes are carried forward. Missing current sources do not prove global withdrawal.",
        "summary_limitation": "RISwhois aggregates do not identify actual peers: each prefix/origin claim remains independent. Only full MRT RIBs support real-peer LPM. Raw observations, compiled public membership and target location are distinct."}}


def summarize_auxiliary(records: Iterable[AuxiliaryRecord], geo_groups: dict[int, list[str]], registry: dict) -> dict:
    """Compare supplemental lists with cleaned geography without adding votes."""
    names = {r["id"]: r["key"] for r in registry["regions"]}
    by_source = defaultdict(Counter)
    by_country = defaultdict(lambda: defaultdict(Counter))
    # Two sorted interval streams, using the same external sorter avoids per-IP work.
    def combined():
        for rec in records:
            for start, end in public_intervals(rec.version, rec.start, rec.end):
                yield rec.version, start, end, {"source": rec.source, "kind": rec.kind,
                                              "country": rec.country}
        for rid, prefixes in geo_groups.items():
            for prefix in prefixes:
                f, a, b = bounds(prefix)
                yield f, a, b, {"region": names[rid]}
    active={}; previous=previous_family=None
    with event_stream(combined()) as points:
        for family, point, changes in points:
            if family != previous_family: active.clear(); previous=None
            if previous is not None and point>previous and active:
                regions={v['region'] for v in active.values() if 'region' in v}
                auxiliary={v['source'] for v in active.values() if 'source' in v}
                if len(regions) > 1:
                    raise ValueError("auxiliary comparison received overlapping Geo regions")
                key = f'ipv{family}_'+('unknown' if not regions else 'region_'+next(iter(regions)))+'_addresses'
                for sid in auxiliary:
                    count=point-previous
                    by_source[sid][f'ipv{family}_candidate_addresses']+=count
                    by_source[sid][key]+=count
                # A delegated file spans many countries. Preserve the actual
                # country field instead of letting the last active row stand
                # for an entire RIR or geofeed source.
                for sid, country in {(v['source'], v.get('country')) for v in active.values()
                                     if 'source' in v and v.get('country') in {'CN', 'RU'}}:
                    by_country[sid][country][f'ipv{family}_candidate_addresses'] += point-previous
                    by_country[sid][country][key] += point-previous
            for rid,delta,payload in changes:
                if delta<0:active.pop(rid,None)
                else:active[rid]=payload
            previous,previous_family=point,family
    return {"semantics":"Auxiliary list membership is reported only; never unioned into location truth.",
            "sources":{k:dict(v) for k,v in sorted(by_source.items())},
            "cn_ru_by_declared_country":{sid:{cc:dict(values) for cc,values in sorted(countries.items())}
                                         for sid,countries in sorted(by_country.items())}}


def audit_auxiliary(sources: Iterable[dict], geo_groups: dict[int, list[str]], registry: dict,
                    routing_prefixes: Iterable[str] | None = None, *, trace=None) -> dict:
    sources = list(sources)
    if routing_prefixes is not None and any(source["id"] == "bgp-visible" for source in sources):
        raise ValueError("bgp-visible is reserved for the current routing snapshot union")
    counts = Counter()
    def records():
        for source in sources:
            for record in parse_source(source["format"], source["path"], source, trace=trace):
                if not isinstance(record, AuxiliaryRecord):
                    raise ValueError("auxiliary source returned routing membership")
                if trace is not None:
                    trace.route_input(record, "auxiliary", "non-voting-" + record.kind)
                counts[record.source] += 1
                yield record
        if routing_prefixes is not None:
            counts["bgp-visible"] = 0
            for prefix in routing_prefixes:
                family, start, end = bounds(prefix)
                counts["bgp-visible"] += 1
                yield AuxiliaryRecord(family, start, end, "bgp-visible", "routing-visibility", None,
                                      "observed-in-current-inputs", "current-routing-snapshots-union")
    report = summarize_auxiliary(records(), geo_groups, registry)
    report["input_rows"] = dict(sorted(counts.items()))
    report["lineage"] = {s["id"]: s.get("lineage", s["id"]) for s in sources}
    if routing_prefixes is not None:
        report["lineage"]["bgp-visible"] = "current-routing-snapshots-union"
    report["country_note"] = "CN/RU labels on route or delegated lists describe list/registration semantics, not target country confirmation."
    return report
