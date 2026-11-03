"""Fail closed at the publication boundary; no network or live target probes."""
from __future__ import annotations

import hashlib
import ipaddress
import json
from bisect import bisect_right
from pathlib import Path, PurePosixPath

from .ardb import read_database


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_file(root: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    if not name or relative.is_absolute() or ".." in relative.parts or "\\" in name:
        raise ValueError(f"unsafe artifact path: {name!r}")
    path = root / relative
    current = root
    for component in relative.parts:
        current = current / component
        if current.is_symlink():
            raise ValueError("artifact symlinks are forbidden")
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("artifact escapes candidate")
    return path


def parse_list(path: Path) -> list[str]:
    allowed = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "IP-CIDR", "IP-CIDR6"}
    result = []
    with path.open(encoding="utf-8") as stream:
        for number, raw in enumerate(stream, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            kind, separator, value = line.partition(",")
            if not separator or kind not in allowed or not value or "\x00" in value:
                raise ValueError(f"unsupported rule in {path.name}:{number}")
            # Core's CSV source grammar cannot express a comma within a regex payload.
            if "," in value or "\n" in value:
                raise ValueError("ambiguous list payload or forbidden policy/modifier")
            if kind in {"IP-CIDR", "IP-CIDR6"}:
                net = ipaddress.ip_network(value, strict=True)
                if net.version != (4 if kind == "IP-CIDR" else 6):
                    raise ValueError("rule address-family mismatch")
            result.append(line)
    if len(result) != len(set(result)):
        raise ValueError("duplicate rules in generated list")
    return result


def validate_candidate(candidate: Path, baseline: Path | None = None,
                       quality: dict | None = None) -> dict:
    candidate = Path(candidate)
    if (candidate / "manifest.json").stat().st_size > 95 * 1024 * 1024:
        raise ValueError("manifest exceeds ordinary Git publication size limit")
    manifest = json.loads((candidate / "manifest.json").read_text())
    if manifest.get("schema") != 1 or manifest.get("format_version") != 1:
        raise ValueError("unsupported manifest")
    version = manifest.get("data_version", "")
    if not version or manifest.get("version") != version or any(c not in "0123456789abcdef" for c in version):
        raise ValueError("invalid data version")
    registry = json.loads((candidate / "regions.json").read_text())
    if registry.get("version") != manifest.get("geo_registry_version"):
        raise ValueError("Geo registry version mismatch")
    regions = registry["regions"]
    ids = [r["id"] for r in regions]
    if len(set(ids)) != len(ids) or any(not isinstance(i, int) or i <= 0 for i in ids):
        raise ValueError("invalid Geo region registry")
    countries = [code for region in regions for code in region["countries"]]
    if len(set(countries)) != len(countries):
        raise ValueError("country mapped into multiple macro-regions")
    names = set()
    for record in manifest.get("files", []):
        name = record["path"]
        if name in names or name == "manifest.json":
            raise ValueError("duplicate or recursive artifact manifest")
        names.add(name)
        if type(record["bytes"]) is not int or not 0 <= record["bytes"] <= 95 * 1024 * 1024:
            raise ValueError("artifact exceeds ordinary Git publication size limit")
        path = safe_file(candidate, name)
        if not path.is_file() or path.stat().st_size != record["bytes"] or file_digest(path) != record["sha256"]:
            raise ValueError(f"artifact digest/length mismatch: {name}")
    actual = {str(p.relative_to(candidate).as_posix()) for p in candidate.rglob("*") if p.is_file()}
    if actual != names | {"manifest.json"}:
        raise ValueError("unmanifested or missing candidate files")
    issue_report = candidate / "reports/geo.json"
    if issue_report.exists():
        issues = json.loads(issue_report.read_text())
        if "issue_files" not in issues:
            raise ValueError("complete issue report needs a shard index")
        seen = set(); total = 0
        for part in issues["issue_files"]:
            name = part["path"]
            import re
            if not re.fullmatch(r"geo-issues/part-[0-9]{5,}\.jsonl", name):
                raise ValueError("noncanonical issue shard path")
            if name in seen:raise ValueError("duplicate issue shard")
            seen.add(name)
            path = safe_file(candidate / "reports", name)
            if path.stat().st_size != part["bytes"]:raise ValueError("issue shard size mismatch")
            with path.open("rb") as stream:
                count = sum(block.count(b"\n") for block in iter(lambda: stream.read(1024 * 1024), b""))
            if count != part["records"]:raise ValueError("issue shard record count mismatch")
            total += count
        if total != issues["issue_intervals"]:
            raise ValueError("incomplete issue report")
        physical = {p.relative_to(candidate / "reports").as_posix()
                    for p in (candidate / "reports/geo-issues").glob("*.jsonl")}
        if physical != seen:raise ValueError("unindexed issue shard")
    geo = read_database(candidate / "geo.ardb", "geo", allowed_geo_ids=ids)
    asn = read_database(candidate / "asn.ardb", "asn")
    intervals = []
    from .geo import SPECIAL
    excluded = {family: [(int(n.network_address), int(n.broadcast_address)) for n in nets]
                for family, nets in SPECIAL.items()}
    excluded_starts = {family: [a for a, _ in rows] for family, rows in excluded.items()}
    v6_start = int(ipaddress.IPv6Address("2000::"))
    v6_end = int(ipaddress.IPv6Address("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
    for group, prefixes in geo.items():
        for prefix in prefixes:
            network = ipaddress.ip_network(prefix)
            family, start, end = network.version, int(network.network_address), int(network.broadcast_address)
            at = bisect_right(excluded_starts[family], end) - 1
            if (at >= 0 and excluded[family][at][1] >= start) or (family == 6 and not v6_start <= start <= end <= v6_end):
                raise ValueError("non-geographic special address in Geo output")
            intervals.append((family, start, end, group))
    previous = None
    for interval in sorted(intervals):
        family, start, end, group = interval
        if previous and family == previous[0] and start <= previous[2] and group != previous[3]:
            raise ValueError("overlapping Geo macro-regions")
        previous = interval
    for region in regions:
        lines = parse_list(candidate / "region" / f"{region['key']}.list")
        listed = {x.split(",", 1)[1] for x in lines if x.startswith(("IP-CIDR,", "IP-CIDR6,"))}
        if listed != set(geo.get(region["id"], [])):
            raise ValueError(f"Geo/list disagreement for {region['key']}")
        if (region["key"] != "cn" and "region/" + region["key"] not in manifest.get("regional_domain_semantics", {})
                and any(not x.startswith(("IP-CIDR,", "IP-CIDR6,")) for x in lines)):
            raise ValueError("geographic IP products must not infer domain geography")
    domain_groups = {p.relative_to(candidate).as_posix().removesuffix(".list"): parse_list(p)
                     for p in candidate.rglob("*.list")}
    from .domains import validate_domain_groups
    validate_domain_groups(domain_groups)
    if any(name.startswith(("special/", "dns/")) for name in domain_groups):
        from .special import validate_special_groups
        validate_special_groups(domain_groups)
    summary = manifest["summary"]
    actual_geo_count = sum(map(len, geo.values()))
    actual_asn_count = sum(map(len, asn.values()))
    actual_domain_count = sum(sum(x.startswith("DOMAIN") for x in lines) for lines in domain_groups.values())
    if (summary.get("geo_prefixes") != actual_geo_count or
            summary.get("asn_prefixes") != actual_asn_count or
            summary.get("domain_rules") != actual_domain_count):
        raise ValueError("manifest summary disagrees with actual data")
    actual_addresses = {4: 0, 6: 0}
    for prefixes in geo.values():
        for prefix in prefixes:
            network = ipaddress.ip_network(prefix)
            actual_addresses[network.version] += network.num_addresses
    for family in (4, 6):
        if summary.get(f"geo_v{family}_addresses") != actual_addresses[family]:
            raise ValueError("manifest address coverage disagrees with actual Geo data")
    policy = quality or {}
    errors = []
    if summary.get("country_lineages", 0) < policy.get("minimum_country_lineages", 2):
        errors.append("fewer than required usable country lineages")
    if summary.get("geo_prefixes", 0) == 0:
        errors.append("no resolved Geo data")
    if summary.get("asn_prefixes", 0) == 0:
        errors.append("no routed ASN data")
    if summary.get("domain_rules", 0) == 0:
        errors.append("no accepted domain rules")
    if baseline is not None:
        previous = json.loads((Path(baseline) / "manifest.json").read_text())["summary"]
        # Compare resolved address coverage, not CIDR count: merging can change counts legitimately.
        # Domain copies across intentionally overlapping product categories are
        # not new matching scope. Per-product language comparison below guards
        # domains; a global sum would reject legitimate catalogue memberships.
        for key in ("geo_v4_addresses", "geo_v6_addresses", "asn_prefixes"):
            old = int(previous.get(key, 0)); new = int(summary.get(key, 0))
            if old and new < old * policy.get("minimum_retained_fraction", 0.70):
                errors.append(f"abnormal coverage collapse: {key}")
            if old and new > old * policy.get("maximum_growth_factor", 2.0):
                errors.append(f"abnormal coverage growth: {key}")
    if errors:
        raise ValueError("publication validation failed: " + "; ".join(errors))
    from .coverage import guard_products
    guard_products(domain_groups, manifest, policy, baseline)
    return {"valid": True, "data_version": version, "files": len(names),
            "geo_groups": len(geo), "asn_groups": len(asn)}
