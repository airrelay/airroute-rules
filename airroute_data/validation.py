"""Fail closed at the publication boundary; no network or live target probes."""
from __future__ import annotations

import hashlib
import ipaddress
import json
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
    from .domains import parse_rule_line
    result=[]
    with path.open(encoding="utf-8") as stream:
        for number,raw in enumerate(stream,1):
            line=raw.strip()
            if not line or line.startswith("#"):continue
            try:rule=parse_rule_line(line)
            except ValueError as error:
                raise ValueError(f"unsupported rule in {path.name}:{number}: {error}") from error
            if rule.text!=line:
                raise ValueError(f"noncanonical rule in {path.name}:{number}")
            result.append(line)
    if len(result)!=len(set(result)):
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
    if registry.get("version") != manifest.get("region_registry_version"):
        raise ValueError("region registry version mismatch")
    regions = registry["regions"]
    ids = [r["id"] for r in regions]
    if len(set(ids)) != len(ids) or any(not isinstance(i, int) or i <= 0 for i in ids):
        raise ValueError("invalid region registry")
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
    # Geographic products are lists; no hidden or published Geo binary exists.
    if any(name.endswith(".ardb") and name != "special/asn.ardb" for name in names):
        raise ValueError("only special/asn.ardb is a supported binary product")
    asn = read_database(candidate / "special/asn.ardb", "asn")
    domain_groups = {p.relative_to(candidate).as_posix().removesuffix(".list"): parse_list(p)
                     for p in candidate.rglob("*.list")}
    for name in domain_groups:
        pieces = name.split("/")
        if len(pieces) != 2 or pieces[0] not in {"region", "category", "provider", "special"}:
            raise ValueError("unsupported client product category: " + name)
    from .domains import validate_domain_groups
    validate_domain_groups(domain_groups)
    expected_regions = {"region/" + ("cn-ip" if r["key"] == "cn" else r["key"]) for r in regions}
    expected_regions.add("region/cn-domain")
    if {name for name in domain_groups if name.startswith("region/")} != expected_regions:
        raise ValueError("regional product inventory disagrees with region registry")
    from .geo import public_intervals
    intervals = []
    actual_addresses = {4: 0, 6: 0}
    actual_geo_count = 0
    for name in sorted(expected_regions - {"region/cn-domain"}):
        for line in domain_groups[name]:
            kind, text = line.split(",", 1)
            if kind not in {"IP-CIDR", "IP-CIDR6"}:
                raise ValueError("regional IP products must contain only IP rules")
            network = ipaddress.ip_network(text, strict=True)
            family, start, end = network.version, int(network.network_address), int(network.broadcast_address)
            if list(public_intervals(family, start, end)) != [(start, end)]:
                raise ValueError("non-geographic special address in regional output")
            intervals.append((family, start, end, name))
            actual_geo_count += 1
    # Regions form a disjoint partition. Track the furthest enclosing interval,
    # so a nested same-region prefix cannot hide a cross-region collision.
    previous = None
    for family, start, end, name in sorted(intervals):
        if previous and family == previous[0] and start <= previous[2]:
            if name != previous[3]:
                raise ValueError("overlapping regional IP products")
            previous = (family, previous[1], max(previous[2], end), name)
        else:
            previous = (family, start, end, name)
    from .coverage import profiles, guard_products
    actual_profiles = profiles(domain_groups)
    for name in expected_regions - {"region/cn-domain"}:
        for family in (4, 6):
            actual_addresses[family] += actual_profiles[name][f"ipv{family}_addresses"]
    context = manifest.get("generation_context", {})
    if context:
        if context.get("mode") != "domains-only":
            raise ValueError("unsupported generation context")
        base = context.get("retained_ip_base", {})
        if not base.get("data_version") or len(base.get("manifest_sha256", "")) != 64:
            raise ValueError("domain-only build needs a fixed retained IP base")
        expected_files = {name + ".list" for name in expected_regions - {"region/cn-domain"}}
        expected_files |= {"special/asn.ardb", "regions.json"}
        if set(base.get("files", {})) != expected_files:
            raise ValueError("incomplete retained IP base inventory")
        for name, record in base["files"].items():
            path = safe_file(candidate, name)
            if path.stat().st_size != record.get("bytes") or file_digest(path) != record.get("sha256"):
                raise ValueError("domain-only build changed retained IP base: " + name)
        sources = {s["id"]: s for s in manifest.get("source_snapshot", [])}
        for source in context.get("ip_source_snapshot", []):
            if sources.get(source["id"]) != source:
                raise ValueError("domain-only build misrepresents retained IP sources")
    if any(name.startswith("special/") for name in domain_groups):
        from .special import validate_special_groups
        validate_special_groups(domain_groups)
    summary = manifest["summary"]
    actual_asn_count = sum(map(len, asn.values()))
    actual_domain_count = sum(sum(x.startswith("DOMAIN") for x in lines) for lines in domain_groups.values())
    if (summary.get("products") != len(domain_groups) + 1 or summary.get("geo_prefixes") != actual_geo_count or
            summary.get("asn_prefixes") != actual_asn_count or summary.get("asn_groups") != len(asn) or
            summary.get("domain_rules") != actual_domain_count):
        raise ValueError("manifest summary disagrees with actual data")
    for family in (4, 6):
        if summary.get(f"geo_v{family}_addresses") != actual_addresses[family]:
            raise ValueError("manifest address coverage disagrees with regional lists")
    actual_asn_families = {ipaddress.ip_network(prefix).version for rows in asn.values() for prefix in rows}
    input_families = summary.get("asn_input_families")
    if not isinstance(input_families, list) or any(type(f) is not int for f in input_families):
        raise ValueError("manifest needs explicit ASN input families")
    expected_asn_families = set(input_families)
    if len(expected_asn_families) != len(input_families) or not expected_asn_families <= {4, 6}:
        raise ValueError("invalid ASN input families")
    if not expected_asn_families <= actual_asn_families:
        raise ValueError("ASN output lost an address family present in admitted input")
    # Detailed historical comparisons belong to the build record, not a second
    # expensive validation pass at every publication boundary.
    guard_products(domain_groups, manifest, quality or {})
    return {"valid": True, "data_version": version, "files": len(names),
            "region_groups": len(expected_regions) - 1, "asn_groups": len(asn)}
