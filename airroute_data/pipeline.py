"""Immutable-snapshot batch build. All computation is offline after acquisition."""
from __future__ import annotations

import hashlib
import itertools
import json
import sys
import time
from pathlib import Path

from . import __version__
from .ardb import write_database
from .validation import file_digest, safe_file, validate_candidate


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(value))


def write_list(path: Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(rules) + ("\n" if rules else ""), encoding="utf-8")


def shard_issue_report(path: Path, max_bytes: int = 32 * 1024 * 1024) -> list[dict]:
    """Lossless bounded JSONL parts for ordinary Git's per-blob size limits."""
    path = Path(path)
    directory = path.with_suffix("")
    directory.mkdir(exist_ok=False)
    parts = []
    output = None
    size = count = 0
    def close_part() -> None:
        if output is not None:
            output.close()
            parts.append({"path": output_path.relative_to(path.parent).as_posix(), "bytes": size, "records": count})
    try:
        with path.open("rb") as source:
            for line in source:
                if not line.endswith(b"\n") or len(line) > max_bytes:
                    raise ValueError("issue record is incomplete or exceeds shard size")
                if output is None or size + len(line) > max_bytes:
                    close_part()
                    output_path = directory / f"part-{len(parts)+1:05}.jsonl"
                    output = output_path.open("xb")
                    size = count = 0
                output.write(line); size += len(line); count += 1
        if output is None:
            output_path = directory / "part-00001.jsonl"
            output = output_path.open("xb")
        close_part(); output = None
    finally:
        if output is not None:output.close()
    path.unlink()
    return parts


def source_path(snapshot_path: Path, source: dict) -> Path:
    # Snapshot paths are produced by acquire; no following links outside the frozen input.
    path = safe_file(snapshot_path.parent, source["path"])
    return path


def stable_source(source: dict) -> dict:
    fields = ("id", "status", "version", "sha256", "lineage", "role", "format", "field_semantics", "license", "publish_allowed", "publisher", "documentation", "terms")
    return {key: source[key] for key in fields if key in source}


def build(snapshot_path: Path, output: Path, config_dir: Path, *, baseline: Path | None = None,
          metrics: dict | None = None) -> dict:
    from .domains import build_domains
    from .geo import fuse_country, parse_source as parse_country
    from .routing import fuse_routes, parse_source as parse_routes, audit_auxiliary

    stage_started = time.monotonic()
    def mark(name: str) -> None:
        nonlocal stage_started
        now = time.monotonic()
        if metrics is not None:
            metrics[name] = round(now - stage_started, 3)
            print(f"stage {name}: {metrics[name]} seconds", file=sys.stderr, flush=True)
        stage_started = now

    snapshot_path = Path(snapshot_path)
    from .acquire import verify_snapshot
    snapshot = verify_snapshot(snapshot_path.parent)
    if snapshot.get("schema") != 1:
        raise ValueError("unsupported input snapshot")
    config_dir = Path(config_dir)
    registry = json.loads((config_dir / "regions.json").read_text())
    products = json.loads((config_dir / "products.json").read_text())
    quality = json.loads((config_dir / "quality.json").read_text())
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError("candidate directory must be empty; never overwrite a version")
    output.mkdir(parents=True, exist_ok=True)
    reports = output / "reports"
    reports.mkdir()
    usable = []
    skipped = []
    for entry in snapshot["sources"]:
        if entry.get("status") not in {"available", "ok", "downloaded"}:
            skipped.append(stable_source(entry)); continue
        if entry.get("publish_allowed") is False:
            skipped.append({**stable_source(entry), "reason": "publication permission not established"}); continue
        item = dict(entry)
        path = source_path(snapshot_path, item)
        item["path"] = str(path)
        usable.append(item)
    country_sources = [s for s in usable if s.get("role") in {"country", "geo"}]
    routing_sources = [s for s in usable if s.get("role") in {"routing", "asn"}]
    mark("inputs")
    country = fuse_country(itertools.chain.from_iterable(parse_country(s["format"], Path(s["path"]), s) for s in country_sources),
                           registry, min_lineages=quality.get("minimum_country_lineages", 2),
                           details_path=reports / "geo-issues.jsonl")
    country["report"]["issue_files"] = shard_issue_report(reports / "geo-issues.jsonl")
    mark("geo")
    floors = quality.get("asn_minimum_source_prefix_length", {"ipv4": 8, "ipv6": 12})
    routes = fuse_routes(itertools.chain.from_iterable(parse_routes(s["format"], Path(s["path"]), s) for s in routing_sources),
                         minimum_prefix_lengths={4: floors["ipv4"], 6: floors["ipv6"]})
    mark("asn")
    domains, domain_report = build_domains([s for s in usable if s.get("role") in {"domains", "domain"}], products)
    mark("domains")
    groups = country["groups"]
    for region in registry["regions"]:
        groups.setdefault(region["id"], [])
        ip_rules = [("IP-CIDR6," if ":" in prefix else "IP-CIDR,") + prefix for prefix in groups[region["id"]]]
        # Domain priority is explicit in the single mainland product; all other geography is IP-only.
        prefix = domains.pop("region/cn", []) if region["key"] == "cn" else []
        write_list(output / "region" / f"{region['key']}.list", prefix + ip_rules)
    for key, rules in sorted(domains.items()):
        path = safe_file(output, key + ".list")
        write_list(path, rules)
    write_database(output / "geo.ardb", "geo", groups, allowed_geo_ids=[r["id"] for r in registry["regions"]])
    write_database(output / "asn.ardb", "asn", routes["groups"])
    write_json(output / "regions.json", registry)
    write_json(reports / "geo.json", country["report"])
    write_json(reports / "asn.json", routes["report"])
    write_json(reports / "domains.json", domain_report)
    write_json(reports / "sources.json", {"used": [stable_source(s) for s in usable], "unavailable_or_withheld": skipped,
                                           "independence": "lineage grouping prevents known duplication; statistical independence is not claimed"})
    # Auxiliary references are audited separately: routing and registries never vote as location truth.
    auxiliary_sources = [s for s in usable if s not in country_sources and s not in routing_sources
                         and s.get("role") not in {"domains", "domain"}]
    by_id = {s["id"]: s for s in usable}
    for view in products.get("auxiliary_views", []):
        parent = by_id.get(view["source"])
        if parent is None:continue
        path = safe_file(Path(parent["path"]), view["path"])
        if not path.is_file():
            raise ValueError("configured auxiliary view is absent from fixed input")
        auxiliary_sources.append({**parent, **view, "path": str(path), "role": "cn-reference"})
    mark("output-core")
    auxiliary = audit_auxiliary(auxiliary_sources, groups, registry, routing_prefixes=routes["routed_prefixes"])
    write_json(reports / "auxiliary.json", auxiliary)
    mark("auxiliary")
    geo4 = geo6 = 0
    import ipaddress
    for prefixes in groups.values():
        for prefix in prefixes:
            network = ipaddress.ip_network(prefix)
            if network.version == 4:geo4 += network.num_addresses
            else:geo6 += network.num_addresses
    # Count actual accepted rules, not categories or requests.
    domain_count = 0
    for path in output.rglob("*.list"):
        domain_count += sum(1 for line in path.read_text().splitlines() if line.startswith("DOMAIN"))
    summary = {"country_lineages": len(country["report"]["usable_lineages"]),
               "geo_prefixes": sum(map(len, groups.values())), "geo_v4_addresses": geo4, "geo_v6_addresses": geo6,
               "asn_groups": len(routes["groups"]), "asn_prefixes": sum(map(len, routes["groups"].values())),
               "domain_rules": domain_count, "products": len(list(output.rglob("*.list"))),
               "source_count_available": len(usable), "source_count_unavailable_or_withheld": len(skipped)}
    attribution = ["# Data attribution", "", "Derived data retain the applicable upstream licenses; see manifest source_snapshot.", ""]
    for s in usable:
        link = s.get('documentation', s.get('source_url', ''))
        label = f"[{s.get('publisher', s['id'])}]({link})" if link else s['id']
        attribution.append(f"- {label}: {s.get('license', 'See source documentation')}; version {s.get('version', 'content SHA-256')}; source SHA-256 {s['sha256']}")
    (output / "ATTRIBUTION.md").write_text("\n".join(attribution) + "\n", encoding="utf-8")
    (output / "README.md").write_text("# AirRoute build candidate\n\n"
                                     "The publisher exports rules, ARDB files, registry, manifest and attribution at the release root.\n"
                                     "Build diagnostics stay in Actions artifacts, not the release branch.\n"
                                     "Pin downloads to one release commit and verify manifest lengths and SHA-256.\n", encoding="utf-8")
    manifest = finalize_candidate(output, snapshot, registry, products, quality, summary, baseline=baseline)
    mark("manifest-and-validation")
    return manifest


def finalize_candidate(output: Path, snapshot: dict, registry: dict, products: dict,
                       quality: dict, summary: dict, *, baseline: Path | None = None) -> dict:
    """Bind already computed batch outputs, then validate their exact bytes."""
    output = Path(output)
    stable_inputs = sorted([stable_source(s) for s in snapshot["sources"]], key=lambda s: s["id"])
    # Version binds output bytes, not wall clock or irrelevant source-code documentation changes.
    files = [{"path": p.relative_to(output).as_posix(), "bytes": p.stat().st_size, "sha256": file_digest(p)}
             for p in sorted(output.rglob("*")) if p.is_file() and p != output / "manifest.json"]
    identity = {"generator": __version__, "inputs": stable_inputs, "registry": registry,
                "products": products, "quality": quality, "files": files}
    version = hashlib.sha256(canonical(identity)).hexdigest()[:24]
    manifest = {"schema": 1, "format_version": 1, "version": version, "data_version": version,
                "generator_version": __version__, "geo_registry_version": registry["version"],
                "files": files, "source_snapshot": stable_inputs, "summary": summary}
    write_json(output / "manifest.json", manifest)
    # A failed validation leaves the complete local candidate and diagnostic report for inspection;
    # publish() independently validates again and will not move a remote pointer.
    validate_candidate(output, baseline=baseline, quality=quality)
    return manifest
