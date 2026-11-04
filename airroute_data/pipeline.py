"""Immutable-snapshot batch build. All computation is offline after acquisition."""
from __future__ import annotations

import hashlib
import itertools
import json
import shutil
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
    fields = ("id", "status", "version", "sha256", "lineage", "shared_upstream_risk", "independence", "role", "domain_role", "format", "field_semantics", "license", "publish_allowed", "publisher", "documentation", "terms")
    return {key: source[key] for key in fields if key in source}


def usable_sources(snapshot_path: Path, snapshot: dict) -> tuple[list[dict], list[dict]]:
    usable, skipped = [], []
    for entry in snapshot["sources"]:
        if entry.get("status") not in {"available", "ok", "downloaded"}:
            skipped.append(stable_source(entry)); continue
        if entry.get("publish_allowed") is False:
            skipped.append({**stable_source(entry), "reason": "publication permission not established"}); continue
        usable.append({**entry, "path": str(source_path(snapshot_path, entry))})
    return usable, skipped


def domain_outputs(usable: list[dict], products: dict, special_config: dict | None,
                   reports: Path, config_dir: Path, trace=None) -> dict[str, list[str]]:
    from .domains import build_domains
    groups, report = build_domains([s for s in usable if s.get("role") in {"domains", "domain"}], products, trace=trace)
    write_json(reports / "domains.json", report)
    if special_config is not None:
        from .special import build_special
        special_groups, special_report = build_special(usable, special_config, trace=trace)
        groups.update(special_groups)
        write_json(reports / "special.json", special_report)
    from .legacy import audit_legacy
    for config in _legacy_configs(config_dir):
        audit = audit_legacy(groups, usable, config, include_records=False)
        audit["acquisition"].pop("fetched_at", None)
        # This is a semantic comparison, not a second permanent corpus or an
        # obligation to retain every old classification. Counts and samples suffice.
        audit.pop("protected_rules", None)
        audit.pop("validation", None)
        audit["comparison_policy"] = "Diagnostic semantic comparison only; old output is not authoritative and unresolved membership is not proven error."
        write_json(reports / ("legacy-" + audit["group"].replace("/", "-") + "-domains.json"), audit)
    return groups


def _legacy_configs(config_dir: Path) -> list[dict]:
    paths = sorted(set(config_dir.glob("legacy-*-domains.json")) | {config_dir / "legacy-domains.json"})
    return [json.loads(path.read_text()) for path in paths if path.is_file()]


def build_domain_candidate(snapshot_path: Path, output: Path, config_dir: Path, *,
                           baseline: Path, metrics: dict | None = None, trace=None) -> dict:
    """Refresh domain/special products while retaining verified published IP bytes.

    This is deliberately not a partial Geo build. Country/ASN credentials and
    parsers are never consulted; their existing source versions remain visible.
    """
    from .acquire import verify_snapshot
    from .domains import load_products
    from .validation import parse_list
    started = time.monotonic()
    baseline, output, config_dir, snapshot_path = map(Path, (baseline, output, config_dir, snapshot_path))
    if trace is not None: trace.stage('retained-baseline-verification', 'started')
    # Verify the full base before reading any of its predicates or copying files.
    validate_candidate(baseline)
    base = json.loads((baseline / "manifest.json").read_text())
    registry = json.loads((baseline / "regions.json").read_text())
    if json.loads((config_dir / "regions.json").read_text()) != registry:
        raise ValueError("domain-only build cannot change the Geo region registry; use a complete build")
    snapshot = verify_snapshot(snapshot_path.parent, trace=trace)
    if trace is not None:
        trace.inputs(snapshot, config_dir)
        trace.stage('domains-only', 'started', retained_binary_base=base['data_version'])
    products = load_products(config_dir / "products.json")
    quality = json.loads((config_dir / "quality.json").read_text())
    special_path = config_dir / "special.json"
    special = json.loads(special_path.read_text()) if special_path.is_file() else None
    if output.exists() and any(output.iterdir()):
        raise ValueError("candidate directory must be empty; never overwrite a version")
    output.mkdir(parents=True, exist_ok=True)
    reports = output / "reports"
    reports.mkdir()
    # Only descriptors actually read by this refresh may replace old versions.
    # A fresh country descriptor in the supplied snapshot must not imply fresh Geo.
    refresh_roles = {"domains", "domain", "legacy-domain-reference", "special", "special-reference"}
    current = {**snapshot, "sources": [s for s in snapshot["sources"] if s.get("role") in refresh_roles]}
    usable, skipped = usable_sources(snapshot_path, current)
    domains = domain_outputs(usable, products, special, reports, config_dir, trace=trace)
    for region in registry["regions"]:
        key = "region/" + region["key"]
        ips = [line for line in parse_list(baseline / (key + ".list"))
               if line.startswith(("IP-CIDR,", "IP-CIDR6,"))]
        write_list(output / (key + ".list"), domains.pop(key, []) + ips)
    for key, lines in sorted(domains.items()):
        write_list(safe_file(output, key + ".list"), lines)
    for name in ("geo.ardb", "asn.ardb", "regions.json"):
        shutil.copyfile(baseline / name, output / name)
    if trace is not None: trace.retained_asn(output/'asn.ardb',base['data_version'])
    retained = [s for s in base["source_snapshot"] if s.get("role") not in refresh_roles]
    fresh_ids = {s["id"] for s in current["sources"]}
    if fresh_ids & {s["id"] for s in retained}:
        raise ValueError("source role changed across domain-only refresh; use a complete build")
    merged = {"schema": 1, "sources": retained + current["sources"]}
    summary = {**base["summary"],
        "domain_rules": sum(sum(line.startswith("DOMAIN") for line in parse_list(p)) for p in output.rglob("*.list")),
        "products": len(list(output.rglob("*.list"))),
        "source_count_available": sum(s.get("status") in {"available", "ok", "downloaded"} and
                                      s.get("publish_allowed") is not False for s in merged["sources"]),
        "source_count_unavailable_or_withheld": sum(s.get("status") not in {"available", "ok", "downloaded"} or
                                                     s.get("publish_allowed") is False for s in merged["sources"])}
    write_json(reports / "sources.json", {"used": [stable_source(s) for s in usable],
        "unavailable_or_withheld": skipped, "retained_ip_sources": retained,
        "meaning": "Domain/special refresh only; retained IP source versions are not newly acquired."})
    attribution = ["# Data attribution", "", "Derived data retain the applicable upstream licenses; see manifest source_snapshot.", ""]
    for source in merged["sources"]:
        if source.get("status") not in {"available", "ok", "downloaded"} or source.get("publish_allowed") is False:
            continue
        link = source.get("documentation", "")
        label = f"[{source.get('publisher', source['id'])}]({link})" if link else source["id"]
        attribution.append(f"- {label}: {source.get('license', 'See source documentation')}; version {source.get('version', 'content SHA-256')}; source SHA-256 {source['sha256']}")
    (output / "ATTRIBUTION.md").write_text("\n".join(attribution) + "\n")
    binary_base = base.get("generation_context", {}).get("binary_base") or {
        "data_version": base["data_version"], "manifest_sha256": file_digest(baseline / "manifest.json"),
        "files": {name: {"sha256": file_digest(baseline / name), "bytes": (baseline / name).stat().st_size}
                  for name in ("geo.ardb", "asn.ardb", "regions.json")}}
    context = {"mode": "domains-only", "binary_base": binary_base,
        "ip_source_snapshot": retained,
        "meaning": "Geo, ASN and regional IP predicates are reused unchanged from this verified base, not recomputed."}
    manifest = finalize_candidate(output, merged, registry, products, quality, summary, baseline=baseline,
        special_config=special, legacy_configs=_legacy_configs(config_dir), generation_context=context, trace=trace)
    if metrics is not None:
        metrics["domains-only-total"] = round(time.monotonic() - started, 3)
    return manifest


def build(snapshot_path: Path, output: Path, config_dir: Path, *, baseline: Path | None = None,
          metrics: dict | None = None, trace=None) -> dict:
    from .domains import load_products
    from .geo import fuse_country, parse_source as parse_country
    from .routing import fuse_routes, parse_source as parse_routes, audit_auxiliary

    stage_started = time.monotonic()
    def mark(name: str) -> None:
        nonlocal stage_started
        now = time.monotonic()
        if metrics is not None:
            metrics[name] = round(now - stage_started, 3)
            print(f"stage {name}: {metrics[name]} seconds", file=sys.stderr, flush=True)
        if trace is not None: trace.stage(name, 'completed', elapsed_seconds=round(now-stage_started, 3))
        stage_started = now

    snapshot_path = Path(snapshot_path)
    from .acquire import verify_snapshot
    if trace is not None: trace.stage('input-verification', 'started')
    snapshot = verify_snapshot(snapshot_path.parent, trace=trace)
    if trace is not None: trace.inputs(snapshot, config_dir)
    if snapshot.get("schema") != 1:
        raise ValueError("unsupported input snapshot")
    config_dir = Path(config_dir)
    registry = json.loads((config_dir / "regions.json").read_text())
    products = load_products(config_dir / "products.json")
    quality = json.loads((config_dir / "quality.json").read_text())
    special_path = config_dir / "special.json"
    special_config = json.loads(special_path.read_text()) if special_path.is_file() else None
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError("candidate directory must be empty; never overwrite a version")
    output.mkdir(parents=True, exist_ok=True)
    reports = output / "reports"
    reports.mkdir()
    usable, skipped = usable_sources(snapshot_path, snapshot)
    country_sources = [s for s in usable if s.get("role") in {"country", "geo"}]
    routing_sources = [s for s in usable if s.get("role") in {"routing", "asn"}]
    mark("inputs")
    if trace is not None: trace.stage('geo', 'started', policy='at-least-N-lineage-agreement-without-cross-macroregion-dissent')
    country = fuse_country(itertools.chain.from_iterable(parse_country(s["format"], Path(s["path"]), s, trace=trace) for s in country_sources),
                           registry, min_lineages=quality.get("minimum_country_lineages", 2),
                           details_path=reports / "geo-issues.jsonl", trace=trace)
    country["report"]["issue_files"] = shard_issue_report(reports / "geo-issues.jsonl")
    mark("geo")
    floors = quality.get("asn_minimum_source_prefix_length", {"ipv4": 8, "ipv6": 12})
    if trace is not None: trace.stage('asn', 'started', policy='current-snapshot-longest-match-per-view-origin-union', floors=floors)
    routes = fuse_routes(itertools.chain.from_iterable(parse_routes(s["format"], Path(s["path"]), s, trace=trace) for s in routing_sources),
                         minimum_prefix_lengths={4: floors["ipv4"], 6: floors["ipv6"]}, trace=trace)
    if trace is not None: trace.route_outputs(routes['groups'])
    mark("asn")
    if trace is not None: trace.stage('domains-and-special', 'started')
    domains = domain_outputs(usable, products, special_config, reports, config_dir, trace=trace)
    mark("domains")
    groups = country["groups"]
    for region in registry["regions"]:
        groups.setdefault(region["id"], [])
        ip_rules = [("IP-CIDR6," if ":" in prefix else "IP-CIDR,") + prefix for prefix in groups[region["id"]]]
        # Regional domains identify curated local services/institutions, never
        # the physical location of a hostname's current server.
        prefix = domains.pop("region/" + region["key"], [])
        write_list(output / "region" / f"{region['key']}.list", prefix + ip_rules)
    for key, rules in sorted(domains.items()):
        path = safe_file(output, key + ".list")
        write_list(path, rules)
    write_database(output / "geo.ardb", "geo", groups, allowed_geo_ids=[r["id"] for r in registry["regions"]])
    write_database(output / "asn.ardb", "asn", routes["groups"])
    write_json(output / "regions.json", registry)
    write_json(reports / "geo.json", country["report"])
    write_json(reports / "asn.json", routes["report"])
    write_json(reports / "sources.json", {"used": [stable_source(s) for s in usable], "unavailable_or_withheld": skipped,
                                           "independence": "lineage grouping prevents known duplication; statistical independence is not claimed"})
    # Auxiliary references are audited separately: routing and registries never vote as location truth.
    auxiliary_sources = [s for s in usable if s.get("role") in {"rir", "geofeed", "cn-reference", "ru-reference"}]
    by_id = {s["id"]: s for s in usable}
    for view in products.get("auxiliary_views", []):
        parent = by_id.get(view["source"])
        if parent is None:continue
        path = safe_file(Path(parent["path"]), view["path"])
        if not path.is_file():
            raise ValueError("configured auxiliary view is absent from fixed input")
        auxiliary_sources.append({**parent, **view, "path": str(path), "role": "cn-reference"})
    mark("output-core")
    if trace is not None: trace.stage('auxiliary', 'started')
    auxiliary = audit_auxiliary(auxiliary_sources, groups, registry, routing_prefixes=routes["routed_prefixes"], trace=trace)
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
    manifest = finalize_candidate(output, snapshot, registry, products, quality, summary,
                                  baseline=baseline, special_config=special_config,
                                  legacy_configs=_legacy_configs(config_dir), trace=trace)
    mark("manifest-and-validation")
    return manifest


def finalize_candidate(output: Path, snapshot: dict, registry: dict, products: dict,
                       quality: dict, summary: dict, *, baseline: Path | None = None,
                       special_config: dict | None = None, legacy_configs: list | None = None,
                       generation_context: dict | None = None, trace=None) -> dict:
    """Bind already computed batch outputs, then validate their exact bytes."""
    output = Path(output)
    stable_inputs = sorted([stable_source(s) for s in snapshot["sources"]], key=lambda s: s["id"])
    # Version binds output bytes, not wall clock or irrelevant source-code documentation changes.
    files = [{"path": p.relative_to(output).as_posix(), "bytes": p.stat().st_size, "sha256": file_digest(p)}
             for p in sorted(output.rglob("*")) if p.is_file() and p != output / "manifest.json"]
    public_files = [r for r in files if not r["path"].startswith("reports/") and r["path"] != "README.md"]
    identity = {"generator": __version__, "inputs": stable_inputs, "registry": registry,
                "products": products, "special": special_config, "quality": quality, "files": public_files,
                "legacy_configs": legacy_configs or [], "generation_context": generation_context}
    version = hashlib.sha256(canonical(identity)).hexdigest()[:24]
    from .coverage import profiles
    from .validation import parse_list
    domain_groups = {p.relative_to(output).as_posix()[:-5]: parse_list(p) for p in output.rglob("*.list")}
    domain_health_path = output / "reports/domains.json"
    domain_health = json.loads(domain_health_path.read_text()) if domain_health_path.is_file() else {}
    catalogue = {}
    geo_sources = sorted(s["id"] for s in snapshot["sources"] if s.get("role") in {"country", "geo"}
                         and s.get("status") == "available" and s.get("publish_allowed") is not False)
    for region in registry["regions"]:
        catalogue["region/" + region["key"]] = {
            "name": region["name"], "kind": "region", "required_output": bool(quality.get("per_product", {}).get("minimum_addresses", {}).get("region/" + region["key"])),
            "purpose": "Cleaned macroregion IP coverage; any domain membership is explicit service identity, not server location.",
            "content_types": ["domain", "ipv4", "ipv6"], "includes": [],
            "source_ids": geo_sources, "ip_source_ids": geo_sources, "domain_source_ids": [],
            "domain_gap": "No justified regional domain selector configured"}
    for group in products["groups"]:
        name = group["id"]
        catalogue[name] = {**catalogue.get(name, {}),
            "name": group.get("name", catalogue.get(name, {}).get("name", name)),
            "kind": group.get("kind", name.partition("/")[0]),
            "purpose": group.get("purpose", group.get("description", group.get("routing_value", group.get("domain_semantics", "Curated service identity membership")))),
            "content_types": group.get("content_types", ["domain", "ipv4", "ipv6"]),
            "required_output": group.get("required_output", False),
            "includes": group.get("includes", []),
            "cn_market_overlaps": domain_health.get("market_overlap_declarations", {}).get(name, group.get("cn_market_overlaps", [])),
            "unresolved_cn_pattern_intersections": name in domain_health.get("unresolved_pattern_intersections", {}),
            "source_ids": sorted(set(domain_health.get("groups", {}).get(name, {}).get("source_support_rules", {}))
                                 | set(catalogue.get(name, {}).get("ip_source_ids", []))),
            "domain_source_ids": sorted(domain_health.get("groups", {}).get(name, {}).get("source_support_rules", {})),
            "declared_source_ids": sorted({s["source"] for s in group.get("selectors", [])}),
            "domain_gap": None if group.get("selectors") or group.get("includes") else "No justified regional domain source"}
    special_path = output / "reports/special.json"
    special_health = json.loads(special_path.read_text()) if special_path.is_file() else {}
    catalogue.update(special_health.get("catalogue", {}))
    manifest = {"schema": 1, "format_version": 1, "version": version, "data_version": version,
                "generator_version": __version__, "geo_registry_version": registry["version"],
                "files": files, "source_snapshot": stable_inputs, "summary": summary,
                "product_coverage": profiles(domain_groups),
                "product_catalogue": catalogue,
                "selector_health": domain_health.get("selectors", []) + special_health.get("selector_health", []),
                "selector_failures": domain_health.get("unavailable_selectors", []),
                "regional_domain_semantics": {g["id"]: g["domain_semantics"] for g in products["groups"]
                                              if g["id"].startswith("region/") and g.get("domain_semantics")}}
    from .legacy import legacy_projection
    manifest["legacy_coverage"] = {report["group"]: legacy_projection(report, include_protected=False)
        for path in sorted((output / "reports").glob("legacy*domains.json"))
        for report in [json.loads(path.read_text())]}
    if generation_context is not None:
        manifest["generation_context"] = generation_context
    write_json(output / "manifest.json", manifest)
    if trace is not None:
        trace.manifest(manifest, baseline)
        trace.product_outputs(domain_groups, catalogue)
        trace.stage('quality', 'started', policy_sha256=hashlib.sha256(canonical(quality)).hexdigest())
    # A failed validation leaves the complete local candidate and diagnostic report for inspection;
    # publish() independently validates again and will not move a remote pointer.
    try:
        validate_candidate(output, baseline=baseline, quality=quality)
    except Exception as error:
        if trace is not None: trace.stage('quality', 'failed', error_type=type(error).__name__, error=str(error))
        raise
    else:
        if trace is not None: trace.stage('quality', 'passed')
    return manifest
