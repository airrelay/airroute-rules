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
    fields = ("id", "status", "version", "sha256", "lineage", "shared_upstream_risk", "independence", "role", "domain_role", "format", "field_semantics", "license", "publish_allowed", "publisher", "documentation", "terms", "address_families", "enabled")
    return {key: source[key] for key in fields if key in source}


def usable_sources(snapshot_path: Path, snapshot: dict) -> tuple[list[dict], list[dict]]:
    usable, skipped = [], []
    for entry in snapshot["sources"]:
        if entry.get("status") in {"disabled", "not-selected"}:
            skipped.append(stable_source(entry)); continue
        if entry.get("status") not in {"available", "ok", "downloaded"}:
            raise ValueError(f"{entry['id']}: participating source unavailable ({entry.get('status')})")
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
        if not any(source["id"] == config["source"]["id"] for source in usable):
            write_json(reports / ("legacy-" + config["group"].replace("/", "-") + "-domains.json"),
                {"group": config["group"], "status": "missing-optional", "source": config["source"]})
            continue
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


def region_product(region: dict) -> str:
    return "region/" + ("cn-ip" if region["key"] == "cn" else region["key"])


def build_domain_candidate(snapshot_path: Path, output: Path, config_dir: Path, *,
                           baseline: Path, metrics: dict | None = None, trace=None) -> dict:
    """Refresh domain/special products while retaining verified published IP bytes.

    This refresh reuses regional IP lists and ASN bytes. Country/ASN credentials and
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
        trace.stage('domains-only', 'started', retained_ip_base=base['data_version'])
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
    retained_files = [region_product(region) + ".list" for region in registry["regions"]]
    retained_files += ["special/asn.ardb", "regions.json"]
    for name in retained_files:
        destination = safe_file(output, name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(safe_file(baseline, name), destination)
    for key, lines in sorted(domains.items()):
        write_list(safe_file(output, key + ".list"), lines)
    if trace is not None: trace.retained_asn(output/'special/asn.ardb',base['data_version'])
    retained = [s for s in base["source_snapshot"] if s.get("role") not in refresh_roles]
    fresh_ids = {s["id"] for s in current["sources"]}
    if fresh_ids & {s["id"] for s in retained}:
        raise ValueError("source role changed across domain-only refresh; use a complete build")
    acquisition = {source["id"]: source for source in base.get("source_acquisition", [])}
    retained_descriptors = [{**source, "fetched_at": acquisition.get(source["id"], {}).get("fetched_at")} for source in retained]
    merged = {"schema": 1, "created_at": snapshot.get("created_at"), "sources": retained_descriptors + current["sources"]}
    summary = {**base["summary"],
        "domain_rules": sum(sum(line.startswith("DOMAIN") for line in parse_list(p)) for p in output.rglob("*.list")),
        "products": len(list(output.rglob("*.list"))) + 1,
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
    retained_ip_base = base.get("generation_context", {}).get("retained_ip_base") or {
        "data_version": base["data_version"], "manifest_sha256": file_digest(baseline / "manifest.json"),
        "input_snapshot_time": base.get("input_snapshot_time"),
        "source_acquisition": base.get("source_acquisition", []),
        "files": {name: {"sha256": file_digest(baseline / name), "bytes": (baseline / name).stat().st_size}
                  for name in retained_files}}
    context = {"mode": "domains-only", "retained_ip_base": retained_ip_base,
        "ip_source_snapshot": retained,
        "meaning": "Regional IP lists and ASN database are reused unchanged from this verified base; source versions and acquisition times are retained, not newly acquired."}
    manifest = finalize_candidate(output, merged, registry, products, quality, summary, baseline=baseline,
        special_config=special, legacy_configs=_legacy_configs(config_dir), generation_context=context,
        address_eligibility=base.get("address_eligibility"), trace=trace)
    if metrics is not None:
        metrics["domains-only-total"] = round(time.monotonic() - started, 3)
    return manifest


def build(snapshot_path: Path, output: Path, config_dir: Path, *, baseline: Path | None = None,
          metrics: dict | None = None, trace=None) -> dict:
    from .domains import load_products
    from .geo import fuse_country, parse_source as parse_country, load_geo_policy
    from .routing import fuse_asn, fuse_routes, parse_source as parse_routes, audit_auxiliary
    from .address_space import AddressEligibility

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
    formal_asn = next((source for source in routing_sources if source["id"] == "maxmind-asn" and source["format"] == "maxmind-asn-csv"), None)
    if formal_asn is None:
        raise ValueError("required formal ASN source unavailable: maxmind-asn")
    comparison_sources = [source for source in routing_sources if source["id"] != "maxmind-asn"]
    eligibility = AddressEligibility.from_sources(usable, trace=trace)
    write_json(reports / "address-eligibility.json", eligibility.report)
    geo_policy = load_geo_policy(config_dir / "geo-policy.json")
    primary = next((source for source in country_sources if source["id"] == geo_policy["primary_source"]), None)
    write_json(reports / "sources.json", {"used": [stable_source(source) for source in usable], "unavailable_or_withheld": skipped})
    if primary is None:
        raise ValueError("required primary country source unavailable: " + geo_policy["primary_source"])
    if trace is not None: trace.stage('geo', 'started', policy=geo_policy)
    country = fuse_country(itertools.chain.from_iterable(parse_country(source["format"], Path(source["path"]), source, trace=trace)
                           for source in country_sources), registry, source_order=geo_policy["source_order"],
                           details_path=None if trace is not None else reports / "geo-issues.jsonl", trace=trace,
                           eligibility=eligibility, comparison_only_address_families=geo_policy.get("comparison_only_address_families", {}))
    if trace is not None:
        country["report"]["issue_storage"] = {"kind": "build-record-sqlite", "path": "trace.sqlite3",
            "tables": ["geo_input", "geo_issue", "output_ip"],
            "query": "python -m airroute_data explain --record-dir <downloaded-record> --ip <IP-or-prefix>",
            "completeness": "See summary.json:evidence_complete and artifact-index.json:complete; failed parses may be partial."}
    else:
        country["report"]["issue_files"] = shard_issue_report(reports / "geo-issues.jsonl")
    write_json(reports / "geo.json", country["report"])
    primary_rows = country["report"]["source_valid_country_rows"].get(primary["id"], {})
    required_families = primary.get("address_families", [4, 6])
    if any(not primary_rows.get(f"ipv{family}") for family in required_families):
        raise ValueError("primary country source has no valid mapped input for a declared address family: " + primary["id"])
    mark("geo")
    if trace is not None: trace.stage('asn', 'started', policy='maxmind-asn-only-longest-prefix; BGP and IPtoASN are comparisons')
    routes = fuse_asn(parse_routes(formal_asn["format"], Path(formal_asn["path"]), formal_asn, trace=trace),
                      eligibility=eligibility, trace=trace)
    comparisons = fuse_routes(itertools.chain.from_iterable(
        parse_routes(source["format"], Path(source["path"]), source, trace=trace)
        for source in comparison_sources), eligibility=eligibility, trace=trace)
    write_json(reports / "asn-comparison.json", comparisons["report"])
    if trace is not None: trace.route_outputs(routes['groups'])
    mark("asn")
    if trace is not None: trace.stage('domains-and-special', 'started')
    domains = domain_outputs(usable, products, special_config, reports, config_dir, trace=trace)
    mark("domains")
    groups = country["groups"]
    for region in registry["regions"]:
        groups.setdefault(region["id"], [])
        ip_rules = [("IP-CIDR6," if ":" in prefix else "IP-CIDR,") + prefix for prefix in groups[region["id"]]]
        write_list(output / (region_product(region) + ".list"), ip_rules)
    for key, rules in sorted(domains.items()):
        write_list(safe_file(output, key + ".list"), rules)
    (output / "special").mkdir(exist_ok=True)
    write_database(output / "special/asn.ardb", "asn", routes["groups"])
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
            if trace is not None: trace.source_event(view["id"], "auxiliary-view", "failed", source=view["source"], path=view["path"])
            raise ValueError("participating auxiliary view is absent from fixed input: " + view["id"])
        auxiliary_sources.append({**parent, "address_families": [4, 6], **view, "path": str(path), "role": "cn-reference"})
    mark("output-core")
    if trace is not None: trace.stage('auxiliary', 'started')
    auxiliary = audit_auxiliary(auxiliary_sources, groups, registry, routing_prefixes=comparisons["observed_prefixes"], trace=trace)
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
               "asn_input_families": routes["report"]["input_families"],
               "asn_expected_families": formal_asn["address_families"],
               "asn_groups": len(routes["groups"]), "asn_prefixes": sum(map(len, routes["groups"].values())),
               "domain_rules": domain_count, "products": len(list(output.rglob("*.list"))) + 1,
               "source_count_available": len(usable), "source_count_unavailable_or_withheld": len(skipped)}
    attribution = ["# Data attribution", "", "Derived data retain the applicable upstream licenses; see manifest source_snapshot.", ""]
    for s in usable:
        link = s.get('documentation', s.get('source_url', ''))
        label = f"[{s.get('publisher', s['id'])}]({link})" if link else s['id']
        attribution.append(f"- {label}: {s.get('license', 'See source documentation')}; version {s.get('version', 'content SHA-256')}; source SHA-256 {s['sha256']}")
    (output / "ATTRIBUTION.md").write_text("\n".join(attribution) + "\n", encoding="utf-8")
    (output / "README.md").write_text("# AirRoute build candidate\n\n"
                                     "The publisher exports region/category/provider/special rules, special/asn.ardb and release metadata.\n"
                                     "Build diagnostics stay in Actions artifacts, not the release branch.\n"
                                     "Pin downloads to one release commit and verify manifest lengths and SHA-256.\n", encoding="utf-8")
    manifest = finalize_candidate(output, snapshot, registry, products, quality, summary,
                                  baseline=baseline, special_config=special_config,
                                  legacy_configs=_legacy_configs(config_dir), address_eligibility=eligibility.report, trace=trace)
    mark("manifest-and-validation")
    return manifest


def finalize_candidate(output: Path, snapshot: dict, registry: dict, products: dict,
                       quality: dict, summary: dict, *, baseline: Path | None = None,
                       special_config: dict | None = None, legacy_configs: list | None = None,
                       generation_context: dict | None = None, address_eligibility: dict | None = None, trace=None) -> dict:
    """Bind already computed batch outputs, then validate their exact bytes."""
    output = Path(output)
    stable_inputs = sorted([stable_source(s) for s in snapshot["sources"]], key=lambda s: s["id"])
    # Version binds output bytes, not wall clock or irrelevant source-code documentation changes.
    files = [{"path": p.relative_to(output).as_posix(), "bytes": p.stat().st_size, "sha256": file_digest(p)}
             for p in sorted(output.rglob("*")) if p.is_file() and p != output / "manifest.json"]
    public_files = [r for r in files if not r["path"].startswith("reports/") and r["path"] != "README.md"]
    identity = {"generator": __version__, "inputs": stable_inputs, "registry": registry,
                "products": products, "special": special_config, "quality": quality, "files": public_files,
                "legacy_configs": legacy_configs or [], "generation_context": generation_context,
                "address_eligibility": address_eligibility}
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
        catalogue[region_product(region)] = {
            "name": region["name"] + (" IP" if region["key"] == "cn" else ""),
            "kind": "region", "required_output": True,
            "purpose": "Macroregion IPv4/IPv6 estimates selected by fixed primary and ordered fallback; not domain service markets.",
            "content_types": ["ipv4", "ipv6"], "includes": [],
            "source_ids": geo_sources, "ip_source_ids": geo_sources, "domain_source_ids": []}
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
            "domain_gap": None if group.get("selectors") or group.get("includes") or not set(group.get("content_types", ["domain"])) & {"domain", "non-ip"} else "No configured upstream selector or included domain product"}
    special_path = output / "reports/special.json"
    special_health = json.loads(special_path.read_text()) if special_path.is_file() else {}
    catalogue.update(special_health.get("catalogue", {}))
    catalogue["special/asn"] = {"name": "ASN database", "kind": "special", "content_types": ["asn"],
        "path": "special/asn.ardb", "required_output": True, "purpose": "MaxMind GeoLite2 ASN longest-prefix attribution for compile-time expansion; BGP/IPtoASN comparison only, not geography or exclusive ownership",
        "source_ids": ["maxmind-asn"]}
    manifest = {"schema": 1, "format_version": 1, "version": version, "data_version": version,
                "generator_version": __version__, "region_registry_version": registry["version"],
                "files": files, "source_snapshot": stable_inputs, "summary": summary,
                "input_snapshot_time": snapshot.get("created_at"),
                "source_acquisition": [{"id": source["id"], "fetched_at": source.get("fetched_at"), "version": source.get("version")} for source in snapshot["sources"]],
                "product_coverage": profiles(domain_groups),
                "product_catalogue": catalogue,
                "selector_health": domain_health.get("selectors", []) + special_health.get("selector_health", []),
                "selector_failures": domain_health.get("unavailable_selectors", []),
                "regional_domain_semantics": {g["id"]: g["domain_semantics"] for g in products["groups"]
                                              if g["id"].startswith("region/") and g.get("domain_semantics")}}
    if address_eligibility is not None:
        manifest["address_eligibility"] = address_eligibility
    from .legacy import legacy_projection
    manifest["legacy_coverage"] = {report["group"]: legacy_projection(report)
        for path in sorted((output / "reports").glob("legacy*domains.json"))
        for report in [json.loads(path.read_text())] if report.get("source_records") is not None}
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
