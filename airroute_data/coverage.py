"""Per-product coverage, predicate containment and release regression gates."""
from __future__ import annotations

from collections import Counter
from decimal import Decimal
import ipaddress
import json
from pathlib import Path

from .domains import CoverageIndex, DOMAIN_KINDS, normalize_rule


def domain_rules(lines):
    return [normalize_rule(*line.split(",", 1)) for line in lines if line.startswith("DOMAIN")]


def _analyze(lines: list[str]) -> tuple[dict, dict]:
    kinds = Counter()
    ranges = {4: [], 6: []}
    for line in lines:
        kind, value = line.split(",", 1)
        kinds[kind] += 1
        if kind in {"IP-CIDR", "IP-CIDR6"}:
            network = ipaddress.ip_network(value, strict=True)
            ranges[network.version].append((int(network.network_address), int(network.broadcast_address)))
    for family in (4, 6):
        merged = []
        for start, end in sorted(ranges[family]):
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
            else:
                merged.append((start, end))
        ranges[family] = merged
    addresses = {f: sum(b-a+1 for a,b in rows) for f,rows in ranges.items()}
    return {"predicate_counts": dict(sorted(kinds.items())),
            "domain_predicates": sum(kinds[k] for k in DOMAIN_KINDS),
            "ipv4_addresses": addresses[4], "ipv6_addresses": addresses[6],
            "ipv4_cidrs": kinds["IP-CIDR"], "ipv6_cidrs": kinds["IP-CIDR6"]}, ranges


def product_profile(lines: list[str]) -> dict:
    return _analyze(lines)[0]


def profiles(groups: dict[str, list[str]]) -> dict:
    return {name: product_profile(lines) for name, lines in sorted(groups.items())}


def compare_product(before: list[str], after: list[str]) -> dict:
    old_profile, old_ranges = _analyze(before)
    new_profile, new_ranges = _analyze(after)
    changes = {}
    for family in (4, 6):
        left, right = old_ranges[family], new_ranges[family]
        a = b = retained = 0
        while a < len(left) and b < len(right):
            retained += max(0, min(left[a][1], right[b][1]) - max(left[a][0], right[b][0]) + 1)
            if left[a][1] < right[b][1]: a += 1
            else: b += 1
        changes[f"ipv{family}"] = {"retained_addresses": retained,
            "added_addresses": new_profile[f"ipv{family}_addresses"] - retained,
            "removed_addresses": old_profile[f"ipv{family}_addresses"] - retained}
    old, new = domain_rules(before), domain_rules(after)
    old_index, new_index = CoverageIndex(old), CoverageIndex(new)
    removed = [r.text for r in old if not new_index.covers(r)]
    added = [r.text for r in new if not old_index.covers(r)]
    # These are predicate languages, not website counts or finite host samples.
    return {"before": old_profile, "after": new_profile, "ip_changes": changes,
            "old_domain_predicates": len(old), "retained_domain_predicates": len(old) - len(removed),
            "new_domain_predicates_not_previously_covered": len(added),
            "old_domain_predicates_not_fully_retained": len(removed),
            "added_examples": added[:20], "removed_examples": removed[:20]}


def _guard_catalogue(groups: dict[str, list[str]], catalogue: dict) -> list[str]:
    """Recheck declared product contracts against the actual publication bytes.

    A catalogue is descriptive metadata, never an alternative source of counts.
    Optional/unavailable targets may be described without publishing empty lists.
    """
    errors = []
    if not isinstance(catalogue, dict):
        return ["invalid product catalogue"]
    allowed_types = {"domain": DOMAIN_KINDS, "ipv4": {"IP-CIDR"}, "ipv6": {"IP-CIDR6"},
                     **{kind: {kind} for kind in DOMAIN_KINDS | {"IP-CIDR", "IP-CIDR6"}}}
    for name in groups:
        if name not in catalogue:
            errors.append(f"{name}: published product is absent from catalogue")
    for name, metadata in catalogue.items():
        if not isinstance(metadata, dict):
            errors.append(f"{name}: invalid catalogue entry")
            continue
        rows = groups.get(name, [])
        if metadata.get("required_output") and not rows:
            errors.append(f"{name}: required product is missing or empty")
        declared = metadata.get("content_types")
        if declared is not None:
            if (not isinstance(declared, list) or not declared or
                    any(not isinstance(kind, str) or kind not in allowed_types for kind in declared)):
                errors.append(f"{name}: invalid declared content types")
            else:
                accepted = set().union(*(allowed_types[kind] for kind in declared))
                if any(row.partition(",")[0] not in accepted for row in rows):
                    errors.append(f"{name}: content violates declared product types")
        children = metadata.get("includes", [])
        if not isinstance(children, list):
            errors.append(f"{name}: invalid product membership")
            continue
        for child in children:
            if not isinstance(child, str) or child not in catalogue or child not in groups:
                errors.append(f"{name}: included product is missing: {child}")
                continue
            diff = compare_product(groups[child], rows)
            if diff["old_domain_predicates_not_fully_retained"] or any(
                    diff["ip_changes"][f"ipv{family}"]["removed_addresses"] for family in (4, 6)):
                errors.append(f"{name}: does not semantically include {child}")
    # The build resolves memberships topologically. Recheck this independently
    # when validating a downloaded candidate/manifest, not only while building.
    complete = set()
    def visit(name, trail):
        if name in trail:
            errors.append(f"{name}: product membership cycle")
            return
        if name in complete:
            return
        metadata = catalogue.get(name, {})
        children = metadata.get("includes", []) if isinstance(metadata, dict) else []
        if isinstance(children, list):
            for child in children:
                if isinstance(child, str) and child in catalogue:
                    visit(child, trail | {name})
        complete.add(name)
    for name in catalogue:
        visit(name, set())
    return errors


def guard_products(groups: dict[str, list[str]], manifest: dict, quality: dict,
                   baseline: Path | None = None) -> dict:
    policy = quality.get("per_product", {})
    actual = profiles(groups)
    if "product_coverage" in manifest and manifest["product_coverage"] != actual:
        raise ValueError("manifest product coverage disagrees with actual data")
    errors = []
    if "product_catalogue" in manifest:
        errors.extend(_guard_catalogue(groups, manifest["product_catalogue"]))
    previous = json.loads((Path(baseline) / "manifest.json").read_text()) if baseline is not None else None
    previous_products = {r["path"][:-5] for r in previous.get("files", []) if r["path"].endswith(".list")} if previous else set()
    sources = {s["id"]: s for s in manifest.get("source_snapshot", [])}
    for name, required in policy.get("required_sources", {}).items():
        # Included service selectors also support the containing category.
        # Diagnostic special-source rows need not name a product at all.
        related = {name}
        pending = [name]
        catalogue = manifest.get("product_catalogue", {})
        while pending:
            for child in catalogue.get(pending.pop(), {}).get("includes", []):
                if child not in related:
                    related.add(child)
                    pending.append(child)
        for sid in required:
            source = sources.get(sid, {})
            if source.get("status") != "available" or source.get("publish_allowed") is False:
                errors.append(f"{name}: required source unavailable: {sid}")
            elif "selector_health" in manifest:
                healthy = any(row.get("group") in related and row.get("source") == sid and
                              row.get("scope_admitted", row.get("input_rules", row.get("rules", 0))) > 0
                              for row in manifest["selector_health"])
                failed = any(row.get("group") in related and row.get("source") == sid for row in manifest.get("selector_failures", []))
                if not healthy or failed:
                    errors.append(f"{name}: required selector failed or empty: {sid}")
    for name, floor in policy.get("minimum_addresses", {}).items():
        for family, minimum in floor.items():
            if actual.get(name, {}).get(f"ipv{family}_addresses", 0) < int(minimum):
                errors.append(f"{name}: IPv{family} coverage below approved floor")
    for name, minimum in policy.get("minimum_domains", {}).items():
        # A baseline containing unrelated products does not waive the initial
        # floor for a newly introduced collection. Existing collections use
        # semantic retention, allowing mathematically safe compaction.
        if actual.get(name, {}).get("domain_predicates", 0) < (1 if name in previous_products else minimum):
            errors.append(f"{name}: empty or implausibly small domain product")
    comparisons = {}
    if baseline is not None and policy:
        if policy.get("protect_used_country_sources", True):
            for source in previous.get("source_snapshot", []):
                if (source.get("role") == "country" and source.get("status") == "available"
                        and source.get("publish_allowed") is not False
                        and sources.get(source["id"], {}).get("status") != "available"):
                    errors.append("previously used country source unavailable: " + source["id"])
        for record in previous.get("files", []):
            if not record["path"].endswith(".list"):
                continue
            name = record["path"][:-5]
            path = Path(baseline) / record["path"]
            if not path.is_file():
                errors.append(f"{name}: baseline rules unavailable for semantic comparison")
                continue
            before = [s.strip() for s in path.read_text().splitlines() if s.strip() and not s.startswith("#")]
            diff = compare_product(before, groups.get(name, []))
            comparisons[name] = diff
            limit = policy.get("overrides", {}).get(name, {})
            effective_old = diff["old_domain_predicates"]
            reviewed = policy.get("reviewed_removals", {}).get(name)
            if reviewed is not None:
                if (not isinstance(reviewed, dict) or not isinstance(reviewed.get("baseline_version"), str)
                        or not isinstance(reviewed.get("predicates"), list) or not isinstance(reviewed.get("reason"), str)
                        or not reviewed["reason"].strip()):
                    errors.append(f"{name}: malformed reviewed removals policy")
                else:
                    allowed = set()
                    for predicate in reviewed["predicates"]:
                        try:
                            if not isinstance(predicate, str):
                                raise ValueError("predicate must be text")
                            rule = normalize_rule(*predicate.split(",", 1))
                            if rule.kind not in DOMAIN_KINDS or rule.text != predicate:
                                raise ValueError("predicate must be a canonical domain rule")
                            allowed.add(predicate)
                        except (ValueError, TypeError):
                            errors.append(f"{name}: invalid reviewed removal predicate")
                    matches = previous.get("data_version") == reviewed["baseline_version"]
                    index = CoverageIndex(domain_rules(groups.get(name, [])))
                    actual_lost = {r.text for r in domain_rules(before) if not index.covers(r)}
                    applied = sorted(allowed & actual_lost) if matches else []
                    effective_old -= len(applied)
                    diff["reviewed_removals"] = {"baseline_version": reviewed["baseline_version"],
                        "baseline_matches": matches, "authorized_actual_losses": applied,
                        "effective_old_domain_predicates": effective_old, "reason": reviewed["reason"]}
            retention = Decimal(str(limit.get("minimum_domain_retention", policy.get("minimum_domain_retention", 0.90))))
            if diff["retained_domain_predicates"] < Decimal(effective_old) * retention:
                errors.append(f"{name}: domain language coverage collapse")
            growth = Decimal(str(limit.get("maximum_domain_growth", policy.get("maximum_domain_growth", 2.0))))
            if (diff["old_domain_predicates"] and
                    diff["after"]["domain_predicates"] > Decimal(diff["old_domain_predicates"]) * growth and
                    diff["new_domain_predicates_not_previously_covered"] > Decimal(diff["old_domain_predicates"]) * (growth - 1)):
                errors.append(f"{name}: abnormal new domain scope growth")
            for family in (4, 6):
                key = f"ipv{family}_addresses"
                old, new = diff["before"][key], diff["after"][key]
                low = Decimal(str(limit.get("minimum_address_retention", policy.get("minimum_address_retention", 0.85))))
                high = Decimal(str(limit.get("maximum_address_growth", policy.get("maximum_address_growth", 1.5))))
                if old and new < Decimal(old) * low:
                    errors.append(f"{name}: IPv{family} address coverage collapse")
                elif old and diff["ip_changes"][f"ipv{family}"]["retained_addresses"] < Decimal(old) * low:
                    errors.append(f"{name}: IPv{family} previously covered address loss")
                if old and new > Decimal(old) * high:
                    errors.append(f"{name}: IPv{family} abnormal address coverage growth")
    if errors:
        raise ValueError("product publication validation failed: " + "; ".join(errors))
    return {"products": actual, "comparison": comparisons,
            "semantics": "Domain differences prove predicate containment, not exact text equality or website counts. IP sizes are address coverage, not location accuracy."}


def compare_directories(before: Path, after: Path) -> dict:
    from .validation import parse_list, safe_file
    def load(root):
        manifest = json.loads((root / "manifest.json").read_text())
        groups = {r["path"][:-5]: parse_list(safe_file(root, r["path"]))
                  for r in manifest["files"] if r["path"].endswith(".list")}
        return manifest, groups
    old, old_groups = load(Path(before))
    new, new_groups = load(Path(after))
    names = sorted(old_groups.keys() | new_groups.keys())
    def domain_union(groups, purpose):
        return sorted({line for name, rows in groups.items()
                       if (purpose == "routing" and name.startswith(("region/", "category/", "provider/", "service/")))
                       or (purpose == "dns" and name.startswith("dns/"))
                       or (purpose == "special" and name.startswith("special/"))
                       for line in rows if line.startswith("DOMAIN")})
    report = {"before_version": old["data_version"], "after_version": new["data_version"],
              "before_summary": old["summary"], "after_summary": new["summary"],
              "products": {name: compare_product(old_groups.get(name, []), new_groups.get(name, [])) for name in names},
              "unique_domain_language": compare_product(
                  sorted({line for rows in old_groups.values() for line in rows if line.startswith("DOMAIN")}),
                  sorted({line for rows in new_groups.values() for line in rows if line.startswith("DOMAIN")})),
              "domain_language_by_purpose": {
                  purpose: compare_product(domain_union(old_groups, purpose), domain_union(new_groups, purpose))
                  for purpose in ("routing", "dns", "special")},
              "counting_note": "Product memberships intentionally overlap. Summed rule rows are not unique services, websites or address coverage; DNS real-IP and special-purpose changes are reported separately from route identity coverage.",
              "product_catalogue": new.get("product_catalogue", {}),
              "source_status": {s["id"]: {k: s.get(k) for k in ("status", "version", "lineage", "publish_allowed")}
                                for s in new["source_snapshot"]}}
    for filename, fields in {"geo": ["special", "coverage", "source_address_support"],
                             "domains": ["reference_decisions", "groups", "selectors", "unavailable_selectors", "cn_overlap_removed"],
                             "auxiliary": ["cn_ru_by_declared_country", "input_rows", "lineage"]}.items():
        path = Path(after) / "reports" / (filename + ".json")
        if path.is_file():
            data = json.loads(path.read_text())
            report[filename] = {k: data[k] for k in fields if k in data}
    return report
