"""Per-product semantic coverage and descriptive release comparisons."""
from __future__ import annotations

from collections import Counter
import ipaddress
import json
from pathlib import Path

from .domains import CoverageIndex, DOMAIN_KINDS, NON_IP_KINDS, normalize_rule


def domain_rules(lines):
    return [normalize_rule(*line.split(",", 1)) for line in lines if line.startswith("DOMAIN")]


def _merge_ranges(rows):
    merged=[]
    for start,end in sorted(rows):
        if merged and start<=merged[-1][1]+1:
            merged[-1]=(merged[-1][0],max(end,merged[-1][1]))
        else:merged.append((start,end))
    return merged


def _analyze(lines: list[str]) -> tuple[dict, dict]:
    kinds = Counter()
    ranges = {4: [], 6: []}
    for line in lines:
        pieces=line.split(",")
        if len(pieces)!=2:
            raise ValueError("generated rules must have exactly two fields")
        kind,value=pieces
        kinds[kind] += 1
        if kind in {"IP-CIDR", "IP-CIDR6"}:
            network = ipaddress.ip_network(value, strict=True)
            ranges[network.version].append((int(network.network_address),int(network.broadcast_address)))
    ranges={family:_merge_ranges(rows) for family,rows in ranges.items()}
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
    old_other = {line for line in before if line.partition(",")[0] in NON_IP_KINDS - DOMAIN_KINDS}
    new_other = {line for line in after if line.partition(",")[0] in NON_IP_KINDS - DOMAIN_KINDS}
    # Literal process/ASN predicates have no implied relationship to domains.
    # These are predicate languages, not website counts or finite host samples.
    return {"before": old_profile, "after": new_profile, "ip_changes": changes,
            "old_domain_predicates": len(old), "retained_domain_predicates": len(old) - len(removed),
            "new_domain_predicates_not_previously_covered": len(added),
            "old_domain_predicates_not_fully_retained": len(removed),
            "added_examples": added[:20], "removed_examples": removed[:20],
            "other_predicates": len(old_other), "retained_other_predicates": len(old_other & new_other),
            "removed_other_predicates": len(old_other - new_other), "added_other_predicates": len(new_other - old_other),
            "removed_other_examples": sorted(old_other - new_other)[:20], "added_other_examples": sorted(new_other - old_other)[:20]}


def _guard_catalogue(groups: dict[str, list[str]], catalogue: dict) -> list[str]:
    """Recheck declared product contracts against the actual publication bytes.

    A catalogue is descriptive metadata, never an alternative source of counts.
    Optional/unavailable targets may be described without publishing empty lists.
    """
    errors = []
    if not isinstance(catalogue, dict):
        return ["invalid product catalogue"]
    allowed_types = {"domain": DOMAIN_KINDS, "non-ip": NON_IP_KINDS, "ipv4": {"IP-CIDR"}, "ipv6": {"IP-CIDR6"},
                     **{kind: {kind} for kind in NON_IP_KINDS | {"IP-CIDR", "IP-CIDR6"}}}
    for name in groups:
        if name not in catalogue:
            errors.append(f"{name}: published product is absent from catalogue")
    for name, metadata in catalogue.items():
        if not isinstance(name, str) or len(name.split("/")) != 2 or name.split("/", 1)[0] not in {"region", "category", "provider", "special"}:
            errors.append(f"{name}: unsupported product category")
        if not isinstance(metadata, dict):
            errors.append(f"{name}: invalid catalogue entry")
            continue
        rows = groups.get(name, [])
        if metadata.get("content_types") == ["asn"]:
            if name != "special/asn":
                errors.append(f"{name}: unexpected binary product")
            continue
        if metadata.get("required_output") and name not in groups:
            errors.append(f"{name}: required product is missing")
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
            if not isinstance(child, str) or child not in catalogue:
                errors.append(f"{name}: included product is missing: {child}")
                continue
            if child not in groups:
                if catalogue[child].get("required_output"):
                    errors.append(f"{name}: included product is missing: {child}")
                continue
            diff = compare_product(groups[child], rows)
            if diff["old_domain_predicates_not_fully_retained"] or diff["removed_other_predicates"] or any(
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
    # Policy quantities and historical changes are observations, not publication
    # oracles. Required inputs are checked when acquired/parsed; this boundary
    # checks exact output bytes and declared composition only.
    actual = profiles(groups)
    if "product_coverage" in manifest and manifest["product_coverage"] != actual:
        raise ValueError("manifest product coverage disagrees with actual data")
    errors = _guard_catalogue(groups, manifest["product_catalogue"]) if "product_catalogue" in manifest else []
    if errors:
        raise ValueError("product publication validation failed: " + "; ".join(errors))
    comparisons = {}
    if baseline is not None:
        previous_path = Path(baseline) / "manifest.json"
        if previous_path.is_file():
            previous = json.loads(previous_path.read_text())
            for record in previous.get("files", []):
                if not record["path"].endswith(".list"):
                    continue
                from .validation import parse_list, safe_file
                path = safe_file(Path(baseline), record["path"])
                if path.is_file():
                    name = record["path"][:-5]
                    comparisons[name] = compare_product(parse_list(path), groups.get(name, []))
    return {"products": actual, "comparison": comparisons,
            "semantics": "Historical changes are descriptive. Domain differences prove predicate containment, not website counts; IP sizes are address coverage, not location accuracy."}


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
        # Old names are recognized only to describe a previous release, never
        # generated as aliases or accepted as a current client product.
        realip_names = {"special/realip", "dns/realip", "dns/realip-optional"}
        return sorted({line for name, rows in groups.items()
                       if (purpose == "routing" and name.startswith(("region/", "category/", "provider/", "service/")))
                       or (purpose == "realip" and name in realip_names)
                       or (purpose == "special" and name.startswith("special/") and name not in realip_names)
                       for line in rows if line.startswith("DOMAIN")})
    report = {"before_version": old["data_version"], "after_version": new["data_version"],
              "before_summary": old["summary"], "after_summary": new["summary"],
              "products": {name: compare_product(old_groups.get(name, []), new_groups.get(name, [])) for name in names},
              "unique_domain_language": compare_product(
                  sorted({line for rows in old_groups.values() for line in rows if line.startswith("DOMAIN")}),
                  sorted({line for rows in new_groups.values() for line in rows if line.startswith("DOMAIN")})),
              "domain_language_by_purpose": {
                  purpose: compare_product(domain_union(old_groups, purpose), domain_union(new_groups, purpose))
                  for purpose in ("routing", "realip", "special")},
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
