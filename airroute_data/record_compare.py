"""Diagnostic differences between a published baseline and a build candidate.

This module does not validate, approve or publish either input. In particular a
candidate rejected by the normal quality gates can still be compared here.
Existing semantic product comparison remains authoritative for containment;
regional IP changes add a disjoint interval overlay, never per-address rows.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import heapq
import ipaddress
import itertools
import json
from pathlib import Path

from .coverage import compare_directories, domain_rules
from .domains import CompactionWitness, CoverageIndex
from .validation import parse_list, safe_file


SOURCE_FIELDS = ("status", "version", "sha256", "lineage", "role", "format",
                 "field_semantics", "publish_allowed")
SAMPLE_LIMIT = 20


def _sources(old, new):
    before = {row["id"]: row for row in old.get("source_snapshot", [])}
    after = {row["id"]: row for row in new.get("source_snapshot", [])}
    changes = []
    for sid in sorted(before.keys() | after.keys()):
        left = {key: before.get(sid, {}).get(key) for key in SOURCE_FIELDS}
        right = {key: after.get(sid, {}).get(key) for key in SOURCE_FIELDS}
        fields = {key: {"before": left[key], "after": right[key]}
                  for key in SOURCE_FIELDS if left[key] != right[key]}
        if fields or sid not in before or sid not in after:
            changes.append({"source": sid, "status": "added" if sid not in before else
                            "removed" if sid not in after else "changed", "fields": fields})
    return changes


def _products(root, manifest):
    return {row["path"][:-5]: safe_file(root, row["path"])
            for row in manifest["files"] if row["path"].endswith(".list")}


def _regional_intervals(paths):
    rows = []
    for name, path in paths.items():
        if not name.startswith("region/"):
            continue
        for line in parse_list(path):
            kind, _, value = line.partition(",")
            if kind in {"IP-CIDR", "IP-CIDR6"}:
                network = ipaddress.ip_network(value, strict=True)
                rows.append((network.version, int(network.network_address),
                             int(network.broadcast_address), name))
    rows.sort()
    merged = []
    for family, start, end, region in rows:
        if merged and merged[-1][0] == family and start <= merged[-1][2]:
            if merged[-1][3] != region:
                raise ValueError("regional IP comparison has cross-region overlapping predicates")
            merged[-1] = (family, merged[-1][1], max(end, merged[-1][2]), region)
        elif (merged and merged[-1][0] == family and start == merged[-1][2] + 1
              and merged[-1][3] == region):
            merged[-1] = (family, merged[-1][1], end, region)
        else:
            merged.append((family, start, end, region))
    return merged


def _events(rows, side):
    for family, start, end, region in rows:
        # Close an interval before opening an adjacent interval at the same IP.
        yield family, start, 1, side, region
        yield family, end + 1, 0, side, None


def _overlay(before, after):
    old = new = None
    previous = previous_family = None
    pending = None
    events = heapq.merge(_events(before, 0), _events(after, 1))
    for (family, point), changes in itertools.groupby(events, lambda item: item[:2]):
        if family != previous_family:
            old = new = None
            previous = None
        if previous is not None and point > previous and (old is not None or new is not None):
            status = ("added" if old is None else "removed-to-unknown" if new is None else
                      "unchanged" if old == new else "reassigned")
            current = (family, previous, point - 1, old, new, status)
            if pending and pending[0] == family and pending[2] + 1 == previous and pending[3:] == current[3:]:
                pending = (family, pending[1], point - 1, old, new, status)
            else:
                if pending is not None:
                    yield pending
                pending = current
        for _, _, _, side, region in changes:
            if side == 0:
                old = region
            else:
                new = region
        previous = point
        previous_family = family
    if pending is not None:
        yield pending


def _cidr_count(start, end, width):
    count = 0
    while start <= end:
        alignment = (start & -start).bit_length() - 1 if start else width
        remaining = (end - start + 1).bit_length() - 1
        start += 1 << min(alignment, remaining)
        count += 1
    return count


def _geo(before_paths, after_paths, trace):
    families = {4: defaultdict(Counter), 6: defaultdict(Counter)}
    transitions = defaultdict(Counter)
    samples = []
    changed_intervals = 0
    for family, start, end, old, new, status in _overlay(
            _regional_intervals(before_paths), _regional_intervals(after_paths)):
        counts = {"addresses": end - start + 1, "intervals": 1,
                  "canonical_cidrs": _cidr_count(start, end, 32 if family == 4 else 128)}
        families[family][status].update(counts)
        transitions[(family, old, new, status)].update(counts)
        if status == "unchanged":
            continue
        changed_intervals += 1
        if trace is not None:
            trace.geo_change(family, start, end, old, new, status)
        if len(samples) < SAMPLE_LIMIT:
            address = ipaddress.IPv4Address if family == 4 else ipaddress.IPv6Address
            samples.append({"family": family, "start": str(address(start)), "end": str(address(end)),
                            "before": old, "after": new, "status": status, **counts})
    return {
        "families": {f"ipv{family}": {status: dict(counts) for status, counts in sorted(states.items())}
                     for family, states in families.items()},
        "transitions": [{"family": key[0], "before": key[1], "after": key[2], "status": key[3], **dict(counts)}
                        for key, counts in sorted(transitions.items(), key=lambda item: tuple(str(v) for v in item[0]))],
        "changed_intervals": changed_intervals, "samples": samples,
        "samples_complete": changed_intervals <= SAMPLE_LIMIT,
        "counting_note": "Addresses are interval cardinality, not active hosts. canonical_cidrs is the minimal CIDR cover of semantic transition intervals, not input/final file line counts. Both-unknown space is not expanded. Removed means no longer assigned by regional products, not proof of no information or global withdrawal."}


def _domain_changes(before_paths, after_paths, trace):
    counts = defaultdict(Counter)
    samples = []
    events = 0
    for product in sorted(before_paths.keys() | after_paths.keys()):
        old_lines = parse_list(before_paths[product]) if product in before_paths else []
        new_lines = parse_list(after_paths[product]) if product in after_paths else []
        old, new = domain_rules(old_lines), domain_rules(new_lines)
        old_index, new_index = CoverageIndex(old), CoverageIndex(new)
        old_witness = CompactionWitness(rule.text for rule in old)
        new_witness = CompactionWitness(rule.text for rule in new)
        old_text, new_text = {rule.text for rule in old}, {rule.text for rule in new}
        def record(rule, status, covering=None):
            nonlocal events
            events += 1
            counts[product][status] += 1
            if trace is not None:
                trace.domain_change(product, rule.text, status, covering)
            if len(samples) < SAMPLE_LIMIT:
                samples.append({"product": product, "predicate": rule.text,
                                "status": status, "covering_predicate": covering})
        for rule in old:
            if not new_index.covers(rule):
                record(rule, "removed")
            elif rule.text not in new_text:
                record(rule, "covered-by-current", new_witness.covering(rule))
        for rule in new:
            if not old_index.covers(rule):
                record(rule, "added")
            elif rule.text not in old_text:
                record(rule, "covered-by-baseline", old_witness.covering(rule))
    return {"products": {product: dict(value) for product, value in sorted(counts.items())},
            "events": events, "samples": samples, "samples_complete": events <= SAMPLE_LIMIT,
            "counting_note": "Added/removed are predicate-language containment changes using the existing CoverageIndex. Covered-by-current/baseline describes proven containment across textual replacement, not whole-product equivalence or a loss. Arbitrary regex language equivalence remains conservative, not guessed from sample hosts."}


def compare_build(candidate: Path, baseline: Path, trace=None) -> dict:
    """Compare complete generated bytes even when the candidate failed quality.

    The baseline's publication field is metadata, not live remote verification.
    The caller owns acquisition/verification of the last published baseline.
    """
    candidate, baseline = Path(candidate), Path(baseline)
    old = json.loads((baseline / "manifest.json").read_text())
    new = json.loads((candidate / "manifest.json").read_text())
    publication = old.get("publication") or {}
    before_paths, after_paths = _products(baseline, old), _products(candidate, new)
    return {
        "schema": 1,
        "baseline": {"role": "comparison-baseline", "data_version": old["data_version"],
                     "publication_recorded": bool(publication),
                     "publication": {key: publication.get(key)
                                     for key in ("sequence", "attempt", "source_sha")}},
        "candidate": {"role": "unpublished-candidate", "data_version": new["data_version"]},
        "baseline_note": "Publication metadata does not prove the current remote head; comparison does not approve a candidate or relax validation.",
        "source_changes": _sources(old, new),
        "semantic_products": compare_directories(baseline, candidate),
        "geo_changes": _geo(before_paths, after_paths, trace),
        "domain_changes": _domain_changes(before_paths, after_paths, trace)}
