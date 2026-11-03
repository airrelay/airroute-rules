"""Fixed legacy domain corpus: an auditable migration baseline, never a vote.

The old output does not identify its per-rule upstream. Missing current support
is therefore pending, not a finding that the old rule was wrong. IP rules remain
outside this domain-only audit. No network or target lookup is performed here.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
from typing import Iterable

from .domains import (CoverageIndex, DOMAIN_KINDS, Rule, RuleError,
                      _strict_subdomain_suffix, normalize_rule, parse_third_party)

DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "config/legacy-domains.json"
DISPOSITIONS = frozenset({"retained-exact", "covered-semantically", "inapplicable",
                         "invalid-rule", "shared-dependency", "pending-verification", "outside-domain-scope"})
REVIEWABLE = frozenset({"inapplicable", "invalid-rule", "shared-dependency", "pending-verification"})


def _canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode()


def load_legacy_config(config=None) -> dict:
    value = config if isinstance(config, dict) else json.loads(Path(config or DEFAULT_CONFIG).read_text())
    if value.get("schema") != 1 or not isinstance(value.get("source"), dict):
        raise RuleError("invalid legacy corpus configuration")
    source = value["source"]
    if not all(isinstance(source.get(k), str) and source[k] for k in ("id", "version", "sha256", "path")):
        raise RuleError("legacy corpus needs fixed source identity")
    if len(source["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in source["sha256"]):
        raise RuleError("invalid legacy corpus SHA-256")
    reviewed_ids = set()
    for item in value.get("reviewed_dispositions", []):
        rule = normalize_rule(*item["predicate"].split(",", 1))
        if (rule.kind not in DOMAIN_KINDS or rule.text != item["predicate"] or
                item.get("disposition") not in REVIEWABLE or not item.get("reason") or not item.get("evidence")):
            raise RuleError("legacy reviewed disposition needs an exact predicate, reason and evidence")
        if item["predicate"] in reviewed_ids:
            raise RuleError("duplicate legacy reviewed disposition")
        reviewed_ids.add(item["predicate"])
    return value


def _file(source: dict, config: dict) -> Path:
    path = Path(source["path"])
    if path.is_file():
        return path
    relative = Path(config["source"]["path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise RuleError("unsafe legacy source path")
    selected = path / relative
    if not selected.resolve().is_relative_to(path.resolve()) or not selected.is_file():
        raise RuleError("fixed legacy corpus file is missing")
    return selected


def _group_rules(groups: dict[str, list[str]], name: str) -> list[Rule]:
    return [normalize_rule(*line.split(",", 1)) for line in groups.get(name, [])
            if line and not line.startswith("#") and line.partition(",")[0] in DOMAIN_KINDS]


def _output_digest(rules: Iterable[Rule]) -> str:
    return hashlib.sha256("\n".join(sorted({r.text for r in rules})).encode()).hexdigest()


def _unsafe_rules(rules: Iterable[Rule], config: dict) -> list[str]:
    shared = {entry["root"] for entry in config.get("shared_infrastructure", [])}
    return [r.text for r in rules if r.kind == "DOMAIN-SUFFIX" and
            ("." not in r.value or r.value in shared)]


def _witness(rule: Rule, index: CoverageIndex) -> str | None:
    if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
        bits = rule.value.split(".")
        for at in range(len(bits)):
            parent = ".".join(bits[at:])
            if parent in index.suffix:
                return "DOMAIN-SUFFIX," + parent
            if at and parent in index.strict:
                import re
                return "DOMAIN-REGEX,^.+\\." + re.escape(parent) + "$"
        for value in sorted(index.keywords, key=lambda k: (len(k), k)):
            if value in rule.value:
                return "DOMAIN-KEYWORD," + value
    elif rule.kind == "DOMAIN-REGEX":
        scope = _strict_subdomain_suffix(rule.value)
        if scope:
            # The canonical strict-subdomain language is narrower than a suffix.
            return _witness(normalize_rule("DOMAIN-SUFFIX", scope), index)
    elif rule.kind == "DOMAIN-KEYWORD":
        for value in sorted(index.keywords, key=lambda k: (len(k), k)):
            if value in rule.value:
                return "DOMAIN-KEYWORD," + value
    return None


def audit_legacy(groups: dict[str, list[str]], sources: Iterable[dict], config=None, *,
                 previous_report: dict | None = None, records_path: str | Path | None = None,
                 include_records: bool = True) -> dict:
    """Classify every fixed old row and protect already retained old languages.

    Pass records_path for a bounded JSONL sink in a full build. Without it the
    records are returned inline, useful for small fixtures and targeted queries.
    Only exact, evidenced reviewed dispositions can exempt a previously retained
    predicate; a newly missing identity or an automatic shared-host label cannot.
    """
    config = load_legacy_config(config)
    source_id = config["source"]["id"]
    matches = [s for s in sources if s["id"] == source_id]
    if len(matches) != 1 or matches[0].get("status", "available") not in {"available", "ok", "downloaded"}:
        raise RuleError("required fixed legacy domain corpus unavailable: " + source_id)
    source = matches[0]
    if source.get("version") != config["source"]["version"]:
        raise RuleError("legacy corpus version does not match fixed commit")
    path = _file(source, config)
    content = path.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    if digest != config["source"]["sha256"]:
        raise RuleError("fixed legacy corpus checksum mismatch")
    if config["source"].get("bytes") is not None and len(content) != config["source"]["bytes"]:
        raise RuleError("fixed legacy corpus byte length mismatch")
    rows, bad = parse_third_party(content.decode("utf-8"), "surge", source_id)
    group = config.get("group", "region/cn")
    current = _group_rules(groups, group)
    exact = {r.text for r in current}
    # A whole TLD or whole shared hosting platform is not a legitimate proof
    # that the migration retained all of its old children.
    shared = {entry["root"]: entry for entry in config.get("shared_infrastructure", [])}
    unsafe = _unsafe_rules(current, config)
    index = CoverageIndex(r for r in current if r.text not in unsafe)
    reviewed = {item["predicate"]: item for item in config.get("reviewed_dispositions", [])}
    counts = Counter(); samples = defaultdict(list); protected = set(); applied = {}
    records = [] if records_path is None and include_records else None
    stream = None
    if records_path is not None:
        sink = Path(records_path); sink.parent.mkdir(parents=True, exist_ok=True)
        stream = sink.open("w", encoding="utf-8")
    def record(item):
        item["upstream_provenance"] = "unknown"
        counts[item["disposition"]] += 1
        key = item["disposition"] + ":" + item["reason"]
        if len(samples[key]) < config.get("sample_limit_per_reason", 8):
            samples[key].append(item)
        if stream is not None:
            stream.write(_canonical(item).decode())
        elif records is not None:
            records.append(item)
    try:
        for rule in rows:
            item = {"line": rule.line, "rule": rule.text, "reviewed": False}
            if rule.kind not in DOMAIN_KINDS:
                item.update(disposition="outside-domain-scope", reason="IP evidence remains in its separate generation chain")
            elif rule.text in exact and rule.text not in unsafe:
                protected.add(rule.text)
                item.update(disposition="retained-exact", reason="same normalized domain predicate", covered_by=rule.text)
            elif index.covers(rule):
                protected.add(rule.text)
                item.update(disposition="covered-semantically", reason="old predicate language is contained in current output", covered_by=_witness(rule, index))
            elif rule.text in reviewed:
                decision = reviewed[rule.text]
                item.update(disposition=decision["disposition"], reason=decision["reason"], evidence=decision["evidence"], reviewed=True)
                applied[rule.text] = decision
            elif rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"} and "." not in rule.value:
                item.update(disposition="inapplicable", reason="whole top-level shortcut is outside the explicit market/service rule contract")
            else:
                parent = next((r for r in shared if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"}
                               and (rule.value == r or rule.value.endswith("." + r))), None)
                if parent:
                    item.update(disposition="shared-dependency", reason="shared infrastructure does not identify the served market; a specific endpoint may be accepted with context",
                                infrastructure=parent, scope="exact-endpoint" if rule.kind == "DOMAIN" else "suffix",
                                evidence=shared[parent]["evidence"])
                else:
                    item.update(disposition="pending-verification", reason="no accepted current classification or explicit correction; missing support is not disproof")
            record(item)
        for error in bad:
            record({"line": error["line"], "rule": error["predicate"], "disposition": "invalid-rule",
                    "reason": error["reason"], "reviewed": False})
    finally:
        if stream is not None:stream.close()
    total = len(rows) + len(bad)
    domain_total = sum(r.kind in DOMAIN_KINDS for r in rows) + sum(
        str(e["predicate"]).lstrip().upper().startswith("DOMAIN") for e in bad)
    expected = config["source"]
    if expected.get("records") is not None and total != expected["records"]:
        raise RuleError("legacy corpus parser lost or added source rows")
    if expected.get("domain_records") is not None and domain_total != expected["domain_records"]:
        raise RuleError("legacy corpus domain scope changed")
    result = {"schema": 1, "group": group,
        "source": {"id": source_id, "version": source["version"], "sha256": digest, "bytes": len(content),
                   "snapshot_sha256": source.get("sha256"), "lineage": source.get("lineage", "unknown"),
                   "per_rule_upstream": "unknown; old output is not per-rule source provenance"},
        "acquisition": {"status": source.get("status", "available"), "role": source.get("role", "legacy-domain-reference"),
                        "fetched_at": source.get("fetched_at")},
        "source_records": total, "domain_records": domain_total,
        "counts": {key: counts.get(key, 0) for key in sorted(DISPOSITIONS)},
        "samples_by_reason": dict(sorted(samples.items())), "protected_rules": sorted(protected),
        "reviewed_dispositions": applied, "output_domain_sha256": _output_digest(current),
        "unsafe_covering_predicates": unsafe,
        "configuration_sha256": hashlib.sha256(_canonical(config)).hexdigest(),
        "meaning": "Old output is a migration baseline, never independent identity/location evidence; absence is not a negative vote."}
    if records is not None:result["records"] = records
    elif records_path is not None:result["records_file"] = Path(records_path).name
    result["validation"] = guard_legacy(result, previous_report, groups=groups, config=config)
    return result


def legacy_projection(report: dict, *, include_protected: bool = True) -> dict:
    """Small persistent obligations; do not publish the old unreviewed corpus."""
    keys = ("schema", "group", "source", "source_records", "domain_records", "counts", "protected_rules",
            "reviewed_dispositions", "output_domain_sha256", "unsafe_covering_predicates", "configuration_sha256")
    return {k: report[k] for k in keys if k in report and (include_protected or k != "protected_rules")}


def guard_legacy(report: dict, previous_report: dict | None = None, *, groups=None, config=None) -> dict:
    config = load_legacy_config(config)
    source = report.get("source", {})
    if (report.get("schema") != 1 or report.get("group") != config.get("group", "region/cn") or
            source.get("id") != config["source"]["id"] or source.get("version") != config["source"]["version"] or
            source.get("sha256") != config["source"]["sha256"]):
        raise RuleError("legacy coverage projection is not bound to the fixed corpus")
    counts = report.get("counts", {})
    if (not isinstance(counts, dict) or set(counts) != DISPOSITIONS or any(type(v) is not int or v < 0 for v in counts.values())
            or sum(counts.values()) != report.get("source_records")):
        raise RuleError("legacy coverage disposition counts are incomplete")
    for key, expected_key in (("source_records", "records"), ("domain_records", "domain_records")):
        if config["source"].get(expected_key) is not None and report.get(key) != config["source"][expected_key]:
            raise RuleError("legacy coverage projection lost fixed source rows")
    protected = report.get("protected_rules", [])
    if (not isinstance(protected, list) or any(not isinstance(p, str) for p in protected)
            or len(protected) != len(set(protected))):
        raise RuleError("invalid legacy protected rule projection")
    for predicate in protected:
        rule = normalize_rule(*predicate.split(",", 1))
        if rule.kind not in DOMAIN_KINDS or rule.text != predicate:
            raise RuleError("noncanonical legacy protected predicate")
    if report.get("unsafe_covering_predicates"):
        raise RuleError("unsafe broad predicate cannot satisfy legacy semantic coverage")
    if groups is not None:
        current = _group_rules(groups, report["group"])
        if _unsafe_rules(current, config):
            raise RuleError("unsafe broad predicate cannot satisfy legacy semantic coverage")
        if _output_digest(current) != report.get("output_domain_sha256"):
            raise RuleError("legacy projection does not match actual domain output")
        index = CoverageIndex(current)
        if any(not index.covers(normalize_rule(*p.split(",", 1))) for p in report.get("protected_rules", [])):
            raise RuleError("legacy protected predicate is absent from actual output")
    if previous_report is not None:
        previous_source = previous_report.get("source", {})
        if any(previous_source.get(k) != source.get(k) for k in ("id", "version", "sha256")):
            raise RuleError("legacy fixed baseline cannot silently change")
        protected = set(report.get("protected_rules", []))
        reviewed = {r["predicate"]: r for r in config.get("reviewed_dispositions", [])}
        allowed = {p for p, r in reviewed.items() if r["disposition"] in {"inapplicable", "invalid-rule", "shared-dependency"}}
        lost = sorted(set(previous_report.get("protected_rules", [])) - protected - allowed)
        if lost:
            raise RuleError("previously retained legacy domain coverage lost: " + ", ".join(lost[:8]))
    return {"fixed_source_verified": True, "protected_legacy_predicates": len(report.get("protected_rules", [])),
            "pending": report.get("counts", {}).get("pending-verification", 0),
            "semantics": "No item-count quota; previously retained predicate languages may not silently disappear."}
