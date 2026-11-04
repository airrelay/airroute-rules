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



def _canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode()


def load_legacy_config(config=None) -> dict:
    value = config if isinstance(config, dict) else json.loads(Path(config or DEFAULT_CONFIG).read_text())
    if value.get("schema") != 1 or not isinstance(value.get("source"), dict):
        raise RuleError("invalid legacy corpus configuration")
    source = value["source"]
    if not all(isinstance(source.get(k), str) and source[k] for k in ("id", "version", "sha256", "path")):
        raise RuleError("legacy corpus needs fixed source identity")
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


def audit_legacy(groups, sources, config=None, *, records_path=None, include_records=True):
    """Describe semantic migration coverage; never constrain current products."""
    config = load_legacy_config(config)
    source_id = config["source"]["id"]
    source = next((source for source in sources if source["id"] == source_id), None)
    if source is None:
        return {"group": config["group"], "status": "missing-optional", "source": config["source"]}
    if source.get("version") != config["source"]["version"]:
        raise RuleError("legacy corpus version does not match fixed commit")
    content = _file(source, config).read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    if digest != config["source"]["sha256"]:
        raise RuleError("fixed legacy corpus checksum mismatch")
    if config["source"].get("bytes") is not None and len(content) != config["source"]["bytes"]:
        raise RuleError("fixed legacy corpus byte length mismatch")
    rows, bad = parse_third_party(content.decode("utf-8"), "surge", source_id)
    current = _group_rules(groups, config["group"])
    exact = {rule.text for rule in current}
    index = CoverageIndex(current)
    counts, samples = Counter(), defaultdict(list)
    records = [] if records_path is None and include_records else None
    stream = None
    if records_path is not None:
        path = Path(records_path); path.parent.mkdir(parents=True, exist_ok=True)
        stream = path.open("w")
    def record(item):
        item["upstream_provenance"] = "unknown"
        counts[item["disposition"]] += 1
        key = item["disposition"] + ":" + item["reason"]
        if len(samples[key]) < config.get("sample_limit_per_reason", 8): samples[key].append(item)
        if stream is not None: stream.write(_canonical(item).decode())
        elif records is not None: records.append(item)
    try:
        for rule in rows:
            item = {"line": rule.line, "rule": rule.text}
            if rule.kind not in DOMAIN_KINDS:
                item.update(disposition="outside-domain-scope", reason="IP generation is a separate evidence chain")
            elif rule.text in exact:
                item.update(disposition="retained-exact", reason="same normalized predicate", covered_by=rule.text)
            elif index.covers(rule):
                item.update(disposition="covered-semantically", reason="existing output contains this predicate", covered_by=_witness(rule,index))
            else:
                item.update(disposition="pending-verification", reason="not covered by current selected sources; absence is not disproof")
            record(item)
        for error in bad:
            record({"line": error["line"], "rule": error["predicate"], "disposition": "invalid-rule", "reason": error["reason"]})
    finally:
        if stream is not None: stream.close()
    result = {"schema": 1, "group": config["group"],
        "source": {"id": source_id, "version": source["version"], "sha256": digest,
                   "bytes": len(content), "lineage": source.get("lineage", "unknown")},
        "acquisition": {"status": source.get("status", "available"), "fetched_at": source.get("fetched_at")},
        "source_records": len(rows)+len(bad),
        "domain_records": sum(rule.kind in DOMAIN_KINDS for rule in rows)+sum(str(e["predicate"]).startswith("DOMAIN") for e in bad),
        "counts": dict(counts), "samples_by_reason": dict(samples),
        "output_domain_sha256": _output_digest(current),
        "meaning": "Descriptive migration comparison only; not a source vote or a publication gate."}
    if records is not None: result["records"] = records
    if records_path is not None: result["records_file"] = Path(records_path).name
    return result


def legacy_projection(report):
    return {key: report[key] for key in ("schema","group","source","source_records","domain_records","counts","output_domain_sha256") if key in report}
