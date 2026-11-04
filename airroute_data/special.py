"""Offline special-address and DNS-address-mode data, with separate purposes.

No discovery/probing, DNS resolution or network access occurs here. RFC-defined
address selections are deliberately narrower than upstream "private" lists.
"""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
from pathlib import Path
import re
from typing import Iterable

from .domains import CompactionWitness, CoverageIndex, DLC, IP_KINDS, Rule, RuleError, minimize, normalize_rule, parse_third_party

DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "config" / "special.json"
LAN_NETWORKS = tuple(ipaddress.ip_network(s) for s in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "fc00::/7", "::1/128", "fe80::/10"))
LOCAL_NAMES = frozenset({"localhost", "local", "home.arpa"})
KNOWN_IDS = frozenset({"special/lan", "special/shared", "special/multicast", "special/broadcast",
    "special/benchmark", "special/documentation", "special/nat64", "special/local-name-compat",
    "special/connectivity", "special/ntp", "special/stun-turn", "special/software-update",
    "special/public-dns", "special/realip"})
IP_SCOPES = {
    "special/shared": ("100.64.0.0/10",),
    "special/multicast": ("224.0.0.0/4", "ff00::/8"),
    "special/broadcast": ("255.255.255.255/32",),
    "special/benchmark": ("198.18.0.0/15", "2001:2::/48"),
    "special/documentation": ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "3fff::/20"),
    "special/nat64": ("64:ff9b::/96", "64:ff9b:1::/48"),
    "special/public-dns": ("8.8.8.8/32", "8.8.4.4/32", "2001:4860:4860::8888/128", "2001:4860:4860::8844/128",
                           "1.1.1.1/32", "1.0.0.1/32", "2606:4700:4700::1111/128", "2606:4700:4700::1001/128"),
}


def load_special_config(config: dict | str | Path | None = None) -> dict:
    if not isinstance(config, dict):
        config = json.loads(Path(config or DEFAULT_CONFIG).read_text(encoding="utf-8"))
    if config.get("schema") != 1 or not isinstance(config.get("groups"), list):
        raise RuleError("unsupported special data configuration")
    ids = [g["id"] for g in config["groups"]]
    if len(ids) != len(set(ids)) or set(ids) - KNOWN_IDS:
        raise RuleError("unknown or duplicate special collection")
    return config


def _inside(network, choices) -> bool:
    return any(network.version == parent.version and network.subnet_of(parent) for parent in choices)


def validate_special_groups(groups: dict[str, list[str]], config=None, *, require_complete: bool = False) -> dict:
    """Validate format and purpose, not historical amounts or fixed contents.

    LAN must remain local/private rather than a catch-all special-address list.
    RealIP contains only client-supported DNS predicates, without route actions.
    """
    selected = {g: rows for g, rows in groups.items() if g.startswith("special/")}
    if set(selected) - KNOWN_IDS:
        raise RuleError("unknown special collection")
    if require_complete:
        expected = {g["id"] for g in load_special_config(config)["groups"]}
        if expected - selected.keys():
            raise RuleError("missing special collections: " + ", ".join(sorted(expected - selected.keys())))
    counts = {}
    for group, lines in selected.items():
        seen = set()
        parsed = []
        for text in lines:
            if not isinstance(text, str) or "," not in text:
                raise RuleError("special rules must contain a predicate and value, no action")
            kind, value = text.split(",", 1)
            rule = normalize_rule(kind, value)
            if rule.text != text or text in seen:
                raise RuleError("noncanonical or duplicate special rule")
            seen.add(text)
            parsed.append(rule)
            if group == "special/realip":
                if rule.kind not in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
                    raise RuleError("RealIP accepts only supported exact, suffix or keyword domain rules")
                if value.endswith(("in-addr.arpa", "ip6.arpa")):
                    raise RuleError("reverse queries require client protocol handling, not A/AAAA exemptions")
            elif group == "special/lan":
                if rule.kind in IP_KINDS:
                    if not _inside(ipaddress.ip_network(value), LAN_NETWORKS):
                        raise RuleError("LAN contains an address outside private/local scope (including Fake IP)")
                elif rule.kind != "DOMAIN-SUFFIX" or value not in LOCAL_NAMES:
                    raise RuleError("LAN name is outside the verified standard local namespaces")
            elif rule.kind in IP_KINDS:
                allowed = tuple(ipaddress.ip_network(s) for s in IP_SCOPES.get(group, ()))
                if not _inside(ipaddress.ip_network(value), allowed):
                    raise RuleError(f"address outside the purpose of {group}")
            elif group in IP_SCOPES and group != "special/public-dns":
                raise RuleError("address-only special group contains a domain")
            elif group == "special/local-name-compat":
                if rule.kind != "DOMAIN-SUFFIX" or value not in {"lan", "localdomain"}:
                    raise RuleError("community local namespace exceeds maintained convention")
            # Other selected special service lists use the same supported
            # predicates as ordinary AirRoute lists; do not downgrade suffixes,
            # keywords or regexes to an invented exact-host requirement.
        counts[group] = len(lines)
    return {"groups": counts, "lan_safety": "private/local allowlist", "realip_safety": "supported-domain-only; address mode is independent of resolver and route"}


def _file(source: dict, relative: str | None = None) -> Path:
    root = Path(source["path"])
    if not relative or root.is_file():
        return root
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise RuleError("unsafe special source selector")
    return path


def _snapshot(source: dict, path: Path | None = None) -> dict:
    meta = {k: source[k] for k in ("id", "lineage", "version", "sha256", "fetched_at") if k in source}
    if path is not None and path.is_file():
        meta["selected_file_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return meta


def _parse_audit(source: dict, selector: dict, dlc: dict[str, DLC], *, trace=None) -> tuple[list[Rule], list[dict], dict]:
    sid = source["id"]
    if selector.get("category"):
        if sid not in dlc:
            dlc[sid] = DLC(source["path"], sid)
            if trace is not None:
                catalog = dlc[sid]
                trace.source_event(sid, "special-source-parse", "parsed",
                    read_lines=catalog.read_lines, parsed_records=catalog.parsed_records,
                    include_records=catalog.include_records, rejected_records=len(catalog.quarantined),
                    count_scope="special DLC parser source files read once, independently from domain-generation reads",
                    include_edges=catalog.include_edges)
                for item in catalog.quarantined:
                    trace.domain_event({"group": selector.get("group", "special/reference"), "source": item["source"],
                        "source_id": sid, "line": item["line"], "predicate": item["predicate"],
                        "stage": "source-parse", "status": "reject", "reason": item["reason"],
                        "scope": "source-wide; original file retained"})
        path = dlc[sid].root / selector["category"]
        return dlc[sid].expand(selector["category"]), [], _snapshot(source, path)
    path = _file(source, selector.get("path"))
    payload = path.read_text(encoding="utf-8")
    if trace is not None:
        trace.source_event(sid, "special-source-read", "read", read_lines=len(payload.splitlines()),
            selector=selector, input_file=selector.get("path", path.name),
            count_scope="physical lines read for this selector, not unique semantic predicates")
    rows, bad = parse_third_party(payload, selector.get("format", "surge"), sid,
                                 behavior=selector.get("behavior", "classical"))
    return rows, bad, _snapshot(source, path)


def _registry(source: dict, *, trace=None) -> dict[str, str]:
    text = _file(source).read_text(encoding="utf-8-sig")
    if trace is not None:
        trace.source_event(source["id"], "special-registry-read", "read", read_lines=len(text.splitlines()),
                           count_scope="physical CSV lines including header")
    rows = csv.DictReader(io.StringIO(text))
    if not rows.fieldnames or not {"Address Block", "Name"}.issubset(rows.fieldnames):
        raise RuleError("invalid IANA registry CSV columns")
    parsed = {}
    for row in rows:
        for prefix in row["Address Block"].split(","):
            prefix = re.sub(r"\s*\[[^]]*\]", "", prefix).strip()
            try:
                parsed[str(ipaddress.ip_network(prefix, strict=True))] = row["Name"]
            except ValueError as exc:
                raise RuleError("invalid IANA special-purpose prefix") from exc
    if not parsed:
        raise RuleError("empty IANA registry")
    return parsed


def build_special(sources: Iterable[dict], config=None, *, trace=None) -> tuple[dict[str, list[str]], dict]:
    config = load_special_config(config)
    by_id = {s["id"]: s for s in sources}
    prepared: dict[str, list[Rule]] = {}
    report = {"schema": 1, "configuration_version": config["version"], "catalogue": {}, "groups": {},
              "provenance": {}, "selectors": [], "selector_health": [], "excluded": [],
              "gaps": list(config.get("gaps", [])), "registry_checks": {},
              "network_activity": "none; frozen public data and maintained RFC/official records only"}
    evidence = config.get("evidence", {})
    def audit(gid, source, predicate, stage, status, reason, **extra):
        if trace is not None:
            trace.domain_event({"group": gid, "source": source, "source_id": source.split(":", 1)[0],
                                "predicate": predicate, "stage": stage, "status": status, "reason": reason, **extra})
    def source_audit(sid, stage, status, **extra):
        if trace is not None:
            trace.source_event(sid, stage, status, **extra)
    for group in config["groups"]:
        gid = group["id"]
        prepared[gid] = []
        report["provenance"][gid] = {}
        source_ids = set()
        for entry in group.get("entries", []):
            if not entry.get("reason") or not entry.get("evidence") or any(e not in evidence for e in entry["evidence"]):
                raise RuleError("special rule lacks a known evidence reference and reason")
            rule = normalize_rule(entry["kind"], entry["value"], source="maintained-special")
            prepared[gid].append(rule)
            source_ids.update(entry["evidence"])
            report["provenance"][gid].setdefault(rule.text, []).append({"reason": entry["reason"],
                "evidence": [{"id": e, **evidence[e]} for e in entry["evidence"]]})
            audit(gid, rule.source, rule.text, "maintained-configuration", "accept", entry["reason"],
                  configuration_version=config["version"], evidence=[{"id": e, **evidence[e]} for e in entry["evidence"]])
        report["catalogue"][gid] = {k: group[k] for k in ("name", "purpose", "content_types", "optional")}
        report["catalogue"][gid].update({"kind": "dns-address-mode" if gid == "special/realip" else "special-purpose", "source_ids": sorted(source_ids), "required_output": True})
    dlc = {}
    for selector in config.get("selectors", []):
        sid, gid = selector["source"], selector["group"]
        if sid not in by_id:
            source_audit(sid, "special-selector", "unavailable", group=gid, selector=selector)
            report["selector_health"].append({"group": gid, "source": sid, "selector": selector["category"], "status": "unavailable"})
            continue
        try:
            rows, bad, snapshot = _parse_audit(by_id[sid], selector, dlc, trace=trace)
        except (OSError, UnicodeError, RuleError) as exc:
            source_audit(sid, "special-selector", "failed", group=gid, selector=selector,
                         error_type=type(exc).__name__, error=str(exc))
            report["selector_health"].append({"group": gid, "source": sid, "selector": selector["category"], "status": "failed", "reason": str(exc)})
            continue
        accepted, rejected = 0, len(bad)
        source_audit(sid, "special-selector-parse", "parsed" if rows else "empty", group=gid,
                     selector=selector, parsed_records=len(rows), rejected_records=len(bad),
                     count_scope="selector predicates; repeated selector expansions are not unique physical records")
        for item in bad:
            audit(gid, item.get("source", sid), item.get("predicate", ""), "parse-normalize", "reject",
                  item["reason"], line=item.get("line", 0), selector=selector)
        for rule in rows:
            audit(gid, rule.source, rule.text, "parse-normalize", "accept", "semantics-preserved",
                  line=rule.line, selector=selector)
            if rule.kind in IP_KINDS and "ipv4" not in report["catalogue"][gid]["content_types"] and "ipv6" not in report["catalogue"][gid]["content_types"]:
                rejected += 1
                audit(gid, rule.source, rule.text, "scope", "excluded", "domain-only-purpose", line=rule.line, selector=selector)
                report["excluded"].append({"source":rule.source,"rule":rule.text,"reason":"domain-only-purpose"})
                continue
            prepared[gid].append(rule)
            proof = {"source": rule.source, "line": rule.line, "snapshot": snapshot,
                     "reason": f"classified {selector['role']} upstream rule; original predicate retained, no universal RealIP requirement"}
            report["provenance"][gid].setdefault(rule.text, []).append(proof)
            audit(gid, rule.source, rule.text, "scope", "accept", proof["reason"], line=rule.line,
                  selector=selector, snapshot=snapshot)
            accepted += 1
        report["catalogue"][gid]["source_ids"].append(sid)
        report["selectors"].append({"group": gid, "source": sid, "selector": selector["category"],
                                  "input_rules": len(rows), "accepted": accepted, "rejected": rejected, "snapshot": snapshot})
        report["selector_health"].append({"group": gid, "source": sid, "selector": selector["category"], "status": "available", "rules": accepted})
    local_index = CoverageIndex(prepared["special/lan"] + prepared["special/local-name-compat"])
    for selector in config.get("audit_inputs", []):
        sid = selector["source"]
        gid = "special/realip" if selector["purpose"] == "realip-compatibility" else "special/lan"
        if sid not in by_id:
            source_audit(sid, "special-reference-selector", "unavailable", group=gid, selector=selector)
            report["selector_health"].append({"source": sid, "selector": selector.get("path", selector.get("category")), "status": "unavailable"})
            continue
        try:
            rows, bad, snapshot = _parse_audit(by_id[sid], selector, dlc, trace=trace)
        except (OSError, UnicodeError, RuleError) as exc:
            source_audit(sid, "special-reference-selector", "failed", group=gid, selector=selector,
                         error_type=type(exc).__name__, error=str(exc))
            report["selector_health"].append({"source": sid, "status": "failed", "reason": str(exc)})
            continue
        reasons = {}
        source_audit(sid, "special-reference-parse", "parsed" if rows else "empty", group=gid,
                     selector=selector, parsed_records=len(rows), rejected_records=len(bad),
                     count_scope="selector predicates; repeated selector expansions are not unique physical records")
        for item in bad:
            audit(gid, item.get("source", sid), item.get("predicate", ""), "parse-normalize", "reject",
                  item["reason"], line=item.get("line", 0), selector=selector)
        report["excluded"].extend(bad[:max(0, 1000-len(report["excluded"]))])
        for rule in rows:
            reason = "outside-standard-or-selected-local-namespace"
            if selector["purpose"] == "realip-compatibility" and rule.kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"} and not rule.value.endswith(("in-addr.arpa", "ip6.arpa")):
                prepared["special/realip"].append(rule)
                report["provenance"]["special/realip"].setdefault(rule.text, []).append({
                    "source": sid, "snapshot": snapshot,
                    "reason": "mature upstream RealIP compatibility list; semantics retained, not independent evidence or a universal protocol requirement"})
                reason = "upstream-domain-compatibility"
            elif selector["purpose"] == "local-name-candidates" and local_index.covers(rule):
                reason = "already-covered-standard-or-opt-in-local-namespace"
            elif rule.kind in IP_KINDS:
                reason = "address-purpose-is-separated-not-a-generic-private-union"
            elif rule.value.endswith(("in-addr.arpa", "ip6.arpa")):
                reason = "reverse-query-handling-is-a-client-protocol-concern"
            elif selector["purpose"] == "realip-compatibility":
                reason = "predicate-not-expressible-by-RealIP-domain-matcher"
            reasons[reason] = reasons.get(reason, 0) + 1
            audit(gid, rule.source, rule.text, "reference-scope",
                  "accept" if reason.startswith("upstream-domain") else "covered" if reason.startswith("already-covered") else "excluded",
                  reason, line=rule.line, selector=selector, snapshot=snapshot)
            if not reason.startswith(("already-covered", "upstream-domain")) and len(report["excluded"]) < 1000:
                report["excluded"].append({"source": sid, "rule": rule.text, "reason": reason})
        report["selectors"].append({"source": sid, "selector": selector.get("path", selector.get("category")),
                                  "purpose": selector["purpose"], "input_rules": len(rows), "parse_rejected": len(bad),
                                  "decisions": reasons, "snapshot": snapshot})
        report["selector_health"].append({"source": sid, "status": "available", "rules": len(rows)})
    # A missing optional registry does not erase the fixed RFC baseline. A
    # present but incompatible registry fails rather than quietly changing LAN.
    for family, sid in ((4, "iana-special-v4"), (6, "iana-special-v6")):
        if sid not in by_id:
            source_audit(sid, "special-registry", "unavailable", reason="maintained RFC baseline retained")
            report["registry_checks"][sid] = {"status": "unavailable", "baseline": "maintained RFC records"}
            continue
        try:
            registry = _registry(by_id[sid], trace=trace)
        except (OSError, UnicodeError, RuleError) as exc:
            source_audit(sid, "special-registry-parse", "failed", error_type=type(exc).__name__, error=str(exc))
            raise
        source_audit(sid, "special-registry-parse", "parsed", parsed_records=len(registry),
                     count_scope="unique normalized registry prefixes; registry rows may contain multiple prefixes")
        prefixes = {r.value for gid, rows in prepared.items() for r in rows if r.kind in IP_KINDS and
                    ipaddress.ip_network(r.value).version == family and gid not in {"special/public-dns", "special/multicast"}}
        missing = sorted(prefixes - registry.keys())
        if missing:
            source_audit(sid, "special-registry-validation", "failed", missing_prefixes=missing)
            raise RuleError("maintained special prefixes absent from frozen IANA registry: " + ", ".join(missing))
        report["registry_checks"][sid] = {"status": "consistent", "checked_prefixes": len(prefixes), "snapshot": _snapshot(by_id[sid], _file(by_id[sid]))}
        source_audit(sid, "special-registry-validation", "consistent", checked_prefixes=len(prefixes))
    groups = {gid: [r.text for r in minimize(rows)] for gid, rows in prepared.items()}
    for gid, lines in groups.items():
        if trace is not None:
            witness = CompactionWitness(lines)
            seen = set()
            for rule in prepared[gid]:
                covering = witness.covering(rule)
                target_group = gid
                status = "output" if rule.text in witness.lines and rule.text not in seen else "covered"
                audit(gid, rule.source, rule.text, "compaction", status,
                      "retained-predicate" if status == "output" else "duplicate-predicate" if rule.text in seen else "semantically-covered",
                      covering_predicate=covering, covering_group=target_group, line=rule.line)
                seen.add(rule.text)
        reported_sources = {p["source"].split(":", 1)[0] for proofs in report["provenance"].get(gid, {}).values() for p in proofs if p.get("source")}
        report["catalogue"][gid]["source_ids"] = sorted(set(report["catalogue"][gid]["source_ids"]) | reported_sources)
        report["groups"][gid] = {"output_rules": len(lines), "accepted_before_compaction": len(prepared[gid]),
                                 "content_types": sorted({"ipv6" if s.startswith("IP-CIDR6,") else "ipv4" if s.startswith("IP-CIDR,") else "domain" for s in lines})}
    report["validation"] = validate_special_groups(groups, config, require_complete=True)
    report["configuration_sha256"] = hashlib.sha256(json.dumps(config, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return groups, report
