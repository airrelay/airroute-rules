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

from .domains import CoverageIndex, DLC, IP_KINDS, Rule, RuleError, minimize, normalize_rule, parse_third_party

DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "config" / "special.json"
LAN_NETWORKS = tuple(ipaddress.ip_network(s) for s in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "fc00::/7", "::1/128", "fe80::/10"))
LOCAL_NAMES = frozenset({"localhost", "local", "home.arpa"})
KNOWN_IDS = frozenset({"special/lan", "special/shared", "special/multicast", "special/broadcast",
    "special/benchmark", "special/documentation", "special/nat64", "special/local-name-compat",
    "special/connectivity", "special/ntp", "special/stun-turn", "special/software-update",
    "special/public-dns", "dns/realip", "dns/realip-optional"})
# A default DNS exemption is a protocol-specific exception, not a service list.
CORE_REALIP_EXACT = frozenset({"dns.msftncsi.com", "ipv4only.arpa"})
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
    """Recheck actual bytes independently of generation report/claimed metadata.

    Does not trust an upstream private list, product catalogue or caller report to
    authorize a new LAN subnet or broad DNS exception. Config can add provenance,
    but changing a safety scope requires an explicit code/test change as well.
    """
    selected = {g: rows for g, rows in groups.items() if g.startswith(("special/", "dns/"))}
    if set(selected) - KNOWN_IDS:
        raise RuleError("unknown special/DNS collection")
    if require_complete:
        expected = {g["id"] for g in load_special_config(config)["groups"]}
        if expected - selected.keys():
            raise RuleError("missing special/DNS collections: " + ", ".join(sorted(expected - selected.keys())))
    counts = {}
    for group, lines in selected.items():
        if not lines:
            raise RuleError(f"empty special collection: {group}")
        seen = set()
        parsed = []
        for text in lines:
            if not isinstance(text, str) or text.count(",") != 1:
                raise RuleError("special rules must contain exactly a predicate and value, no action")
            kind, value = text.split(",", 1)
            rule = normalize_rule(kind, value)
            if rule.text != text or text in seen:
                raise RuleError("noncanonical or duplicate special rule")
            seen.add(text)
            parsed.append(rule)
            if group.startswith("dns/"):
                if rule.kind not in {"DOMAIN", "DOMAIN-SUFFIX"}:
                    raise RuleError("Real IP lists accept only exact/suffix domain rules")
                if group == "dns/realip":
                    if not ((rule.kind == "DOMAIN-SUFFIX" and value in LOCAL_NAMES) or
                            (rule.kind == "DOMAIN" and value in CORE_REALIP_EXACT)):
                        raise RuleError("default Real IP exemption exceeds the verified protocol scope")
                elif rule.kind != "DOMAIN" or "." not in value:
                    raise RuleError("optional Real IP compatibility data must remain exact hosts")
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
            elif rule.kind != "DOMAIN" or "." not in value:
                raise RuleError("special endpoint groups contain exact documented hostnames only")
        # An allowlist prevents accidental expansion; mandatory coverage also
        # prevents a correctly rehashed but truncated baseline from publishing.
        # Compare IP unions, so an equivalent split into smaller CIDRs is valid.
        if group == "special/lan" or group in IP_SCOPES and group != "special/public-dns":
            required = LAN_NETWORKS if group == "special/lan" else tuple(ipaddress.ip_network(s) for s in IP_SCOPES[group])
            collapsed = [n for family in (4, 6) for n in ipaddress.collapse_addresses(
                ipaddress.ip_network(r.value) for r in parsed if r.kind in IP_KINDS and
                ipaddress.ip_network(r.value).version == family)]
            missing = [str(n) for n in required if not _inside(n, collapsed)]
            if missing:
                raise RuleError(f"{group} mandatory address coverage is missing: " + ", ".join(missing))
        if group in {"special/lan", "dns/realip"}:
            index = CoverageIndex(parsed)
            required = [normalize_rule("DOMAIN-SUFFIX", name) for name in LOCAL_NAMES]
            if group == "dns/realip":
                required.extend(normalize_rule("DOMAIN", name) for name in CORE_REALIP_EXACT)
            missing = sorted(r.text for r in required if not index.covers(r))
            if missing:
                raise RuleError(f"{group} mandatory domain coverage is missing: " + ", ".join(missing))
        counts[group] = len(lines)
    return {"groups": counts, "lan_safety": "private/local allowlist", "realip_safety": "domain-only, conservative core; optional exact-only"}


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


def _parse_audit(source: dict, selector: dict, dlc: dict[str, DLC]) -> tuple[list[Rule], list[dict], dict]:
    sid = source["id"]
    if selector.get("category"):
        if sid not in dlc:
            dlc[sid] = DLC(source["path"], sid)
        path = dlc[sid].root / selector["category"]
        return dlc[sid].expand(selector["category"]), [], _snapshot(source, path)
    path = _file(source, selector.get("path"))
    rows, bad = parse_third_party(path.read_text(encoding="utf-8"), selector.get("format", "surge"), sid,
                                 behavior=selector.get("behavior", "classical"))
    return rows, bad, _snapshot(source, path)


def _registry(source: dict) -> dict[str, str]:
    text = _file(source).read_text(encoding="utf-8-sig")
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


def build_special(sources: Iterable[dict], config=None) -> tuple[dict[str, list[str]], dict]:
    config = load_special_config(config)
    by_id = {s["id"]: s for s in sources}
    prepared: dict[str, list[Rule]] = {}
    report = {"schema": 1, "configuration_version": config["version"], "catalogue": {}, "groups": {},
              "provenance": {}, "selectors": [], "selector_health": [], "excluded": [],
              "gaps": list(config.get("gaps", [])), "registry_checks": {},
              "network_activity": "none; frozen public data and maintained RFC/official records only"}
    evidence = config.get("evidence", {})
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
        report["catalogue"][gid] = {k: group[k] for k in ("name", "purpose", "content_types", "optional", "minimum_rules")}
        report["catalogue"][gid].update({"kind": "dns-address-mode" if gid.startswith("dns/") else "special-purpose", "source_ids": sorted(source_ids), "required_output": True})
    dlc = {}
    for selector in config.get("selectors", []):
        sid, gid = selector["source"], selector["group"]
        if sid not in by_id:
            report["selector_health"].append({"group": gid, "source": sid, "selector": selector["category"], "status": "unavailable"})
            continue
        try:
            rows, bad, snapshot = _parse_audit(by_id[sid], selector, dlc)
        except (OSError, UnicodeError, RuleError) as exc:
            report["selector_health"].append({"group": gid, "source": sid, "selector": selector["category"], "status": "unavailable", "reason": str(exc)})
            continue
        accepted, rejected = 0, len(bad)
        for rule in rows:
            # A category name establishes endpoint role only. Broad roots,
            # keyword/regex and IP values are not promoted to DNS exceptions.
            if rule.kind != "DOMAIN":
                rejected += 1
                report["excluded"].append({"source": rule.source, "rule": rule.text, "reason": "role catalogue requires exact endpoint; suffix is not an equivalent host"})
                continue
            prepared[gid].append(rule)
            proof = {"source": rule.source, "line": rule.line, "snapshot": snapshot,
                     "reason": f"explicit {selector['role']} endpoint catalogue; no assertion that Real IP is universally required"}
            report["provenance"][gid].setdefault(rule.text, []).append(proof)
            accepted += 1
        report["catalogue"][gid]["source_ids"].append(sid)
        report["selectors"].append({"group": gid, "source": sid, "selector": selector["category"],
                                  "input_rules": len(rows), "accepted": accepted, "rejected": rejected, "snapshot": snapshot})
        report["selector_health"].append({"group": gid, "source": sid, "selector": selector["category"], "status": "available", "rules": accepted})
    role_exact = {r.text: gid for gid in ("special/ntp", "special/stun-turn") for r in prepared.get(gid, []) if r.kind == "DOMAIN"}
    local_index = CoverageIndex(prepared["special/lan"] + prepared["special/local-name-compat"])
    for selector in config.get("audit_inputs", []):
        sid = selector["source"]
        if sid not in by_id:
            report["selector_health"].append({"source": sid, "selector": selector.get("path", selector.get("category")), "status": "unavailable"})
            continue
        try:
            rows, bad, snapshot = _parse_audit(by_id[sid], selector, dlc)
        except (OSError, UnicodeError, RuleError) as exc:
            report["selector_health"].append({"source": sid, "status": "unavailable", "reason": str(exc)})
            continue
        reasons = {}
        report["excluded"].extend(bad[:max(0, 1000-len(report["excluded"]))])
        for rule in rows:
            reason = "no-specific-compatibility-or-local-purpose-evidence"
            if selector["purpose"] == "realip-compatibility" and rule.text in role_exact:
                # DustinWin explicitly derives from these same DLC catalogues;
                # this is traceable role selection, never an independent vote.
                prepared["dns/realip-optional"].append(rule)
                report["provenance"]["dns/realip-optional"].setdefault(rule.text, []).append({
                    "source": sid, "snapshot": snapshot, "role_catalogue": role_exact[rule.text],
                    "reason": "opt-in compatibility candidate also classified as an exact NTP/STUN endpoint; shared upstream, not independent corroboration"})
                reason = "optional-exact-endpoint-compatibility"
            elif selector["purpose"] == "local-name-candidates" and local_index.covers(rule):
                reason = "already-covered-standard-or-opt-in-local-namespace"
            elif rule.kind in IP_KINDS:
                reason = "address-purpose-is-separated-not-a-generic-private-union"
            elif rule.value.endswith(("in-addr.arpa", "ip6.arpa")):
                reason = "reverse-query-handling-is-a-client-protocol-concern"
            elif rule.kind != "DOMAIN":
                reason = "broad-suffix-keyword-or-regex-not-a-proven-endpoint-exception"
            reasons[reason] = reasons.get(reason, 0) + 1
            if not reason.startswith(("already-covered", "optional-exact")) and len(report["excluded"]) < 1000:
                report["excluded"].append({"source": sid, "rule": rule.text, "reason": reason})
        report["selectors"].append({"source": sid, "selector": selector.get("path", selector.get("category")),
                                  "purpose": selector["purpose"], "input_rules": len(rows), "parse_rejected": len(bad),
                                  "decisions": reasons, "snapshot": snapshot})
        report["selector_health"].append({"source": sid, "status": "available", "rules": len(rows)})
    # A missing optional registry does not erase the fixed RFC baseline. A
    # present but incompatible registry fails rather than quietly changing LAN.
    for family, sid in ((4, "iana-special-v4"), (6, "iana-special-v6")):
        if sid not in by_id:
            report["registry_checks"][sid] = {"status": "unavailable", "baseline": "maintained RFC records"}
            continue
        registry = _registry(by_id[sid])
        prefixes = {r.value for gid, rows in prepared.items() for r in rows if r.kind in IP_KINDS and
                    ipaddress.ip_network(r.value).version == family and gid not in {"special/public-dns", "special/multicast"}}
        missing = sorted(prefixes - registry.keys())
        if missing:
            raise RuleError("maintained special prefixes absent from frozen IANA registry: " + ", ".join(missing))
        report["registry_checks"][sid] = {"status": "consistent", "checked_prefixes": len(prefixes), "snapshot": _snapshot(by_id[sid], _file(by_id[sid]))}
    groups = {gid: [r.text for r in minimize(rows)] for gid, rows in prepared.items()}
    # Optional compatibility data need not repeat the conservative default set.
    core = CoverageIndex(prepared["dns/realip"])
    groups["dns/realip-optional"] = [line for line in groups["dns/realip-optional"] if not core.covers(normalize_rule(*line.split(",", 1)))]
    for gid, lines in groups.items():
        reported_sources = {p["source"].split(":", 1)[0] for proofs in report["provenance"].get(gid, {}).values() for p in proofs if p.get("source")}
        report["catalogue"][gid]["source_ids"] = sorted(set(report["catalogue"][gid]["source_ids"]) | reported_sources)
        report["groups"][gid] = {"output_rules": len(lines), "accepted_before_compaction": len(prepared[gid]),
                                 "content_types": sorted({"ipv6" if s.startswith("IP-CIDR6,") else "ipv4" if s.startswith("IP-CIDR,") else "domain" for s in lines})}
    report["validation"] = validate_special_groups(groups, config, require_complete=True)
    report["configuration_sha256"] = hashlib.sha256(json.dumps(config, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return groups, report
