"""Offline rule semantics and deliberately conservative product classification.

Only consumes frozen public files. No DNS, TLS, HTTP target or ownership probes.
The returned rule text is the subset accepted by AirRoute Core's Surge parser.
"""
from __future__ import annotations

from dataclasses import dataclass
from bisect import bisect_left
import ipaddress
import json
from pathlib import Path
import re
from typing import Iterable


class RuleError(ValueError):
    """A source predicate cannot safely be represented by this product."""


@dataclass(frozen=True)
class Rule:
    kind: str
    value: str
    attrs: frozenset[str] = frozenset()
    source: str = ""
    line: int = 0

    @property
    def text(self) -> str:
        return f"{self.kind},{self.value}"


DOMAIN_KINDS = frozenset({"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX"})
IP_KINDS = frozenset({"IP-CIDR", "IP-CIDR6"})


def _ascii_lower(value: str) -> str:
    return value.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))


def _domain(value: str) -> str:
    value = value.strip().rstrip(".")
    if not value or any(c in value for c in " ,\t\r\n/*?\\:@"):
        raise RuleError("invalid literal domain")
    # Core only trims and ASCII-lowercases; stdlib's IDNA2003 maps e.g. ß to
    # "ss", changing a modern IDNA hostname. Do not guess Unicode equivalence.
    if not value.isascii():
        raise RuleError("non-ASCII domain requires an agreed IDNA mapping; preserve ASCII/punycode input only")
    value = value.lower()
    if len(value) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in value.split(".")):
        raise RuleError("invalid DNS label")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise RuleError("IP address is not a service-domain identity")


def normalize_rule(kind: str, value: str, **kwargs) -> Rule:
    kind = kind.upper()
    if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
        value = _domain(value)
    elif kind == "DOMAIN-KEYWORD":
        value = _ascii_lower(value.strip())
        if not value or any(c in value for c in ",\r\n\t "):
            raise RuleError("invalid domain keyword")
    elif kind == "DOMAIN-REGEX":
        # Core lowercases ASCII regex literals. Refuse regex constructs accepted by
        # Python but not Rust regex; do not "repair" by broadening their matches.
        # Lowercasing an operator is not lowercasing a domain: \D becomes \d,
        # \B becomes \b and \A becomes \a. Reject these before Core normalization.
        if re.search(r"\\[A-Z]", value):
            raise RuleError("Core ASCII lowercase would change uppercase regex escape semantics")
        if _ascii_lower(value) != value:
            raise RuleError("Core ASCII lowercase would change case-sensitive regex literals/classes")
        if not value or any(c in value for c in ",\r\n") or len(value.encode()) > 16_384:
            raise RuleError("regex cannot be represented by Core CSV")
        if re.search(r"\\[1-9]|\\[kKgG]|\(\?(?:[=!<]|P[=<]|\(|>)|\(\*|\+\+|\*\+|\?\+|\}\+", value):
            raise RuleError("regex uses unsupported lookaround/backreference/atomic syntax")
        if "\\p{" in value or "\\P{" in value or "\\z" in value:
            # Supported by Rust but not Python's validator: explicit quarantine
            # until a common validator is used, never silently change the regex.
            raise RuleError("regex requires a validator not available in this build")
        try:
            re.compile(value)
        except re.error as exc:
            raise RuleError("invalid regex") from exc
    elif kind in IP_KINDS:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise RuleError("invalid IP prefix") from exc
        kind = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
        value = str(network)
    else:
        raise RuleError(f"unsupported predicate {kind}")
    return Rule(kind, value, **kwargs)


def _attribute_matches(attrs: frozenset[str], filters: Iterable[str]) -> bool:
    for flag in filters:
        flag = flag.removeprefix("@")
        if not flag:
            raise RuleError("empty attribute filter")
        if flag.startswith("-"):
            if flag[1:] in attrs:
                return False
        elif flag not in attrs:
            return False
    return True


class DLC:
    """Expand upstream include filters and affiliations without flattening attrs."""

    def __init__(self, path: str | Path, source: str = "dlc"):
        root = Path(path)
        self.root = root / "data" if (root / "data").is_dir() else root
        self.source = source
        self.items: dict[str, list[Rule | tuple[str, tuple[str, ...], int]]] = {}
        self.affiliations: dict[str, list[Rule]] = {}
        self.cache: dict[tuple[str, tuple[str, ...]], tuple[Rule, ...]] = {}
        self.include_edges: dict[str, list[dict]] = {}
        self.quarantined: list[dict] = []
        if not self.root.is_dir():
            raise RuleError("DLC data directory is missing")
        for file in sorted(self.root.iterdir()):
            if not file.is_file() or not re.fullmatch(r"[a-zA-Z0-9_!.-]+", file.name):
                continue
            rows: list[Rule | tuple[str, tuple[str, ...], int]] = []
            for number, raw in enumerate(file.read_text(encoding="utf-8").splitlines(), 1):
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                pieces = line.split()
                head, annotations = pieces[0], pieces[1:]
                try:
                    if head.startswith("include:"):
                        if any(not p.startswith("@") for p in annotations):
                            raise RuleError("include supports only attribute filters")
                        rows.append((head[8:], tuple(annotations), number))
                        self.include_edges.setdefault(file.name, []).append({"category": head[8:], "filters": annotations, "line": number})
                        continue
                    attrs = frozenset(p[1:] for p in annotations if p.startswith("@"))
                    affiliated = [p[1:] for p in annotations if p.startswith("&")]
                    if any(not p.startswith(("@", "&")) or len(p) == 1 for p in annotations):
                        raise RuleError("invalid attribute/affiliation")
                    if ":" in head:
                        tag, value = head.split(":", 1)
                    else:
                        tag, value = "domain", head
                    kinds = {"domain": "DOMAIN-SUFFIX", "full": "DOMAIN", "keyword": "DOMAIN-KEYWORD", "regexp": "DOMAIN-REGEX"}
                    if tag not in kinds:
                        raise RuleError(f"unknown DLC type {tag}")
                    rule = normalize_rule(kinds[tag], value, attrs=attrs, source=f"{source}:{file.name}", line=number)
                    for target in affiliated:
                        if not re.fullmatch(r"[a-zA-Z0-9_!.-]+", target):
                            raise RuleError("unsafe affiliation name")
                    rows.append(rule)
                    for target in affiliated:
                        self.affiliations.setdefault(target, []).append(rule)
                except RuleError as exc:
                    self.quarantined.append({"source": f"{source}:{file.name}", "line": number, "predicate": raw, "reason": str(exc)})
            self.items[file.name] = rows

    def expand(self, category: str, filters: Iterable[str] = (), trail: tuple[str, ...] = (), *,
               exclude_categories: Iterable[str] = ()) -> list[Rule]:
        if not re.fullmatch(r"[a-zA-Z0-9_!.-]+", category):
            raise RuleError("unsafe DLC include path")
        excluded = tuple(sorted(set(exclude_categories)))
        if category in excluded:
            return []
        if category in trail:
            raise RuleError("DLC include cycle: " + " -> ".join((*trail, category)))
        if category not in self.items and category not in self.affiliations:
            raise RuleError(f"DLC category missing: {category}")
        key = (category, excluded)
        if key not in self.cache:
            rules = list(self.affiliations.get(category, []))
            for row in self.items.get(category, []):
                if isinstance(row, Rule):
                    rules.append(row)
                else:
                    child, child_filters, _ = row
                    rules.extend(self.expand(child, child_filters, (*trail, category), exclude_categories=excluded))
            # Attributes survive expansion, and filters never become new flags.
            self.cache[key] = tuple(dict.fromkeys(rules))
        return [r for r in self.cache[key] if _attribute_matches(r.attrs, filters)]


def _quarantine(source: str, number: int, raw: str, reason: str) -> dict:
    return {"source": source, "line": number, "predicate": raw, "reason": reason}


def _v2ray_rule(value: str, source: str, number: int) -> Rule:
    if ":" in value:
        kind, value = value.split(":", 1)
        kinds = {"full": "DOMAIN", "domain": "DOMAIN-SUFFIX", "keyword": "DOMAIN-KEYWORD", "regexp": "DOMAIN-REGEX"}
        if kind not in kinds:
            raise RuleError("unresolved or unsupported V2Ray domain selector")
        return normalize_rule(kinds[kind], value, source=source, line=number)
    # V2Ray config's unprefixed domain entries are substrings; unlike DLC.
    return normalize_rule("DOMAIN-KEYWORD", value, source=source, line=number)


def parse_third_party(text: str, format: str, source: str = "source", *, behavior: str = "classical") -> tuple[list[Rule], list[dict]]:
    """Parse only independent OR predicates. Reject compound/implicit constraints."""
    rules: list[Rule] = []
    quarantine: list[dict] = []
    format = format.lower()
    if format == "v2ray" and text.lstrip().startswith(("{", "[")):
        try:
            payload = json.loads(text)
            if isinstance(payload, list):
                blocks = [{"domain": payload}]
            elif "routing" in payload:
                blocks = payload["routing"].get("rules", [])
            elif "rules" in payload:
                blocks = payload["rules"]
            elif "domains" in payload:
                blocks = [{"domain": payload["domains"]}]
            else:
                blocks = [payload]
            for number, block in enumerate(blocks, 1):
                if not isinstance(block, dict) or not isinstance(block.get("domain"), list):
                    raise RuleError("V2Ray block has no flat domain array")
                if set(block) - {"domain", "type", "outboundTag", "balancerTag", "ruleTag"}:
                    quarantine.append(_quarantine(source, number, json.dumps(block, sort_keys=True), "compound V2Ray field constraints cannot be flattened"))
                    continue
                if block.get("type", "field") != "field":
                    raise RuleError("unsupported V2Ray rule type")
                for entry in block["domain"]:
                    try:
                        rules.append(_v2ray_rule(entry, source, number))
                    except (RuleError, AttributeError, TypeError) as exc:
                        quarantine.append(_quarantine(source, number, str(entry), str(exc)))
            return rules, quarantine
        except (ValueError, TypeError, KeyError) as exc:
            return [], [_quarantine(source, 0, "", f"invalid V2Ray input: {exc}")]
    if format not in {"surge", "surge-domainset", "clash", "mihomo", "v2ray"}:
        raise RuleError(f"unsupported third-party format {format}")
    yaml_payload = False
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";", "//", "[")):
            continue
        try:
            if format in {"clash", "mihomo"}:
                if line == "payload:":
                    yaml_payload = True
                    continue
                if line.startswith("- "):
                    line = line[2:].strip()
                    if line.startswith('"'):
                        line = json.loads(line)
                    elif line.startswith("'") and line.endswith("'"):
                        line = line[1:-1].replace("''", "'")
                    elif line.startswith(("!", "&", "*", "|", ">", "{")):
                        # An unquoted *.example is valid domain text only outside
                        # a YAML payload; inside YAML '*' denotes an alias.
                        if yaml_payload:
                            raise RuleError("YAML aliases/tags/objects are unsupported")
                    elif " #" in line:
                        line = line.split(" #", 1)[0].rstrip()
                elif yaml_payload or line.endswith(":"):
                    raise RuleError("only a flat YAML payload array is supported")
            if format == "v2ray":
                rules.append(_v2ray_rule(line, source, number))
                continue
            if format == "surge-domainset":
                kind = "DOMAIN-SUFFIX" if line.startswith(".") else "DOMAIN"
                rules.append(normalize_rule(kind, line.lstrip("."), source=source, line=number))
                continue
            if format in {"clash", "mihomo"} and behavior == "domain":
                if line.startswith("+."):
                    rule = normalize_rule("DOMAIN-SUFFIX", line[2:], source=source, line=number)
                elif line.startswith("*.") and not any(c in line[2:] for c in "*?"):
                    domain = _domain(line[2:])
                    rule = normalize_rule("DOMAIN-REGEX", r"^.+\." + re.escape(domain) + "$", source=source, line=number)
                else:
                    rule = normalize_rule("DOMAIN", line, source=source, line=number)
                rules.append(rule)
                continue
            if format in {"clash", "mihomo"} and behavior == "ipcidr":
                rules.append(normalize_rule("IP-CIDR", line, source=source, line=number))
                continue
            pieces = [part.strip() for part in line.split(",")]
            if len(pieces) < 2:
                raise RuleError("type and payload required")
            kind, value = pieces[:2]
            kind = kind.upper()
            if kind in {"AND", "OR", "NOT", "SUB-RULE", "RULE-SET"}:
                raise RuleError("compound/reference predicate cannot be flattened")
            if kind == "DOMAIN-WILDCARD":
                raise RuleError("wildcard dialect is ambiguous; Core includes apex for *.suffix")
            if kind == "DOMAIN-REGEX" and len(pieces) != 2:
                raise RuleError("regex comma/policy cannot be disambiguated by Core CSV")
            if len(pieces) > 3 or any("=" in p for p in pieces[2:]):
                raise RuleError("unsupported rule modifiers/conditions")
            for extra in pieces[2:]:
                if extra.lower() == "no-resolve" and kind not in IP_KINDS:
                    raise RuleError("no-resolve on a non-IP rule")
                # A single policy target does not constrain the predicate and is
                # intentionally omitted: this repository never picks an exit.
            rules.append(normalize_rule(kind, value, source=source, line=number))
        except (RuleError, ValueError, TypeError) as exc:
            quarantine.append(_quarantine(source, number, raw, str(exc)))
    return rules, quarantine


def _covered_domain(value: str, suffixes: set[str]) -> bool:
    parts = value.split(".")
    return any(".".join(parts[i:]) in suffixes for i in range(len(parts)))


class CoverageIndex:
    """Prove predicate containment, never use text inequality as a coverage gap."""

    def __init__(self, rules: Iterable[Rule]):
        rules = list(rules)
        self.exact = {r.value for r in rules if r.kind == "DOMAIN"}
        self.suffix = {r.value for r in rules if r.kind == "DOMAIN-SUFFIX"}
        self.strict = {scope for r in rules if r.kind == "DOMAIN-REGEX"
                       and (scope := _strict_subdomain_suffix(r.value)) is not None}
        self.keywords = {r.value for r in rules if r.kind == "DOMAIN-KEYWORD"}
        self.regex = {r.value for r in rules if r.kind == "DOMAIN-REGEX"}

    def covers(self, rule: Rule) -> bool:
        value = rule.value
        if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
            if _covered_domain(value, self.suffix) or any(k in value for k in self.keywords):
                return True
            parent = value.partition(".")[2]
            if parent and _covered_domain(parent, self.strict):
                return True
            return rule.kind == "DOMAIN" and value in self.exact
        if rule.kind == "DOMAIN-KEYWORD":
            return any(k in value for k in self.keywords)
        if rule.kind == "DOMAIN-REGEX":
            scope = _strict_subdomain_suffix(value)
            return (value in self.regex or scope is not None and
                    (_covered_domain(scope, self.suffix | self.strict) or
                     any(k in scope for k in self.keywords)))
        return False


def _strict_subdomain_suffix(pattern: str) -> str | None:
    """Recognize only the exact strict-subdomain regex emitted by our adapters.

    This is not a general regex analyzer. The round trip prevents interpretation
    of alternative regex languages, unescaped metacharacters or extra branches.
    """
    prefix = r"^.+\."
    if not pattern.startswith(prefix) or not pattern.endswith("$"):
        return None
    escaped = pattern[len(prefix):-1]
    literal = escaped.replace(r"\.", ".").replace(r"\-", "-")
    try:
        normalized = _domain(literal)
    except RuleError:
        return None
    if "." not in normalized or literal != normalized or re.escape(normalized) != escaped:
        return None
    return normalized


def minimize(rules: Iterable[Rule]) -> list[Rule]:
    """Only remove predicates whose coverage is mathematically included."""
    unique: dict[tuple[str, str], Rule] = {}
    for rule in rules:
        unique.setdefault((rule.kind, rule.value), rule)
    suffixes = {v for k, v in unique if k == "DOMAIN-SUFFIX"}
    suffixes = {v for v in suffixes if not _covered_domain(v.partition(".")[2], suffixes)}
    strict = {scope for k, v in unique if k == "DOMAIN-REGEX"
              and (scope := _strict_subdomain_suffix(v)) is not None}
    keywords = sorted({v for k, v in unique if k == "DOMAIN-KEYWORD"}, key=lambda x: (len(x), x))
    short: list[str] = []
    for keyword in keywords:
        if not any(k in keyword for k in short):
            short.append(keyword)
    out: list[Rule] = []
    ips: dict[int, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {4: [], 6: []}
    for (kind, value), rule in unique.items():
        if kind in IP_KINDS:
            network = ipaddress.ip_network(value)
            ips[network.version].append(network)
        elif kind == "DOMAIN-SUFFIX":
            if (value in suffixes and not any(k in value for k in short)
                    and not _covered_domain(value.partition(".")[2], strict)):
                out.append(rule)
        elif kind == "DOMAIN":
            if (not _covered_domain(value, suffixes) and not any(k in value for k in short)
                    and not _covered_domain(value.partition(".")[2], strict)):
                out.append(rule)
        elif kind == "DOMAIN-KEYWORD":
            if value in short:
                out.append(rule)
        elif kind == "DOMAIN-REGEX" and (scope := _strict_subdomain_suffix(value)) is not None:
            if (not _covered_domain(scope, suffixes) and
                    not _covered_domain(scope.partition(".")[2], strict)):
                out.append(rule)
        else:
            out.append(rule)
    for version in (4, 6):
        for network in ipaddress.collapse_addresses(ips[version]):
            out.append(normalize_rule("IP-CIDR", str(network)))
    return sorted(out, key=lambda r: (r.kind not in DOMAIN_KINDS, r.kind, r.value))


class _CNIndex:
    def __init__(self, cn: list[Rule]):
        self.patterns = [r for r in cn if r.kind == "DOMAIN-KEYWORD" or
                         (r.kind == "DOMAIN-REGEX" and _strict_subdomain_suffix(r.value) is None)]
        self.exact = {r.value for r in cn if r.kind == "DOMAIN"}
        self.suffix = {r.value for r in cn if r.kind == "DOMAIN-SUFFIX"}
        self.strict = {scope for r in cn if r.kind == "DOMAIN-REGEX"
                       and (scope := _strict_subdomain_suffix(r.value)) is not None}
        self.reversed = sorted(".".join(v.split(".")[::-1]) for v in self.exact | self.suffix | self.strict)

    def _has_descendant(self, value: str) -> bool:
        prefix = ".".join(value.split(".")[::-1]) + "."
        at = bisect_left(self.reversed, prefix)
        return at < len(self.reversed) and self.reversed[at].startswith(prefix)

    def witnesses(self, rule: Rule, limit: int = 8) -> list[str]:
        value = _strict_subdomain_suffix(rule.value) if rule.kind == "DOMAIN-REGEX" else rule.value
        if not value or rule.kind not in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-REGEX"}:
            return ["nonliteral language requires explicit subtraction review"]
        values = []
        for pattern in self.patterns:
            if pattern.value in value if pattern.kind == "DOMAIN-KEYWORD" else re.search(pattern.value, value):
                values.append(pattern.text)
        parts = value.split(".")
        for i in range(len(parts)):
            name = ".".join(parts[i:])
            if name in self.suffix: values.append("DOMAIN-SUFFIX," + name)
            if i == 0 and name in self.exact: values.append("DOMAIN," + name)
            if i > 0 and name in self.strict: values.append("strict-subdomains:" + name)
        if rule.kind != "DOMAIN":
            prefix = ".".join(value.split(".")[::-1]) + "."
            at = bisect_left(self.reversed, prefix)
            for reversed_name in self.reversed[at:at + limit]:
                if not reversed_name.startswith(prefix): break
                name = ".".join(reversed_name.split(".")[::-1])
                if name in self.suffix: values.append("DOMAIN-SUFFIX," + name)
                elif name in self.exact: values.append("DOMAIN," + name)
                else: values.append("strict-subdomains:" + name)
        return sorted(set(values))[:limit]

    def overlaps(self, rule: Rule) -> bool:
        if self.patterns:
            if rule.kind == "DOMAIN":
                if any((p.value in rule.value if p.kind == "DOMAIN-KEYWORD" else re.search(p.value, rule.value)) for p in self.patterns):
                    return True
            else:
                # A suffix denotes all descendants: matching only its apex
                # cannot prove disjointness from an arbitrary keyword/regex.
                return True
        if rule.kind == "DOMAIN-REGEX" and (scope := _strict_subdomain_suffix(rule.value)) is not None:
            # The apex alone is outside this exact language. A CN suffix at or
            # above the scope, or any known CN descendant, does intersect it.
            return _covered_domain(scope, self.suffix | self.strict) or self._has_descendant(scope)
        if rule.kind not in {"DOMAIN", "DOMAIN-SUFFIX"}:
            # General regex/keywords require language subtraction, which .list
            # cannot express. Quarantine rather than relying on client ordering.
            return True
        if rule.value in self.exact or _covered_domain(rule.value, self.suffix):
            return True
        parent = rule.value.partition(".")[2]
        if parent and _covered_domain(parent, self.strict):
            return True
        if rule.kind == "DOMAIN-SUFFIX":
            prefix = ".".join(rule.value.split(".")[::-1])
            at = bisect_left(self.reversed, prefix)
            return at < len(self.reversed) and (self.reversed[at] == prefix or self.reversed[at].startswith(prefix + "."))
        return False


def load_products(path: str | Path) -> dict:
    path = Path(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    regional = path.with_name("regional-domains.json")
    if regional.is_file():
        fragment = json.loads(regional.read_text(encoding="utf-8"))
        if fragment.get("schema") != 1:
            raise RuleError("unsupported regional domain registry")
        replacements = {g["id"]: g for g in fragment.get("groups", [])}
        value["groups"] = [{**g, **replacements.pop(g["id"], {})} for g in value["groups"]]
        value["groups"].extend(replacements.values())
        value["regional_policy"] = {k: v for k, v in fragment.items() if k != "groups"}
    return _validate_products(value)


def _validate_products(value: dict) -> dict:
    if value.get("schema") != 1 or not isinstance(value.get("groups"), list):
        raise RuleError("invalid product registry")
    ids = [g.get("id") for g in value["groups"]]
    if len(ids) != len(set(ids)) or any(not isinstance(k, str) or not re.fullmatch(r"(?:region|provider|service|category)/[a-z0-9-]+", k) for k in ids):
        raise RuleError("invalid or duplicate product ID")
    if ids.count("region/cn") != 1:
        raise RuleError("exactly one public CN collection is required")
    for group in value["groups"]:
        if not isinstance(group.get("includes", []), list) or any(k not in ids for k in group.get("includes", [])):
            raise RuleError("product includes an unknown group")
    return value


def validate_domain_groups(groups: dict[str, list[str]], *, market_overlaps: dict | None = None,
                           unresolved_pattern_groups: Iterable[str] = ()) -> dict:
    """Recheck publication bytes, independently of the build's provenance report.

    Geo IP prefixes may coexist in region products; they are checked elsewhere
    against Geo. A manifest hash alone does not prove the CN exclusion invariant.
    """
    parsed: dict[str, list[Rule]] = {}
    for name, lines in groups.items():
        rules = []
        seen = set()
        for line in lines:
            if line.startswith("#") or not line.strip():
                continue
            pieces = line.split(",")
            if len(pieces) != 2:
                raise RuleError(f"noncanonical output predicate in {name}")
            rule = normalize_rule(*pieces)
            if rule.text != line:
                raise RuleError(f"nonnormalized output predicate in {name}")
            if (name.startswith(("region/", "provider/", "service/", "category/"))
                    and rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"} and "." not in rule.value):
                raise RuleError(f"top-level shortcut in {name}: {rule.text}")
            if rule.text in seen:
                raise RuleError(f"duplicate output predicate in {name}")
            seen.add(rule.text)
            rules.append(rule)
        parsed[name] = rules
    cn = [r for r in parsed.get("region/cn", []) if r.kind in DOMAIN_KINDS]
    if any(r.kind not in DOMAIN_KINDS or
           (r.kind in {"DOMAIN", "DOMAIN-SUFFIX"} and "." not in r.value) or
           (r.kind == "DOMAIN-REGEX" and re.search(r.value, "unrelated.example")) for r in cn):
        raise RuleError("CN output contains unbounded identity predicate")
    index = _CNIndex(cn)
    checked = 0
    declared = 0
    potential = 0
    unresolved_pattern_groups = set(unresolved_pattern_groups)
    allowed = {name: {d["predicate"] for d in entries if d.get("source") and d.get("reason")}
               for name, entries in (market_overlaps or {}).items()}
    for name, rows in parsed.items():
        if name == "region/cn" or not name.startswith(("region/", "provider/", "service/", "category/")):
            continue
        for rule in rows:
            if rule.kind in IP_KINDS:
                continue
            if index.overlaps(rule):
                if (name in unresolved_pattern_groups and index.patterns and not index.witnesses(rule)):
                    potential += 1
                elif rule.text in allowed.get(name, set()):
                    if rule.kind not in DOMAIN_KINDS:
                        raise RuleError("market overlap must be an explicitly classified domain predicate")
                    declared += 1
                else:
                    raise RuleError(f"CN/overseas domain overlap in {name}: {rule.text}")
            checked += 1
    return {"cn_domain_rules": len(cn), "overseas_domain_rules": checked, "cn_overlap": declared,
            "declared_market_overlaps": declared, "unresolved_pattern_intersections": potential, "priority": "none imposed by the data producer"}


def official_domains(data: object, source_id: str, selector: dict) -> tuple[list[Rule], list[dict]]:
    """Service endpoint catalogues, not all dependencies in an allowlist."""
    endpoints = []
    adapter = selector.get("adapter")
    if adapter == "microsoft365":
        if not isinstance(data, list):
            raise RuleError("Microsoft365 endpoint snapshot must be an array")
        for number, entry in enumerate(data, 1):
            if not isinstance(entry, dict) or not isinstance(entry.get("urls", []), list):
                raise RuleError("invalid Microsoft365 endpoint record")
            if entry.get("serviceArea") in selector.get("service_areas", ["Common", "Exchange", "SharePoint", "Skype"]):
                endpoints.extend((number, entry.get("id"), i, d)
                                 for i, d in enumerate(entry.get("urls", []), 1))
    elif adapter == "github-meta":
        if not isinstance(data, dict) or not isinstance(data.get("domains"), dict):
            raise RuleError("GitHub meta snapshot needs a domain catalogue")
        for category in selector.get("categories", []):
            entries = data["domains"].get(category)
            if not isinstance(entries, list):
                raise RuleError("GitHub meta domain category missing")
            endpoints.extend((i, category, i, d) for i, d in enumerate(entries, 1))
    else:
        raise RuleError("unconfigured official endpoint schema")
    rows, rejected = [], []
    for number, record_id, index, value in endpoints:
        try:
            if not isinstance(value, str):
                raise RuleError("official endpoint URL must be text")
            domain = _domain(value[2:] if value.startswith("*.") else value)
            if _covered_domain(domain, set(selector.get("dependency_roots", []))):
                raise RuleError("certificate/shared dependency is not service ownership")
            if (suffix := selector.get("regional_suffix")) and not domain.endswith(suffix):
                raise RuleError("common dependency is not a region-specific endpoint")
            # Official connectivity allowlists also list wildcard shared cloud
            # providers. They are dependencies, not exclusive GitHub identity.
            if (roots := selector.get("owned_roots")) and not _covered_domain(domain, set(roots)):
                if value.startswith("*.") or not selector.get("allow_exact_dependencies", False):
                    raise RuleError("shared provider/dependency is not exclusive service identity")
            kind, payload = ("DOMAIN-REGEX", r"^.+\." + re.escape(domain) + "$") if value.startswith("*.") else ("DOMAIN", domain)
            rows.append(normalize_rule(kind, payload, source=source_id, line=number))
        except RuleError as exc:
            rejected.append({**_quarantine(source_id, number, str(value), str(exc)),
                             "record_id": record_id, "endpoint_index": index})
    return rows, rejected


def build_domains(sources: list[dict], products: dict | str | Path) -> tuple[dict[str, list[str]], dict]:
    return _build_domains(sources, products)


def _build_domains(sources: list[dict], products: dict | str | Path) -> tuple[dict[str, list[str]], dict]:
    """Build products from frozen descriptors; paths may point to files or trees.

    Selectors bind frozen source classifications and preserve matching scope.
    Purpose-scoped mature community sources introduce new predicates directly.
    Only explicit scope exceptions and unsupported syntax are excluded.
    """
    products = _validate_products(products) if isinstance(products, dict) else load_products(products)
    source_ids = [s["id"] for s in sources]
    if len(source_ids) != len(set(source_ids)):
        raise RuleError("duplicate domain source ID")
    by_id = {s["id"]: s for s in sources if s.get("path") and s.get("status", "available") in {"available", "ok", "downloaded"}}
    dlc: dict[str, DLC] = {}
    prepared: dict[str, list[Rule]] = {}
    official_ip_sources: dict[str, set[str]] = {}
    report: dict = {"quarantined": [], "unavailable_selectors": [], "groups": {}, "cn_overlap_removed": [], "provenance": {}, "selectors": [],
                    "decisions": {}, "stage_records": 0, "dlc_includes": {}, "market_conflicts": [],
                    "sources": [{k: s[k] for k in ("id", "status", "version", "sha256", "lineage", "domain_role", "format") if k in s} for s in sources]}
    def audit(group, selector, rule, stage, status, reason, **extra):
        sid = selector.get("source", rule.source.split(":", 1)[0])
        key = selector.get("category", selector.get("path", selector.get("adapter", "membership")))
        item = {"group": group, "source": rule.source, "line": rule.line, "predicate": rule.text,
                "selector": key, "stage": stage, "status": status, "reason": reason, **extra}
        bucket = report["decisions"].setdefault(group, {}).setdefault(sid + ":" + str(key), {}).setdefault(stage, {})
        counted = bucket.setdefault(status + ":" + reason, {"count": 0, "samples": []})
        counted["count"] += 1
        if len(counted["samples"]) < 12:
            counted["samples"].append(item)
        report["stage_records"] += 1
    def quarantine(item):
        key = item.get("source", "unknown") + ":" + item["reason"]
        counts = report.setdefault("quarantine_counts", {})
        counts[key] = counts.get(key, 0) + 1
        if counts[key] <= 12:
            report["quarantined"].append(item)
    # Selector provenance remains available after memberships and compaction.
    origins: dict[tuple[str, str, int, str], list[dict]] = {}
    def mark_origin(group, selector, row):
        origins.setdefault((group, row.source, row.line, row.text), []).append(selector)
    for group in products.get("groups", []):
        name = group["id"]
        accepted: list[Rule] = []
        for selector in group.get("selectors", []):
            source_id = selector["source"]
            source = by_id.get(source_id)
            if source is None:
                if selector.get("required", False):
                    raise RuleError(f"required selector {name}/{source_id}: source unavailable")
                report["unavailable_selectors"].append({"group": name, "source": source_id, "reason": "source unavailable"})
                continue
            try:
                rejected = []
                format = selector.get("format", source.get("format", "surge"))
                if format == "dlc":
                    if source_id not in dlc:
                        dlc[source_id] = DLC(source["path"], source_id)
                        for bad in dlc[source_id].quarantined:
                            quarantine(bad)
                            audit(name, selector, Rule("UNSUPPORTED", bad["predicate"], source=bad["source"], line=bad["line"]),
                                  "source-parse", "reject", bad["reason"], scope="source-wide; original file retained")
                        report["dlc_includes"][source_id] = dlc[source_id].include_edges
                    for category in selector.get("exclude_categories", []):
                        if category in dlc[source_id].items:
                            for excluded_row in dlc[source_id].expand(category):
                                audit(name, selector, excluded_row, "include", "filtered", "excluded-include-subtree", category=category)
                    expanded = dlc[source_id].expand(selector["category"], exclude_categories=selector.get("exclude_categories", []))
                    rows = []
                    for row in expanded:
                        keep = _attribute_matches(row.attrs, selector.get("attributes", []))
                        audit(name, selector, row, "include-and-attributes", "accept" if keep else "filtered",
                              "include-expanded" if keep else "attribute-filter", attributes=sorted(row.attrs),
                              excluded_categories=selector.get("exclude_categories", []))
                        if keep: rows.append(row)
                elif format == "official-json":
                    path = Path(source["path"])
                    data = json.loads(path.read_text(encoding="utf-8"))
                    rows, rejected = official_domains(data, source_id, selector)
                elif format == "official-cidr":
                    if source.get("service") != name or not selector.get("official_service_ips"):
                        raise RuleError("official IP catalogue is not scoped to this product")
                    rows = [normalize_rule("IP-CIDR", line.strip(), source=source_id, line=i)
                            for i, line in enumerate(Path(source["path"]).read_text().splitlines(), 1)
                            if line.strip() and not line.startswith("#")]
                    official_ip_sources.setdefault(name, set()).add(source_id)
                else:
                    path = Path(source["path"])
                    if selector.get("path"):
                        relative = Path(selector["path"])
                        if relative.is_absolute() or ".." in relative.parts:
                            raise RuleError("unsafe selector path")
                        path = path / relative if path.is_dir() else path
                    rows, rejected = parse_third_party(path.read_text(encoding="utf-8"), format, f"{source_id}:{selector.get('path', path.name)}", behavior=selector.get("behavior", "classical"))
                for bad in rejected:
                    quarantine(bad)
                    audit(name, selector, Rule("UNSUPPORTED", bad["predicate"], source=bad["source"], line=bad["line"]),
                          "parse-normalize", "reject", bad["reason"])
                for row in rows:
                    audit(name, selector, row, "parse-normalize", "accept", "semantics-preserved", attributes=sorted(row.attrs))
                    mark_origin(name, selector, row)
                # A curated service list can be a primary identity assertion;
                # it need not get a second vote from its own upstream mirror.
                # Its declared match scope is still enforced, especially for
                # shared cloud/CDN parents and compound predicates.
                scoped = []
                excluded = _CNIndex([normalize_rule("DOMAIN-SUFFIX", root) for root in selector.get("exclude_roots", [])]) if selector.get("exclude_roots") else None
                owned = CoverageIndex(normalize_rule("DOMAIN-SUFFIX", root) for root in selector.get("owned_roots", [])) if selector.get("owned_roots") and format != "official-json" else None
                for row in rows:
                    reason = None
                    if row.text in group.get("exclude_predicates", []) or row.text in selector.get("exclude_predicates", []):
                        reason = "explicit-predicate-exclusion"
                    elif selector.get("domain_only") and row.kind not in DOMAIN_KINDS:
                        reason = "selector admits domain identities only"
                    elif selector.get("bounded_service") and (row.kind not in {"DOMAIN", "DOMAIN-SUFFIX"} or "." not in row.value):
                        reason = "curated service selector requires bounded literal domains"
                    elif owned is not None and not owned.covers(row):
                        reason = "outside configured service-owned roots"
                    elif excluded is not None and excluded.overlaps(row):
                        reason = "overlaps shared infrastructure or excluded service scope"
                    if reason:
                        quarantine(_quarantine(row.source, row.line, row.text, reason))
                        audit(name, selector, row, "scope", "excluded", reason)
                    elif row.value in group.get("shared_roots", []) + selector.get("shared_roots", []) and row.kind != "DOMAIN":
                        quarantine(_quarantine(row.source, row.line, row.text, "shared-parent-needs-precise-endpoint"))
                        audit(name, selector, row, "scope", "pending", "shared-parent-needs-precise-endpoint")
                    else:
                        scoped.append(row)
                        audit(name, selector, row, "scope", "accept", "selector-scope")
                prior = CoverageIndex(accepted)
                report["selectors"].append({"group": name, "source": source_id,
                    "selector": selector.get("category", selector.get("path", selector.get("adapter", format))),
                    "mode": selector.get("mode", "primary"), "lineage": source.get("lineage", source_id),
                    "input_rules": len(rows), "scope_admitted": len(scoped),
                    "scope_rejected": len(rows) - len(scoped), "already_covered": sum(prior.covers(r) for r in scoped)})
                rows = scoped
                if selector.get("required") and not rows:
                    raise RuleError("required selector has no usable predicates")
                accepted.extend(rows)
            except (RuleError, OSError, UnicodeError, json.JSONDecodeError) as exc:
                if selector.get("required", False):
                    raise RuleError(f"required selector {name}/{source_id}: {exc}") from exc
                reason = f"input unavailable ({type(exc).__name__})" if isinstance(exc, (OSError, UnicodeError)) else str(exc)
                report["unavailable_selectors"].append({"group": name, "source": source_id, "selector": selector.get("category", selector.get("path")), "reason": reason})
        prepared[name] = accepted
    # Resolve memberships after all selectors/references, before the same CN
    # exclusion is applied to both services and their containing categories.
    definitions = {g["id"]: g for g in products["groups"]}
    resolved = set()
    def include(name: str, trail: tuple[str, ...] = ()) -> None:
        if name in trail:
            raise RuleError("product include cycle: " + " -> ".join((*trail, name)))
        if name in resolved:
            return
        for child in definitions[name].get("includes", []):
            include(child, (*trail, name))
            for row in prepared[child]:
                audit(name, {"source": row.source.split(":", 1)[0]}, row, "membership", "accept", "included-product", child=child)
            prepared[name].extend(prepared[child])
            official_ip_sources.setdefault(name, set()).update(official_ip_sources.get(child, set()))
        resolved.add(name)
    for name in definitions:
        include(name)
    cn: list[Rule] = []
    for rule in prepared.get("region/cn", []):
        if rule.kind not in DOMAIN_KINDS or (rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"} and "." not in rule.value):
            quarantine(_quarantine(rule.source, rule.line, rule.text, "not a named domain predicate; IP geography is generated separately"))
        elif rule.kind == "DOMAIN-REGEX" and re.search(rule.value, "unrelated.example"):
            quarantine(_quarantine(rule.source, rule.line, rule.text, "regional regex matches unrelated negative control"))
        elif rule.kind == "DOMAIN-KEYWORD" and rule.value in {"cn", "china", "ru", "russia"}:
            quarantine(_quarantine(rule.source, rule.line, rule.text, "country-name keyword is not a service scope"))
        elif "!cn" in rule.attrs:
            quarantine(_quarantine(rule.source, rule.line, rule.text, "source explicitly marks non-CN service"))
        else:
            cn.append(rule)
    prepared["region/cn"] = cn
    cn_index = _CNIndex(cn)
    # A domestic-access list can contain international service endpoints. Its
    # inclusion is not a claim that an entire international product is CN-only.
    # DLC's named CN classifications remain the exclusion anchor; no published
    # output or external identity lookup is needed to admit new CN rules.
    cn_named = CoverageIndex(r for r in cn if r.source.startswith("dlc:"))
    market_policy = products.get("policy", {}).get("cn_exclusion") == "named-mainland-services; report mixed-market overlaps"
    declarations = {g["id"]: g["cn_market_overlaps"] for g in products["groups"] if g.get("cn_market_overlaps")}
    report["market_overlap_declarations"] = declarations
    report["unresolved_pattern_intersections"] = {}
    groups: dict[str, list[str]] = {}
    for group in products.get("groups", []):
        name = group["id"]
        rows = prepared[name]
        if name != "region/cn":
            kept = []
            for rule in rows:
                if rule.kind in IP_KINDS and rule.source not in official_ip_sources.get(name, set()):
                    quarantine(_quarantine(rule.source, rule.line, rule.text, "third-party service IP/ASN does not establish exclusive service identity"))
                elif rule.kind in IP_KINDS:
                    kept.append(rule)
                elif "." not in rule.value and rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
                    quarantine(_quarantine(rule.source, rule.line, rule.text, "TLD alone is not service identity"))
                elif cn_index.overlaps(rule):
                    declared = next((d for d in declarations.get(name, []) if d.get("predicate") == rule.text
                                     and d.get("source") == rule.source and d.get("reason")), None)
                    witnesses = cn_index.witnesses(rule)
                    if declared is None and market_policy and not cn_named.covers(rule) and cn_index.patterns and not witnesses:
                        kept.append(rule)
                        uncertain = report["unresolved_pattern_intersections"].setdefault(name, {"count": 0, "samples": [],
                            "meaning": "CN keyword/regex versus an infinite suffix/pattern language; no disjointness proof. Upstream predicates are retained unchanged, with no inferred priority."})
                        uncertain["count"] += 1
                        if len(uncertain["samples"]) < 12: uncertain["samples"].append(rule.text)
                        continue
                    if declared is None and market_policy and not cn_named.covers(rule):
                        declared = {"predicate": rule.text, "source": rule.source,
                            "reason": "Domestic-access coverage overlaps an explicitly classified international service. Preserve its original predicate; this is not a mainland-only identity or an implicit rule priority."}
                        entries = declarations.setdefault(name, [])
                        if declared not in entries: entries.append(declared)
                    item = {"group": name, "predicate": rule.text, "source": rule.source,
                            "reason": declared["reason"] if declared else "CN overlap or non-subtractable predicate",
                            "cn_witnesses": witnesses}
                    if declared:
                        kept.append(rule)
                        item["status"] = "unresolved-positive-overlap"
                        item["priority"] = "none; consumer must choose policy"
                        report["market_conflicts"].append(item)
                    else:
                        item["status"] = "pending-nonsubtractable-overlap"
                        report["cn_overlap_removed"].append(item)
                    audit(name, {"source": rule.source.split(":", 1)[0]}, rule, "cross-market",
                          "retained-conflict" if declared else "pending", item["reason"], cn_witnesses=item["cn_witnesses"])
                else:
                    kept.append(rule)
            rows = kept
        report["groups"][name] = {"accepted_before_compaction": len(rows), "selector_count": len(group.get("selectors", []))}
        for rule in rows:
            report["provenance"].setdefault(name, {}).setdefault(rule.text, []).append({"source": rule.source, "line": rule.line, "attributes": sorted(rule.attrs)})
        groups[name] = [r.text for r in minimize(rows)]
        output_set = set(groups[name])
        seen_rows = set()
        for row in rows:
            status = "output" if row.text in output_set and row.text not in seen_rows else "covered"
            reason = "retained-predicate" if status == "output" else "duplicate-predicate" if row.text in seen_rows else "semantically-covered"
            for selector in origins.get((name, row.source, row.line, row.text), [{"source": row.source.split(":", 1)[0]}]):
                audit(name, selector, row, "compaction", status, reason)
            seen_rows.add(row.text)
        if group.get("required_output") and not groups[name]:
            raise RuleError(f"required product has no accepted rules: {name}")
        report["groups"][name]["output_rules"] = len(groups[name])
        support = {}
        for rule in rows:
            sid = rule.source.split(":", 1)[0]
            support.setdefault(sid, set()).add(rule.text)
        report["groups"][name]["source_support_rules"] = {sid: len(values) for sid, values in sorted(support.items())}
        report["groups"][name]["support_note"] = "Overlapping support is not additive contribution or independent votes."

    report["raw_accepted_rules"] = sum(v["accepted_before_compaction"] for v in report["groups"].values())
    report["sample_limit_per_source_reason"] = 12
    report["output_rules"] = sum(map(len, groups.values()))
    report["memberships"] = {g["id"]: g["includes"] for g in products["groups"] if g.get("includes")}
    report["exclusion_validation"] = validate_domain_groups(groups, market_overlaps=declarations,
        unresolved_pattern_groups=report["unresolved_pattern_intersections"])
    return groups, report
