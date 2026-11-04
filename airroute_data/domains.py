"""Offline conversion and merging of configured upstream rule classifications.

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
    removed_modifiers: tuple[str, ...] = ()
    source_details: tuple[tuple[str, object], ...] = ()

    @property
    def text(self) -> str:
        return f"{self.kind},{self.value}"


DOMAIN_KINDS = frozenset({"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX"})
IP_KINDS = frozenset({"IP-CIDR", "IP-CIDR6"})
NON_IP_KINDS = DOMAIN_KINDS | frozenset({"PROCESS-NAME", "IP-ASN"})


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


def _regex_safe_shorthands(value: str) -> str:
    r"""Spell uppercase negated classes without Core changing their operators.

    Rust regex treats \S and [^\s] identically (also \D/\W). Only
    rewrite outside classes; nested class algebra is deliberately not guessed.
    """
    out = []
    inside = first = False
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            escaped = value[index + 1]
            out.append("[^\\" + escaped.lower() + "]" if not inside and escaped in "DSW" else value[index:index + 2])
            if inside: first = False
            index += 2
            continue
        out.append(char)
        if char == "[" and not inside:
            inside = first = True
        elif inside:
            if char == "]" and not first:
                inside = False
            elif not (char == "^" and first):
                first = False
        index += 1
    return "".join(out)


def normalize_rule(kind: str, value: str, **kwargs) -> Rule:
    kind = kind.upper()
    if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
        value = _domain(value)
    elif kind == "DOMAIN-KEYWORD":
        value = _ascii_lower(value.strip())
        if not value or any(c in value for c in ",\r\n\t "):
            raise RuleError("invalid domain keyword")
    elif kind == "DOMAIN-REGEX":
        original_regex = value
        value = _regex_safe_shorthands(value)
        if value != original_regex:
            kwargs["source_details"] = (*kwargs.get("source_details", ()),
                ("original_regex", original_regex), ("conversion", "negated-shorthand-to-lowercase-safe-class"))
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
    elif kind == "IP-ASN":
        if not value.strip().isascii() or not value.strip().isdigit() or not 0 <= int(value.strip()) < 2**32:
            raise RuleError("invalid ASN predicate")
        value = str(int(value.strip()))
    elif kind == "PROCESS-NAME":
        value = value.strip()
        if not value or any(c in value for c in ",\r\n\0"):
            raise RuleError("invalid process-name predicate")
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


def parse_rule_line(line: str) -> Rule:
    """Parse modifier-free canonical AirRoute output."""
    parts = line.split(",")
    if len(parts) != 2:
        raise RuleError("invalid output predicate fields; generated rules do not carry modifiers")
    return normalize_rule(parts[0], parts[1])


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
        # Diagnostic counters are source reads, not expanded selector copies.
        self.read_lines = self.parsed_records = self.include_records = 0
        if not self.root.is_dir():
            raise RuleError("DLC data directory is missing")
        for file in sorted(self.root.iterdir()):
            if not file.is_file() or not re.fullmatch(r"[a-zA-Z0-9_!.-]+", file.name):
                continue
            rows: list[Rule | tuple[str, tuple[str, ...], int]] = []
            lines = file.read_text(encoding="utf-8").splitlines()
            self.read_lines += len(lines)
            for number, raw in enumerate(lines, 1):
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
                        self.include_records += 1
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
                    self.parsed_records += 1
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
            if len(pieces) > 4 or any("=" in p for p in pieces[2:]):
                raise RuleError("unsupported rule modifiers/conditions")
            no_resolve = False
            policy = None
            for extra in pieces[2:]:
                if extra.lower() == "no-resolve":
                    if kind not in IP_KINDS | {"IP-ASN"}:
                        raise RuleError("no-resolve on a non-IP rule")
                    no_resolve = True
                elif policy is None:
                    # Exit actions are intentionally not imposed by a product.
                    policy = extra
                else:
                    raise RuleError("multiple policy targets or unknown modifiers")
            rules.append(normalize_rule(kind, value, removed_modifiers=("no-resolve",) if no_resolve else (), source=source, line=number))
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
        self.predicates = {r.text for r in rules}
        self.exact = {r.value for r in rules if r.kind == "DOMAIN"}
        self.suffix = {r.value for r in rules if r.kind == "DOMAIN-SUFFIX"}
        self.strict = {scope for r in rules if r.kind == "DOMAIN-REGEX"
                       and (scope := _strict_subdomain_suffix(r.value)) is not None}
        self.keywords = {r.value for r in rules if r.kind == "DOMAIN-KEYWORD"}
        self.regex = {r.value for r in rules if r.kind == "DOMAIN-REGEX"}

    def covers(self, rule: Rule) -> bool:
        if rule.text in self.predicates:
            return True
        value = rule.value
        if rule.kind in IP_KINDS:
            network = ipaddress.ip_network(value)
            return any(f"{rule.kind},{network.supernet(new_prefix=length)}" in self.predicates
                       for length in range(network.prefixlen - 1, -1, -1))
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
    ips: dict[int, list] = {4: [], 6: []}
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
    for version, networks in ips.items():
        for network in ipaddress.collapse_addresses(networks):
            out.append(normalize_rule("IP-CIDR", str(network)))
    return sorted(out, key=lambda r: (r.kind not in DOMAIN_KINDS, r.kind, r.value))


class CompactionWitness:
    """Bounded lookup of a final predicate that covers an original rule.

    This describes the existing minimizer; it never decides admission. In
    particular, arbitrary regex containment is not inferred from a host sample.
    """
    def __init__(self, lines: Iterable[str]):
        self.lines = set(lines)
        self.suffix = {v for line in self.lines for k, _, v in [line.partition(",")] if k == "DOMAIN-SUFFIX"}
        self.keywords = sorted(v for line in self.lines for k, _, v in [line.partition(",")] if k == "DOMAIN-KEYWORD")
        self.strict = {scope: line for line in self.lines for k, _, v in [line.partition(",")]
                       if k == "DOMAIN-REGEX" and (scope := _strict_subdomain_suffix(v)) is not None}

    def covering(self, rule: Rule) -> str | None:
        if rule.text in self.lines:
            return rule.text
        value = rule.value
        if rule.kind in IP_KINDS:
            network = ipaddress.ip_network(value)
            kind = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
            for length in range(network.prefixlen - 1, -1, -1):
                text = f"{kind},{network.supernet(new_prefix=length)}"
                if text in self.lines:
                    return text
            return None
        strict = _strict_subdomain_suffix(value) if rule.kind == "DOMAIN-REGEX" else None
        if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"} or strict is not None:
            value = strict or value
            parts = value.split(".")
            for i in range(len(parts)):
                parent = ".".join(parts[i:])
                if parent in self.suffix:
                    return "DOMAIN-SUFFIX," + parent
                if i > 0 and parent in self.strict:
                    return self.strict[parent]
        if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
            for keyword in self.keywords:
                if keyword in value:
                    return "DOMAIN-KEYWORD," + keyword
        return None



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
    if len(ids) != len(set(ids)) or any(not isinstance(k, str) or not re.fullmatch(r"(?:region|provider|category|special)/[a-z0-9-]+", k) for k in ids):
        raise RuleError("invalid or duplicate product ID")
    if ids.count("region/cn-domain") != 1:
        raise RuleError("exactly one CN non-IP collection is required")
    for group in value["groups"]:
        if not isinstance(group.get("includes", []), list) or any(k not in ids for k in group.get("includes", [])):
            raise RuleError("product includes an unknown group")
    return value


def validate_domain_groups(groups: dict[str, list[str]]) -> dict:
    """Validate canonical predicates and product types, never identity/overlap."""
    counts = {}
    for name, lines in groups.items():
        if not re.fullmatch(r"(?:region|category|provider|special)/[a-z0-9-]+", name):
            raise RuleError(f"invalid product ID: {name}")
        seen = set()
        for line in lines:
            if line.startswith("#") or not line.strip():
                continue
            rule = parse_rule_line(line)
            if rule.text != line:
                raise RuleError(f"nonnormalized output predicate in {name}")
            if rule.text in seen:
                raise RuleError(f"duplicate output predicate in {name}")
            if name.startswith("region/"):
                if name == "region/cn-domain" and rule.kind not in NON_IP_KINDS:
                    raise RuleError("CN non-IP output contains an IP predicate")
                if name != "region/cn-domain" and rule.kind not in IP_KINDS:
                    raise RuleError(f"IP-only region contains a non-IP predicate: {name}")
            seen.add(rule.text)
        counts[name] = len(seen)
    return {"rules": counts, "overlap_policy": "Collections may overlap; no routing action or implicit priority."}


def _official_endpoint(value: str) -> tuple[str, str]:
    if not isinstance(value, str):
        raise RuleError("official endpoint URL must be text")
    value = value.strip().rstrip(".")
    if "*" not in value:
        return "DOMAIN", _domain(value)
    # Microsoft endpoint wildcards are shell-style host patterns. Escape every
    # literal character and replace only '*' rather than widening parent roots.
    # Validate a concrete substitution before compiling the anchored pattern.
    _domain(value.replace("*", "wildcard"))
    if not value.startswith("*") or value.count("*") != 1:
        raise RuleError("interior or multiple wildcard endpoint template has no confirmed expansion grammar")
    if value.startswith("*.") and "*" not in value[2:]:
        return "DOMAIN-REGEX", r"^.+\." + re.escape(_domain(value[2:])) + "$"
    return "DOMAIN-REGEX", "^" + ".*".join(re.escape(part.lower()) for part in value.split("*")) + "$"


def official_domains(data: object, source_id: str, selector: dict) -> tuple[list[Rule], list[dict]]:
    """Preserve selected endpoint records, including both URL and IP fields.

    Ports, serviceArea/category and required status remain provenance; endpoint
    sets are connectivity inventories, not exclusive ownership or Geo evidence.
    """
    endpoints = []
    adapter = selector.get("adapter")
    if adapter == "microsoft365":
        if not isinstance(data, list):
            raise RuleError("Microsoft365 endpoint snapshot must be an array")
        areas = selector.get("service_areas", ["Common", "Exchange", "SharePoint", "Skype"])
        for number, entry in enumerate(data, 1):
            if not isinstance(entry, dict) or any(not isinstance(entry.get(field, []), list) for field in ("urls", "ips")):
                raise RuleError("invalid Microsoft365 endpoint record")
            if entry.get("serviceArea") in areas:
                for field in ("urls", "ips"):
                    endpoints.extend((number, entry.get("id"), field, i, value,
                                      {key:entry[key] for key in ("serviceArea", "category", "required", "tcpPorts", "udpPorts") if key in entry})
                                     for i, value in enumerate(entry.get(field, []), 1))
    elif adapter == "github-meta":
        if not isinstance(data, dict) or not isinstance(data.get("domains"), dict):
            raise RuleError("GitHub meta snapshot needs a domain catalogue")
        for category in selector.get("categories", []):
            entries = data["domains"].get(category)
            if not isinstance(entries, list):
                raise RuleError("GitHub meta domain category missing")
            endpoints.extend((i, category, "domains", i, value, {}) for i, value in enumerate(entries, 1))
    else:
        raise RuleError("unconfigured official endpoint schema")
    rows, rejected = [], []
    for number, record_id, field, index, value, context in endpoints:
        provenance = {"record_id":record_id, "endpoint_field":field, "endpoint_index":index,
                      "upstream_value":value, **context}
        try:
            if field == "ips":
                if not isinstance(value, str):
                    raise RuleError("official IP prefix must be text")
                network = ipaddress.ip_network(value, strict=True)
                kind, payload = "IP-CIDR", str(network)
            else:
                kind, payload = _official_endpoint(value)
            rows.append(normalize_rule(kind, payload, source=source_id, line=number,
                                       source_details=tuple(provenance.items())))
        except (RuleError, ValueError) as exc:
            rejected.append({**_quarantine(source_id, number, str(value), str(exc)), **provenance})
    # A raw template may remain unsupported while its possible literal suffix
    # is already covered by an independently accepted catalogue predicate.
    # Report that witness, never call the raw grammar supported or re-emit it.
    index = CoverageIndex(rows)
    witness = CompactionWitness(r.text for r in rows)
    for item in rejected:
        value = item.get("upstream_value")
        if item.get("endpoint_field") not in {"urls", "domains"} or not isinstance(value, str) or "*" not in value:
            continue
        suffix = value.rsplit("*", 1)[1]
        if not suffix.startswith("."):
            continue
        try:
            broad = normalize_rule("DOMAIN-REGEX", r"^.+\." + re.escape(_domain(suffix[1:])) + "$")
        except RuleError:
            continue
        if index.covers(broad):
            item["covered_by"] = witness.covering(broad)
            item["coverage_note"] = "Raw template remains unsupported; accepted rule covers all concrete hosts under its literal suffix. This is not a claim that template syntax is supported."
    return rows, rejected


def domain_match(rule: Rule, hostname: str) -> bool:
    """Match a concrete valid ASCII host, not predicate-language containment.

    Core normalizes host case/dots and uses substring regex matching. This
    helper covers only our validated common Python/Rust regex subset; it does
    not infer containment between arbitrary regex or suffix languages.
    """
    try:
        host = _domain(hostname.strip().strip("."))
    except RuleError:
        return False
    if rule.kind == "DOMAIN":
        return host == rule.value
    if rule.kind == "DOMAIN-SUFFIX":
        return host == rule.value or host.endswith("." + rule.value)
    if rule.kind == "DOMAIN-KEYWORD":
        return rule.value in host
    if rule.kind == "DOMAIN-REGEX":
        return re.search(rule.value, host) is not None
    return False


def build_domains(sources: list[dict], products: dict | str | Path, *, trace=None) -> tuple[dict[str, list[str]], dict]:
    return _build_domains(sources, products, trace=trace)


def _build_domains(sources: list[dict], products: dict | str | Path, *, trace=None) -> tuple[dict[str, list[str]], dict]:
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
    report: dict = {"quarantined": [], "unavailable_selectors": [], "groups": {}, "provenance": {}, "selectors": [],
                    "decisions": {}, "stage_records": 0, "dlc_includes": {},
                    "sources": [{k: s[k] for k in ("id", "status", "version", "sha256", "lineage", "domain_role", "format") if k in s} for s in sources]}
    def audit(group, selector, rule, stage, status, reason, **extra):
        sid = selector.get("source", rule.source.split(":", 1)[0])
        key = selector.get("category", selector.get("path", selector.get("adapter", "membership")))
        item = {"group": group, "source": rule.source, "line": rule.line, "predicate": rule.text,
                "selector": key, "stage": stage, "status": status, "reason": reason,
                **({"source_details":dict(rule.source_details)} if rule.source_details else {}), **extra}
        bucket = report["decisions"].setdefault(group, {}).setdefault(sid + ":" + str(key), {}).setdefault(stage, {})
        counted = bucket.setdefault(status + ":" + reason, {"count": 0, "samples": []})
        counted["count"] += 1
        if len(counted["samples"]) < 12:
            counted["samples"].append(item)
        report["stage_records"] += 1
        if trace is not None:
            traced = {**item, "source_id": sid}
            if stage == "compaction":
                traced["covering_predicate"] = compaction.covering(rule)
            trace.domain_event(traced)
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
                if trace is not None:
                    trace.source_event(source_id, "domain-selector", "unavailable", group=name,
                                       selector=selector, reason="source unavailable")
                if selector.get("required", False):
                    raise RuleError(f"required selector {name}/{source_id}: source unavailable")
                report["unavailable_selectors"].append({"group": name, "source": source_id, "reason": "source unavailable"})
                continue
            try:
                rejected = []
                read_lines = None
                input_records = None
                format = selector.get("format", source.get("format", "surge"))
                if format == "dlc":
                    if source_id not in dlc:
                        dlc[source_id] = DLC(source["path"], source_id)
                        for bad in dlc[source_id].quarantined:
                            quarantine(bad)
                            audit(name, selector, Rule("UNSUPPORTED", bad["predicate"], source=bad["source"], line=bad["line"]),
                                  "source-parse", "reject", bad["reason"], scope="source-wide; original file retained")
                        report["dlc_includes"][source_id] = dlc[source_id].include_edges
                        if trace is not None:
                            catalog = dlc[source_id]
                            trace.source_event(source_id, "domain-source-parse", "parsed",
                                read_lines=catalog.read_lines, parsed_records=catalog.parsed_records,
                                include_records=catalog.include_records, rejected_records=len(catalog.quarantined),
                                count_scope="source files read once; selector/include expansions counted separately",
                                include_edges=catalog.include_edges)
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
                    payload = path.read_text(encoding="utf-8")
                    if trace is not None: read_lines = len(payload.splitlines())
                    data = json.loads(payload)
                    input_records = len(data) if isinstance(data,list) else None
                    rows, rejected = official_domains(data, source_id, selector)
                elif format == "official-cidr":
                    if source.get("service") != name or not selector.get("official_service_ips"):
                        raise RuleError("official IP catalogue is not scoped to this product")
                    families = source.get("address_families")
                    if (not isinstance(families,list) or not families or
                            any(type(f) is not int or f not in (4,6) for f in families) or
                            len(set(families)) != len(families)):
                        raise RuleError("official CIDR source needs a valid address_families contract")
                    payload = Path(source["path"]).read_text()
                    if trace is not None: read_lines = len(payload.splitlines())
                    rows = [normalize_rule("IP-CIDR", line.strip(), source=source_id, line=i)
                            for i, line in enumerate(payload.splitlines(), 1)
                            if line.strip() and not line.lstrip().startswith("#")]
                    observed = {ipaddress.ip_network(row.value).version for row in rows}
                    if observed - set(families):
                        raise RuleError("official CIDR row is outside declared address families")
                    if set(families) - observed:
                        raise RuleError("official CIDR source is missing a declared address family")
                else:
                    path = Path(source["path"])
                    if selector.get("path"):
                        relative = Path(selector["path"])
                        if relative.is_absolute() or ".." in relative.parts:
                            raise RuleError("unsafe selector path")
                        path = path / relative if path.is_dir() else path
                    payload = path.read_text(encoding="utf-8")
                    if trace is not None: read_lines = len(payload.splitlines())
                    rows, rejected = parse_third_party(payload, format, f"{source_id}:{selector.get('path', path.name)}", behavior=selector.get("behavior", "classical"))
                for bad in rejected:
                    quarantine(bad)
                    audit(name, selector, Rule("UNSUPPORTED", bad["predicate"], source=bad["source"], line=bad["line"],
                        source_details=tuple((key,value) for key,value in bad.items() if key not in {"source","line","predicate","reason"})),
                          "parse-normalize", "reject", bad["reason"])
                for row in rows:
                    if dict(row.source_details).get("conversion"):
                        audit(name, selector, row, "conversion", "normalized", dict(row.source_details)["conversion"])
                    if row.removed_modifiers:
                        audit(name, selector, row, "conversion", "normalized", "upstream-resolution-modifier-removed",
                              removed_modifiers=list(row.removed_modifiers), policy="AirRoute products do not carry no-resolve")
                    audit(name, selector, row, "parse-normalize", "accept", "normalized-upstream-predicate", attributes=sorted(row.attrs))
                    mark_origin(name, selector, row)
                if trace is not None:
                    trace.source_event(source_id, "domain-selector-parse", "parsed" if rows else "empty",
                        group=name, selector=selector, parsed_records=len(rows), rejected_records=len(rejected),
                        source_record_count=input_records,
                        parsed_kind_counts={kind:sum(r.kind==kind for r in rows) for kind in sorted({r.kind for r in rows})},
                        read_lines=read_lines, input_file=selector.get("path", selector.get("category", source.get("path"))),
                        count_scope="expanded selector predicates; repeated reads/memberships are not unique physical records")
                # Upstream classifications are the input. Only an explicit
                # exclusion with proven whole-predicate coverage is applied;
                # unknown regex intersections cannot justify removing a rule.
                scoped = []
                excluded = CoverageIndex(normalize_rule("DOMAIN-SUFFIX", root)
                    for root in selector.get("exclude_roots", []))
                for row in rows:
                    reason = None
                    if row.text in group.get("exclude_predicates", []) or row.text in selector.get("exclude_predicates", []):
                        reason = "explicit-predicate-exclusion"
                    elif excluded.covers(row):
                        reason = "covered-by-explicit-excluded-root"
                    elif name == "region/cn-domain" and row.kind in IP_KINDS:
                        reason = "IP predicate belongs to separately generated regional IP data"
                    if reason:
                        quarantine(_quarantine(row.source, row.line, row.text, reason))
                        audit(name, selector, row, "scope", "excluded", reason)
                    else:
                        scoped.append(row)
                        audit(name, selector, row, "scope", "accept", "upstream-classification")
                prior = CoverageIndex(accepted)
                report["selectors"].append({"group": name, "source": source_id,
                    "selector": selector.get("category", selector.get("path", selector.get("adapter", format))),
                    "mode": selector.get("mode", "primary"), "lineage": source.get("lineage", source_id),
                    "input_rules": len(rows), "source_record_count":input_records,
                    "parsed_kind_counts":{kind:sum(r.kind==kind for r in rows) for kind in sorted({r.kind for r in rows})},
                    "scope_admitted": len(scoped),
                    "scope_rejected": len(rows) - len(scoped), "already_covered": sum(prior.covers(r) for r in scoped)})
                rows = scoped
                accepted.extend(rows)
            except (RuleError, OSError, UnicodeError, json.JSONDecodeError) as exc:
                if trace is not None:
                    trace.source_event(source_id, "domain-selector", "failed", group=name,
                                       selector=selector, error_type=type(exc).__name__, error=str(exc))
                reason = f"input unavailable ({type(exc).__name__})" if isinstance(exc, (OSError, UnicodeError)) else str(exc)
                requirement = "required" if selector.get("required", False) else "selected"
                raise RuleError(f"{requirement} selector {name}/{source_id}: {reason}") from exc
        prepared[name] = accepted
    # Resolve memberships after selectors; categories retain all included members.
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
        resolved.add(name)
    for name in definitions:
        include(name)
    groups: dict[str, list[str]] = {}
    for group in products.get("groups", []):
        name = group["id"]
        rows = prepared[name]
        report["groups"][name] = {"accepted_before_compaction": len(rows), "selector_count": len(group.get("selectors", []))}
        for rule in rows:
            report["provenance"].setdefault(name, {}).setdefault(rule.text, []).append({"source": rule.source, "line": rule.line, "attributes": sorted(rule.attrs), **({"source_details":dict(rule.source_details)} if rule.source_details else {})})
        groups[name] = [r.text for r in minimize(rows)]
        output_set = set(groups[name])
        compaction = CompactionWitness(groups[name]) if trace is not None else None
        seen_rows = set()
        for row in rows:
            status = "output" if row.text in output_set and row.text not in seen_rows else "covered"
            reason = "retained-predicate" if status == "output" else "duplicate-predicate" if row.text in seen_rows else "semantically-covered"
            for selector in origins.get((name, row.source, row.line, row.text), [{"source": row.source.split(":", 1)[0]}]):
                audit(name, selector, row, "compaction", status, reason)
            seen_rows.add(row.text)
        report["groups"][name]["output_rules"] = len(groups[name])
        report["groups"][name]["status"] = "generated" if groups[name] else "empty"
        support = {}
        for rule in rows:
            sid = rule.source.split(":", 1)[0]
            support.setdefault(sid, set()).add(rule.text)
        report["groups"][name]["source_support_rules"] = {sid: len(values) for sid, values in sorted(support.items())}
        report["groups"][name]["support_note"] = "Overlapping support is not additive contribution or independent votes."

    report["not_selected_classifications"] = products.get("not_selected_classifications", [])
    if trace is not None:
        for item in report["not_selected_classifications"]:
            trace.source_event(item["source"], "domain-selection", "not-selected", **{k:v for k,v in item.items() if k != "source"})
    report["raw_accepted_rules"] = sum(v["accepted_before_compaction"] for v in report["groups"].values())
    report["sample_limit_per_source_reason"] = 12
    report["output_rules"] = sum(map(len, groups.values()))
    report["memberships"] = {g["id"]: g["includes"] for g in products["groups"] if g.get("includes")}
    report["format_validation"] = validate_domain_groups(groups)
    return groups, report
