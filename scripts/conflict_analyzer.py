#!/usr/bin/env python3
"""
MikroTik RouterOS .rsc Conflict Analyzer
=========================================
Detects configuration conflicts and logical errors in exported .rsc files
using offline static analysis (NO SSH needed).

Conflict Types Detected:
  1. UNREACHABLE_RULE        — Rules after a catch-all that will never match
  2. NAT_BYPASSES_FIREWALL   — DSTNAT rules forwarding to internal IPs without
                               matching forward-chain accept rules
  3. ORPHAN_ROUTING_MARK     — Mangle rules that mark routing but no route uses
                               that mark
  4. INTERFACE_NOT_IN_LIST   — Active interfaces not in any named interface list
  5. ADDRESS_LIST_CONFLICT   — Same IP address in both allow and block lists
  6. FORWARD_WITHOUT_FASTTRACK — Many forward rules without FastTrack rule
  7. SHADOWED_RULE           — More specific rules placed after less specific
                               rules matching the same traffic
  8. DUPLICATE_RULE          — Exact same parameters ignoring comments

Usage:
    from conflict_analyzer import ConflictAnalyzer

    analyzer = ConflictAnalyzer()
    analyzer.load_data(config_sections)
    conflicts = analyzer.analyze()
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
import os


# ═══════════════════════════════════════════════════════════════════════════
# Enums & Dataclasses
# ═══════════════════════════════════════════════════════════════════════════


class ConflictType(str, Enum):
    """Enum of all detectable conflict types with unique string values."""

    UNREACHABLE_RULE = "unreachable_rule"
    NAT_BYPASSES_FIREWALL = "nat_bypasses_firewall"
    ORPHAN_ROUTING_MARK = "orphan_routing_mark"
    INTERFACE_NOT_IN_LIST = "interface_not_in_list"
    ADDRESS_LIST_CONFLICT = "address_list_conflict"
    FORWARD_WITHOUT_FASTTRACK = "forward_without_fasttrack"
    SHADOWED_RULE = "shadowed_rule"
    DUPLICATE_RULE = "duplicate_rule"


SEVERITY_MAP: Dict[ConflictType, str] = {
    ConflictType.UNREACHABLE_RULE: "Medium",
    ConflictType.NAT_BYPASSES_FIREWALL: "High",
    ConflictType.ORPHAN_ROUTING_MARK: "Medium",
    ConflictType.INTERFACE_NOT_IN_LIST: "Medium",
    ConflictType.ADDRESS_LIST_CONFLICT: "High",
    ConflictType.FORWARD_WITHOUT_FASTTRACK: "Low",
    ConflictType.SHADOWED_RULE: "Medium",
    ConflictType.DUPLICATE_RULE: "Medium",
}

TITLE_MAP: Dict[ConflictType, str] = {
    ConflictType.UNREACHABLE_RULE: "Unreachable Firewall Rule",
    ConflictType.NAT_BYPASSES_FIREWALL: "NAT Rule Bypasses Firewall Forward Chain",
    ConflictType.ORPHAN_ROUTING_MARK: "Orphaned Routing Mark",
    ConflictType.INTERFACE_NOT_IN_LIST: "Active Interface Not in Any Interface List",
    ConflictType.ADDRESS_LIST_CONFLICT: "Address List Conflict — Same IP in Allow and Block",
    ConflictType.FORWARD_WITHOUT_FASTTRACK: "Many Forward Rules Without FastTrack",
    ConflictType.SHADOWED_RULE: "Shadowed Firewall Rule",
    ConflictType.DUPLICATE_RULE: "Duplicate Firewall/NAT/Mangle Rule",
}

DESCRIPTION_MAP: Dict[ConflictType, str] = {
    ConflictType.UNREACHABLE_RULE: (
        "A catch-all rule (action=drop/accept/reject with no filtering conditions) "
        "appears before other rules in the same chain. All subsequent rules will "
        "never be evaluated because the catch-all matches all packets first."
    ),
    ConflictType.NAT_BYPASSES_FIREWALL: (
        "A DSTNAT rule forwards traffic to an internal IP address through the router, "
        "but the forward chain does not have an explicit rule to accept traffic "
        "to that destination. If the forward chain has a default-drop policy, "
        "the NAT'd traffic will be silently dropped."
    ),
    ConflictType.ORPHAN_ROUTING_MARK: (
        "A mangle rule sets a routing-mark on packets, but no route entry "
        "references that routing mark. The marked packets will use the main "
        "routing table instead of the intended custom table."
    ),
    ConflictType.INTERFACE_NOT_IN_LIST: (
        "An active (enabled) interface is not assigned to any named interface list "
        "(WAN, LAN, etc.). This can cause it to bypass firewall rules that use "
        "in-interface-list or out-interface-list filtering."
    ),
    ConflictType.ADDRESS_LIST_CONFLICT: (
        "The same IP address appears in both an allow/whitelist and a block/blacklist "
        "address-list. The evaluation order of firewall rules determines which list "
        "wins, but this configuration is ambiguous and likely a sign of poor list "
        "management or a stale entry."
    ),
    ConflictType.FORWARD_WITHOUT_FASTTRACK: (
        "The firewall forward chain has multiple rules (3+) but no FastTrack rule "
        "is configured. FastTrack significantly improves forwarding throughput by "
        "offloading established connections. Without it, all traffic is processed "
        "through the slow path, impacting performance on high-throughput links."
    ),
    ConflictType.SHADOWED_RULE: (
        "A rule with broad matching conditions appears before a more specific rule "
        "in the same chain. The specific rule will never be reached because the "
        "broader rule matches all of its traffic first."
    ),
    ConflictType.DUPLICATE_RULE: (
        "Two or more rules in the same chain have identical match parameters "
        "(same chain, action, src, dst, protocol, ports, interfaces, connection-state). "
        "The duplicate rule is redundant and adds no additional security or functionality."
    ),
}


@dataclass
class ParsedEntry:
    """A single parsed RouterOS command entry from the .rsc export."""

    raw: str
    command: str  # add, set, remove, enable, disable, etc.
    params: Dict[str, str] = field(default_factory=dict)

    def get(self, key: str, default: str = "") -> str:
        """Get a parameter value, returning default if not present."""
        return self.params.get(key, default)


@dataclass
class ConfigSection:
    """A section of configuration from a specific menu path."""

    path: str  # e.g., /ip firewall filter
    entries: List[ParsedEntry] = field(default_factory=list)


@dataclass
class ConflictResult:
    """A single detected conflict with metadata and remediation commands."""

    conflict_type: ConflictType
    severity: str
    title: str
    description: str
    config_path: str
    details: str
    recommendation: str
    fix_commands: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a plain dict compatible with the audit_rsc.py findings format."""
        return {
            "id": f"CF-{self.conflict_type.value.upper()}",
            "name": self.title,
            "severity": self.severity,
            "cvss": self._cvss_score(),
            "category": "Configuration Conflict",
            "path": self.config_path,
            "description": self.description,
            "details": self.details,
            "remediation": "\n".join(self.fix_commands),
            "compliance": {},
        }

    def _cvss_score(self) -> str:
        """Return approximate CVSS score based on severity."""
        mapping = {
            "Critical": "9.0",
            "High": "7.5",
            "Medium": "5.5",
            "Low": "3.3",
            "Info": "0.0",
        }
        return mapping.get(self.severity, "5.5")


# ═══════════════════════════════════════════════════════════════════════════
# Parser Helpers
# ═══════════════════════════════════════════════════════════════════════════


RE_PARAM = re.compile(r'(\w[\w-]*)=(?:"([^"]*)"|(\S+))')
RE_CONTINUATION = re.compile(r"\\\s*$")
RE_COMMAND = re.compile(r"^\s*(add|set|remove|enable|disable|comment|move|print|get|find|export)\b")
RE_PATH = re.compile(r"^(/(?:[\w/-]+(?:\s|$))+)")

# Parameter keys that constitute "conditions" (not just settings)
CONDITIONAL_PARAMS: Set[str] = {
    "src-address",
    "dst-address",
    "protocol",
    "src-port",
    "dst-port",
    "in-interface",
    "out-interface",
    "connection-state",
    "connection-type",
    "connection-mark",
    "src-address-list",
    "dst-address-list",
    "src-address-type",
    "dst-address-type",
    "in-interface-list",
    "out-interface-list",
    "content",
    "layer7-protocol",
    "limit",
    "packet-size",
    "random",
    "tcp-flags",
    "tcp-mss",
    "ipsec-policy",
    "icmp-options",
    "ttl",
    "hop-limit",
    "dscp",
    "port",
    "address",
    "mac-address",
}

# Parameters used for duplicate rule signature (excluding comments/descriptions)
SIGNATURE_PARAMS: List[str] = [
    "chain",
    "action",
    "src-address",
    "dst-address",
    "protocol",
    "src-port",
    "dst-port",
    "port",
    "in-interface",
    "out-interface",
    "in-interface-list",
    "out-interface-list",
    "connection-state",
    "connection-mark",
    "src-address-list",
    "dst-address-list",
    "address-list",
    "src-address-type",
    "dst-address-type",
    "icmp-options",
    "tcp-flags",
    "tcp-mss",
    "content",
    "layer7-protocol",
    "packet-size",
    "random",
    "ttl",
    "hop-limit",
    "dscp",
    "ipsec-policy",
    "mac-address",
    "to-addresses",
    "to-ports",
    "new-routing-mark",
    "new-packet-mark",
    "new-connection-mark",
    "new-dscp",
    "new-ttl",
    "log",
    "log-prefix",
]


def join_continuations(lines: List[str]) -> List[str]:
    """Join lines split with backslash continuations into single logical lines.
    
    RouterOS uses trailing backslash for line continuation. This function
    joins them before further parsing.
    
    Handles multi-line values correctly: when a line ends with
    ``key=\\`` and the continuation starts with spaces + ``value``,
    it produces ``key=value`` (no spurious space after ``=``).
    """
    joined: List[str] = []
    buffer = ""
    for line in lines:
        cont_match = RE_CONTINUATION.search(line)
        if cont_match:
            stripped = RE_CONTINUATION.sub("", line).strip()
            # Add space when joining two distinct parameters across
            # continuation boundaries (e.g. ``..." \\`` + ``key=...``)
            if buffer and stripped and (buffer[-1].isalnum() or buffer[-1] == '"') \
                    and (stripped[0].isalnum() or stripped[0] == '"'):
                buffer += " "
            buffer += stripped
        else:
            if buffer:
                next_part = line.strip()
                # Insert a single space between parts only when genuinely
                # separating two distinct parameters (both sides are words),
                # NOT between ``key=`` and ``value`` across a continuation.
                if next_part and buffer and (buffer[-1].isalnum() or buffer[-1] == '"') \
                        and next_part[0].isalnum():
                    buffer += " "
                buffer += next_part
                joined.append(buffer)
                buffer = ""
            else:
                joined.append(line.strip())
    if buffer:
        joined.append(buffer.strip())
    return joined


def parse_params(line: str) -> Dict[str, str]:
    """Extract key=value parameters from a RouterOS command line.
    
    Handles:
    - Simple params: chain=input → {"chain": "input"}
    - Quoted values: comment="allow SSH" → {"comment": "allow SSH"}
    - Multi-values: connection-state=established,related
    - Extended keys: tcp-md5-key=secret, src-address=10.0.0.0/24
    """
    params: Dict[str, str] = {}
    for match in RE_PARAM.finditer(line):
        key = match.group(1)
        value = match.group(2) if match.group(2) is not None else match.group(3)
        params[key] = value
    return params


def _split_path_and_command(line: str) -> Tuple[str, str, str]:
    """Split a config line into its (path_prefix, command, remainder).
    
    Returns (path_prefix, command, rest_of_line).
    path_prefix is everything before the command (e.g., /ip firewall filter).
    If no explicit path, path_prefix reflects the last known path.
    """
    line_stripped = line.strip()

    # Check for path command first
    path_match = re.match(r"^(/\S+(?:\s+(?!/)\S+)*)\s+(add|set|remove|enable|disable|comment|move|print|get|find|export)\b", line_stripped)
    if path_match:
        return path_match.group(1), path_match.group(2), line_stripped[path_match.end():].strip()

    # Check for just a path (no command) — e.g., /ip firewall filter
    path_only = re.match(r"^(/\S+(?:\s+\S+)*)$", line_stripped)
    if path_only:
        return path_only.group(1), "", ""

    # Check for command without path (e.g., "add chain=input ...")
    cmd_match = RE_COMMAND.match(line_stripped)
    if cmd_match:
        return "", cmd_match.group(1), line_stripped[cmd_match.end():].strip()

    return "", "", line_stripped


def parse_section(lines: List[str], default_path: str = "") -> List[ParsedEntry]:
    """Parse a list of raw .rsc lines into structured ParsedEntry objects.
    
    Args:
        lines: Raw lines from the .rsc export for a given path section
        default_path: The path context for entries (e.g., /ip firewall filter)
    
    Returns:
        List of ParsedEntry objects
    """
    joined_lines = join_continuations(lines)
    entries: List[ParsedEntry] = []
    current_path = default_path

    for line in joined_lines:
        if not line or line.startswith("#"):
            continue

        # Check if this line introduces a new path
        path_only = re.match(r"^(/\S+(?:\s+\S+)*)$", line)
        if path_only:
            current_path = path_only.group(1)
            continue

        # Check if line is a command with embedded path
        path_match = re.match(r"^(/\S+(?:\s+(?!/)\S+)*)\s+(add|set|remove|enable|disable|comment|move|print|get|find|export)\b", line)
        if path_match:
            current_path = path_match.group(1)
            command = path_match.group(2)
            rest = line[path_match.end():].strip()
        else:
            # No path prefix — guess command (likely add/set under current path)
            cmd_match = RE_COMMAND.match(line)
            if cmd_match:
                command = cmd_match.group(1)
                rest = line[cmd_match.end():].strip()
            else:
                # Unrecognized — store raw with empty command
                entries.append(ParsedEntry(raw=line, command="", params={}))
                continue

        params = parse_params(rest)
        entries.append(ParsedEntry(raw=line, command=command, params=params))

    return entries


# ═══════════════════════════════════════════════════════════════════════════
# ConflictAnalyzer
# ═══════════════════════════════════════════════════════════════════════════


class ConflictAnalyzer:
    """Detects configuration conflicts in MikroTik RouterOS .rsc exports.
    
    Usage:
        analyzer = ConflictAnalyzer()
        analyzer.load_data(config_sections)
        results = analyzer.analyze()
        
        for result in results:
            print(f"[{result.severity}] {result.title}")
            for cmd in result.fix_commands:
                print(f"  → {cmd}")
    """

    # Threshold for FORWARD_WITHOUT_FASTTRACK: number of forward rules before flagging
    FORWARD_RULE_THRESHOLD: int = 3

    # Address-list name heuristics for categorizing allow/block lists
    ALLOW_KEYWORDS: List[str] = [
        "allow", "whitelist", "white_list", "trusted", "permit", "accept",
    ]
    BLOCK_KEYWORDS: List[str] = [
        "block", "blacklist", "black_list", "deny", "ban", "reject",
        "blocked", "banned", "restricted",
    ]

    def __init__(self) -> None:
        self._sections: Dict[str, ConfigSection] = {}
        self._all_lines: List[str] = []
        self._conflicts: List[ConflictResult] = []

    # ── Public API ──────────────────────────────────────────────────────

    def load_data(self, results: List[Dict[str, Any]]) -> None:
        """Load parsed .rsc configuration sections.
        
        Args:
            results: List of dicts, each with:
                - "path": str — the RouterOS menu path (e.g., "/ip firewall filter")
                - "lines": List[str] — raw command lines under that path
                
                Or alternatively:
                - "path": str
                - "entries": List[Dict] — pre-parsed entries with "command" and "params"
                
                Can also accept the raw .rsc content via:
                - {"raw": "full file content as string", "_is_raw": True}
        """
        self._sections = {}
        self._all_lines = []
        self._conflicts = []

        for section in results:
            if section.get("_is_raw"):
                # Raw file content — parse everything
                self._load_raw(section.get("raw", ""))
                continue

            path = section.get("path", "")
            raw_lines: List[str] = section.get("lines", [])
            entries_raw: List[Dict] = section.get("entries", [])

            if entries_raw:
                # Pre-parsed entries
                entries = [
                    ParsedEntry(
                        raw=e.get("raw", ""),
                        command=e.get("command", ""),
                        params=e.get("params", {}),
                    )
                    for e in entries_raw
                ]
            elif raw_lines:
                entries = parse_section(raw_lines)
            else:
                entries = []

            self._sections[path] = ConfigSection(path=path, entries=entries)
            self._all_lines.extend(raw_lines)

    def analyze(self) -> List[ConflictResult]:
        """Run all conflict detection checks.
        
        Returns:
            List of ConflictResult objects, sorted by severity (Critical→Info).
        """
        self._conflicts = []
        
        self._check_unreachable_rules()
        self._check_nat_bypasses_firewall()
        self._check_orphan_routing_mark()
        self._check_interface_not_in_list()
        self._check_address_list_conflict()
        self._check_forward_without_fasttrack()
        self._check_shadowed_rules()
        self._check_duplicate_rules()

        # Sort by severity (Critical → Info)
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        self._conflicts.sort(key=lambda c: sev_order.get(c.severity, 99))

        return self._conflicts

    def get_conflicts_by_type(self, conflict_type: ConflictType) -> List[ConflictResult]:
        """Filter results by conflict type."""
        return [c for c in self._conflicts if c.conflict_type == conflict_type]

    def get_conflicts_by_severity(self, severity: str) -> List[ConflictResult]:
        """Filter results by severity level."""
        return [c for c in self._conflicts if c.severity == severity]

    # ── Internal Data Access ────────────────────────────────────────────

    def _get_entries(self, path: str) -> List[ParsedEntry]:
        """Get parsed entries for a specific config path."""
        section = self._sections.get(path)
        if section:
            return section.entries
        return []

    def _get_entries_path_filter(self, path_prefix: str) -> List[Tuple[str, ParsedEntry]]:
        """Get entries from all paths matching a prefix.
        
        Returns list of (path, entry) tuples.
        """
        results: List[Tuple[str, ParsedEntry]] = []
        for path, section in self._sections.items():
            if path.startswith(path_prefix):
                for entry in section.entries:
                    results.append((path, entry))
        return results

    def _get_entries_by_chain(self, paths: List[str]) -> Dict[str, List[ParsedEntry]]:
        """Group entries from given paths by their 'chain' parameter.
        
        Returns mapping of chain_name → list of entries.
        """
        by_chain: Dict[str, List[ParsedEntry]] = defaultdict(list)
        for path in paths:
            for entry in self._get_entries(path):
                chain = entry.get("chain", "")
                if chain:
                    by_chain[chain].append(entry)
        return by_chain

    def _load_raw(self, content: str) -> None:
        """Parse raw .rsc file content into sections.
        
        Splits content by path boundaries (lines starting with /).
        """
        lines = content.splitlines()
        joined = join_continuations(lines)

        current_path = ""
        current_lines: List[str] = []

        for line in joined:
            if not line or line.startswith("#"):
                continue

            # Detect path declaration
            path_only = re.match(r"^(/\S+(?:\s+\S+)*)$", line)
            if path_only:
                # Save previous section
                if current_path and current_lines:
                    self._sections[current_path] = ConfigSection(
                        path=current_path,
                        entries=parse_section(current_lines, current_path),
                    )
                current_path = path_only.group(1)
                current_lines = []
                continue

            # Check if line contains path+command
            path_match = re.match(r"^(/\S+(?:\s+(?!/)\S+)*)\s+(add|set|remove|enable|disable)\b", line)
            if path_match:
                new_path = path_match.group(1)
                if new_path != current_path:
                    # Path changed mid-section
                    if current_path and current_lines:
                        self._sections[current_path] = ConfigSection(
                            path=current_path,
                            entries=parse_section(current_lines, current_path),
                        )
                    current_path = new_path
                    current_lines = []

            current_lines.append(line)

        # Save last section
        if current_path and current_lines:
            self._sections[current_path] = ConfigSection(
                path=current_path,
                entries=parse_section(current_lines, current_path),
            )

    # ── Check 1: UNREACHABLE_RULE ───────────────────────────────────────

    def _check_unreachable_rules(self) -> None:
        """Detect firewall rules placed after a catch-all that will never match.
        
        A catch-all rule has action=drop/accept/reject and NO filtering conditions
        (no src/dst-address, protocol, port, interface, connection-state, etc.).
        """
        fw_paths = [
            "/ip firewall filter",
            "/ip firewall nat",
            "/ip firewall mangle",
            "/ip firewall raw",
        ]
        by_chain = self._get_entries_by_chain(fw_paths)

        for chain, entries in by_chain.items():
            found_catch_all = False
            catch_all_line = ""

            for entry in entries:
                if found_catch_all:
                    # Everything after the catch-all is unreachable
                    self._conflicts.append(ConflictResult(
                        conflict_type=ConflictType.UNREACHABLE_RULE,
                        severity=SEVERITY_MAP[ConflictType.UNREACHABLE_RULE],
                        title=TITLE_MAP[ConflictType.UNREACHABLE_RULE],
                        description=DESCRIPTION_MAP[ConflictType.UNREACHABLE_RULE],
                        config_path=f"chain={chain}",
                        details=(
                            f"Catch-all rule '{catch_all_line}' prevents subsequent "
                            f"rule from being reached: '{entry.raw}'"
                        ),
                        recommendation=(
                            f"Move rule before the catch-all, or remove it if superseded. "
                            f"The catch-all rule at the end of the chain serves as "
                            f"your default policy."
                        ),
                        fix_commands=[
                            f"# Rule is unreachable after catch-all in chain={chain}:",
                            f"# {entry.raw}",
                            f"# Move it before the catch-all rule using 'move' command.",
                        ],
                    ))
                    continue

                # Check if this entry is a catch-all
                action = entry.get("action", "")
                if action not in ("drop", "accept", "reject"):
                    continue

                has_conditions = False
                for key in entry.params:
                    if key in CONDITIONAL_PARAMS:
                        has_conditions = True
                        break

                if not has_conditions:
                    # Disabled rules cannot shadow anything
                    if entry.params.get("disabled") == "yes":
                        continue
                    found_catch_all = True
                    catch_all_line = entry.raw

    # ── Check 2: NAT_BYPASSES_FIREWALL ─────────────────────────────────

    def _check_nat_bypasses_firewall(self) -> None:
        """Detect DSTNAT rules forwarding to internal IPs without matching
        forward-chain accept rules.
        
        If the forward chain has a default-drop rule (explicit drop for WAN→LAN
        or general drop), DSTNAT traffic may be dropped after translation.
        """
        # Get DSTNAT rules
        nat_entries = self._get_entries("/ip firewall nat")
        dstnat_rules = [e for e in nat_entries if e.get("chain", "").lower() == "dstnat"]

        if not dstnat_rules:
            return

        # Get forward chain rules
        fwd_entries = self._get_entries("/ip firewall filter")
        forward_rules = [e for e in fwd_entries if e.get("chain", "").lower() == "forward"]

        # Check if forward chain has a default-drop pattern
        has_default_drop = False
        for e in forward_rules:
            if e.get("action", "").lower() == "drop":
                in_iface_list = e.get("in-interface-list", "").lower()
                in_iface = e.get("in-interface", "").lower()
                dst_addr = e.get("dst-address", "")

                # Default drops: WAN input, !LAN, or no-conditions
                has_conditions = any(k in e.params for k in CONDITIONAL_PARAMS)
                
                if not has_conditions:
                    has_default_drop = True
                    break
                # Also check for WAN→LAN drop pattern
                if "wan" in in_iface_list or "wan" in in_iface:
                    has_default_drop = True
                    break

        if not has_default_drop:
            # Without a default-drop, traffic may pass through. Skip to reduce noise.
            return

        # Get all dst addresses accepted in forward chain
        accepted_dsts: List[str] = []
        for e in forward_rules:
            if e.get("action", "").lower() == "accept":
                dst = e.get("dst-address", "")
                if dst:
                    accepted_dsts.append(dst)

        # Check each DSTNAT rule
        for rule in dstnat_rules:
            to_addr = rule.get("to-addresses", "")
            if not to_addr:
                continue

            to_port = rule.get("to-ports", "")
            protocol = rule.get("protocol", "")
            dst_port = rule.get("dst-port", "")

            # Try to find a matching forward accept rule
            covered = False
            for fwd_dst in accepted_dsts:
                if self._ip_in_prefix(to_addr, fwd_dst):
                    covered = True
                    break

            if not covered:
                self._conflicts.append(ConflictResult(
                    conflict_type=ConflictType.NAT_BYPASSES_FIREWALL,
                    severity=SEVERITY_MAP[ConflictType.NAT_BYPASSES_FIREWALL],
                    title=TITLE_MAP[ConflictType.NAT_BYPASSES_FIREWALL],
                    description=DESCRIPTION_MAP[ConflictType.NAT_BYPASSES_FIREWALL],
                    config_path="/ip firewall nat",
                    details=(
                        f"DSTNAT rule forwards to {to_addr}"
                        f"{' port ' + to_port if to_port else ''}"
                        f"{' (' + protocol + ')' if protocol else ''}. "
                        f"No forward-chain accept rule explicitly allows traffic "
                        f"to {to_addr}. Forward chain has a default-drop pattern."
                    ),
                    recommendation=(
                        f"Add a forward-chain accept rule for traffic to {to_addr}"
                        f"{' port ' + to_port if to_port else ''}:"
                    ),
                    fix_commands=[
                        f"/ip firewall filter add chain=forward action=accept \\",
                        f"    dst-address={to_addr}"
                        f"{' protocol=' + protocol if protocol else ''}"
                        f"{' dst-port=' + (to_port or dst_port) if (to_port or dst_port) else ''}"
                        f" \\",
                        f"    comment=\"Allow DSTNAT traffic to {to_addr}\"",
                    ],
                ))

    @staticmethod
    def _ip_in_prefix(ip: str, prefix: str) -> bool:
        """Check if an IP address falls within a CIDR prefix.
        
        Simplified check for static analysis — handles basic cases.
        Returns True if ip is within the prefix, or if the check is ambiguous.
        """
        if not ip or not prefix:
            return False

        # Exact match
        if ip == prefix or prefix.endswith(ip):
            return True

        # Check CIDR notation
        if "/" in prefix:
            try:
                from ipaddress import ip_address, ip_network
                net = ip_network(prefix, strict=False)
                addr = ip_address(ip)
                return addr in net
            except (ValueError, ImportError):
                # Fallback: simple string prefix match
                base = prefix.split("/")[0]
                return ip.startswith(base.rsplit(".", 1)[0] + ".")
        
        return False

    # ── Check 3: ORPHAN_ROUTING_MARK ───────────────────────────────────

    def _check_orphan_routing_mark(self) -> None:
        """Detect mangle rules that mark routing but no route uses that mark."""
        mangle_entries = self._get_entries("/ip firewall mangle")
        route_entries = self._get_entries("/ip route")

        # Handle both RouterOS v6 (ip route) and v7 routing
        route_vrf_entries = self._get_entries("/routing table")

        # Collect routing marks set by mangle rules
        marked_marks: Set[str] = set()
        for e in mangle_entries:
            if e.get("action", "").lower() == "mark-routing":
                mark = e.get("new-routing-mark", "")
                if mark:
                    marked_marks.add(mark)

        if not marked_marks:
            return

        # Collect routing marks used by routes
        used_marks: Set[str] = set()
        for e in route_entries:
            mark = e.get("routing-mark", "")
            if mark:
                used_marks.add(mark)

        # Also check v7 routing table definitions
        for e in route_vrf_entries:
            table_name = e.get("name", "")
            fib = e.get("fib", "")
            if table_name and fib:
                used_marks.add(table_name)

        # Orphaned = marked but not used by any route
        orphaned = marked_marks - used_marks

        for mark in sorted(orphaned):
            # Find the mangle rules that set this mark
            setting_rules = [
                e.raw for e in mangle_entries
                if e.get("action", "").lower() == "mark-routing"
                and e.get("new-routing-mark", "") == mark
            ]

            self._conflicts.append(ConflictResult(
                conflict_type=ConflictType.ORPHAN_ROUTING_MARK,
                severity=SEVERITY_MAP[ConflictType.ORPHAN_ROUTING_MARK],
                title=TITLE_MAP[ConflictType.ORPHAN_ROUTING_MARK],
                description=DESCRIPTION_MAP[ConflictType.ORPHAN_ROUTING_MARK],
                config_path="/ip firewall mangle",
                details=(
                    f"Routing mark '{mark}' is set by mangle rules but no route "
                    f"references it. Affected rules: {len(setting_rules)}"
                ),
                recommendation=(
                    f"Either add a route with routing-mark={mark}, or remove "
                    f"the mangle rules if the routing mark is no longer needed."
                ),
                fix_commands=[
                    f"# Option 1: Add a route using this routing mark:",
                    f"/ip route add dst-address=0.0.0.0/0 gateway=<gateway> \\",
                    f"    routing-mark={mark} comment=\"Traffic for {mark}\"",
                    f"",
                    f"# Option 2: If mark is unused, review mangle rules:",
                    f"/ip firewall mangle print where new-routing-mark={mark}",
                ],
            ))

    # ── Check 4: INTERFACE_NOT_IN_LIST ─────────────────────────────────

    def _check_interface_not_in_list(self) -> None:
        """Detect active interfaces not assigned to any named interface list.
        
        Interfaces without list membership may bypass firewall rules that
        use in-interface-list / out-interface-list filtering.
        """
        # Get all interfaces (various types)
        interface_paths = [
            "/interface",
            "/interface ethernet",
            "/interface bridge",
            "/interface vlan",
            "/interface wireless",
            "/interface wifi",
            "/interface wireguard",
            "/interface vrrp",
            "/interface bonding",
            "/interface pppoe-client",
            "/interface l2tp-client",
            "/interface ovpn-client",
            "/interface sstp-client",
        ]

        # Collect active interface names
        active_interfaces: Set[str] = set()
        seen_in_paths: Set[str] = set()

        for path in interface_paths:
            for entry in self._get_entries(path):
                if entry.command in ("add", "set"):
                    name = entry.get("name", "")
                    disabled = entry.get("disabled", "")
                    if name and disabled != "yes":
                        active_interfaces.add(name)
                        seen_in_paths.add(name)

        # Also check main /interface for add commands
        for entry in self._get_entries("/interface"):
            if entry.command == "add":
                name = entry.get("name", "")
                iface_type = entry.get("type", "")
                disabled = entry.get("disabled", "")
                if name and disabled != "yes":
                    active_interfaces.add(name)

        if not active_interfaces:
            return

        # Collect interfaces that are members of any named list
        listed_interfaces: Set[str] = set()
        for entry in self._get_entries("/interface list member"):
            iface = entry.get("interface", "")
            if iface:
                listed_interfaces.add(iface)

        # Get the names of existing lists
        list_names: Set[str] = set()
        for entry in self._get_entries("/interface list"):
            name = entry.get("name", "")
            if name:
                list_names.add(name)

        # Find unlisted active interfaces
        unlisted = active_interfaces - listed_interfaces

        # Filter out common pseudo-interfaces that are exempt
        exempt_prefixes = (
            "loopback", "lo", "bridge", "vlan",
            "lte", "wwan", "usb", "pppoe", "pptp",
        )
        unlisted_filtered = {
            i for i in unlisted
            if not any(i.lower().startswith(p) for p in exempt_prefixes)
        }

        for iface in sorted(unlisted_filtered):
            self._conflicts.append(ConflictResult(
                conflict_type=ConflictType.INTERFACE_NOT_IN_LIST,
                severity=SEVERITY_MAP[ConflictType.INTERFACE_NOT_IN_LIST],
                title=TITLE_MAP[ConflictType.INTERFACE_NOT_IN_LIST],
                description=DESCRIPTION_MAP[ConflictType.INTERFACE_NOT_IN_LIST],
                config_path="/interface list member",
                details=(
                    f"Interface '{iface}' is active (enabled) but not assigned to "
                    f"any named interface list. "
                    f"Existing lists: {', '.join(sorted(list_names)) if list_names else 'none defined'}"
                ),
                recommendation=(
                    f"Add '{iface}' to the appropriate interface list (WAN/LAN/MGMT):"
                ),
                fix_commands=[
                    f"/interface list member add list=<list-name> interface={iface} \\",
                    f"    comment=\"Added interface {iface} to list\"",
                    f"# Create a list if needed:",
                    f"/interface list add name=WAN comment=\"WAN-facing interfaces\"",
                ],
            ))

    # ── Check 5: ADDRESS_LIST_CONFLICT ─────────────────────────────────

    def _check_address_list_conflict(self) -> None:
        """Detect same IP address in both allow and block address lists."""
        addr_entries = self._get_entries("/ip firewall address-list")
        v6_addr_entries = self._get_entries("/ipv6 firewall address-list")

        all_entries = addr_entries + v6_addr_entries

        if not all_entries:
            return

        # Categorize addresses by allow/block list membership
        allow_addrs: Dict[str, List[str]] = defaultdict(list)  # ip → list_names
        block_addrs: Dict[str, List[str]] = defaultdict(list)

        for e in all_entries:
            list_name = e.get("list", "").lower()
            address = e.get("address", "")

            if not list_name or not address:
                continue

            # Determine if this is an allow or block list by name heuristics
            is_allow = any(kw in list_name for kw in self.ALLOW_KEYWORDS)
            is_block = any(kw in list_name for kw in self.BLOCK_KEYWORDS)

            if is_allow:
                allow_addrs[address].append(list_name)
            elif is_block:
                block_addrs[address].append(list_name)

        # Find conflicts: same IP in both
        conflicts = set(allow_addrs.keys()) & set(block_addrs.keys())

        for addr in sorted(conflicts):
            self._conflicts.append(ConflictResult(
                conflict_type=ConflictType.ADDRESS_LIST_CONFLICT,
                severity=SEVERITY_MAP[ConflictType.ADDRESS_LIST_CONFLICT],
                title=TITLE_MAP[ConflictType.ADDRESS_LIST_CONFLICT],
                description=DESCRIPTION_MAP[ConflictType.ADDRESS_LIST_CONFLICT],
                config_path="/ip firewall address-list",
                details=(
                    f"IP {addr} appears in allow-list(s): "
                    f"{', '.join(allow_addrs[addr])} "
                    f"AND block-list(s): {', '.join(block_addrs[addr])}. "
                    f"Resolution depends on rule evaluation order."
                ),
                recommendation=(
                    f"Remove '{addr}' from one of the conflicting lists to "
                    f"eliminate ambiguity:"
                ),
                fix_commands=[
                    f"# Check which rules reference these lists:",
                    f"/ip firewall filter print where src-address-list~\"{'|'.join(allow_addrs[addr])}\"",
                    f"/ip firewall filter print where dst-address-list~\"{'|'.join(block_addrs[addr])}\"",
                    f"# Remove from the less-relevant list:",
                    f"/ip firewall address-list remove [find where=address={addr} list~\"allow|whitelist\"]",
                    f"# OR remove from block list:",
                    f"/ip firewall address-list remove [find where=address={addr} list~\"block|blacklist\"]",
                ],
            ))

    # ── Check 6: FORWARD_WITHOUT_FASTTRACK ─────────────────────────────

    def _check_forward_without_fasttrack(self) -> None:
        """Detect when many forward rules exist without a FastTrack rule.
        
        FastTrack improves performance by bypassing the slow path for
        established connections. Without it, all traffic is processed
        through filter/mangle/connection tracking.
        """
        fwd_entries = self._get_entries("/ip firewall filter")
        forward_rules = [
            e for e in fwd_entries
            if e.get("chain", "").lower() == "forward"
               and e.get("action", "") != "fasttrack-connection"
        ]

        if len(forward_rules) < self.FORWARD_RULE_THRESHOLD:
            return

        # Check if ANY rule in the filter table (any chain) has FastTrack
        has_fasttrack = any(
            e.get("action", "").lower() == "fasttrack-connection"
            for e in fwd_entries
        )

        if not has_fasttrack:
            self._conflicts.append(ConflictResult(
                conflict_type=ConflictType.FORWARD_WITHOUT_FASTTRACK,
                severity=SEVERITY_MAP[ConflictType.FORWARD_WITHOUT_FASTTRACK],
                title=TITLE_MAP[ConflictType.FORWARD_WITHOUT_FASTTRACK],
                description=DESCRIPTION_MAP[ConflictType.FORWARD_WITHOUT_FASTTRACK],
                config_path="/ip firewall filter",
                details=(
                    f"Forward chain has {len(forward_rules)} rules but no "
                    f"FastTrack rule is configured. This may impact throughput "
                    f"on high-bandwidth links."
                ),
                recommendation=(
                    "Add a FastTrack rule as the first rule in the forward chain "
                    "to accelerate established connections. NOTE: FastTrack bypasses "
                    "mangle, queue trees, and per-connection queuing. If you use "
                    "these features, FastTrack may not be appropriate."
                ),
                fix_commands=[
                    f"/ip firewall filter add chain=forward \\",
                    f"    connection-state=established,related \\",
                    f"    action=fasttrack-connection \\",
                    f"    comment=\"FastTrack established/related connections\"",
                ],
            ))

    # ── Check 7: SHADOWED_RULE ─────────────────────────────────────────

    def _check_shadowed_rules(self) -> None:
        """Detect rules placed after broader rules that match the same traffic.
        
        A rule shadows another if it comes first and its match conditions
        are a superset of the later rule's conditions. The later rule will
        never be reached.
        """
        fw_paths = [
            "/ip firewall filter",
            "/ip firewall nat",
            "/ip firewall mangle",
        ]
        by_chain = self._get_entries_by_chain(fw_paths)

        for chain, entries in by_chain.items():
            for i in range(len(entries)):
                for j in range(i + 1, len(entries)):
                    earlier = entries[i]
                    later = entries[j]

                    if self._is_shadowing(earlier, later):
                        self._conflicts.append(ConflictResult(
                            conflict_type=ConflictType.SHADOWED_RULE,
                            severity=SEVERITY_MAP[ConflictType.SHADOWED_RULE],
                            title=TITLE_MAP[ConflictType.SHADOWED_RULE],
                            description=DESCRIPTION_MAP[ConflictType.SHADOWED_RULE],
                            config_path=f"chain={chain}",
                            details=(
                                f"Rule ({i+1}) shadows rule ({j+1}):\n"
                                f"  Earlier (broader):  {earlier.raw}\n"
                                f"  Later (narrower):   {later.raw}\n"
                                f"The later rule will never be evaluated."
                            ),
                            recommendation=(
                                "Reorder the rules so the most specific rules come "
                                "first, or remove the shadowed rule if it's redundant."
                            ),
                            fix_commands=[
                                f"# Move the specific rule before the broader rule:",
                                f"/ip firewall {self._path_from_chain(chain)} move \\",
                                f"    [find where=comment=\"{later.get('comment', '(specific)')}\"] \\",
                                f"    [find where=comment=\"{earlier.get('comment', '(broad)')}\"]",
                                f"# Or remove the shadowed rule if unwanted:",
                                f"/ip firewall {self._path_from_chain(chain)} remove \\",
                                f"    [find where=comment=\"{later.get('comment', '(specific)')}\"]",
                            ],
                        ))

    @staticmethod
    def _path_from_chain(chain: str) -> str:
        """Map a chain name back to a firewall table path."""
        chain_lower = chain.lower()
        if chain_lower in ("input", "forward", "output"):
            return "filter"
        elif chain_lower in ("dstnat", "srcnat"):
            return "nat"
        elif chain_lower in ("prerouting", "postrouting", "output"):
            return "mangle"
        return "filter"

    def _is_shadowing(self, earlier: ParsedEntry, later: ParsedEntry) -> bool:
        """Determine if 'earlier' rule shadows 'later' rule.
        
        'earlier' shadows 'later' if:
        1. They are in the same chain
        2. Earlier's match conditions cover ALL conditions of later (superset)
        3. Earlier does NOT have restrictive extra conditions that later lacks
           (e.g., connection-state=established,related is restrictive — earlier
           won't match new connections that later targets)
        
        This is a heuristic — RouterOS rule matching is complex (jumps, 
        address-lists, layer7, dynamic state). The heuristic covers the 
        most common cases of parameter-based shadowing.
        """
        # Build parameter sets for comparison
        earlier_conditions = self._get_match_conditions(earlier)
        later_conditions = self._get_match_conditions(later)

        if not later_conditions:
            # Later rule has no conditions — can't be shadowed (it's a catch-all)
            return False

        if not earlier_conditions:
            # Earlier rule is a catch-all — it shadows everything after it
            return True

        # ── Step 1: Check every condition in later is covered by earlier ──
        for key, later_val in later_conditions.items():
            if key not in earlier_conditions:
                # Earlier doesn't restrict on this key at all — broader match,
                # so this condition is covered (earlier matches more things).
                continue

            earlier_val = earlier_conditions[key]
            if not self._condition_at_least_as_broad(key, earlier_val, later_val):
                # Earlier is narrower on this key — can't shadow
                return False

        # ── Step 2: Check earlier doesn't have restrictive extras ──
        # If earlier has a condition that later doesn't have, earlier is MORE
        # restrictive in that dimension. Packets matching later might NOT match
        # earlier because they fail on this extra condition.
        #
        # Known restrictive parameters that narrow the match:
        RESTRICTIVE_EXTRA_KEYS = {
            "connection-state",
            "connection-mark",
            "src-address-list",
            "dst-address-list",
            "in-interface",
            "out-interface",
            "in-interface-list",
            "out-interface-list",
            "layer7-protocol",
            "content",
            "tcp-mss",
            "packet-size",
            "random",
            "limit",
            "icmp-options",
        }
        
        for key, earlier_val in earlier_conditions.items():
            if key not in later_conditions and key in RESTRICTIVE_EXTRA_KEYS:
                # Earlier has a restrictive extra condition — it won't match
                # packets that fail this condition, so later rules can still be reached.
                return False

        return True

    @staticmethod
    def _get_match_conditions(entry: ParsedEntry) -> Dict[str, str]:
        """Extract only match-condition parameters from an entry.
        
        Excludes: action, comment, disabled, log, log-prefix, etc.
        """
        excluded_keys = {
            "action", "comment", "disabled", "log", "log-prefix",
            "to-addresses", "to-ports", "new-routing-mark", "new-packet-mark",
            "new-connection-mark", "new-dscp", "new-ttl",
            "src-address-list-timeout", "address-list-timeout",
            "place-before", "copy-from",
        }
        return {
            k: v for k, v in entry.params.items()
            if k not in excluded_keys and k in CONDITIONAL_PARAMS
        }

    @staticmethod
    def _condition_at_least_as_broad(key: str, earlier_val: str, later_val: str) -> bool:
        """Check if earlier's condition value is at least as broad as later's.
        
        Examples:
        - dst-port=1000-2000 is broader than dst-port=1500
        - dst-address=0.0.0.0/0 is broader than dst-address=10.0.0.0/24
        - No protocol is broader than protocol=tcp
        - src-address=10.0.0.0/8 is broader than src-address=10.0.1.0/24
        """
        # If earlier value equals later value, they're the same breadth
        if earlier_val == later_val:
            return True

        # Handle IP/CIDR comparisons
        if key in ("src-address", "dst-address", "address"):
            return ConflictAnalyzer._cidr_at_least_as_broad(earlier_val, later_val)

        # Handle port range comparisons
        if key in ("src-port", "dst-port", "port"):
            return ConflictAnalyzer._port_at_least_as_broad(earlier_val, later_val)

        # For multi-value params like connection-state=established,related
        # If earlier has more values, it's broader
        if "," in earlier_val or "," in later_val:
            earlier_set = set(earlier_val.split(","))
            later_set = set(later_val.split(","))
            # Earlier is at least as broad if it covers all of later's values
            return later_set.issubset(earlier_set) or not later_set

        # For other params (protocol, interface, etc.), if values differ,
        # we can't confidently say which is broader — return False (no shadow)
        return False

    @staticmethod
    def _cidr_at_least_as_broad(earlier: str, later: str) -> bool:
        """Check if earlier CIDR/IP is at least as broad as later."""
        try:
            from ipaddress import ip_network, ip_address

            # Handle single IPs (convert to /32 or /128)
            def to_net(val: str) -> Any:
                if "/" in val:
                    return ip_network(val, strict=False)
                else:
                    return ip_network(f"{val}/32" if "." in val else f"{val}/128",
                                      strict=False)

            e_net = to_net(earlier)
            l_net = to_net(later)

            # Earlier is broader if it covers all of later's addresses
            return e_net.supernet_of(l_net)
        except (ImportError, ValueError):
            # Fallback: compare prefix length
            e_prefix = earlier.split("/")[1] if "/" in earlier else "32"
            l_prefix = later.split("/")[1] if "/" in later else "32"
            try:
                return int(e_prefix) <= int(l_prefix)
            except ValueError:
                return False

    @staticmethod
    def _port_at_least_as_broad(earlier: str, later: str) -> bool:
        """Check if earlier port range/set is at least as broad as later.
        
        Handles: single port, port range (start-end), port list (p1,p2,p3).
        """
        try:
            e_ranges = ConflictAnalyzer._port_to_ranges(earlier)
            l_ranges = ConflictAnalyzer._port_to_ranges(later)

            # Earlier covers later if every port in later is within earlier's ranges
            for l_start, l_end in l_ranges:
                covered = any(
                    e_start <= l_start and e_end >= l_end
                    for e_start, e_end in e_ranges
                )
                if not covered:
                    return False
            return True
        except (ValueError, IndexError):
            return False

    @staticmethod
    def _port_to_ranges(port_str: str) -> List[Tuple[int, int]]:
        """Convert a port specification to a list of (start, end) ranges.
        
        Examples:
        "80" → [(80, 80)]
        "80-90" → [(80, 90)]
        "22,80,443" → [(22, 22), (80, 80), (443, 443)]
        "80,443-450" → [(80, 80), (443, 450)]
        """
        ranges: List[Tuple[int, int]] = []
        parts = port_str.split(",")
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                start_s, end_s = part.split("-", 1)
                start = int(start_s.strip())
                end = int(end_s.strip())
                ranges.append((min(start, end), max(start, end)))
            else:
                p = int(part)
                ranges.append((p, p))
        return ranges

    # ── Check 8: DUPLICATE_RULE ────────────────────────────────────────

    def _check_duplicate_rules(self) -> None:
        """Detect rules with identical match parameters (ignoring comments).
        
        Duplicate rules provide no additional security or functionality
        and waste hardware resources (TCAM entries, connection tracking slots).
        """
        fw_paths = [
            "/ip firewall filter",
            "/ip firewall nat",
            "/ip firewall mangle",
            "/ip firewall raw",
        ]
        by_chain = self._get_entries_by_chain(fw_paths)

        for chain, entries in by_chain.items():
            # Build signature → list of (index, entry)
            sig_map: Dict[str, List[Tuple[int, ParsedEntry]]] = defaultdict(list)

            for idx, entry in enumerate(entries):
                sig = self._rule_signature(entry)
                sig_map[sig].append((idx, entry))

            # Report duplicates
            for sig, matches in sig_map.items():
                if len(matches) < 2:
                    continue

                # First occurrence is the original; rest are duplicates
                original = matches[0][1]
                for dup_idx, dup_entry in matches[1:]:
                    self._conflicts.append(ConflictResult(
                        conflict_type=ConflictType.DUPLICATE_RULE,
                        severity=SEVERITY_MAP[ConflictType.DUPLICATE_RULE],
                        title=TITLE_MAP[ConflictType.DUPLICATE_RULE],
                        description=DESCRIPTION_MAP[ConflictType.DUPLICATE_RULE],
                        config_path=f"chain={chain}",
                        details=(
                            f"Duplicate of rule #{original.get('comment', matches[0][1].raw)}:\n"
                            f"  Original: {original.raw}\n"
                            f"  Duplicate: {dup_entry.raw}"
                        ),
                        recommendation=(
                            "Remove the duplicate rule. It provides no additional "
                            "security or functionality."
                        ),
                        fix_commands=[
                            f"# Remove the duplicate rule:",
                            f"/ip firewall {self._path_from_chain(chain)} remove \\",
                            f"    [find where=comment=\"{dup_entry.get('comment', '')}\"",
                            f"    and chain={chain} and action={dup_entry.get('action', '')}]",
                            f"# Or if you want to keep only one, use the original.",
                        ],
                    ))

    @staticmethod
    def _rule_signature(entry: ParsedEntry) -> str:
        """Create a normalized signature for duplicate detection.
        
        Uses a normalized set of match parameters, sorted for consistency.
        Comment and log-prefix fields are excluded to allow for descriptive
        differences while detecting functional duplicates.
        """
        parts = []
        for key in SIGNATURE_PARAMS:
            val = entry.get(key)
            if val:
                # Normalize: strip whitespace, lowercase (RouterOS is case-insensitive
                # for most values, but keeps case for some like comments)
                parts.append(f"{key}={val.strip()}")
        return "|".join(sorted(parts))


# ═══════════════════════════════════════════════════════════════════════════
# Convenience function
# ═══════════════════════════════════════════════════════════════════════════


def analyze_config_sections(sections: List[Dict[str, Any]]) -> List[ConflictResult]:
    """One-shot convenience: create analyzer, load, analyze.
    
    Args:
        sections: List of dicts with "path" and "lines" keys
    
    Returns:
        List of ConflictResult objects
    """
    analyzer = ConflictAnalyzer()
    analyzer.load_data(sections)
    return analyzer.analyze()


def analyze_raw_rsc(content: str) -> List[ConflictResult]:
    """One-shot convenience: parse raw .rsc content and analyze.
    
    Args:
        content: The full text content of a .rsc export file
    
    Returns:
        List of ConflictResult objects
    """
    analyzer = ConflictAnalyzer()
    analyzer.load_data([{"raw": content, "_is_raw": True}])
    return analyzer.analyze()


# ═══════════════════════════════════════════════════════════════════════════
# CLI Entry Point (for standalone testing)
# ═══════════════════════════════════════════════════════════════════════════


def main() -> None:
    """CLI entry point for standalone conflict analysis."""
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(
        description="MikroTik RouterOS .rsc Conflict Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python conflict_analyzer.py export.rsc
  python conflict_analyzer.py export.rsc --format json
  python conflict_analyzer.py export.rsc --type duplicate_rule
        """,
    )
    parser.add_argument("file", help="Path to .rsc configuration file")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--type", help="Filter by conflict type (e.g., duplicate_rule)")
    parser.add_argument("-o", "--output", help="Output file path")

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    with open(args.file, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    results = analyze_raw_rsc(content)

    # Apply type filter
    if args.type:
        try:
            target_type = ConflictType(args.type.lower())
            results = [r for r in results if r.conflict_type == target_type]
        except ValueError:
            valid = ", ".join(t.value for t in ConflictType)
            print(f"Error: Invalid conflict type '{args.type}'. "
                  f"Valid: {valid}", file=sys.stderr)
            sys.exit(1)

    if args.format == "json":
        output = json.dumps(
            [r.to_dict() for r in results],
            indent=2,
        )
    else:
        lines = []
        lines.append("=" * 76)
        lines.append("  MikroTik RouterOS .rsc Conflict Analysis Report")
        lines.append(f"  File: {args.file}")
        lines.append(f"  Conflicts found: {len(results)}")
        lines.append("=" * 76)

        if not results:
            lines.append("\n  No conflicts detected.")
        else:
            # Summary by severity
            sev_counts: Dict[str, int] = defaultdict(int)
            type_counts: Dict[str, int] = defaultdict(int)
            for r in results:
                sev_counts[r.severity] += 1
                type_counts[r.conflict_type.value] += 1

            lines.append(f"\n  Severity breakdown: {dict(sev_counts)}")
            lines.append(f"  Type breakdown: {dict(type_counts)}")

            for r in results:
                lines.append(f"\n{'─' * 76}")
                lines.append(f"  [{r.severity}] {r.title}")
                lines.append(f"{'─' * 76}")
                lines.append(f"  Path: {r.config_path}")
                lines.append(f"  {r.description}")
                lines.append(f"  Detail: {r.details}")
                lines.append(f"  Recommendation: {r.recommendation}")
                if r.fix_commands:
                    for cmd in r.fix_commands:
                        lines.append(f"  → {cmd}")

        lines.append(f"\n{'=' * 76}")
        output = "\n".join(lines)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Report written to {args.output}")
    else:
        print(output)

    # Exit non-zero if High or Critical conflicts found
    high_crit = sum(1 for r in results if r.severity in ("High", "Critical"))
    if high_crit > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
