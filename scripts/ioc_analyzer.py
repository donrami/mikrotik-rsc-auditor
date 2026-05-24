#!/usr/bin/env python3
"""
IoC (Indicators of Compromise) Analyzer for MikroTik RouterOS
==============================================================
Detects signs of active compromise in static .rsc configuration exports.

Based on known RouterOS malware patterns:
- VPNFilter (2018) — used scheduler + fetch for persistence
- Meris botnet (2021) — SOCKS proxy + HTTP proxy for C2 traffic relay
- Various cryptominers — DNS references to mining pools, scheduler tasks

Severity Rationale
------------------
SOCKS and HTTP proxy are classified as IoC (Critical/High) rather than
service hardening issues. These services are rarely intentionally enabled
on production routers and are a primary indicator of active compromise.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class IoCType(Enum):
    """Types of IoC indicators detected by this module."""

    SCHEDULER_FETCH_BACKDOOR = "SCHEDULER_FETCH_BACKDOOR"
    """Scheduler task executes fetch to HTTP URL — VPNFilter persistence pattern."""

    SCHEDULER_SCRIPT_RUN = "SCHEDULER_SCRIPT_RUN"
    """Scheduler task runs /system script run — persistence mechanism."""

    SOCKS_PROXY_ENABLED = "SOCKS_PROXY_ENABLED"
    """SOCKS proxy enabled — Meris botnet C2 relay pattern."""

    HTTP_PROXY_ENABLED = "HTTP_PROXY_ENABLED"
    """HTTP proxy enabled — traffic interception / C2 channel."""

    SUSPICIOUS_FILES = "SUSPICIOUS_FILES"
    """Files with non-standard extensions (.php, .exe, .sh, .py, .pl, .rb)."""

    UNKNOWN_FULL_ACCESS_USER = "UNKNOWN_FULL_ACCESS_USER"
    """User in group=full not in the known set of authorized admins."""

    DNS_HIJACKING = "DNS_HIJACKING"
    """Static DNS entries pointing to known malicious or C2 domains."""

    FILTER_SNIFF_RULE = "FILTER_SNIFF_RULE"
    """Filter rules with action=sniff — traffic interception; review if intentional."""

    CRYPTOMINER_INDICATORS = "CRYPTOMINER_INDICATORS"
    """DNS or scheduler content referencing known cryptomining pools."""

    C2_PATTERN_RECOGNITION = "C2_PATTERN_RECOGNITION"
    """Script source or scheduler on-event containing IP:port, Telegram, or Discord."""


@dataclass
class IoCResult:
    """Result of a single IoC detection check."""

    ioc_type: IoCType
    severity: str  # Critical, High, Medium, Low
    title: str
    description: str
    evidence: str
    recommendation: str
    remediation_commands: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


# ── Known threat domain lists ──────────────────────────────────────────────

KNOWN_MALICIOUS_DOMAINS: Dict[str, str] = {
    "check-host.net": "Used in RouterOS attacks for connectivity checks",
    "ip-api.com": "Used by malware for IP geolocation / C2 beaconing",
    "api.ipify.org": "Used for external IP exfiltration",
    "pastebin.com": "Used for payload delivery and C2 instruction retrieval",
    "raw.githubusercontent.com": "Used for downloading malicious scripts",
}

CRYPTOMINER_POOL_DOMAINS: Dict[str, str] = {
    "pool.minexmr.com": "Monero mining pool",
    "xmr.pool.minergate.com": "Monero mining pool",
    "pool.hashvault.pro": "Monero mining pool",
    "supportxmr.com": "Monero mining pool",
    "nanopool.org": "Multi-coin mining pool",
    "nicehash.com": "Hashrate marketplace (may be used legitimately)",
}

C2_DOMAIN_PATTERNS: List[str] = [
    r"t\.me/",
    r"telegram\.org/bot",
    r"discord\.com/api/webhooks",
]

C2_IP_PORT_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{4,5}\b")

# ── Suspicious file extensions ──────────────────────────────────────────────

SUSPICIOUS_EXTENSIONS: List[str] = [
    ".php", ".exe", ".sh", ".py", ".pl", ".rb",
    ".elf", ".bin",
    ".scr", ".jar",
]

# ── Regex helpers ───────────────────────────────────────────────────────────

_RE_FETCH_URL = re.compile(r"fetch\s+https?://", re.IGNORECASE)
_RE_SCRIPT_RUN = re.compile(r"/system\s+script\s+run", re.IGNORECASE)
_RE_SOCKS_ENABLED = re.compile(r"enabled\s*=\s*(yes|true)", re.IGNORECASE)
_RE_PROXY_ENABLED = re.compile(r"enabled\s*=\s*(yes|true)", re.IGNORECASE)
_RE_USER_FULL = re.compile(r"group\s*=\s*full", re.IGNORECASE)
_RE_USER_NAME = re.compile(r"name\s*=\s*\"?([^\"\s]+)\"?", re.IGNORECASE)
_RE_DNS_STATIC_ADDR = re.compile(r"address\s*=\s*\"?([^\"\s]+)\"?", re.IGNORECASE)
_RE_DNS_STATIC_NAME = re.compile(r"name\s*=\s*\"?([^\"\s]+)\"?", re.IGNORECASE)
_RE_FILTER_ACTION_SNIFF = re.compile(r"action\s*=\s*sniff", re.IGNORECASE)
_RE_FILTER_ACTION_TARPIT = re.compile(r"action\s*=\s*tarpit", re.IGNORECASE)
_RE_FILE_NAME = re.compile(r"name\s*=\s*\"?([^\"\s]+)\"?", re.IGNORECASE)
_RE_DOMAIN_IN_STRING = re.compile(r"https?://([^/\s\"']+)", re.IGNORECASE)


def _extract_param(line: str, param: str) -> Optional[str]:
    """Extract the value of a RouterOS parameter from a line."""
    m = re.search(rf"\b{re.escape(param)}\s*=\s*\"?([^\"\s]+)\"?", line, re.IGNORECASE)
    return m.group(1) if m else None


class IoCAnalyzer:
    """
    Analyzes parsed .rsc configuration sections for indicators of compromise.

    Usage:
        analyzer = IoCAnalyzer()
        analyzer.load_data(sections_dict)
        iocs = analyzer.analyze()
    """

    def __init__(self):
        self.sections: Dict[str, List[str]] = {}
        # Known legitimate admin usernames — configurable
        self.known_users: set = {"admin"}

    def load_data(self, sections: Dict[str, List[str]]) -> None:
        """Load parsed .rsc sections keyed by config path."""
        self.sections = sections

    def analyze(self) -> List[IoCResult]:
        """Run all IoC checks and return findings."""
        results: List[IoCResult] = []
        results.extend(self._check_scheduler_backdoor())
        results.extend(self._check_scheduler_script_run())
        results.extend(self._check_socks_proxy())
        results.extend(self._check_http_proxy())
        results.extend(self._check_suspicious_files())
        results.extend(self._check_unknown_users())
        results.extend(self._check_dns_hijacking())
        results.extend(self._check_filter_sniff())
        results.extend(self._check_cryptominer())
        results.extend(self._check_c2_patterns())
        return results

    # ── 1. Scheduler Fetch Backdoor ────────────────────────────────────────

    def _check_scheduler_backdoor(self) -> List[IoCResult]:
        """
        Detect scheduler tasks that fetch from HTTP URLs.

        VPNFilter and similar malware persist by scheduling a task that
        periodically fetches a new payload or C2 instruction set.
        """
        results: List[IoCResult] = []
        lines = self.sections.get("scheduler", [])

        for line in lines:
            if _RE_FETCH_URL.search(line):
                name = _extract_param(line, "name") or "unknown"
                on_event = _extract_param(line, "on-event") or _extract_param(line, "on_event") or ""
                results.append(IoCResult(
                    ioc_type=IoCType.SCHEDULER_FETCH_BACKDOOR,
                    severity="Critical",
                    title=f"Scheduler fetch backdoor detected: '{name}'",
                    description=(
                        f"Scheduler task '{name}' executes fetch to an HTTP(S) URL. "
                        "This is the primary persistence mechanism used by VPNFilter and other "
                        "RouterOS malware. The task downloads and potentially executes remote payloads. "
                        "This should NEVER appear in a legitimate configuration."
                    ),
                    evidence=f"Scheduler '{name}': on-event={on_event[:200]}",
                    recommendation=(
                        "This is a strong indicator of active compromise. "
                        "1. Immediately remove this scheduler task. "
                        "2. Check for downloaded files on the router. "
                        "3. Review all user accounts. "
                        "4. Consider a factory reset and reconfiguration from trusted backup."
                    ),
                    remediation_commands=[
                        f'/system scheduler remove [find name="{name}"]',
                        "# Check for downloaded files",
                        "/file print detail",
                        "# Review system logs for fetch activity",
                        "/log print where topics~\"system,info\"",
                        "# Review all users for unauthorized accounts",
                        "/user print detail",
                    ],
                    references=[
                        "https://www.cisco.com/c/en/us/support/docs/security/vpnfilter/213905-vpnfilter-malware.html",
                        "https://www.us-cert.gov/ncas/alerts/TA18-141A",
                    ],
                ))
        return results

    # ── 2. Scheduler Script Run ────────────────────────────────────────────

    def _check_scheduler_script_run(self) -> List[IoCResult]:
        """
        Detect scheduler tasks that execute local scripts.

        While legitimate maintenance scripts exist, this is also a common
        persistence pattern for RouterOS implants.
        """
        results: List[IoCResult] = []
        lines = self.sections.get("scheduler", [])

        for line in lines:
            if _RE_SCRIPT_RUN.search(line):
                name = _extract_param(line, "name") or "unknown"
                on_event = _extract_param(line, "on-event") or _extract_param(line, "on_event") or ""
                results.append(IoCResult(
                    ioc_type=IoCType.SCHEDULER_SCRIPT_RUN,
                    severity="High",
                    title=f"Scheduled script execution: '{name}'",
                    description=(
                        f"Scheduler task '{name}' executes /system script run. "
                        "While this can be legitimate (e.g., daily backup), it is also "
                        "used by malware for persistence. Verify the script being executed "
                        "is authorized and documented."
                    ),
                    evidence=f"Scheduler '{name}': on-event={on_event[:200]}",
                    recommendation=(
                        "Review the target script for malicious content. "
                        "If this task was not intentionally configured, "
                        "investigate as a potential persistence mechanism."
                    ),
                    remediation_commands=[
                        f"/system scheduler print detail where name=\"{name}\"",
                        "# Review the script being executed",
                        "/system script print detail",
                        "# If unauthorized, remove",
                        f'/system scheduler remove [find name="{name}"]',
                    ],
                ))
        return results

    # ── 3. SOCKS Proxy Enabled ─────────────────────────────────────────────

    def _check_socks_proxy(self) -> List[IoCResult]:
        """
        Detect SOCKS proxy service enabled.

        The Meris botnet (2021) and other RouterOS malware enable SOCKS proxy
        to route C2 traffic through compromised routers. SOCKS should NEVER be
        enabled on production routers.
        """
        results: List[IoCResult] = []
        lines = self.sections.get("ip socks", [])

        for line in lines:
            if _RE_SOCKS_ENABLED.search(line) and not line.strip().startswith("#"):
                results.append(IoCResult(
                    ioc_type=IoCType.SOCKS_PROXY_ENABLED,
                    severity="Critical",
                    title="SOCKS proxy is enabled — possible Meris/compromise indicator",
                    description=(
                        "SOCKS proxy service is enabled on the router. "
                        "This is a STRONG indicator of active compromise. "
                        "The Meris botnet (2021) and other RouterOS malware enable "
                        "SOCKS proxy to relay C2 traffic and provide anonymous access "
                        "through the compromised router. SOCKS is very rarely needed "
                        "in legitimate RouterOS configurations."
                    ),
                    evidence=f"SOCKS config line: {line.strip()[:200]}",
                    recommendation=(
                        "Disable SOCKS proxy immediately unless you have an explicit, "
                        "documented business need. Investigate how it was enabled."
                    ),
                    remediation_commands=[
                        "/ip socks set enabled=no",
                        "# Review SOCKS access rules",
                        "/ip socks access-list print",
                        "# Check for unauthorized users",
                        "/user print detail",
                        "# Review system logs",
                        "/log print where topics~\"system,error,critical\"",
                    ],
                    references=[
                        "https://blog.cloudflare.com/meris-botnet/",
                        "https://www.mikrotik.com/security/advisories/socks-proxy-abuse/",
                    ],
                ))
        return results

    # ── 4. HTTP Proxy Enabled ──────────────────────────────────────────────

    def _check_http_proxy(self) -> List[IoCResult]:
        """
        Detect HTTP proxy service enabled.

        HTTP proxy on RouterOS is often used by malware for C2 communication
        and traffic interception. While it has legitimate uses (caching, content
        filtering), it should be intentionally configured and documented.
        """
        results: List[IoCResult] = []
        lines = self.sections.get("ip proxy", [])

        for line in lines:
            if _RE_PROXY_ENABLED.search(line) and not line.strip().startswith("#"):
                results.append(IoCResult(
                    ioc_type=IoCType.HTTP_PROXY_ENABLED,
                    severity="High",
                    title="HTTP proxy is enabled — potential C2 channel",
                    description=(
                        "HTTP proxy service is enabled on the router. "
                        "While HTTP proxy has legitimate use cases (caching, content filtering), "
                        "it is also used by malware as a C2 relay and traffic interception point. "
                        "Verify this was intentionally configured and documented."
                    ),
                    evidence=f"Proxy config line: {line.strip()[:200]}",
                    recommendation=(
                        "Disable HTTP proxy unless you have an explicit documented need. "
                        "Review proxy access rules for unauthorized entries."
                    ),
                    remediation_commands=[
                        "/ip proxy set enabled=no",
                        "# Review proxy access rules",
                        "/ip proxy access-list print",
                        "# Check for suspicious cache entries",
                        "/ip proxy cache print",
                    ],
                ))
        return results

    # ── 5. Suspicious Files ────────────────────────────────────────────────

    def _check_suspicious_files(self) -> List[IoCResult]:
        """
        Detect files with suspicious extensions on the router filesystem.

        RouterOS is not a general-purpose OS — .php, .exe, .py, .sh, .pl files
        have NO legitimate purpose on the device. Their presence indicates
        that malware has been uploaded.
        """
        results: List[IoCResult] = []
        lines = self.sections.get("file", [])

        for line in lines:
            name = _extract_param(line, "name") or ""
            if not name:
                continue

            for ext in SUSPICIOUS_EXTENSIONS:
                if name.lower().endswith(ext):
                    results.append(IoCResult(
                        ioc_type=IoCType.SUSPICIOUS_FILES,
                        severity="High",
                        title=f"Suspicious file on router: '{name}'",
                        description=(
                            f"File '{name}' has extension '{ext}' which has no legitimate "
                            "purpose on RouterOS. This is a strong indicator that malware "
                            "has been uploaded to the device."
                        ),
                        evidence=f"File: {name} (extension: {ext})",
                        recommendation=(
                            "Immediately remove the file and investigate how it arrived. "
                            "Check system logs for upload activity and review user accounts."
                        ),
                        remediation_commands=[
                            f'/file remove "{name}"',
                            "# Check for other suspicious files",
                            "/file print detail",
                            "# Review logs for file upload activity",
                            "/log print where topics~\"system,error\"",
                        ],
                    ))
                    break
        return results

    # ── 6. Unknown Full-Access Users ───────────────────────────────────────

    def _check_unknown_users(self) -> List[IoCResult]:
        """
        Detect user accounts with group=full that are not in the known set.

        Attackers create backdoor admin accounts for persistent access.
        """
        results: List[IoCResult] = []
        lines = self.sections.get("user", [])

        for line in lines:
            if not _RE_USER_FULL.search(line):
                continue
            name_match = _RE_USER_NAME.search(line)
            if not name_match:
                continue
            username = name_match.group(1)

            if username not in self.known_users:
                results.append(IoCResult(
                    ioc_type=IoCType.UNKNOWN_FULL_ACCESS_USER,
                    severity="Critical",
                    title=f"Unknown user with full admin access: '{username}'",
                    description=(
                        f"User '{username}' has group=full (administrator) but is not "
                        f"in the known set of authorized admins: {self.known_users}. "
                        "This may indicate an attacker-created backdoor account."
                    ),
                    evidence=f"User config: {line.strip()[:200]}",
                    recommendation=(
                        "If this user is not authorized, disable immediately. "
                        "Check when the account was created and by whom."
                    ),
                    remediation_commands=[
                        f'/user disable [find name="{username}"]',
                        "# If unauthorized, remove the account",
                        f'/user remove [find name="{username}"]',
                        "# Review all users",
                        "/user print detail",
                    ],
                ))
        return results

    # ── 7. DNS Hijacking ──────────────────────────────────────────────────

    def _check_dns_hijacking(self) -> List[IoCResult]:
        """
        Detect static DNS entries pointing to known malicious domains.

        RouterOS malware often adds static DNS entries to hijack traffic
        to attacker-controlled servers or to resolve C2 domains.
        """
        results: List[IoCResult] = []
        lines = self.sections.get("ip dns static", [])

        for line in lines:
            name = _extract_param(line, "name") or _extract_param(line, "regexp") or ""
            address = _extract_param(line, "address") or ""
            if not name and not address:
                continue

            # Check if the domain name matches known malicious domains
            for malicious_domain, description in KNOWN_MALICIOUS_DOMAINS.items():
                if malicious_domain in name.lower():
                    results.append(IoCResult(
                        ioc_type=IoCType.DNS_HIJACKING,
                        severity="High",
                        title=f"DNS static entry for known malicious domain: '{name}'",
                        description=(
                            f"Static DNS entry '{name}' → {address} points to "
                            f"'{malicious_domain}', which is a known malicious domain. "
                            f"Context: {description}. "
                            "This may be traffic hijacking or C2 resolution."
                        ),
                        evidence=f"DNS static: {line.strip()[:200]}",
                        recommendation=(
                            "Remove this DNS entry immediately. "
                            "Investigate which device or service uses this resolution."
                        ),
                        remediation_commands=[
                            f'/ip dns static remove [find name="{name}"]',
                            "# Check all DNS entries",
                            "/ip dns static print detail",
                        ],
                    ))
                    break

            # Check for IP-only static entries with suspicious addresses
            # (common malware C2 pattern — bare IP entry with no domain)
            if address and not name:
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", address):
                    results.append(IoCResult(
                        ioc_type=IoCType.DNS_HIJACKING,
                        severity="Medium",
                        title=f"Suspicious IP-only DNS static entry: {address}",
                        description=(
                            f"DNS static entry contains an IP address ({address}) "
                            "with no domain name. This pattern is used by malware "
                            "to redirect traffic or resolve C2 endpoints."
                        ),
                        evidence=f"DNS static: {line.strip()[:200]}",
                        recommendation=(
                            "Verify this DNS entry is intentional. "
                            "If unauthorized, remove it."
                        ),
                        remediation_commands=[
                            f'/ip dns static remove [find address="{address}"]',
                        ],
                    ))
        return results

    # ── 8. Filter Sniff Rules ─────────────────────────────────────────────

    def _check_filter_sniff(self) -> List[IoCResult]:
        """
        Detect filter rules with action=sniff or action=tarpit.

        Unlike our previous check on the mangle table (which does NOT support
        action=sniff or action=tarpit — those are filter-only), this correctly
        inspects the /ip firewall filter table.

        action=sniff performs packet mirroring/traffic interception. In the
        filter table this has legitimate diagnostic uses (mirroring traffic
        to a monitoring port), but it should always be intentionally configured
        and documented. Raised as Medium severity IoC rather than Critical
        because sniff in the filter table is a standard RouterOS feature,
        unlike SOCKS/proxy which are near-certain compromise indicators.
        """
        results: List[IoCResult] = []
        lines = self.sections.get("ip firewall filter", [])

        for line in lines:
            if _RE_FILTER_ACTION_SNIFF.search(line):
                results.append(IoCResult(
                    ioc_type=IoCType.FILTER_SNIFF_RULE,
                    severity="Medium",
                    title="Filter rule with action=sniff — traffic mirroring",
                    description=(
                        "A firewall filter rule with action=sniff is configured. "
                        "This enables packet mirroring/traffic interception. "
                        "While sniff has legitimate uses (e.g., port mirroring to "
                        "a monitoring appliance), verify this rule is intentionally "
                        "configured and documented."
                    ),
                    evidence=f"Filter rule: {line.strip()[:200]}",
                    recommendation=(
                        "Verify this rule is part of an authorized monitoring setup. "
                        "If unauthorized, this may indicate traffic interception."
                    ),
                    remediation_commands=[
                        "/ip firewall filter print where action=sniff",
                        "# Review if sniff is authorized",
                        "/ip firewall filter remove [find action=sniff]",
                    ],
                ))

            if _RE_FILTER_ACTION_TARPIT.search(line):
                results.append(IoCResult(
                    ioc_type=IoCType.FILTER_SNIFF_RULE,
                    severity="Low",
                    title="Filter rule with action=tarpit — unusual configuration",
                    description=(
                        "A firewall filter rule with action=tarpit is configured. "
                        "Tarpit slows down TCP connections by sending a TCP RST, "
                        "which is a legitimate anti-scanning technique. However, "
                        "it can also be used maliciously to interfere with specific "
                        "traffic flows. Verify intentionality."
                    ),
                    evidence=f"Filter rule: {line.strip()[:200]}",
                    recommendation=(
                        "Review this rule to ensure it is intentionally configured "
                        "as part of your network security policy."
                    ),
                    remediation_commands=[
                        "# Review all tarpit rules",
                        "/ip firewall filter print where action=tarpit",
                    ],
                ))
        return results

    # ── 9. Cryptominer Indicators ─────────────────────────────────────────

    def _check_cryptominer(self) -> List[IoCResult]:
        """
        Detect references to known cryptomining pools in DNS static entries,
        scheduler tasks, or script source code.

        RouterOS cryptominer malware adds DNS entries or scheduler tasks
        pointing to mining pool domains.
        """
        results: List[IoCResult] = []

        # Check DNS static entries
        dns_lines = self.sections.get("ip dns static", [])
        for line in dns_lines:
            name = _extract_param(line, "name") or ""
            for pool_domain, pool_desc in CRYPTOMINER_POOL_DOMAINS.items():
                if pool_domain in name.lower():
                    address = _extract_param(line, "address") or "unknown"
                    results.append(IoCResult(
                        ioc_type=IoCType.CRYPTOMINER_INDICATORS,
                        severity="High",
                        title=f"Cryptominer DNS entry for {pool_domain}",
                        description=(
                            f"Static DNS entry for '{pool_domain}' ({pool_desc}). "
                            "This is a known cryptomining pool domain. "
                            "RouterOS cryptominer malware resolves the pool address "
                            "through the router's DNS service."
                        ),
                        evidence=f"DNS static: name={name}, address={address}",
                        recommendation=(
                            "Remove this DNS entry immediately. "
                            "Check for cryptominer software on connected devices."
                        ),
                        remediation_commands=[
                            f'/ip dns static remove [find name="{name}"]',
                            "# Check for other mining pool entries",
                            "/ip dns static print detail",
                        ],
                    ))
                    break

        # Check scheduler content for mining pool URLs
        scheduler_lines = self.sections.get("scheduler", [])
        for line in scheduler_lines:
            on_event = _extract_param(line, "on-event") or _extract_param(line, "on_event") or ""
            name = _extract_param(line, "name") or "unknown"
            for pool_domain, pool_desc in CRYPTOMINER_POOL_DOMAINS.items():
                if pool_domain in on_event.lower():
                    results.append(IoCResult(
                        ioc_type=IoCType.CRYPTOMINER_INDICATORS,
                        severity="Critical",
                        title=f"Cryptominer scheduler task: '{name}' references {pool_domain}",
                        description=(
                            f"Scheduler task '{name}' references '{pool_domain}' "
                            f"({pool_desc}) in its on-event script. "
                            "This is a strong indicator of active cryptominer infection."
                        ),
                        evidence=f"Scheduler '{name}': on-event contains {pool_domain}",
                        recommendation=(
                            "Immediately remove this scheduler task. "
                            "This indicates active cryptomining on the router."
                        ),
                        remediation_commands=[
                            f'/system scheduler remove [find name="{name}"]',
                            "# Check for mining files",
                            "/file print detail",
                        ],
                    ))
                    break

        return results

    # ── 10. C2 Pattern Recognition ────────────────────────────────────────

    def _check_c2_patterns(self) -> List[IoCResult]:
        """
        Detect C2 communication patterns in scripts and scheduler content.

        Looks for:
        - IP:port patterns (common C2 endpoint format)
        - Telegram bot API URLs
        - Discord webhook URLs
        """
        results: List[IoCResult] = []

        # Check scheduler on-event content
        scheduler_lines = self.sections.get("scheduler", [])
        for line in scheduler_lines:
            on_event = _extract_param(line, "on-event") or _extract_param(line, "on_event") or ""
            name = _extract_param(line, "name") or "unknown"

            # Check for IP:port patterns
            ip_port_matches = C2_IP_PORT_PATTERN.findall(on_event)
            if ip_port_matches:
                for match in ip_port_matches:
                    results.append(IoCResult(
                        ioc_type=IoCType.C2_PATTERN_RECOGNITION,
                        severity="Critical",
                        title=f"C2 endpoint detected in scheduler '{name}': {match}",
                        description=(
                            f"Scheduler task '{name}' contains IP:port pattern '{match}' "
                            "in its on-event script. This format is commonly used for "
                            "C2 communication in RouterOS malware."
                        ),
                        evidence=f"Scheduler '{name}': on-event contains {match}",
                        recommendation=(
                            "This is a strong indicator of C2 communication. "
                            "Remove the scheduler task and investigate."
                        ),
                        remediation_commands=[
                            f'/system scheduler remove [find name="{name}"]',
                            "# Check for unauthorized outbound connections",
                            "/ip firewall connection print where dst-port~\"^[0-9]{4,5}$\"",
                        ],
                    ))

            # Check for Telegram bot URLs
            for c2_pattern in C2_DOMAIN_PATTERNS:
                if c2_pattern in on_event.lower():
                    results.append(IoCResult(
                        ioc_type=IoCType.C2_PATTERN_RECOGNITION,
                        severity="Critical",
                        title=f"C2 channel detected in scheduler '{name}': {c2_pattern}",
                        description=(
                            f"Scheduler task '{name}' contains a known C2 channel pattern "
                            f"('{c2_pattern}') in its on-event script. "
                            "This is used for exfiltration and command reception."
                        ),
                        evidence=f"Scheduler '{name}': on-event contains {c2_pattern}",
                        recommendation=(
                            "Immediately remove this scheduler task. "
                            "This indicates active C2 communication."
                        ),
                        remediation_commands=[
                            f'/system scheduler remove [find name="{name}"]',
                        ],
                    ))
                    break

        # Check script source content for C2 patterns
        script_lines = self.sections.get("system script", [])
        for line in script_lines:
            source = _extract_param(line, "source") or ""
            name = _extract_param(line, "name") or "unknown"

            # Truncate very long source for evidence
            source_preview = source[:300] if len(source) > 300 else source

            # Check for IP:port in script source
            ip_port_matches = C2_IP_PORT_PATTERN.findall(source)
            if ip_port_matches:
                for match in ip_port_matches:
                    results.append(IoCResult(
                        ioc_type=IoCType.C2_PATTERN_RECOGNITION,
                        severity="Critical",
                        title=f"C2 endpoint in script '{name}': {match}",
                        description=(
                            f"Script '{name}' contains IP:port pattern '{match}' "
                            "in its source code. This format is commonly used for "
                            "C2 communication."
                        ),
                        evidence=f"Script '{name}': source contains {match}",
                        recommendation=(
                            "Review this script for malicious content. "
                            "IP:port patterns in scripts are a strong C2 indicator."
                        ),
                        remediation_commands=[
                            f'/system script print detail where name="{name}"',
                            "# Review the full script content",
                        ],
                    ))

            # Check for Telegram/Discord C2 in script source
            for c2_pattern in C2_DOMAIN_PATTERNS:
                if c2_pattern in source.lower():
                    results.append(IoCResult(
                        ioc_type=IoCType.C2_PATTERN_RECOGNITION,
                        severity="Critical",
                        title=f"C2 channel in script '{name}': {c2_pattern}",
                        description=(
                            f"Script '{name}' contains a '{c2_pattern}' URL. "
                            "This is used for Telegram/Discord-based C2 communication "
                            "and is a strong indicator of compromise."
                        ),
                        evidence=f"Script '{name}': source contains {c2_pattern}",
                        recommendation=(
                            "Immediately investigate this script. "
                            "Telegram and Discord C2 channels are used by multiple "
                            "RouterOS malware families."
                        ),
                        remediation_commands=[
                            f'/system script print detail where name="{name}"',
                            "# Remove if malicious",
                            f'/system script remove [find name="{name}"]',
                        ],
                    ))
                    break

        return results


def analyze_sections(sections: Dict[str, List[str]]) -> List[IoCResult]:
    """
    Convenience function for one-shot IoC analysis.

    Args:
        sections: Dict mapping config path -> list of config lines

    Returns:
        List of IoCResult findings
    """
    analyzer = IoCAnalyzer()
    analyzer.load_data(sections)
    return analyzer.analyze()
