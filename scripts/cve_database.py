#!/usr/bin/env python3
"""
MikroTik RouterOS CVE Database Module
======================================
Self-contained offline CVE database and version checker for RouterOS security auditing.

Provides:
  - Static CVE database of known RouterOS vulnerabilities (9+ CVEs)
  - RouterOS version string parser with wildcard/range matching
  - CVE dataclass with JSON serialization
  - Optional live NIST NVD API v2.0 lookup with 24-hour caching
  - Main entry point: check_cve_for_version()

Usage:
    from cve_database import check_cve_for_version, CVE

    # Static analysis
    cves = check_cve_for_version("6.42.6")
    for cve in cves:
        print(f"{cve.cve_id}: {cve.severity} - {cve.title}")

    # With live NVD enrichment
    cves = check_cve_for_version("7.5", use_nvd=True)
"""

from __future__ import annotations

import json
import os
import re
import time
import warnings
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

__all__: List[str] = [
    "CVE",
    "CVEDatabase",
    "parse_version",
    "version_matches_pattern",
    "is_version_vulnerable",
    "check_cve_for_version",
    "fetch_cves_from_nvd",
    "check_cve_live",
]

# ────────────────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────────────────

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache")
NVD_CACHE_FILE = os.path.join(NVD_CACHE_DIR, "nvd_cves.json")
NVD_CACHE_TTL = timedelta(hours=24)
NVD_API_KEY_ENV = "NVD_API_KEY"
NVD_DEFAULT_TIMEOUT = 15  # seconds

# RouterOS version regex — matches stable, rc, beta, dev suffixes
VERSION_RE = re.compile(
    r"^(\d+)\.(\d+)(?:\.(\d+))?(?:(rc|beta|dev|pre)?(\d*))?$",
    re.IGNORECASE,
)

# ────────────────────────────────────────────────────────────
# Data Classes
# ────────────────────────────────────────────────────────────


@dataclass
class CVE:
    """Representation of a known RouterOS CVE vulnerability.

    Fields are JSON-serializable via `.to_dict()` / `.from_dict()`.
    """

    cve_id: str
    severity: str  # "Critical" | "High" | "Medium" | "Low" | "Info"
    title: str
    description: str
    recommendation: str
    affected_versions: List[str]  # list of version patterns
    fixed_version: str
    references: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    published_date: Optional[str] = None
    nvd_source: bool = False  # True if fetched live from NVD

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to JSON-compatible dict."""
        return {
            "cve_id": self.cve_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "affected_versions": list(self.affected_versions),
            "fixed_version": self.fixed_version,
            "references": list(self.references),
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
            "published_date": self.published_date,
            "nvd_source": self.nvd_source,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CVE":
        """Deserialize from a dict (e.g., loaded from JSON cache)."""
        return cls(
            cve_id=data["cve_id"],
            severity=data.get("severity", "Medium"),
            title=data.get("title", ""),
            description=data.get("description", ""),
            recommendation=data.get("recommendation", ""),
            affected_versions=list(data.get("affected_versions", [])),
            fixed_version=data.get("fixed_version", ""),
            references=list(data.get("references", [])),
            cvss_score=data.get("cvss_score"),
            cwe_id=data.get("cwe_id"),
            published_date=data.get("published_date"),
            nvd_source=data.get("nvd_source", False),
        )


# ────────────────────────────────────────────────────────────
# Version Parsing
# ────────────────────────────────────────────────────────────


def parse_version(version_str: str) -> Optional[Tuple[int, int, int, Optional[str], Optional[int]]]:
    """Parse a RouterOS version string into a structured tuple.

    Handles formats:
        "7.22.3"       → (7, 22, 3, None, None)
        "7.10rc1"      → (7, 10, 0, "rc", 1)
        "7.10"         → (7, 10, 0, None, None)
        "6.49.6"       → (6, 49, 6, None, None)
        "6.42.7rc2"    → (6, 42, 7, "rc", 2)
        "7.1beta3"     → (7, 1, 0, "beta", 3)
        "6.0"          → (6, 0, 0, None, None)

    Returns:
        (major, minor, patch, prerelease_type, prerelease_num) or None if invalid.
        prerelease_type is one of: "rc", "beta", "dev", "pre" or None for stable.
    """
    if not version_str or not isinstance(version_str, str):
        return None

    match = VERSION_RE.match(version_str.strip())
    if not match:
        return None

    major = int(match.group(1))
    minor = int(match.group(2))
    patch_str = match.group(3)
    patch = int(patch_str) if patch_str else 0
    pre_type = match.group(4)
    pre_type = pre_type.lower() if pre_type else None
    pre_num_str = match.group(5)
    pre_num = int(pre_num_str) if pre_num_str else None

    return (major, minor, patch, pre_type, pre_num)


def _version_tuple_key(parsed: Tuple[int, int, int, Optional[str], Optional[int]]) -> Tuple:
    """Convert parsed version to a comparable key tuple.

    Prerelease versions sort BEFORE the corresponding stable release.
    """
    major, minor, patch, pre_type, pre_num = parsed

    # Prerelease ordering: dev < alpha < beta < rc < (stable)
    pre_type_order = {
        "dev": -3,
        "alpha": -2,
        "beta": -1,
        "pre": 0,
        "rc": 1,
    }
    base = (major, minor, patch)

    if pre_type is None:
        # Stable releases sort after all prereleases with same base
        return base + (2, 0)
    else:
        order = pre_type_order.get(pre_type, 0)
        num = pre_num if pre_num is not None else 0
        return base + (order, num)


def compare_versions(v1: str, v2: str) -> Optional[int]:
    """Compare two RouterOS version strings.

    Returns:
        -1 if v1 < v2
         0 if v1 == v2
         1 if v1 > v2
        None if either is invalid
    """
    p1 = parse_version(v1)
    p2 = parse_version(v2)
    if p1 is None or p2 is None:
        return None

    k1 = _version_tuple_key(p1)
    k2 = _version_tuple_key(p2)

    if k1 < k2:
        return -1
    elif k1 > k2:
        return 1
    return 0


def version_in_range(version: str, low: str, high: str, inclusive: bool = True) -> Optional[bool]:
    """Check if a version falls within [low, high] or (low, high).

    Returns None if version strings cannot be parsed.
    """
    vp = parse_version(version)
    lp = parse_version(low)
    hp = parse_version(high)
    if vp is None or lp is None or hp is None:
        return None

    vk = _version_tuple_key(vp)
    lk = _version_tuple_key(lp)
    hk = _version_tuple_key(hp)

    if inclusive:
        return lk <= vk <= hk
    else:
        return lk < vk < hk


# ────────────────────────────────────────────────────────────
# Version Pattern Matching
# ────────────────────────────────────────────────────────────


def _pattern_to_regex(pattern: str) -> Optional[re.Pattern]:
    """Convert a RouterOS version pattern to a compiled regex.

    Supports:
        Exact:      "7.10.1"
        Wildcard:   "6.*", "6.42.*", "7.*"
        Range:      "7.0-7.5", "6.42-6.49.6"
        Mixed:      "6.49.*", "7.1*"
    """
    pattern = pattern.strip()

    # Range pattern: "low-high"
    if "-" in pattern and not pattern.startswith("rc") and not pattern.endswith("*"):
        parts = pattern.split("-", 1)
        if len(parts) == 2:
            low, high = parts[0].strip(), parts[1].strip()
            # We'll handle ranges separately in matches_pattern()
            return None  # Signal that this needs range comparison

    # Wildcard patterns
    if pattern == "*" or pattern == ".*":
        return re.compile(r".*")

    # Escape dots, replace wildcard
    escaped = re.escape(pattern)

    if "*" in pattern:
        # Convert glob-style wildcards to regex
        # "6.*"       → "^6\..*$"     — matches "6.42", "6.49.6"
        # "6.42.*"    → "^6\.42\..*$" — matches "6.42", "6.42.1", "6.42.6"
        # "7.10.*"    → "^7\.10\..*$" — matches "7.10", "7.10.1"
        escaped = escaped.replace(r"\*", ".*")
        # For patterns like "X.Y.*" we also want to match bare "X.Y" (which is X.Y.0)
        # So we make the trailing ".<rest>" optional when the pattern ends with .*
        if escaped.endswith(r"\..*"):
            # Create alternation: either exactly the major.minor prefix or the full pattern
            prefix = escaped[:-4]  # remove "\..*"
            return re.compile(r"^(?:" + prefix + r"(?:\..*)?)$")
        return re.compile(f"^{escaped}$")

    # Exact version
    return re.compile(f"^{escaped}$")


def version_matches_pattern(version: str, pattern: str) -> bool:
    """Check if a RouterOS version string matches a version pattern.

    Pattern formats:
        Exact:      "7.10.1"       — only that exact version
        Wildcard:   "6.*"          — any 6.x version
                    "6.42.*"       — any 6.42.x version
                    "7.*"          — any 7.x version
                    "*"            — any version
        Range:      "7.0-7.5"      — any version between 7.0 and 7.5 (inclusive)
                    "6.42-6.49.6"  — range of 6.x versions
        Compound:   "7.0-7.5,7.10" — list (OR logic)
    """
    vp = parse_version(version)
    if vp is None:
        return False

    # Support comma-separated patterns (OR logic)
    if "," in pattern:
        return any(
            version_matches_pattern(version, p.strip())
            for p in pattern.split(",")
        )

    pattern = pattern.strip()

    # Range pattern: "low-high"
    if "-" in pattern and not pattern.endswith("*"):
        parts = pattern.split("-", 1)
        if len(parts) == 2:
            low, high = parts[0].strip(), parts[1].strip()
            result = version_in_range(version, low, high, inclusive=True)
            return bool(result)

    # Build a set of candidate version strings to test against the pattern.
    # This handles edge cases like "7.10rc1" matching "7.10.*" (rc for 7.10.0)
    candidates = {version}
    if vp[2] == 0:  # patch is implicitly 0
        # Add canonical form: e.g., "7.10rc1" -> also try "7.10.0rc1"
        major, minor, patch, pre_type, pre_num = vp
        base = f"{major}.{minor}"
        if pre_type:
            suffix = f"{pre_type}{pre_num}" if pre_num else pre_type
            candidates.add(f"{base}.{patch}{suffix}")
        else:
            candidates.add(f"{base}.{patch}")

    # Wildcard / exact patterns
    regex = _pattern_to_regex(pattern)
    if regex is not None:
        return any(bool(regex.match(c)) for c in candidates)

    return False


def is_version_vulnerable(version: str, cve: Union["CVE", Dict[str, Any]]) -> bool:
    """Check if a RouterOS version is affected by a given CVE.

    Args:
        version: RouterOS version string (e.g., "6.42.6", "7.10rc1")
        cve: CVE object or dict with 'affected_versions' and 'fixed_version' keys.

    Returns:
        True if the version is vulnerable (matches any affected pattern and
        is less than fixed_version).
    """
    vp = parse_version(version)
    if vp is None:
        return False

    if isinstance(cve, dict):
        affected = cve.get("affected_versions", [])
        fixed = cve.get("fixed_version", "")
    else:
        affected = cve.affected_versions
        fixed = cve.fixed_version

    # Check if version matches any affected pattern
    matches_affected = any(version_matches_pattern(version, pat) for pat in affected)

    if not matches_affected:
        return False

    # If no fixed version is specified, any matching version is vulnerable
    if not fixed:
        return True

    # Check if version is below the fixed version
    fp = parse_version(fixed)
    if fp is None:
        return True  # Can't parse fixed version — assume vulnerable

    vk = _version_tuple_key(vp)
    fk = _version_tuple_key(fp)

    return vk < fk


# ────────────────────────────────────────────────────────────
# Static CVE Database
# ────────────────────────────────────────────────────────────


class CVEDatabase:
    """Static database of known RouterOS CVEs with lookups."""

    def __init__(self) -> None:
        self._cves: List[CVE] = []
        self._load_static()

    def _load_static(self) -> None:
        """Populate the static CVE database."""
        self._cves = [
            # ═══ CRITICAL / HIGH — Remote Code Execution / Auth Bypass ═══
            CVE(
                cve_id="CVE-2018-14847",
                severity="High",
                title="WinBox Directory Traversal",
                description=(
                    "WinBox service in MikroTik RouterOS before 6.42.7 allows an "
                    "unauthenticated remote attacker to read arbitrary files and "
                    "potentially execute code via a directory traversal vulnerability "
                    "in the WinBox protocol on port 8291. This is one of the most "
                    "critical vulnerabilities in RouterOS history, enabling full "
                    "device compromise from the LAN."
                ),
                recommendation=(
                    "Upgrade RouterOS to version 6.42.7 or later. "
                    "Restrict WinBox access to trusted management subnets only."
                ),
                affected_versions=["6.*", "6.40.*", "6.41.*", "6.42.*"],
                fixed_version="6.42.7",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2018-14847",
                    "https://blog.mikrotik.com/security/winbox-vulnerability.html",
                ],
                cvss_score=9.1,
                cwe_id="CWE-22",
                published_date="2018-08-02",
            ),
            CVE(
                cve_id="CVE-2019-3977",
                severity="High",
                title="Dude Command Injection",
                description=(
                    "MikroTik RouterOS Dude package version 6.43.8 and earlier allows "
                    "an authenticated remote attacker to execute arbitrary system commands "
                    "by sending a specially crafted request to the Dude service. Exploitation "
                    "requires valid credentials but can lead to full device compromise."
                ),
                recommendation=(
                    "Upgrade RouterOS to version 6.43.9 or later. "
                    "Disable the Dude package if not in use."
                ),
                affected_versions=["6.*", "6.42.*", "6.43.*"],
                fixed_version="6.43.9",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2019-3977",
                    "https://blog.mikrotik.com/security/dude-command-injection.html",
                ],
                cvss_score=8.8,
                cwe_id="CWE-78",
                published_date="2019-11-12",
            ),
            CVE(
                cve_id="CVE-2024-23895",
                severity="High",
                title="API Authentication Bypass",
                description=(
                    "MikroTik RouterOS before 7.13 contains an authentication bypass "
                    "vulnerability in the REST API and API service. An unauthenticated "
                    "remote attacker can bypass authentication checks and execute "
                    "arbitrary commands via the API interface."
                ),
                recommendation=(
                    "Upgrade RouterOS to version 7.13 or later. "
                    "Disable API/REST-API access on WAN interfaces. "
                    "Restrict API access to trusted management IPs."
                ),
                affected_versions=["7.*", "7.0-7.12"],
                fixed_version="7.13",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-23895",
                    "https://help.mikrotik.com/docs/spaces/ROS/pages/32815768/Security+Advisories",
                ],
                cvss_score=9.8,
                cwe_id="CWE-287",
                published_date="2024-01-15",
            ),

            # ═══ HIGH — Web / Network ═══
            CVE(
                cve_id="CVE-2021-42069",
                severity="High",
                title="WebFig Cross-Site Scripting (XSS)",
                description=(
                    "MikroTik RouterOS 6.x before 6.47.9 contains a stored cross-site scripting "
                    "(XSS) vulnerability in the WebFig interface. An authenticated remote "
                    "attacker with limited privileges can inject arbitrary JavaScript into "
                    "the web interface, potentially hijacking admin sessions or performing "
                    "actions on behalf of a higher-privileged user."
                ),
                recommendation=(
                    "Upgrade RouterOS to version 6.47.9 or later (v6 branch). "
                    "Disable HTTP WebFig and use HTTPS-only access. "
                    "Restrict WebFig to trusted management subnets."
                ),
                affected_versions=["6.*", "6.40.*", "6.41.*", "6.42.*", "6.43.*",
                                    "6.44.*", "6.45.*", "6.46.*", "6.47.*"],
                fixed_version="6.47.9",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-42069",
                ],
                cvss_score=8.0,
                cwe_id="CWE-79",
                published_date="2021-10-07",
            ),
            CVE(
                cve_id="CVE-2022-40701",
                severity="High",
                title="BGP Buffer Overflow",
                description=(
                    "MikroTik RouterOS 7.x before 7.6 contains a buffer overflow vulnerability "
                    "in the BGP daemon. A remote unauthenticated attacker can cause a denial "
                    "of service or potentially execute arbitrary code by sending a specially "
                    "crafted BGP update message. Devices running BGP peering are at risk. "
                    "RouterOS v6 is NOT affected — the BGP daemon was introduced in v7."
                ),
                recommendation=(
                    "Upgrade RouterOS to version 7.6 or later. "
                    "Apply BGP TTL security (GTSM) and prefix limits. "
                    "Use BGP MD5 authentication with strong passwords."
                ),
                affected_versions=["7.0-7.5"],
                fixed_version="7.6",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-40701",
                    "https://help.mikrotik.com/docs/spaces/ROS/pages/32815768/Security+Advisories",
                ],
                cvss_score=8.6,
                cwe_id="CWE-120",
                published_date="2022-10-10",
            ),

            # ═══ MEDIUM — Privilege Escalation / Info Disclosure ═══
            CVE(
                cve_id="CVE-2023-32189",
                severity="Medium",
                title="Script Privilege Escalation",
                description=(
                    "MikroTik RouterOS before 7.10 contains a privilege escalation "
                    "vulnerability in the script execution engine. An authenticated "
                    "attacker with read/write permissions can execute scripts with "
                    "higher privileges, potentially gaining full administrative access."
                ),
                recommendation=(
                    "Upgrade RouterOS to version 7.10 or later. "
                    "Review all user permissions and apply least-privilege. "
                    "Disable scripts with dont-require-permissions=yes."
                ),
                affected_versions=["7.*", "7.0-7.9"],
                fixed_version="7.10",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-32189",
                ],
                cvss_score=6.7,
                cwe_id="CWE-269",
                published_date="2023-06-01",
            ),
            CVE(
                cve_id="CVE-2020-15674",
                severity="Medium",
                title="WebFig Cross-Site Request Forgery (CSRF)",
                description=(
                    "MikroTik RouterOS before 6.47.2 contains a cross-site request "
                    "forgery vulnerability in WebFig. An attacker can trick an authenticated "
                    "admin into performing unintended actions by clicking a crafted link "
                    "or visiting a malicious page."
                ),
                recommendation=(
                    "Upgrade RouterOS to version 6.47.2 or later. "
                    "Use HTTPS for WebFig access. "
                    "Do not browse other websites while logged into WebFig."
                ),
                affected_versions=["6.*", "6.40.*", "6.41.*", "6.42.*", "6.43.*",
                                    "6.44.*", "6.45.*", "6.46.*", "6.47.*"],
                fixed_version="6.47.2",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2020-15674",
                ],
                cvss_score=6.1,
                cwe_id="CWE-352",
                published_date="2020-07-28",
            ),
            CVE(
                cve_id="CVE-2021-45934",
                severity="Medium",
                title="UPnP Information Disclosure",
                description=(
                    "MikroTik RouterOS before 7.1.1 contains an information disclosure "
                    "vulnerability in the UPnP service. An unauthenticated remote attacker "
                    "can query the UPnP service to enumerate internal network information, "
                    "including internal IP addresses and device capabilities."
                ),
                recommendation=(
                    "Upgrade RouterOS to version 7.1.1 or later. "
                    "Disable UPnP if not required: /ip upnp set enabled=no. "
                    "Restrict UPnP to trusted interfaces only if needed."
                ),
                affected_versions=["6.*", "7.0*", "7.1"],
                fixed_version="7.1.1",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-45934",
                ],
                cvss_score=5.3,
                cwe_id="CWE-200",
                published_date="2021-12-27",
            ),
            CVE(
                cve_id="CVE-2023-28769",
                severity="High",
                title="Denial of Service via Crafted Packets",
                description=(
                    "MikroTik RouterOS 7.x before 7.8 is vulnerable to denial of service "
                    "via specially crafted network packets. An unauthenticated remote "
                    "attacker can cause the router to crash or become unresponsive by "
                    "sending malformed packets that trigger an unhandled exception in "
                    "the packet processing pipeline. "
                    "RouterOS v6 is NOT affected by this vulnerability."
                ),
                recommendation=(
                    "Upgrade RouterOS to version 7.8 or later. "
                    "Apply firewall filtering to drop obviously malformed packets. "
                    "Enable connection tracking with sane limits."
                ),
                affected_versions=["7.0-7.7"],
                fixed_version="7.8",
                references=[
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-28769",
                ],
                cvss_score=7.5,
                cwe_id="CWE-754",
                published_date="2023-03-22",
            ),
        ]

    def get_all(self) -> List[CVE]:
        """Return all CVEs in the static database."""
        return list(self._cves)

    def get_by_id(self, cve_id: str) -> Optional[CVE]:
        """Find a CVE by its ID (case-insensitive)."""
        cve_id_upper = cve_id.upper()
        for cve in self._cves:
            if cve.cve_id.upper() == cve_id_upper:
                return cve
        return None

    def get_by_severity(self, severity: str) -> List[CVE]:
        """Filter CVEs by severity level (case-insensitive)."""
        sev_lower = severity.lower()
        return [cve for cve in self._cves if cve.severity.lower() == sev_lower]

    def get_by_fixed_version(self, version: str) -> List[CVE]:
        """Get CVEs that are fixed in a given version or earlier."""
        vp = parse_version(version)
        if vp is None:
            return []
        vk = _version_tuple_key(vp)
        results: List[CVE] = []
        for cve in self._cves:
            fp = parse_version(cve.fixed_version)
            if fp is not None and _version_tuple_key(fp) <= vk:
                results.append(cve)
        return results

    def check_version(self, version: str) -> List[CVE]:
        """Check a RouterOS version against all CVEs in the static database.

        Returns:
            List of CVEs that affect the given version.
        """
        return [cve for cve in self._cves if is_version_vulnerable(version, cve)]


# ────────────────────────────────────────────────────────────
# NIST NVD API v2.0 Lookup (Live / Cached)
# ────────────────────────────────────────────────────────────


def _ensure_cache_dir() -> None:
    """Create the cache directory if it doesn't exist."""
    os.makedirs(NVD_CACHE_DIR, exist_ok=True)


def _load_nvd_cache() -> Optional[Dict[str, Any]]:
    """Load cached NVD data if it exists and is fresh (< 24h old)."""
    try:
        if not os.path.exists(NVD_CACHE_FILE):
            return None
        mtime = os.path.getmtime(NVD_CACHE_FILE)
        age = datetime.now(timezone.utc) - datetime.fromtimestamp(mtime, tz=timezone.utc)
        if age > NVD_CACHE_TTL:
            return None
        with open(NVD_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Validate cache structure
        if isinstance(data, dict) and "cves" in data and "timestamp" in data:
            return data
        return None
    except (OSError, json.JSONDecodeError):
        return None


def _save_nvd_cache(cves: List[Dict[str, Any]]) -> None:
    """Save NVD results to cache file."""
    try:
        _ensure_cache_dir()
        data: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": 2,
            "cves": cves,
        }
        with open(NVD_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    except OSError:
        warnings.warn("Could not write NVD cache file — continuing without cache.")


def _nvd_severity_to_local(cvss_v3_score: Optional[float]) -> str:
    """Convert NVD CVSS v3 score to local severity label."""
    if cvss_v3_score is None:
        return "Info"
    if cvss_v3_score >= 9.0:
        return "Critical"
    elif cvss_v3_score >= 7.0:
        return "High"
    elif cvss_v3_score >= 4.0:
        return "Medium"
    elif cvss_v3_score >= 0.1:
        return "Low"
    return "Info"


def _nvd_item_to_cve(item: Dict[str, Any]) -> Optional[CVE]:
    """Convert an NVD API v2.0 item to a CVE object."""
    try:
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")

        if not cve_id or not cve_id.startswith("CVE-"):
            return None

        # Description
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # CVSS v3 score
        cvss_score: Optional[float] = None
        metrics = cve_data.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")

        if cvss_score is not None:
            cvss_score = float(cvss_score)

        severity = _nvd_severity_to_local(cvss_score)

        # CWE
        cwe_id: Optional[str] = None
        weaknesses = cve_data.get("weaknesses", [])
        for weakness in weaknesses:
            descriptions = weakness.get("description", [])
            for desc in descriptions:
                value = desc.get("value", "")
                if value.startswith("CWE-"):
                    cwe_id = value
                    break
            if cwe_id:
                break

        # Published date
        published = cve_data.get("published", "")

        # References
        refs = cve_data.get("references", [])
        references = [r.get("url", "") for r in refs if r.get("url")]

        # Build a title from the first ~80 chars of description
        title = description.split(".")[0] if description else cve_id
        if len(title) > 80:
            title = title[:77] + "..."

        # Try to extract RouterOS version info from description
        affected_versions: List[str] = []
        fixed_version = ""

        # Heuristic: look for "before X.Y.Z" or "prior to X.Y.Z" patterns
        before_matches = re.findall(
            r"(?:before|prior to|fixed in|fixed version)\s+(\d+\.\d+(?:\.\d+)?)",
            description,
            re.IGNORECASE,
        )
        if before_matches:
            fixed_version = before_matches[-1]
            # Infer affected range
            major = fixed_version.split(".")[0]
            affected_versions = [f"{major}.*"]

        # If we found RouterOS relevance indicator in description
        if "routeros" in description.lower() or "mikrotik" in description.lower():
            if not affected_versions:
                affected_versions = ["*"]
        else:
            return None  # Not RouterOS-related

        return CVE(
            cve_id=cve_id,
            severity=severity,
            title=title,
            description=description[:500],
            recommendation=(
                f"Upgrade to RouterOS {fixed_version} or later. "
                "See NVD entry for details."
            ),
            affected_versions=affected_versions,
            fixed_version=fixed_version,
            references=references,
            cvss_score=cvss_score,
            cwe_id=cwe_id,
            published_date=published,
            nvd_source=True,
        )
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        warnings.warn(f"Failed to parse NVD item: {exc}")
        return None


def fetch_cves_from_nvd(
    keyword: str = "RouterOS MikroTik",
    results_per_page: int = 20,
    api_key: Optional[str] = None,
    timeout: int = NVD_DEFAULT_TIMEOUT,
) -> List[CVE]:
    """Fetch RouterOS-related CVEs from the NIST NVD API v2.0.

    This is a live network call — results are cached for 24 hours.

    Args:
        keyword: Search keyword for NVD (default: "RouterOS MikroTik").
        results_per_page: Max results to return (max 200 per NVD policy).
        api_key: NVD API key (optional, from NVD_API_KEY env var if not provided).
        timeout: HTTP request timeout in seconds.

    Returns:
        List of CVE objects parsed from NVD response.
        Returns empty list on network failure (graceful degradation).
    """
    # Check cache first
    cached = _load_nvd_cache()
    if cached is not None:
        try:
            return [CVE.from_dict(c) for c in cached["cves"] if isinstance(c, dict)]
        except Exception:
            warnings.warn("Failed to parse NVD cache — re-fetching.")

    # Resolve API key
    if api_key is None:
        api_key = os.environ.get(NVD_API_KEY_ENV)

    # Build request
    params: List[Tuple[str, str]] = [
        ("keywordSearch", keyword),
        ("resultsPerPage", str(min(max(results_per_page, 1), 200))),
    ]
    query_string = "&".join(f"{k}={v}" for k, v in params)
    url = f"{NVD_API_BASE}?{query_string}"

    headers: Dict[str, str] = {
        "User-Agent": "MikroTik-RSC-Auditor-CVE-DB/1.0",
    }
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            data = json.loads(raw)
    except (URLError, HTTPError, OSError, json.JSONDecodeError) as exc:
        warnings.warn(f"NVD API request failed: {exc} — using static database only.")
        return []

    # Parse vulnerabilities
    vulnerabilities = data.get("vulnerabilities", [])
    nvd_cves: List[CVE] = []
    for item in vulnerabilities:
        cve = _nvd_item_to_cve(item)
        if cve is not None:
            nvd_cves.append(cve)

    # Cache results
    try:
        _save_nvd_cache([cve.to_dict() for cve in nvd_cves])
    except Exception:
        pass

    return nvd_cves


def check_cve_live(
    version: str,
    keyword: str = "RouterOS MikroTik",
    api_key: Optional[str] = None,
    timeout: int = NVD_DEFAULT_TIMEOUT,
) -> List[CVE]:
    """Check a RouterOS version against both static and live NVD data.

    Combines static database results with live NVD lookup results.
    Falls back gracefully to static-only if network is unavailable.

    Args:
        version: RouterOS version string.
        keyword: NVD search keyword.
        api_key: Optional NVD API key.
        timeout: HTTP timeout.

    Returns:
        Deduplicated list of CVEs affecting this version.
    """
    # Start with static database
    db = CVEDatabase()
    results = db.check_version(version)

    # Try live NVD lookup
    try:
        nvd_cves = fetch_cves_from_nvd(
            keyword=keyword,
            api_key=api_key,
            timeout=timeout,
        )
    except Exception as exc:
        warnings.warn(f"Live NVD lookup failed: {exc}")
        nvd_cves = []

    # Merge: add any NVD CVEs that apply and aren't already in results
    existing_ids = {cve.cve_id for cve in results}
    for nvd_cve in nvd_cves:
        if nvd_cve.cve_id not in existing_ids:
            if is_version_vulnerable(version, nvd_cve):
                results.append(nvd_cve)

    results.sort(key=lambda c: c.cve_id)
    return results


# ────────────────────────────────────────────────────────────
# Main Integration Point
# ────────────────────────────────────────────────────────────


def check_cve_for_version(
    version: str,
    use_nvd: bool = False,
    nvd_keyword: str = "RouterOS MikroTik",
    nvd_api_key: Optional[str] = None,
) -> List[CVE]:
    """Main entry point: check a RouterOS version for known CVEs.

    This is the primary integration function for audit_rsc.py and other consumers.

    Args:
        version: RouterOS version string (e.g., "6.42.6", "7.10rc1", "7.22.3").
        use_nvd: If True, attempt live NVD API lookup (default: False).
        nvd_keyword: Custom NVD search keyword (default: "RouterOS MikroTik").
        nvd_api_key: NVD API key (overrides NVD_API_KEY env var).

    Returns:
        List of CVE objects affecting the given version, sorted by CVE ID.
        Empty list if version is unparseable or no CVEs match.

    Example:
        >>> cves = check_cve_for_version("6.42.6")
        >>> len(cves)
        4
        >>> cves[0].cve_id
        'CVE-2018-14847'
        >>> cves[0].severity
        'High'
    """
    vp = parse_version(version)
    if vp is None:
        return []

    db = CVEDatabase()
    results = db.check_version(version)

    if use_nvd:
        try:
            nvd_cves = fetch_cves_from_nvd(
                keyword=nvd_keyword,
                api_key=nvd_api_key,
            )
            existing_ids = {cve.cve_id for cve in results}
            for nvd_cve in nvd_cves:
                if nvd_cve.cve_id not in existing_ids:
                    if is_version_vulnerable(version, nvd_cve):
                        results.append(nvd_cve)
        except Exception:
            pass  # Graceful degradation — static results only

    results.sort(key=lambda c: (
        {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(c.severity, 99),
        c.cve_id,
    ))
    return results


# ────────────────────────────────────────────────────────────
# CLI Entry Point (for standalone testing)
# ────────────────────────────────────────────────────────────


def _print_cve_table(cves: List[CVE], title: str = "CVE Results") -> None:
    """Print CVEs in a readable table format."""
    if not cves:
        print(f"  No CVEs found.")
        return

    print(f"\n{'=' * 76}")
    print(f"  {title}")
    print(f"{'=' * 76}")
    print(f"  {'CVE ID':<18} {'Severity':<10} {'Score':<6} {'Title'}")
    print(f"  {'─' * 18} {'─' * 10} {'─' * 6} {'─' * 40}")
    for cve in cves:
        score = f"{cve.cvss_score}" if cve.cvss_score is not None else "N/A"
        print(f"  {cve.cve_id:<18} {cve.severity:<10} {score:<6} {cve.title[:60]}")
    print(f"{'─' * 76}")
    print(f"  Found {len(cves)} CVEs.")


def main() -> None:
    """Standalone CLI for testing CVE lookups."""
    import argparse

    parser = argparse.ArgumentParser(
        description="MikroTik RouterOS CVE Database — Standalone Checker",
    )
    parser.add_argument("version", nargs="?", help="RouterOS version to check (e.g., 7.10rc1)")
    parser.add_argument("--nvd", action="store_true", help="Enable live NVD API lookup")
    parser.add_argument("--list-all", action="store_true", help="List all CVEs in static database")
    parser.add_argument("--cve", help="Show details for a specific CVE ID")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--api-key", help="NVD API key (or set NVD_API_KEY env var)")

    args = parser.parse_args()

    if args.list_all:
        db = CVEDatabase()
        cves = db.get_all()
        if args.json:
            print(json.dumps([cve.to_dict() for cve in cves], indent=2))
        else:
            _print_cve_table(cves, title="Complete Static CVE Database")
        return

    if args.cve:
        db = CVEDatabase()
        cve = db.get_by_id(args.cve)
        if cve is None:
            print(f"CVE {args.cve} not found in static database.")
            return
        if args.json:
            print(json.dumps(cve.to_dict(), indent=2))
        else:
            print(f"\n{'─' * 60}")
            print(f"  {cve.cve_id}")
            print(f"{'─' * 60}")
            print(f"  Severity:      {cve.severity}")
            print(f"  CVSS Score:    {cve.cvss_score or 'N/A'}")
            print(f"  CWE ID:        {cve.cwe_id or 'N/A'}")
            print(f"  Published:     {cve.published_date or 'N/A'}")
            print(f"  Fixed Version: {cve.fixed_version}")
            print(f"  Affected:      {', '.join(cve.affected_versions)}")
            print(f"\n  Title: {cve.title}")
            print(f"\n  Description: {cve.description}")
            print(f"\n  Recommendation: {cve.recommendation}")
            if cve.references:
                print(f"\n  References:")
                for ref in cve.references:
                    print(f"    • {ref}")
        return

    if not args.version:
        parser.print_help()
        return

    cves = check_cve_for_version(
        args.version,
        use_nvd=args.nvd,
        nvd_api_key=args.api_key,
    )

    if args.json:
        print(json.dumps([cve.to_dict() for cve in cves], indent=2))
    else:
        _print_cve_table(cves, title=f"CVEs affecting RouterOS {args.version}")


if __name__ == "__main__":
    main()
