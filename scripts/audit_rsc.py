#!/usr/bin/env python3
"""
MikroTik RouterOS .rsc Configuration Auditor
=============================================
Offline static analysis tool for auditing exported RouterOS configuration files.

Audits .rsc files for:
  - Security misconfigurations (100+ checks)
  - Syntax validation
  - Compliance gaps (CIS/NIST/ISO/PCI-DSS)
  - hAP-specific constraints (flash, HW offload, WiFi stability)

Usage:
  python audit_rsc.py export.rsc                  # Default audit, text output
  python audit_rsc.py export.rsc --format json     # JSON output
  python audit_rsc.py export.rsc --format html     # HTML report
  python audit_rsc.py export.rsc --severity high   # Only high+critical
  python audit_rsc.py export.rsc --check AUTH-001,FW-005      # Specific checks only
  python audit_rsc.py export.rsc --cve             # Include CVE check
  python audit_rsc.py export.rsc --cve --cve-live  # CVE + NVD live lookup
  python audit_rsc.py export.rsc --conflicts       # Rule conflict analysis
  python audit_rsc.py export.rsc --ioc             # IoC detection
  python audit_rsc.py export.rsc --lint script.rsc # Lint a separate script
  python audit_rsc.py export.rsc --skip-wifi       # Skip WiFi checks
  python audit_rsc.py export.rsc --skip-routing    # Skip routing checks
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# ───────── New Module Imports ─────────
from .cve_database import check_cve_for_version, CVE
from .conflict_analyzer import ConflictAnalyzer, ConflictType, ConflictResult
from .ioc_analyzer import IoCAnalyzer, IoCType, IoCResult
from . import lint_rsc as linter
from .device_profiles import detect_device, get_profile, DeviceProfile, DEVICE_PROFILES
from .check_hardware_map import CHECK_HARDWARE_MAP, get_check_rules
# ─────────────────────────────────────

# ────────────────────────────── Audit Check Definitions ──────────────────────────────

AUDIT_CHECKS: List[Dict[str, Any]] = [
    # ═══ AUTHENTICATION & ACCESS CONTROL ═══
    {
        "id": "AUTH-001",
"domain": "general",
        "name": "Default admin user present",
        "severity": "Critical",
        "cvss": "9.8",
        "category": "Authentication & Access Control",
        "path": "/user",
        "description": "Default admin user exists without being disabled or removed",
        "detect": [
            r"/user\s+add\s+.*?\bname=admin\b",
            r"/user\s+set\s+.*?\bname=admin\b(?!.*disabled=yes)",
        ],
        "remediation": (
            "/user add name=localadmin group=full password=<strong-password>\n"
            "/user disable [find name=admin]"
        ),
        "compliance": {"cis": "1.1", "nist": "AC-2", "iso": "A.8.3", "pci": "2.1"},
    },
    {
        "id": "AUTH-002",
"domain": "general",
        "name": "No password set on admin user",
        "severity": "Critical",
        "cvss": "10.0",
        "category": "Authentication & Access Control",
        "path": "/user",
        "description": "User accounts without password or with empty password",
        "detect": [
            r"/user\s+add\s+.*?\bname=(\w+)\b(?!.*password=)",
            r"/user\s+set\s+.*?\bname=(\w+)\b(?!.*password=)",
        ],
        "remediation": (
            "/user set [find name=<username>] password=<strong-password>"
        ),
        "compliance": {"cis": "1.1", "nist": "IA-5", "iso": "A.8.5", "pci": "8.2"},
    },
    {
        "id": "AUTH-003",
"domain": "general",
        "name": "Weak password patterns",
        "severity": "High",
        "cvss": "7.5",
        "category": "Authentication & Access Control",
        "path": "/user",
        "description": "Passwords use common words, short length, or default patterns",
        "detect": [
            r"password=admin",
            r"password=1234",
            r"password=mikrotik",
            r"password=default",
            r"password=.{1,7}\b",
        ],
        "remediation": (
            "Use passwords with minimum 12 characters, mixed case, numbers, and symbols.\n"
            "/user set [find name=<username>] password=<strong-password>"
        ),
        "compliance": {"cis": "1.2", "nist": "IA-5(1)", "iso": "A.8.5", "pci": "8.2.1"},
    },
    {
        "id": "AUTH-004",
"domain": "general",
        "name": "Users in full group without IP restrictions",
        "severity": "High",
        "cvss": "7.5",
        "category": "Authentication & Access Control",
        "path": "/user",
        "description": "Users with 'full' group membership not restricted to specific source IPs",
        "detect": [
            r"/user\s+add\s+.*?\bgroup=full\b(?!.*address=)",
            r"/user\s+set\s+.*?\bgroup=full\b(?!.*address=)",
        ],
        "remediation": (
            "/user set [find name=<username>] address=<mgmt-subnet/cidr>"
        ),
        "compliance": {"cis": "3.1", "nist": "AC-6", "iso": "A.5.15", "pci": "7.1"},
    },
    {
        "id": "AUTH-005",
"domain": "general",
        "name": "SSH weak-crypto enabled",
        "severity": "High",
        "cvss": "7.4",
        "category": "Authentication & Access Control",
        "path": "/ip ssh",
        "description": "SSH server configured with weak cryptography (strong-crypto=no)",
        "detect": [
            r"/ip\s+ssh\s+set\s+.*?strong-crypto=no\b",
        ],
        "remediation": (
            "/ip ssh set strong-crypto=yes"
        ),
        "compliance": {"cis": "3.2", "nist": "SC-8", "iso": "A.8.5", "pci": "2.2.3"},
    },
    {
        "id": "AUTH-006",
"domain": "general",
        "name": "MAC-Telnet service enabled",
        "severity": "High",
        "cvss": "7.5",
        "category": "Authentication & Access Control",
        "path": "/tool mac-server",
        "description": "MAC-Telnet service is enabled, allowing L2 access without IP authentication",
        "detect": [
            r"/tool\s+mac-server\s+set\s+.*?allowed-interface-list=all\b",
            r"/tool\s+mac-server\s+set\s+.*?allowed-interface-list=.*?(?!none)",
        ],
        "remediation": (
            "/tool mac-server set allowed-interface-list=none\n"
            "/tool mac-server mac-winbox set allowed-interface-list=none"
        ),
        "compliance": {"cis": "3.3", "nist": "AC-17", "iso": "A.8.22", "pci": "2.2.3"},
    },
    {
        "id": "AUTH-007",
"domain": "general",
        "name": "MAC-WinBox service enabled",
        "severity": "High",
        "cvss": "7.5",
        "category": "Authentication & Access Control",
        "path": "/tool mac-server mac-winbox",
        "description": "MAC-WinBox service enabled, allowing L2 WinBox access",
        "detect": [
            r"/tool\s+mac-server\s+mac-winbox\s+set\s+allowed-interface-list=all\b",
        ],
        "remediation": (
            "/tool mac-server mac-winbox set allowed-interface-list=none"
        ),
        "compliance": {"cis": "3.3", "nist": "AC-17", "iso": "A.8.22", "pci": "2.2.3"},
    },
    {
        "id": "AUTH-008",
"domain": "general",
        "name": "MAC-Ping service enabled",
        "severity": "Medium",
        "cvss": "5.3",
        "category": "Authentication & Access Control",
        "path": "/tool mac-server ping",
        "description": "MAC-Ping enabled, allowing device discovery at L2",
        "detect": [
            r"/tool\s+mac-server\s+ping\s+set\s+enabled=yes\b",
        ],
        "remediation": (
            "/tool mac-server ping set enabled=no"
        ),
        "compliance": {"cis": "3.3", "nist": "CM-7", "iso": "A.8.9", "pci": "2.2.2"},
    },
    {
        "id": "AUTH-009",
"domain": "general",
        "name": "WinBox exposed on WAN",
        "severity": "Critical",
        "cvss": "9.1",
        "category": "Authentication & Access Control",
        "path": "/ip service",
        "description": "WinBox service is accessible from WAN interface (no firewall restriction)",
        "detect": [
            r"/ip\s+service\s+set\s+winbox\s+disabled=no\b",
            r"/ip\s+service\s+set\s+winbox\s+.*?address=\S+",
        ],
        "remediation": (
            "/ip service set winbox address=<mgmt-subnet/cidr>"
        ),
        "compliance": {"cis": "3.4", "nist": "AC-17", "iso": "A.8.22", "pci": "2.2.3"},
    },
    {
        "id": "AUTH-010",
"domain": "general",
        "name": "API/REST-API exposed on WAN",
        "severity": "Critical",
        "cvss": "9.1",
        "category": "Authentication & Access Control",
        "path": "/ip service",
        "description": "API or API-SSL service accessible from WAN",
        "detect": [
            r"/ip\s+service\s+set\s+api\s+disabled=no\b",
            r"/ip\s+service\s+set\s+api-ssl\s+disabled=no\b",
        ],
        "remediation": (
            "/ip service set api disabled=yes\n"
            "/ip service set api-ssl address=<mgmt-subnet/cidr>"
        ),
        "compliance": {"cis": "3.5", "nist": "AC-17", "iso": "A.8.22", "pci": "2.2.3"},
    },
    {
        "id": "AUTH-011",
"domain": "general",
        "name": "No login attempt restrictions",
        "severity": "High",
        "cvss": "7.5",
        "category": "Authentication & Access Control",
        "path": "/ip firewall filter",
        "description": "No brute-force protection rules for management service access",
        "detect": [
            r"/ip\s+firewall\s+filter\s+add\s+.*?connection-state=new\s+.*?(?:dst-port|port).*(?:22|8291)",
        ],
        "negate": True,
        "remediation": (
            "Add brute-force detection rules:\n"
            "/ip firewall filter add chain=input protocol=tcp dst-port=22,8291 \\\n"
            "    connection-state=new src-address-list=ssh_blacklist action=drop \\\n"
            "    comment=\"Drop brute-force sources\"\n"
            "/ip firewall filter add chain=input protocol=tcp dst-port=22,8291 \\\n"
            "    connection-state-new src-address-list=ssh_stalker action=add-src-to-list \\\n"
            "    address-list=ssh_blacklist address-list-timeout=1h \\\n"
            "    comment=\"Escalate stalker to blacklist\""
        ),
        "compliance": {"cis": "4.4", "nist": "AC-7", "iso": "A.8.5", "pci": "8.3"},
    },
    {
        "id": "AUTH-012",
"domain": "general",
        "name": "Default management ports unchanged",
        "severity": "Low",
        "cvss": "3.7",
        "category": "Authentication & Access Control",
        "path": "/ip service",
        "description": "Management services using default ports (SSH:22, WinBox:8291, WWW:80)",
        "detect": [
            r"/ip\s+service\s+set\s+ssh\s+.*?port=22\b",
            r"/ip\s+service\s+set\s+winbox\s+.*?port=8291\b",
            r"/ip\s+service\s+set\s+www\s+.*?port=80\b",
        ],
        "remediation": (
            "/ip service set ssh port=2222 comment=\"SSH alternate port\"\n"
            "Note: changing ports is security-through-obscurity; focus on ACLs."
        ),
        "compliance": {"cis": "3.6", "nist": "CM-6", "iso": "A.8.9", "pci": "2.2"},
    },
    {
        "id": "AUTH-013",
"domain": "general",
        "name": "RoMON enabled",
        "severity": "Medium",
        "cvss": "5.9",
        "category": "Authentication & Access Control",
        "path": "/romon",
        "description": "RoMON protocol enabled, allowing remote monitoring without authentication",
        "detect": [
            r"/romon\s+set\s+enabled=yes\b",
        ],
        "remediation": (
            "/romon set enabled=no"
        ),
        "compliance": {"cis": "3.7", "nist": "CM-7", "iso": "A.8.9", "pci": "2.2.2"},
    },
    {
        "id": "AUTH-014",
"domain": "general",
        "name": "No password policy enforcement",
        "severity": "Medium",
        "cvss": "5.9",
        "category": "Authentication & Access Control",
        "path": "/user settings",
        "description": "No minimum password length or complexity requirements configured",
        "detect": [
            r"/user\s+settings\s+set\s+.*?minimum-password-length=",
        ],
        "negate": True,
        "remediation": (
            "/user settings set minimum-password-length=12"
        ),
        "compliance": {"cis": "1.2", "nist": "IA-5(1)", "iso": "A.8.5", "pci": "8.2.1"},
    },
    {
        "id": "AUTH-015",
"domain": "general",
        "name": "User accounts without expiry configured",
        "severity": "Low",
        "cvss": "3.3",
        "category": "Authentication & Access Control",
        "path": "/user",
        "description": "User accounts without configured expiration",
        "detect": [
            r"/user\s+add\s+.*?\bname=(\w+)\b(?!.*?disabled=yes)(?!.*?last-logged-in)",
        ],
        "remediation": (
            "Set password expiration via external management; RouterOS lacks native password expiry."
        ),
        "compliance": {"cis": "1.3", "nist": "AC-2(2)", "iso": "A.8.3", "pci": "8.1"},
    },
    {
        "id": "AUTH-016",
"domain": "general",
        "name": "Sensitive policies too permissive",
        "severity": "High",
        "cvss": "7.1",
        "category": "Authentication & Access Control",
        "path": "/user group",
        "description": "User groups configured with overly broad policies (full/read/write/policy/test/sniff/sensitive/reboot combined)",
        "detect": [
            r"/user\s+group\s+set\s+.*?policy=.*?full\b",
            r"/user\s+group\s+add\s+.*?policy=.*?full\b",
        ],
        "remediation": (
            "Create specific groups with minimal policies:\n"
            "/user group add name=monitor policy=read,test\n"
            "/user group add name=operator policy=read,write,policy,reboot\n"
            "/user set [find group=full] group=operator"
        ),
        "compliance": {"cis": "1.4", "nist": "AC-6", "iso": "A.5.15", "pci": "7.2"},
    },
    {
        "id": "AUTH-017",
"domain": "general",
        "name": "SSH idle timeout not configured",
        "severity": "Medium",
        "cvss": "5.3",
        "category": "Authentication & Access Control",
        "path": "/ip ssh",
        "description": "SSH idle timeout not set — sessions can remain open indefinitely",
        "detect": [
            r"/ip\s+ssh\s+set\s+.*?idle-timeout=\d+[smhd]\b",
        ],
        "negate": True,
        "remediation": "/ip ssh set idle-timeout=10m",
        "compliance": {"cis": "3.5", "nist": "AC-11", "iso": "A.8.5", "pci": "8.1.8"},
    },
    {
        "id": "AUTH-018",
"domain": "general",
        "name": "RADIUS AAA not configured for admin auth",
        "severity": "Medium",
        "cvss": "4.6",
        "category": "Authentication & Access Control",
        "path": "/radius",
        "description": "No RADIUS server configured for centralized admin authentication",
        "detect": [
            r"/radius\s+add\s+.*?address=\d+\.\d+\.\d+\.\d+\b",
        ],
        "negate": True,
        "remediation": (
            "/radius add address=<radius-server-ip> secret=<radius-secret> service=login\n"
            "/user aaa set use-radius=yes"
        ),
        "compliance": {"cis": "7.1", "nist": "AC-2(1)", "iso": "A.8.5", "pci": "8.3"},
    },

    # ═══ SERVICE HARDENING ═══
    {
        "id": "SRV-001",
"domain": "general",
        "name": "DNS remote requests allowed (open resolver)",
        "severity": "High",
        "cvss": "7.5",
        "category": "Service Hardening",
        "path": "/ip dns",
        "description": "DNS server configured to accept remote requests, creating an open DNS resolver",
        "detect": [
            r"/ip\s+dns\s+set\s+.*?allow-remote-requests=yes\b",
        ],
        "remediation": (
            "/ip dns set allow-remote-requests=no"
        ),
        "compliance": {"cis": "5.1", "nist": "SC-7", "iso": "A.8.12", "pci": "2.2.2"},
    },
    {
        "id": "SRV-002",
"domain": "general",
        "name": "Bandwidth server enabled",
        "severity": "Medium",
        "cvss": "5.3",
        "category": "Service Hardening",
        "path": "/tool bandwidth-server",
        "description": "Bandwidth testing server enabled, consuming resources and potentially used for DoS amplification",
        "detect": [
            r"/tool\s+bandwidth-server\s+set\s+enabled=yes\b",
        ],
        "remediation": (
            "/tool bandwidth-server set enabled=no"
        ),
        "compliance": {"cis": "5.2", "nist": "CM-7", "iso": "A.8.9", "pci": "2.2.2"},
    },
    {
        "id": "SRV-003",
"domain": "general",
        "name": "Proxy service enabled",
        "severity": "High",
        "cvss": "7.5",
        "category": "Service Hardening",
        "path": "/ip proxy",
        "description": "Web proxy service enabled, creating an open proxy if not restricted",
        "detect": [
            r"/ip\s+proxy\s+set\s+enabled=yes\b",
        ],
        "remediation": (
            "/ip proxy set enabled=no"
        ),
        "compliance": {"cis": "5.3", "nist": "CM-7", "iso": "A.8.9", "pci": "2.2.2"},
    },
    {
        "id": "SRV-004",
"domain": "general",
        "name": "SOCKS service enabled",
        "severity": "High",
        "cvss": "7.5",
        "category": "Service Hardening",
        "path": "/ip socks",
        "description": "SOCKS proxy enabled, potential for traffic tunneling and compromise",
        "detect": [
            r"/ip\s+socks\s+set\s+enabled=yes\b",
        ],
        "remediation": (
            "/ip socks set enabled=no"
        ),
        "compliance": {"cis": "5.4", "nist": "CM-7", "iso": "A.8.9", "pci": "2.2.2"},
    },
    {
        "id": "SRV-005",
"domain": "general",
        "name": "UPnP enabled",
        "severity": "High",
        "cvss": "7.4",
        "category": "Service Hardening",
        "path": "/ip upnp",
        "description": "UPnP enabled, allowing internal devices to open firewall holes automatically",
        "detect": [
            r"/ip\s+upnp\s+set\s+enabled=yes\b",
        ],
        "remediation": (
            "/ip upnp set enabled=no"
        ),
        "compliance": {"cis": "5.5", "nist": "CM-7", "iso": "A.8.9", "pci": "2.2.2"},
    },
    {
        "id": "SRV-006",
"domain": "general",
        "name": "Neighbor discovery enabled on WAN",
        "severity": "Medium",
        "cvss": "5.3",
        "category": "Service Hardening",
        "path": "/ip neighbor discovery",
        "description": "Neighbor discovery (MNDP) enabled on WAN-facing interfaces, leaking device info at L2",
        "detect": [
            r"/ip\s+neighbor\s+discovery\s+set\s+.*?discover=yes\b",
            r"/ip\s+neighbor\s+discovery-settings\s+set\s+.*?discover=yes\b",
        ],
        "remediation": (
            "/ip neighbor discovery set interfaces=all discover=no\n"
            "/ip neighbor discovery set interfaces=<lan-bridge> discover=yes"
        ),
        "compliance": {"cis": "5.6", "nist": "CM-7", "iso": "A.8.20", "pci": "2.2.2"},
    },
    {
        "id": "SRV-007",
"domain": "general",
        "name": "SNMP v1/v2c with public community",
        "severity": "High",
        "cvss": "7.5",
        "category": "Service Hardening",
        "path": "/snmp community",
        "description": "SNMP community 'public' configured with read access",
        "detect": [
            r"/snmp\s+community\s+set\s+.*?\bname=public\b",
            r"/snmp\s+community\s+add\s+.*?\bname=public\b",
        ],
        "remediation": (
            "/snmp community remove [find name=public]\n"
            "/snmp community add name=readonly address=<mgmt-subnet/cidr> security=authorized\n"
            "# Or disable SNMP entirely:\n"
            "/snmp set enabled=no"
        ),
        "compliance": {"cis": "5.7", "nist": "SI-4", "iso": "A.8.12", "pci": "2.2.2"},
    },
    {
        "id": "SRV-008",
"domain": "general",
        "name": "Telnet service enabled",
        "severity": "High",
        "cvss": "7.4",
        "category": "Service Hardening",
        "path": "/ip service",
        "description": "Telnet service enabled (cleartext protocol, should be replaced by SSH)",
        "detect": [
            r"/ip\s+service\s+set\s+telnet\s+disabled=no\b",
            r"/ip\s+service\s+enable\s+telnet\b",
        ],
        "remediation": (
            "/ip service disable telnet"
        ),
        "compliance": {"cis": "5.8", "nist": "CM-7", "iso": "A.8.9", "pci": "2.2.3"},
    },
    {
        "id": "SRV-009",
"domain": "general",
        "name": "FTP service enabled",
        "severity": "High",
        "cvss": "7.4",
        "category": "Service Hardening",
        "path": "/ip service",
        "description": "FTP service enabled (cleartext credentials, use SCP/SFTP instead)",
        "detect": [
            r"/ip\s+service\s+set\s+ftp\s+disabled=no\b",
            r"/ip\s+service\s+enable\s+ftp\b",
        ],
        "remediation": (
            "/ip service disable ftp"
        ),
        "compliance": {"cis": "5.9", "nist": "CM-7", "iso": "A.8.9", "pci": "2.2.3"},
    },
    {
        "id": "SRV-010",
"domain": "general",
        "name": "PPTP server enabled",
        "severity": "Medium",
        "cvss": "5.9",
        "category": "Service Hardening",
        "path": "/ppp profile",
        "description": "PPTP VPN protocol enabled (insecure, use WireGuard or L2TP/IPsec instead)",
        "detect": [
            r"/ppp\s+profile\s+set\s+.*?\bpptp\b",
        ],
        "remediation": (
            "/ppp profile set [find name=default-encryption] use-encryption=yes\n"
            "/interface wireguard add name=wg0\n"
            "# Migrate PPTP users to WireGuard"
        ),
        "compliance": {"cis": "5.10", "nist": "SC-8", "iso": "A.8.22", "pci": "2.2.3"},
    },
    {
        "id": "SRV-011",
"domain": "general",
        "name": "Cloud services enabled",
        "severity": "Medium",
        "cvss": "4.6",
        "category": "Service Hardening",
        "path": "/ip cloud",
        "description": "MikroTik cloud services enabled (DDNS, update-time), increasing attack surface",
        "detect": [
            r"/ip\s+cloud\s+set\s+.*?ddns-enabled=yes\b",
            r"/ip\s+cloud\s+set\s+.*?update-time=yes\b",
        ],
        "remediation": (
            "/ip cloud set ddns-enabled=no update-time=no"
        ),
        "compliance": {"cis": "5.11", "nist": "CM-7", "iso": "A.8.9", "pci": "2.2.2"},
    },
    {
        "id": "SRV-012",
"domain": "general",
        "name": "SMB service enabled",
        "severity": "Medium",
        "cvss": "4.6",
        "category": "Service Hardening",
        "path": "/ip smb",
        "description": "SMB file sharing service enabled",
        "detect": [
            r"/ip\s+smb\s+set\s+enabled=yes\b",
        ],
        "remediation": (
            "/ip smb set enabled=no"
        ),
        "compliance": {"cis": "5.12", "nist": "CM-7", "iso": "A.8.9", "pci": "2.2.2"},
    },
    {
        "id": "SRV-013",
"domain": "general",
        "name": "Unused interfaces not disabled",
        "severity": "Low",
        "cvss": "3.7",
        "category": "Service Hardening",
        "path": "/interface ethernet",
        "description": "Physical ethernet ports may be unused but still enabled",
        "detect": [
            r"/interface\s+ethernet\s+set\s+.*?\bdisabled=no\b",
        ],
        "remediation": (
            "/interface ethernet set [find name=etherX] disabled=yes\n"
            "Requires knowledge of which interfaces are in use."
        ),
        "compliance": {"cis": "1.1", "nist": "CM-7", "iso": "A.8.9", "pci": "2.2.2"},
    },
    {
        "id": "SRV-014",
"domain": "general",
        "name": "WebFig/HTTP enabled without HTTPS",
        "severity": "Medium",
        "cvss": "5.9",
        "category": "Service Hardening",
        "path": "/ip service",
        "description": "HTTP (WWW) enabled while HTTPS (WWW-SSL) is disabled, exposing cleartext admin interface",
        "detect": [
            r"/ip\s+service\s+set\s+www\s+disabled=no\b",
            r"/ip\s+service\s+disable\s+www-ssl\b",
        ],
        "remediation": (
            "/ip service disable www\n"
            "/ip service enable www-ssl\n"
            "/ip service set www-ssl certificate=<valid-cert>"
        ),
        "compliance": {"cis": "5.13", "nist": "SC-8", "iso": "A.8.22", "pci": "2.2.3"},
    },
    {
        "id": "SRV-015",
"domain": "general",
        "name": "LCD not secured",
        "severity": "Low",
        "cvss": "2.2",
        "category": "Service Hardening",
        "path": "/lcd",
        "description": "LCD panel enabled without PIN protection (hardware-specific)",
        "detect": [
            r"/lcd\s+set\s+enabled=yes\b(?!.*pin=)",
        ],
        "remediation": (
            "/lcd set enabled=yes pin=<numeric-pin>"
        ),
        "compliance": {"cis": "5.14", "nist": "PE-3", "iso": "A.7.6", "pci": "9.1"},
    },
    {
        "id": "SRV-016",
"domain": "general",
        "name": "DNS cache size not configured",
        "severity": "Low",
        "cvss": "3.3",
        "category": "Service Hardening",
        "path": "/ip dns",
        "description": "DNS cache size not explicitly configured — using potentially suboptimal default",
        "detect": [
            r"/ip\s+dns\s+set\s+.*?cache-size=\d+\b",
        ],
        "negate": True,
        "remediation": (
            "/ip dns set cache-size=4096\n"
            "# For large RAM devices (>512MB): cache-size=8192 recommended"
        ),
        "compliance": {"cis": "5.7", "nist": "SC-20", "iso": "A.8.12", "pci": "2.2"},
    },
    {
        "id": "SRV-017",
"domain": "general",
        "name": "DNS query server TCP disabled",
        "severity": "Low",
        "cvss": "3.3",
        "category": "Service Hardening",
        "path": "/ip dns",
        "description": "DNS query-server-tcp not enabled — may cause issues with large DNS responses",
        "detect": [
            r"/ip\s+dns\s+set\s+.*?query-server-tcp=yes\b",
        ],
        "negate": True,
        "remediation": "/ip dns set query-server-tcp=yes",
        "compliance": {"cis": "5.8", "nist": "SC-20", "iso": "A.8.12", "pci": "2.2"},
    },

    # ═══ FIREWALL & NETWORK SECURITY ═══
    {
        "id": "FW-001",
"domain": "general",
        "name": "No firewall filter rules defined",
        "severity": "Critical",
        "cvss": "10.0",
        "category": "Firewall & Network Security",
        "path": "/ip firewall filter",
        "description": "No firewall filter rules configured at all — device is completely unprotected",
        "detect": [
            r"/ip\s+firewall\s+filter",
        ],
        "negate": True,
        "remediation": (
            "Implement a defense-in-depth firewall ruleset:\n"
            "/ip firewall filter add chain=input connection-state=established,related action=accept \\\n"
            "    comment=\"Allow established/related\"\n"
            "/ip firewall filter add chain=input connection-state=invalid action=drop \\\n"
            "    comment=\"Drop invalid connections\"\n"
            "/ip firewall filter add chain=input protocol=icmp action=accept \\\n"
            "    comment=\"Allow ICMP\"\n"
            "/ip firewall filter add chain=input dst-address-type=!local action=drop \\\n"
            "    in-interface-list=WAN comment=\"Drop WAN to router\""
        ),
        "compliance": {"cis": "4.1", "nist": "SC-7", "iso": "A.8.20", "pci": "1.1"},
    },
    {
        "id": "FW-002",
"domain": "general",
        "name": "WAN input chain without default drop rule",
        "severity": "High",
        "cvss": "8.6",
        "category": "Firewall & Network Security",
        "path": "/ip firewall filter input",
        "description": "No default drop rule on WAN-facing input chain",
        "detect": [
            r"/ip\s+firewall\s+filter\s+add\s+chain=input\s+.*?\baction=drop\b.*?\bin-interface",
        ],
        "negate": True,
        "remediation": (
            "/ip firewall filter add chain=input in-interface-list=WAN action=drop \\\n"
            "    comment=\"Drop all WAN input by default\""
        ),
        "compliance": {"cis": "4.2", "nist": "SC-7(5)", "iso": "A.8.20", "pci": "1.2"},
    },
    {
        "id": "FW-003",
"domain": "general",
        "name": "No established/related connection rule",
        "severity": "High",
        "cvss": "7.5",
        "category": "Firewall & Network Security",
        "path": "/ip firewall filter input",
        "description": "No rule to accept established/related connections in input chain",
        "detect": [
            r"/ip\s+firewall\s+filter\s+add\s+chain=input\s+.*?\bconnection-state=established,related\b",
        ],
        "negate": True,
        "remediation": (
            "/ip firewall filter add chain=input connection-state=established,related \\\n"
            "    action=accept comment=\"Allow established/related\""
        ),
        "compliance": {"cis": "4.3", "nist": "SC-7", "iso": "A.8.20", "pci": "1.2"},
    },
    {
        "id": "FW-004",
"domain": "general",
        "name": "No brute-force protection",
        "severity": "High",
        "cvss": "7.5",
        "category": "Firewall & Network Security",
        "path": "/ip firewall filter",
        "description": "No address-list based brute-force protection rules for management services",
        "detect": [
            r"/ip\s+firewall\s+filter\s+add\s+.*?src-address-list=.*?blacklist\b.*?action=drop\b",
        ],
        "negate": True,
        "remediation": (
            "See AUTH-011 for brute-force protection rules."
        ),
        "compliance": {"cis": "4.4", "nist": "AC-7", "iso": "A.8.5", "pci": "8.3"},
    },
    {
        "id": "FW-005",
"domain": "general",
        "name": "No bogon filtering in RAW table",
        "severity": "High",
        "cvss": "7.5",
        "category": "Firewall & Network Security",
        "path": "/ip firewall raw",
        "description": "RAW table does not filter bogon IPs (RFC1918, loopback, multicast) on WAN interface",
        "detect": [
            r"/ip\s+firewall\s+raw\s+add\s+chain=prerouting\s+.*?\bdst-address=.*?\baction=drop\b",
        ],
        "negate": True,
        "remediation": (
            "/ip firewall raw add chain=prerouting dst-address=10.0.0.0/8 action=drop \\\n"
            "    in-interface-list=WAN comment=\"Drop RFC1918\"\n"
            "/ip firewall raw add chain=prerouting dst-address=172.16.0.0/12 action=drop \\\n"
            "    in-interface-list=WAN comment=\"Drop RFC1918\"\n"
            "/ip firewall raw add chain=prerouting dst-address=192.168.0.0/16 action=drop \\\n"
            "    in-interface-list=WAN comment=\"Drop RFC1918\"\n"
            "/ip firewall raw add chain=prerouting dst-address=127.0.0.0/8 action=drop \\\n"
            "    in-interface-list=WAN comment=\"Drop loopback\"\n"
            "/ip firewall raw add chain=prerouting protocol=tcp dst-port=22 action=drop \\\n"
            "    in-interface-list=WAN src-address-list=blacklist comment=\"Drop blacklist\""
        ),
        "compliance": {"cis": "4.5", "nist": "SC-7(5)", "iso": "A.8.20", "pci": "1.2"},
    },
    {
        "id": "FW-006",
"domain": "general",
        "name": "IPv6 firewall not configured",
        "severity": "High",
        "cvss": "7.5",
        "category": "Firewall & Network Security",
        "path": "/ipv6 firewall filter",
        "description": "IPv6 firewall rules not configured (if IPv6 is enabled)",
        "detect": [
            r"/ipv6\s+firewall\s+filter",
        ],
        "negate": True,
        "remediation": (
            "/ipv6 firewall filter add chain=input connection-state=established,related action=accept\n"
            "/ipv6 firewall filter add chain=input connection-state=invalid action=drop\n"
            "/ipv6 firewall filter add chain=input protocol=icmpv6 action=accept\n"
            "/ipv6 firewall filter add chain=input action=drop comment=\"Drop all IPv6 input default\""
        ),
        "compliance": {"cis": "4.6", "nist": "SC-7(11)", "iso": "A.8.20", "pci": "1.2"},
    },
    {
        "id": "FW-007",
"domain": "general",
        "name": "FastTrack not configured",
        "severity": "Low",
        "cvss": "3.3",
        "category": "Firewall & Network Security",
        "path": "/ip firewall filter",
        "description": "FastTrack connection acceleration not configured for established connections",
        "detect": [
            r"/ip\s+firewall\s+filter\s+add\s+.*?\baction=fasttrack-connection\b",
        ],
        "negate": True,
        "remediation": (
            "/ip firewall filter add chain=forward connection-state=established,related \\\n"
            "    action=fasttrack-connection comment=\"FastTrack established\"\n"
            "Note: FastTrack works with NAT but bypasses queue trees, mangle rules, and per-connection queuing."
        ),
        "compliance": {"cis": "4.7", "nist": "SC-7", "iso": "A.8.20", "pci": "1.2"},
    },
    {
        "id": "FW-008",
"domain": "general",
        "name": "Port knocking not configured for WAN services",
        "severity": "Medium",
        "cvss": "5.9",
        "category": "Firewall & Network Security",
        "path": "/ip firewall filter",
        "description": "Management services on WAN lack port knocking protection",
        "detect": [
            r"/ip\s+firewall\s+filter\s+add\s+.*?port-knocking\b",
        ],
        "negate": True,
        "remediation": (
            "See MikroTik port knocking examples at:\n"
            "https://help.mikrotik.com/docs/spaces/ROS/pages/154042369/Port+knocking"
        ),
        "compliance": {"cis": "4.8", "nist": "AC-17", "iso": "A.8.20", "pci": "1.2"},
    },
    {
        "id": "FW-009",
"domain": "general",
        "name": "WAN-side management access unrestricted",
        "severity": "Critical",
        "cvss": "9.1",
        "category": "Firewall & Network Security",
        "path": "/ip firewall filter",
        "description": "Management services (SSH, WinBox, API) reachable from WAN without restriction",
        "detect": [
            r"/ip\s+firewall\s+filter\s+add\s+chain=input\s+.*?\bin-interface=ether1\b(?!.*action=drop)",
        ],
        "remediation": (
            "Add interface-list-based restriction:\n"
            "/interface list add name=WAN\n"
            "/interface list member add interface=ether1 list=WAN\n"
            "/interface list add name=LAN\n"
            "/interface list member add interface=bridge1 list=LAN\n"
            "/ip firewall filter add chain=input in-interface-list=WAN action=drop \\\n"
            "    comment=\"Drop all WAN input\"\n"
            "/ip firewall filter add chain=input in-interface-list=LAN \\\n"
            "    protocol=tcp dst-port=22,8291 action=accept comment=\"Allow mgmt from LAN\""
        ),
        "compliance": {"cis": "4.2", "nist": "AC-17(2)", "iso": "A.8.20", "pci": "1.2"},
    },
    {
        "id": "FW-010",
"domain": "general",
        "name": "Forward chain too permissive",
        "severity": "High",
        "cvss": "7.5",
        "category": "Firewall & Network Security",
        "path": "/ip firewall filter forward",
        "description": "No firewall restrictions in forward chain (inter-VLAN traffic unrestricted)",
        "detect": [
            r"/ip\s+firewall\s+filter\s+add\s+chain=forward\s+.*?\baction=accept\b",
        ],
        "remediation": (
            "/ip firewall filter add chain=forward in-interface-list=LAN \\\n"
            "    out-interface-list=LAN connection-state=established,related action=accept\n"
            "/ip firewall filter add chain=forward in-interface-list=LAN \\\n"
            "    out-interface-list=WAN action=accept\n"
            "/ip firewall filter add chain=forward action=drop comment=\"Drop all forward default\""
        ),
        "compliance": {"cis": "4.9", "nist": "SC-7", "iso": "A.8.21", "pci": "1.3"},
    },
    {
        "id": "FW-011",
"domain": "general",
        "name": "NAT rules with overly broad source",
        "severity": "Medium",
        "cvss": "5.9",
        "category": "Firewall & Network Security",
        "path": "/ip firewall nat",
        "description": "Source NAT rules using source=0.0.0.0/0 should be scoped to LAN subnets",
        "detect": [
            r"/ip\s+firewall\s+nat\s+add\s+chain=srcnat\s+.*?\bsrc-address=0\.0\.0\.0/0\b",
        ],
        "remediation": (
            "/ip firewall nat set [find chain=srcnat] src-address=192.168.0.0/16\n"
            "# Or better, use specific LAN subnet"
        ),
        "compliance": {"cis": "4.10", "nist": "SC-7", "iso": "A.8.20", "pci": "1.2"},
    },
    {
        "id": "FW-012",
"domain": "general",
        "name": "No ICMP rate limiting",
        "severity": "Medium",
        "cvss": "5.3",
        "category": "Firewall & Network Security",
        "path": "/ip firewall filter",
        "description": "No rate limiting on ICMP, could be used for DoS amplification",
        "detect": [
            r"/ip\s+firewall\s+filter\s+add\s+chain=input\s+.*?protocol=icmp\s+.*?\blimit\b",
        ],
        "negate": True,
        "remediation": (
            "/ip firewall filter add chain=input protocol=icmp limit=10,5:packets \\\n"
            "    action=accept comment=\"Rate-limited ICMP\""
        ),
        "compliance": {"cis": "4.11", "nist": "SC-7", "iso": "A.8.20", "pci": "1.2"},
    },
    {
        "id": "FW-013",
"domain": "general",
        "name": "DSTNAT without source restriction",
        "severity": "Medium",
        "cvss": "6.1",
        "category": "Firewall & Network Security",
        "path": "/ip firewall nat",
        "description": "Destination NAT rules without src-address restriction expose internal services broadly",
        "detect": [
            r"/ip\s+firewall\s+nat\s+add\s+chain=dstnat\b(?!.*src-address=)",
        ],
        "remediation": (
            "/ip firewall nat add chain=dstnat dst-port=<port> protocol=tcp \\\n"
            "    in-interface=ether1 src-address=<allowed-ip/cidr> action=dst-nat \\\n"
            "    to-addresses=<internal-ip> to-ports=<port>\n"
            "Always restrict DSTNAT with src-address when possible."
        ),
        "compliance": {"cis": "4.12", "nist": "SC-7", "iso": "A.8.20", "pci": "1.3"},
    },
    {
        "id": "FW-014",
"domain": "general",
        "name": "Broadcast/multicast not blocked",
        "severity": "Low",
        "cvss": "3.7",
        "category": "Firewall & Network Security",
        "path": "/ip firewall filter forward",
        "description": "Broadcast and multicast traffic not explicitly blocked in forward chain",
        "detect": [
            r"/ip\s+firewall\s+filter\s+add\s+chain=forward\s+.*?\bdst-address-type=broadcast\b",
            r"/ip\s+firewall\s+filter\s+add\s+chain=forward\s+.*?\bdst-address-type=multicast\b",
        ],
        "negate": True,
        "remediation": (
            "/ip firewall filter add chain=forward dst-address-type=broadcast action=drop\n"
            "/ip firewall filter add chain=forward dst-address-type=multicast action=drop"
        ),
        "compliance": {"cis": "4.13", "nist": "SC-7", "iso": "A.8.20", "pci": "1.2"},
    },
    {
        "id": "FW-015",
"domain": "general",
        "name": "RAW table not configured",
        "severity": "Low",
        "cvss": "3.7",
        "category": "Firewall & Network Security",
        "path": "/ip firewall raw",
        "description": "RAW prerouting chain not configured for pre-conntrack packet filtering",
        "detect": [
            r"/ip\s+firewall\s+raw",
        ],
        "negate": True,
        "remediation": (
            "/ip firewall raw add chain=prerouting in-interface-list=WAN \\\n"
            "    action=notrack comment=\"Skip tracking for high-throughput WAN\""
        ),
        "compliance": {"cis": "4.14", "nist": "SC-7", "iso": "A.8.20", "pci": "1.2"},
    },
    {
        "id": "FW-016",
"domain": "general",
        "name": "Connection tracking limits not configured",
        "severity": "Medium",
        "cvss": "5.9",
        "category": "Firewall & Network Security",
        "path": "/ip firewall connection tracking",
        "description": "Connection tracking max-entries or TCP syncookies not configured",
        "detect": [
            r"/ip\s+firewall\s+connection-tracking\s+set",
        ],
        "negate": True,
        "remediation": (
            "/ip firewall connection-tracking set max-entries=16384 tcp-syncookie=yes"
        ),
        "compliance": {"cis": "4.15", "nist": "SC-7", "iso": "A.8.20", "pci": "1.2"},
    },
    {
        "id": "FW-017",
"domain": "general",
        "name": "BGP TTL security not configured",
        "severity": "Medium",
        "cvss": "5.3",
        "category": "Firewall & Network Security",
        "path": "/routing bgp connection",
        "description": "BGP TTL security (GTSM) not configured — BGP sessions vulnerable to off-path attacks",
        "detect": [
            r"/routing\s+bgp\s+connection\s+add\s+.*?ttl=\d+\b",
        ],
        "negate": True,
        "remediation": "/routing bgp connection set [find remote.address=<peer>] ttl=1",
        "compliance": {"cis": "4.16", "nist": "SC-7", "iso": "A.8.20", "pci": "1.2"},
    },

    # ═══ SYSTEM HARDENING ═══
    # SYS-001 through SYS-009
    {
        "id": "SYS-001",
"domain": "general",
        "name": "RouterOS version check",
        "severity": "Info",
        "cvss": "0.0",
        "category": "System Hardening",
        "path": "export header",
        "description": "RouterOS version detected from export file header (no CVE analysis without live check)",
        "detect": [
            r"#\s+\w+/\w+/\d+\s+\d+:\d+:\d+\s+by\s+RouterOS\s+(\d+\.\d+)",
        ],
        "remediation": "Check for CVEs at https://help.mikrotik.com and upgrade to latest stable.",
        "compliance": {"cis": "6.1", "nist": "SI-2", "iso": "A.8.8", "pci": "6.2"},
    },
    {
        "id": "SYS-002",
"domain": "general",
        "name": "System identity not set to descriptive name",
        "severity": "Low",
        "cvss": "1.9",
        "category": "System Hardening",
        "path": "/system identity",
        "description": "System identity is not configured or is at default value (RouterOS)",
        "detect": [
            r"/system\s+identity\s+set\s+name=(RouterOS|MikroTik)\b",
        ],
        "remediation": (
            '/system identity set name="<location-function-type>-<device-number>"'
        ),
        "compliance": {"cis": "6.2", "nist": "CM-8", "iso": "A.8.9", "pci": "2.2"},
    },
    {
        "id": "SYS-003",
"domain": "general",
        "name": "NTP not configured",
        "severity": "High",
        "cvss": "7.5",
        "category": "System Hardening",
        "path": "/system ntp client",
        "description": "NTP client not configured — logs will have incorrect timestamps",
        "detect": [
            r"/system\s+ntp\s+client\s+set\s+enabled=yes\b",
        ],
        "negate": True,
        "remediation": (
            "/system ntp client set enabled=yes primary-ntp=pool.ntp.org \\\n"
            "    secondary-ntp=time.google.com"
        ),
        "compliance": {"cis": "6.3", "nist": "AU-8", "iso": "A.8.16", "pci": "10.4"},
    },
    {
        "id": "SYS-004",
"domain": "general",
        "name": "Local logging not configured",
        "severity": "Medium",
        "cvss": "5.9",
        "category": "System Hardening",
        "path": "/system logging",
        "description": "System logging not configured for important topics (firewall, errors, critical)",
        "detect": [
            r"/system\s+logging\s+add\s+topics=critical\b",
            r"/system\s+logging\s+add\s+topics=error\b",
            r"/system\s+logging\s+add\s+topics=firewall\b",
        ],
        "remediation": (
            "/system logging add topics=info action=memory\n"
            "/system logging add topics=critical,error,warning action=memory\n"
            "/system logging add topics=ssh,winbox,account action=memory"
        ),
        "compliance": {"cis": "7.1", "nist": "AU-3", "iso": "A.8.15", "pci": "10.1"},
    },
    {
        "id": "SYS-005",
"domain": "general",
        "name": "Remote syslog not configured",
        "severity": "Medium",
        "cvss": "5.9",
        "category": "System Hardening",
        "path": "/system logging action",
        "description": "No remote syslog server configured for centralized log aggregation",
        "detect": [
            r"/system\s+logging\s+action\s+set\s+remote\s+.*?remote=\d+\.\d+\.\d+\.\d+\b",
        ],
        "negate": True,
        "remediation": (
            "/system logging action set remote remote=<syslog-server-ip> \\\n"
            "    remote-port=514 bsd-syslog=yes\n"
            "/system logging add topics=critical,error,warning,firewall,account \\\n"
            "    action=remote comment=\"Send to SIEM\""
        ),
        "compliance": {"cis": "7.2", "nist": "AU-9(2)", "iso": "A.8.15", "pci": "10.2"},
    },
    {
        "id": "SYS-006",
"domain": "general",
        "name": "Auto-update check not configured",
        "severity": "Low",
        "cvss": "3.7",
        "category": "System Hardening",
        "path": "/system package update",
        "description": "RouterOS auto-update check channel not configured",
        "detect": [
            r"/system\s+package\s+update\s+set\s+channel=stable\b",
        ],
        "negate": True,
        "remediation": (
            "/system package update set channel=stable\n"
            "# Then periodically check:\n"
            "/system package update check-for-updates"
        ),
        "compliance": {"cis": "6.4", "nist": "SI-2", "iso": "A.8.8", "pci": "6.2"},
    },
    {
        "id": "SYS-007",
"domain": "general",
        "name": "Unsigned packages allowed",
        "severity": "High",
        "cvss": "7.5",
        "category": "System Hardening",
        "path": "/system package update",
        "description": "RouterOS configured to allow unsigned packages",
        "detect": [
            r"/system\s+package\s+update\s+set\s+.*?allow-signed=no\b",
        ],
        "skip_if_version_ge": 7.0,
        "remediation": (
            "/system package update set allow-signed=yes"
        ),
        "compliance": {"cis": "6.5", "nist": "SI-7", "iso": "A.8.25", "pci": "6.3"},
    },
    {
        "id": "SYS-008",
"domain": "general",
        "name": "Support output not secured",
        "severity": "Low",
        "cvss": "3.3",
        "category": "System Hardening",
        "path": "/tool",
        "description": "Support/troubleshooting tools accessible without restriction",
        "detect": [
            r"/tool\s+sniffer\b",
        ],
        "remediation": (
            "Restrict sniffer and bandwidth test via firewall or disable."
        ),
        "compliance": {"cis": "6.6", "nist": "AU-9", "iso": "A.8.9", "pci": "10.7"},
    },
    {
        "id": "SYS-009",
"domain": "general",
        "name": "Backup not configured",
        "severity": "Medium",
        "cvss": "5.5",
        "category": "System Hardening",
        "path": "/system backup",
        "description": "No scheduled backup configuration found",
        "detect": [
            r"/system\s+backup\s+save\b",
            r"/export\s+file={SCHEDULED_BACKUP}",
        ],
        "remediation": (
            "# Add scheduled backup via scheduler:\n"
            "/system scheduler add name=daily-backup interval=1d \\\n"
            '    on-event="/system backup save name=auto-backup; \\\n'
            '    /export file=auto-config" \\\n'
            "    comment=\"Daily configuration backup\""
        ),
        "compliance": {"cis": "6.7", "nist": "CP-9", "iso": "A.8.8", "pci": "11.5"},
    },
    {
        "id": "SYS-010",
"domain": "general",
        "name": "IPv6 not explicitly disabled when unused",
        "severity": "Low",
        "cvss": "3.3",
        "category": "System Hardening",
        "path": "/ipv6",
        "description": "IPv6 not disabled — potential unused attack surface if IPv6 is not deployed",
        "detect": [
            r"/ipv6\s+settings\s+set\s+disable-ipv6=yes\b",
        ],
        "negate": True,
        "remediation": (
            "/ipv6 settings set disable-ipv6=yes"
        ),
        "compliance": {"cis": "6.8", "nist": "CM-7", "iso": "A.8.9", "pci": "2.2.2"},
    },

    # ═══ NETWORK CONFIGURATION ═══
    {
        "id": "NET-001",
"domain": "general",
        "name": "Bridge VLAN filtering not enabled with VLANs present",
        "severity": "High",
        "cvss": "7.1",
        "category": "Network Configuration",
        "path": "/interface bridge",
        "description": "VLAN interfaces exist but bridge VLAN filtering is not enabled",
        "detect": [
            r"/interface\s+vlan\b",
        ],
        "context": "if /interface bridge vlan-filtering=no or not set",
        "remediation": (
            "/interface bridge set [find name=bridge1] vlan-filtering=yes\n"
            "# Note: disables HW offload on hAP ac²!"
        ),
        "compliance": {"cis": "8.1", "nist": "SC-7", "iso": "A.8.21", "pci": "1.3"},
    },
    {
        "id": "NET-002",
"domain": "general",
        "name": "DHCP server without secure options",
        "severity": "Medium",
        "cvss": "5.9",
        "category": "Network Configuration",
        "path": "/ip dhcp-server",
        "description": "DHCP server not configured with lease limits or authoritative flag",
        "detect": [
            r"/ip\s+dhcp-server\s+add\s+.*?\bname=(\w+)\b(?!.*lease-time=)",
            r"/ip\s+dhcp-server\s+set\s+.*?\buse-radius=yes\b",
        ],
        "remediation": (
            "/ip dhcp-server set [find] authoritative=yes lease-time=01:00:00"
        ),
        "compliance": {"cis": "8.2", "nist": "SC-7", "iso": "A.8.9", "pci": "1.3"},
    },
    {
        "id": "NET-003",
"domain": "general",
        "name": "DHCP lease storage on disk enabled (flash warning)",
        "severity": "Low",
        "cvss": "3.3",
        "category": "Network Configuration",
        "path": "/ip dhcp-server config",
        "description": "DHCP lease persistence to disk enabled on flash-constrained hardware (hAP ac² risk)",
        "detect": [
            r"/ip\s+dhcp-server\s+config\s+set\s+store-leases-on-disk=yes\b",
        ],
        "skip_unless_model_in": ["RBD52G", "RB750", "RB750P", "RB750GL", "RB750Gr3", "RB951", "hAP ac", "hAP ac²", "hAP ac2", "CRS", "CRS1"],
        "remediation": (
            "/ip dhcp-server config set store-leases-on-disk=no"
        ),
        "compliance": {"cis": "8.3", "nist": "CM-6", "iso": "A.8.9", "pci": "2.2"},
    },
    {
        "id": "NET-004",
"domain": "general",
        "name": "DNS cache poisoning protection not configured",
        "severity": "Medium",
        "cvss": "5.3",
        "category": "Network Configuration",
        "path": "/ip dns",
        "description": "DNS cache size limits or query pool restrictions not configured",
        "detect": [
            r"/ip\s+dns\s+set\s+.*?cache-size=2048\b",
            r"/ip\s+dns\s+set\s+.*?use-doh=yes\b",
        ],
        "remediation": (
            "/ip dns set cache-size=4096"
        ),
        "compliance": {"cis": "8.4", "nist": "SC-20", "iso": "A.8.12", "pci": "2.2"},
    },
    {
        "id": "NET-005",
"domain": "general",
        "name": "No DNS forwarders configured",
        "severity": "Medium",
        "cvss": "5.3",
        "category": "Network Configuration",
        "path": "/ip dns",
        "description": "DNS servers (forwarders) not explicitly configured",
        "detect": [
            r"/ip\s+dns\s+set\s+.*?servers=\d+\.\d+\.\d+\.\d+\b",
            r"/ip\s+dns\s+set\s+.*?servers=[0-9a-fA-F:]+\b",
            r"/ip\s+dns\s+set\s+.*?servers=[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        ],
        "negate": True,
        "remediation": (
            "/ip dns set servers=1.1.1.1,8.8.8.8"
        ),
        "compliance": {"cis": "8.5", "nist": "SC-20", "iso": "A.8.12", "pci": "2.2"},
    },
    {
        "id": "NET-006",
"domain": "general",
        "name": "Bridge HW offload misconfiguration (hAP ac²)",
        "severity": "High",
        "cvss": "7.0",
        "category": "Network Configuration",
        "path": "/interface bridge",
        "description": "hAP ac² detected with bridge VLAN filtering — HW offload is disabled",
        "detect": [
            r"#\s+.*?hAP\s+ac\b",
            r"/interface\s+bridge\s+set\s+.*?vlan-filtering=yes\b",
        ],
        "context": "If vlan-filtering=yes is set on hAP ac² (RBD52G), HW offload is disabled. Consider dual-bridge workaround.",
        "remediation": "See SECURITY_BASELINE.md section 9 for dual-bridge workaround.",
        "compliance": {"cis": "8.6", "nist": "CM-6", "iso": "A.8.9", "pci": "2.2"},
    },
    {
        "id": "NET-007",
"domain": "general",
        "name": "MTU/fragmentation mismatch or PPPoE without MSS clamp",
        "severity": "Low",
        "cvss": "3.3",
        "category": "Network Configuration",
        "path": "/interface bridge, /interface pppoe-client",
        "description": "MTU values differ between bridge interface and member ports, or PPPoE client configured without MSS clamping",
        "detect": [
            r"/interface\s+bridge\s+set\s+.*?mtu=(\d+)",
            r"/interface\s+pppoe-client\s+add\s+.*?mtu=",
        ],
        "remediation": (
            "Ensure bridge MTU matches lowest port MTU minus L2 overhead.\n"
            "For PPPoE, add MSS clamp mangle rule:\n"
            "/ip firewall mangle add chain=forward protocol=tcp tcp-flags=syn \\n"
            "    tcp-mss=1452-65535 action=change-mss new-mss=1452 \\n"
            "    comment=\"Clamp TCP MSS to 1452 for PPPoE\""
        ),
        "compliance": {"cis": "8.7", "nist": "CM-6", "iso": "A.8.9", "pci": "2.2"},
    },
    {
        "id": "NET-008",
"domain": "general",
        "name": "VRRP/HA not configured for critical services",
        "severity": "Info",
        "cvss": "0.0",
        "category": "Network Configuration",
        "path": "/ip address",
        "description": "No VRRP or HA configuration detected for default gateway",
        "detect": [
            r"/ip\s+address\s+add\s+.*?interface=\S+\b",
        ],
        "remediation": "Evaluate if high-availability is needed for this deployment.",
        "compliance": {"cis": "8.8", "nist": "CP-9", "iso": "A.8.8", "pci": "1.2"},
    },
    {
        "id": "NET-009",
"domain": "general",
        "name": "Default gateway without check-gateway=ping",
        "severity": "Medium",
        "cvss": "5.5",
        "category": "Network Configuration",
        "path": "/ip route",
        "description": "Default route does not use gateway health checking",
        "detect": [
            r"/ip\s+route\s+add\s+.*?gateway=\d+\.\d+\.\d+\.\d+(?!.*check-gateway=ping)",
        ],
        "remediation": (
            "/ip route set [find dst-address=0.0.0.0/0] check-gateway=ping"
        ),
        "compliance": {"cis": "8.9", "nist": "CP-9", "iso": "A.8.8", "pci": "1.2"},
    },

    # ═══ ROUTING SECURITY ═══
    {
        "id": "ROUTE-001",
"domain": "routing",
        "name": "BGP without MD5 authentication",
        "severity": "High",
        "cvss": "7.4",
        "category": "Routing Security",
        "path": "/routing bgp connection",
        "description": "BGP connections without TCP MD5 signature authentication",
        "detect": [
            r"/routing\s+bgp\s+connection\s+add\s+.*?remote\.address=\d+\.\d+\.\d+\.\d+(?!.*tcp-md5-key=)",
        ],
        "remediation": (
            "/routing bgp connection set [find remote.address=<peer-ip>] \\\n"
            "    tcp-md5-key=<secure-password>"
        ),
        "compliance": {"cis": "9.1", "nist": "SC-8", "iso": "A.8.20", "pci": "1.2"},
    },
    {
        "id": "ROUTE-002",
"domain": "routing",
        "name": "OSPF without authentication",
        "severity": "High",
        "cvss": "7.4",
        "category": "Routing Security",
        "path": "/routing ospf interface-template",
        "description": "OSPF interface templates without authentication configured",
        "detect": [
            r"/routing\s+ospf\s+interface-template\s+add\s+.*?\bnetwork=\d+\.\d+\.\d+\.\d+/\d+\b",
        ],
        "remediation": (
            "/routing ospf interface-template set [find network=<network>] \\\n"
            "    authentication=md5 authentication-key=<key>"
        ),
        "compliance": {"cis": "9.2", "nist": "SC-8", "iso": "A.8.20", "pci": "1.2"},
    },
    {
        "id": "ROUTE-003",
"domain": "routing",
        "name": "Routing filters not applied",
        "severity": "Medium",
        "cvss": "5.9",
        "category": "Routing Security",
        "path": "/routing bgp connection",
        "description": "BGP/OSPF connections without input or output routing filters",
        "detect": [
            r"/routing\s+bgp\s+connection\s+add\s+.*?(?!(?:input|output)\.filter=)",
        ],
        "remediation": (
            "/routing filter rule add chain=bgp-in rule=\"if (protocol == bgp) { reject }\"\n"
            "/routing bgp connection set [find] input.filter=bgp-in"
        ),
        "compliance": {"cis": "9.3", "nist": "SC-7", "iso": "A.8.20", "pci": "1.2"},
    },
    {
        "id": "ROUTE-004",
"domain": "routing",
        "name": "BGP TTL security not configured",
        "severity": "Medium",
        "cvss": "5.3",
        "category": "Routing Security",
        "path": "/routing bgp connection",
        "description": "BGP connections without TTL security (GTSM/ttl=1)",
        "detect": [
            r"/routing\s+bgp\s+connection\s+add\s+.*?\bttl=\d+\b",
        ],
        "negate": True,
        "remediation": (
            "# For directly connected eBGP peers:\n"
            "/routing bgp connection set [find remote.address=<peer-ip>] ttl=1"
        ),
        "compliance": {"cis": "9.4", "nist": "SC-7", "iso": "A.8.20", "pci": "1.2"},
    },
    {
        "id": "ROUTE-005",
"domain": "routing",
        "name": "BGP prefix limits not configured",
        "severity": "Medium",
        "cvss": "5.3",
        "category": "Routing Security",
        "path": "/routing bgp connection",
        "description": "BGP connections without max-prefix limits (memory exhaustion risk)",
        "detect": [
            r"/routing\s+bgp\s+connection\s+add\s+.*?\bmax-prefix=\d+\b",
        ],
        "negate": True,
        "remediation": (
            "/routing bgp connection set [find remote.address=<peer-ip>] max-prefix=1000"
        ),
        "compliance": {"cis": "9.5", "nist": "SC-7", "iso": "A.8.20", "pci": "1.2"},
    },
    {
        "id": "ROUTE-006",
"domain": "routing",
        "name": "Dynamic routing on WAN interfaces",
        "severity": "Medium",
        "cvss": "5.9",
        "category": "Routing Security",
        "path": "/routing ospf interface-template",
        "description": "Dynamic routing protocols enabled on WAN-facing interfaces",
        "detect": [
            r"/routing\s+ospf\s+interface-template\s+add\s+.*?network=.*?0\.0\.0\.0",
        ],
        "remediation": (
            "Use passive-interface or restrict OSPF to specific network prefixes."
        ),
        "compliance": {"cis": "9.6", "nist": "SC-7", "iso": "A.8.20", "pci": "1.2"},
    },
    {
        "id": "ROUTE-007",
"domain": "routing",
        "name": "Default route without backup",
        "severity": "Low",
        "cvss": "3.7",
        "category": "Routing Security",
        "path": "/ip route",
        "description": "Only one default route defined without backup",
        "detect": [
            r"/ip\s+route\s+add\s+.*?dst-address=0\.0\.0\.0/0\b",
        ],
        "remediation": (
            "/ip route add dst-address=0.0.0.0/0 gateway=<backup-gateway> \\\n"
            "    routing-mark=backup distance=2 check-gateway=ping"
        ),
        "compliance": {"cis": "9.7", "nist": "CP-9", "iso": "A.8.8", "pci": "1.2"},
    },
    {
        "id": "ROUTE-008",
"domain": "routing",
        "name": "Loopback interface not configured for router ID",
        "severity": "Low",
        "cvss": "2.2",
        "category": "Routing Security",
        "path": "/interface bridge",
        "description": "No loopback interface defined for router ID stability in dynamic routing",
        "detect": [
            r"/interface\s+bridge\s+add\s+name=loopback\b",
        ],
        "negate": True,
        "remediation": (
            "/interface bridge add name=loopback\n"
            "/ip address add address=10.255.255.1/32 interface=loopback\n"
            "Use loopback IP for router-id in dynamic routing protocols."
        ),
        "compliance": {"cis": "9.8", "nist": "CM-6", "iso": "A.8.9", "pci": "1.2"},
    },
    {
        "id": "ROUTE-009",
"domain": "routing",
        "name": "Routing filters not implemented for route filtering",
        "severity": "Medium",
        "cvss": "5.9",
        "category": "Routing Security",
        "path": "/routing filter rule",
        "description": "No custom routing filter chains defined",
        "detect": [
            r"/routing\s+filter\s+rule\s+add\s+chain=\w+\b",
        ],
        "negate": True,
        "remediation": (
            "Create routing filter rules for prefix filtering, community manipulation, and route-maps."
        ),
        "compliance": {"cis": "9.3", "nist": "SC-7", "iso": "A.8.20", "pci": "1.2"},
    },

    # ═══ WIFI SECURITY ═══
    {
        "id": "WIFI-001",
"domain": "wifi",
        "name": "Insecure encryption (WEP/TKIP) configured",
        "severity": "High",
        "cvss": "8.1",
        "category": "WiFi Security",
        "path": "/interface wireless security-profile",
        "description": "WiFi security profile uses WEP or TKIP encryption, which are compromised",
        "detect": [
            r"/interface\s+wireless\s+security-profile\s+set\s+.*?authentication-types=.*?\bwep\b",
            r"/interface\s+wireless\s+security-profile\s+set\s+.*?authentication-types=.*?\btkip\b",
            r"/interface\s+wifi\s+security\s+set\s+.*?authentication-types=.*?\btkip\b",
        ],
        "remediation": (
            "/interface wifi security set [find] authentication-types=wpa2-psk,wpa3-psk\n"
            "Use only CCMP (AES) encryption."
        ),
        "compliance": {"cis": "10.1", "nist": "SC-8", "iso": "A.8.22", "pci": "4.1"},
    },
    {
        "id": "WIFI-002",
"domain": "wifi",
        "name": "WPS enabled",
        "severity": "High",
        "cvss": "7.4",
        "category": "WiFi Security",
        "path": "/interface wireless",
        "description": "WiFi Protected Setup (WPS) enabled, vulnerable to PIN brute-force attacks",
        "detect": [
            r"/interface\s+wireless\s+set\s+.*?\bwps-mode=(?:pin|push-button|enabled)\b",
            r"/interface\s+wifi\s+set\s+.*?\bwps=(?:enabled|pin|push-button)\b",
        ],
        "remediation": (
            "/interface wireless set [find] wps-mode=disabled"
        ),
        "compliance": {"cis": "10.2", "nist": "CM-7", "iso": "A.8.9", "pci": "2.2.2"},
    },
    {
        "id": "WIFI-003",
"domain": "wifi",
        "name": "Guest network without isolation",
        "severity": "High",
        "cvss": "7.5",
        "category": "WiFi Security",
        "path": "/interface wifi configuration",
        "description": "Guest WiFi network without client isolation, allowing lateral movement",
        "detect": [
            r"/interface\s+wifi\s+configuration\s+(?:add|set)\s+.*?client-isolation=no\b",
            r"/interface\s+wireless\s+(?:add|set)\s+.*?\bisolate=yes\b",
        ],
        "remediation": (
            "/interface wifi datapath add name=guest-dp client-isolation=yes\n"
            "/interface wifi configuration set [find ssid=Guest] datapath=guest-dp"
        ),
        "compliance": {"cis": "10.3", "nist": "SC-7", "iso": "A.8.21", "pci": "1.3"},
    },
    {
        "id": "WIFI-004",
"domain": "wifi",
        "name": "Broadcast SSID disabled (hiding SSID)",
        "severity": "Low",
        "cvss": "3.3",
        "category": "WiFi Security",
        "path": "/interface wireless",
        "description": "SSID broadcast disabled (security-through-obscurity, may cause client issues)",
        "detect": [
            r"/interface\s+wireless\s+set\s+.*?\bhide-ssid=yes\b",
        ],
        "remediation": "Enable SSID broadcast. Hidden SSID provides no security and can cause client connectivity problems.",
        "compliance": {"cis": "10.4", "nist": "CM-6", "iso": "A.8.21", "pci": "4.1"},
    },
    {
        "id": "WIFI-005",
"domain": "wifi",
        "name": "Same security profile across bands",
        "severity": "Medium",
        "cvss": "4.6",
        "category": "WiFi Security",
        "path": "/interface wifi configuration",
        "description": "WiFi security profile configured — manual review needed to verify different profiles per band",
        "detect": [
            r"/interface\s+wifi\s+configuration\s+(?:add|set)\s+.*?\bsecurity=\S+\b",
        ],
        "negate": False,
        "remediation": (
            "Create separate security profiles per band:\n"
            "/interface wifi security add name=sec-24 authentication-types=wpa2-psk\n"
            "/interface wifi security add name=sec-5 authentication-types=wpa2-psk,wpa3-psk"
        ),
        "compliance": {"cis": "10.5", "nist": "CM-6", "iso": "A.8.9", "pci": "4.1"},
    },
    {
        "id": "WIFI-006",
"domain": "wifi",
        "name": "Client isolation not configured on guest SSID",
        "severity": "High",
        "cvss": "7.5",
        "category": "WiFi Security",
        "path": "/interface wifi datapath",
        "description": "Guest SSID datapath without client-isolation",
        "detect": [
            r"/interface\s+wifi\s+datapath\s+(?:add|set)\s+.*?\bname=\w*guest\w*\b(?!.*client-isolation=yes)",
            r"/interface\s+wifi\s+configuration\s+(?:add|set)\s+.*?\bssid=.*?[Gg]uest.*?(?!.*client-isolation=yes)",
        ],
        "remediation": (
            "/interface wifi datapath set [find name=guest-dp] client-isolation=yes"
        ),
        "compliance": {"cis": "10.3", "nist": "SC-7", "iso": "A.8.21", "pci": "1.3"},
    },
    {
        "id": "WIFI-007",
"domain": "wifi",
        "name": "CAPsMAN without TLS encryption",
        "severity": "High",
        "cvss": "7.4",
        "category": "WiFi Security",
        "path": "/caps-man",
        "description": "CAPsMAN control channel without TLS encryption",
        "detect": [
            r"/caps-man\s+set\s+enabled=yes\b(?!.*certificate=)",
            r"/interface\s+wifi\s+capsman\s+set\s+enabled=yes\b(?!.*ca-certificate=)",
        ],
        "remediation": (
            "Configure CAPsMAN with TLS:\n"
            "/caps-man manager set enabled=yes certificate=<cert>"
        ),
        "compliance": {"cis": "10.6", "nist": "SC-8", "iso": "A.8.20", "pci": "4.1"},
    },
    {
        "id": "WIFI-008",
"domain": "wifi",
        "name": "WiFi access list not configured",
        "severity": "Medium",
        "cvss": "4.6",
        "category": "WiFi Security",
        "path": "/interface wifi access-list",
        "description": "No MAC or L2 access list configured for WiFi interfaces",
        "detect": [
            r"/interface\s+wifi\s+access-list\s+add\b",
        ],
        "negate": True,
        "remediation": (
            "/interface wifi access-list add mac-address=<client-mac> action=accept\n"
            "/interface wifi access-list add action=reject comment=\"Default deny\""
        ),
        "compliance": {"cis": "10.7", "nist": "AC-2", "iso": "A.8.3", "pci": "7.1"},
    },
    {
        "id": "WIFI-009",
"domain": "wifi",
        "name": "Management Frame Protection (PMF) not enabled",
        "severity": "Medium",
        "cvss": "5.3",
        "category": "WiFi Security",
        "path": "/interface wifi security",
        "description": "PMF (802.11w) not enabled — management frames can be spoofed for deauth attacks",
        "detect": [
            r"/interface\s+wifi\s+security\s+set\s+.*?\bmanagement-protection=required\b",
            r"/interface\s+wireless\s+security-profile\s+set\s+.*?\bmanagement-protection=key\b",
        ],
        "negate": True,
        "remediation": (
            "/interface wifi security set [find] management-protection=required"
        ),
        "compliance": {"cis": "10.8", "nist": "SC-8", "iso": "A.8.22", "pci": "4.1"},
    },
    {
        "id": "WIFI-010",
"domain": "wifi",
        "name": "WiFi password too weak or default",
        "severity": "High",
        "cvss": "7.5",
        "category": "WiFi Security",
        "path": "/interface wifi security",
        "description": "WiFi passphrase appears weak, short, or default",
        "detect": [
            r"passphrase=\S{1,7}\b",
            r"passphrase=(12345678|password|admin|default|mikrotik|wifi)\b",
        ],
        "remediation": (
            "Set passphrase to min 12 random characters:\n"
            "/interface wifi security set [find] passphrase=<strong-passphrase>"
        ),
        "compliance": {"cis": "10.9", "nist": "IA-5", "iso": "A.8.5", "pci": "8.2"},
    },
    {
        "id": "WIFI-011",
"domain": "wifi",
        "name": "DFS channels configured without radar handling",
        "severity": "Info",
        "cvss": "0.0",
        "category": "WiFi Security",
        "path": "/interface wifi channel",
        "description": "DFS channels in use—radar events may cause long 5GHz outages",
        "detect": [
            r"/interface\s+wifi\s+channel\s+add\s+.*?\bfrequency=52\b",
            r"/interface\s+wifi\s+channel\s+add\s+.*?\bfrequency=56\b",
            r"/interface\s+wifi\s+channel\s+add\s+.*?\bfrequency=60\b",
            r"/interface\s+wifi\s+channel\s+add\s+.*?\bfrequency=64\b",
            r"/interface\s+wifi\s+channel\s+add\s+.*?\bfrequency=100\b",
            r"/interface\s+wifi\s+channel\s+add\s+.*?\bfrequency=104\b",
        ],
        "remediation": (
            "If using DFS channels, ensure ROS ≥7.15+ for reselect-interval.\n"
            "Prefer non-DFS channels for 5GHz access points."
        ),
        "compliance": {"cis": "10.10", "nist": "CM-6", "iso": "A.8.9", "pci": "2.2"},
    },
    {
        "id": "WIFI-012",
"domain": "wifi",
        "name": "hAP ac² wifi-qcom-ac package (flash exhaustion)",
        "severity": "Medium",
        "cvss": "5.0",
        "category": "WiFi Security",
        "path": "device model",
        "description": "hAP ac² device detected with wifi-qcom-ac package — 16MB flash constraint",
        "detect": [
            r"#\s+.*?hAP\s+ac\b",
            r"model\s*=\s*RBD52G",
        ],
        "context": "Requires live /system resource print to confirm flash space.",
        "remediation": (
            "On hAP ac²: disable DHCP lease disk storage, consider replacement with ax².\n"
            "Check /system resource print for free flash space before any upgrade."
        ),
        "compliance": {"cis": "10.11", "nist": "CM-6", "iso": "A.8.6", "pci": "2.2"},
    },
    {
        "id": "WIFI-013",
"domain": "wifi",
        "name": "hAP ax²/ax³ WiFi stability concern (ROS <7.19.2)",
        "severity": "High",
        "cvss": "7.5",
        "category": "WiFi Security",
        "path": "export header",
        "description": "hAP ax²/ax³ detected on RouterOS <7.19.2 — known 5GHz disconnection issue",
        "detect": [
            r"#\s+.*?by RouterOS\s+7\.(?:1[0-8]|1[0-9])\.",
            r"model\s*=\s*(?:C52iG|C53UiG)",
        ],
        "remediation": (
            "Upgrade to RouterOS ≥7.19.2 to fix SA Query timeout / 5GHz disconnections.\n"
            "Tested fix: 7.19.2 resolves the AX WiFi instability regression."
        ),
        "compliance": {"cis": "10.12", "nist": "SI-2", "iso": "A.8.8", "pci": "6.2"},
    },

    # ═══ SCRIPT & AUTOMATION ═══
    {
        "id": "SCRIPT-001",
"domain": "general",
        "name": "Scripts with excessive permissions",
        "severity": "High",
        "cvss": "7.1",
        "category": "Script & Automation",
        "path": "/system script",
        "description": "Scripts configured with 'full' or too many combined policy flags",
        "detect": [
            r"/system\s+script\s+add\s+.*?policy=.*?full\b",
            r"/system\s+script\s+set\s+.*?policy=.*?full\b",
        ],
        "remediation": (
            "/system script set [find name=<script>] policy=read,write,test"
        ),
        "compliance": {"cis": "11.1", "nist": "AC-6", "iso": "A.8.25", "pci": "6.3"},
    },
    {
        "id": "SCRIPT-002",
"domain": "general",
        "name": "Hardcoded credentials in scripts",
        "severity": "Critical",
        "cvss": "9.1",
        "category": "Script & Automation",
        "path": "/system script source",
        "description": "Hardcoded passwords, passphrases, or secrets detected in script source",
        "detect": [
            r"(?:on-event|source)=.*?(?:password|passphrase|secret|tcp-md5-key)=\S+",
        ],
        "remediation": (
            "Use :global environment variables instead:\n"
            ":global MyPassword \"<stored-in-environment>\";\n"
            "Store values in /system script environment set MyPassword=..."
        ),
        "compliance": {"cis": "11.2", "nist": "IA-5", "iso": "A.8.3", "pci": "8.2"},
    },
    {
        "id": "SCRIPT-003",
"domain": "general",
        "name": "Scheduled scripts without single-instance guards",
        "severity": "Medium",
        "cvss": "5.5",
        "category": "Script & Automation",
        "path": "/system scheduler",
        "description": "Scheduled scripts missing single-instance protection via :jobname pattern",
        "detect": [
            r"/system\s+scheduler\s+add\s+.*?on-event=\{\s*\n",
        ],
        "remediation": (
            "Add single-instance guard at script start:\n"
            ':if ([/system script job print count-only as-value where script=[:jobname]] > 1) do={\n'
            '    :log warning "Instance already running: $[:jobname]";\n'
            '    :error "Already running";\n'
            "}"
        ),
        "compliance": {"cis": "11.3", "nist": "CM-6", "iso": "A.8.25", "pci": "6.3"},
    },
    {
        "id": "SCRIPT-004",
"domain": "general",
        "name": "Scheduler scripts without error handling",
        "severity": "Medium",
        "cvss": "5.3",
        "category": "Script & Automation",
        "path": "/system scheduler",
        "description": "Critical scripts running without :onerror wrapped around risky operations",
        "detect": [
            r":onerror\b",
            r"\bonerror\s*=",
        ],
        "negate": True,
        "remediation": (
            "Wrap critical operations:\n"
            ":onerror e in={\n"
            "    # dangerous operation\n"
            "} do={\n"
            '    :log error "Failed: $e"\n'
            "}"
        ),
        "compliance": {"cis": "11.4", "nist": "SI-2", "iso": "A.8.25", "pci": "6.3"},
    },
    {
        "id": "SCRIPT-010",
"domain": "general",
        "name": "Scripts with dont-require-permissions=yes",
        "severity": "Critical",
        "cvss": "9.0",
        "category": "Script & Automation",
        "path": "/system script",
        "description": "Scripts configured with dont-require-permissions=yes — arbitrary command execution risk",
        "detect": [
            r"/system\s+script\s+(?:add|set)\s+.*?dont-require-permissions=yes\b",
        ],
        "remediation": (
            "/system script set [find name=<script>] dont-require-permissions=no\n"
            "# Ensure the script's policy list grants only the minimum permissions needed:\n"
            "/system script set [find name=<script>] policy=read,write,test"
        ),
        "compliance": {"cis": "11.4", "nist": "AC-6", "iso": "A.8.25", "pci": "6.3"},
    },
    {
        "id": "SCRIPT-005",
"domain": "general",
        "name": "Global variable namespace pollution",
        "severity": "Low",
        "cvss": "3.3",
        "category": "Script & Automation",
        "path": "/system script environment",
        "description": "Excessive :global variables detected without :set pattern",
        "detect": [
            r":global\s+\w+",
        ],
        "remediation": (
            "Use :local scoping where possible. :global should reference configuration constants,\n"
            "not runtime state. Always :set after :global."
        ),
        "compliance": {"cis": "11.5", "nist": "CM-6", "iso": "A.8.25", "pci": "6.3"},
    },
    {
        "id": "SCRIPT-006",
"domain": "general",
        "name": "Destructive commands in scripts",
        "severity": "Critical",
        "cvss": "9.0",
        "category": "Script & Automation",
        "path": "/system script source",
        "description": "Destructive RouterOS commands found in script source code",
        "detect": [
            r"system\s+reset-configuration\b",
            r"system\s+backup\s+load\b",
            r"file\s+remove\b.*?backup",
        ],
        "remediation": "Remove or disable scripts containing destructive commands. Use safe alternatives.",
        "compliance": {"cis": "11.6", "nist": "CP-9", "iso": "A.8.10", "pci": "11.5"},
    },
    {
        "id": "SCRIPT-007",
"domain": "general",
        "name": "Scripts with high run count not in scheduler",
        "severity": "Low",
        "cvss": "3.3",
        "category": "Script & Automation",
        "path": "/system script",
        "description": "Scripts with high run-count values not referenced by scheduler (potential automated execution)",
        "detect": [
            r"/system\s+script\s+add\s+.*?run-count=\d+",
        ],
        "remediation": (
            "Audit script purpose. If needed by scheduler, ensure it is registered:\n"
            "/system scheduler add name=script-schedule interval=1d on-event=\"/system script run <script>\""
        ),
        "compliance": {"cis": "11.7", "nist": "CM-6", "iso": "A.8.25", "pci": "6.3"},
    },
    {
        "id": "SCRIPT-008",
"domain": "general",
        "name": "Script source contains infinite loops without guards",
        "severity": "Medium",
        "cvss": "5.5",
        "category": "Script & Automation",
        "path": "/system script source",
        "description": "Loop constructs (:while/:foreach/:for) without iteration limits or break conditions",
        "detect": [
            r":while\s+\(true\)",
            r":while\s+\(1\)",
            r":while\s+\(yes\)",
        ],
        "remediation": (
            "Always include iteration limits or break conditions:\n"
            ":local counter 0\n"
            ":while ($counter < 10) do={\n"
            "    :set counter ($counter +1)\n"
            "}"
        ),
        "compliance": {"cis": "11.8", "nist": "CM-6", "iso": "A.8.25", "pci": "6.3"},
    },

    # ═══ COMPLIANCE INFO CHECKS ═══
    {
        "id": "COMP-001",
"domain": "general",
        "name": "CIS compliance mapping available",
        "severity": "Info",
        "cvss": "0.0",
        "category": "Compliance Mapping",
        "path": "compliance",
        "description": "CIS Benchmark crosswalk available for all actionable checks",
        "remediation": "See COMPLIANCE_MAPPING.md for full CIS control mapping.",
        "compliance": {},
    },
    {
        "id": "COMP-002",
"domain": "general",
        "name": "NIST SP 800-53 compliance mapping available",
        "severity": "Info",
        "cvss": "0.0",
        "category": "Compliance Mapping",
        "path": "compliance",
        "description": "NIST SP 800-53 Rev 5 control crosswalk available",
        "remediation": "See COMPLIANCE_MAPPING.md for full NIST control mapping.",
        "compliance": {},
    },
    {
        "id": "COMP-003",
"domain": "general",
        "name": "ISO 27001 compliance mapping available",
        "severity": "Info",
        "cvss": "0.0",
        "category": "Compliance Mapping",
        "path": "compliance",
        "description": "ISO 27001:2022 Annex A control crosswalk available",
        "remediation": "See COMPLIANCE_MAPPING.md for full ISO 27001 mapping.",
        "compliance": {},
    },
    {
        "id": "COMP-004",
"domain": "general",
        "name": "PCI DSS compliance mapping available",
        "severity": "Info",
        "cvss": "0.0",
        "category": "Compliance Mapping",
        "path": "compliance",
        "description": "PCI DSS v4.0 requirement crosswalk available",
        "remediation": "See COMPLIANCE_MAPPING.md for full PCI DSS mapping.",
        "compliance": {},
    },
    {
        "id": "COMP-005",
"domain": "general",
        "name": "MITRE ATT&CK mapping available",
        "severity": "Info",
        "cvss": "0.0",
        "category": "Compliance Mapping",
        "path": "compliance",
        "description": "MITRE ATT&CK technique crosswalk available",
        "remediation": "See COMPLIANCE_MAPPING.md for full ATT&CK mapping.",
        "compliance": {},
    },
    {
        "id": "COMP-006",
"domain": "general",
        "name": "CVSS scoring matrix provided",
        "severity": "Info",
        "cvss": "0.0",
        "category": "Compliance Mapping",
        "path": "compliance",
        "description": "Each finding includes CVSS v3.1 adapted severity score",
        "remediation": "Severity mapped directly per finding definition.",
        "compliance": {},
    },
]


class RSCAuditor:
    """Offline MikroTik RouterOS .rsc Configuration Auditor."""

    def __init__(self, filepath: str, severity_filter: Optional[str] = None,
                 check_filter: Optional[List[str]] = None,
                 do_cve: bool = False, do_cve_live: bool = False,
                 do_conflicts: bool = False, do_ioc: bool = False, skip_wifi: bool = False, skip_routing: bool = False):
        self.filepath = filepath
        self.severity_filter = severity_filter
        self.check_filter = set(check_filter) if check_filter else None
        self.do_cve = do_cve
        self.do_cve_live = do_cve_live
        self.do_conflicts = do_conflicts
        self.do_ioc = do_ioc
        self.skip_wifi = skip_wifi
        self.skip_routing = skip_routing
        self.raw_content: str = ""
        self.lines: List[str] = []
        self.header: Dict[str, str] = {}
        self.config_paths: Dict[str, List[str]] = defaultdict(list)
        self.findings: List[Dict[str, Any]] = []
        self.device_model: str = "Unknown"
        self.lint_findings: List[Dict[str, Any]] = []
        self.device_profile: Optional[DeviceProfile] = None

    def load(self) -> None:
        """Load and parse the .rsc file."""
        with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
            self.raw_content = f.read()
        self.lines = self.raw_content.splitlines()
        self._parse_header()
        self._index_config_paths()
        # Detect device profile from header
        device_key = detect_device(self.lines[:30])
        self.device_profile = get_profile(device_key) if device_key else None

    def _parse_header(self) -> None:
        """Extract metadata from export file header comments."""
        meta_map = {
            "RouterOS": "version",
            "model": "model",
            "serial": "serial",
            "software id": "software_id",
        }
        for line in self.lines[:20]:
            for keyword, key in meta_map.items():
                if keyword in line:
                    if "by RouterOS" in line:
                        match = re.search(r"by RouterOS\s+([\d.]+)", line)
                        if match:
                            self.header["version"] = match.group(1)
                    elif "=" in line:
                        parts = line.split("=", 1)
                        if len(parts) == 2:
                            self.header[key] = parts[1].strip()

        # Detect device model from header
        if "model" in self.header:
            self.device_model = self.header["model"]
        else:
            # Try to infer from any model= line
            for line in self.lines[:20]:
                mm = re.search(r"model\s*=\s*(\S+)", line)
                if mm:
                    self.device_model = mm.group(1)

    def _parse_ros_version(self) -> Optional[float]:
        """Extract RouterOS version as a float for comparison (e.g., 6.49 -> 6.49, 7.15 -> 7.15).

        Handles prerelease versions like "7.10rc1" by stripping the prerelease suffix
        from the minor version part before float conversion.
        """
        ver_str = self.header.get("version", "")
        if ver_str:
            try:
                parts = ver_str.split(".")
                # Strip any non-numeric prerelease suffix from the minor version
                # e.g., "10rc1" -> "10", "1beta3" -> "1"
                minor = re.sub(r'[^0-9].*', '', parts[1])
                return float(f"{parts[0]}.{minor}")
            except (ValueError, IndexError):
                return None
        return None

    def _index_config_paths(self) -> None:
        """Build an index of configuration paths found in the file.

        Extracts the full hierarchical path (e.g., /ip firewall filter,
        /system scheduler) rather than just the first segment.
        """
        for i, line in enumerate(self.lines):
            stripped = line.strip()
            # Skip comments and blank lines
            if not stripped or stripped.startswith("#"):
                continue

            # Try to match full path followed by a command keyword
            # Path is everything from "/" up to a known RouterOS command keyword
            path_match = re.match(
                r"^(/[\w/-]+(?:\s+[\w/-]+)*)\s+(?:add|set|remove|enable|disable|print|get|find|export|move|comment)\b",
                stripped, re.IGNORECASE
            )
            if path_match:
                path = path_match.group(1)
                self.config_paths[path].append(stripped)
                continue

            # Fallback: just a path declaration (e.g., "/ip firewall filter")
            path_only = re.match(r"^(/[\w/-]+(?:\s+[\w/-]+)*)$", stripped)
            if path_only:
                path = path_only.group(1)
                self.config_paths[path].append(stripped)
                continue

            # Last-resort: capture first path segment (backward compatibility)
            path_first = re.match(r"^/([\w\/-]+)\b", stripped)
            if path_first:
                path = "/" + path_first.group(1)
                self.config_paths[path].append(stripped)

    def run_audit(self) -> List[Dict[str, Any]]:
        """Execute all applicable audit checks against the loaded config."""
        self.findings = []
        parsed_version = self._parse_ros_version()

        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

        # ── Hardware context ──
        device_key: Optional[str] = None
        if self.device_profile:
            for key, profile in DEVICE_PROFILES.items():
                if profile == self.device_profile:
                    device_key = key
                    break

        # ── Run built-in audit checks ──
        for check in AUDIT_CHECKS:
            # Apply filters
            if self.check_filter and check["id"] not in self.check_filter:
                continue
            if self.skip_wifi and check["id"].startswith("WIFI-"):
                continue
            if self.skip_routing and check["id"].startswith("ROUTE-"):
                continue

            required = sev_order.get(self.severity_filter, -1)
            check_sev = sev_order.get(check["severity"], 4)
            if required >= 0 and check_sev > required:
                continue

            # Apply version-gating (skip_if_version_ge)
            skip_version = check.get("skip_if_version_ge", None)
            if skip_version is not None and parsed_version is not None:
                if parsed_version >= skip_version:
                    continue

            # Apply model-gating (skip_unless_model_in)
            skip_models = check.get("skip_unless_model_in", None)
            if skip_models is not None:
                if self.device_model not in skip_models:
                    continue

            # ── Hardware-profile aware filtering ──
            hw_rules = CHECK_HARDWARE_MAP.get(check["id"], {})

            # N/A check: skip if check doesn't apply to this device family
            na_if_na = hw_rules.get("na_if_not_applicable", False)
            if na_if_na:
                applicable_models = hw_rules.get("applicable_models")
                applicable_families = hw_rules.get("applicable_families")
                if applicable_models and device_key and device_key not in applicable_models:
                    continue
                if applicable_families and self.device_profile \
                        and self.device_profile.family not in applicable_families:
                    continue

            # Version threshold: skip if device is past the fixed threshold
            version_threshold = hw_rules.get("version_threshold")
            if version_threshold and parsed_version is not None:
                if parsed_version >= float(version_threshold):
                    continue

            # Run detection
            result = self._evaluate_check(check)
            if result is not None:
                # Apply hardware-based severity override
                sev_override = hw_rules.get("severity_override", {})
                if sev_override:
                    if device_key and device_key in sev_override:
                        result["severity"] = sev_override[device_key]
                    elif "default" in sev_override:
                        result["severity"] = sev_override["default"]
                self.findings.append(result)

        # ── CVE check ──
        if self.do_cve and parsed_version:
            version_str = self.header.get("version", "")
            if version_str:
                cves = check_cve_for_version(version_str, use_nvd=self.do_cve_live)
                for cve in cves:
                    self.findings.append({
                        "id": cve.cve_id,
                        "name": cve.title,
                        "severity": cve.severity,
                        "cvss": str(cve.cvss_score) if cve.cvss_score else "7.5",
                        "category": "Vulnerability Management",
                        "path": "export header",
                        "description": cve.description,
                        "details": f"CVE {cve.cve_id} affects RouterOS {version_str}. Fixed in {cve.fixed_version}.",
                        "remediation": cve.recommendation,
                        "compliance": {},
                    })

        # ── Conflict analysis ──
        if self.do_conflicts:
            try:
                from conflict_analyzer import analyze_raw_rsc as _analyze_raw_rsc
                conflict_results = _analyze_raw_rsc(self.raw_content)
                for cr in conflict_results:
                    self.findings.append(cr.to_dict())
            except Exception as e:
                self.findings.append({
                    "id": "CF-ERROR",
                    "name": "Conflict Analysis Error",
                    "severity": "Info",
                    "cvss": "0.0",
                    "category": "Configuration Conflict",
                    "path": "analysis",
                    "description": f"Conflict analyzer failed: {e}",
                    "details": "The conflict analyzer encountered an error during parsing.",
                    "remediation": "Check the .rsc file for syntax errors that may prevent parsing.",
                    "compliance": {},
                })

        # ── IoC detection ──
        if self.do_ioc:
            try:
                # Build sections dict from config_paths — map to IoC analyzer keys
                # IoC analyzer expects keys like "scheduler", "ip socks", etc.
                ioc_path_map = {
                    "/system scheduler": "scheduler",
                    "/ip socks": "ip socks",
                    "/ip proxy": "ip proxy",
                    "/file": "file",
                    "/user": "user",
                    "/ip dns static": "ip dns static",
                    "/ip firewall mangle": "ip firewall mangle",
                    "/system script": "system script",
                }
                ioc_sections: Dict[str, List[str]] = {}
                for path, lines in self.config_paths.items():
                    mapped = ioc_path_map.get(path)
                    if mapped:
                        ioc_sections.setdefault(mapped, []).extend(lines)
                analyzer = IoCAnalyzer()
                analyzer.load_data(ioc_sections)
                ioc_results = analyzer.analyze()
                for ioc in ioc_results:
                    self.findings.append({
                        "id": f"IOC-{ioc.ioc_type.value}",
                        "name": ioc.title,
                        "severity": ioc.severity,
                        "cvss": "9.0" if ioc.severity == "Critical" else "7.5" if ioc.severity == "High" else "5.5",
                        "category": "Indicators of Compromise",
                        "path": "ioc_analysis",
                        "description": ioc.description,
                        "details": ioc.evidence,
                        "remediation": ioc.recommendation + "\n" + "\n".join(ioc.remediation_commands),
                        "compliance": {},
                    })
            except Exception as e:
                self.findings.append({
                    "id": "IOC-ERROR",
                    "name": "IoC Analysis Error",
                    "severity": "Info",
                    "cvss": "0.0",
                    "category": "Indicators of Compromise",
                    "path": "analysis",
                    "description": f"IoC analyzer failed: {e}",
                    "details": "The IoC analyzer encountered an error during parsing.",
                    "remediation": "Check the .rsc file for syntax issues.",
                    "compliance": {},
                })

        # Sort by severity (Critical first)
        self.findings.sort(key=lambda f: sev_order.get(f["severity"], 99))
        return self.findings

    def run_lint(self, lint_file: str) -> List[Dict[str, Any]]:
        """Run the RSC linter on a separate .rsc script file.

        Args:
            lint_file: Path to the .rsc file to lint.

        Returns:
            List of finding dicts with line, severity, rule, and message.
        """
        self.lint_findings = []
        try:
            with open(lint_file, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            findings = linter.lint_text(content)
            for f_ in findings:
                self.lint_findings.append({
                    "id": f"LINT-{f_.rule}",
                    "name": f_.rule,
                    "severity": "High" if f_.severity == "error" else "Medium" if f_.severity == "warning" else "Low",
                    "cvss": "9.0" if f_.severity == "error" else "5.5" if f_.severity == "warning" else "3.3",
                    "category": "Script Linting",
                    "path": lint_file,
                    "description": f_.message,
                    "details": f"L{f_.line}: {f_.snippet}",
                    "remediation": f_.message,
                    "compliance": {},
                })
        except Exception as e:
            self.lint_findings.append({
                "id": "LINT-ERROR",
                "name": "Lint Error",
                "severity": "Info",
                "cvss": "0.0",
                "category": "Script Linting",
                "path": lint_file,
                "description": f"Linter failed: {e}",
                "details": str(e),
                "remediation": "Check the file path and syntax.",
                "compliance": {},
            })
        return self.lint_findings

    def _evaluate_check(self, check: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Evaluate a single check against the config content."""
        negate = check.get("negate", False)
        detected = False

        for pattern in check.get("detect", []):
            try:
                matches = re.findall(pattern, self.raw_content, re.IGNORECASE | re.DOTALL)
                if matches:
                    detected = True
                    if not negate:
                        break
            except re.error:
                continue

        # Negation logic
        if negate:
            if not detected:
                # Check if the path exists at all — if not, it's trivially missing
                path = check.get("path", "")
                if path in self.config_paths:
                    return self._make_finding(check, details=f"{path} exists but no matching pattern found")
                else:
                    path_exists = bool(re.findall(r"^" + re.escape(path), self.raw_content, re.MULTILINE))
                    if path_exists:
                        return self._make_finding(check, details=f"{path} exists but no matching pattern found")
                    return self._make_finding(check, details=f"{path} not configured at all")
        else:
            if detected:
                return self._make_finding(check, details="Pattern matched")

        return None

    def _make_finding(self, check: Dict[str, Any], details: str) -> Dict[str, Any]:
        """Create a finding dict from a check definition."""
        return {
            "id": check["id"],
            "name": check["name"],
            "severity": check["severity"],
            "cvss": check["cvss"],
            "category": check["category"],
            "path": check["path"],
            "description": check["description"],
            "details": details,
            "remediation": check.get("remediation", ""),
            "compliance": check.get("compliance", {}),
        }

    def score_config(self) -> Dict[str, Any]:
        """Calculate overall security score based on findings.

        Uses percentage-based approach:
        - Base score: 100
        - Deduct percentage of applicable checks that fired, weighted by severity
        - Per-category breakdown: show which domains need attention
        - No zero saturation: minimum score is 1 (not 0) so progress is visible
        """
        if not self.findings:
            return {"score": 100, "grade": "A+", "summary": "No findings — config appears clean",
                    "total_findings": 0, "total_applicable_checks": 0,
                    "by_severity": {}, "by_category": {}}

        # Count checks that ran (applicable + checked)
        total_checks = len(self.findings)

        sev_weights = {"Critical": 0.40, "High": 0.25, "Medium": 0.15, "Low": 0.05, "Info": 0.0}

        # Weighted severity sum
        weighted_sum = sum(sev_weights.get(f["severity"], 0) for f in self.findings)

        # Normalize by total checks to get percentage impact
        # If all checks fired at Critical, score approaches (1 - 0.40) = 0.60 = 60
        impact_per_check = weighted_sum / max(total_checks, 1)
        raw_score = 100 * (1.0 - min(impact_per_check, 0.99))
        score = max(1, round(raw_score))

        # Keep the same grade boundaries for consistency
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        by_severity = defaultdict(int)
        by_category = defaultdict(int)
        for f in self.findings:
            by_severity[f["severity"]] += 1
            by_category[f["category"]] += 1

        return {
            "score": score,
            "grade": grade,
            "total_findings": len(self.findings),
            "total_applicable_checks": len(self.findings),
            "by_severity": dict(by_severity),
            "by_category": dict(by_category),
        }

    def report_text(self) -> str:
        """Generate a human-readable text report."""
        lines = []
        lines.append("=" * 76)
        lines.append(f"  MikroTik RouterOS .rsc Audit Report")
        lines.append(f"  File: {self.filepath}")
        lines.append(f"  Device: {self.device_model}")
        lines.append(f"  Version: {self.header.get('version', 'Unknown')}")
        lines.append(f"  Date: {datetime.now().isoformat()}")
        lines.append("=" * 76)

        score_info = self.score_config()
        lines.append(f"\n  Overall Score: {score_info['score']}/100 (Grade: {score_info['grade']})")
        lines.append(f"  Total Findings: {score_info['total_findings']}")
        lines.append(f"  By Severity: {score_info['by_severity']}")
        lines.append(f"  By Category: {score_info['by_category']}")

        if not self.findings:
            lines.append("\n  ✓ No findings — configuration passes all checks.")
            return "\n".join(lines)

        # Top 5 Executive Summary
        lines.append(f"\n{'─' * 76}")
        lines.append(f"  TOP 5 EXECUTIVE SUMMARY — Areas requiring immediate attention")
        lines.append(f"{'─' * 76}")
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        top5 = sorted(self.findings, key=lambda f: (severity_order.get(f["severity"], 99), float(f.get("cvss", "0")) or 0))[:5]
        for i, f in enumerate(top5, 1):
            lines.append(f"  {i}. [{f['id']}] {f['name']} — {f['severity']} (CVSS: {f['cvss']})")
            lines.append(f"     {f['description']}")

        # Safety Warnings for high-risk checks
        high_risk_ids = {"AUTH-001", "AUTH-004", "AUTH-009", "FW-002", "FW-009"}
        safety_findings = [f for f in self.findings if f['id'] in high_risk_ids]
        if safety_findings:
            lines.append(f"\n{'─' * 76}")
            lines.append(f"  ⚠ SAFETY WARNINGS — High-risk findings that may impact device access")
            lines.append(f"{'─' * 76}")
            for f in safety_findings:
                lines.append(f"  ⚠ [{f['id']}] {f['name']}")
                lines.append(f"     {f['description']}")
                lines.append(f"     CAUTION: Remediating this finding may lock you out of the device!")
                lines.append(f"     Ensure out-of-band access before applying changes.")

        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            sev_findings = [f for f in self.findings if f["severity"] == sev]
            if sev_findings:
                lines.append(f"\n{'─' * 76}")
                lines.append(f"  {sev} Findings ({len(sev_findings)})")
                lines.append(f"{'─' * 76}")
                for f in sev_findings:
                    lines.append(f"\n  [{f['id']}] {f['name']}  (CVSS: {f['cvss']})")
                    lines.append(f"        {f['description']}")
                    lines.append(f"        Path: {f['path']}")
                    lines.append(f"        Detail: {f['details']}")
                    if f['remediation']:
                        for rline in f['remediation'].split('\n'):
                            lines.append(f"        → {rline}")

        # ── CVE Findings Section ──
        cve_findings = [f for f in self.findings if f["id"].startswith("CVE-")]
        if cve_findings:
            lines.append(f"\n{'─' * 76}")
            lines.append(f"  VULNERABILITY MANAGEMENT — CVE Findings ({len(cve_findings)})")
            lines.append(f"{'─' * 76}")
            for f in cve_findings:
                lines.append(f"\n  [{f['id']}] {f['name']}  ({f['severity']} CVSS: {f['cvss']})")
                lines.append(f"        {f['details']}")
                if f['remediation']:
                    for rline in f['remediation'].split('\n'):
                        lines.append(f"        → {rline}")

        # ── Configuration Conflicts Section ──
        conflict_findings = [f for f in self.findings if f["category"] == "Configuration Conflict"]
        if conflict_findings:
            lines.append(f"\n{'─' * 76}")
            lines.append(f"  CONFIGURATION CONFLICTS — Rule Conflict Analysis ({len(conflict_findings)})")
            lines.append(f"{'─' * 76}")
            for f in conflict_findings:
                lines.append(f"\n  [{f['id']}] {f['name']}  ({f['severity']} CVSS: {f['cvss']})")
                lines.append(f"        {f['description']}")
                lines.append(f"        Detail: {f['details']}")
                if f['remediation']:
                    for rline in f['remediation'].split('\n'):
                        lines.append(f"        → {rline}")

        # ── IoC Findings Section ──
        ioc_findings = [f for f in self.findings if f["category"] == "Indicators of Compromise"]
        if ioc_findings:
            lines.append(f"\n{'─' * 76}")
            lines.append(f"  INDICATORS OF COMPROMISE — IoC Detection ({len(ioc_findings)})")
            lines.append(f"{'─' * 76}")
            for f in ioc_findings:
                lines.append(f"\n  [{f['id']}] {f['name']}  ({f['severity']} CVSS: {f['cvss']})")
                lines.append(f"        {f['description']}")
                lines.append(f"        Evidence: {f['details']}")
                if f['remediation']:
                    lines.append(f"        Remediation:")
                    for rline in f['remediation'].split('\n'):
                        lines.append(f"        → {rline}")

        # ── Lint Findings Section ──
        if self.lint_findings:
            lines.append(f"\n{'─' * 76}")
            lines.append(f"  SCRIPT LINTING — Pre-deployment Validation ({len(self.lint_findings)})")
            lines.append(f"{'─' * 76}")
            for f in self.lint_findings:
                lines.append(f"\n  [{f['id']}] {f['name']}  ({f['severity']})")
                lines.append(f"        Line: {f['details']}")
                if f['remediation']:
                    lines.append(f"        {f['remediation']}")

        lines.append(f"\n{'=' * 76}")
        lines.append(f"  Report generated {datetime.now().isoformat()}")
        lines.append(f"{'=' * 76}")
        return "\n".join(lines)

    def report_json(self) -> Dict[str, Any]:
        """Generate a structured JSON report."""
        score_info = self.score_config()

        # Separate findings by module origin
        cve_findings = [f for f in self.findings if f["id"].startswith("CVE-")]
        conflict_findings = [f for f in self.findings if f["category"] == "Configuration Conflict"]
        ioc_findings = [f for f in self.findings if f["category"] == "Indicators of Compromise"]
        lint_findings = [f for f in self.lint_findings]
        standard_findings = [
            f for f in self.findings
            if not f["id"].startswith("CVE-")
            and f["category"] not in ("Configuration Conflict", "Indicators of Compromise")
        ]

        return {
            "meta": {
                "file": self.filepath,
                "device_model": self.device_model,
                "version": self.header.get("version", "Unknown"),
                "software_id": self.header.get("software_id", "Unknown"),
                "serial": self.header.get("serial", "Unknown"),
                "audit_date": datetime.now().isoformat(),
                "auditor_version": "1.0.0",
            },
            "score": score_info,
            "findings": {
                "standard": standard_findings,
                "cve": cve_findings,
                "conflicts": conflict_findings,
                "ioc": ioc_findings,
                "lint": lint_findings,
            } if (cve_findings or conflict_findings or ioc_findings or lint_findings) else self.findings,
        }

    def report_html(self) -> str:
        """Generate an HTML report."""
        score_info = self.score_config()

        def esc(s: str) -> str:
            return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        colors = {"Critical": "#dc3545", "High": "#fd7e14", "Medium": "#ffc107",
                  "Low": "#17a2b8", "Info": "#6c757d"}

        html = [
            "<!DOCTYPE html><html><head><meta charset='utf-8'>",
            "<title>MikroTik RSC Audit Report</title>",
            "<style>",
            "body{font-family:system-ui,sans-serif;margin:2rem;max-width:1200px}",
            "h1{color:#333}h2{border-bottom:2px solid #eee;padding-bottom:.5rem}",
            ".score{font-size:2rem;font-weight:700}",
            ".findings{margin-top:1rem}",
            ".finding{border:1px solid #ddd;border-radius:8px;margin:.5rem 0;padding:1rem}",
            ".finding .head{display:flex;justify-content:space-between;align-items:center}",
            ".finding .id{font-weight:700;font-size:1.1rem}",
            ".severity-badge{padding:2px 8px;border-radius:4px;color:#fff;font-weight:600}",
            "table{width:100%;border-collapse:collapse;margin:1rem 0}",
            "td,th{border:1px solid #ddd;padding:8px;text-align:left}",
            "th{background:#f5f5f5}.remediation{background:#f8f9fa;padding:8px;font-family:monospace;font-size:.9rem;white-space:pre-wrap}",
            "@media(prefers-color-scheme:dark){body{background:#1a1a2e;color:#e0e0e0}",
            ".finding{background:#16213e;border-color:#0f3460}",
            "th{background:#0f3460;color:#e0e0e0}",
            "td{border-color:#0f3460}.remediation{background:#0f3460}}",
            "</style></head><body>",
            f"<h1>MikroTik RouterOS .rsc Audit</h1>",
            f"<p><strong>File:</strong> {esc(self.filepath)}</p>",
            f"<p><strong>Device:</strong> {esc(self.device_model)}</p>",
            f"<p><strong>Version:</strong> {esc(self.header.get('version', 'Unknown'))}</p>",
            f"<p><strong>Date:</strong> {datetime.now().isoformat()}</p>",
            f"<div class='score' style='color:{'#28a745' if score_info['score']>=80 else '#dc3545'}'>",
            f"Score: {score_info['score']}/100 | Grade: {score_info['grade']}</div>",
            f"<p>Total Findings: {score_info['total_findings']} | ",
            f"Critical: {score_info['by_severity'].get('Critical',0)} | ",
            f"High: {score_info['by_severity'].get('High',0)} | ",
            f"Medium: {score_info['by_severity'].get('Medium',0)} | ",
            f"Low: {score_info['by_severity'].get('Low',0)} | ",
            f"Info: {score_info['by_severity'].get('Info',0)}</p>",
        ]

        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            sev_f = [f for f in self.findings if f["severity"] == sev]
            if sev_f:
                html.append(f"<h2>{sev} Findings ({len(sev_f)})</h2>")
                for f in sev_f:
                    c = colors.get(f["severity"], "#6c757d")
                    html.extend([
                        f"<div class='finding'>",
                        f"<div class='head'>",
                        f"<span class='id'>[{esc(f['id'])}] {esc(f['name'])}</span>",
                        f"<span class='severity-badge' style='background:{c}'>{esc(f['severity'])} (CVSS:{esc(f['cvss'])})</span>",
                        f"</div>",
                        f"<p><strong>Category:</strong> {esc(f['category'])} | <strong>Path:</strong> {esc(f['path'])}</p>",
                        f"<p>{esc(f['description'])}</p>",
                        f"<p><strong>Detail:</strong> {esc(f['details'])}</p>",
                    ])
                    if f["remediation"]:
                        html.append(
                            f"<div class='remediation'><strong>Remediation:</strong>\n{esc(f['remediation'])}</div>"
                        )
                    if f["compliance"]:
                        comp = ", ".join(f"{k.upper()}: {v}" for k, v in f["compliance"].items())
                        html.append(f"<p><strong>Compliance:</strong> {comp}</p>")
                    html.append("</div>")

        # ── CVE Findings Section ──
        cve_findings = [f for f in self.findings if f["id"].startswith("CVE-")]
        if cve_findings:
            html.append(f"<h2>Vulnerability Management — CVE Findings ({len(cve_findings)})</h2>")
            for f in cve_findings:
                c = colors.get(f["severity"], "#6c757d")
                html.extend([
                    f"<div class='finding'>",
                    f"<div class='head'>",
                    f"<span class='id'>{esc(f['id'])}</span>",
                    f"<span class='severity-badge' style='background:{c}'>{esc(f['severity'])} (CVSS:{esc(f['cvss'])})</span>",
                    f"</div>",
                    f"<p><strong>{esc(f['name'])}</strong></p>",
                    f"<p>{esc(f['details'])}</p>",
                ])
                if f["remediation"]:
                    html.append(f"<div class='remediation'>{esc(f['remediation'])}</div>")
                html.append("</div>")

        # ── Configuration Conflicts Section ──
        conflict_findings = [f for f in self.findings if f["category"] == "Configuration Conflict"]
        if conflict_findings:
            html.append(f"<h2>Configuration Conflicts ({len(conflict_findings)})</h2>")
            for f in conflict_findings:
                c = colors.get(f["severity"], "#6c757d")
                html.extend([
                    f"<div class='finding'>",
                    f"<div class='head'>",
                    f"<span class='id'>[{esc(f['id'])}] {esc(f['name'])}</span>",
                    f"<span class='severity-badge' style='background:{c}'>{esc(f['severity'])} (CVSS:{esc(f['cvss'])})</span>",
                    f"</div>",
                    f"<p>{esc(f['description'])}</p>",
                    f"<p><strong>Detail:</strong> {esc(f['details'])}</p>",
                ])
                if f["remediation"]:
                    html.append(f"<div class='remediation'>{esc(f['remediation'])}</div>")
                html.append("</div>")

        # ── IoC Findings Section ──
        ioc_findings = [f for f in self.findings if f["category"] == "Indicators of Compromise"]
        if ioc_findings:
            html.append(f"<h2>Indicators of Compromise ({len(ioc_findings)})</h2>")
            for f in ioc_findings:
                c = colors.get(f["severity"], "#6c757d")
                html.extend([
                    f"<div class='finding'>",
                    f"<div class='head'>",
                    f"<span class='id'>[{esc(f['id'])}] {esc(f['name'])}</span>",
                    f"<span class='severity-badge' style='background:{c}'>{esc(f['severity'])} (CVSS:{esc(f['cvss'])})</span>",
                    f"</div>",
                    f"<p>{esc(f['description'])}</p>",
                    f"<p><strong>Evidence:</strong> {esc(f['details'])}</p>",
                ])
                if f["remediation"]:
                    html.append(f"<div class='remediation'>{esc(f['remediation'])}</div>")
                html.append("</div>")

        # ── Lint Findings Section ──
        if self.lint_findings:
            html.append(f"<h2>Script Linting ({len(self.lint_findings)})</h2>")
            for f in self.lint_findings:
                c = colors.get(f["severity"], "#6c757d")
                html.extend([
                    f"<div class='finding'>",
                    f"<div class='head'>",
                    f"<span class='id'>[{esc(f['id'])}] {esc(f['name'])}</span>",
                    f"<span class='severity-badge' style='background:{c}'>{esc(f['severity'])}</span>",
                    f"</div>",
                    f"<p><strong>File:</strong> {esc(f.get('path', ''))}</p>",
                    f"<p>{esc(f['description'])}</p>",
                    f"<p><strong>Line:</strong> {esc(f['details'])}</p>",
                ])
                html.append("</div>")

        html.append("</body></html>")
        return "\n".join(html)


def main():
    parser = argparse.ArgumentParser(
        description="MikroTik RouterOS .rsc Configuration Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python audit_rsc.py export.rsc --format text                          # Text report
  python audit_rsc.py export.rsc --format json                           # JSON output
  python audit_rsc.py export.rsc --format html                           # HTML report
  python audit_rsc.py export.rsc --severity high                         # High+Critical only
  python audit_rsc.py export.rsc --check AUTH-001,FW-003                 # Specific checks
  python audit_rsc.py export.rsc --cve                                    # CVE vulnerability check
  python audit_rsc.py export.rsc --cve --cve-live                        # Live NVD CVE lookup
  python audit_rsc.py export.rsc --conflicts                             # Rule conflict analysis
  python audit_rsc.py export.rsc --ioc                                    # Compromise indicator check
  python audit_rsc.py export.rsc --lint my-script.rsc                   # Lint separate .rsc script
  python audit_rsc.py export.rsc --skip-wifi                            # Skip WiFi checks
  python audit_rsc.py export.rsc --skip-routing                         # Skip routing checks
  python audit_rsc.py export.rsc --output report.html      # Save to file
  python audit_rsc.py export.rsc --cve                     # Include CVE check
  python audit_rsc.py export.rsc --cve --cve-live          # CVE + NVD live lookup
  python audit_rsc.py export.rsc --conflicts               # Rule conflict analysis
  python audit_rsc.py export.rsc --ioc                     # IoC detection
  python audit_rsc.py export.rsc --lint script.rsc         # Lint a separate script
        """,
    )
    parser.add_argument("file", help="Path to .rsc configuration file")
    parser.add_argument("--format", choices=["text", "json", "html"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"],
                        help="Minimum severity to report")
    parser.add_argument("--check", help="Comma-separated check IDs to run")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--cve", action="store_true",
                        help="Run CVE check for RouterOS version (static DB)")
    parser.add_argument("--cve-live", action="store_true",
                        help="Enable live NVD API lookup for CVE check (requires internet)")
    parser.add_argument("--conflicts", action="store_true",
                        help="Run rule conflict analysis on firewall/NAT/mangle")
    parser.add_argument("--ioc", action="store_true",
                        help="Run indicator of compromise (IoC) detection")
    parser.add_argument("--lint", metavar="FILE",
                        help="Lint a separate .rsc script file for pre-deployment validation")
    parser.add_argument("--skip-wifi", action="store_true",
                        help="Skip WiFi security checks (WIFI-*)")
    parser.add_argument("--skip-routing", action="store_true",
                        help="Skip routing security checks (ROUTE-*)")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    check_filter = args.check.split(",") if args.check else None
    sev_map = {"critical": "Critical", "high": "High", "medium": "Medium",
               "low": "Low", "info": "Info"}

    auditor = RSCAuditor(
        args.file,
        severity_filter=sev_map.get(args.severity.lower()) if args.severity else None,
        check_filter=check_filter,
        do_cve=args.cve,
        do_cve_live=args.cve_live,
        do_conflicts=args.conflicts,
        do_ioc=args.ioc,
        skip_wifi=getattr(args, 'skip_wifi', False),
        skip_routing=getattr(args, 'skip_routing', False),
    )

    try:
        auditor.load()
    except Exception as e:
        print(f"Error loading file: {e}", file=sys.stderr)
        sys.exit(1)

    auditor.run_audit()

    # Run linter if requested
    if args.lint:
        if not os.path.exists(args.lint):
            print(f"Error: Lint file not found: {args.lint}", file=sys.stderr)
            sys.exit(1)
        auditor.run_lint(args.lint)

    if args.format == "json":
        output = json.dumps(auditor.report_json(), indent=2)
    elif args.format == "html":
        output = auditor.report_html()
    else:
        output = auditor.report_text()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Report written to {args.output}")
    else:
        print(output)

    # Exit with non-zero for findings >= High
    critical_high = sum(1 for f in auditor.findings if f["severity"] in ("Critical", "High"))
    if critical_high > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
