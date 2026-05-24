---
name: mikrotik-rsc-auditor
description: "Audit MikroTik RouterOS configuration files (.rsc) for security issues, compliance gaps, syntax errors, and configuration best practices. Performs comprehensive offline static analysis of exported RouterOS configs. Use when auditing .rsc files, reviewing RouterOS security, or assessing MikroTik device configurations for compliance hardening."
---

# MikroTik RouterOS .rsc Auditor

Expert-level offline static analysis skill for auditing MikroTik RouterOS exported configuration files (`.rsc`). Covers 100+ audit checks across 9 security domains with CVSS-based severity scoring, compliance mapping (CIS/NIST/ISO/PCI-DSS), and generated remediation scripts.

## When to Use

- A `.rsc` configuration export is provided for security review
- Evaluating a RouterOS deployment for security hardening compliance
- Pre-deployment audit of a configuration before applying to production
- Post-incident forensic review of router configuration artifacts
- Compliance audit mapping RouterOS config to CIS/NIST/ISO/PCI-DSS controls
- Assessing MikroTik hAP, CCR, RB, or Cloud Core Router configurations

**NOT for:**
- Live SSH/REST API interaction with a running RouterOS device
- Creating new `.rsc` scripts from scratch (see `mikrotik-routeros-rsc` skill)
- Realtime traffic analysis or SNMP monitoring
- Configuring CAPsMAN, BGP sessions, or other dynamic protocols

## Audit Methodology

The audit follows a 9-phase static analysis methodology applied to the entire `.rsc` file:

```
Phase 1:  Parse & Normalize     — Tokenize the .rsc, extract all config paths
Phase 2:  Authentication Audit   — Users, groups, service ACLs, password policies
Phase 3:  Service Surface Audit  — All enabled services, their bindings and ACLs
Phase 4:  Firewall & RAW Audit   — Filter/NAT/Mangle rules, connection tracking
Phase 5:  System Hardening Audit — Version, NTP, logging, updates, backups
Phase 6:  Network Config Audit   — VLANs, bridges, DHCP, DNS, interfaces
Phase 7:  Routing Security Audit — BGP/OSPF auth, filters, prefix limits
Phase 8:  WiFi Security Audit    — Encryption, isolation, CAPsMAN, PMF
Phase 9:  Script & Automation    — Script permissions, hardcoded secrets, scheduler
```

Each finding is assigned a severity using CVSS v3.1 principles adapted for configuration analysis:

| Severity | Score Range | Impact | Example |
|----------|-------------|--------|---------|
| **Critical** | 9.0–10.0 | Immediate compromise | Default admin, no firewall, WAN services exposed |
| **High** | 7.0–8.9 | Significant weakness | Open DNS resolver, SNMP public, no brute-force protection |
| **Medium** | 4.0–6.9 | Defense-in-depth gap | No remote syslog, NTP not configured, bridge MTU misconfig |
| **Low** | 0.1–3.9 | Informational | System identity not set, LCD not configured |
| **Info** | 0.0 | Reference only | RouterOS version reported, model identified |

## Audit Check Categories

### 1. Authentication & Access Control (AUTH) — 18 checks — Critical
Default admin, weak/no passwords, users without IP restrictions, SSH crypto, MAC-services (telnet/winbox/ping), WinBox/API on WAN, login restrictions, password policies, RoMON, permissive policies.

### 2. Service Hardening (SRV) — 17 checks — High
DNS open resolver, bandwidth server, proxy/SOCKS/UPnP, neighbor discovery on WAN, SNMP v1/v2c public, Telnet/FTP/PPTP, cloud services, SMB, WebFig HTTP, unused interfaces.

### 3. Firewall & Network Security (FW) — 17 checks — Critical/High
Missing default rules, no WAN drop, no established/related, brute-force protection, bogon filtering (RAW), IPv6 firewall, FastTrack, port knocking, unrestricted WAN access, ICMP rate limiting, DSTNAT controls, broadcast blocking, connection tracking limits.

### 4. System Hardening (SYS) — 10 checks — High
RouterOS version (CVE check), identity, NTP, local logging, remote syslog, update policy, unsigned packages, support output, backup configuration.

### 5. Network Configuration (NET) — 9 checks — Medium
Bridge VLAN filtering, DHCP security, DHCP lease storage on flash-constrained, DNS cache poisoning, MTU, VRRP/HA, hAP ac² offload considerations.

### 6. Routing Security (ROUTE) — 9 checks — Medium/High
BGP MD5 auth, OSPF auth, routing filters, BGP TTL security, prefix limits, dynamic routing on WAN, default route resilience, loopback router ID.

### 7. WiFi Security (WIFI) — 13 checks — High/Medium
Insecure encryption (WEP/TKIP), WPS, guest isolation, hidden SSID, per-band security, client isolation, CAPsMAN encryption, access lists, PMF, password strength, DFS radar handling, hAP ac² flash crisis.

### 8. Script & Automation (SCRIPT) — 9 checks — Medium
Excessive permissions, hardcoded credentials, single-instance guards, error handling, global variable pollution, destructive commands.

### 9. Compliance Mapping (COMP) — 6 info checks
CIS crosswalk, NIST SP 800-53, ISO 27001, PCI-DSS, Mitre ATT&CK, CVSS scoring.

## Interactive Onboarding

When the user invokes the skill on a `.rsc` file without providing additional context, use `ask_user_question` to gather missing information. This tailors the audit to the specific device and deployment, reducing false positives and irrelevant findings.

### Tier 1 Questions (Essential — ask on first run, skip if profile exists)

**Question 1: Device Role** — Determines the security baseline severity:
- Home Router → relaxed defaults (WAN-side UPnP = Info, not Critical)
- Office/SMB Gateway → medium hardening (VLAN isolation, VPN checks enabled)
- Enterprise Router → maximum hardening (RADIUS, 802.1X, logging checks = Critical)
- ISP/DC Router → carrier-grade (BGP security, minimal attack surface focus)

**Question 2: Services in Use** — Multi-select; unused services get N/A (excluded from report):
- Internet Gateway / NAT
- WiFi Access Point (2.4GHz, 5GHz, or both)
- DHCP Server
- DNS Server
- VPN Server (L2TP/IPsec, SSTP, WireGuard, OpenVPN)
- Dynamic Routing (BGP, OSPF)
- CAPsMAN Controller

**Question 3: Audit Scope** — Controls check depth:
- Quick Review → top 15 critical/high checks only (~2 seconds)
- Standard Audit → all 108 checks with full scoring
- Compliance Focus → filtered to selected framework

### Tier 2 Questions (Conditional — ask only if relevant)

**If Compliance Focus selected:** Which framework? (CIS / NIST / ISO / PCI-DSS)

**If WiFi selected:** Deployment type? (Home/SOHO / Office-Enterprise / Public Hotspot)

**If Routing selected:** Profile? (Single ISP / Multi-homed BGP / Internal OSPF)

### Profile Persistence

Save answers to `~/.config/mikrotik-auditor/profile.yml` after the first run:

```yaml
version: 1
device_role: "office"
services:
  - nat
  - wifi
  - dhcp
audit_scope: "standard"
compliance: "cis"
routing: null
wifi_type: "home"
cve_check: "offline"
```

On subsequent runs, if the profile exists, skip all questions and use saved values (silent mode). Offer to re-interview if the user passes `--reconfigure`.

### Answer → Audit Mapping

| Answer | Effect |
|--------|--------|
| `device_role = "home"` | Relaxed severity for WAN-side UPnP, management access |
| `device_role = "enterprise"` | RADIUS, 802.1X, logging checks become Critical severity |
| `services = ["wifi"]` | WiFi checks are active. Missing encryption → Critical |
| `services = []` | WiFi checks set to N/A — excluded from report |
| `services = ["routing"]` | BGP/OSPF authentication checks enabled |
| `audit_scope = "quick"` | Only top 15 findings by CVSS score |
| `audit_scope = "compliance"` | Filter to compliance-mapped checks only |
| `cve_check = "offline"` | Pass `--cve` to audit_rsc.py |
| `cve_check = "live"` | Pass `--cve --cve-live` to audit_rsc.py |

### Implementation Note

All interactivity lives in this SKILL.md — the Python tools remain pure CLI with no interactive logic. The `ask_user_question` tool is a pi agent capability. Profile reading/writing is done via `bash` commands (`cat`, `write`). This separation keeps the CLI tool chainable in pipelines while the skill provides the interactive UX.

## Response Approach

1. **Check for profile** — If `~/.config/mikrotik-auditor/profile.yml` exists, read it silently. If not, enter interactive onboarding (see Interactive Onboarding section).
2. **Parse** the `.rsc` file — extract all configuration paths, commands, and parameters
3. **Apply context** — Use profile answers to tailor check relevance, severity, and scope
4. **Run audit checks** against each configuration domain in order (AUTH → SRV → FW → SYS → NET → ROUTE → WIFI → SCRIPT → COMP)
5. **Assign severity** to each finding using the CVSS-based scale, adjusted by device role
6. **Generate remediation** — produce the exact RouterOS CLI commands to fix each finding
7. **Score the config** — overall security score (0–100) with per-category breakdown
8. **Generate reports** — structured JSON, raw text, and Markdown report format with severity grouping
9. **Map to compliance frameworks** — cross-reference each finding to CIS/NIST/ISO/PCI-DSS controls
10. **Save profile** — If this was an interactive run, save answers to profile.yml for next time

## Report Structure

Every audit produces a structured report with these sections:
```
1.  Meta — device model, RouterOS version, export timestamp, software ID
2.  Risk Score — overall (0-100) with per-category heatmap
3.  Critical Findings — immediate action required (list with CVSS, path, fix)
4.  High Findings — significant security weaknesses (list with CVSS, path, fix)
5.  Medium Findings — defense-in-depth gaps (list with CVSS, path, fix)
6.  Low Findings — informational (list)
7.  Compliance Map — CIS/NIST/ISO/PCI-DSS control mappings per finding
8.  Summary Statistics — counts by severity, category hits, false positive notes
9.  Remediation Commands — per-finding RouterOS CLI commands (consolidation planned)
```

## Safety Guardrails

- **DO NOT** output actual credentials, keys, or certificates found in configs — mask with `[REDACTED]`
- **DO NOT** suggest `system reset-configuration` unless explicitly requested
- **DO NOT** recommend firmware downgrades without CVE justification
- **DO NOT** recommend blocking essential services without understanding the deployment context
- **ALWAYS** classify findings with severity and note when context may change risk level
- **ALWAYS** include the exact config path in findings for reproducible reference
- **ALWAYS** provide remediation CLI commands for every actionable finding

## Limitations & Assumptions

- Offline analysis cannot verify live state — only what was exported. Some checks (e.g., port knocking state, brute-force detection) inherently require live access.
- Export file format assumptions: assumes standard `/export` output; `hide-sensitive=yes` masks passwords; `verbose=yes` includes defaults; `compact=yes` (default) omits default values.
- If `hide-sensitive` was used, password-related checks show `[REDACTED]` values, which must be noted as indeterminate.
- RouterOS v7 vs v6 syntax differences are flagged but both are validated against their respective grammar.
- hAP ac² flash space cannot be determined from a config export — requires live `/system resource print`.
- Device model detection from export header is best-effort (model line may be truncated or absent).

## References

- [references/AUDIT_CHECKS.md](references/AUDIT_CHECKS.md) — Complete 100+ item audit checklist with per-check rationale, query, and fix
- [references/SECURITY_BASELINE.md](references/SECURITY_BASELINE.md) — Secure configuration baseline with service-by-service safe defaults
- [references/SYNTAX_REFERENCE.md](references/SYNTAX_REFERENCE.md) — RouterOS .rsc syntax and validation rules
- [references/COMPLIANCE_MAPPING.md](references/COMPLIANCE_MAPPING.md) — CIS/NIST/ISO/PCI-DSS control mapping reference
- [references/EXAMPLES.md](references/EXAMPLES.md) — Idempotent RouterOS scripting patterns with copy-paste ready code
- [references/SCRIPTING_PITFALLS.md](references/SCRIPTING_PITFALLS.md) — Common RouterOS scripting mistakes and safe alternatives
- [scripts/audit_rsc.py](scripts/audit_rsc.py) — Python tool for automated offline .rsc audit with HTML/JSON/TXT reports

## Related Tools

The following companion scripts extend the auditor with specialized analysis capabilities:

- [scripts/cve_database.py](scripts/cve_database.py) — CVE lookup tool for RouterOS versions. Uses a static database of 9+ known CVEs (CVE-2018-14847 through CVE-2024-23895) with version parsing, wildcard/range matching, and severity scoring. Supports optional live NIST NVD API v2.0 lookup with 24-hour caching. Integrated via `--cve` and `--cve-live` flags.

- [scripts/conflict_analyzer.py](scripts/conflict_analyzer.py) — Rule conflict detection for firewall, NAT, and mangle configurations. Detects 8 conflict types: unreachable rules, NAT bypasses firewall, orphan routing marks, interfaces not in interface lists, address list conflicts, missing FastTrack, shadowed rules, and duplicate rules. Integrated via `--conflicts` flag.

- [scripts/ioc_analyzer.py](scripts/ioc_analyzer.py) — Indicator of Compromise (IoC) detection for signs of active RouterOS compromise. Checks for: scheduler fetch backdoors (VPNFilter pattern), SOCKS/HTTP proxies (Meris botnet), suspicious files, unknown admin users, DNS hijacking, mangle sniff rules, cryptominer indicators, and C2 patterns (IP:port, Telegram, Discord webhooks). Integrated via `--ioc` flag.

- [scripts/lint_rsc.py](scripts/lint_rsc.py) — Heuristic script linter for pre-deployment validation of .rsc scripts. Features scope-tracking engine (5 scope kinds), context-aware suppression, and 15+ rules across 5 categories. Detects destructive commands, unconditional bulk removes, unguarded `add` operations, fixed numeric IDs, bare `import` usage, `:delay` in loops, and credential leakage in `:log` statements. Integrated via `--lint` flag.

## Development Workflow

For engineers developing and deploying RouterOS scripts, the following workflow integrates auditing at every stage:

```
Step 1: Write script with idempotent patterns
  → Follow the patterns in references/EXAMPLES.md
  → Review references/SCRIPTING_PITFALLS.md for common mistakes

Step 2: Lint the script before deployment
  → python scripts/lint_rsc.py my-script.rsc --strict
  → Fix any errors and warnings before proceeding

Step 3: Dry-run the import on target device
  → /import file=my-script.rsc verbose=yes dry-run
  → Review output for unexpected changes

Step 4: Import with :onerror wrapper for safety
  → :onerror e in={ /import file=my-script.rsc } do={ :log error "Failed: $e" }
  → This catches both import parse errors and script execution errors

Step 5: Audit the deployed configuration
  → Export config: /export hide-sensitive file=audit-export
  → Run full audit: python scripts/audit_rsc.py audit-export.rsc --cve --conflicts --ioc
  → Review findings and apply remediation commands
```

This workflow ensures that scripts are safe to import (steps 1–4) and the resulting configuration is secure (step 5). The `audit_rsc.py` tool with the new `--cve`, `--conflicts`, `--ioc`, and `--lint` flags provides end-to-end coverage from development to post-deployment.

## Related Skills

- `mikrotik-routeros-rsc` — Creating and editing RouterOS scripts (complementary; this skill audits what that skill creates)
- `security-auditor` — General security auditing framework (this skill specializes for MikroTik/RouterOS)
- `vulnerability-scanner` — Vulnerability scanning methodology (this skill focuses on config-specific findings)
