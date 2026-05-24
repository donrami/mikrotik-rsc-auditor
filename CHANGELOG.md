# Changelog

## [Unreleased]

## [0.1.0] - 2026-05-24

### Added
- Initial pre-release
- 108 security checks across 9 domains (AUTH, SRV, FW, SYS, NET, ROUTE, WIFI, SCRIPT, COMP)
- CVSS v3.1 scoring with per-finding vector strings
- Compliance mapping to CIS RouterOS Benchmark, NIST SP 800-53, ISO 27001, PCI-DSS
- CVE database module (static DB + optional live NIST NVD API lookup)
- Conflict detection engine (8 types: unreachable rules, NAT bypass, orphan marks, interface lists, address list conflicts, FastTrack, shadowed rules, duplicates)
- IoC detection engine (10 indicators: scheduler backdoors, proxy/SOCKS, suspicious files, unknown users, DNS hijacking, sniff rules, cryptominers, C2 patterns)
- Script linter (15+ rules with scope-aware context suppression, guard tracking, CI exit codes)
- 6 reference documents (AUDIT_CHECKS, SECURITY_BASELINE, SYNTAX_REFERENCE, COMPLIANCE_MAPPING, EXAMPLES, SCRIPTING_PITFALLS)
- Interactive onboarding mode for pi agent (device role, services, audit scope questions)
- Text, JSON, and HTML report formats
- Device-specific guidance for hAP ax³ and hAP ac²
- Zero external Python dependencies (stdlib only)
