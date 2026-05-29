# Changelog

## [Unreleased]

## [0.2.0] - 2026-05-29

### Added
- 7 cross-domain consistency checks (XCHK-*) via `--cross-checks` flag
- `scripts/cross_checks.py` module — detects config contradictions between domains

### Changed
- Version gating engine: `skip_if_version_lt` support, fail-closed on unparseable versions
- Version parser unified with `cve_database.parse_version()` — no crash on 7.19.2
- SRV-006 detect pattern: now matches v7 `discover-interface-list=` syntax
- AUTH-014 now gated to v7 only (`minimum-password-length` doesn't exist in v6)
- FW-017, ROUTE-004, ROUTE-005 now gated to v7 only (BGP connection paths)
- NET-003 now gated to v7 only (`store-leases-on-disk` removed in v7)

### Fixed
- Runtime crash on patch-level versions (e.g. RouterOS 7.19.2)
- False positives: BGP checks no longer fire on v6 configs
- False positives: AUTH-014 no longer fires on v6 configs
- False positives: NET-003 no longer fires on v7 configs

## [0.1.1] - 2026-05-24

### Fixed
- CLI docstring examples now match actual argparse (missing file argument)
- Compliance framework counts in README (CIS, NIST, ISO clause references)
- Line count in README project structure (audit_rsc.py)
- Duplicate `files` key in package.json

## [0.1.0] - 2026-05-24
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
