<!-- markdownlint-disable MD033 MD041 -->

# MikroTik RouterOS .rsc Auditor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![npm](https://img.shields.io/npm/v/mikrotik-rsc-auditor)](https://www.npmjs.com/package/mikrotik-rsc-auditor)
[![Pi Skill](https://img.shields.io/badge/pi-skill-purple)](https://github.com/nicolodavis/pi)
[![Checks](https://img.shields.io/badge/checks-108-success)](scripts/audit_rsc.py)
[![CLI](https://img.shields.io/badge/CLI-ready-brightgreen)](README.md)

**Scans MikroTik RouterOS .rsc exports for security issues, misconfigurations, and compliance gaps -- 108 checks across 9 domains, with CVSS scoring, conflict detection, CVE lookup, and a script linter.**

---

## Features

| Feature | Description |
|---------|-------------|
| 108 Security Checks | Authentication, services, firewall, system hardening, networking, routing, WiFi, scripts, compliance |
| CVSS v3.1 Scoring | Every finding scored with severity (Critical/High/Medium/Low/Info) and CVSS vector |
| Compliance Mapping | Each finding cross-referenced to CIS, NIST SP 800-53, ISO 27001, and PCI-DSS controls |
| Conflict Detection | 8 rule conflict types -- unreachable rules, NAT bypasses, orphan marks, duplicates, and more |
| IoC Detection | 10 compromise indicators -- scheduler backdoors, DNS hijacking, cryptominers, C2 patterns |
| Script Linter | 15+ rules with scope-aware context suppression, guard tracking, CI-ready exit codes |
| Zero Dependencies | Uses only Python stdlib -- runs on any system with Python 3.10+ |
| Pi Agent Integration | Also works as a pi skill with interactive onboarding for first-time users |

---

## Quick Start

```bash
# Install via pi (npm-based)
pi install npm:mikrotik-rsc-auditor

# Audit a RouterOS export
mikrotik-audit export.rsc

# Or run directly from source
python scripts/audit_rsc.py export.rsc
```

---

## Usage

### Basic Audit

```bash
mikrotik-audit export.rsc
```

### JSON Output

```bash
mikrotik-audit export.rsc --format json
```

### HTML Report

```bash
mikrotik-audit export.rsc --format html -o report.html
```

### Severity Filter (High and Critical only)

```bash
mikrotik-audit export.rsc --severity high
```

### Specific Checks

```bash
mikrotik-audit export.rsc --check AUTH-001,FW-003
```

### CVE Vulnerability Check

```bash
mikrotik-audit export.rsc --cve
```

### Live NVD CVE Lookup (requires internet)

```bash
export NVD_API_KEY=your_key
mikrotik-audit export.rsc --cve --cve-live
```

### Conflict Detection

```bash
mikrotik-audit export.rsc --conflicts
```

### IoC / Compromise Detection

```bash
mikrotik-audit export.rsc --ioc
```

### Lint a Script (development-time validation)

```bash
mikrotik-audit export.rsc --lint my-script.rsc
```

### All Features

```bash
mikrotik-audit export.rsc --cve --conflicts --ioc --format html -o full-report.html
```

---

## CLI Flags

| Flag | Type | Description | Default |
|------|------|-------------|---------|
| `file` | positional | Path to `.rsc` configuration file | required |
| `--format` | choice | Output format: `text`, `json`, `html` | `text` |
| `--severity` | choice | Minimum severity: `critical`, `high`, `medium`, `low`, `info` | all |
| `--check` | string | Comma-separated check IDs to run (e.g., `AUTH-001,FW-003`) | all |
| `--cve` | flag | Enable CVE vulnerability check using static database | off |
| `--cve-live` | flag | Enable live NIST NVD API lookup (requires internet) | off |
| `--conflicts` | flag | Enable 8-type rule conflict analysis | off |
| `--ioc` | flag | Enable 10-type compromise indicator detection | off |
| `--lint` | string | Path to a `.rsc` script file to lint (used alongside the config file) | -- |
| `--skip-wifi` | flag | Skip WiFi security checks (for non-wireless devices) | off |
| `--skip-routing` | flag | Skip routing security checks (BGP/OSPF) | off |
| `-o, --output` | path | Save report to file instead of stdout | -- |

---

## Pi Agent Interactive Mode

When installed as a pi agent skill, the auditor runs an interactive setup on first use:

1. **Device Role** -- Home router / Office gateway / Enterprise / ISP -- determines security baseline severity
2. **Services in Use** -- Multi-select which features this device provides (WiFi, NAT, DHCP, VPN, routing, CAPsMAN)
3. **Audit Scope** -- Quick review / Standard / Compliance -- controls check depth
4. **Conditional Follow-ups** -- Compliance framework, WiFi type, routing profile (only if relevant)

Answers are saved to `~/.config/mikrotik-auditor/profile.yml`. Subsequent runs skip the questions.

```bash
# Install as pi skill
pi install npm:mikrotik-rsc-auditor

# Run interactively (first time)
mikrotik-audit export.rsc
# -- asks 3-4 questions, then runs a tailored audit
```

---

## Report Formats

### Text Report

Terminal-friendly output with severity grouping, score, top-5 executive summary, and per-finding remediation commands. Includes safety warnings for high-risk changes.

### JSON Report

Structured machine-readable output for pipeline integration:

```json
{
  "meta": { "device_model": "C53UiG+5HPaxD2HPaxD", "version": "7.22.3" },
  "score": { "score": 72, "grade": "B", "by_severity": { "Critical": 0, "High": 2 } },
  "findings": [
    {
      "id": "AUTH-005",
      "name": "SSH weak-crypto enabled",
      "severity": "High",
      "cvss": "7.5",
      "category": "Authentication & Access Control",
      "remediation": "/ip ssh set strong-crypto=yes"
    }
  ]
}
```

### HTML Report

Self-contained dark-mode compatible HTML with color-coded severity badges, score display, and remediation blocks.

---

## Compliance Frameworks

| Framework | Coverage |
|-----------|----------|
| **CIS RouterOS Benchmark v1.x** | 42 controls mapped |
| **NIST SP 800-53** | 30+ controls (AC, AU, IA, SC, SI, PE, CP) |
| **ISO 27001** | 25+ controls (A.8, A.9, A.10, A.12, A.13, A.17) |
| **PCI-DSS** | 15+ requirements (1, 2, 4, 6, 7, 8, 10, 11) |

---

## Project Structure

```
mikrotik-rsc-auditor/
├── scripts/
│   ├── audit_rsc.py              # Main entry point (2,860 lines)
│   ├── cve_database.py            # CVE lookup + NVD API (1,111 lines)
│   ├── conflict_analyzer.py       # 8 conflict types (1,551 lines)
│   ├── conflict_explanations.py   # User-friendly explanations (650 lines)
│   ├── device_profiles.py         # Hardware-specific profile system
│   ├── ioc_analyzer.py            # 10 IoC types (784 lines)
│   ├── sanitize_rsc.py            # Config redaction for safe sharing (72 lines)
│   └── lint_rsc.py                # Script linter with scope tracking (587 lines)
├── references/
│   ├── AUDIT_CHECKS.md            # 108-item audit checklist
│   ├── SECURITY_BASELINE.md       # Secure configuration baseline
│   ├── SYNTAX_REFERENCE.md        # RouterOS .rsc syntax reference
│   ├── COMPLIANCE_MAPPING.md      # CIS/NIST/ISO/PCI-DSS crosswalk
│   ├── EXAMPLES.md                # Idempotent scripting patterns
│   ├── HARDWARE_COMPATIBILITY.md  # Device profile reference for 15+ families
│   └── SCRIPTING_PITFALLS.md      # Common RouterOS scripting mistakes
├── examples/
│   ├── sanitized-export.rsc       # Sanitized real-world export
│   ├── minimal-config.rsc         # Minimal secure configuration
│   └── vulnerable-config.rsc      # Deliberately insecure demo config
├── tests/                         # Test suite
├── CHANGELOG.md                   # Release history
├── CONTRIBUTING.md                # Contribution guide
├── LICENSE                        # MIT license
├── package.json                   # npm/pi packaging manifest
├── pyproject.toml                 # Python project metadata
├── SKILL.md                       # Pi agent skill definition
└── README.md                      # This file
```

---

## Installation

### Via pi (npm registry)

```bash
pi install npm:mikrotik-rsc-auditor
```

This makes the `mikrotik-audit` command available on your PATH.

### From source

```bash
git clone https://github.com/donrami/mikrotik-rsc-auditor.git
cd mikrotik-rsc-auditor
# Run directly
python scripts/audit_rsc.py export.rsc
```

### As a pi agent skill

```bash
pi install npm:mikrotik-rsc-auditor
```

The package ships with a `SKILL.md` that registers it as a pi agent skill.

---

## Requirements

- Python 3.10 or later
- Zero external Python dependencies -- only standard library
- For live CVE lookup: internet access and optional `NVD_API_KEY` environment variable
- For linting: RouterOS script files (`.rsc`)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on reporting bugs, suggesting features, and submitting pull requests.

---

## License

MIT License -- see [LICENSE](LICENSE) for full text.

---

## Related

- [MikroTik RouterOS Documentation](https://help.mikrotik.com/docs/)
- [CIS RouterOS Benchmark](https://www.cisecurity.org/benchmark/mikrotik_routeros)
- [NIST NVD](https://nvd.nist.gov/)
- [Pi Agent Framework](https://github.com/nicolodavis/pi)
- [npm package: mikrotik-rsc-auditor](https://www.npmjs.com/package/mikrotik-rsc-auditor)
