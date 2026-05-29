---
name: mikrotik-rsc-auditor-test
description: "TEST BUILD — Audits MikroTik RouterOS .rsc config exports (version gating + cross-checks). Use when testing the latest pre-push changes alongside the stable v0.1.0 skill."
---

# MikroTik RSC Auditor (Test Build)

This is a **test installation** of the mikrotik-rsc-auditor skill pointing at the working directory.
Use it to verify changes before pushing. It is identical to the stable version plus:

- Version gating engine fixes (skip_if_version_lt, fail-closed on unparseable versions)
- 7 cross-domain consistency checks (`--cross-checks` flag)
- Version parser unified with cve_database (no crash on 7.19.2)
- SRV-006 v7 syntax pattern fix

## Testing

```bash
# Quick audit with all features
python scripts/audit_rsc.py examples/vulnerable-config.rsc --cross-checks

# Verify version gating (v7 checks skipped on v6)
python scripts/audit_rsc.py examples/vulnerable-config.rsc --cross-checks --format json \
  | python -c "import json,sys; d=json.load(sys.stdin); print([f['id'] for f in d['findings'] if f['id'].startswith('XCHK-')])"

# Run test suite
python -m pytest tests/ -v
```

## What changed

| PR | Changes |
|----|---------|
| PR 1 (version gating) | `_parse_ros_version()` → `Optional[str]`, `skip_if_version_lt`, fail-closed, 6 version-gated checks fixed |
| PR 2 (cross-checks) | `scripts/cross_checks.py`, `--cross-checks` flag, 7 cross-domain consistency checks |
