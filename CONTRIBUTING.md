# Contributing to MikroTik RSC Auditor

Thanks for your interest in contributing! This project is a static analysis tool for MikroTik RouterOS security configurations. All contributions — bug reports, feature suggestions, documentation, or code — are welcome.

## How to Report Bugs

1. **Check existing issues** — search the issue tracker before filing a duplicate
2. **Include a minimal reproduction** — a sanitized `.rsc` export that triggers the bug is ideal
3. **Describe the environment** — RouterOS version, device model, Python version, OS
4. **Attach the full output** — run with `mikrotik-audit --format json` and attach the JSON

## How to Suggest Features

Open an issue with the `enhancement` label and describe:
- What the feature should do
- Why it's useful (use case)
- How the user would interact with it
- Any relevant prior art (Lynis, CIS-CAT, OpenSCAP patterns)

## Development Setup

```bash
# Clone the repo
git clone https://github.com/your-org/mikrotik-rsc-auditor.git
cd mikrotik-rsc-auditor

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install in editable mode with dev dependencies
pip install -e .[dev]
```

## Running Tests

```bash
# Run all tests
pytest

# With coverage
pytest --cov=scripts --cov-report=html

# Run specific test
pytest tests/test_cve_database.py -v
```

## Code Style

- Follow existing patterns in the codebase
- All code must be Python 3.10+ compatible
- Use stdlib only — no external dependencies for production code
- Max line length: 100 characters
- Use `ruff` for linting: `ruff check scripts/`
- Use `mypy` for type checking: `mypy scripts/`

### Adding a New Audit Check

1. Add the check definition to `scripts/audit_rsc.py` in `AUDIT_CHECKS`
2. Follow the existing dict format (id, name, severity, cvss, category, path, description, detect, remediation, compliance)
3. Add the detection regex pattern in the `detect` list
4. Include compliance mappings (cis, nist, iso, pci)
5. Add a test case in `tests/test_audit_rsc.py`

## Pull Request Process

1. Fork the repo and create a feature branch from `main`
2. Write tests for any new functionality
3. Ensure all existing tests pass: `pytest`
4. Run the linter: `ruff check scripts/`
5. Update documentation if adding CLI flags or report formats
6. Open a PR against `main` with a clear title and description
7. Reference any related issues

## Commit Messages

Use conventional commits:
- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation changes
- `test:` test additions or changes
- `refactor:` code restructuring
- `chore:` maintenance tasks
