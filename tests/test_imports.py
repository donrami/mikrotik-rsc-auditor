"""Basic import and smoke tests for all modules.

All imports use the installed package namespace (scripts.xxx).
Run with: pytest tests/  (after pip install -e .)
"""


class TestImports:
    """Verify all modules import without errors."""

    def test_audit_rsc_import(self):
        from scripts.audit_rsc import RSCAuditor
        assert RSCAuditor is not None

    def test_cve_database_import(self):
        from scripts.cve_database import check_cve_for_version, parse_version, version_matches_pattern
        assert check_cve_for_version is not None
        assert parse_version is not None

    def test_conflict_analyzer_import(self):
        from scripts.conflict_analyzer import ConflictAnalyzer, ConflictType
        assert ConflictAnalyzer is not None
        assert ConflictType is not None

    def test_conflict_explanations_import(self):
        from scripts.conflict_explanations import get_explanation
        assert get_explanation is not None

    def test_ioc_analyzer_import(self):
        from scripts.ioc_analyzer import IoCAnalyzer, IoCType
        assert IoCAnalyzer is not None
        assert IoCType is not None

    def test_lint_rsc_import(self):
        import scripts.lint_rsc
        assert hasattr(scripts.lint_rsc, "lint_text")


class TestCVEDatabase:
    """Test CVE version parsing and matching."""

    def test_version_parse_stable(self):
        from scripts.cve_database import parse_version, version_matches_pattern
        v = parse_version("7.5")
        assert v is not None
        assert version_matches_pattern("7.5", "7.*")

    def test_version_parse_prerelease(self):
        from scripts.cve_database import parse_version, version_matches_pattern
        v7rc = parse_version("7.10rc1")
        v7b = parse_version("7.1beta3")
        assert v7rc is not None
        assert v7b is not None

    def test_cve_lookup_v7(self):
        from scripts.cve_database import check_cve_for_version
        cves = check_cve_for_version("7.5")
        assert len(cves) > 0, "v7.5 should have CVEs"

    def test_cve_lookup_v6(self):
        from scripts.cve_database import check_cve_for_version
        cves = check_cve_for_version("6.42.6")
        v7_only = [c for c in cves if not any("6.*" in v or v.startswith("6.") for v in c.affected_versions)]
        assert len(v7_only) == 0, f"v6 got v7-only CVEs: {[c.cve_id for c in v7_only]}"


class TestLinter:
    """Test lint_rsc basic functionality."""

    def test_destructive_detected(self):
        import scripts.lint_rsc
        result = scripts.lint_rsc.lint_text("/system reset-configuration")
        assert any("destructive" in r.rule for r in result)

    def test_clean_rule_no_false_positive(self):
        import scripts.lint_rsc
        # Non-sensitive command should not trigger idempotency warnings
        result = scripts.lint_rsc.lint_text(":global myVar \"hello\"")
        assert len(result) == 0, f"Clean command flagged: {result}"

    def test_unguarded_add_detected(self):
        import scripts.lint_rsc
        # Unguarded add on sensitive menu IS a real finding
        result = scripts.lint_rsc.lint_text("/ip firewall filter add chain=input action=accept")
        assert len(result) > 0, "Should flag unguarded add on firewall"
