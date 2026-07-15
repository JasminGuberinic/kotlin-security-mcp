"""Tests for the Bandit (Python) report parser and analyzer wiring."""

from pathlib import Path

from code_security_mcp.adapters.bandit_analyzer import BanditConfig, PythonAnalyzer
from code_security_mcp.adapters.bandit_report import parse_bandit_report
from code_security_mcp.domain.models import Severity


def _bandit_json_with_one_result() -> dict:
    """A minimal but realistic Bandit JSON document with a single issue."""
    return {
        "results": [
            {
                "filename": "app/crypto.py",
                "line_number": 12,
                "test_id": "B303",
                "test_name": "md5",
                "issue_severity": "HIGH",
                "issue_text": "Use of insecure MD5 hash function.",
                "issue_cwe": {"id": 327, "link": "https://cwe.mitre.org/..."},
            }
        ]
    }


def test_parses_all_core_fields():
    result = parse_bandit_report(_bandit_json_with_one_result())

    assert result.count == 1
    finding = result.findings[0]
    assert finding.rule_id == "B303"
    assert finding.message == "Use of insecure MD5 hash function."
    assert finding.file_path == "app/crypto.py"
    assert finding.line == 12
    assert finding.severity is Severity.ERROR  # HIGH -> ERROR
    assert finding.cwe == "CWE-327"


def test_missing_cwe_becomes_none():
    report = _bandit_json_with_one_result()
    del report["results"][0]["issue_cwe"]
    result = parse_bandit_report(report)
    assert result.findings[0].cwe is None


def test_empty_report_is_a_clean_result():
    assert parse_bandit_report({}).has_findings is False


def test_analyzer_unavailable_when_binary_missing(tmp_path):
    # Point at a non-existent executable: it must report itself unavailable and
    # therefore not support any target.
    analyzer = PythonAnalyzer(BanditConfig(executable=str(tmp_path / "no-bandit")))
    assert analyzer.is_available() is False
    assert analyzer.supports(tmp_path / "x.py") is False


def test_command_uses_recurse_for_directories(tmp_path):
    analyzer = PythonAnalyzer()
    file_cmd = analyzer._build_command(tmp_path / "a.py", tmp_path / "out.json")
    dir_cmd = analyzer._build_command(tmp_path, tmp_path / "out.json")

    assert "-r" not in file_cmd  # a single file is not recursed
    assert "-r" in dir_cmd  # a directory is
    assert "-f" in file_cmd and "json" in file_cmd
