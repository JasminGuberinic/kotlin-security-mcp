"""Translate a Bandit JSON report into our domain Findings.

Unlike detekt and SpotBugs, Bandit does not emit SARIF — it has its own simple
JSON shape. So instead of reusing the SARIF parser we write a tiny dedicated
mapper here. It is the same idea as `sarif.py`: read only the fields we rely on,
guard every access, and normalize into the shared `Finding` vocabulary.
"""

from __future__ import annotations

from typing import Any

from code_security_mcp.domain.models import Finding, ScanResult, Severity

# Bandit grades severity as LOW / MEDIUM / HIGH; map those onto our three levels.
_BANDIT_SEVERITY_TO_SEVERITY: dict[str, Severity] = {
    "HIGH": Severity.ERROR,
    "MEDIUM": Severity.WARNING,
    "LOW": Severity.INFO,
}


def parse_bandit_report(report: dict[str, Any]) -> ScanResult:
    """Turn a parsed Bandit JSON document into a ScanResult.

    Bandit puts every issue under a top-level "results" array; we map each entry
    to one Finding.
    """
    findings = [_finding_from_result(result) for result in report.get("results", [])]
    return ScanResult(findings=tuple(findings))


def _finding_from_result(result: dict[str, Any]) -> Finding:
    """Build one Finding from one Bandit result object."""
    return Finding(
        rule_id=result.get("test_id", "unknown"),
        message=result.get("issue_text", "").strip(),
        file_path=result.get("filename", ""),
        line=result.get("line_number", 1),
        severity=_severity_of(result),
        cwe=_cwe_of(result),
    )


def _severity_of(result: dict[str, Any]) -> Severity:
    """Map Bandit's issue_severity onto our Severity, defaulting to WARNING."""
    level = result.get("issue_severity", "MEDIUM").upper()
    return _BANDIT_SEVERITY_TO_SEVERITY.get(level, Severity.WARNING)


def _cwe_of(result: dict[str, Any]) -> str | None:
    """Format Bandit's CWE id as "CWE-<n>", when the report includes one.

    Newer Bandit versions attach an `issue_cwe` object like {"id": 327, ...};
    older ones omit it, so we return None in that case.
    """
    cwe = result.get("issue_cwe")
    if isinstance(cwe, dict) and cwe.get("id") is not None:
        return f"CWE-{cwe['id']}"
    return None
