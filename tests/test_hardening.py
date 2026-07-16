"""Tests for Phase-0 hardening: subprocess timeouts and the findings cap."""

import pytest

from code_security_mcp.adapters.process import run_with_timeout
from code_security_mcp.domain.models import Finding, ScanResult, Severity
from code_security_mcp.server import _MAX_FINDINGS, _findings_payload


def test_run_with_timeout_raises_on_timeout():
    # A command that outlives the timeout must fail cleanly, not hang.
    with pytest.raises(RuntimeError, match="timed out"):
        run_with_timeout(["sleep", "5"], timeout=1)


def test_run_with_timeout_does_not_raise_on_nonzero_exit():
    # Analyzers exit non-zero when they find issues — that is normal.
    completed = run_with_timeout(["false"], timeout=5)
    assert completed.returncode != 0


def _result_with(n: int) -> ScanResult:
    findings = tuple(
        Finding(f"R{i}", "m", "f", i + 1, Severity.WARNING) for i in range(n)
    )
    return ScanResult(findings=findings)


def test_findings_payload_caps_and_flags_truncation():
    payload = _findings_payload(_result_with(_MAX_FINDINGS + 100))

    assert payload["count"] == _MAX_FINDINGS + 100  # true total is preserved
    assert payload["truncated"] is True
    assert len(payload["findings"]) == _MAX_FINDINGS  # list is capped


def test_findings_payload_not_truncated_when_small():
    payload = _findings_payload(_result_with(3))
    assert payload["truncated"] is False
    assert len(payload["findings"]) == 3
