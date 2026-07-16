"""End-to-end integration tests: run the REAL analyzers over the example files.

Unlike the unit tests (which use fakes and hand-built fixtures), these actually
launch detekt, SpotBugs, Bandit, Roslyn, and ESLint and assert that a known
vulnerability in `examples/` is reported. That verifies the whole pipeline —
subprocess invocation, real tool output, parsing, routing — not just our code.

Each test builds its analyzer exactly the way the server does, from the same
environment variables, by reusing the server's composition helpers. When a tool
is not configured on this machine, `_try_build_*` returns None and the test
skips — so this file is safe to have around even where the tools are absent.

Run them with:  pytest -m integration
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from code_security_mcp.server import (
    _try_build_csharp,
    _try_build_detekt,
    _try_build_java,
    _try_build_javascript,
    _try_build_python,
)

# Repo root: this file is at <root>/tests/integration/test_real_analyzers.py.
_ROOT = Path(__file__).resolve().parents[2]
_EXAMPLES = _ROOT / "examples"


def _rule_ids(result) -> set[str]:
    """The set of rule ids in a ScanResult — what our assertions check."""
    return {finding.rule_id for finding in result.findings}


@pytest.mark.integration
def test_kotlin_detekt_finds_hardcoded_key():
    analyzer = _try_build_detekt()
    if analyzer is None:
        pytest.skip("detekt not configured (KSM_JAVA/KSM_DETEKT_CLI_JAR/KSM_PLUGIN_JARS)")

    result = analyzer.scan(_EXAMPLES / "VulnerableSample.kt")

    assert "HardcodedAesKey" in _rule_ids(result)


@pytest.mark.integration
def test_java_spotbugs_finds_weak_crypto(tmp_path):
    analyzer = _try_build_java()
    if analyzer is None:
        pytest.skip("SpotBugs not configured (KSM_SPOTBUGS_JAR/KSM_FINDSECBUGS_JARS)")

    # SpotBugs needs bytecode, so compile the example first with the same JDK.
    javac = Path(analyzer._config.java_executable).parent / "javac"
    if not javac.exists():
        pytest.skip("javac not found next to the configured java")
    subprocess.run(
        [str(javac), "-d", str(tmp_path), str(_EXAMPLES / "VulnerableSample.java")],
        check=True,
        capture_output=True,
        text=True,
    )

    result = analyzer.scan(tmp_path)

    assert "WEAK_MESSAGE_DIGEST_MD5" in _rule_ids(result)


@pytest.mark.integration
def test_python_bandit_finds_shell_injection():
    analyzer = _try_build_python()
    if analyzer is None:
        pytest.skip("bandit not installed")

    result = analyzer.scan(_EXAMPLES / "vulnerable_sample.py")

    # B602 = subprocess call with shell=True.
    assert "B602" in _rule_ids(result)


@pytest.mark.integration
def test_csharp_roslyn_finds_weak_crypto():
    analyzer = _try_build_csharp()
    if analyzer is None:
        pytest.skip("Roslyn/.NET not configured (KSM_DOTNET_ROOT)")

    result = analyzer.scan(_EXAMPLES / "csharp")

    # CA5351 = do not use broken cryptographic algorithms (MD5).
    assert "CA5351" in _rule_ids(result)


@pytest.mark.integration
def test_javascript_eslint_finds_child_process():
    analyzer = _try_build_javascript()
    if analyzer is None:
        pytest.skip("ESLint not configured (KSM_ESLINT_BIN/KSM_ESLINT_CONFIG)")

    result = analyzer.scan(_EXAMPLES / "javascript")

    assert "security/detect-child-process" in _rule_ids(result)
