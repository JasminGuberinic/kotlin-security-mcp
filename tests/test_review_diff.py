"""Tests for the unified-diff parser and the ReviewDiffUseCase."""

from pathlib import Path

from code_security_mcp.adapters.diff import parse_unified_diff
from code_security_mcp.application.review_diff import ReviewDiffUseCase
from code_security_mcp.domain.models import Finding, ScanResult, Severity

# A small but realistic git-style unified diff adding two lines to one file.
_DIFF = """\
diff --git a/src/App.kt b/src/App.kt
index 1111111..2222222 100644
--- a/src/App.kt
+++ b/src/App.kt
@@ -10,3 +10,5 @@ class App {
     val a = 1
+    val b = SSLContext.getInstance("SSL")
     val c = 3
+    val d = 4
"""


def test_parser_records_only_added_lines():
    added = parse_unified_diff(_DIFF)

    # The file path has its "b/" prefix stripped.
    assert set(added.keys()) == {"src/App.kt"}
    # Two "+" lines were added, at new-file lines 11 and 13
    # (10=context, 11=added, 12=context, 13=added).
    assert added["src/App.kt"] == {11, 13}


class _FakeAnalyzer:
    """Returns findings on fixed lines regardless of the file it is given."""

    def __init__(self, findings: tuple[Finding, ...]) -> None:
        self._findings = findings

    def scan(self, target: Path) -> ScanResult:
        return ScanResult(findings=self._findings)


def test_use_case_keeps_only_findings_on_added_lines(tmp_path):
    # A real file must exist for the use case to scan it.
    changed = tmp_path / "App.kt"
    changed.write_text("// placeholder\n")
    diff = _DIFF.replace("src/App.kt", str(changed))

    # One finding on an added line (11), one on an untouched line (12).
    on_added = Finding("R1", "bad", str(changed), 11, Severity.ERROR)
    on_untouched = Finding("R2", "old", str(changed), 12, Severity.WARNING)
    use_case = ReviewDiffUseCase(_FakeAnalyzer((on_added, on_untouched)))

    result = use_case.execute(diff)

    # Only the finding introduced by the diff survives.
    assert result.count == 1
    assert result.findings[0].rule_id == "R1"
