"""The ReviewDiffUseCase: security-check only what a change introduced.

An agent that just edited some files can paste the diff and ask "did I add any
security problems?". We scan each changed file and keep only the findings that
land on lines the diff *added* — so pre-existing issues elsewhere in the file do
not drown out the ones the change is responsible for.
"""

from __future__ import annotations

from pathlib import Path

from code_security_mcp.adapters.diff import parse_unified_diff
from code_security_mcp.domain.models import Finding, ScanResult
from code_security_mcp.domain.ports import SecurityAnalyzer


class ReviewDiffUseCase:
    """Report security findings introduced by a unified diff."""

    def __init__(self, analyzer: SecurityAnalyzer) -> None:
        # Same analyzer the plain scan uses; we just narrow the results to the diff.
        self._analyzer = analyzer

    def execute(self, diff_text: str) -> ScanResult:
        """Scan each changed file and keep findings on added lines only."""
        added_lines_by_file = parse_unified_diff(diff_text)

        introduced: list[Finding] = []
        for file_path, added_lines in added_lines_by_file.items():
            introduced.extend(self._findings_on_added_lines(file_path, added_lines))
        return ScanResult(findings=tuple(introduced))

    def _findings_on_added_lines(
        self, file_path: str, added_lines: set[int]
    ) -> list[Finding]:
        """Scan one changed file, returning only findings on its added lines.

        We skip files that are not present on disk (e.g. deleted, or a diff for
        code that was never written), since there is nothing to analyze there.
        """
        target = Path(file_path)
        if not target.is_file():
            return []
        result = self._analyzer.scan(target)
        return [finding for finding in result.findings if finding.line in added_lines]
