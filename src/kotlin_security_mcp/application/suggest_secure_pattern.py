"""The SuggestSecurePatternUseCase: answer "how do I do X securely?".

Like ScanCodeUseCase, it depends only on a domain port (SecurePatternCatalog),
so the curated catalog we ship today can later become anything without touching
this layer or the MCP server.
"""

from __future__ import annotations

from kotlin_security_mcp.domain.patterns import SecurePattern
from kotlin_security_mcp.domain.ports import SecurePatternCatalog


class SuggestSecurePatternUseCase:
    """Recommend secure code patterns for a described task."""

    def __init__(self, catalog: SecurePatternCatalog) -> None:
        # The source of recipes, injected so tests can supply a tiny catalog.
        self._catalog = catalog

    def execute(self, framework: str | None, task: str) -> tuple[SecurePattern, ...]:
        """Look up patterns for `task`, optionally narrowed to `framework`.

        We treat a blank task as a usage error: without something to search for
        there is no meaningful recommendation to give.
        """
        if not task.strip():
            raise ValueError("A non-empty task description is required.")
        return self._catalog.find(framework, task)
