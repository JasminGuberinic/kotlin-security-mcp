"""JavaScriptAnalyzer: security-analyze JS/TS with ESLint + eslint-plugin-security.

ESLint is the native JavaScript/TypeScript linter; eslint-plugin-security adds
the security rules (child_process, eval, unsafe regex, non-literal fs paths, …).
That combination is the JS/TS counterpart to detekt-for-Kotlin or Bandit-for-
Python: a native, security-focused analyzer, not a generic multi-language one.

It runs on source (no build). Two ESLint details this adapter handles:
  - we pass our own flat config (`--config` + `--no-config-lookup`) so the
    user's own ESLint setup does not change what we check, and
  - ESLint only lints files under its working directory, so we run it *from* the
    target's directory.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from code_security_mcp.adapters.eslint_report import parse_eslint_report
from code_security_mcp.adapters.language import target_has_extension
from code_security_mcp.adapters.process import run_with_timeout
from code_security_mcp.domain.models import ScanResult

# The file types we route to ESLint.
_JS_TS_EXTENSIONS: tuple[str, ...] = (
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
)


@dataclass(frozen=True)
class EslintConfig:
    """Where the ESLint CLI and our security flat-config live."""

    # Path to the ESLint executable (e.g. node_modules/.bin/eslint).
    eslint_executable: Path

    # Path to our flat config that enables only the security rules. It must sit
    # next to the node_modules that hold eslint-plugin-security so ESLint can
    # resolve the plugin.
    config_file: Path


class JavaScriptAnalyzer:
    """A LanguageAnalyzer that delegates to ESLint with the security plugin."""

    def __init__(self, config: EslintConfig) -> None:
        self._config = config

    def supports(self, target: Path) -> bool:
        """True when ESLint is available AND the target is (or contains) JS/TS."""
        if not self._config.eslint_executable.exists():
            return False
        return target_has_extension(target, _JS_TS_EXTENSIONS)

    def scan(self, target: Path) -> ScanResult:
        """Run ESLint over `target` and return the findings it reports."""
        working_dir, lint_path = self._working_dir_and_path(target)
        # ESLint exits non-zero when it finds problems; run_with_timeout never
        # raises on that, only on a genuine timeout.
        completed = run_with_timeout(
            self._build_command(lint_path), cwd=str(working_dir)
        )
        return self._parse_output(completed.stdout, completed.stderr)

    def _working_dir_and_path(self, target: Path) -> tuple[Path, str]:
        """Decide where to run ESLint and what to lint.

        ESLint ignores files outside its working directory, so we run it inside
        the target directory (linting ".") or inside a file's parent (linting
        the file by name).
        """
        if target.is_dir():
            return target, "."
        return target.parent, target.name

    def _build_command(self, lint_path: str) -> list[str]:
        """Assemble the `eslint --config <ours> -f json <path>` argument list.

        `--no-config-lookup` stops ESLint from picking up the *project's* config,
        so we always apply exactly our security rules.
        """
        return [
            str(self._config.eslint_executable),
            "--no-config-lookup",
            "--config",
            str(self._config.config_file),
            "-f",
            "json",
            lint_path,
        ]

    def _parse_output(self, stdout: str, stderr: str) -> ScanResult:
        """Parse ESLint's JSON stdout into a ScanResult.

        ESLint prints its JSON report to stdout even when problems are found. If
        the output is not valid JSON, ESLint failed to run (bad config, missing
        plugin), so we surface that with its stderr.
        """
        try:
            report = json.loads(stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"eslint did not return JSON; it likely failed to run.\n{stderr.strip()}"
            ) from error
        return parse_eslint_report(report)
