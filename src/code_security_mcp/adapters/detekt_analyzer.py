"""DetektAnalyzer: run the detekt CLI with our ruleset and return Findings.

This is the concrete implementation of the SecurityAnalyzer port for Kotlin.
It shells out to detekt as a JVM subprocess, asks it to write a SARIF report,
then hands that report to `parse_sarif_report` (which we already unit-test in
isolation). This file owns everything JVM-specific; nothing above it does.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from code_security_mcp.adapters.language import target_has_extension
from code_security_mcp.adapters.process import run_with_timeout
from code_security_mcp.adapters.sarif import parse_sarif_report
from code_security_mcp.domain.models import ScanResult

# The file types detekt understands: Kotlin source and Kotlin scripts.
_KOTLIN_EXTENSIONS: tuple[str, ...] = (".kt", ".kts")


@dataclass(frozen=True)
class DetektConfig:
    """Everything the analyzer needs to locate and launch detekt.

    We pass these in explicitly rather than hard-coding paths, so the same code
    runs on any machine (and so tests can point it at fixtures). Each field is
    the answer to a "where is ...?" question.
    """

    # Path to the `java` executable (Java is not always on PATH on macOS).
    java_executable: Path

    # Path to the detekt command-line jar (the analyzer engine itself).
    detekt_cli_jar: Path

    # Our security ruleset jar(s) — the 216-rule scanner-all plugin.
    plugin_jars: tuple[Path, ...]

    # Optional detekt YAML config; when None we rely on rules being
    # active-by-default (which our scanner is designed to be).
    config_file: Path | None = None


class DetektAnalyzer:
    """A SecurityAnalyzer that delegates to the detekt CLI.

    It satisfies the SecurityAnalyzer port structurally: it exposes a `scan`
    method with the right shape, so the use case accepts it without either side
    importing the other beyond the shared domain models.
    """

    def __init__(self, config: DetektConfig) -> None:
        # Hold the "where is everything" configuration for the whole object.
        self._config = config

    def supports(self, target: Path) -> bool:
        """True when the target is, or contains, Kotlin source."""
        return target_has_extension(target, _KOTLIN_EXTENSIONS)

    def scan(self, target: Path) -> ScanResult:
        """Run detekt over `target` and return the findings it reports.

        We write the SARIF report to a throwaway temp file, run detekt, then
        parse whatever it produced. The temp file is cleaned up automatically.
        """
        with tempfile.TemporaryDirectory() as work_dir:
            report_path = Path(work_dir) / "report.sarif"
            self._run_detekt(target, report_path)
            return self._read_report(report_path)

    def _run_detekt(self, target: Path, report_path: Path) -> None:
        """Launch the detekt subprocess to analyze `target` into `report_path`.

        Important detekt behavior: when it *finds* issues it exits with a
        non-zero status. That is a normal outcome for us, not a failure — so we
        do NOT check the return code here. Instead, `_read_report` decides
        success by whether a readable SARIF report was actually produced.
        """
        command = self._build_command(target, report_path)
        run_with_timeout(command)

    def _build_command(self, target: Path, report_path: Path) -> list[str]:
        """Assemble the exact `java -jar detekt-cli ...` argument list.

        Building the command as a list (not a shell string) means arguments are
        passed verbatim — no quoting bugs, no shell injection through file paths.
        """
        command: list[str] = [
            str(self._config.java_executable),
            "-jar",
            str(self._config.detekt_cli_jar),
            "--input",
            str(target),
            "--plugins",
            self._joined_plugin_jars(),
            # Turn OFF detekt's built-in rule sets (style, complexity, naming, ...).
            # We are a *security* tool: the agent should get security findings only,
            # not "TooManyFunctions" or "MagicNumber" noise. This leaves just the
            # rules our plugin jars contribute.
            "--disable-default-rulesets",
            "--report",
            f"sarif:{report_path}",
        ]
        # Only add a --config flag when the caller actually supplied one.
        if self._config.config_file is not None:
            command += ["--config", str(self._config.config_file)]
        return command

    def _joined_plugin_jars(self) -> str:
        """detekt expects multiple plugin jars as one comma-separated string."""
        return ",".join(str(jar) for jar in self._config.plugin_jars)

    def _read_report(self, report_path: Path) -> ScanResult:
        """Load and parse the SARIF report detekt was asked to write.

        If the report is missing, detekt failed to run at all (bad paths, no
        Java, ...) — so we raise a clear error rather than silently pretending
        the code was clean.
        """
        if not report_path.exists():
            raise RuntimeError(
                "detekt did not produce a report; check the Java, CLI jar, and "
                "plugin jar paths in DetektConfig."
            )
        report = json.loads(report_path.read_text(encoding="utf-8"))
        return parse_sarif_report(report)
