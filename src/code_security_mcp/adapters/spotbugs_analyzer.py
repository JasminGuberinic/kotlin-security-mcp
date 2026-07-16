"""JavaAnalyzer: security-analyze compiled Java with SpotBugs + FindSecBugs.

This is the native, security-focused Java counterpart to detekt-for-Kotlin.
SpotBugs is the analysis engine; FindSecBugs is a plugin that adds ~135 security
detectors (crypto misuse, injection, insecure config, framework-specific issues).

Key difference from detekt: SpotBugs analyzes **compiled bytecode**, not source.
So this adapter reads *binaries*. You can point it at:

  - a directory of `.class` files,
  - a `.jar`, or
  - a project/module root — it then locates the build output itself
    (Gradle's `build/classes/...`, Maven's `target/classes`, etc.).

As with detekt, SpotBugs emits SARIF, so we reuse the very same parser.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from code_security_mcp.adapters.process import run_with_timeout
from code_security_mcp.adapters.sarif import parse_sarif_report
from code_security_mcp.domain.models import ScanResult

# Where compiled classes usually live, relative to a project/module root. Checked
# in order; the first ones that actually contain classes are analyzed. Covers the
# common Gradle, Maven, and IntelliJ output layouts.
_BUILD_OUTPUT_SUBDIRS: tuple[str, ...] = (
    "build/classes/java/main",
    "build/classes/kotlin/main",
    "target/classes",
    "out/production/classes",
    "bin/main",
)


@dataclass(frozen=True)
class SpotBugsConfig:
    """Everything the analyzer needs to locate and launch SpotBugs."""

    # Path to the `java` executable (SpotBugs runs on the JVM, like detekt).
    java_executable: Path

    # Path to the SpotBugs engine jar (spotbugs.jar from the distribution).
    spotbugs_jar: Path

    # Security plugin jar(s) — the FindSecBugs plugin.
    plugin_jars: tuple[Path, ...]

    # Analysis effort. "max" finds the most issues at the cost of speed.
    effort: str = "max"

    # Optional dependency jars/dirs for -auxclasspath. Giving SpotBugs the
    # project's dependencies lets it resolve types it would otherwise miss,
    # which improves accuracy. Empty by default (analysis still works without).
    aux_classpath: tuple[Path, ...] = field(default_factory=tuple)


class JavaAnalyzer:
    """A LanguageAnalyzer that delegates to SpotBugs with FindSecBugs."""

    def __init__(self, config: SpotBugsConfig) -> None:
        # Hold the "where is everything" configuration for the whole object.
        self._config = config

    def supports(self, target: Path) -> bool:
        """True when SpotBugs is available AND we can find bytecode to analyze.

        We require the engine jar to exist (so the router skips Java on machines
        without SpotBugs) and at least one class root to be resolvable (so we do
        not claim a Java project that has not been built yet).
        """
        if not self._config.spotbugs_jar.exists():
            return False
        return len(self._resolve_class_roots(target)) > 0

    def scan(self, target: Path) -> ScanResult:
        """Locate the compiled binaries under `target` and analyze them."""
        class_roots = self._resolve_class_roots(target)
        if not class_roots:
            raise RuntimeError(
                f"No compiled Java found under {target}. Build the project first, "
                "or point at a directory of .class files or a .jar."
            )
        with tempfile.TemporaryDirectory() as work_dir:
            report_path = Path(work_dir) / "report.sarif"
            self._run_spotbugs(class_roots, report_path)
            return self._read_report(report_path)

    def _resolve_class_roots(self, target: Path) -> tuple[Path, ...]:
        """Find the bytecode to analyze for `target`.

        The resolution order mirrors what a developer would expect:
          1. a `.class` file or `.jar` given directly,
          2. known build-output directories under a project root,
          3. the directory itself, if it already contains class files anywhere.
        """
        if target.is_file():
            return (target,) if target.suffix in (".class", ".jar") else ()
        if not target.is_dir():
            return ()

        build_outputs = tuple(
            candidate
            for subdir in _BUILD_OUTPUT_SUBDIRS
            if self._contains_classes(candidate := target / subdir)
        )
        if build_outputs:
            return build_outputs

        # Fall back to the directory itself if classes live somewhere inside it
        # (e.g. the caller already pointed at a compiled-classes folder).
        if self._contains_classes(target):
            return (target,)
        return ()

    def _contains_classes(self, directory: Path) -> bool:
        """True if `directory` exists and holds at least one `.class` file."""
        if not directory.is_dir():
            return False
        return next(directory.rglob("*.class"), None) is not None

    def _run_spotbugs(self, class_roots: tuple[Path, ...], report_path: Path) -> None:
        """Launch the SpotBugs subprocess over the resolved class roots.

        SpotBugs' exit status reflects whether bugs were found, so — as with
        detekt — we ignore the return code and judge success by whether a report
        was written.
        """
        command = self._build_command(class_roots, report_path)
        run_with_timeout(command)

    def _build_command(
        self, class_roots: tuple[Path, ...], report_path: Path
    ) -> list[str]:
        """Assemble the `java -jar spotbugs.jar -textui ...` argument list."""
        command = [
            str(self._config.java_executable),
            "-jar",
            str(self._config.spotbugs_jar),
            "-textui",
            f"-effort:{self._config.effort}",
            "-pluginList",
            self._joined(self._config.plugin_jars),
            # Report only SECURITY-category bugs (FindSecBugs' findings). Without
            # this, SpotBugs also emits correctness/style/malicious-code patterns
            # (e.g. EI_EXPOSE_REP) — noise for a security tool. This is the Java
            # equivalent of detekt's --disable-default-rulesets.
            "-bugCategories",
            "SECURITY",
            "-sarif",
            "-output",
            str(report_path),
        ]
        # Dependencies help SpotBugs resolve types, when the caller supplies them.
        if self._config.aux_classpath:
            command += ["-auxclasspath", self._joined(self._config.aux_classpath)]
        # The binaries to analyze come last; SpotBugs accepts several.
        command += [str(root) for root in class_roots]
        return command

    def _joined(self, paths: tuple[Path, ...]) -> str:
        """Join paths with the platform separator SpotBugs expects (':' here)."""
        return ":".join(str(path) for path in paths)

    def _read_report(self, report_path: Path) -> ScanResult:
        """Load and parse the SARIF report, reusing the shared parser."""
        if not report_path.exists():
            raise RuntimeError(
                "SpotBugs did not produce a report; check the Java, SpotBugs jar, "
                "and plugin jar paths."
            )
        report = json.loads(report_path.read_text(encoding="utf-8"))
        return parse_sarif_report(report)
