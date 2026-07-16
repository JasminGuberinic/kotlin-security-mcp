"""CSharpAnalyzer: security-analyze C# with the built-in Roslyn analyzers.

The .NET SDK ships Roslyn security analyzers (the CA3xxx injection/ASP.NET and
CA5xxx crypto/configuration rules). We run them by building the project with
`AnalysisMode=None` + `AnalysisModeSecurity=All` — the security equivalent of
detekt's `--disable-default-rulesets` — and emitting a SARIF report via MSBuild's
`ErrorLog` property. That report flows through the very same SARIF parser.

Two things make this the robust choice on any machine:
  - it uses the SDK's own MSBuild (no external tool / version mismatch), and
  - it does not modify the user's project (all analyzer settings are passed on
    the command line).

Like SpotBugs for Java, Roslyn needs a *buildable* project — point it at a
`.sln`, a `.csproj`, or a directory containing one.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from code_security_mcp.adapters.process import run_with_timeout
from code_security_mcp.adapters.sarif import parse_sarif_report
from code_security_mcp.domain.models import ScanResult

# The project/solution files that anchor a C# build.
_CSHARP_PROJECT_EXTENSIONS: tuple[str, ...] = (".sln", ".csproj")


@dataclass(frozen=True)
class RoslynConfig:
    """Where the .NET SDK lives and where to keep its state.

    We keep NuGet packages and the CLI's home inside our own cache so a scan
    never writes to the user's global `~/.nuget` or `~/.dotnet`.
    """

    # Root of the .NET SDK install (contains the `dotnet` executable).
    dotnet_root: Path

    # Optional: where to restore NuGet packages (isolation). None = SDK default.
    nuget_packages: Path | None = None

    # Optional: the dotnet CLI's home directory (isolation). None = SDK default.
    cli_home: Path | None = None

    @property
    def dotnet_executable(self) -> Path:
        """The `dotnet` binary inside the SDK root."""
        return self.dotnet_root / "dotnet"


class CSharpAnalyzer:
    """A LanguageAnalyzer that delegates to Roslyn via `dotnet build`."""

    def __init__(self, config: RoslynConfig) -> None:
        self._config = config

    def supports(self, target: Path) -> bool:
        """True when the SDK is present AND a C# project/solution is resolvable."""
        if not self._config.dotnet_executable.exists():
            return False
        return self._resolve_project(target) is not None

    def scan(self, target: Path) -> ScanResult:
        """Build the resolved project with security analyzers and read the SARIF."""
        project = self._resolve_project(target)
        if project is None:
            raise RuntimeError(
                f"No .sln or .csproj found under {target}; C# analysis needs a "
                "buildable project."
            )
        with tempfile.TemporaryDirectory() as work_dir:
            report_path = Path(work_dir) / "report.sarif"
            self._run_build(project, report_path)
            return self._read_report(report_path)

    def _resolve_project(self, target: Path) -> Path | None:
        """Find the project/solution to build for `target`.

        A solution is preferred (it covers every project); otherwise the first
        `.csproj`. A single project/solution file is used as-is.
        """
        if target.is_file():
            return target if target.suffix in _CSHARP_PROJECT_EXTENSIONS else None
        if not target.is_dir():
            return None
        return next(target.rglob("*.sln"), None) or next(target.rglob("*.csproj"), None)

    def _run_build(self, project: Path, report_path: Path) -> None:
        """Run `dotnet build` with security analyzers, writing SARIF.

        A build can fail for reasons unrelated to security (a missing Main, a
        broken reference), yet the analyzers still emit their report — so, as
        with our other analyzers, we ignore the exit code and rely on the report.
        """
        command = self._build_command(project, report_path)
        run_with_timeout(command, env=self._subprocess_env())

    def _build_command(self, project: Path, report_path: Path) -> list[str]:
        """Assemble the `dotnet build ... -p:ErrorLog=...` argument list."""
        return [
            str(self._config.dotnet_executable),
            "build",
            str(project),
            "-p:EnableNETAnalyzers=true",
            # Security equivalent of detekt's --disable-default-rulesets:
            # turn every category off, then re-enable only Security.
            "-p:AnalysisMode=None",
            "-p:AnalysisModeSecurity=All",
            # %2C is MSBuild's escaped comma; it selects SARIF v2.1 (a literal
            # comma is mis-parsed and silently falls back to the older SARIF v1).
            f"-p:ErrorLog={report_path}%2Cversion=2.1",
            "--nologo",
        ]

    def _subprocess_env(self) -> dict[str, str]:
        """Build the environment for the dotnet subprocess.

        We start from the current environment and force the .NET location plus
        privacy/isolation settings, so a scan is self-contained and quiet.
        """
        env = dict(os.environ)
        env["DOTNET_ROOT"] = str(self._config.dotnet_root)
        env["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
        env["DOTNET_NOLOGO"] = "1"
        if self._config.nuget_packages is not None:
            env["NUGET_PACKAGES"] = str(self._config.nuget_packages)
        if self._config.cli_home is not None:
            env["DOTNET_CLI_HOME"] = str(self._config.cli_home)
        return env

    def _read_report(self, report_path: Path) -> ScanResult:
        """Load and parse the SARIF report, keeping only security findings.

        A build emits both analyzer diagnostics (the CA security rules we want)
        and plain compiler diagnostics (CSxxxx — e.g. "no Main method"). The
        latter are build noise, not security issues, so we drop them.
        """
        if not report_path.exists():
            raise RuntimeError(
                "dotnet build did not produce a report; check the .NET SDK path "
                "and that the project can be restored."
            )
        report = json.loads(report_path.read_text(encoding="utf-8"))
        parsed = parse_sarif_report(report)
        findings = tuple(
            finding
            for finding in parsed.findings
            if not _is_compiler_diagnostic(finding.rule_id)
        )
        return ScanResult(findings=findings)


def _is_compiler_diagnostic(rule_id: str) -> bool:
    """True for C# compiler diagnostics like "CS5001" (not analyzer findings)."""
    return rule_id.startswith("CS") and rule_id[2:].isdigit()
