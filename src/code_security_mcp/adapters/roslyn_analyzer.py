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
        """True when the SDK is present AND at least one C# project is resolvable."""
        if not self._config.dotnet_executable.exists():
            return False
        return len(self._resolve_projects(target)) > 0

    def scan(self, target: Path) -> ScanResult:
        """Build each resolved project with security analyzers, merge the SARIFs.

        We build project-by-project rather than the whole solution because a
        solution build makes every project write to the *same* ErrorLog file,
        so only the last one survives. Per-project builds give each its own
        report, which we then merge.
        """
        projects = self._resolve_projects(target)
        if not projects:
            raise RuntimeError(
                f"No .csproj found under {target}; C# analysis needs a buildable "
                "project."
            )
        findings: list = []
        with tempfile.TemporaryDirectory() as work_dir:
            for index, project in enumerate(projects):
                report_path = Path(work_dir) / f"report-{index}.sarif"
                self._run_build(project, report_path)
                if report_path.exists():
                    findings.extend(self._read_report(report_path).findings)
        return ScanResult(findings=tuple(findings))

    def _resolve_projects(self, target: Path) -> tuple[Path, ...]:
        """Find the buildable C# projects for `target`, excluding test projects.

        A `.csproj` is used as-is; a `.sln` is expanded to its projects; a
        directory contributes every `.csproj` under it. Test projects are skipped
        — their analyzer packages (xUnit, etc.) add non-security diagnostics and
        they are not the code we are securing.
        """
        if target.is_file():
            if target.suffix == ".csproj":
                return (target,)
            if target.suffix == ".sln":
                return self._projects_in_solution(target)
            return ()
        if not target.is_dir():
            return ()
        found = tuple(target.rglob("*.csproj"))
        return tuple(p for p in found if not self._is_test_project(p))

    def _projects_in_solution(self, solution: Path) -> tuple[Path, ...]:
        """Extract the .csproj paths listed in a .sln file (skipping test ones)."""
        projects: list[Path] = []
        for line in solution.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.startswith("Project(") or ".csproj" not in line:
                continue
            fields = line.split(",")
            if len(fields) < 2:
                continue
            relative = fields[1].strip().strip('"').replace("\\", "/")
            candidate = (solution.parent / relative).resolve()
            if candidate.exists() and not self._is_test_project(candidate):
                projects.append(candidate)
        return tuple(projects)

    def _is_test_project(self, project: Path) -> bool:
        """Heuristic: a project whose file name mentions 'test' is a test project."""
        return "test" in project.name.lower()

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

        A build emits many diagnostic kinds: the .NET security analyzer rules we
        want (CA2100/CA3xxx/CA5xxx), plain compiler diagnostics (CSxxxx), and any
        third-party analyzers a project references (xUnit's xUnit####, StyleCop's
        SA####, …). Since we enabled only the security category, we keep just the
        CA-prefixed rules and drop everything else as noise.
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
            if _is_security_analyzer_rule(finding.rule_id)
        )
        return ScanResult(findings=findings)


def _is_security_analyzer_rule(rule_id: str) -> bool:
    """True for a .NET analyzer rule like "CA5351".

    With AnalysisMode=None + AnalysisModeSecurity=All, the only CA rules that
    fire are security ones — so a CA#### id is exactly what we want to keep,
    while compiler (CS) and third-party (xUnit/StyleCop) diagnostics are dropped.
    """
    return rule_id.startswith("CA") and rule_id[2:].isdigit()
