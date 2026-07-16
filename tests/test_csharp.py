"""Tests for the C# (Roslyn) analyzer wiring — no .NET SDK required."""

from pathlib import Path

from code_security_mcp.adapters.roslyn_analyzer import (
    CSharpAnalyzer,
    RoslynConfig,
    _is_security_analyzer_rule,
)


def _config_with_sdk(tmp_path, **overrides) -> RoslynConfig:
    """A RoslynConfig whose `dotnet` executable exists (for supports()/env tests)."""
    sdk = tmp_path / "sdk"
    sdk.mkdir()
    (sdk / "dotnet").write_text("")  # a fake dotnet binary that exists
    base = dict(dotnet_root=sdk)
    base.update(overrides)
    return RoslynConfig(**base)


def test_security_rules_are_recognized():
    # .NET security analyzer rules (CA####) are kept.
    assert _is_security_analyzer_rule("CA5351") is True
    # Compiler diagnostics (CS####) and third-party analyzers are dropped.
    assert _is_security_analyzer_rule("CS5001") is False
    assert _is_security_analyzer_rule("xUnit2013") is False
    assert _is_security_analyzer_rule("SA1200") is False


def test_unsupported_when_sdk_missing(tmp_path):
    config = RoslynConfig(dotnet_root=tmp_path / "no-sdk")
    (tmp_path / "app.csproj").write_text("<Project/>")
    assert CSharpAnalyzer(config).supports(tmp_path) is False


def test_resolves_projects_and_skips_tests(tmp_path):
    (tmp_path / "Web").mkdir()
    (tmp_path / "Web" / "Web.csproj").write_text("<Project/>")
    (tmp_path / "UnitTests").mkdir()
    (tmp_path / "UnitTests" / "UnitTests.csproj").write_text("<Project/>")
    analyzer = CSharpAnalyzer(_config_with_sdk(tmp_path))

    projects = analyzer._resolve_projects(tmp_path)

    names = {p.name for p in projects}
    assert names == {"Web.csproj"}  # the test project is skipped
    assert analyzer.supports(tmp_path) is True


def test_loose_cs_file_is_not_a_project(tmp_path):
    (tmp_path / "Program.cs").write_text("class C {}")
    analyzer = CSharpAnalyzer(_config_with_sdk(tmp_path))
    # A bare .cs file (no .csproj) is not buildable on its own → unsupported.
    assert analyzer.supports(tmp_path) is False


def test_build_command_enables_security_only_and_sarif(tmp_path):
    analyzer = CSharpAnalyzer(_config_with_sdk(tmp_path))
    project = tmp_path / "app.csproj"

    command = analyzer._build_command(project, tmp_path / "out.sarif")

    assert command[1] == "build"
    assert "-p:AnalysisMode=None" in command
    assert "-p:AnalysisModeSecurity=All" in command
    assert any(arg.startswith("-p:ErrorLog=") and "version=2.1" in arg for arg in command)


def test_subprocess_env_is_isolated(tmp_path):
    config = _config_with_sdk(
        tmp_path, nuget_packages=tmp_path / "nuget", cli_home=tmp_path / "home"
    )
    env = CSharpAnalyzer(config)._subprocess_env()

    assert env["DOTNET_ROOT"] == str(config.dotnet_root)
    assert env["DOTNET_CLI_TELEMETRY_OPTOUT"] == "1"
    assert env["NUGET_PACKAGES"] == str(tmp_path / "nuget")
    assert env["DOTNET_CLI_HOME"] == str(tmp_path / "home")
