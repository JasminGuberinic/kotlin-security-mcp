"""The MCP server: the outermost, driving adapter.

This is where the Model Context Protocol meets our use case. It does three
things and nothing more:

  1. Composition root  — read configuration and wire the concrete objects
                         (DetektAnalyzer -> ScanCodeUseCase) together, once.
  2. Tool surface      — expose `security_scan` to the AI agent.
  3. Presentation      — turn domain Findings into a plain, JSON-friendly shape
                         the agent can read.

No security logic lives here. If we deleted MCP tomorrow and drove the use case
from a CLI instead, only this file would change.
"""

from __future__ import annotations

import os
from pathlib import Path

from code_security_mcp.adapters.bandit_analyzer import PythonAnalyzer
from code_security_mcp.adapters.detekt_analyzer import DetektAnalyzer, DetektConfig
from code_security_mcp.adapters.eslint_analyzer import EslintConfig, JavaScriptAnalyzer
from code_security_mcp.adapters.pattern_catalog import InMemorySecurePatternCatalog
from code_security_mcp.adapters.roslyn_analyzer import CSharpAnalyzer, RoslynConfig
from code_security_mcp.adapters.routing_analyzer import RoutingAnalyzer
from code_security_mcp.adapters.spotbugs_analyzer import JavaAnalyzer, SpotBugsConfig
from code_security_mcp.domain.ports import LanguageAnalyzer
from code_security_mcp.application.review_diff import ReviewDiffUseCase
from code_security_mcp.application.scan_code import ScanCodeUseCase
from code_security_mcp.application.suggest_secure_pattern import (
    SuggestSecurePatternUseCase,
)
from code_security_mcp.domain.models import Finding
from code_security_mcp.domain.patterns import SecurePattern

# The SDK renamed FastMCP -> MCPServer. Import the current name, but fall back
# to the old one so the server keeps working on either SDK generation.
try:
    from mcp.server import MCPServer
except ImportError:  # pragma: no cover - depends on installed SDK version
    from mcp.server.fastmcp import FastMCP as MCPServer

# The server instance. The name is what shows up in the client's tool list.
mcp = MCPServer("code-security-mcp")

# Upper bound on findings returned in one response. A scan of a large, messy
# repository can produce thousands of findings; returning them all would bloat
# the agent's context for little gain. We cap the list and flag truncation.
_MAX_FINDINGS = 500


@mcp.tool()
def security_scan(path: str) -> dict:
    """Scan Kotlin/JVM code for security issues using a 216-rule analyzer.

    Point this at a file or directory. It returns every security finding the
    analyzer reports — rule id, message, location, and severity — so the agent
    can fix issues *while writing*, not after.

    Args:
        path: File or directory to scan (absolute, or relative to the project).
    """
    use_case = _build_use_case()
    result = use_case.execute(Path(path))
    return {"target": path, **_findings_payload(result)}


@mcp.tool()
def review_diff(diff: str) -> dict:
    """Security-review a unified diff: flag issues the change *introduces*.

    Paste a unified diff (e.g. the output of `git diff`) after editing Kotlin
    code. Only findings on lines the diff adds are returned, so the agent sees
    exactly what its change is responsible for — a self-check before committing.

    Args:
        diff: A unified diff whose file paths are relative to the current
            project directory.
    """
    use_case = _build_review_diff_use_case()
    result = use_case.execute(diff)
    return _findings_payload(result)


@mcp.tool()
def secure_pattern(task: str, framework: str = "") -> dict:
    """Get the secure way to do a risky Kotlin/JVM task, before writing it.

    Ask "how do I do X securely" and get vetted before/after snippets and the
    reason — so the agent writes the safe version the first time.

    Args:
        task: What you want to do, e.g. "create a session cookie", "store a JWT
            secret", "configure CORS", "read the current user in reactive code".
        framework: Optional stack to narrow results, e.g. "spring-webflux",
            "ktor", "vertx". Leave empty to search all frameworks.
    """
    use_case = _build_pattern_use_case()
    patterns = use_case.execute(framework or None, task)
    return {
        "task": task,
        "framework": framework or "any",
        "count": len(patterns),
        "patterns": [_pattern_to_dict(pattern) for pattern in patterns],
    }


def _build_use_case() -> ScanCodeUseCase:
    """Composition root for the scan feature: wire the analyzer to the use case."""
    return ScanCodeUseCase(_build_analyzer())


def _build_review_diff_use_case() -> ReviewDiffUseCase:
    """Composition root for the diff-review feature (same analyzer, narrowed)."""
    return ReviewDiffUseCase(_build_analyzer())


def _build_analyzer() -> RoutingAnalyzer:
    """Build the multi-language analyzer from environment configuration.

    We enable each specialist only if its tools are configured, then route
    between them. This is the single place allowed to name concrete analyzers;
    everything downstream sees only ports. Adding a language (e.g. C#/Roslyn)
    means adding one more `_try_build_*` here — nothing else changes.
    """
    analyzers: list[LanguageAnalyzer] = []

    detekt = _try_build_detekt()  # Kotlin
    if detekt is not None:
        analyzers.append(detekt)

    java = _try_build_java()  # Java (SpotBugs + FindSecBugs)
    if java is not None:
        analyzers.append(java)

    python = _try_build_python()  # Python (Bandit)
    if python is not None:
        analyzers.append(python)

    csharp = _try_build_csharp()  # C# (Roslyn security analyzers)
    if csharp is not None:
        analyzers.append(csharp)

    javascript = _try_build_javascript()  # JS/TS (ESLint + eslint-plugin-security)
    if javascript is not None:
        analyzers.append(javascript)

    if not analyzers:
        raise RuntimeError(
            "No analyzer configured. Configure detekt (KSM_JAVA, "
            "KSM_DETEKT_CLI_JAR, KSM_PLUGIN_JARS), SpotBugs (KSM_JAVA, "
            "KSM_SPOTBUGS_JAR, KSM_FINDSECBUGS_JARS), Roslyn (KSM_DOTNET_ROOT), "
            "and/or ESLint (KSM_ESLINT_BIN, KSM_ESLINT_CONFIG), and/or install bandit."
        )
    return RoutingAnalyzer(tuple(analyzers))


def _try_build_detekt() -> DetektAnalyzer | None:
    """Build the Kotlin analyzer, or None if detekt is not configured."""
    if not _all_env_present("KSM_JAVA", "KSM_DETEKT_CLI_JAR", "KSM_PLUGIN_JARS"):
        return None
    config = DetektConfig(
        java_executable=Path(_required_env("KSM_JAVA")),
        detekt_cli_jar=Path(_required_env("KSM_DETEKT_CLI_JAR")),
        plugin_jars=_paths_from_env("KSM_PLUGIN_JARS"),
        config_file=_optional_path_from_env("KSM_DETEKT_CONFIG"),
    )
    return DetektAnalyzer(config)


def _try_build_java() -> JavaAnalyzer | None:
    """Build the Java analyzer, or None if SpotBugs is not configured."""
    if not _all_env_present("KSM_JAVA", "KSM_SPOTBUGS_JAR", "KSM_FINDSECBUGS_JARS"):
        return None
    config = SpotBugsConfig(
        java_executable=Path(_required_env("KSM_JAVA")),
        spotbugs_jar=Path(_required_env("KSM_SPOTBUGS_JAR")),
        plugin_jars=_paths_from_env("KSM_FINDSECBUGS_JARS"),
        aux_classpath=_optional_paths_from_env("KSM_JAVA_AUXCLASSPATH"),
    )
    return JavaAnalyzer(config)


def _try_build_python() -> PythonAnalyzer | None:
    """Build the Python analyzer, or None if Bandit is not installed.

    Python needs no environment variables — if `bandit` is importable/on PATH,
    the analyzer enables itself; otherwise it is simply left out.
    """
    analyzer = PythonAnalyzer()
    return analyzer if analyzer.is_available() else None


def _try_build_csharp() -> CSharpAnalyzer | None:
    """Build the C# analyzer, or None if the .NET SDK is not configured."""
    if not _all_env_present("KSM_DOTNET_ROOT"):
        return None
    config = RoslynConfig(
        dotnet_root=Path(_required_env("KSM_DOTNET_ROOT")),
        nuget_packages=_optional_path_from_env("KSM_NUGET_PACKAGES"),
        cli_home=_optional_path_from_env("KSM_DOTNET_CLI_HOME"),
    )
    return CSharpAnalyzer(config)


def _try_build_javascript() -> JavaScriptAnalyzer | None:
    """Build the JS/TS analyzer, or None if ESLint is not configured."""
    if not _all_env_present("KSM_ESLINT_BIN", "KSM_ESLINT_CONFIG"):
        return None
    config = EslintConfig(
        eslint_executable=Path(_required_env("KSM_ESLINT_BIN")),
        config_file=Path(_required_env("KSM_ESLINT_CONFIG")),
    )
    return JavaScriptAnalyzer(config)


def _build_pattern_use_case() -> SuggestSecurePatternUseCase:
    """Composition root for the secure-pattern feature.

    The catalog is self-contained (no external tools), so unlike the scanner
    this needs no configuration — just wire the in-memory catalog to the use case.
    """
    catalog = InMemorySecurePatternCatalog()
    return SuggestSecurePatternUseCase(catalog)


def _findings_payload(result) -> dict:
    """Shape a ScanResult for a tool response, capping the findings list.

    `count` is always the true total; `findings` is at most `_MAX_FINDINGS`, and
    `truncated` tells the agent when it is seeing only a prefix.
    """
    shown = result.findings[:_MAX_FINDINGS]
    return {
        "count": result.count,
        "truncated": result.count > _MAX_FINDINGS,
        "findings": [_finding_to_dict(finding) for finding in shown],
    }


def _finding_to_dict(finding: Finding) -> dict:
    """Flatten a domain Finding into a JSON-serializable dict for the agent.

    Presentation lives here, at the edge, so the domain never has to know how
    it will be displayed or transported.
    """
    return {
        "rule_id": finding.rule_id,
        "message": finding.message,
        "file": finding.file_path,
        "line": finding.line,
        "severity": finding.severity.value,
        "cwe": finding.cwe,
        "remediation": finding.remediation,
    }


def _pattern_to_dict(pattern: SecurePattern) -> dict:
    """Flatten a SecurePattern into a JSON-serializable dict for the agent."""
    return {
        "framework": pattern.framework,
        "task": pattern.task,
        "insecure_example": pattern.insecure_example,
        "secure_example": pattern.secure_example,
        "explanation": pattern.explanation,
        "cwe": pattern.cwe,
    }


def _required_env(name: str) -> str:
    """Read an environment variable, failing clearly if it is missing.

    A missing path is a setup mistake we want surfaced immediately, with the
    exact variable name, rather than a mysterious failure deep inside detekt.
    """
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _all_env_present(*names: str) -> bool:
    """True only if every named environment variable is set and non-empty.

    Used to decide whether a given analyzer is configured on this machine.
    """
    return all(os.environ.get(name) for name in names)


def _paths_from_env(name: str) -> tuple[Path, ...]:
    """Read a comma-separated list of paths (e.g. multiple plugin jars)."""
    raw = _required_env(name)
    return tuple(Path(part.strip()) for part in raw.split(",") if part.strip())


def _optional_path_from_env(name: str) -> Path | None:
    """Read an optional path; return None when the variable is unset."""
    value = os.environ.get(name)
    return Path(value) if value else None


def _optional_paths_from_env(name: str) -> tuple[Path, ...]:
    """Read an optional comma-separated path list; empty tuple when unset."""
    value = os.environ.get(name)
    if not value:
        return ()
    return tuple(Path(part.strip()) for part in value.split(",") if part.strip())


def main() -> None:
    """Console entry point (see pyproject `[project.scripts]`).

    `mcp.run()` blocks for the whole server lifetime and speaks stdio by
    default — exactly what a local MCP client (Claude Code, Cursor) expects.
    """
    mcp.run()


if __name__ == "__main__":
    main()
