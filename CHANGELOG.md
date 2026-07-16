# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (continued)
- **Integration tests** (`pytest -m integration`): run the real analyzers
  (detekt, SpotBugs, Bandit, Roslyn, ESLint) over the `examples/` fixtures and
  assert the expected findings. They self-skip when a tool is not configured, so
  the default (hermetic) suite and CI stay fast and green.
- **One-command setup** (`scripts/setup.sh`): downloads every analyzer into an
  isolated cache (Kotlin ruleset + detekt from Maven Central/GitHub, SpotBugs +
  FindSecBugs; optional isolated .NET SDK and ESLint) and prints the
  `claude mcp add` command. Nothing global is modified.
- **JavaScript/TypeScript support** via a `JavaScriptAnalyzer` adapter backed by
  ESLint + eslint-plugin-security (native, source-based). It applies its own flat
  security config (`--no-config-lookup`) so the project's ESLint setup is not
  used, and runs from the target directory. Configured via `KSM_ESLINT_BIN` and
  `KSM_ESLINT_CONFIG` (a copy of `configs/eslint.security.config.mjs`).
- **C# support** via a `CSharpAnalyzer` adapter backed by the Roslyn security
  analyzers. It builds the project with `AnalysisMode=None` +
  `AnalysisModeSecurity=All` and reads the SARIF `ErrorLog`, so only security
  findings are reported and the user's project is not modified. Point it at a
  `.sln`, `.csproj`, or directory. Isolated via `KSM_DOTNET_ROOT` (+ optional
  `KSM_NUGET_PACKAGES`, `KSM_DOTNET_CLI_HOME`).

### Changed
- The SARIF parser now accepts both SARIF 2.x (message object) and 1.x (message
  string), so reports from any tool/version parse cleanly.
- Java analysis now **locates the compiled binaries itself**: point `security_scan`
  at a project/module root and it finds the build output (`build/classes/...`,
  `target/classes`, `out/...`), a classes directory, or a `.jar`. Optional
  `KSM_JAVA_AUXCLASSPATH` supplies dependency jars for more accurate analysis.

### Added
- **Python support** via a `PythonAnalyzer` adapter backed by Bandit (native,
  source-based, no build step). It auto-enables whenever Bandit is installed
  (`pip install "code-security-mcp[python]"`); no environment variables needed.
- **Java support** via a `JavaAnalyzer` adapter backed by SpotBugs + FindSecBugs
  (native, security-focused). A `RoutingAnalyzer` now dispatches each target to
  the analyzers that support it, so `security_scan` handles Kotlin and Java
  through one tool. Java analysis runs on compiled bytecode (build first).
- `review_diff(diff)` tool — parses a unified diff and reports only the security
  findings on lines the change adds (a pre-commit self-check for agents).
- `secure_pattern(task, framework?)` tool — returns vetted before/after Kotlin
  snippets for risky tasks (cookies, secrets, TLS, CORS, reactive auth, CSPRNG).
- `security_scan(path)` tool — runs the detekt-based, framework-aware Kotlin
  ruleset and returns normalized findings; detekt's built-in style/complexity
  rules are disabled so only security findings are reported.
- Continuous integration (GitHub Actions) running a hermetic test suite that
  needs neither a JDK nor detekt.

### Notes
- Clean hexagonal architecture (domain / application / adapters / server); the
  domain has no knowledge of detekt or MCP, so new languages arrive as new
  adapters. Native, framework-aware analyzers per language are the design goal
  (detekt for Kotlin; Roslyn for C# planned), not a single generic scanner.
