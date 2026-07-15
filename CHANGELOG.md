# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
