# code-security-mcp

[![CI](https://github.com/JasminGuberinic/code-security-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/JasminGuberinic/code-security-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

**A security [MCP](https://modelcontextprotocol.io) server for AI coding agents.**
It gives Claude Code, Cursor, and other agents real security findings **while
they write, not after** — and each language is analyzed by its **best native
security tool**, not one generic scanner stretched across everything.

> **A specialist, not a generalist.** Kotlin is analyzed by **detekt** with a
> 216-rule, framework-aware ruleset (Spring, WebFlux, Ktor, Quarkus, Micronaut,
> Vert.x); Java by **SpotBugs + FindSecBugs**; Python by **Bandit** — each the
> established native security analyzer for its language, routed automatically.
>
> _New languages arrive as their own native analyzer (C# via Roslyn next) —
> never a single lowest-common-denominator scanner._

## Why

Generic assistants and multi-language scanners are shallow on framework idioms —
they don't know that a `@GetMapping` is missing `@PreAuthorize`, that a WebClient
trusts all certificates, or that a Vert.x cookie isn't `HttpOnly`. This server
wraps a **216-rule, framework-aware analyzer** (the
[`kotlin-security-scanner`](https://github.com/JasminGuberinic/kotlin-security-scanner)
detekt ruleset) and exposes it to agents through three tools.

**Design principle:** each language is handled by its **best native security
analyzer** — routed automatically — never a single lowest-common-denominator
generic scanner.

## Languages

| Language | Analyzer | Analyzes |
|----------|----------|----------|
| **Kotlin** | detekt + the 216-rule framework-aware ruleset | source (`.kt`, `.kts`) |
| **Java** | SpotBugs + FindSecBugs | compiled bytecode (`.class`, `.jar`) — build first |
| **Python** | Bandit | source (`.py`) — no build, just `pip install` |

## Tools

| Tool | What it does |
|------|--------------|
| `security_scan(path)` | Scan a file/directory (Kotlin, Java, or Python) and return every security finding (rule, line, severity, CWE). |
| `review_diff(diff)` | Review a unified diff and flag only the issues the change *introduces* — a pre-commit self-check. |
| `secure_pattern(task, framework?)` | Get the vetted secure way to do a risky task — *before* writing it. |

For Kotlin, `security_scan` returns **security** findings only — detekt's
built-in style/complexity rules are switched off, so the agent gets signal, not
noise.

### Example

> _"What's the secure way to create a session cookie in Vert.x?"_

```kotlin
// secure_pattern(task = "create a session cookie", framework = "vertx")  →  CWE-614
val cookie = Cookie.cookie("session", token)
    .setSecure(true)      // only sent over HTTPS
    .setHttpOnly(true)    // hidden from JavaScript
    .setSameSite(CookieSameSite.STRICT)
response.addCookie(cookie)
```

## Architecture

Clean, hexagonal (ports & adapters). Dependencies point inward; the domain knows
nothing about detekt or MCP.

```
server.py            MCP surface + composition root   (knows MCP)
   │
application/         use cases: scan / review_diff / secure_pattern
   │
domain/              Finding, ScanResult, ports         (pure vocabulary)
   ↑ implemented by
adapters/            DetektAnalyzer, JavaAnalyzer, RoutingAnalyzer,
                     SARIF & diff parsers, pattern catalog
```

A `RoutingAnalyzer` sends each target to the analyzers that support it, so the
use cases treat "one language" and "many" identically. Adding a language = one
new adapter implementing the same `LanguageAnalyzer` port — the domain and use
cases do not change.

## Requirements

- Python 3.11+
- Kotlin: a JDK + the detekt CLI jar + the ruleset jar(s)
- Java: a JDK + the SpotBugs jar + the FindSecBugs plugin jar
- Python: Bandit (`pip install "code-security-mcp[python]"`) — no JDK, no jars

Each analyzer is optional and enabled independently — configure only the
languages you need. (Python auto-enables whenever Bandit is installed.)

## Configuration

The server locates its tools through environment variables:

| Variable | Meaning |
|----------|---------|
| `KSM_JAVA` | Path to the `java` executable (shared) |
| `KSM_DETEKT_CLI_JAR` | Kotlin: detekt CLI (`-all`) jar |
| `KSM_PLUGIN_JARS` | Kotlin: comma-separated ruleset jar(s) |
| `KSM_DETEKT_CONFIG` | Kotlin: _(optional)_ path to a `detekt.yml` |
| `KSM_SPOTBUGS_JAR` | Java: SpotBugs engine jar |
| `KSM_FINDSECBUGS_JARS` | Java: comma-separated plugin jar(s) (FindSecBugs) |

Python needs no variables — install Bandit and it is used automatically.

## Use with Claude Code

```bash
claude mcp add code-security -s user \
  -e KSM_JAVA=/path/to/java \
  -e KSM_DETEKT_CLI_JAR=/path/to/detekt-cli-<ver>-all.jar \
  -e KSM_PLUGIN_JARS=/path/to/scanner-core.jar,/path/to/scanner-spring-boot.jar,... \
  -- /path/to/.venv/bin/code-security-mcp
```

Then ask the agent, e.g. _"run security_scan on src/Main.kt"_ or
_"review_diff on my staged changes"_.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

The test suite is hermetic — it uses fake analyzers and hand-built SARIF / diff /
Bandit-JSON fixtures, so it needs no external analyzer (JDK, detekt, SpotBugs, or
Bandit) to run.

## Roadmap

Each new language arrives as its own **native, framework-aware** analyzer adapter
(never a generic multi-language scanner):

- ✅ **Kotlin** — detekt + the 216-rule framework-aware ruleset.
- ✅ **Java** — SpotBugs + FindSecBugs.
- ✅ **Python** — Bandit.
- **C#** — via **Roslyn** analyzers.
- Zero-setup: auto-resolve the JVM analyzer runtimes and rulesets.

## License

MIT — see [LICENSE](LICENSE).

---

<sub>Keywords: MCP server, Model Context Protocol, Kotlin security, JVM security,
SAST, static analysis, detekt, Spring Security, AI coding agent, Claude Code,
Cursor, secure coding.</sub>
