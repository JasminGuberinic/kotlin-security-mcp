# kotlin-security-mcp

An [MCP](https://modelcontextprotocol.io) server that exposes a **216-rule,
framework-aware Kotlin/JVM security analyzer** to AI coding agents (Claude Code,
Cursor, …).

Generic assistants guess at JVM security. This server lets an agent **query real
security findings while it writes** — rule id, line, severity, and fix — backed
by the [`kotlin-security-scanner`](https://github.com/JasminGuberinic/kotlin-security-scanner)
detekt ruleset (Spring / WebFlux / Ktor / Quarkus / Micronaut / Vert.x).

> Not generic navigation (Serena), not generic SAST (Snyk): the JVM-framework
> **security specialist** for agents.

## Tools

| Tool | What it does |
|------|--------------|
| `security_scan(path)` | Scan a Kotlin file/directory and return every security finding. |

Only **security** findings are returned — detekt's built-in style/complexity
rules are switched off, so the agent gets signal, not noise.

_(More tools — `secure_pattern`, `review_diff`, and tree-sitter navigation —
are on the roadmap.)_

## Architecture

Clean, hexagonal (ports & adapters). Dependencies point inward; the domain knows
nothing about detekt or MCP.

```
server.py            MCP surface + composition root   (knows MCP)
   │
application/         ScanCodeUseCase                  (knows only ports)
   │
domain/              Finding, ScanResult, ports        (pure vocabulary)
   ↑ implemented by
adapters/            DetektAnalyzer, SARIF parser      (knows detekt/JVM)
```

Swapping detekt for another engine, or adding Python/Java/C# analyzers, means
adding an adapter — nothing in the domain or use case changes.

## Requirements

- Python 3.11+
- A JDK (for the detekt runtime)
- The detekt CLI jar and the `scanner-all` ruleset jar

## Configuration

The server locates its tools through environment variables:

| Variable | Meaning |
|----------|---------|
| `KSM_JAVA` | Path to the `java` executable |
| `KSM_DETEKT_CLI_JAR` | Path to the detekt CLI jar |
| `KSM_PLUGIN_JARS` | Comma-separated ruleset jar(s) (`scanner-all`) |
| `KSM_DETEKT_CONFIG` | _(optional)_ path to a `detekt.yml` |

## Use with Claude Code

Register the server (stdio) and point it at your JDK, the detekt CLI jar, and
the ruleset jar(s):

```bash
claude mcp add kotlin-security -s user \
  -e KSM_JAVA=/path/to/java \
  -e KSM_DETEKT_CLI_JAR=/path/to/detekt-cli-<ver>-all.jar \
  -e KSM_PLUGIN_JARS=/path/to/scanner-core.jar,/path/to/scanner-spring-boot.jar,... \
  -- /path/to/.venv/bin/kotlin-security-mcp
```

Then ask the agent to scan a file, e.g. _"run security_scan on src/Main.kt"_.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

## License

MIT
