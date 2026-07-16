"""A single place to launch analyzer subprocesses — always with a timeout.

Real code-bases are large, and any analyzer can occasionally get stuck. Every
adapter runs its tool through `run_with_timeout` so a scan can *fail cleanly*
instead of hanging the MCP server forever. Centralizing this also means the
timeout policy lives in exactly one place.

We never pass `check=True`: analyzers routinely exit non-zero when they *find*
issues, which is a normal outcome, not an error. Callers decide success from the
report/output, not the exit code.
"""

from __future__ import annotations

import os
import subprocess

# How long any single analyzer may run before we give up (seconds). Overridable
# with the KSM_TIMEOUT environment variable for very large projects.
_DEFAULT_TIMEOUT_SECONDS = 300


def _resolve_timeout(explicit: int | None) -> int:
    """Pick the timeout: an explicit argument wins, then KSM_TIMEOUT, then default."""
    if explicit is not None:
        return explicit
    from_env = os.environ.get("KSM_TIMEOUT", "")
    return int(from_env) if from_env.isdigit() else _DEFAULT_TIMEOUT_SECONDS


def run_with_timeout(
    command: list[str],
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run `command`, capturing output, never raising on a non-zero exit.

    Raises a clear RuntimeError if the analyzer exceeds the timeout, so the agent
    gets an actionable message instead of a hung request.
    """
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            cwd=cwd,
            env=env,
            timeout=_resolve_timeout(timeout),
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            f"Analyzer timed out after {error.timeout:.0f}s: {command[0]}. "
            "Scan a smaller path, or raise KSM_TIMEOUT."
        ) from error
