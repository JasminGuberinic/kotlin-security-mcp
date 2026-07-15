"""The SecurePattern value object: a known-good way to do a risky task.

Where a Finding says "this is wrong", a SecurePattern says "here is the right
way". It pairs the insecure shape an agent might reach for with the secure one,
plus a short reason — exactly the guidance an agent needs *before* it writes.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SecurePattern:
    """A secure recipe for one task in one framework."""

    # Which stack this applies to, e.g. "spring-webflux", "ktor", "vertx",
    # or "any" for framework-agnostic JVM code.
    framework: str

    # A short human title of the task, e.g. "Create a secure session cookie".
    task: str

    # Lowercase words we match the agent's free-text request against. This is
    # how "make a cookie in vertx" finds the Vert.x cookie pattern.
    keywords: tuple[str, ...]

    # The tempting-but-wrong version, so the agent recognizes what to avoid.
    insecure_example: str

    # The recommended version to write instead.
    secure_example: str

    # One or two sentences on *why* the secure version is safe.
    explanation: str

    # Optional CWE this pattern defends against (e.g. "CWE-614").
    cwe: str | None = None
