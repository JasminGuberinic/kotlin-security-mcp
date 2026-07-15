"""Parse a unified diff into "which lines were added in each file".

`review_diff` only wants to flag problems the change *introduces*, so we need to
know, per file, the set of line numbers that are new in the post-change version.
This module answers exactly that and nothing more. It is a pure function over a
string, which makes it trivial to unit-test without any real diff on disk.
"""

from __future__ import annotations

import re

# Matches a hunk header like "@@ -12,7 +14,9 @@" and captures the new-file start
# line (14 here). We only care about the "+" side, since we track added lines.
_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_unified_diff(diff_text: str) -> dict[str, set[int]]:
    """Return a map of file path -> set of line numbers added in the new version.

    We walk the diff line by line, tracking the current file (from "+++" headers)
    and a running new-file line counter that advances on context and added lines
    but not on removed lines — the standard way to recover new-file positions.
    """
    added_by_file: dict[str, set[int]] = {}
    current_file: str | None = None
    new_line_number = 0

    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            current_file = _path_from_header(line)
            continue

        hunk = _HUNK_HEADER.match(line)
        if hunk:
            # A new hunk resets the counter to its declared new-file start line.
            new_line_number = int(hunk.group(1))
            continue

        if current_file is None:
            continue  # still in the pre-hunk preamble

        new_line_number = _consume_body_line(line, current_file, new_line_number, added_by_file)

    return added_by_file


def _consume_body_line(
    line: str,
    current_file: str,
    new_line_number: int,
    added_by_file: dict[str, set[int]],
) -> int:
    """Account for one hunk-body line and return the next new-file line number.

    - "+" lines are additions: record the number, then advance.
    - " " context lines exist in both versions: just advance.
    - "-" lines were removed: they do not exist in the new file, so do not advance.
    """
    if line.startswith("+"):
        added_by_file.setdefault(current_file, set()).add(new_line_number)
        return new_line_number + 1
    if line.startswith(" "):
        return new_line_number + 1
    # "-" removals and metadata lines ("\ No newline…") do not advance the counter.
    return new_line_number


def _path_from_header(header: str) -> str | None:
    """Extract the file path from a "+++ b/path" line.

    Git prefixes the new-file path with "b/"; a deletion shows "/dev/null", which
    we translate to None so nothing gets attributed to a non-existent file.
    """
    raw = header[len("+++ ") :].strip()
    if raw == "/dev/null":
        return None
    for prefix in ("a/", "b/"):
        if raw.startswith(prefix):
            return raw[len(prefix) :]
    return raw
