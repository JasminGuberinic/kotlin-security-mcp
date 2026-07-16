"""PythonAnalyzer: security-analyze Python source with Bandit.

Bandit is the standard, security-focused Python static analyzer — the Python
counterpart to FindSecBugs for Java. It runs on *source* (no build step) and is
a pure `pip install`, which makes Python the lightest language to enable here.

We resolve the `bandit` executable automatically: from PATH, or from the same
virtual environment this server runs in, so "pip install bandit" is usually all
a user needs.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from code_security_mcp.adapters.bandit_report import parse_bandit_report
from code_security_mcp.adapters.language import target_has_extension
from code_security_mcp.adapters.process import run_with_timeout
from code_security_mcp.domain.models import ScanResult

# The file types Bandit analyzes.
_PYTHON_EXTENSIONS: tuple[str, ...] = (".py",)


@dataclass(frozen=True)
class BanditConfig:
    """Optional configuration for the Bandit analyzer.

    `executable` may be left None, in which case we auto-resolve `bandit`. It
    exists mainly so tests and unusual setups can point at a specific binary.
    """

    executable: str | None = None


class PythonAnalyzer:
    """A LanguageAnalyzer backed by the Bandit CLI."""

    def __init__(self, config: BanditConfig | None = None) -> None:
        self._config = config or BanditConfig()

    def is_available(self) -> bool:
        """True when a Bandit executable can be located on this machine."""
        return self._resolve_executable() is not None

    def supports(self, target: Path) -> bool:
        """True when Bandit is available AND the target is (or contains) Python."""
        if not self.is_available():
            return False
        return target_has_extension(target, _PYTHON_EXTENSIONS)

    def scan(self, target: Path) -> ScanResult:
        """Run Bandit over `target` and return the findings it reports."""
        with tempfile.TemporaryDirectory() as work_dir:
            report_path = Path(work_dir) / "report.json"
            self._run_bandit(target, report_path)
            return self._read_report(report_path)

    def _run_bandit(self, target: Path, report_path: Path) -> None:
        """Launch the Bandit subprocess.

        Bandit exits non-zero when it finds issues, so — as with our other
        analyzers — we ignore the return code and judge success by whether the
        JSON report was written.
        """
        command = self._build_command(target, report_path)
        run_with_timeout(command)

    def _build_command(self, target: Path, report_path: Path) -> list[str]:
        """Assemble the `bandit ... -f json -o <report>` argument list.

        A directory target needs `-r` (recurse); a single file does not. We
        resolve the executable here, trusting `supports()`/`is_available()` to
        have already confirmed it exists.
        """
        executable = self._resolve_executable() or "bandit"
        command = [executable]
        if target.is_dir():
            command.append("-r")
        command += [str(target), "-f", "json", "-o", str(report_path), "-q"]
        return command

    def _resolve_executable(self) -> str | None:
        """Find the Bandit binary: explicit config, PATH, or this venv's bin.

        The venv fallback means installing the server with its `python` extra
        (`pip install "code-security-mcp[python]"`) is enough — no separate
        global Bandit install and no PATH juggling required.
        """
        if self._config.executable:
            explicit = self._config.executable
            return explicit if (shutil.which(explicit) or Path(explicit).exists()) else None

        on_path = shutil.which("bandit")
        if on_path:
            return on_path

        sibling = Path(sys.executable).parent / "bandit"
        return str(sibling) if sibling.exists() else None

    def _read_report(self, report_path: Path) -> ScanResult:
        """Load and parse the Bandit JSON report."""
        if not report_path.exists():
            raise RuntimeError(
                "bandit did not produce a report; check that bandit is installed "
                "(pip install bandit)."
            )
        report = json.loads(report_path.read_text(encoding="utf-8"))
        return parse_bandit_report(report)
