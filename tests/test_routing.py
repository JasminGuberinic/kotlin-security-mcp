"""Tests for the RoutingAnalyzer and the SpotBugs (Java) adapter wiring."""

from pathlib import Path

from code_security_mcp.adapters.routing_analyzer import RoutingAnalyzer
from code_security_mcp.adapters.spotbugs_analyzer import JavaAnalyzer, SpotBugsConfig
from code_security_mcp.domain.models import Finding, ScanResult, Severity


class _FakeLanguageAnalyzer:
    """A language analyzer that supports a fixed extension and returns one finding."""

    def __init__(self, extension: str, rule_id: str) -> None:
        self._extension = extension
        self._rule_id = rule_id

    def supports(self, target: Path) -> bool:
        return target.suffix == self._extension

    def scan(self, target: Path) -> ScanResult:
        return ScanResult(
            findings=(Finding(self._rule_id, "m", str(target), 1, Severity.WARNING),)
        )


def test_router_runs_only_supporting_analyzers():
    kotlin = _FakeLanguageAnalyzer(".kt", "KotlinRule")
    java = _FakeLanguageAnalyzer(".class", "JavaRule")
    router = RoutingAnalyzer((kotlin, java))

    result = router.scan(Path("App.kt"))

    # Only the Kotlin analyzer supports a .kt file.
    assert result.count == 1
    assert result.findings[0].rule_id == "KotlinRule"


def test_router_merges_findings_from_all_supporting_analyzers(tmp_path):
    # Two analyzers that both support directories (via the fake's suffix "").
    a = _FakeLanguageAnalyzer("", "RuleA")
    b = _FakeLanguageAnalyzer("", "RuleB")
    router = RoutingAnalyzer((a, b))

    result = router.scan(tmp_path)  # a directory has an empty suffix

    rule_ids = {finding.rule_id for finding in result.findings}
    assert rule_ids == {"RuleA", "RuleB"}


def _spotbugs_config(tmp_path, **overrides) -> SpotBugsConfig:
    """A SpotBugsConfig whose engine jar exists, for supports()/command tests."""
    spotbugs = tmp_path / "spotbugs.jar"
    spotbugs.write_text("")  # must exist so availability passes
    base = dict(
        java_executable=Path("/opt/java/bin/java"),
        spotbugs_jar=spotbugs,
        plugin_jars=(tmp_path / "findsecbugs.jar",),
    )
    base.update(overrides)
    return SpotBugsConfig(**base)


def test_java_analyzer_skips_itself_when_spotbugs_missing(tmp_path):
    # Point at a non-existent SpotBugs jar: supports() must return False so the
    # router transparently skips Java analysis instead of failing.
    config = SpotBugsConfig(
        java_executable=Path("/usr/bin/java"),
        spotbugs_jar=tmp_path / "does-not-exist.jar",
        plugin_jars=(tmp_path / "fsb.jar",),
    )
    a_class = tmp_path / "Foo.class"
    a_class.write_bytes(b"\xca\xfe\xba\xbe")  # a fake .class file
    assert JavaAnalyzer(config).supports(a_class) is False


def test_java_analyzer_finds_gradle_build_output(tmp_path):
    # Simulate a Gradle project: source at the root, compiled classes under
    # build/classes/java/main. Pointing at the project root must resolve to the
    # build output — this is the "read the binaries" behavior.
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "App.java").write_text("class App {}")
    build_main = tmp_path / "build" / "classes" / "java" / "main"
    build_main.mkdir(parents=True)
    (build_main / "App.class").write_bytes(b"\xca\xfe\xba\xbe")

    analyzer = JavaAnalyzer(_spotbugs_config(tmp_path))
    roots = analyzer._resolve_class_roots(tmp_path)

    assert roots == (build_main,)
    assert analyzer.supports(tmp_path) is True


def test_java_analyzer_unsupported_when_only_source(tmp_path):
    # A Java project that has not been built yet has no bytecode to read.
    (tmp_path / "App.java").write_text("class App {}")
    analyzer = JavaAnalyzer(_spotbugs_config(tmp_path))
    assert analyzer.supports(tmp_path) is False


def test_java_analyzer_command_is_well_formed(tmp_path):
    plugin = tmp_path / "findsecbugs.jar"
    classes = tmp_path / "classes"
    classes.mkdir()
    config = _spotbugs_config(
        tmp_path, plugin_jars=(plugin,), aux_classpath=(tmp_path / "dep.jar",)
    )
    analyzer = JavaAnalyzer(config)

    command = analyzer._build_command((classes,), tmp_path / "out.sarif")

    assert command[0] == "/opt/java/bin/java"
    assert "-textui" in command
    assert "-sarif" in command
    assert "-pluginList" in command
    assert str(plugin) in command
    # Security-only: report just the SECURITY bug category.
    assert "-bugCategories" in command
    assert "SECURITY" in command
    # aux classpath is passed when configured, and the class root comes last.
    assert "-auxclasspath" in command
    assert command[-1] == str(classes)
