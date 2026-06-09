"""Tests for the ``dscan trail`` CLI command.

TrailAnalyzer is mocked so these tests don't depend on the real engine
or on actual agent runs — only on the CLI's reading, filtering,
rendering, and exit-code behavior.
"""

import json

import pytest
from click.testing import CliRunner
from unittest.mock import MagicMock

from dscan.cli import main
from dscan.trail import Finding


@pytest.fixture(autouse=True)
def wide_terminal(monkeypatch):
    # Keep the rich table from wrapping/truncating headers under CliRunner.
    monkeypatch.setenv("COLUMNS", "200")


def finding(severity, pattern="PATTERN", tools=("a", "b"), indices=(0, 1),
            message="message", confidence=0.8):
    return Finding(
        pattern=pattern,
        severity=severity,
        calls_involved=list(tools),
        call_indices=list(indices),
        message=message,
        confidence=confidence,
    )


def write_traces(tmp_path, count=3, session="s1", name="2026-06-09_agent.ndjson"):
    lines = []
    for i in range(count):
        lines.append(
            json.dumps(
                {
                    "ts": f"2026-06-09T{i:02d}:00:00Z",
                    "session_id": session,
                    "agent": "agent",
                    "tool": "read_file",
                    "params": {"path": f"/x{i}"},
                    "result": {},
                    "duration_ms": 1,
                    "flagged": False,
                    "flag_reason": None,
                }
            )
        )
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def patch_analyzer(monkeypatch, findings):
    """Patch dscan.cli.TrailAnalyzer; return the mock instance."""
    instance = MagicMock()
    instance.analyze.return_value = findings
    monkeypatch.setattr("dscan.cli.TrailAnalyzer", MagicMock(return_value=instance))
    return instance


def run(args):
    return CliRunner().invoke(main, args)


# --------------------------------------------------------------------------
# Exit codes by severity
# --------------------------------------------------------------------------
class TestExitCodes:
    def test_no_findings_exit_0(self, tmp_path, monkeypatch):
        write_traces(tmp_path)
        patch_analyzer(monkeypatch, [])
        result = run(["trail", str(tmp_path)])
        assert result.exit_code == 0
        assert "No issues found" in result.output

    def test_medium_only_exit_0(self, tmp_path, monkeypatch):
        write_traces(tmp_path)
        patch_analyzer(monkeypatch, [finding("medium", pattern="DATA_STAGING")])
        result = run(["trail", str(tmp_path)])
        assert result.exit_code == 0

    def test_high_exit_1(self, tmp_path, monkeypatch):
        write_traces(tmp_path)
        patch_analyzer(monkeypatch, [finding("high", pattern="EXFIL_SEQUENCE")])
        result = run(["trail", str(tmp_path)])
        assert result.exit_code == 1

    def test_critical_exit_1(self, tmp_path, monkeypatch):
        write_traces(tmp_path)
        patch_analyzer(monkeypatch, [finding("critical", pattern="INJECTION_RELAY")])
        result = run(["trail", str(tmp_path)])
        assert result.exit_code == 1


# --------------------------------------------------------------------------
# Path handling
# --------------------------------------------------------------------------
class TestPathHandling:
    def test_missing_path_exit_2_mentions_path(self):
        result = run(["trail", "/no/such/dscan_path_xyz"])
        assert result.exit_code == 2
        assert "/no/such/dscan_path_xyz" in result.output

    def test_single_file_path(self, tmp_path, monkeypatch):
        file = write_traces(tmp_path)
        patch_analyzer(monkeypatch, [finding("high", pattern="EXFIL_SEQUENCE")])
        result = run(["trail", str(file)])
        assert result.exit_code == 1
        assert "EXFIL_SEQUENCE" in result.output

    def test_directory_path(self, tmp_path, monkeypatch):
        write_traces(tmp_path)
        patch_analyzer(monkeypatch, [finding("medium", pattern="DATA_STAGING")])
        result = run(["trail", str(tmp_path)])
        assert result.exit_code == 0
        assert "DATA_STAGING" in result.output


# --------------------------------------------------------------------------
# --min-severity
# --------------------------------------------------------------------------
class TestMinSeverity:
    def test_skips_below_threshold(self, tmp_path, monkeypatch):
        write_traces(tmp_path)
        patch_analyzer(
            monkeypatch,
            [
                finding("medium", pattern="DATA_STAGING", message="staging-msg"),
                finding("high", pattern="EXFIL_SEQUENCE", message="exfil-msg"),
            ],
        )
        result = run(["trail", str(tmp_path), "--min-severity", "high"])
        assert "EXFIL_SEQUENCE" in result.output
        assert "DATA_STAGING" not in result.output  # medium hidden

    def test_exit_code_reflects_all_findings_not_filter(self, tmp_path, monkeypatch):
        # A HIGH finding still gates the build even if the display filter
        # is set above it.
        write_traces(tmp_path)
        patch_analyzer(monkeypatch, [finding("high", pattern="EXFIL_SEQUENCE")])
        result = run(["trail", str(tmp_path), "--min-severity", "critical"])
        assert result.exit_code == 1
        assert "EXFIL_SEQUENCE" not in result.output  # hidden by filter


# --------------------------------------------------------------------------
# --json
# --------------------------------------------------------------------------
class TestJsonOutput:
    def test_outputs_valid_json_array(self, tmp_path, monkeypatch):
        write_traces(tmp_path)
        patch_analyzer(
            monkeypatch,
            [
                finding(
                    "critical",
                    pattern="INJECTION_RELAY",
                    tools=("search_web", "send_email"),
                    indices=(0, 1),
                    message="relay",
                    confidence=0.85,
                )
            ],
        )
        result = run(["trail", str(tmp_path), "--json"])
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert data[0]["pattern"] == "INJECTION_RELAY"
        assert data[0]["severity"] == "critical"
        assert data[0]["confidence"] == 0.85
        assert data[0]["calls_involved"] == ["search_web", "send_email"]

    def test_json_respects_min_severity(self, tmp_path, monkeypatch):
        write_traces(tmp_path)
        patch_analyzer(
            monkeypatch,
            [
                finding("medium", pattern="DATA_STAGING"),
                finding("critical", pattern="INJECTION_RELAY"),
            ],
        )
        result = run(["trail", str(tmp_path), "--json", "--min-severity", "high"])
        data = json.loads(result.output)
        assert [f["pattern"] for f in data] == ["INJECTION_RELAY"]


# --------------------------------------------------------------------------
# Table rendering
# --------------------------------------------------------------------------
class TestTable:
    def test_has_expected_columns(self, tmp_path, monkeypatch):
        write_traces(tmp_path)
        patch_analyzer(
            monkeypatch,
            [finding("high", pattern="EXFIL_SEQUENCE", tools=("read_file", "send_email"))],
        )
        result = run(["trail", str(tmp_path)])
        for column in ["Severity", "Pattern", "Tools Involved", "Message", "Confidence"]:
            assert column in result.output

    def test_confidence_rendered_as_percent(self, tmp_path, monkeypatch):
        write_traces(tmp_path)
        patch_analyzer(
            monkeypatch,
            [finding("high", pattern="EXFIL_SEQUENCE", confidence=0.85)],
        )
        result = run(["trail", str(tmp_path)])
        assert "85%" in result.output

    def test_footer_counts(self, tmp_path, monkeypatch):
        write_traces(tmp_path, count=4)
        patch_analyzer(monkeypatch, [finding("high", pattern="EXFIL_SEQUENCE")])
        result = run(["trail", str(tmp_path)])
        assert "findings across" in result.output
        assert "tool calls analysed" in result.output
        assert "4" in result.output  # Y = 4 tool calls

    def test_tools_involved_shows_chain(self, tmp_path, monkeypatch):
        write_traces(tmp_path)
        patch_analyzer(
            monkeypatch,
            [finding("high", pattern="EXFIL_SEQUENCE", tools=("read_file", "send_email"))],
        )
        result = run(["trail", str(tmp_path)])
        assert "read_file" in result.output
        assert "send_email" in result.output


# --------------------------------------------------------------------------
# Per-session scoping
# --------------------------------------------------------------------------
class TestRobustReading:
    def test_skips_blank_and_malformed_lines(self, tmp_path, monkeypatch):
        valid = json.dumps(
            {"ts": "2026-06-09T01:00:00Z", "session_id": "s1", "tool": "read_file",
             "params": {"path": "/a"}}
        )
        path = tmp_path / "2026-06-09_agent.ndjson"
        path.write_text(
            valid + "\n\n{ this is not json\n" + valid + "\n", encoding="utf-8"
        )
        patch_analyzer(monkeypatch, [])
        result = run(["trail", str(path)])
        assert result.exit_code == 0
        # Two valid lines parsed; blank + malformed skipped.
        assert "No issues found in 2 tool calls" in result.output


class TestSessionScoping:
    def test_analyze_runs_once_per_session(self, tmp_path, monkeypatch):
        # Two sessions in one file -> analyze() called once per session,
        # so chains never bridge unrelated agent runs.
        s1 = [
            {"ts": "2026-06-09T01:00:00Z", "session_id": "s1", "tool": "read_file",
             "params": {"path": "/a"}},
            {"ts": "2026-06-09T02:00:00Z", "session_id": "s1", "tool": "send_email",
             "params": {"to": "x@y.com"}},
        ]
        s2 = [
            {"ts": "2026-06-09T03:00:00Z", "session_id": "s2", "tool": "whoami",
             "params": {}},
        ]
        path = tmp_path / "2026-06-09_agent.ndjson"
        path.write_text("\n".join(json.dumps(t) for t in s1 + s2) + "\n", encoding="utf-8")
        instance = patch_analyzer(monkeypatch, [])
        result = run(["trail", str(path)])
        assert result.exit_code == 0
        assert instance.analyze.call_count == 2
