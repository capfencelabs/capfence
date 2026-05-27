"""CapFence CLI entry point.

Commands:
    check              Scan codebase for ungated AI agent tools
    replay             Deterministic trace replay and policy simulation
    verify             Verify integrity of a hash-chained audit log
    pending-approvals  List pending tool execution approvals
    approve            Approve a pending tool execution
    reject             Reject a pending tool execution
    grant              Grant temporary or session pre-authorizations
    logs               View structured audit logs
    trace              View a detailed execution trace
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from capfence.check import scan_directory, scan_file, compute_aggregate_score, ToolFinding
from capfence.core.audit import AuditLogger
from capfence.core.approvals import ApprovalManager
from capfence.core.policy import PolicyLoader
from capfence.core.policy_testing import (
    diff_policy_fixtures,
    explain_policy_event,
    load_fixture_file,
    run_policy_fixture_file,
)
from capfence.core.replay import ReplayEngine

__version__ = "0.8.4"


@click.group()
@click.version_option(version=__version__, prog_name="capfence")
def main() -> None:
    """CapFence — deterministic execution authorization runtime for autonomous AI systems."""
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
@click.option("--framework", "-f", type=str, default=None,
              help="Filter by framework (langchain, crewai, autogen)")
@click.option("--fail-on-ungated", is_flag=True,
              help="Exit with non-zero code if ungated high-risk tools found")
@click.option("--strict", is_flag=True,
              help="Exit with non-zero code if ANY ungated tools are found")
@click.option("--report-json", is_flag=True,
              help="Output findings in JSON format to stdout")
def check(
    path: Path,
    framework: str | None,
    fail_on_ungated: bool,
    strict: bool,
    report_json: bool,
) -> None:
    """Scan Python codebase for ungated AI agent tool classes."""
    if path.is_file():
        findings = scan_file(path)
    else:
        findings = scan_directory(path)

    if framework:
        framework_lower = framework.lower()
        findings = [f for f in findings if f.framework and f.framework.lower() == framework_lower]

    if report_json:
        out = [{"name": f.name, "file": str(f.file), "line": f.line, "framework": f.framework, "category": f.category, "risk_delta": f.risk_delta, "is_wrapped": f.is_wrapped} for f in findings]
        click.echo(json.dumps(out, indent=2))
    else:
        _print_findings(findings, path)

    # strict means ANY ungated tool fails
    if strict:
        all_ungated = [f for f in findings if not f.is_wrapped]
        if all_ungated:
            if not report_json:
                click.echo(f"\nCI FAILED (STRICT): {len(all_ungated)} ungated tool(s) found.", err=True)
            sys.exit(1)
            
    if fail_on_ungated:
        high_risk_ungated = [f for f in findings if not f.is_wrapped and f.risk_delta <= 0.2]
        if high_risk_ungated:
            if not report_json:
                click.echo(
                    f"\nCI FAILED: {len(high_risk_ungated)} high-risk ungated tool(s) found.",
                    err=True,
                )
            sys.exit(1)
        else:
            if not report_json:
                click.echo("\nAll high-risk tools are gated.")


@main.command(name="check-policy")
@click.argument("policy_file", type=click.Path(exists=True, path_type=Path))
def check_policy(policy_file: Path) -> None:
    """Validate a CapFence YAML policy file."""
    try:
        policy = PolicyLoader().load(policy_file)
    except Exception as exc:
        click.echo(f"[POLICY] INVALID: {policy_file}", err=True)
        click.echo(f"  {type(exc).__name__}: {exc}", err=True)
        sys.exit(2)

    click.echo(f"[POLICY] VALID: {policy_file}")
    click.echo(f"  Rules: {len(policy.rules)}")
    click.echo(f"  Risk levels: {len(policy.risk_levels)}")


@main.group(name="policy")
def policy_group() -> None:
    """Policy development commands."""


@policy_group.command(name="test")
@click.argument("fixture_file", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "output_json", is_flag=True, help="Output machine-readable JSON")
def policy_test(fixture_file: Path, output_json: bool) -> None:
    """Run policy fixture tests."""
    suite = run_policy_fixture_file(fixture_file)
    if output_json:
        click.echo(json.dumps({
            "suite": suite.name,
            "passed": suite.passed,
            "total": suite.total,
            "failures": suite.failures,
            "results": [result.__dict__ for result in suite.results],
        }, indent=2))
    else:
        click.echo(f"[POLICY TEST] {suite.name}: {suite.total - suite.failures}/{suite.total} passed")
        for result in suite.results:
            mark = "PASS" if result.passed else "FAIL"
            click.echo(
                f"  {mark:<4} {result.name}: expected={result.expected} actual={result.actual} "
                f"reason={result.reason}"
            )
    if not suite.passed:
        sys.exit(1)


@policy_group.command(name="explain")
@click.argument("policy_file", type=click.Path(exists=True, path_type=Path))
@click.argument("event_file", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "output_json", is_flag=True, help="Output machine-readable JSON")
def policy_explain(policy_file: Path, event_file: Path, output_json: bool) -> None:
    """Explain how a policy evaluates one event fixture."""
    event_data = load_fixture_file(event_file)
    if "event" in event_data:
        event = event_data["event"]
    elif event_data.get("cases"):
        event = event_data["cases"][0]["event"]
    else:
        event = event_data
    explanation = explain_policy_event(policy_file, event)
    if output_json:
        click.echo(json.dumps(explanation, indent=2))
        return
    click.echo(f"[POLICY EXPLAIN] {policy_file}")
    click.echo(f"  Capability:       {explanation['capability']}")
    click.echo(f"  Final verdict:    {explanation['final_verdict']}")
    click.echo(f"  Section:          {explanation['section']}")
    click.echo(f"  Rule index:       {explanation['rule_index']}")
    click.echo(f"  Predicate result: {explanation['predicate_result']}")
    click.echo(f"  Reason:           {explanation['reason']}")


@policy_group.command(name="diff")
@click.argument("before_policy", type=click.Path(exists=True, path_type=Path))
@click.argument("after_policy", type=click.Path(exists=True, path_type=Path))
@click.argument("fixture_file", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "output_json", is_flag=True, help="Output machine-readable JSON")
def policy_diff(
    before_policy: Path,
    after_policy: Path,
    fixture_file: Path,
    output_json: bool,
) -> None:
    """Compare two policies against the same event fixture corpus."""
    diff = diff_policy_fixtures(before_policy, after_policy, fixture_file)
    if output_json:
        click.echo(json.dumps(diff, indent=2))
        return

    click.echo("[POLICY DIFF]")
    if not diff["transitions"]:
        click.echo("  No verdict changes.")
        return
    for transition, entries in diff["transitions"].items():
        click.echo(f"  {transition}: {len(entries)}")
        for entry in entries:
            click.echo(f"    - {entry['name']} ({entry['capability']})")
    if diff["newly_allowed"]:
        click.echo("\n[WARNING] Newly allowed side effects:")
        for entry in diff["newly_allowed"]:
            click.echo(f"  - {entry['name']} ({entry['capability']})")


def _print_findings(findings: list[ToolFinding], path: Path) -> None:
    """Print findings table to stdout."""
    if not findings:
        click.echo(f"[SCAN] No tool classes found in {path}")
        click.echo("[RISK SCORE] 0/100 (SAFE)")
        click.echo("\nNo agent tools detected.")
        return

    click.echo(f"[SCAN] {len(findings)} tool(s) found in {path}")
    click.echo()
    click.echo(f"{'Tool':<25} {'Framework':<12} {'Category':<20} {'Gated?':<8} {'Risk':<8} {'File'}")
    click.echo("-" * 100)

    for finding in findings:
        gated = "YES" if finding.is_wrapped else "NO"
        risk = finding.risk_level()
        category = finding.category or "unknown"
        fw = finding.framework or "-"
        rel = _rel_path(finding.file, path)
        click.echo(
            f"{finding.name:<25} {fw:<12} {category:<20} {gated:<8} {risk:<8} {rel}:{finding.line}"
        )

    score, label = compute_aggregate_score(findings)
    ungated = sum(1 for f in findings if not f.is_wrapped)
    gated_count = len(findings) - ungated
    high_risk = sum(1 for f in findings if not f.is_wrapped and f.risk_delta <= 0.2)

    click.echo()
    click.echo(f"[RISK SCORE] {score}/100 ({label})")
    click.echo(f"  Total tools:     {len(findings)}")
    click.echo(f"  Gated:           {gated_count}")
    click.echo(f"  Ungated:         {ungated}")
    if high_risk:
        click.echo(f"  High-risk ungated: {high_risk}")

    if ungated > 0:
        click.echo()
        click.echo("[RECOMMENDATION]")
        click.echo("  Wrap ungated tools with CapFenceTool.")


def _rel_path(file_path: Path, base_path: Path) -> str:
    try:
        return str(file_path.relative_to(base_path))
    except ValueError:
        return file_path.name


@main.command(name="replay")
@click.argument("trace_file", type=click.Path(exists=True, path_type=Path))
@click.option("--policy", "-p", type=click.Path(exists=True, path_type=Path), default=None,
              help="Simulate a custom policy file during replay")
def replay(trace_file: Path, policy: Path | None) -> None:
    """Deterministic trace replay and policy simulation for autonomous systems."""
    engine = ReplayEngine()
    if policy:
        click.echo(f"[REPLAY] Simulating policy '{policy}' on trace '{trace_file}'...")
        summary = engine.simulate_policy(trace_file, policy)
    else:
        click.echo(f"[REPLAY] Replaying incident trace '{trace_file}'...")
        summary = engine.replay_incident(trace_file)

    click.echo()
    click.echo("=" * 60)
    click.echo(f"Replayed {summary.total_events} events:")
    click.echo(f"  Authorized:         {summary.authorized}")
    click.echo(f"  Blocked:            {summary.blocked}")
    click.echo(f"  Requires Approval:  {summary.require_approval}")
    click.echo(f"  Drifts/Diffs:       {summary.diffs_detected}")
    click.echo("=" * 60)
    
    if summary.compliance_evidence:
        click.echo("\n[COMPLIANCE EVIDENCE]")
        for standard, text in summary.compliance_evidence.get("standards", {}).items():
            click.echo(f"  {standard}: {text}")
        click.echo(f"  Status: {summary.compliance_evidence.get('status')}")
    click.echo()


@main.command(name="verify")
@click.option("--audit-log", "-a", type=click.Path(exists=True, path_type=Path), required=True,
              help="Path to SQLite audit log database")
def verify(audit_log: Path) -> None:
    """Verify hash-chain integrity of an audit log database."""
    audit = AuditLogger(db_path=audit_log)
    valid, errors = audit.verify()
    if valid:
        click.echo("[VERIFY] Audit chain: VALID")
        click.echo("  No tampering detected.")
    else:
        click.echo("[VERIFY] Audit chain: INVALID", err=True)
        click.echo(f"  {len(errors)} error(s) detected:", err=True)
        for e in errors:
            click.echo(f"    - {e}", err=True)
        sys.exit(3)


@main.command(name="pending-approvals")
@click.option("--db-path", "-d", type=click.Path(path_type=Path), default="capfence_approvals.db",
              help="Path to approvals database")
def pending_approvals(db_path: Path) -> None:
    """List pending tool execution approvals."""
    manager = ApprovalManager(db_path=db_path)
    pending = manager.get_pending()
    
    if not pending:
        click.echo("No pending approvals.")
        return
        
    click.echo(f"{'ID':<40} {'Agent ID':<15} {'Tool':<25} {'Capability'}")
    click.echo("-" * 100)
    for req in pending:
        cap = req.capability or "-"
        click.echo(f"{req.id:<40} {req.agent_id:<15} {req.tool_name:<25} {cap}")


@main.command(name="approve")
@click.argument("request_id", type=str)
@click.option("--db-path", "-d", type=click.Path(path_type=Path), default="capfence_approvals.db",
              help="Path to approvals database")
@click.option("--user", "-u", type=str, default="cli_user", help="User approving the request")
def approve(request_id: str, db_path: Path, user: str) -> None:
    """Approve a pending tool execution."""
    manager = ApprovalManager(db_path=db_path)
    req = manager.get_request(request_id)
    if not req:
        click.echo(f"Request {request_id} not found.", err=True)
        sys.exit(1)
        
    if req.status != "pending":
        click.echo(f"Request {request_id} is already {req.status}.", err=True)
        sys.exit(1)
        
    manager.approve(request_id, resolved_by=user)
    click.echo(f"Request {request_id} approved.")


@main.command(name="reject")
@click.argument("request_id", type=str)
@click.option("--db-path", "-d", type=click.Path(path_type=Path), default="capfence_approvals.db",
              help="Path to approvals database")
@click.option("--user", "-u", type=str, default="cli_user", help="User rejecting the request")
def reject(request_id: str, db_path: Path, user: str) -> None:
    """Reject a pending tool execution."""
    manager = ApprovalManager(db_path=db_path)
    req = manager.get_request(request_id)
    if not req:
        click.echo(f"Request {request_id} not found.", err=True)
        sys.exit(1)
        
    if req.status != "pending":
        click.echo(f"Request {request_id} is already {req.status}.", err=True)
        sys.exit(1)
        
    manager.reject(request_id, resolved_by=user)
    click.echo(f"Request {request_id} rejected.")


@main.command(name="grant")
@click.option("--db-path", "-d", type=click.Path(path_type=Path), default="capfence_approvals.db",
              help="Path to approvals database")
@click.option("--actor", "-a", type=str, required=True, help="Actor ID or '*' for all")
@click.option("--capability", "-c", type=str, required=True, help="Capability to grant (e.g. github.push.main)")
@click.option("--environment", "-e", type=str, default="*", help="Target environment or '*'")
@click.option("--duration", type=float, default=None, help="Duration in seconds for temporary grant")
@click.option("--session", "-s", type=str, default=None, help="Session ID for session-bound grant")
@click.option("--by", type=str, default="cli_admin", help="Granter identifier")
def grant(db_path: Path, actor: str, capability: str, environment: str, duration: float | None, session: str | None, by: str) -> None:
    """Grant temporary or session pre-authorizations to an actor."""
    manager = ApprovalManager(db_path=db_path)
    
    if duration:
        g = manager.grant_temporary_approval(actor, capability, environment, duration, granted_by=by)
        click.echo(f"[GRANT] Temporary grant {g.id} created successfully!")
        click.echo(f"  Actor:      {g.actor}")
        click.echo(f"  Capability: {g.capability}")
        click.echo(f"  Expires:    In {duration} seconds")
    elif session:
        g = manager.grant_session_approval(actor, capability, environment, session, granted_by=by)
        click.echo(f"[GRANT] Session grant {g.id} created successfully!")
        click.echo(f"  Actor:      {g.actor}")
        click.echo(f"  Capability: {g.capability}")
        click.echo(f"  Session ID: {g.session_id}")
    else:
        g = manager.grant_temporary_approval(actor, capability, environment, 3600.0, granted_by=by)
        click.echo(f"[GRANT] Created default 1-hour temporary grant {g.id}:")
        click.echo(f"  Actor:      {g.actor}")
        click.echo(f"  Capability: {g.capability}")
        click.echo("  Expires:    In 3600.0 seconds")


@main.command(name="logs")
@click.option("--audit-log", "-a", type=click.Path(path_type=Path), default="audit.db",
              help="Path to SQLite audit log database")
@click.option("--agent", type=str, default=None, help="Filter by agent ID")
@click.option("--limit", type=int, default=50, help="Number of logs to show")
@click.option("--json", "output_json", is_flag=True, help="Output logs in JSON format")
def logs(audit_log: Path, agent: str | None, limit: int, output_json: bool) -> None:
    """View structured audit logs."""
    if not audit_log.exists():
        if not output_json:
            click.echo(f"Audit log not found at {audit_log}")
        return

    audit = AuditLogger(db_path=audit_log)
    events = audit.get_events(agent_id=agent, limit=limit)
    
    if not events:
        if not output_json:
            click.echo("No audit events found.")
        return
        
    if output_json:
        click.echo(json.dumps(events, indent=2))
        return

    for ev in events:
        decision_color = "green" if ev["decision"] == "pass" else "red"
        click.echo(f"[{ev['timestamp']}] ", nl=False)
        click.secho(f"{ev['decision'].upper()}", fg=decision_color, nl=False)
        click.echo(f" Agent: {ev['agent_id']} Tool: {ev['task_context']} Category: {ev.get('risk_category', '-')}")


@main.command(name="trace")
@click.argument("trace_id", type=str)
@click.option("--audit-log", "-a", type=click.Path(path_type=Path), default="audit.db")
def trace(trace_id: str, audit_log: Path) -> None:
    """View a detailed execution trace."""
    if not audit_log.exists():
        click.echo(f"Audit log not found at {audit_log}")
        return
        
    audit = AuditLogger(db_path=audit_log)
    events = audit.get_events(limit=1000)
    
    found = [e for e in events if e.get("entry_hash") == trace_id or e.get("payload_hash") == trace_id]
    if not found:
        click.echo(f"Trace {trace_id} not found.")
        return
        
    for ev in found:
        click.echo("=" * 60)
        click.echo(f"Trace ID:      {trace_id}")
        click.echo(f"Agent ID:      {ev['agent_id']}")
        click.echo(f"Tool:          {ev['task_context']}")
        click.echo(f"Decision:      {ev['decision']}")
        click.echo(f"Reason:        {ev.get('reason')}")
        click.echo(f"Risk Score:    {ev.get('risk_score')}")
        click.echo("=" * 60)


@main.command(name="eu-ai-act")
@click.argument("src_path", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=Path("eu-ai-act-report.html"),
              help="Path to save the generated HTML report")
@click.option("--audit-log", "-a", type=click.Path(exists=True, path_type=Path), default=None,
              help="Path to an existing audit.db SQLite database")
def eu_ai_act(src_path: Path, output: Path, audit_log: Path | None) -> None:
    """Generate an EU AI Act compliance evidence report."""
    from jinja2 import Template
    from capfence.check import scan_file, scan_directory
    from capfence.core.audit import AuditLogger

    # a. Scan source directory for tool gating coverage
    if src_path.is_file():
        findings = scan_file(src_path)
    else:
        findings = scan_directory(src_path)

    total_tools = len(findings)
    ungated_tools = [f.name for f in findings if not f.is_wrapped]
    ungated_count = len(ungated_tools)
    gated_count = total_tools - ungated_count

    ratio = (gated_count / total_tools) if total_tools > 0 else 1.0
    article_9_status = "PASS" if ratio >= 0.8 else "FAIL"

    # b. Audit log metrics
    total_decisions = 0
    block_rate = 0.0
    decisions_by_actor: dict[str, int] = {}
    article_12_status = "NOT ASSESSED"

    if audit_log:
        try:
            audit = AuditLogger(db_path=audit_log)
            chain_valid, _ = audit.verify()
            article_12_status = "PASS" if chain_valid else "FAIL"
            
            events = audit.get_events(limit=10000)
            total_decisions = len(events)
            if total_decisions > 0:
                blocked = sum(1 for e in events if str(e.get("decision", "")).lower() in ("fail", "deny", "block", "blocked", "fail-closed"))
                block_rate = (blocked / total_decisions) * 100.0
                for e in events:
                    actor = e.get("agent_id") or "unknown"
                    decisions_by_actor[actor] = decisions_by_actor.get(actor, 0) + 1
        except Exception:
            article_12_status = "FAIL"

    # c. Transparency check (policy config files)
    policy_detected = False
    if src_path.is_dir():
        for p in src_path.rglob("*"):
            if p.suffix in (".yaml", ".yml"):
                policy_detected = True
                break
    else:
        if src_path.suffix in (".yaml", ".yml"):
            policy_detected = True

    article_53_status = "PASS" if policy_detected else "NOT ASSESSED"

    # Premium dark mode / HSL-curated report layout
    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EU AI Act Compliance Evidence Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-color: #f8fafc;
            --text-secondary: #94a3b8;
            --primary: #38bdf8;
            --primary-gradient: linear-gradient(135deg, #38bdf8 0%, #0369a1 100%);
            --border-color: #334155;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --info: #6366f1;
        }

        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 40px 20px;
            display: flex;
            justify-content: center;
        }

        .container {
            max-width: 900px;
            width: 100%;
        }

        .header {
            text-align: center;
            margin-bottom: 50px;
            background: var(--primary-gradient);
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }

        .header h1 {
            margin: 0 0 10px 0;
            font-size: 2.5rem;
            font-weight: 700;
            letter-spacing: -0.05em;
        }

        .header p {
            margin: 0;
            color: #e0f2fe;
            font-size: 1.1rem;
            font-weight: 300;
        }

        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.25);
        }

        .card h2 {
            margin-top: 0;
            font-size: 1.5rem;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 12px;
            margin-bottom: 20px;
            color: var(--primary);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .status-badge {
            font-size: 0.85rem;
            padding: 6px 16px;
            border-radius: 9999px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .status-pass {
            background-color: rgba(16, 185, 129, 0.15);
            color: var(--success);
            border: 1px solid var(--success);
        }

        .status-fail {
            background-color: rgba(239, 68, 68, 0.15);
            color: var(--danger);
            border: 1px solid var(--danger);
        }

        .status-na {
            background-color: rgba(148, 163, 184, 0.15);
            color: var(--text-secondary);
            border: 1px solid var(--text-secondary);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }

        th, td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
        }

        th {
            color: var(--text-secondary);
            font-weight: 500;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 0.05em;
        }

        .metric-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 15px;
        }

        .metric-card {
            background-color: rgba(15, 23, 42, 0.3);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }

        .metric-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--primary);
            margin-bottom: 4px;
        }

        .metric-label {
            font-size: 0.85rem;
            color: var(--text-secondary);
        }

        .disclaimer {
            background-color: rgba(245, 158, 11, 0.05);
            border-left: 4px solid var(--warning);
            padding: 20px;
            border-radius: 0 12px 12px 0;
            margin-top: 40px;
            font-size: 0.9rem;
            line-height: 1.6;
        }

        .disclaimer-title {
            font-weight: 600;
            color: var(--warning);
            margin-bottom: 6px;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 0.05em;
        }

        .disclaimer-text {
            color: var(--text-secondary);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>EU AI Act Evidence Report</h1>
            <p>Generated by CapFence Technical Compliance Scanner</p>
        </div>

        <!-- Scanned Source Info -->
        <div class="card">
            <h2>Scan Scope</h2>
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">{{ total_tools }}</div>
                    <div class="metric-label">Total Tools Scanned</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: var(--success);">{{ gated_count }}</div>
                    <div class="metric-label">Gated Tools</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: {% if ungated_count > 0 %}var(--danger){% else %}var(--text-secondary){% endif %};">{{ ungated_count }}</div>
                    <div class="metric-label">Ungated Tools</div>
                </div>
            </div>
        </div>

        <!-- Article 9 -->
        <div class="card">
            <h2>
                Article 9: Risk Management
                <span class="status-badge status-{{ article_9_status|lower }}">{{ article_9_status }}</span>
            </h2>
            <p>High-risk AI systems require established risk management systems. CapFence enforces deterministic safety thresholds via runtime tool gating.</p>
            {% if article_9_status == "FAIL" %}
            <p style="color: var(--danger); font-weight: 500;">Warning: The following tools do not have runtime enforcement filters wrapped:</p>
            <ul>
                {% for tool in ungated_tools %}
                <li><code>{{ tool }}</code></li>
                {% endfor %}
            </ul>
            {% else %}
            <p style="color: var(--success); font-weight: 500;">✓ Minimum required tool-gating threshold is met (&ge; 80% coverage).</p>
            {% endif %}
        </div>

        <!-- Article 12 -->
        <div class="card">
            <h2>
                Article 12: Record Keeping
                <span class="status-badge status-{{ article_12_status|lower }}">{{ article_12_status }}</span>
            </h2>
            <p>Requires high-risk AI systems to automatically log execution events to enable traceability and auditing. CapFence maintains a cryptographically signed, SHA-256 hash-chained immutable audit trail.</p>
            {% if article_12_status == "PASS" %}
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">{{ total_decisions }}</div>
                    <div class="metric-label">Decisions Logged</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" style="color: var(--warning);">{{ "%.1f"|format(block_rate) }}%</div>
                    <div class="metric-label">Enforcement Block Rate</div>
                </div>
            </div>
            <h3 style="margin-top: 25px; font-size: 1rem; color: var(--text-secondary);">Decisions by Autonomous Agent:</h3>
            <table>
                <thead>
                    <tr>
                        <th>Agent / Actor</th>
                        <th>Logged Requests</th>
                    </tr>
                </thead>
                <tbody>
                    {% for actor, count in decisions_by_actor.items() %}
                    <tr>
                        <td><code>{{ actor }}</code></td>
                        <td>{{ count }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% elif article_12_status == "FAIL" %}
            <p style="color: var(--danger); font-weight: 500;">✗ Audit trail validation failed. The cryptographic chain has been broken or tampered with.</p>
            {% else %}
            <p style="color: var(--text-secondary);">Audit metrics were not assessed because no <code>--audit-log</code> SQLite file path was provided.</p>
            {% endif %}
        </div>

        <!-- Article 53 -->
        <div class="card">
            <h2>
                Article 53: Transparency
                <span class="status-badge status-{{ article_53_status|lower }}">{{ article_53_status }}</span>
            </h2>
            <p>Requires technical documentation and transparency in policy constraints. CapFence implements deterministic runtime policy rules defined via transparent YAML configuration files.</p>
            {% if article_53_status == "PASS" %}
            <p style="color: var(--success); font-weight: 500;">✓ Declarative CapFence policy YAML configuration detected within scan directory.</p>
            {% else %}
            <p style="color: var(--text-secondary);">No declarative policy configuration YAML files were detected inside the scanned path.</p>
            {% endif %}
        </div>

        <!-- Disclaimer -->
        <div class="disclaimer">
            <div class="disclaimer-title">Legal Disclaimer</div>
            <div class="disclaimer-text">
                CapFence provides technical evidence. It does not determine legal classification, regulatory obligations, or final compliance status.
            </div>
        </div>
    </div>
</body>
</html>"""

    template = Template(html_template)
    rendered_html = template.render(
        total_tools=total_tools,
        gated_count=gated_count,
        ungated_count=ungated_count,
        ungated_tools=ungated_tools,
        article_9_status=article_9_status,
        article_12_status=article_12_status,
        total_decisions=total_decisions,
        block_rate=block_rate,
        decisions_by_actor=decisions_by_actor,
        article_53_status=article_53_status,
    )

    with open(output, "w", encoding="utf-8") as f:
        f.write(rendered_html)

    click.echo(f"EU AI Act evidence report written to {output}")


@main.group(name="taxonomy")
def taxonomy() -> None:
    """Manage and inspect risk taxonomies."""
    pass


@taxonomy.command(name="list")
@click.option("--domain", "-d", type=str, default=None, help="Filter by taxonomy domain")
@click.option("--format", "-f", "output_format", type=click.Choice(["table", "json"]), default="table",
              help="Output format (table or json)")
def list_taxonomy(domain: str | None, output_format: str) -> None:
    """List all categories, descriptions, and mapped capabilities from risk taxonomies."""
    from capfence.core.capabilities import TAXONOMY_TO_CAPABILITY

    taxonomies_dir = Path(__file__).parent / "taxonomies"
    if not taxonomies_dir.exists():
        click.echo(f"Taxonomy directory not found at {taxonomies_dir}", err=True)
        sys.exit(1)

    all_data = []
    
    # Read all JSON files
    for p in sorted(taxonomies_dir.glob("*.json")):
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            domain_name = data.get("domain", p.stem)
            
            # Filter by domain if requested
            if domain and domain_name.lower() != domain.lower():
                continue
                
            categories = data.get("categories", {})
            for cat_name, cat_info in categories.items():
                mapped_cap = TAXONOMY_TO_CAPABILITY.get(cat_name, "-")
                all_data.append({
                    "domain": domain_name,
                    "category": cat_name,
                    "description": cat_info.get("description", ""),
                    "capability": mapped_cap,
                })
        except Exception as e:
            click.echo(f"Warning: Failed to load taxonomy file {p.name}: {e}", err=True)

    if output_format == "json":
        click.echo(json.dumps(all_data, indent=2))
        return

    # Print table
    if not all_data:
        click.echo("No matching taxonomies found.")
        return

    # Group by domain
    current_domain = None
    for item in all_data:
        if item["domain"] != current_domain:
            current_domain = item["domain"]
            click.echo(f"\nDomain: {current_domain.upper()}")
            click.echo(f"{'Category':<30} {'Capability Scope':<30} {'Description'}")
            click.echo("-" * 100)
        
        desc = item["description"]
        if len(desc) > 37:
            desc = desc[:34] + "..."
        click.echo(f"{item['category']:<30} {item['capability']:<30} {desc}")


if __name__ == "__main__":
    main()
