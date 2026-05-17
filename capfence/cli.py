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
from typing import Any

import click

from capfence.check import scan_directory, scan_file, compute_aggregate_score, ToolFinding
from capfence.core.audit import AuditLogger
from capfence.core.approvals import ApprovalManager
from capfence.core.policy import PolicyLoader
from capfence.core.replay import ReplayEngine

__version__ = "0.7.1"


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


if __name__ == "__main__":
    main()
