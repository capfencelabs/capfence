"""CapFence CLI entry point.

Commands:
    check           Scan codebase for ungated AI agent tools
    assess          Generate detailed HTML assessment report
    simulate        Replay agent traces through CapFence gate
    build-taxonomy  Interactive taxonomy builder
    verify          Verify hash-chain integrity of an audit log
    tune            Analyze audit log and suggest threshold adjustments

Usage:
    capfence check ./src
    capfence check ./src --output report.html
    capfence check ./src --framework=langchain --fail-on-ungated
    capfence simulate --trace-file agent_trace.jsonl --compare
    capfence build-taxonomy
    capfence verify --audit-log audit.db
    capfence tune --audit-log audit.db
"""

from __future__ import annotations

import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import click

from capfence.check import scan_directory, scan_file, compute_aggregate_score, ToolFinding
from capfence.assessment.scanner import scan_assessment, AssessmentData
from capfence.assessment.reporter import generate_html_report
from capfence.assessment.simulator import TraceSimulator
from capfence.assessment.builder import TaxonomyBuilder
from capfence.assessment.owasp import generate_owasp_context
from capfence.assessment.eu_ai_act import generate_evidence_pack
from capfence.core.audit import AuditLogger
from capfence.core.approvals import ApprovalManager
from capfence.core.policy import PolicyLoader


__version__ = "0.6.2"


@click.group()
@click.version_option(version=__version__, prog_name="capfence")
def main() -> None:
    """CapFence — fail-closed deterministic enforcement for AI agent tool calls."""
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
@click.option("--framework", "-f", type=str, default=None,
              help="Filter by framework (langchain, crewai, autogen)")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Write HTML report to file")
@click.option("--fail-on-ungated", is_flag=True,
              help="Exit with non-zero code if ungated high-risk tools found")
@click.option("--strict", is_flag=True,
              help="Exit with non-zero code if ANY ungated tools are found")
@click.option("--report-json", is_flag=True,
              help="Output findings in JSON format to stdout")
def check(
    path: Path,
    framework: str | None,
    output: Path | None,
    fail_on_ungated: bool,
    strict: bool,
    report_json: bool,
) -> None:
    """Scan Python files for ungated AI agent tool classes."""
    if path.is_file():
        findings = scan_file(path)
    else:
        findings = scan_directory(path)

    if framework:
        framework_lower = framework.lower()
        findings = [f for f in findings if f.framework and f.framework.lower() == framework_lower]

    if report_json:
        # Output JSON only
        out = [{"name": f.name, "file": str(f.file), "line": f.line, "framework": f.framework, "category": f.category, "risk_delta": f.risk_delta, "is_wrapped": f.is_wrapped} for f in findings]
        click.echo(json.dumps(out, indent=2))
    else:
        _print_findings(findings, path)

    if output:
        _write_html_report(findings, output, path)
        if not report_json:
            click.echo(f"\nReport written to: {output}")

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

    click.echo()
    click.echo("[ASSESSMENT] Run capfence assess for detailed HTML report.")


def _rel_path(file_path: Path, base_path: Path) -> str:
    try:
        return str(file_path.relative_to(base_path))
    except ValueError:
        return file_path.name


def _write_html_report(findings: list[ToolFinding], output: Path, path: Path) -> None:
    from capfence.assessment.scanner import AssessmentData, enrich_finding
    tools = [enrich_finding(f, None) for f in findings]
    data = AssessmentData(path=path, taxonomy_name=None, tools=tools)
    generate_html_report(data, output_path=output)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Write detailed HTML assessment report")
@click.option("--taxonomy", "-t", type=str, default=None,
              help="Taxonomy to use (general, financial, legal, or path)")
@click.option("--compliance", "-c", is_flag=True,
              help="Include SOX/PCI-DSS compliance mapping in report")
def assess(path: Path, output: Path | None, taxonomy: str | None, compliance: bool) -> None:
    """Generate detailed HTML assessment report with taxonomy enrichment."""
    click.echo(f"[ASSESS] Running assessment on {path}...")
    if taxonomy:
        click.echo(f"[ASSESS] Using taxonomy: {taxonomy}")

    data = scan_assessment(path, taxonomy_path=taxonomy)

    click.echo(f"\n[RESULT] Risk Score: {data.risk_score}/100 ({data.risk_label})")
    click.echo(f"  Total tools: {data.total_tools}")
    click.echo(f"  Gated: {data.gated_count}")
    click.echo(f"  Ungated: {data.ungated_count}")
    if data.critical_ungated > 0:
        click.echo(f"  Critical ungated: {data.critical_ungated}")
    click.echo(f"  Coverage: {data.coverage_percent}%")

    if compliance:
        report_path = output or Path("capfence-compliance-report.html")
        from capfence.assessment.reporter import _get_template_dir, _risk_color, _risk_bg
        tpl_dir = _get_template_dir()
        import jinja2
        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(tpl_dir)),
            autoescape=jinja2.select_autoescape(["html", "xml"]),
        )
        env.filters["risk_color"] = _risk_color
        env.filters["risk_bg"] = _risk_bg
        try:
            template = env.get_template("report_compliance.html")
            ctx = data.to_dict()
            ctx["version"] = __version__
            ctx["compliance_mappings"] = _get_compliance_context(data)
            html = template.render(**ctx)
            report_path.write_text(html, encoding="utf-8")
        except jinja2.TemplateNotFound:
            generate_html_report(data, output_path=report_path)
    else:
        report_path = output or Path("capfence-assessment-report.html")
        generate_html_report(data, output_path=report_path)

    click.echo(f"\nAssessment report written to: {report_path}")

    if data.critical_ungated > 0:
        click.echo("\nAssessment: CRITICAL ungated tools found.", err=True)
        sys.exit(2)
    elif data.ungated_count > 0:
        click.echo("\nAssessment: Ungated tools found.", err=True)
        sys.exit(1)


def _get_compliance_context(data: AssessmentData) -> dict[str, Any]:
    """Generate compliance context for template rendering."""
    return {
        "sox_302": "AgentStateStore tracks all decisions for corporate responsibility reporting.",
        "sox_404": "AuditLogger provides append-only decision log for internal control assessment.",
        "pci_dss_3_4": "Hash module ensures payload integrity, rendering sensitive data unreadable.",
        "pci_dss_10_2": "All gate decisions logged with timestamp, agent ID, and payload hash.",
        "pci_dss_6_5": "Gate prevents unauthorized tool execution, addressing common coding vulnerabilities.",
    }


@main.command()
@click.argument("policy_file", type=click.Path(exists=True, path_type=Path), required=False)
@click.option("--trace-file", "-t", type=click.Path(exists=True, path_type=Path), required=False,
              help="Path to JSONL trace file")
@click.option("--taxonomy", type=str, default="general",
              help="Taxonomy to use for simulation")
@click.option("--taxonomy-pack", "-p", type=str, multiple=True,
              help="Additional taxonomy packs to evaluate (multi-pack mode)")
@click.option("--compare", is_flag=True,
              help="Show static vs adaptive side-by-side comparison")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Write simulation report to JSON file")
def simulate(
    policy_file: Path | None,
    trace_file: Path | None,
    taxonomy: str,
    taxonomy_pack: tuple[str, ...],
    compare: bool,
    output: Path | None,
) -> None:
    """Replay agent execution traces through CapFence gate or simulate a custom policy."""
    if policy_file is not None:
        # Run custom policy simulation using ReplayEngine
        from capfence.core.replay import ReplayEngine
        
        # Determine trace file to use
        t_file = trace_file
        if not t_file:
            for candidate in ("incident.json", "agent_trace.jsonl", "trace.jsonl", "trace.json"):
                if Path(candidate).exists():
                    t_file = Path(candidate)
                    break
        
        if not t_file:
            # Create a quick mock/demo trace file if none exists so the command always works and wows the user!
            t_file = Path("incident_demo.json")
            demo_events = [
                {"actor": "coding-agent", "action": "push", "resource": "github.push.main", "environment": "production", "risk": "high"},
                {"actor": "ops-agent", "action": "execute", "resource": "deployment.execute.production", "environment": "production", "risk": "critical"},
                {"actor": "finance-agent", "action": "transfer", "resource": "payment.execute.high_value", "environment": "production", "risk": "high"},
                {"actor": "coding-agent", "action": "delete", "resource": "filesystem.delete.workspace", "environment": "development", "risk": "medium"},
            ]
            t_file.write_text(json.dumps(demo_events, indent=2), encoding="utf-8")
            click.echo(f"[SIMULATE] No trace file specified, generated temporary demo trace: {t_file}")

        click.echo(f"[SIMULATE] Simulating custom policy '{policy_file}' on trace '{t_file}'...")
        engine = ReplayEngine()
        summary = engine.simulate_policy(t_file, policy_file)
        
        click.echo()
        click.echo("=" * 60)
        click.echo(f"Simulation Summary for {policy_file}:")
        click.echo(f"  Total replayed:     {summary.total_events}")
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
        return

    # Fallback to legacy TraceSimulator
    if not trace_file:
        click.echo("[ERROR] Please provide --trace-file or specify a policy file.", err=True)
        sys.exit(1)

    click.echo(f"[SIMULATE] Replaying trace: {trace_file}")
    click.echo(f"[SIMULATE] Primary taxonomy: {taxonomy}")
    if taxonomy_pack:
        click.echo(f"[SIMULATE] Additional packs: {', '.join(taxonomy_pack)}")

    sim = TraceSimulator(taxonomy_path=taxonomy, taxonomy_paths=list(taxonomy_pack) if taxonomy_pack else None)
    summary = sim.run(trace_file=trace_file, verbose=False)

    click.echo()
    click.echo(f"Replayed {summary.total_calls} tool call(s):")
    click.echo(f"  Static rules blocked:     {summary.static_blocked}")
    click.echo(f"  Adaptive would block:     {summary.adaptive_blocked}")
    click.echo(f"  Additional flagged:       {summary.adaptive_additional_blocks}")

    if compare:
        click.echo()
        click.echo(f"{'Call ID':<10} {'Tool':<25} {'Static':<10} {'Adaptive':<10} {'Gap':<10}")
        click.echo("-" * 65)
        for r in summary.results:
            static_status = "BLOCKED" if r.static_blocked else "OK"
            adaptive_status = "BLOCKED" if r.adaptive_blocked else "OK"
            gap = (
                "{:.2f}".format(r.adaptive_delta)
                if r.adaptive_delta is not None else "-"
            )
            click.echo(f"{r.call_id:<10} {r.tool_name:<25} {static_status:<10} {adaptive_status:<10} {gap:<10}")

    if summary.patterns:
        click.echo()
        click.echo("[PATTERNS DETECTED]")
        for p in summary.patterns:
            click.echo(f"  {p}")

    click.echo()
    click.echo(f"[RECOMMENDATION] {summary.recommendation}")

    if output:
        out = {
            "total_calls": summary.total_calls,
            "static_blocked": summary.static_blocked,
            "adaptive_blocked": summary.adaptive_blocked,
            "adaptive_additional_blocks": summary.adaptive_additional_blocks,
            "patterns": summary.patterns,
            "recommendation": summary.recommendation,
            "details": [
                {
                    "call_id": r.call_id,
                    "tool_name": r.tool_name,
                    "static_blocked": r.static_blocked,
                    "adaptive_blocked": r.adaptive_blocked,
                    "adaptive_delta": r.adaptive_delta,
                }
                for r in summary.results
            ],
        }
        output.write_text(json.dumps(out, indent=2), encoding="utf-8")
        click.echo(f"\nSimulation report written to: {output}")


@main.command(name="build-taxonomy")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Output path for generated taxonomy JSON")
def build_taxonomy(output: Path | None) -> None:
    """Interactive taxonomy builder."""
    builder = TaxonomyBuilder()
    taxonomy = builder.interactive_build()

    path = output or Path(f"custom_taxonomy_{taxonomy['domain']}.json")
    builder.save(taxonomy, path)
    click.echo(f"\nTaxonomy saved to: {path}")


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


@main.command(name="owasp")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Write OWASP coverage matrix HTML report")
def owasp(output: Path | None) -> None:
    """Generate OWASP Agentic Top 10 coverage matrix."""
    ctx = generate_owasp_context()
    summary = ctx["summary"]
    click.echo("[OWASP] Agentic AI Top 10 Coverage Matrix")
    click.echo()
    click.echo(f"  Full coverage:     {summary['full']}")
    click.echo(f"  Partial coverage:  {summary['partial']}")
    click.echo(f"  Planned:           {summary['planned']}")
    click.echo(f"  Not applicable:    {summary['not_applicable']}")
    click.echo(f"  Covered:           {summary['covered']}/{summary['total']} ({summary['coverage_percent']}%)")
    click.echo()
    click.echo(f"{'ID':<6} {'Risk':<30} {'Covered':<10} {'Level':<12}")
    click.echo("-" * 70)
    for item in ctx["items"]:
        covered = "Yes" if item["covered"] else "No"
        click.echo(f"{item['risk_id']:<6} {item['risk_name']:<30} {covered:<10} {item['coverage_level']:<12}")

    if output:
        from capfence.assessment.reporter import _get_template_dir, _risk_color, _risk_bg
        tpl_dir = _get_template_dir()
        import jinja2
        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(tpl_dir)),
            autoescape=jinja2.select_autoescape(["html", "xml"]),
        )
        env.filters["risk_color"] = _risk_color
        env.filters["risk_bg"] = _risk_bg
        try:
            template = env.get_template("report_owasp.html")
            html = template.render(**ctx)
            output.write_text(html, encoding="utf-8")
            click.echo(f"\nOWASP report written to: {output}")
        except jinja2.TemplateNotFound:
            click.echo("[ERROR] report_owasp.html template not found.", err=True)
            sys.exit(1)


@main.command(name="eu-ai-act")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--taxonomy", "-t", type=str, default="general",
              help="Taxonomy to use for assessment")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Write EU AI Act evidence pack HTML report")
@click.option("--json-output", "j", type=click.Path(path_type=Path), default=None,
              help="Write EU AI Act evidence pack JSON file")
@click.option("--system-name", type=str, default="CapFence-Governed Agent",
              help="System name for the evidence pack")
def eu_ai_act(path: Path, taxonomy: str, output: Path | None, j: Path | None, system_name: str) -> None:
    """Generate EU AI Act Annex IV evidence pack from codebase assessment."""
    click.echo(f"[EU AI ACT] Assessing {path} with taxonomy '{taxonomy}'...")
    data = scan_assessment(path, taxonomy_path=taxonomy)
    pack = generate_evidence_pack(data, system_name=system_name)

    click.echo(f"  Risk score: {pack.risk_management.get('risk_score', 'N/A')}")
    click.echo(f"  Risk label: {pack.risk_management.get('risk_label', 'N/A')}")
    click.echo(f"  Tools: {pack.risk_management.get('tool_count', 0)}")
    click.echo(f"  Ungated: {pack.risk_management.get('ungated_tools', 0)}")
    click.echo(f"  Critical ungated: {pack.risk_management.get('critical_ungated', 0)}")

    if output:
        pack.write_html(output)
        click.echo(f"\nEvidence pack (HTML) written to: {output}")

    if j:
        pack.write_json(j)
        click.echo(f"Evidence pack (JSON) written to: {j}")


@main.command(name="tune")
@click.option("--audit-log", "-a", type=click.Path(exists=True, path_type=Path), required=True,
              help="Path to SQLite audit log database")
@click.option("--agent-id", type=str, default=None,
              help="Filter to a specific agent (default: all agents)")
@click.option("--window", type=int, default=200,
              help="Number of recent decisions to analyse (default: 200)")
@click.option("--false-positive-budget", type=float, default=0.05,
              help="Acceptable false-positive rate (default: 0.05 = 5%)")
def tune(
    audit_log: Path,
    agent_id: str | None,
    window: int,
    false_positive_budget: float,
) -> None:
    """Analyse audit log and suggest per-category threshold adjustments.

    Reads recent gate decisions from the audit log and identifies categories
    where the current threshold is either too tight (high block rate on
    low-risk payloads) or too loose (low block rate despite risky payloads).

    Prints per-category recommendations you can apply to your taxonomy file.
    """
    audit = AuditLogger(db_path=audit_log)
    events = audit.get_events(agent_id=agent_id, limit=window)

    if not events:
        click.echo("[TUNE] No events found in audit log.", err=True)
        sys.exit(1)

    click.echo(f"[TUNE] Analysing {len(events)} recent decisions"
               + (f" for agent '{agent_id}'" if agent_id else "") + "...")
    click.echo()

    # Group by risk_category
    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        cat = ev.get("risk_category") or "unknown"
        by_category[cat].append(ev)

    has_suggestions = False
    click.echo(f"{'Category':<30} {'N':<6} {'BlockRate':<12} {'AvgScore':<12} {'CurrThresh':<12} {'Suggestion'}")
    click.echo("-" * 95)

    for category, evts in sorted(by_category.items()):
        scores = [e["risk_score"] for e in evts if e.get("risk_score") is not None]
        thresholds = [e["threshold"] for e in evts if e.get("threshold") is not None]
        blocked = sum(1 for e in evts if e["decision"] == "fail")

        if not scores or not thresholds:
            continue

        avg_score = statistics.mean(scores)
        block_rate = blocked / len(evts)
        curr_threshold = thresholds[-1]  # most recent threshold

        # Suggest raising threshold if block rate >> false_positive_budget
        # and most scores are low (suggesting false positives dominate)
        p95_score = sorted(scores)[int(len(scores) * 0.95)]
        suggestion = "OK"

        if block_rate > false_positive_budget and avg_score < curr_threshold * 0.5:
            # Blocking a lot but avg score is well below threshold — likely false positives
            suggestion = f"RAISE to ~{round(p95_score * 1.1, 3)} (high block rate, low avg score)"
        elif block_rate == 0 and avg_score > curr_threshold * 0.7:
            # Never blocking but scores are getting close — threshold may be too loose
            suggestion = f"LOWER to ~{round(avg_score * 0.9, 3)} (never blocking, scores approaching threshold)"
        elif block_rate > 0.5:
            suggestion = f"RAISE to ~{round(p95_score * 1.05, 3)} (>50% block rate)"
        has_suggestions = has_suggestions or suggestion != "OK"

        click.echo(
            f"{category:<30} {len(evts):<6} {block_rate:<12.1%} {avg_score:<12.3f} "
            f"{curr_threshold:<12.3f} {suggestion}"
        )

    click.echo()
    if has_suggestions:
        click.echo("[TUNE] Suggestions found. Review and apply to your taxonomy JSON.")
        click.echo("       Test each change with: capfence simulate --trace-file <file> --compare")
    else:
        click.echo("[TUNE] Current thresholds look well-calibrated for this window.")

    click.echo()
    click.echo("[TUNE] Tip: run with --false-positive-budget 0.01 for stricter calibration.")


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
        import json
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
        
    # Assuming trace_id can be mapped to an agent_id or event hash for now.
    # We will search by payload_hash or agent_id for demo.
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

@main.command(name="replay")
@click.argument("trace_file", type=click.Path(exists=True, path_type=Path))
@click.option("--policy", "-p", type=click.Path(exists=True, path_type=Path), default=None,
              help="Simulate a custom policy file during replay")
def replay(trace_file: Path, policy: Path | None) -> None:
    """Deterministic trace replay and policy simulation for autonomous systems."""
    from capfence.core.replay import ReplayEngine
    
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

if __name__ == "__main__":
    main()
