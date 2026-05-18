import pytest
from click.testing import CliRunner
from pathlib import Path

from capfence.cli import main
from capfence.core.audit import AuditLogger


def test_cli_eu_ai_act_not_assessed(tmp_path):
    # Create a dummy folder without tools or yaml
    src = tmp_path / "dummy_src"
    src.mkdir()
    
    # Create a simple python file with no tools
    (src / "app.py").write_text("print('hello')")
    
    runner = CliRunner()
    output_report = tmp_path / "report.html"
    
    result = runner.invoke(main, ["eu-ai-act", str(src), "--output", str(output_report)])
    
    assert result.exit_code == 0
    assert f"EU AI Act evidence report written to {output_report}" in result.output
    assert output_report.exists()
    
    report_content = output_report.read_text()
    # Disclaimer must be present
    assert "CapFence provides technical evidence" in report_content
    # Article 9 must be PASS since 0 tools = 100% gated
    assert "PASS" in report_content
    # Article 12 must be NOT ASSESSED because no audit log is provided
    assert "NOT ASSESSED" in report_content
    # Article 53 must be NOT ASSESSED because no policy yaml is present
    assert "NOT ASSESSED" in report_content


def test_cli_eu_ai_act_article_9_fail_and_article_53_pass(tmp_path):
    src = tmp_path / "dummy_src"
    src.mkdir()
    
    # Create a dummy langchain ungated tool class
    (src / "tool.py").write_text("""
from langchain.tools import BaseTool
class DangerousTool(BaseTool):
    name = "dangerous_shell_executor"
    description = "runs shell commands"
""")
    
    # Create policy.yaml to trigger Article 53 PASS
    (src / "policy.yaml").write_text("allow: []")
    
    runner = CliRunner()
    output_report = tmp_path / "report.html"
    
    result = runner.invoke(main, ["eu-ai-act", str(src), "--output", str(output_report)])
    
    assert result.exit_code == 0
    assert output_report.exists()
    
    report_content = output_report.read_text()
    # Article 9 must FAIL because we have 1 tool, 0 gated (0% < 80%)
    assert "FAIL" in report_content
    assert "DangerousTool" in report_content
    
    # Article 53 must PASS
    assert "PASS" in report_content


def test_cli_eu_ai_act_article_12_pass(tmp_path):
    src = tmp_path / "dummy_src"
    src.mkdir()
    (src / "app.py").write_text("print('hello')")
    
    # Create an audit log and record 1 decision
    from capfence import ActionEvent, ExecutionVerdict
    import time

    audit_db = tmp_path / "audit.db"
    audit = AuditLogger(db_path=audit_db, sign_entries=False)

    event = ActionEvent.create(
        actor="agent-compliance",
        action="test",
        resource="test",
        environment="production",
        risk="low"
    )
    verdict = ExecutionVerdict(
        authorized=True,
        decision="allow",
        reason="policy_allow",
        event=event,
        timestamp=time.time()
    )
    audit.record_event(verdict)
    
    runner = CliRunner()
    output_report = tmp_path / "report.html"
    
    result = runner.invoke(main, [
        "eu-ai-act",
        str(src),
        "--output",
        str(output_report),
        "--audit-log",
        str(audit_db)
    ])
    
    assert result.exit_code == 0
    assert output_report.exists()
    
    report_content = output_report.read_text()
    # Article 12 must be PASS because audit log is provided and chain is valid
    assert "PASS" in report_content
    assert "agent-compliance" in report_content
