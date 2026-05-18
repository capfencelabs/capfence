import pytest
from click.testing import CliRunner
from capfence.cli import main
from capfence.core.capabilities import TAXONOMY_TO_CAPABILITY


def test_cli_taxonomy_list_table():
    runner = CliRunner()
    result = runner.invoke(main, ["taxonomy", "list"])
    
    assert result.exit_code == 0
    assert "Domain: FINANCIAL" in result.output
    assert "stripe_payment_initiation" in result.output
    assert "payment.transfer.*" in result.output


def test_cli_taxonomy_list_json():
    runner = CliRunner()
    result = runner.invoke(main, ["taxonomy", "list", "--format", "json"])
    
    assert result.exit_code == 0
    assert "stripe_payment_initiation" in result.output
    assert "payment.transfer.*" in result.output
    # Must be valid json
    import json
    parsed = json.loads(result.output)
    assert len(parsed) > 0
    assert any(x["category"] == "stripe_payment_initiation" for x in parsed)


def test_cli_taxonomy_list_filter_domain():
    runner = CliRunner()
    result = runner.invoke(main, ["taxonomy", "list", "--domain", "legal"])
    
    assert result.exit_code == 0
    assert "Domain: LEGAL" in result.output
    assert "Domain: FINANCIAL" not in result.output


def test_taxonomy_mapping_completeness():
    # Make sure we have the critical categories mapped
    assert "stripe_payment_initiation" in TAXONOMY_TO_CAPABILITY
    assert TAXONOMY_TO_CAPABILITY["stripe_payment_initiation"] == "payment.transfer.*"
    assert "balance_inquiry" in TAXONOMY_TO_CAPABILITY
    assert TAXONOMY_TO_CAPABILITY["balance_inquiry"] == "payment.balance.*"
