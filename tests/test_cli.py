"""
CLI tests for TriageForge using Click CliRunner.
"""

from click.testing import CliRunner
from triageforge.cli import main


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "TriageForge" in result.output


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "diagnose" in result.output
    assert "list-faults" in result.output
    assert "inject" in result.output
    assert "recover" in result.output


def test_cli_list_faults():
    runner = CliRunner()
    result = runner.invoke(main, ["list-faults"])
    assert result.exit_code == 0
    assert "01_sg_block" in result.output
    assert "02_gunicorn_down" in result.output
    assert "03_disk_full" in result.output
    assert "04_pg_connections" in result.output
    assert "07_expired_tls" in result.output
    assert "09_oom_killed" in result.output
