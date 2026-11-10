"""
Test harness for validating all 10 fault specifications and test artifacts.
"""

import json
from pathlib import Path
import pytest

FAULTS_DIR = Path(__file__).resolve().parent.parent / "faults"

EXPECTED_FAULTS = [
    "01_sg_block",
    "02_gunicorn_down",
    "03_disk_full",
    "04_pg_connections",
    "05_missing_route",
    "06_bad_dns",
    "07_expired_tls",
    "08_iam_s3_denied",
    "09_oom_killed",
    "10_ssh_lockout",
]


@pytest.mark.parametrize("fault_id", EXPECTED_FAULTS)
def test_fault_directory_structure(fault_id):
    """Ensures each fault has break.sh, fix.sh, and valid expected.json."""
    fdir = FAULTS_DIR / fault_id
    assert fdir.is_dir(), f"Fault directory {fdir} does not exist"

    break_sh = fdir / "break.sh"
    fix_sh = fdir / "fix.sh"
    expected_json = fdir / "expected.json"

    assert break_sh.exists(), f"Missing break.sh in {fdir}"
    assert fix_sh.exists(), f"Missing fix.sh in {fdir}"
    assert expected_json.exists(), f"Missing expected.json in {fdir}"

    # Verify expected.json is valid JSON with required schema fields
    data = json.loads(expected_json.read_text(encoding="utf-8"))
    assert data.get("fault_type") == fault_id
    assert "expected_top_fault" in data
    assert "expected_layer_failure" in data
    assert "min_confidence" in data
    assert 0.0 <= data["min_confidence"] <= 1.0
