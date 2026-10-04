"""Regenerate sample_data/sample_scan.json.

Runs the REAL scanner against a fake AWS account built with moto (no AWS
credentials or network needed), then tags the result as mode="demo".
Requires dev dependencies: pip install -r requirements-dev.txt
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
             "AWS_DEFAULT_REGION": "us-east-1", "AWS_EC2_METADATA_DISABLED": "true"}.items():
    os.environ[k] = v
os.environ.pop("AWS_PROFILE", None)

from moto import mock_aws  # noqa: E402

from aws_env import build_demo_account  # noqa: E402
from cloudposture.config import ScanConfig  # noqa: E402
from cloudposture.reporting import write_csv, write_json  # noqa: E402
from cloudposture.scanner import run_scan  # noqa: E402

with mock_aws():
    build_demo_account()
    result = run_scan(ScanConfig(home_region="us-east-1", regions=["us-east-1"], credential_report_poll_seconds=0))

result.metadata.mode = "demo"
result.metadata.notes = [
    "DEMO DATA: produced by running the real scanner against a simulated AWS account (moto). "
    "Account ID and resources are fictional."
]
out = ROOT / "sample_data"
out.mkdir(exist_ok=True)
write_json(result, out / "sample_scan.json")
write_csv(result.findings, out / "sample_findings.csv")
print(f"{len(result.findings)} findings written to {out}")
