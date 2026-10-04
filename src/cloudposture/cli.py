"""Command line interface: ``cloudposture scan | list-checks | demo``."""
from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from cloudposture import __version__
from cloudposture.checks import REGISTRY
from cloudposture.config import ScanConfig, load_dotenv
from cloudposture.reporting import load_json, write_csv, write_json
from cloudposture.scoring import summarize

SAMPLE_PATH = Path(__file__).resolve().parents[2] / "sample_data" / "sample_scan.json"


def _print_summary(result) -> None:
    s = summarize(result.findings)
    m = result.metadata
    print(f"\nCloudPosture {m.tool_version} | account {m.account_id} | mode {m.mode}")
    rate = "n/a" if s.pass_rate is None else f"{s.pass_rate}%"
    print(f"Pass rate: {rate}  (passed {s.passed} / failed {s.failed}; "
          f"errors {s.errors}, n/a {s.not_applicable})")
    print("Failed by severity: " + ", ".join(f"{k}={b.failed}" for k, b in s.severity.items()))
    for fw in s.frameworks.values():
        r = "n/a" if fw.bucket.pass_rate is None else f"{fw.bucket.pass_rate}%"
        print(f"  {fw.framework:<9} {r:>7}  ({fw.checks_mapped}/{fw.checks_total} checks mapped)")


def _export(result, outdir: Path) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    csv_path = write_csv(result.findings, outdir / f"cloudposture_{stamp}.csv")
    json_path = write_json(result, outdir / f"cloudposture_{stamp}.json")
    print(f"CSV:  {csv_path}\nJSON: {json_path}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cloudposture", description="Read-only AWS security posture scanner")
    p.add_argument("--version", action="version", version=f"cloudposture {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Scan an AWS account (read-only)")
    scan.add_argument("--profile", help="AWS profile name (credentials come from the standard boto3 chain)")
    scan.add_argument("--home-region")
    scan.add_argument("--regions", help="Comma-separated regions (default: all enabled)")
    scan.add_argument("--role-arn", help="Optional read-only role to assume")
    scan.add_argument("--services", help="Comma-separated: IAM,S3,EC2,CloudTrail")
    scan.add_argument("--checks", help="Comma-separated check ids, e.g. IAM-001,S3-002")
    scan.add_argument("--output-dir", default="reports")

    sub.add_parser("list-checks", help="List all implemented checks")

    demo = sub.add_parser("demo", help="Show the bundled sample scan (no AWS credentials needed)")
    demo.add_argument("--output-dir", default=None, help="Also export CSV/JSON here")
    return p


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if args.cmd == "list-checks":
        for rc in sorted(REGISTRY.values(), key=lambda r: r.spec.id):
            s = rc.spec
            print(f"{s.id:<8} {s.service:<10} {s.severity.value:<9} {s.title}")
        print(f"\n{len(REGISTRY)} checks")
        return 0

    if args.cmd == "demo":
        result = load_json(SAMPLE_PATH)
        _print_summary(result)
        if args.output_dir:
            _export(result, Path(args.output_dir))
        return 0

    # scan
    from cloudposture.scanner import run_scan  # imported lazily so list-checks/demo need no AWS setup

    cfg = ScanConfig.from_env()
    if args.profile:
        cfg.profile = args.profile
    if args.home_region:
        cfg.home_region = args.home_region
    if args.regions:
        cfg.regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    if args.role_arn:
        cfg.role_arn = args.role_arn
    try:
        result = run_scan(
            cfg,
            services=[s.strip() for s in args.services.split(",")] if args.services else None,
            check_ids=[c.strip() for c in args.checks.split(",")] if args.checks else None,
        )
    except Exception as exc:  # surface credential/config problems cleanly
        print(f"Scan failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    _print_summary(result)
    _export(result, Path(args.output_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
