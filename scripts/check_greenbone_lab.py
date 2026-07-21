"""Print non-destructive Greenbone lab readiness checks."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.lab.greenbone_preflight import run_preflight  # noqa: E402


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run non-destructive readiness checks for an authorized Greenbone lab.")
    parser.add_argument("--compose-file", help="Optional official Greenbone compose.yaml path")
    parser.add_argument("--gsa-url", help="Optional GSA HTTPS URL, for example https://127.0.0.1")
    parser.add_argument("--allow-self-signed", action="store_true", help="Explicitly disable TLS certificate verification for the local lab GSA check")
    parser.add_argument("--target-ip", help="Optional authorized lab target IP address")
    parser.add_argument("--target-port", type=int, help="Optional single TCP port for a basic reachability check")
    parser.add_argument("--minimum-free-gb", type=float, default=20.0, help="Warning threshold for free disk space (default: 20 GiB)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(argv)
    summary = run_preflight(
        compose_file=args.compose_file,
        gsa_url=args.gsa_url,
        allow_self_signed=args.allow_self_signed,
        target_ip=args.target_ip,
        target_port=args.target_port,
        minimum_free_gb=args.minimum_free_gb,
    )
    print("=== GREENBONE LAB PREFLIGHT (READ-ONLY) ===")
    for item in summary.checks:
        print(f"[{item.level.value}] {item.name}: {item.message}")
    print("No containers, scans, targets, credentials, or Docker settings were changed.")
    return summary.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
