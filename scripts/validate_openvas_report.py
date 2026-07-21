"""Validate and summarize an OpenVAS XML report without database access."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.lab.report_validation import summarize_openvas_report  # noqa: E402
from app.parsers.openvas import parse_openvas  # noqa: E402


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Securely validate and summarize OpenVAS XML without writing to SQLite.")
    parser.add_argument("xml_report", help="Path to an OpenVAS XML report")
    parser.add_argument("--show-first-five", action="store_true", help="Print up to five short sanitized finding summaries")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(argv)
    parsed = parse_openvas(args.xml_report)
    summary = summarize_openvas_report(parsed, include_examples=args.show_first_five)
    print("=== OPENVAS REPORT VALIDATION (NO DATABASE) ===")
    print(f"Usable findings: {summary.findings_count}")
    print(f"Unique hosts ({len(summary.unique_hosts)}): {', '.join(summary.unique_hosts) or 'none'}")
    print(f"Unique CVEs ({len(summary.unique_cves)}): {', '.join(summary.unique_cves) or 'none'}")
    print(f"Findings without CVEs: {summary.findings_without_cves}")
    print("CVSS distribution: " + ", ".join(f"{key}={value}" for key, value in summary.cvss_distribution.items()))
    for issue in parsed.warnings:
        location = f" result {issue.result_index}" if issue.result_index else ""
        print(f"WARNING{location}: {issue.message}")
    for issue in parsed.errors:
        print(f"ERROR: {issue.message}")
    if summary.short_findings:
        print("First findings:")
        for item in summary.short_findings:
            print(f"  - {item}")
    return 1 if parsed.errors and not parsed.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
