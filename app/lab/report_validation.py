"""Read-only summaries for findings produced by the secure M3 parser."""

from __future__ import annotations

from dataclasses import dataclass

from app.parsers.openvas import OpenVASParseResult, ParsedSeverity


@dataclass(frozen=True)
class OpenVASReportSummary:
    findings_count: int
    unique_hosts: list[str]
    unique_cves: list[str]
    findings_without_cves: int
    cvss_distribution: dict[str, int]
    short_findings: list[str]


def summarize_openvas_report(
    parsed: OpenVASParseResult, *, include_examples: bool = False
) -> OpenVASReportSummary:
    distribution = {severity.value: 0 for severity in ParsedSeverity}
    for finding in parsed.findings:
        distribution[finding.severity.value] += 1
    examples = [_short_summary(finding) for finding in parsed.findings[:5]] if include_examples else []
    return OpenVASReportSummary(
        findings_count=len(parsed.findings),
        unique_hosts=sorted({finding.host for finding in parsed.findings}),
        unique_cves=sorted({cve for finding in parsed.findings for cve in finding.cve_ids}),
        findings_without_cves=sum(not finding.cve_ids for finding in parsed.findings),
        cvss_distribution=distribution,
        short_findings=examples,
    )


def _short_summary(finding) -> str:
    title = " ".join(finding.title.split())[:80]
    identities = ", ".join(finding.cve_ids[:3]) or finding.nvt_oid or "no CVE/NVT identity shown"
    return f"{finding.host} | CVSS {finding.cvss_score:.1f} | {identities} | {title}"
