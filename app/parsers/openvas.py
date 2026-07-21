"""Secure, database-independent parser for OpenVAS XML reports."""

from __future__ import annotations

import ipaddress
import math
import re
from enum import Enum
from pathlib import Path
from typing import IO
from xml.etree import ElementTree

from pydantic import BaseModel, Field, ValidationError, field_validator

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
HOST_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class ParsedSeverity(str, Enum):
    """Severity derived consistently from the numeric CVSS score."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ParsedFinding(BaseModel):
    """Normalized representation of one usable OpenVAS result."""

    host: str
    port: str | None = None
    title: str = Field(min_length=1)
    description: str | None = None
    cvss_score: float = Field(ge=0, le=10)
    severity: ParsedSeverity
    cve_ids: list[str] = Field(default_factory=list)
    solution: str | None = None
    threat: str | None = None
    nvt_oid: str | None = None

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        """Accept and normalize an IPv4 address, IPv6 address, or hostname."""
        cleaned = value.strip().rstrip(".")
        if not cleaned:
            raise ValueError("Host is required.")

        try:
            return str(ipaddress.ip_address(cleaned))
        except ValueError:
            pass

        if len(cleaned) > 253:
            raise ValueError("Hostname is longer than 253 characters.")
        labels = cleaned.split(".")
        if not all(HOST_LABEL_PATTERN.fullmatch(label) for label in labels):
            raise ValueError("Host must be a valid IP address or hostname.")
        return cleaned.lower()


class ParserIssue(BaseModel):
    """A warning or fatal error encountered while parsing a report."""

    result_index: int | None = None
    message: str


class OpenVASParseResult(BaseModel):
    """Usable findings plus non-fatal warnings and report-level errors."""

    findings: list[ParsedFinding] = Field(default_factory=list)
    warnings: list[ParserIssue] = Field(default_factory=list)
    errors: list[ParserIssue] = Field(default_factory=list)


def classify_severity(cvss_score: float) -> ParsedSeverity:
    """Map a CVSS score between 0 and 10 to the required severity level."""
    if not math.isfinite(cvss_score) or not 0 <= cvss_score <= 10:
        raise ValueError("CVSS score must be a finite number between 0 and 10.")
    if cvss_score == 0:
        return ParsedSeverity.INFORMATIONAL
    if cvss_score < 4:
        return ParsedSeverity.LOW
    if cvss_score < 7:
        return ParsedSeverity.MEDIUM
    if cvss_score < 9:
        return ParsedSeverity.HIGH
    return ParsedSeverity.CRITICAL


def normalize_cve_ids(values: list[str]) -> list[str]:
    """Extract valid CVE identifiers, uppercase them, and remove duplicates."""
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        for match in CVE_PATTERN.findall(value):
            cve_id = match.upper()
            if cve_id not in seen:
                seen.add(cve_id)
                normalized.append(cve_id)
    return normalized


def parse_openvas(
    source: str | Path | bytes | bytearray | IO[str] | IO[bytes],
) -> OpenVASParseResult:
    """Parse OpenVAS XML from a path, bytes, or readable file-like object."""
    parsed = OpenVASParseResult()
    try:
        xml_content = _read_xml_content(source)
    except (OSError, TypeError, ValueError) as exc:
        parsed.errors.append(ParserIssue(message=f"Could not read XML: {exc}"))
        return parsed

    if _contains_forbidden_xml_declaration(xml_content):
        parsed.errors.append(
            ParserIssue(
                message="DTD and entity declarations are not allowed in OpenVAS XML."
            )
        )
        return parsed

    try:
        root = ElementTree.fromstring(xml_content)
    except ElementTree.ParseError as exc:
        parsed.errors.append(ParserIssue(message=f"Malformed XML: {exc}"))
        return parsed

    result_elements = [
        element for element in root.iter() if _local_name(element.tag) == "result"
    ]
    for index, result_element in enumerate(result_elements, start=1):
        finding = _parse_result_element(result_element, index, parsed.warnings)
        if finding is not None:
            parsed.findings.append(finding)
    return parsed


def _read_xml_content(
    source: str | Path | bytes | bytearray | IO[str] | IO[bytes],
) -> bytes:
    if isinstance(source, (str, Path)):
        return Path(source).read_bytes()
    if isinstance(source, (bytes, bytearray)):
        return bytes(source)
    if hasattr(source, "read"):
        content = source.read()
        if isinstance(content, str):
            return content.encode("utf-8")
        if isinstance(content, bytes):
            return content
        raise TypeError("The file-like object must return text or bytes.")
    raise TypeError("Source must be a path, bytes, or a readable file-like object.")


def _contains_forbidden_xml_declaration(xml_content: bytes) -> bool:
    # Removing null bytes also detects declarations in UTF-16 encoded XML.
    security_probe = xml_content.replace(b"\x00", b"").upper()
    return b"<!DOCTYPE" in security_probe or b"<!ENTITY" in security_probe


def _parse_result_element(
    result_element: ElementTree.Element,
    result_index: int,
    warnings: list[ParserIssue],
) -> ParsedFinding | None:
    host = _find_text(result_element, "host")
    title = _find_text(result_element, "name")
    if not host or not title:
        missing = []
        if not host:
            missing.append("host")
        if not title:
            missing.append("title")
        warnings.append(
            ParserIssue(
                result_index=result_index,
                message=f"Skipped result because required field(s) are missing: {', '.join(missing)}.",
            )
        )
        return None

    cvss_score = _parse_cvss(
        _find_text(result_element, "severity"), result_index, warnings
    )
    cve_values = _collect_cve_values(result_element)
    nvt = _find_element(result_element, "nvt")

    try:
        return ParsedFinding(
            host=host,
            port=_find_text(result_element, "port"),
            title=title,
            description=_find_text(result_element, "description"),
            cvss_score=cvss_score,
            severity=classify_severity(cvss_score),
            cve_ids=normalize_cve_ids(cve_values),
            solution=_find_text(result_element, "solution"),
            threat=_find_text(result_element, "threat"),
            nvt_oid=nvt.attrib.get("oid", "").strip() or None if nvt is not None else None,
        )
    except ValidationError as exc:
        warnings.append(
            ParserIssue(
                result_index=result_index,
                message=f"Skipped result because normalized data is invalid: {exc.errors()[0]['msg']}.",
            )
        )
        return None


def _parse_cvss(
    raw_severity: str | None,
    result_index: int,
    warnings: list[ParserIssue],
) -> float:
    if raw_severity is None:
        warnings.append(
            ParserIssue(
                result_index=result_index,
                message="Missing severity; defaulted CVSS score to 0.0.",
            )
        )
        return 0.0
    try:
        score = float(raw_severity)
        classify_severity(score)
        return score
    except ValueError:
        warnings.append(
            ParserIssue(
                result_index=result_index,
                message=f"Invalid severity '{raw_severity}'; defaulted CVSS score to 0.0.",
            )
        )
        return 0.0


def _collect_cve_values(result_element: ElementTree.Element) -> list[str]:
    values: list[str] = []
    for element in result_element.iter():
        local_name = _local_name(element.tag)
        if local_name == "cve":
            text = _element_text(element)
            if text:
                values.append(text)
        elif local_name == "ref" and element.attrib.get("type", "").lower() == "cve":
            reference = element.attrib.get("id") or _element_text(element)
            if reference:
                values.append(reference)
    return values


def _find_element(
    parent: ElementTree.Element, local_name: str
) -> ElementTree.Element | None:
    return next(
        (
            element
            for element in parent.iter()
            if _local_name(element.tag) == local_name
        ),
        None,
    )


def _find_text(parent: ElementTree.Element, local_name: str) -> str | None:
    element = _find_element(parent, local_name)
    return _element_text(element) if element is not None else None


def _element_text(element: ElementTree.Element) -> str | None:
    value = " ".join(part.strip() for part in element.itertext() if part.strip())
    return value or None


def _local_name(tag: object) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]
