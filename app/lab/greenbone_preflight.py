"""Non-destructive readiness checks for a manual Greenbone container lab."""

from __future__ import annotations

import ipaddress
import shutil
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Sequence
from urllib.parse import urlparse


class CheckLevel(str, Enum):
    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"


@dataclass(frozen=True)
class CheckResult:
    name: str
    level: CheckLevel
    message: str


@dataclass(frozen=True)
class PreflightSummary:
    checks: list[CheckResult]

    @property
    def exit_code(self) -> int:
        return 1 if any(item.level is CheckLevel.FAIL for item in self.checks) else 0


CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
CORE_SERVICES = {
    "nginx",
    "gsa",
    "gvmd",
    "ospd-openvas",
    "pg-gvm",
    "redis-server",
}


def default_command_runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run only the read-only Docker status commands assembled by this module."""
    return subprocess.run(
        list(command),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
        shell=False,
    )


def run_preflight(
    *,
    compose_file: str | Path | None = None,
    gsa_url: str | None = None,
    allow_self_signed: bool = False,
    target_ip: str | None = None,
    target_port: int | None = None,
    minimum_free_gb: float = 20.0,
    disk_path: str | Path = ".",
    docker_path: str | None = None,
    command_runner: CommandRunner = default_command_runner,
) -> PreflightSummary:
    checks: list[CheckResult] = []
    executable = docker_path or shutil.which("docker")
    if not executable:
        checks.append(CheckResult("Docker CLI", CheckLevel.FAIL, "docker was not found on PATH."))
    else:
        checks.append(CheckResult("Docker CLI", CheckLevel.PASS, f"Found {executable}."))
        checks.extend(_check_docker(executable, compose_file, command_runner))

    checks.append(_check_disk_space(disk_path, minimum_free_gb))
    if gsa_url:
        checks.append(_check_https(gsa_url, allow_self_signed))
    if target_ip:
        target_check, normalized = validate_target_ip(target_ip)
        checks.append(target_check)
        if normalized and target_port is not None:
            checks.append(_check_tcp(normalized, target_port))
    elif target_port is not None:
        checks.append(CheckResult("Target reachability", CheckLevel.FAIL, "--target-port requires --target-ip."))
    return PreflightSummary(checks)


def validate_target_ip(value: str) -> tuple[CheckResult, str | None]:
    """Validate and normalize a lab target without sending traffic."""
    try:
        normalized = str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return CheckResult("Target IP", CheckLevel.FAIL, f"Invalid IP address: {value}"), None
    return CheckResult("Target IP", CheckLevel.PASS, f"Valid address: {normalized}"), normalized


def _check_docker(
    executable: str,
    compose_file: str | Path | None,
    runner: CommandRunner,
) -> list[CheckResult]:
    results: list[CheckResult] = []
    daemon = runner([executable, "version", "--format", "{{.Server.Version}}"])
    if daemon.returncode:
        results.append(CheckResult("Docker daemon", CheckLevel.FAIL, _command_error(daemon)))
        return results
    results.append(CheckResult("Docker daemon", CheckLevel.PASS, f"Server version {daemon.stdout.strip() or 'available'}."))

    compose = runner([executable, "compose", "version", "--short"])
    if compose.returncode:
        results.append(CheckResult("Docker Compose", CheckLevel.FAIL, _command_error(compose)))
        return results
    results.append(CheckResult("Docker Compose", CheckLevel.PASS, f"Version {compose.stdout.strip() or 'available'}."))

    if compose_file is None:
        results.append(CheckResult("Compose file", CheckLevel.WARNING, "No compose file supplied; container status was not checked."))
        return results
    path = Path(compose_file).expanduser().resolve()
    if not path.is_file():
        results.append(CheckResult("Compose file", CheckLevel.FAIL, f"File does not exist: {path}"))
        return results

    configured = runner([executable, "compose", "-f", str(path), "config", "--services"])
    if configured.returncode:
        results.append(CheckResult("Compose file", CheckLevel.FAIL, _command_error(configured)))
        return results
    declared = {line.strip() for line in configured.stdout.splitlines() if line.strip()}
    missing_definitions = CORE_SERVICES - declared
    if missing_definitions:
        results.append(CheckResult("Compose services", CheckLevel.FAIL, "Missing expected services: " + ", ".join(sorted(missing_definitions))))
        return results
    results.append(CheckResult("Compose services", CheckLevel.PASS, "Expected Greenbone core services are defined."))

    running_result = runner([executable, "compose", "-f", str(path), "ps", "--services", "--filter", "status=running"])
    if running_result.returncode:
        results.append(CheckResult("Container status", CheckLevel.FAIL, _command_error(running_result)))
        return results
    running = {line.strip() for line in running_result.stdout.splitlines() if line.strip()}
    missing_running = CORE_SERVICES - running
    if missing_running:
        results.append(CheckResult("Container status", CheckLevel.FAIL, "Core services not running: " + ", ".join(sorted(missing_running))))
    else:
        results.append(CheckResult("Container status", CheckLevel.PASS, "All expected core services are running."))
    return results


def _check_disk_space(path: str | Path, minimum_free_gb: float) -> CheckResult:
    if minimum_free_gb < 0:
        return CheckResult("Free disk space", CheckLevel.FAIL, "Minimum free space cannot be negative.")
    try:
        free_gb = shutil.disk_usage(Path(path).expanduser().resolve()).free / (1024**3)
    except OSError as exc:
        return CheckResult("Free disk space", CheckLevel.FAIL, f"Could not inspect disk: {exc}")
    level = CheckLevel.PASS if free_gb >= minimum_free_gb else CheckLevel.WARNING
    return CheckResult("Free disk space", level, f"{free_gb:.1f} GiB free; configured minimum is {minimum_free_gb:.1f} GiB.")


def _check_https(url: str, allow_self_signed: bool) -> CheckResult:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return CheckResult("GSA HTTPS", CheckLevel.FAIL, "GSA URL must be a valid https:// URL.")
    context = ssl._create_unverified_context() if allow_self_signed else ssl.create_default_context()
    try:
        with urllib.request.urlopen(url, context=context, timeout=5) as response:
            response.read(1)
            status = getattr(response, "status", 200)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        hint = " Use --allow-self-signed only for the local lab certificate." if not allow_self_signed else ""
        return CheckResult("GSA HTTPS", CheckLevel.FAIL, f"Connection failed: {exc}.{hint}")
    if allow_self_signed:
        return CheckResult("GSA HTTPS", CheckLevel.WARNING, f"HTTP {status}; TLS certificate verification was explicitly disabled.")
    return CheckResult("GSA HTTPS", CheckLevel.PASS, f"HTTP {status} with certificate verification enabled.")


def _check_tcp(host: str, port: int) -> CheckResult:
    if not 1 <= port <= 65535:
        return CheckResult("Target reachability", CheckLevel.FAIL, "TCP port must be between 1 and 65535.")
    try:
        with socket.create_connection((host, port), timeout=3):
            pass
    except OSError as exc:
        return CheckResult("Target reachability", CheckLevel.WARNING, f"TCP {host}:{port} was not reachable: {exc}")
    return CheckResult("Target reachability", CheckLevel.PASS, f"TCP {host}:{port} is reachable from this host.")


def _command_error(result: subprocess.CompletedProcess[str]) -> str:
    return (result.stderr or result.stdout or "Command failed.").strip()
