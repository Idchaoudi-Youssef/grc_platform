# Greenbone/OpenVAS isolated training lab

This procedure connects the existing GRC project to a **manual, authorized lab**.
Greenbone runs in Docker Desktop/WSL2, while a deliberately vulnerable target
such as Metasploitable 2 runs on an isolated private or host-only network. Never
scan a public IP, a school/company network, or any system without written
authorization.

Greenbone describes the Community Containers as a way to learn and test current
features, not as a production deployment. Always consult the
[latest official container guide](https://greenbone.github.io/docs/latest/22.4/container/)
and download its current Compose file instead of copying one into this project.

## Architecture and safety boundary

```text
Windows host
|- grc_platform (Python, SQLite, manual XML validation/import)
|- Docker Desktop with WSL2
|  `- Greenbone Community Containers (GSA, gvmd, scanner, feeds)
`- isolated vulnerable VM (authorized target only)
```

Use a private/host-only lab network. Do not bridge a vulnerable VM directly to a
public or campus network. Docker Desktop, WSL2, and VirtualBox/VMware networking
are separate layers: host-to-target connectivity does **not** prove that the
scanner container can reach the target. Verify the exact route before creating
a scan.

## Prerequisites

- Windows 10/11 with virtualization enabled.
- WSL2 and Docker Desktop using the WSL2 engine.
- Docker Compose v2 (`docker compose`, not the old `docker-compose`).
- An isolated, authorized target VM. Metasploitable 2 is intentionally unsafe;
  never expose it publicly and never reuse its credentials elsewhere.
- Greenbone's documented minimum is 2 CPU cores, 4 GB RAM, and 20 GB free disk.
  Its recommendation is 4 cores, 8 GB RAM, and 60 GB free disk. Assign enough
  resources to Docker Desktop and keep additional capacity for the target VM.

In **PowerShell**, verify Docker Desktop and WSL:

```powershell
wsl --status
docker version
docker compose version
```

In a **WSL/Linux shell**, use Linux paths and commands:

```bash
docker version
docker compose version
```

Choose one shell for the Greenbone commands so paths remain understandable.

## Download the latest official Compose file

The Compose file is external lab infrastructure and is deliberately not stored
in this repository.

PowerShell:

```powershell
$GreenboneDir = Join-Path $HOME "greenbone-community-edition"
New-Item -ItemType Directory -Force -Path $GreenboneDir | Out-Null
Invoke-WebRequest `
  -Uri "https://greenbone.github.io/docs/latest/_static/compose.yaml" `
  -OutFile (Join-Path $GreenboneDir "compose.yaml")
```

WSL/Linux (the command published by Greenbone):

```bash
export DOWNLOAD_DIR="$HOME/greenbone-community-edition"
mkdir -p "$DOWNLOAD_DIR"
curl -f -O -L \
  https://greenbone.github.io/docs/latest/_static/compose.yaml \
  --output-dir "$DOWNLOAD_DIR"
```

Read the downloaded file and confirm its source before running it. M10A does not
download or vendor it automatically.

## Pull, start, and inspect

PowerShell:

```powershell
docker compose -f "$GreenboneDir\compose.yaml" pull
docker compose -f "$GreenboneDir\compose.yaml" up -d
docker compose -f "$GreenboneDir\compose.yaml" ps
docker compose -f "$GreenboneDir\compose.yaml" logs --tail 100
```

WSL/Linux:

```bash
docker compose -f "$DOWNLOAD_DIR/compose.yaml" pull
docker compose -f "$DOWNLOAD_DIR/compose.yaml" up -d
docker compose -f "$DOWNLOAD_DIR/compose.yaml" ps
docker compose -f "$DOWNLOAD_DIR/compose.yaml" logs --tail 100
```

Open <https://127.0.0.1>. The current official containers use HTTPS and a local
self-signed certificate, so a browser warning is expected in this isolated lab.
Do not expose the GSA port beyond localhost.

The initial account is `admin` / `admin`. Change it immediately. Replace the
placeholder below and protect the value from screenshots and shell history:

```powershell
docker compose -f "$GreenboneDir\compose.yaml" exec -u gvmd gvmd `
  gvmd --user=admin --new-password='<STRONG-LAB-ONLY-PASSWORD>'
```

Greenbone feeds arrive through data-container images, then gvmd and the scanner
load their data. This can take significant time on the first startup. Check
**Administration > Feed Status** in GSA and monitor logs until feeds and scan
configurations are available. A login page alone does not mean the scanner is
ready.

## Run the non-destructive preflight

From this project in PowerShell:

```powershell
.\.venv\Scripts\python.exe scripts\check_greenbone_lab.py `
  --compose-file "$GreenboneDir\compose.yaml" `
  --gsa-url "https://127.0.0.1" `
  --allow-self-signed `
  --target-ip "192.168.56.20" `
  --target-port 22 `
  --minimum-free-gb 20
```

`--allow-self-signed` is an explicit lab-only choice. Without it, normal TLS
certificate verification stays enabled. The TCP check tests one port from the
host; it is not a port scan and does not prove container-to-target reachability.

Before scanning, verify the scanner's network path. If the existing scanner
container has `ping`, this optional diagnostic sends only ICMP echo requests:

```powershell
docker compose -f "$GreenboneDir\compose.yaml" exec ospd-openvas `
  ping -c 3 192.168.56.20
```

If the command is unavailable, do not install tools into the container. Review
Docker/VM network settings and use another approved connectivity diagnostic.
Never assume reachability and never weaken the target isolation to make it work.

## Stop, restart, and update

These commands preserve named volumes:

```powershell
docker compose -f "$GreenboneDir\compose.yaml" stop
docker compose -f "$GreenboneDir\compose.yaml" start
docker compose -f "$GreenboneDir\compose.yaml" down
docker compose -f "$GreenboneDir\compose.yaml" up -d
```

For an update, download the latest official Compose file again, review it, then:

```powershell
docker compose -f "$GreenboneDir\compose.yaml" pull
docker compose -f "$GreenboneDir\compose.yaml" up -d
docker compose -f "$GreenboneDir\compose.yaml" ps
```

## Troubleshooting

- Docker daemon unavailable: start Docker Desktop and verify its WSL2 engine.
- Containers restarting: inspect `docker compose ... ps` and
  `docker compose ... logs --tail 200 <service>`.
- GSA unavailable: verify the `nginx`, `gsa`, and `gvmd` services and localhost
  binding.
- Scan configurations/VTs absent: allow feed loading to finish and inspect the
  `gvmd` and `ospd-openvas` logs. Follow Greenbone's
  [container troubleshooting guide](https://greenbone.github.io/docs/latest/22.4/container/troubleshooting.html)
  before running recovery commands.
- Target appears dead: re-check private network adapters and test the route from
  the scanner context. Do not switch the vulnerable VM to a public bridge.
- Low disk: stop before feeds or database volumes fill the drive; Greenbone's
  recommended capacity is 60 GB.

## Safe cleanup

Normal cleanup preserves feed/database volumes:

```powershell
docker compose -f "$GreenboneDir\compose.yaml" down
```

Greenbone documents `down -v` for starting from scratch, but `-v` permanently
deletes the lab volumes, feed state, users, and scan history. Use it only after
confirming the exact Compose path and accepting that loss:

```powershell
# DESTRUCTIVE LAB RESET - do not run casually
docker compose -f "$GreenboneDir\compose.yaml" down -v
```

Never delete `grc.db` as part of Greenbone cleanup. Keep real XML exports,
credentials, logs, Compose overrides, VM disks, and database backups outside Git.

Official references:

- [Greenbone Community Containers](https://greenbone.github.io/docs/latest/22.4/container/)
- [Container workflows](https://greenbone.github.io/docs/latest/22.4/container/workflows.html)
- [Container troubleshooting](https://greenbone.github.io/docs/latest/22.4/container/troubleshooting.html)
