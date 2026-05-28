<h1 align="center">IoT Honeypot</h1>

---

> [!WARNING]
> **Analysis Honeypot**: This system is designed to attract and observe real attackers.
> It is **not** a production security product. Deploy only on isolated infrastructure
> with appropriate institutional and legal approvals.

---

## Why ZeroTrace?

Today's IoT forensics captures network logs but rarely kernel level activity. When an attacker pivots between containers, drops a binary in `/tmp`, or injects code into a running process, traditional tools miss it entirely.

ZeroTrace solves this by placing four [Cilium Tetragon](https://github.com/cilium/tetragon) eBPF kprobes at the kernel level inside an IoT honeypot that emulates a **Hikvision DS-2CD2183G2 IP camera**. Every kernel event is tagged with a UUID per attacker, then sealed into a tamper-evident evidence chain (SHA-256, [OpenTimestamps](https://opentimestamps.org/) Bitcoin anchor, MinIO WORM).
<p align="center">
  <img width="1672" height="941" alt="why zerotrace" src="https://github.com/user-attachments/assets/a611f390-e0aa-4aad-b399-54de84e4faab" />
</p>
---

## Setup

> [!NOTE]
> Anywhere you see `YOUR_ORG` in this README, replace it with your GitHub username or organization name.

### Prerequisites (all options)

| Requirement | Minimum | How to check |
|-------------|---------|--------------|
| OS | Linux x86_64, kernel 5.8+ | `uname -r` |
| Kernel BTF | Enabled (required for Tetragon) | `ls /sys/kernel/btf/vmlinux` |
| Docker | 20.10+ with Compose V2 | `docker --version && docker compose version` |
| Python | 3.10+ with pip | `python3 --version && pip3 --version` |
| Git | Any recent version | `git --version` |

If any prerequisite is missing, install it before proceeding:

```bash
# Install Python 3 + pip (Ubuntu/Debian)
sudo apt-get update && sudo apt-get install -y python3 python3-pip git

# Install Docker (official script: works on Ubuntu, Debian, Fedora, CentOS)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

> After running `usermod`, **log out and log back in** (or run `newgrp docker`) so your user picks up the `docker` group. All commands below assume you can run `docker` without `sudo`.

```bash
# Verify BTF is available (Tetragon will silently fail without it)
ls /sys/kernel/btf/vmlinux || echo "ERROR: BTF not available. Tetragon needs kernel 5.8+ with CONFIG_DEBUG_INFO_BTF=y"
```

---

<details>
<summary><strong>Option A: Dev Container (recommended for development)</strong></summary>

1. Open this repository in VS Code or GitHub Codespaces
2. When prompted, click **"Reopen in Container"**
3. The dev container installs all Python dependencies automatically
4. Inside the container terminal:

```bash
cd src/honeypot && docker compose up -d
```

> [!NOTE]
> Tetragon requires `--privileged` and host PID namespace access, which most dev containers don't provide. Use Option B or C for full eBPF deployment.

</details>

<details>
<summary><strong>Option B: Any Linux host (bare metal, VPS, or VM)</strong></summary>

```bash
# 1. Create forensics directory
sudo mkdir -p /forensics/{pcap,memdump,zeek,rita,evidence,manifest,tetragon,logs}
sudo chown -R $USER:$USER /forensics

# 2. Clone the repository
git clone https://github.com/YOUR_ORG/zerotrace.git
cd zerotrace

# 3. Install Python dependencies
pip3 install paho-mqtt flask requests

# 4. Deploy honeypot surface (4 Docker containers)
cd src/honeypot && docker compose up -d && cd ../..

# 5. Start Tetragon (eBPF kprobes)
docker run --name tetragon --rm -d \
  --pid=host --cgroupns=host --privileged \
  -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
  -v /forensics/tetragon:/var/log/tetragon \
  quay.io/cilium/tetragon:v1.1.2 \
  --export-filename /var/log/tetragon/tetragon.log

# 6. Load ZTA tracing policy
docker cp src/tetragon/policies/zt-forensics.yaml tetragon:/tmp/
docker exec tetragon tetra tracingpolicy add /tmp/zt-forensics.yaml

# 7. Start session correlator
nohup bash -c "docker exec tetragon /usr/bin/tetra getevents --output json \
  --include-fields 'process,parent,function_name,args,time' \
  | python3 src/correlator/session_correlator.py" \
  > /tmp/correlator.log 2>&1 &
disown
```

</details>

<details>
<summary><strong>Option C: Azure VM deployment</strong></summary>

**Azure-specific prerequisites:**
- `Standard_D4s_v3` VM (4 vCPU, 16 GB RAM, Ubuntu 22.04 x86_64)
- 128 GiB Premium SSD data disk attached
- NSG inbound rules: 22 (SSH), 80, 443, 1883

```bash
# 1. Mount forensics volume
#    IMPORTANT: pin by UUID, never /dev/sdX Azure reshuffles device letters on stop/start
DATA_DEV=$(lsblk -bno NAME,SIZE,MOUNTPOINT | awk '$2==137438953472 && $3=="" {print "/dev/"$1; exit}')
sudo mkfs.ext4 "$DATA_DEV"
DATA_UUID=$(sudo blkid -s UUID -o value "$DATA_DEV")
sudo mkdir -p /forensics
echo "UUID=$DATA_UUID /forensics ext4 defaults,nofail 0 2" | sudo tee -a /etc/fstab
sudo mount /forensics
sudo mkdir -p /forensics/{pcap,memdump,zeek,rita,evidence,manifest,tetragon,logs}
sudo chown -R ubuntu:ubuntu /forensics

# 2. Install Python dependencies
sudo apt-get update && sudo apt-get install -y python3 python3-pip
pip3 install paho-mqtt flask requests

# 3. Deploy honeypot surface
sudo mkdir -p /opt/honeypot
cp -r src/honeypot/* /opt/honeypot/
cd /opt/honeypot && docker compose up -d && cd -

# 4. Start Tetragon (eBPF kprobes)
docker run --name tetragon --rm -d \
  --pid=host --cgroupns=host --privileged \
  -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
  -v /forensics/tetragon:/var/log/tetragon \
  quay.io/cilium/tetragon:v1.1.2 \
  --export-filename /var/log/tetragon/tetragon.log

# 5. Load ZTA tracing policy
docker cp src/tetragon/policies/zt-forensics.yaml tetragon:/tmp/
docker exec tetragon tetra tracingpolicy add /tmp/zt-forensics.yaml

# 6. Start session correlator
pip3 install paho-mqtt flask requests
nohup bash -c "docker exec tetragon /usr/bin/tetra getevents --output json \
  --include-fields 'process,parent,function_name,args,time' \
  | python3 src/correlator/session_correlator.py" \
  > /tmp/correlator.log 2>&1 &
disown
```

</details>

---

## Verification

After completing any setup option, run these checks. **Every one must pass.**

```bash
# 1. Honeypot containers are running
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "mqtt-broker|web-ui|firmware-updater|behavior-sim"
# Expected: all four show "Up"

# 2. Honeypot fingerprint is correct (must say App-webs/2.0, NOT nginx)
curl -sI http://localhost/ | grep Server
# Expected: Server: App-webs/2.0

# 3. MQTT broker accepts connections
timeout 5 mosquitto_sub -h localhost -t '#' -C 1 -v 2>/dev/null && echo "MQTT OK" || echo "MQTT OK (no messages yet)"
# Expected: MQTT OK (broker is listening even if no messages yet)

# 4. Tetragon is running and policy is loaded
docker exec tetragon tetra tracingpolicy list
# Expected: iot-zt-forensics    STATE=enabled

# 5. Session correlator is running
pgrep -af session_correlator
# Expected: at least 1 PID

# 6. Tetragon log file exists and is being written
ls -la /forensics/tetragon/tetragon.log
# Expected: file exists (may be empty until first event fires)

# 7. BTF is available (confirms eBPF can attach)
ls /sys/kernel/btf/vmlinux
# Expected: /sys/kernel/btf/vmlinux (no error)
```
If check 2 shows `nginx` or `openresty` instead of `App-webs/2.0`, the nginx config isn't loaded correctly. Verify `src/honeypot/nginx-iot.conf` was copied to the right location.

If check 4 fails with "container not found", Tetragon crashed on startup, check `docker logs tetragon` and verify BTF (check 7).

---

## Viewing Your Data

> [!IMPORTANT]
> Replace these placeholders with your values before running commands:
> - `YOUR_HOST_IP` = your server's public or private IP address
> - `YOUR_GRAFANA_PASSWORD` = set this in [`src/grafana/docker-compose.yml`](src/grafana/docker-compose.yml) under the `GF_SECURITY_ADMIN_PASSWORD` environment variable

### Dashboard

```bash
# 1. Start the Grafana + Loki observability stack
cd src/grafana && docker compose up -d && cd ../..

# 2. Open an SSH tunnel from your local machine (run this locally, not on the server)
ssh -L 3000:127.0.0.1:3000 ubuntu@YOUR_HOST_IP

# 3. Open http://localhost:3000 in your browser
#    Login: admin / YOUR_GRAFANA_PASSWORD
```

A pre built 16 panel dashboard loads automatically. Grafana binds to `127.0.0.1` only it is never exposed to the internet.

### Data on Disk

| Path | Contents | Format |
|------|----------|--------|
| `/forensics/tetragon/tetragon.log` | eBPF kprobe events (lateral move, execve, memfd, ptrace) | JSON Lines |
| `/forensics/manifest/evidence_manifest.jsonl` | Evidence index linking events to sessions | JSON Lines |

### Quick Queries

```bash
# View the 5 most recent Tetragon events
tail -5 /forensics/tetragon/tetragon.log | jq .

# Count events by kprobe type
jq -r '.process_kprobe.function_name' /forensics/tetragon/tetragon.log | sort | uniq -c | sort -rn

# List unique attacker sessions
jq -r '.session_id' /forensics/manifest/evidence_manifest.jsonl | sort -u
```

---

## Configuration

| File | Purpose | Deploy Path |
|------|---------|-------------|
| [`src/tetragon/policies/zt-forensics.yaml`](src/tetragon/policies/zt-forensics.yaml) | eBPF kprobe definitions (4 hooks) | `/opt/tetragon/policies/` |
| [`src/correlator/session_correlator.py`](src/correlator/session_correlator.py) | Maps src_ip &rarr; UUID4, writes manifest, triggers PANDA | `/opt/correlator/` |
| [`src/honeypot/docker-compose.yml`](src/honeypot/docker-compose.yml) | 4 container IoT microservices stack | `/opt/honeypot/` |
| [`src/honeypot/nginx-iot.conf`](src/honeypot/nginx-iot.conf) | Hikvision fingerprint (`App-webs/2.0` header) | `/opt/honeypot/` |
| [`src/honeypot/mosquitto.conf`](src/honeypot/mosquitto.conf) | MQTT broker (attacker entry point, port 1883) | `/opt/honeypot/` |
| [`src/honeypot/firmware_server.py`](src/honeypot/firmware_server.py) | Internal only ZTA violation target (port 8080) | `/opt/honeypot/` |
| [`src/honeypot/iot_behavior_sim.py`](src/honeypot/iot_behavior_sim.py) | Gaussian MQTT telemetry (realistic device traffic) | `/opt/honeypot/` |
| [`src/spire/conf/server.conf`](src/spire/conf/server.conf) | SPIRE server (trust domain `iot-honeypot.local`) | `/opt/spire/conf/` |
| [`src/spire/conf/agent.conf`](src/spire/conf/agent.conf) | SPIRE agent (Docker WorkloadAttestor) | `/opt/spire/conf/` |

---

## Tracked Kernel Events

Four eBPF kprobes defined in [`src/tetragon/policies/zt-forensics.yaml`](src/tetragon/policies/zt-forensics.yaml):

| Hook | Syscall | Why It Matters | Filter |
|------|---------|----------------|--------|
| `tcp_connect` | No (kernel function) | Catches lateral movement when an attacker pivots from the MQTT broker to the internal firmware-updater (172.20.0.12:8080) | `NotIn /usr/sbin/mosquitto` |
| `sys_execve` | Yes | Detects binary drop and execute from world writable directories. The classic Mirai IoT staging pattern | `Prefix /tmp/ /dev/shm/ /var/tmp/` |
| `sys_memfd_create` | Yes | Flags fileless malware that never touches disk, its invisible to filesystem based detection | None (every call is suspicious) |
| `sys_ptrace` | Yes | Catches process injection via `PTRACE_POKEDATA`, the attacker is writing code into a victim process's memory | `arg0 == 4` (POKEDATA) |

<details>
<summary><strong>Sample Tetragon event (lateral movement)</strong></summary>

```json
{
  "process_kprobe": {
    "process": {
      "exec_id": "aWFkLWhvbmV5cG90LWhvc3Q6OTQ1MzU4MDAwMDAwMDox",
      "pid": 9421,
      "uid": 0,
      "binary": "/usr/bin/curl",
      "arguments": "-X POST http://172.20.0.12:8080/upload"
    },
    "parent": { "binary": "/bin/sh", "pid": 9420 },
    "function_name": "tcp_connect",
    "args": [
      { "sock_arg": { "daddr": "172.20.0.12", "dport": 8080 } }
    ],
    "time": "2026-05-17T03:14:22.401Z"
  }
}
```

A `curl` process spawned from `/bin/sh` connected to `172.20.0.12:8080` (the firmware-updater). The MQTT container should never originate traffic to that port, this is a **lateral movement** ZTA violation.

</details>

---

## SPIFFE/SPIRE Zero Trust

Every container in the honeypot receives a short lived X.509 SVID from [SPIRE v1.14.1](https://github.com/spiffe/spire), creating cryptographic workload identity without static credentials.

```
Trust Domain: spiffe://iot-honeypot.local

Workload Registration:
  mqtt-broker      → spiffe://iot-honeypot.local/workload/mqtt-broker
  web-ui           → spiffe://iot-honeypot.local/workload/web-ui
  firmware-updater → spiffe://iot-honeypot.local/workload/firmware-updater
  behavior-sim     → spiffe://iot-honeypot.local/workload/behavior-sim

Attestor: Docker (label based)
SVID Lifetime: 1 hour (auto rotated)
```

When an attacker compromises a container and attempts lateral movement, the destination container can validate (or reject) the SVID providing cryptographic evidence of trust boundary violations that correlates with Tetragon's kernel level observations.

---

## Honeypot Stack

Four Docker containers on a private bridge network (`172.20.0.0/24`):

<p align="center">
  <img width="1672" height="941" alt="Honeypot Stack" src="https://github.com/user-attachments/assets/d98e0dea-f2c5-498f-81af-f01d7f4c276f" />
</p>

The `firmware-updater` is deliberately **not** exposed to the internet. Any connection to `172.20.0.12:8080` from the MQTT broker's namespace is a lateral movement violation captured by Tetragon's `tcp_connect` kprobe.

---

## Repository Structure
<p align="center">
  <img width="1186" height="783" alt="file structure" src="https://github.com/user-attachments/assets/b8cc60c7-14ad-41b0-bab9-899fa248e2da" />
</p>

---
## Dashboard View
<p align="center">
  <img width="1658" height="837" alt="image" src="https://github.com/user-attachments/assets/c477a190-8c36-444e-890f-9e1a02349e45" />
</p>

---
## License

[Apache License 2.0](LICENSE)

---

## Acknowledgments

Built on the shoulders of:

- [Cilium Tetragon](https://github.com/cilium/tetragon): eBPF based runtime security observability
- [SPIFFE/SPIRE](https://spiffe.io/): Universal workload identity
- [OpenTimestamps](https://opentimestamps.org/): Bitcoin anchored timestamping
- [MinIO](https://min.io/): S3 compatible object storage with Compliance Object Lock
- [Volatility 3](https://github.com/volatilityfoundation/volatility3): Memory forensics framework
- [PANDA](https://github.com/panda-re/panda): Whole system dynamic analysis platform
