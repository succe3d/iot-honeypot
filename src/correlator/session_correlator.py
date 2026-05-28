"""
session_correlator.py
Deploy to: /opt/correlator/session_correlator.py

Reads Tetragon JSON event stream from stdin (piped from `tetra getevents`).
Maps attacker IP → session_id, writes Plane 1 artifacts to evidence manifest,
triggers PANDA memory dumps (Gap 3), and tags Zeek sessions (Gap 6).

Fixes from Plan.pdf:
  - uuid.uuid4() correct call (not uuid.uuid4.uuid4())
  - manifest writes use JSON objects {} (not arrays [])
  - session_id assigned before use in correlation_tag block
  - Unwrap process_kprobe envelope (fields nested, not at root)
  - Added __x64_sys_* prefix variants (Tetragon on x86_64)
  - Removed tcp_connect (floods manifest with background traffic)
  - PANDA trigger port 9090 (not 9000 — ClickHouse conflict)
  - PANDA trigger timeout 30s (not 2s — 512MB dump takes time)
"""

import sys, json, uuid, datetime, requests

MANIFEST_PATH   = "/forensics/manifest/evidence_manifest.jsonl"
SESSIONS_PATH   = "/forensics/manifest/active_sessions.jsonl"
TRIGGER_PORT    = 9090   # Port 9000 is ClickHouse (RITA); PANDA webhook on 9090

# Tetragon function names that create a forensic session.
# On x86_64, Tetragon reports syscall kprobes with __x64_ prefix
# (e.g., __x64_sys_execve instead of sys_execve). Include both forms.
TRIGGER_FUNCTIONS = {
    "sys_memfd_create":         "fileless_staging",
    "__x64_sys_memfd_create":   "fileless_staging",
    "sys_ptrace":               "process_injection",
    "__x64_sys_ptrace":         "process_injection",
    # tcp_connect removed: floods manifest with background traffic (ClickHouse,
    # Grafana, etc.) — ~4 events/6s. Lateral movement is captured by Zeek instead.
    "sys_execve":               "binary_execution",
    "__x64_sys_execve":         "binary_execution",
}

# In-memory map: src_ip → session_id (reuses session for same attacker IP)
active_sessions: dict = {}


def utc_now() -> str:
    return datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def utc_now_iso_us() -> str:
    # Microsecond-precision ISO 8601 — paired with Tetragon's nanosecond `time`
    # so end-to-end latency (event → manifest write) can be computed downstream.
    return datetime.datetime.utcnow().isoformat(timespec="microseconds") + "Z"


def process_tetragon_event(event: dict) -> None:
    # Tetragon wraps kprobe events inside "process_kprobe" envelope;
    # all fields (function_name, process, parent) are nested within it.
    kprobe = event.get("process_kprobe")
    if kprobe is None:
        return  # Not a kprobe event (process_exec, process_exit, etc.)

    func = kprobe.get("function_name", "")
    if func not in TRIGGER_FUNCTIONS:
        return

    event_type    = TRIGGER_FUNCTIONS[func]
    ts            = utc_now()
    trigger_time  = event.get("time", "")            # Tetragon event timestamp (ns ISO 8601)

    # Extract attacker source IP from Tetragon event structure
    src_ip = (
        kprobe.get("process", {})
              .get("pod", {})
              .get("host_ip", "unknown")
    )

    # Reuse session_id if this attacker IP already has an active session
    if src_ip not in active_sessions:
        session_id = str(uuid.uuid4())          # Correct: uuid.uuid4() not uuid.uuid4.uuid4()
        active_sessions[src_ip] = session_id
    else:
        session_id = active_sessions[src_ip]

    # --- Plane 1: Write ZTA forensic artifact to evidence manifest ---
    plane1 = {
        "session_id":               session_id,
        "timestamp":                ts,
        "plane":                    "network_forensics_gap2",
        "event_type":               event_type,
        "function":                 func,
        "src_ip":                   src_ip,
        "process":                  kprobe.get("process", {}).get("binary", ""),
        "parent":                   kprobe.get("parent",  {}).get("binary", ""),
        "trigger_event":            {"time": trigger_time},
        "evidence_collection_time": utc_now_iso_us(),
        "raw_event":                event,
    }
    with open(MANIFEST_PATH, "a") as m:
        m.write(json.dumps(plane1) + "\n")

    # --- Gap 3 bridge: Trigger PANDA memory dump for high-value events ---
    if event_type in ("fileless_staging", "process_injection"):
        try:
            requests.post(
                f"http://127.0.0.1:{TRIGGER_PORT}/trigger-dump",
                json={"event": event, "session_id": session_id},
                timeout=30  # PANDA dumps 512MB RAM; 2s was too short
            )
        except requests.exceptions.RequestException as e:
            print(f"[{ts}] WARN: PANDA trigger failed for session={session_id}: {e}", flush=True)

    # --- Gap 6 bridge: Tag Zeek session for LegalTrace correlation ---
    correlation_tag = {
        "session_id": session_id,
        "src_ip":     src_ip,
        "start_ts":   ts,
        "trigger":    event_type,
    }
    with open(SESSIONS_PATH, "a") as af:
        af.write(json.dumps(correlation_tag) + "\n")

    print(f"[{ts}] SESSION {session_id} | {event_type} | {src_ip} | {func}", flush=True)


# ---------------------------------------------------------------------------
# Main: read Tetragon JSON stream from stdin
# Invoked as: docker exec tetragon /usr/bin/tetra getevents --output json \
#               --include-fields "process,parent,function_name,args,time" \
#             | python3 /opt/correlator/session_correlator.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"[{utc_now()}] Session correlator started", flush=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
            process_tetragon_event(event)
        except json.JSONDecodeError:
            continue
        except Exception as e:
            print(f"[{utc_now()}] ERROR processing event: {e}", flush=True)
            continue
