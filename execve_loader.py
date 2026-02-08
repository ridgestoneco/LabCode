#!/usr/bin/env python3
"""
execve_loader.py — eBPF shell-spawn detector
Loads execve_probe.c, watches for suspicious parent→shell executions,
outputs structured JSON events to syslog.

Run as root: sudo python3 execve_loader.py
"""

import ctypes
import json
import signal
import sys
import os
import logging
import logging.handlers
from datetime import datetime, timezone

from bcc import BPF

# ---------- constants matching the C struct ----------
TASK_COMM_LEN = 16
MAX_ARG_LEN = 256

class Event(ctypes.Structure):
    _fields_ = [
        ("pid",      ctypes.c_uint32),
        ("ppid",     ctypes.c_uint32),
        ("uid",      ctypes.c_uint32),
        ("comm",     ctypes.c_char * TASK_COMM_LEN),
        ("pcomm",    ctypes.c_char * TASK_COMM_LEN),
        ("filename", ctypes.c_char * MAX_ARG_LEN),
    ]

# ---------- shell detection (moved from kernel) ----------
SHELLS = {"sh", "bash", "dash", "zsh"}

def is_shell(filename):
    basename = os.path.basename(filename)
    return basename in SHELLS

# ---------- syslog setup ----------
syslog_handler = logging.handlers.SysLogHandler(
    address="/dev/log",
    facility=logging.handlers.SysLogHandler.LOG_AUTH
)
syslog_handler.setFormatter(logging.Formatter("%(message)s"))

logger = logging.getLogger("ebpf-detector")
logger.setLevel(logging.INFO)
logger.addHandler(syslog_handler)

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(stdout_handler)

# ---------- load BPF program ----------
probe_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "execve_probe.c")

with open(probe_path, "r") as f:
    bpf_source = f.read()

print("[*] Loading eBPF probe...")
b = BPF(text=bpf_source)
print("[*] Probe attached to sys_enter_execve tracepoint")
print("[*] Watching for suspicious shell spawns...")
print("[*] Ctrl+C to stop\n")

# ---------- MITRE mapping ----------
MITRE_TECHNIQUE = "T1059"
MITRE_TACTIC = "Execution"

# ---------- event callback ----------
def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents

    filename = event.filename.decode("utf-8", errors="replace")

    # Shell check in userspace — clean and no verifier issues
    if not is_shell(filename):
        return

    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "detector": "ebpf-execve-monitor",
        "severity": "HIGH",
        "event": "suspicious_shell_spawn",
        "mitre_attack": {
            "technique": MITRE_TECHNIQUE,
            "tactic": MITRE_TACTIC,
            "name": "Command and Scripting Interpreter"
        },
        "process": {
            "pid": event.pid,
            "name": event.comm.decode("utf-8", errors="replace"),
            "executable": filename,
        },
        "parent": {
            "pid": event.ppid,
            "name": event.pcomm.decode("utf-8", errors="replace"),
        },
        "user": {
            "uid": event.uid,
        },
    }

    json_str = json.dumps(alert)
    logger.info(json_str)

# ---------- attach callback and poll ----------
b["events"].open_perf_buffer(handle_event)

def shutdown(sig, frame):
    print("\n[*] Shutting down...")
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        shutdown(None, None)
