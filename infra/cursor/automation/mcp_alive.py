#!/usr/bin/env python3
"""Precise MCP-connection detector.

Reads the heartbeat the jefr MCP server writes every ~2.5s to
~/.moyu-message/agent-alive.json:  {"ts": <ms>, "pid": <int>, "state": "waiting"|"working"}

This is the ground truth (written by the server process itself) and is far more
reliable than the DOM "Worked for" / generating heuristic:
  - fresh heartbeat  => the MCP loop is ALIVE (state says waiting vs working)
  - stale heartbeat  => the loop is GONE / cut out (or the process is suspended)
"""
import json, os, sys, time, subprocess

DATA_DIR = os.environ.get("MESSENGER_DATA_DIR") or os.path.join(os.path.expanduser("~"), ".moyu-message")
HEARTBEAT = os.path.join(DATA_DIR, "agent-alive.json")
# Ticker runs every 2.5s; allow ~3 missed ticks before calling it stale.
STALE_MS = int(os.environ.get("MCP_STALE_MS", "8000"))


def pid_alive(pid: int) -> bool:
    if not pid:
        return False
    try:
        if os.name == "nt":
            out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                                 capture_output=True, text=True, timeout=5)
            return str(pid) in out.stdout
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def main() -> int:
    try:
        hb = json.load(open(HEARTBEAT, "r", encoding="utf-8"))
    except FileNotFoundError:
        print(json.dumps({"alive": False, "reason": "no heartbeat file", "path": HEARTBEAT}))
        return 1
    except Exception as e:
        print(json.dumps({"alive": False, "reason": f"unreadable: {e}"}))
        return 1

    now = int(time.time() * 1000)
    age = now - int(hb.get("ts", 0))
    pid = int(hb.get("pid", 0))
    state = hb.get("state")
    proc_up = pid_alive(pid)
    fresh = age <= STALE_MS
    alive = fresh and proc_up

    print(json.dumps({
        "alive": alive,
        "state": state,            # "waiting" = blocked in check_messages; "working" = mid-task
        "age_ms": age,
        "fresh": fresh,
        "pid": pid,
        "pid_alive": proc_up,
        "verdict": ("LIVE (" + str(state) + ")") if alive
                   else ("PROCESS GONE" if not proc_up else "STALE / cut out"),
    }))
    return 0 if alive else 2


if __name__ == "__main__":
    sys.exit(main())
