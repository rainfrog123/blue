#!/usr/bin/env python3
"""
Run stripe_url.py for all sessions until info.json is complete.

Iterates through sessions.json, ensures each has email + stripe_url in info.json.
Uses one browser profile per run; processes one session per invocation.

Usage:
    python stripe_runner.py           # Run until all complete
    python stripe_runner.py --max 5   # Run max 5 sessions
    python stripe_runner.py --delay 3 # Wait 3s between runs
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path


def transform_jupyter_to_async(code: str) -> str:
    """Transform Jupyter-style code with bare await to proper async Python."""
    lines = code.split('\n')
    import_end_idx = 0
    paren_depth = 0

    for i, line in enumerate(lines):
        stripped = line.strip()
        prev_depth = paren_depth
        paren_depth += line.count('(') - line.count(')')

        if prev_depth > 0:
            import_end_idx = i + 1
            continue
        if not stripped or stripped.startswith('#'):
            continue
        if stripped.startswith('import ') or stripped.startswith('from '):
            import_end_idx = i + 1
            continue
        if (stripped.startswith('sys.path') or
                stripped.startswith('WORKER_PATH') or
                stripped.startswith('if WORKER_PATH') or
                re.match(r'^[A-Z_]+ = ', stripped)):
            import_end_idx = i + 1
            continue
        if paren_depth > 0:
            import_end_idx = i + 1
            continue
        break

    import_section = lines[:import_end_idx]
    body_section = lines[import_end_idx:]

    result = []
    result.extend(import_section)
    result.append('')
    result.append('async def __stripe_main__():')
    for line in body_section:
        result.append('    ' + line if line.strip() else '')
    result.append('')
    result.append('if __name__ == "__main__":')
    result.append('    import asyncio')
    result.append('    asyncio.run(__stripe_main__())')
    return '\n'.join(result)


def get_pending_sessions(script_dir: Path) -> list[int]:
    """Return list of session indices that need processing (missing email or stripe_url)."""
    session_file = script_dir / "sessions.json"
    info_file = script_dir / "info.json"

    try:
        with open(session_file) as f:
            sessions = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

    try:
        with open(info_file) as f:
            infos = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        infos = []

    pending = []
    for i, session in enumerate(sessions):
        token = session.get("workos_session_token", "")
        if not token:
            continue
        if i >= len(infos):
            pending.append(i)
        else:
            info = infos[i]
            needs_email = not (info.get("email") or "").strip()
            trial_status = (info.get("trial_status") or "").strip()
            needs_trial_status = not trial_status
            # stripe_url only needed when can_trial; already_trial/expired = done
            needs_stripe = (
                not (info.get("stripe_url") or "").strip()
                and trial_status not in ("already_trial", "expired")
            )
            if needs_email or needs_stripe or needs_trial_status:
                pending.append(i)
    return pending


def run_stripe_extract(script_dir: Path, session_index: int) -> int:
    """Run stripe_url.py for given session index. Returns exit code."""
    stripe_file = script_dir / "stripe_url.py"
    code = stripe_file.read_text()
    transformed = transform_jupyter_to_async(code)

    path_setup = f'''import sys
import os
os.chdir({repr(str(script_dir))})
if {repr(str(script_dir))} not in sys.path:
    sys.path.insert(0, {repr(str(script_dir))})
os.environ["AUTO_DIR"] = {repr(str(script_dir))}
os.environ["SESSION_INDEX"] = {repr(str(session_index))}

'''
    transformed = path_setup + transformed

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(transformed)
        temp_path = f.name

    try:
        env = {**os.environ, "AUTO_DIR": str(script_dir), "SESSION_INDEX": str(session_index)}
        result = subprocess.run(
            [sys.executable, temp_path],
            cwd=script_dir,
            env=env,
        )
        return result.returncode
    finally:
        Path(temp_path).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description="Run stripe extraction for all sessions")
    parser.add_argument("--max", "-m", type=int, default=0, help="Max sessions to process (0=all)")
    parser.add_argument("--delay", "-d", type=int, default=2, help="Delay between runs (seconds)")
    args = parser.parse_args()

    script_dir = Path(__file__).parent.resolve()

    count = 0
    while True:
        pending = get_pending_sessions(script_dir)
        if not pending:
            print("\n[✓] All sessions have complete info in info.json")
            break

        session_index = pending[0]  # Process first pending
        count += 1

        print(f"\n{'='*60}")
        print(f"  SESSION #{count} (index {session_index}) | {len(pending)} pending")
        print(f"{'='*60}\n")

        try:
            exit_code = run_stripe_extract(script_dir, session_index)

            if exit_code != 0:
                print(f"\n[!] Session {session_index} failed with exit code {exit_code}")
                # Don't break - try next session
                pending = get_pending_sessions(script_dir)
                if session_index in pending:
                    print(f"[!] Session {session_index} still pending, moving to next...")

        except KeyboardInterrupt:
            print(f"\n[!] Interrupted by user")
            break
        except Exception as e:
            print(f"\n[!] Session {session_index} crashed: {e}")
            traceback.print_exc()

        print(f"\n[✓] Run #{count} completed")

        if args.max and count >= args.max:
            print(f"\n[✓] Reached max runs ({args.max})")
            break

        print(f"[...] Waiting {args.delay}s before next run...")
        try:
            time.sleep(args.delay)
        except KeyboardInterrupt:
            print(f"\n[!] Interrupted during delay")
            break

    print(f"\n[DONE] Total runs: {count}")


if __name__ == "__main__":
    main()
