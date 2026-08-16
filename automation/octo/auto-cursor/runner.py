#!/usr/bin/env python3
"""
Run automation.py in a loop until it fails.

Usage:
    python runner.py           # Run forever until error
    python runner.py --max 10  # Run max 10 times  
    python runner.py --delay 5 # Wait 5s between runs
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path


def transform_jupyter_to_async(code: str) -> str:
    """
    Transform Jupyter-style code with bare await to proper async Python.
    Wraps everything after imports in async def main() and calls asyncio.run().
    """
    lines = code.split('\n')
    
    # Find where imports end - look for first line that starts executable code
    import_end_idx = 0
    paren_depth = 0
    
    for i, line in enumerate(lines):
        stripped = line.strip()
        
        # Update paren depth BEFORE processing
        prev_depth = paren_depth
        paren_depth += line.count('(') - line.count(')')
        
        # If we were in multi-line (parens), include this line in imports
        if prev_depth > 0:
            import_end_idx = i + 1
            continue
        
        # Skip comments, empty lines, cell markers
        if not stripped or stripped.startswith('#'):
            continue
            
        # Import statements
        if stripped.startswith('import ') or stripped.startswith('from '):
            import_end_idx = i + 1
            continue
            
        # Path manipulation and constants at module level
        if (stripped.startswith('sys.path') or 
            stripped.startswith('WORKER_PATH') or
            stripped.startswith('if WORKER_PATH') or
            re.match(r'^[A-Z_]+ = ', stripped)):
            import_end_idx = i + 1
            continue
            
        # If this line opened parens (multi-line import), include it
        if paren_depth > 0:
            import_end_idx = i + 1
            continue
            
        # Found executable code - stop here
        break
    
    import_section = lines[:import_end_idx]
    body_section = lines[import_end_idx:]
    
    # Build transformed code
    result = []
    result.extend(import_section)
    result.append('')
    result.append('async def __automation_main__():')
    
    # Indent body section
    for line in body_section:
        if line.strip():
            result.append('    ' + line)
        else:
            result.append('')
    
    result.append('')
    result.append('if __name__ == "__main__":')
    result.append('    import asyncio')
    result.append('    asyncio.run(__automation_main__())')
    
    return '\n'.join(result)


def run_automation(automation_file: Path) -> int:
    """Run the automation script, returns exit code."""
    code = automation_file.read_text()
    transformed = transform_jupyter_to_async(code)
    
    # Prepend path setup to ensure local imports work
    script_dir = str(automation_file.parent.resolve())
    path_setup = f'''import sys
import os
os.chdir({repr(script_dir)})
if {repr(script_dir)} not in sys.path:
    sys.path.insert(0, {repr(script_dir)})
os.environ["AUTO_DIR"] = {repr(script_dir)}

'''
    transformed = path_setup + transformed
    
    # Write to temp file and run
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(transformed)
        temp_path = f.name
    
    try:
        env = {**os.environ, "AUTO_DIR": script_dir}
        result = subprocess.run(
            [sys.executable, temp_path],
            cwd=automation_file.parent,
            env=env,
        )
        return result.returncode
    finally:
        Path(temp_path).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description="Run cursor automation in a loop")
    parser.add_argument("--max", "-m", type=int, default=0, help="Max runs (0=infinite)")
    parser.add_argument("--delay", "-d", type=int, default=2, help="Delay between runs (seconds)")
    parser.add_argument("--transform-only", action="store_true", help="Just print transformed code")
    args = parser.parse_args()
    
    automation_file = Path(__file__).parent / "automation.py"
    if not automation_file.exists():
        print(f"[!] File not found: {automation_file}")
        sys.exit(1)
    
    if args.transform_only:
        code = automation_file.read_text()
        print(transform_jupyter_to_async(code))
        return
    
    # Exit code 2 = rate limit/SMS fail, should retry with new profile
    RETRY_EXIT_CODE = 2
    
    count = 0
    success_count = 0
    fail_count = 0
    total_start = time.time()
    
    while True:
        count += 1
        print(f"\n{'='*60}")
        print(f"  RUN #{count}")
        print(f"{'='*60}\n")
        
        run_start = time.time()
        
        try:
            exit_code = run_automation(automation_file)
            
            run_elapsed = time.time() - run_start
            run_mins = int(run_elapsed // 60)
            run_secs = int(run_elapsed % 60)
            
            if exit_code == 0:
                success_count += 1
                print(f"\n[✓] Run #{count} completed in {run_mins}m {run_secs}s")
                print(f"    (success: {success_count}, failed: {fail_count})")
            elif exit_code == RETRY_EXIT_CODE:
                fail_count += 1
                print(f"\n[!] Run #{count} needs retry (exit code {exit_code}) - took {run_mins}m {run_secs}s")
                print(f"    (success: {success_count}, failed: {fail_count})")
                print("    → Retrying with new profile...")
                # Continue to next run
            else:
                fail_count += 1
                print(f"\n[!] Run #{count} failed with exit code {exit_code} - took {run_mins}m {run_secs}s")
                print(f"    (success: {success_count}, failed: {fail_count})")
                break  # Stop on other errors
                
        except KeyboardInterrupt:
            print(f"\n[!] Interrupted by user after {count} runs")
            break
        except Exception as e:
            fail_count += 1
            print(f"\n[!] Run #{count} crashed: {e}")
            traceback.print_exc()
            break  # Stop on crashes
        
        if args.max and count >= args.max:
            print(f"\n[✓] Reached max runs ({args.max})")
            break
        
        print(f"[...] Waiting {args.delay}s before next run...")
        try:
            time.sleep(args.delay)
        except KeyboardInterrupt:
            print(f"\n[!] Interrupted during delay")
            break
    
    total_elapsed = time.time() - total_start
    total_mins = int(total_elapsed // 60)
    total_secs = int(total_elapsed % 60)
    print(f"\n[DONE] Total runs: {count} (success: {success_count}, failed: {fail_count})")
    print(f"       Total time: {total_mins}m {total_secs}s")


if __name__ == "__main__":
    main()
