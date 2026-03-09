# %% [markdown]
# # Configuration for Cursor Automation
# Paths, settings, and constants. Import this first to verify environment.

# %% Imports
import os
import sys

# %% Paths
OCTO_APPIMAGE = "/opt/octobrowser/OctoBrowser.AppImage"
OCTO_PORT_FILE = os.path.expanduser("~/.Octo Browser/local_port")
OCTO_DEFAULT_PORT = "59999"

# Add herosms to path
HEROSMS_PATH = "/allah/blue/web/auto/herosms"
if HEROSMS_PATH not in sys.path:
    sys.path.insert(0, HEROSMS_PATH)

# %% Read Octo Port
def get_octo_port():
    """Read OctoBrowser port from file or return default"""
    try:
        with open(OCTO_PORT_FILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        return OCTO_DEFAULT_PORT

OCTO_PORT = get_octo_port()
OCTO_API = f"http://localhost:{OCTO_PORT}"

# %% Automation Settings
CONFIG = {
    "profile_uuid": None,
    "email_domain": "@hyas.site",
    "prefixes_file": "/allah/blue/web/auto/worker/hyas_prefixes.txt",
    "email_worker_url": "https://cursor-email-worker.jar711red.workers.dev",
    "phone_country_id": 16,       # UK
    "phone_country_code": "44",
    "phone_service": "ot",
}

# %% Verify Paths Exist
def verify_paths():
    """Check all required paths exist"""
    checks = [
        ("OctoBrowser", OCTO_APPIMAGE),
        ("HeroSMS module", os.path.join(HEROSMS_PATH, "herosms.py")),
        ("Prefixes file", CONFIG["prefixes_file"]),
    ]
    
    all_ok = True
    for name, path in checks:
        exists = os.path.exists(path)
        status = "✓" if exists else "✗ MISSING"
        print(f"  {status} {name}: {path}")
        if not exists:
            all_ok = False
    
    return all_ok

# %% Test: Run this cell to verify config
if __name__ == "__main__" or "get_ipython" in dir():
    print("Configuration loaded:")
    print(f"  OCTO_API: {OCTO_API}")
    print(f"  Email domain: {CONFIG['email_domain']}")
    print(f"  Phone country: {CONFIG['phone_country_code']} (ID: {CONFIG['phone_country_id']})")
    print("\nPath verification:")
    verify_paths()
