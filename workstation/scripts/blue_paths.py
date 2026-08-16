"""Repo-root resolver for the blue domain tree.

Import-stable name is this file loaded via ``cred_loader`` (see cred_loader.py).
Walks up from any caller until secrets/cred.json or .git + trading exist.
"""
from __future__ import annotations

from pathlib import Path


def repo_root(start: Path | None = None) -> Path:
    here = (start or Path(__file__)).resolve()
    if here.is_file():
        here = here.parent
    for cand in [here, *here.parents]:
        if (cand / "secrets" / "cred.json").is_file():
            return cand
        if (cand / ".git").exists() and (cand / "trading").is_dir() and (cand / "cloud").is_dir():
            return cand
    # This file lives at workstation/scripts/blue_paths.py
    return Path(__file__).resolve().parents[2]


ROOT = repo_root()
CRED_JSON = ROOT / "secrets" / "cred.json"
FREQTRADE_USERDIR = ROOT / "trading" / "freqtrade"
SCRIPTS = ROOT / "workstation" / "scripts"
CLASH_BLUE_YML = ROOT / "network" / "clash" / "blue.yml"


def ensure_scripts_on_path(sys_mod) -> Path:
    """Insert workstation/scripts on sys.path (idempotent)."""
    s = str(SCRIPTS)
    if s not in sys_mod.path:
        sys_mod.path.insert(0, s)
    return SCRIPTS
