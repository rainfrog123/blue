#!/usr/bin/env python3
"""Write gitignored config/secrets.json from secrets/cred.json."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "workstation" / "scripts"))
from cred_loader import get_binance, get_freqtrade

OUT = Path(__file__).resolve().parent / "config" / "secrets.json"


def main() -> None:
    bn = get_binance()
    ft = get_freqtrade()
    overlay = {
        "exchange": {
            "key": bn["api_key"],
            "secret": bn["api_secret"],
        },
        "api_server": {
            "jwt_secret_key": ft["jwt_secret_key"],
            "ws_token": ft["ws_token"],
            "username": ft.get("username", "freqtrader"),
            "password": ft["password"],
        },
    }
    OUT.write_text(json.dumps(overlay, indent=4) + "\n", encoding="utf-8")
    print("wrote", OUT.relative_to(OUT.parents[2]), "(gitignored)")


if __name__ == "__main__":
    main()
