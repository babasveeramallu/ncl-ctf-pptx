from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path
from typing import Any, Dict

TOOLS: Dict[str, Dict[str, Any]] = {
    "hashcat": {"cmd": "hashcat --version", "critical": False, "fallback": "john"},
    "john": {"cmd": "john --version", "critical": False, "fallback": "passlib_brute"},
    "tshark": {"cmd": "tshark --version", "critical": False, "fallback": "dpkt_parse"},
    "ciphey": {"cmd": "ciphey --version", "critical": False, "fallback": "skip_step_10"},
    "steghide": {"cmd": "steghide --version", "critical": False, "fallback": "zsteg_only"},
    "binwalk": {"cmd": "binwalk --version", "critical": False, "fallback": "strings_scan"},
    "zsteg": {"cmd": "zsteg --version", "critical": False, "fallback": "strings_scan"},
}


def check_tools() -> dict:
    status = {}
    for name, cfg in TOOLS.items():
        available = shutil.which(name) is not None
        status[name] = {
            "available": available,
            "fallback": cfg["fallback"] if not available else None,
            "critical": cfg["critical"],
        }
    return status


def initialize_database(db_path: str, schema_path: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        with open(schema_path, "r", encoding="utf-8") as fh:
            conn.executescript(fh.read())
        conn.commit()
