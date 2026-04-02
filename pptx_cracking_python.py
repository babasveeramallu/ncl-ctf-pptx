#!/usr/bin/env python3
"""Python-only PPTX cracking workflow helper.

This script keeps the Office/PPTX cracking flow in one file:
1) Extract an Office hash from a protected PPTX using office2john.py
2) Save the hash to a file (hashcat/john-compatible)
3) Run hashcat dictionary attack from Python via subprocess

Usage examples:
  python pptx_cracking_python.py extract --pptx "protected.pptx"
  python pptx_cracking_python.py crack --hash-file office_hash.txt --wordlist rockyou_full.txt
  python pptx_cracking_python.py run --pptx "protected.pptx" --wordlist rockyou_full.txt
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Optional


OFFICE_TO_HASHCAT_MODE = {
    "2007": 9400,
    "2010": 9500,
    "2013": 9600,
}


def repo_root() -> Path:
    return Path(__file__).resolve().parent


def bundled_office2john() -> Path:
    path = repo_root() / "office2john.py"
    if not path.exists():
        raise FileNotFoundError(f"office2john.py not found at: {path}")
    return path


def bundled_hashcat() -> Optional[Path]:
    path = repo_root() / "tools" / "hashcat-6.2.6" / "hashcat-6.2.6" / "hashcat.exe"
    if path.exists():
        return path
    return None


def extract_office_hash(pptx_path: Path, timeout_s: int = 90) -> tuple[str, str]:
    if not pptx_path.exists() or not pptx_path.is_file():
        raise FileNotFoundError(f"PPTX file not found: {pptx_path}")

    cmd = [sys.executable, str(bundled_office2john()), str(pptx_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s, check=False)

    office_lines = [line.strip() for line in (proc.stdout or "").splitlines() if "$office$" in line]
    if not office_lines:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        detail = stderr or stdout or "No office hash found in output"
        raise RuntimeError(f"Hash extraction failed: {detail}")

    office_hash = office_lines[0]
    version = "unknown"
    for tag in ("*2007*", "*2010*", "*2013*"):
        if tag in office_hash:
            version = tag.strip("*")
            break

    return office_hash, version


def write_hash_file(office_hash: str, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(f"{office_hash}\n", encoding="utf-8")
    return output_path


def crack_hash_with_hashcat(
    hash_file: Path,
    wordlist: Path,
    version: str,
    hashcat_path: Optional[Path] = None,
    potfile: Optional[Path] = None,
    runtime: Optional[int] = None,
    extra_args: Optional[list[str]] = None,
) -> int:
    if not hash_file.exists():
        raise FileNotFoundError(f"Hash file not found: {hash_file}")
    if not wordlist.exists():
        raise FileNotFoundError(f"Wordlist not found: {wordlist}")

    if version not in OFFICE_TO_HASHCAT_MODE:
        supported = ", ".join(sorted(OFFICE_TO_HASHCAT_MODE))
        raise ValueError(f"Unsupported Office version '{version}'. Supported versions: {supported}")

    mode = OFFICE_TO_HASHCAT_MODE[version]
    hashcat_exe = hashcat_path or bundled_hashcat()
    if hashcat_exe is None or not hashcat_exe.exists():
        raise FileNotFoundError(
            "hashcat.exe not found. Pass --hashcat-path or place it under tools/hashcat-6.2.6/hashcat-6.2.6/"
        )

    cmd = [
        str(hashcat_exe),
        "-m",
        str(mode),
        "-a",
        "0",
        str(hash_file),
        str(wordlist),
        "--status",
        "--status-timer",
        "30",
    ]

    if potfile:
        cmd.extend(["--potfile-path", str(potfile)])
    if runtime and runtime > 0:
        cmd.extend(["--runtime", str(runtime)])
    if extra_args:
        cmd.extend(extra_args)

    print("Running:", " ".join(cmd))
    proc = subprocess.run(cmd, check=False)
    return proc.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Python-only helper for PPTX Office hash extraction + cracking")
    sub = parser.add_subparsers(dest="command", required=True)

    p_extract = sub.add_parser("extract", help="Extract Office hash from PPTX")
    p_extract.add_argument("--pptx", required=True, type=Path, help="Path to protected .pptx file")
    p_extract.add_argument("--out", type=Path, default=Path("office_hash.txt"), help="Output hash file")

    p_crack = sub.add_parser("crack", help="Run hashcat on an existing Office hash")
    p_crack.add_argument("--hash-file", required=True, type=Path, help="Path to file containing $office$ hash")
    p_crack.add_argument("--wordlist", required=True, type=Path, help="Wordlist path")
    p_crack.add_argument("--version", choices=sorted(OFFICE_TO_HASHCAT_MODE.keys()), default="2013")
    p_crack.add_argument("--hashcat-path", type=Path, default=None, help="Optional hashcat.exe path")
    p_crack.add_argument("--potfile", type=Path, default=Path("_office_tmp.pot"), help="Potfile path")
    p_crack.add_argument("--runtime", type=int, default=0, help="Runtime limit in seconds (0 = no limit)")

    p_run = sub.add_parser("run", help="Extract hash then crack in one command")
    p_run.add_argument("--pptx", required=True, type=Path, help="Path to protected .pptx file")
    p_run.add_argument("--wordlist", required=True, type=Path, help="Wordlist path")
    p_run.add_argument("--out", type=Path, default=Path("office_hash.txt"), help="Output hash file")
    p_run.add_argument("--hashcat-path", type=Path, default=None, help="Optional hashcat.exe path")
    p_run.add_argument("--potfile", type=Path, default=Path("_office_tmp.pot"), help="Potfile path")
    p_run.add_argument("--runtime", type=int, default=0, help="Runtime limit in seconds (0 = no limit)")

    return parser


def cmd_extract(args: argparse.Namespace) -> int:
    office_hash, version = extract_office_hash(args.pptx)
    out = write_hash_file(office_hash, args.out)
    print(f"[OK] Extracted Office {version} hash")
    print(f"[OK] Wrote hash file: {out}")
    return 0


def cmd_crack(args: argparse.Namespace) -> int:
    return crack_hash_with_hashcat(
        hash_file=args.hash_file,
        wordlist=args.wordlist,
        version=args.version,
        hashcat_path=args.hashcat_path,
        potfile=args.potfile,
        runtime=args.runtime,
    )


def cmd_run(args: argparse.Namespace) -> int:
    office_hash, version = extract_office_hash(args.pptx)
    out = write_hash_file(office_hash, args.out)
    print(f"[OK] Extracted Office {version} hash")
    print(f"[OK] Wrote hash file: {out}")

    return crack_hash_with_hashcat(
        hash_file=out,
        wordlist=args.wordlist,
        version=version,
        hashcat_path=args.hashcat_path,
        potfile=args.potfile,
        runtime=args.runtime,
    )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "extract":
        return cmd_extract(args)
    if args.command == "crack":
        return cmd_crack(args)
    if args.command == "run":
        return cmd_run(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
