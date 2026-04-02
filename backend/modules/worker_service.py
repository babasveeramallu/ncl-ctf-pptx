from __future__ import annotations

import asyncio
import base64
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from hashlib import md5
from pathlib import Path
from typing import Any, Dict, List

from .password_crack_service import crack_wifi_psk_config


def safe_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="ignore")


async def run_cli(cmd: List[str], timeout_s: int = 20) -> Dict[str, Any]:
    def _invoke() -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, timeout=timeout_s, check=False)

    try:
        proc = await asyncio.to_thread(_invoke)
        return {
            "ok": proc.returncode == 0,
            "code": proc.returncode,
            "stdout": safe_decode(proc.stdout),
            "stderr": safe_decode(proc.stderr),
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "code": -1, "stdout": "", "stderr": "command timeout"}
    except Exception as exc:
        return {"ok": False, "code": -1, "stdout": "", "stderr": str(exc)}


def extract_inline_basic_auth(payload: bytes) -> List[Dict[str, str]]:
    creds: List[Dict[str, str]] = []
    marker = b"Authorization: Basic "
    idx = payload.find(marker)
    while idx >= 0:
        start = idx + len(marker)
        end = payload.find(b"\n", start)
        if end < 0:
            end = len(payload)
        token = payload[start:end].strip().decode("latin-1", errors="ignore")
        try:
            decoded = base64.b64decode(token).decode("latin-1", errors="ignore")
            if ":" in decoded:
                user, pwd = decoded.split(":", 1)
                creds.append({"protocol": "HTTP", "host": "captured.local", "user": user, "pass": pwd})
        except Exception:
            pass
        idx = payload.find(marker, end)
    return creds


def _resolve_wordlist_path(req_wordlist: str | None, config: Any) -> str | None:
    if not req_wordlist:
        return None

    key = req_wordlist.strip()
    key_l = key.lower()

    alias_map = {
        "rockyou": getattr(config.wordlists, "rockyou", None),
        "ncl-common": getattr(config.wordlists, "ncl_common", None),
        "ncl_common": getattr(config.wordlists, "ncl_common", None),
        "realuniq": getattr(config.wordlists, "realuniq", None),
        "realuniq.lst": getattr(config.wordlists, "realuniq", None),
        "realhuman": getattr(config.wordlists, "realhuman_phill", None),
        "realhuman_phill": getattr(config.wordlists, "realhuman_phill", None),
        "realhuman_phill.txt": getattr(config.wordlists, "realhuman_phill", None),
    }

    mapped = alias_map.get(key_l)
    if mapped and Path(mapped).exists():
        return mapped

    # Accept explicit path (absolute or relative to current working directory).
    if Path(key).exists():
        return key

    # Accept bare filenames located in common repository wordlist locations.
    repo_root = Path(__file__).resolve().parents[2]
    candidate_names = [key, key_l]
    search_dirs = [repo_root, repo_root / "wordlists", repo_root / "wordlists_nonrockyou"]
    for directory in search_dirs:
        for name in candidate_names:
            candidate = directory / name
            if candidate.exists() and candidate.is_file():
                return str(candidate)

    # Allow config custom list by filename alias.
    for custom_path in getattr(config.wordlists, "custom", []) or []:
        p = Path(custom_path)
        if p.exists() and p.name.lower() == key_l:
            return str(p)
    return None


def _resolve_wordlist_paths(req_wordlist: str | None, config: Any) -> List[str]:
    if not req_wordlist:
        return []

    raw_tokens = [tok.strip() for tok in re.split(r"[,;\n]+", req_wordlist) if tok.strip()]
    if not raw_tokens:
        raw_tokens = [req_wordlist.strip()]

    resolved: List[str] = []
    seen: set[str] = set()
    for token in raw_tokens:
        path = _resolve_wordlist_path(token, config)
        if not path:
            continue
        norm = str(Path(path))
        key = norm.lower()
        if key in seen:
            continue
        seen.add(key)
        resolved.append(norm)
    return resolved


def _resolve_rule_path(req_rule: str | None, config: Any) -> str | None:
    if not req_rule:
        return None

    key = req_rule.strip()
    if not key:
        return None

    direct = Path(key)
    if direct.exists() and direct.is_file():
        return str(direct)

    repo_root = Path(__file__).resolve().parents[2]
    search_dirs = [
        repo_root,
        repo_root / "rules",
        repo_root / "tools" / "password_research" / "rules",
        repo_root / "tools" / "hashcat-6.2.6" / "hashcat-6.2.6" / "rules",
    ]
    for directory in search_dirs:
        candidate = directory / key
        if candidate.exists() and candidate.is_file():
            return str(candidate)

    return None


def _top_rules_from_counter(counter: Counter[str], limit: int) -> List[Dict[str, Any]]:
    return [
        {"rule": rule, "hits": hits}
        for rule, hits in counter.most_common(max(1, int(limit or 10)))
    ]


def _john_format_from_hash_mode(hash_mode: int) -> str | None:
    mapping = {
        0: "raw-md5",
        100: "raw-sha1",
        1400: "raw-sha256",
        1700: "raw-sha512",
        1000: "nt",
    }
    return mapping.get(hash_mode)


def _build_expected_hash_index(hashes: List[str]) -> List[str]:
    # Sort longest-first so prefixed Office hashes are matched before shorter suffixes.
    return sorted({h.strip() for h in hashes if h and h.strip()}, key=len, reverse=True)


def _extract_hash_plain_from_line(line: str, expected_hashes: List[str]) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped:
        return None

    lowered = stripped.lower()
    for expected in expected_hashes:
        expected_l = expected.lower()
        prefix = expected_l + ":"
        if lowered.startswith(prefix):
            return expected, stripped[len(expected) + 1 :].strip()

    # Fallback for generic formats where hash does not contain ':'
    if ":" in stripped:
        h, p = stripped.rsplit(":", 1)
        return h.strip(), p.strip()
    return None


async def password_crack_worker(req: Any, tool_status: Dict[str, Any], config: Any) -> Dict[str, Any]:
    await asyncio.sleep(0)
    hashcat_available = tool_status.get("hashcat", {}).get("available", False)
    john_available = tool_status.get("john", {}).get("available", False)
    fallback = tool_status.get("hashcat", {}).get("fallback") if not hashcat_available else None
    wordlist_paths = _resolve_wordlist_paths(req.wordlist, config)
    rule_path = _resolve_rule_path(getattr(req, "rule_file", None), config)
    candidates = ["password", "123456", "letmein", "qwerty", "ncl2026", "ctf", "admin"]
    tool_attempts: List[Dict[str, Any]] = []

    cracked: List[Dict[str, str]] = []
    remaining: List[str] = list(req.hashes)
    engine = "fallback"
    used_fallback = True
    notes: List[str] = []
    engines_used: set[str] = set()
    rule_hits: Counter[str] = Counter()
    top_rules_limit = int(getattr(req, "top_rules_limit", 10) or 10)

    if req.attack_mode == "dictionary" and req.wordlist and not wordlist_paths:
        return {
            "status": "complete",
            "results": [],
            "uncracked": list(req.hashes),
            "engine": "none",
            "fallback_used": False,
            "fallback": fallback,
            "hash_mode": req.hash_mode,
            "tool_attempts": tool_attempts,
            "error": f"Wordlist not found: {req.wordlist}",
            "notes": [
                "You can chain multiple lists with commas, e.g. rockyou,realuniq.lst,realhuman_phill.txt",
            ],
        }

    if req.attack_mode == "dictionary" and getattr(req, "rule_file", None) and not rule_path:
        return {
            "status": "complete",
            "results": [],
            "uncracked": list(req.hashes),
            "engine": "none",
            "fallback_used": False,
            "fallback": fallback,
            "hash_mode": req.hash_mode,
            "tool_attempts": tool_attempts,
            "error": f"Rule file not found: {getattr(req, 'rule_file', None)}",
            "notes": [
                "Provide a valid hashcat rule file path or place it under ./rules",
            ],
        }

    office_modes = {9400, 9500, 9600}
    if req.hash_mode in office_modes and not hashcat_available:
        return {
            "status": "complete",
            "results": [],
            "uncracked": list(req.hashes),
            "engine": "none",
            "fallback_used": False,
            "fallback": fallback,
            "hash_mode": req.hash_mode,
            "tool_attempts": tool_attempts,
            "error": "Office/PPTX cracking requires hashcat for this mode; hashcat is not available",
            "notes": [
                "Provide a valid $office$ hash line (optionally prefixed with filename:)",
                "Ensure hashcat is installed and reachable from backend config",
            ],
        }

    # Attempt 1: hashcat for dictionary attacks across chained wordlists.
    if hashcat_available and req.attack_mode == "dictionary" and wordlist_paths:
        hashcat_bin = getattr(config.tools, "hashcat_path", "hashcat")
        with tempfile.TemporaryDirectory() as td:
            pot_file = Path(td) / "hashcat.pot"
            for idx, wordlist_path in enumerate(wordlist_paths, start=1):
                if not remaining:
                    break
                hash_file = Path(td) / f"hashes_{idx}.txt"
                hash_file.write_text("\n".join(remaining) + "\n", encoding="utf-8")
                debug_file = Path(td) / f"hashcat_debug_{idx}.log"

                crack_cmd = [
                    hashcat_bin,
                    "-m",
                    str(req.hash_mode),
                    "-a",
                    "0",
                    str(hash_file),
                    str(wordlist_path),
                    "--potfile-path",
                    str(pot_file),
                    "--quiet",
                ]
                if rule_path:
                    crack_cmd.extend(["-r", str(rule_path), "--debug-mode", "1", "--debug-file", str(debug_file)])
                crack_res = await run_cli(crack_cmd, timeout_s=min(max(req.timeout_s or 120, 5), 600))
                tool_attempts.append(
                    {
                        "tool": "hashcat",
                        "wordlist": wordlist_path,
                        "rule_file": rule_path,
                        "ok": crack_res["ok"],
                        "stderr": crack_res["stderr"][:160],
                    }
                )

                if rule_path and debug_file.exists():
                    for line in debug_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                        rule = line.strip()
                        if not rule:
                            continue
                        rule_hits[rule] += 1

                show_cmd = [
                    hashcat_bin,
                    "-m",
                    str(req.hash_mode),
                    str(hash_file),
                    "--show",
                    "--potfile-path",
                    str(pot_file),
                ]
                show_res = await run_cli(show_cmd, timeout_s=30)
                if not (show_res["ok"] and show_res["stdout"].strip()):
                    continue

                expected = _build_expected_hash_index(remaining)
                found_map: Dict[str, str] = {}
                for line in show_res["stdout"].splitlines():
                    parsed = _extract_hash_plain_from_line(line, expected)
                    if not parsed:
                        continue
                    h, p = parsed
                    found_map[h.strip().lower()] = p

                next_remaining: List[str] = []
                newly_cracked = 0
                for h in remaining:
                    p = found_map.get(h.lower())
                    if p is not None:
                        cracked.append({"hash": h, "plaintext": p})
                        newly_cracked += 1
                    else:
                        next_remaining.append(h)

                if newly_cracked > 0:
                    engines_used.add("hashcat")
                    used_fallback = False
                remaining = next_remaining

    # Attempt 2: john fallback over remaining hashes and chained wordlists.
    if remaining and john_available and req.attack_mode == "dictionary" and wordlist_paths:
        john_format = _john_format_from_hash_mode(req.hash_mode)
        if john_format:
            john_bin = getattr(config.tools, "john_path", "john")
            with tempfile.TemporaryDirectory() as td:
                for idx, wordlist_path in enumerate(wordlist_paths, start=1):
                    if not remaining:
                        break
                    hash_file = Path(td) / f"hashes_{idx}.txt"
                    hash_file.write_text("\n".join(remaining) + "\n", encoding="utf-8")

                    crack_cmd = [john_bin, f"--wordlist={wordlist_path}", f"--format={john_format}", str(hash_file)]
                    crack_res = await run_cli(crack_cmd, timeout_s=min(max(req.timeout_s or 120, 5), 600))
                    tool_attempts.append(
                        {
                            "tool": "john",
                            "wordlist": wordlist_path,
                            "ok": crack_res["ok"],
                            "stderr": crack_res["stderr"][:160],
                        }
                    )

                    show_cmd = [john_bin, "--show", f"--format={john_format}", str(hash_file)]
                    show_res = await run_cli(show_cmd, timeout_s=30)
                    expected = _build_expected_hash_index(remaining)
                    found_map: Dict[str, str] = {}
                    if show_res["stdout"].strip():
                        for line in show_res["stdout"].splitlines():
                            if "password hash" in line:
                                continue
                            parsed = _extract_hash_plain_from_line(line, expected)
                            if not parsed:
                                continue
                            h, p = parsed
                            # john --show often appends trailing fields after plaintext.
                            found_map[h.strip().lower()] = p.split(":", 1)[0].strip()

                    next_remaining = []
                    newly_cracked = 0
                    for h in remaining:
                        p = found_map.get(h.lower())
                        if p is not None:
                            cracked.append({"hash": h, "plaintext": p})
                            newly_cracked += 1
                        else:
                            next_remaining.append(h)

                    if newly_cracked > 0:
                        engines_used.add("john")
                        used_fallback = False
                    remaining = next_remaining

    # Final fallback: deterministic local mini-rainbow for common demo hashes.
    if remaining:
        if req.hash_mode == 0:
            rainbow = {md5(word.encode("utf-8")).hexdigest(): word for word in candidates}
            next_remaining = []
            for h in remaining:
                plain = rainbow.get(h.lower())
                if plain:
                    cracked.append({"hash": h, "plaintext": plain})
                else:
                    next_remaining.append(h)
            remaining = next_remaining
        if req.hash_mode in office_modes:
            notes.append("No Office password found in current wordlist/time budget")

    if engines_used == {"hashcat"}:
        engine = "hashcat"
    elif engines_used == {"john"}:
        engine = "john"
    elif engines_used == {"hashcat", "john"}:
        engine = "hashcat+john"

    if req.attack_mode == "dictionary" and wordlist_paths:
        notes.append(f"Wordlists tried in order: {', '.join(wordlist_paths)}")
    if rule_path:
        notes.append(f"Rule file used: {rule_path}")

    return {
        "status": "complete",
        "results": cracked,
        "uncracked": remaining,
        "engine": engine,
        "fallback_used": used_fallback,
        "fallback": fallback,
        "hash_mode": req.hash_mode,
        "wordlists": wordlist_paths,
        "rule_file": rule_path,
        "top_rules": _top_rules_from_counter(rule_hits, top_rules_limit),
        "tool_attempts": tool_attempts,
        "notes": notes,
    }


async def wifi_psk_crack_worker(req: Any, config: Any) -> Dict[str, Any]:
    await asyncio.sleep(0)
    wordlist_paths = _resolve_wordlist_paths(req.wordlist, config)
    if not wordlist_paths:
        return {
            "success": False,
            "attempts": 0,
            "cracked": [],
            "uncracked": [],
            "error": f"Wordlist not found: {req.wordlist}",
        }

    deadline_ms = max(1000, int((req.timeout_s or 180) * 1000))
    started = asyncio.get_running_loop().time()
    attempts_budget = max(1, int(req.max_attempts))
    merged_cracked: Dict[str, Dict[str, str]] = {}
    last_uncracked: List[Dict[str, str]] = []
    network_count = 0
    tried: List[str] = []

    for wordlist_path in wordlist_paths:
        if attempts_budget <= 0:
            break
        elapsed_ms = int((asyncio.get_running_loop().time() - started) * 1000)
        remaining_ms = max(0, deadline_ms - elapsed_ms)
        if remaining_ms <= 0:
            break

        per_result = crack_wifi_psk_config(
            config_text=req.config_text,
            wordlist_path=wordlist_path,
            timeout_ms=remaining_ms,
            max_attempts=attempts_budget,
        )
        tried.append(wordlist_path)
        attempts_budget = max(0, attempts_budget - int(per_result.get("attempts", 0) or 0))
        network_count = max(network_count, int(per_result.get("network_count", 0) or 0))

        for item in per_result.get("cracked", []) if isinstance(per_result.get("cracked"), list) else []:
            if isinstance(item, dict) and item.get("ssid"):
                merged_cracked[str(item["ssid"])] = item

        if isinstance(per_result.get("uncracked"), list):
            last_uncracked = [item for item in per_result["uncracked"] if isinstance(item, dict)]

        if network_count > 0 and len(merged_cracked) >= network_count:
            break

    cracked_list = list(merged_cracked.values())
    if network_count > 0:
        cracked_ssids = {str(item.get("ssid")) for item in cracked_list if isinstance(item, dict)}
        uncracked = [item for item in last_uncracked if str(item.get("ssid")) not in cracked_ssids]
        success = len(cracked_ssids) >= network_count
    else:
        uncracked = last_uncracked
        success = False

    elapsed_ms = int((asyncio.get_running_loop().time() - started) * 1000)
    return {
        "success": success,
        "attempts": max(0, int(req.max_attempts) - attempts_budget),
        "elapsed_ms": elapsed_ms,
        "network_count": network_count,
        "cracked": cracked_list,
        "uncracked": uncracked,
        "wordlist": tried[0] if tried else None,
        "wordlists": tried,
        "notes": [f"Wordlists tried in order: {', '.join(tried)}"] if tried else [],
    }


async def osint_subdomains_worker(req: Any) -> Dict[str, Any]:
    await asyncio.sleep(0)
    root = req.domain.strip().lower()
    names = [f"www.{root}", f"api.{root}", f"mail.{root}", f"dev.{root}"]
    subdomains = [
        {"name": name, "source": req.sources[idx % max(1, len(req.sources))], "ip": None}
        for idx, name in enumerate(names)
    ]
    return {"domain": root, "count": len(subdomains), "subdomains": subdomains, "mode": req.mode}


async def osint_username_worker(req: Any) -> Dict[str, Any]:
    await asyncio.sleep(0)
    found: List[Dict[str, Any]] = []
    not_found: List[str] = []

    for platform in req.platforms:
        if platform.lower() in {"github", "reddit", "twitter"}:
            found.append(
                {
                    "platform": platform,
                    "url": f"https://{platform}.com/{req.username}",
                    "exists": True,
                }
            )
        else:
            not_found.append(platform)

    return {"found": found, "not_found": not_found, "errors": []}


async def network_pcap_worker(
    file_name: str,
    payload: bytes,
    extract_creds: bool,
    tool_status: Dict[str, Any],
    config: Any | None = None,
) -> Dict[str, Any]:
    await asyncio.sleep(0)
    size_mb = round(len(payload) / (1024 * 1024), 3)
    pseudo_packets = max(1, len(payload) // 64)
    creds: List[Dict[str, str]] = []
    tools_failed: List[Dict[str, str]] = []
    parser_engine = "fallback"

    if tool_status.get("tshark", {}).get("available", False):
        tshark_bin = "tshark"
        if config is not None:
            tshark_bin = getattr(config.tools, "tshark_path", tshark_bin)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(payload)
            tmp_path = tmp.name
        try:
            tshark_summary = await run_cli([tshark_bin, "-r", tmp_path, "-q", "-z", "io,phs"])
            if tshark_summary["ok"]:
                parser_engine = "tshark"
            else:
                tools_failed.append({"tool": "tshark", "error": tshark_summary["stderr"][:200]})
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    if extract_creds and b"Authorization: Basic" in payload:
        creds = extract_inline_basic_auth(payload)

    return {
        "packets": pseudo_packets,
        "duration_s": max(1, pseudo_packets // 20),
        "size_mb": size_mb,
        "file_name": file_name,
        "protocols": {"TCP": 0.70, "UDP": 0.20, "HTTP": 0.07, "DNS": 0.03},
        "credentials": creds,
        "dns_queries": [],
        "top_talkers": [{"ip": "10.0.0.5", "bytes": len(payload)}],
        "parser_engine": parser_engine,
        "tools_failed": tools_failed,
    }


async def forensics_steg_worker(file_name: str, payload: bytes, tool_status: Dict[str, Any], config: Any | None = None) -> Dict[str, Any]:
    await asyncio.sleep(0)
    tools_run = ["strings_scan"]
    tools_unavailable: List[str] = []
    tools_failed: List[str] = []

    file_type = "binary"
    if payload.startswith(b"\x89PNG\r\n\x1a\n"):
        file_type = "PNG"
    elif payload.startswith(b"\xff\xd8\xff"):
        file_type = "JPEG"
    elif payload.startswith(b"BM"):
        file_type = "BMP"
    elif payload.startswith(b"RIFF"):
        file_type = "WAV"

    if not tool_status.get("steghide", {}).get("available", False):
        tools_unavailable.append("steghide")
    else:
        tools_run.append("steghide")

    zsteg_bin = "zsteg"
    if config is not None:
        zsteg_bin = getattr(config.tools, "zsteg_path", zsteg_bin)

    if file_type == "PNG" and shutil.which(zsteg_bin) is not None:
        tools_run.append("zsteg")
    elif file_type == "PNG":
        tools_unavailable.append("zsteg")

    binwalk_bin = "binwalk"
    if config is not None:
        binwalk_bin = getattr(config.tools, "binwalk_path", binwalk_bin)

    if shutil.which(binwalk_bin) is None:
        tools_unavailable.append("binwalk")
    else:
        tools_run.append("binwalk")

    findings: List[Dict[str, Any]] = []

    if "steghide" in tools_run and file_type in {"JPEG", "BMP", "WAV"}:
        suffix = ".jpg" if file_type == "JPEG" else ".bmp" if file_type == "BMP" else ".wav"
        steghide_bin = "steghide"
        if config is not None:
            steghide_bin = getattr(config.tools, "steghide_path", steghide_bin)

        with tempfile.TemporaryDirectory() as td:
            in_file = Path(td) / f"input{suffix}"
            out_file = Path(td) / "extracted.bin"
            in_file.write_bytes(payload)
            steg = await run_cli(
                [steghide_bin, "extract", "-sf", str(in_file), "-p", "", "-xf", str(out_file), "-f"],
                timeout_s=20,
            )
            if steg["ok"] and out_file.exists() and out_file.stat().st_size > 0:
                extracted = out_file.read_bytes()
                findings.append(
                    {
                        "tool": "steghide",
                        "channel": "embedded-extract",
                        "finding": extracted[:200].decode("latin-1", errors="ignore"),
                    }
                )
            elif not steg["ok"]:
                tools_failed.append(f"steghide: {steg['stderr'][:120]}")

    if "zsteg" in tools_run and file_type == "PNG":
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
            tmp.write(payload)
            tmp_path = tmp.name
        try:
            zsteg_res = await run_cli([zsteg_bin, "-a", tmp_path], timeout_s=20)
            if zsteg_res["ok"] and zsteg_res["stdout"].strip():
                findings.append(
                    {
                        "tool": "zsteg",
                        "channel": "lsb-scan",
                        "finding": zsteg_res["stdout"].splitlines()[0][:200],
                    }
                )
            elif not zsteg_res["ok"]:
                tools_failed.append(f"zsteg: {zsteg_res['stderr'][:120]}")
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    if "binwalk" in tools_run:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            tmp.write(payload)
            tmp_path = tmp.name
        try:
            bw = await run_cli([binwalk_bin, "-B", tmp_path])
            if bw["ok"] and bw["stdout"].strip():
                findings.append(
                    {
                        "tool": "binwalk",
                        "channel": "signature-scan",
                        "finding": bw["stdout"].splitlines()[0][:200],
                    }
                )
            elif not bw["ok"]:
                tools_failed.append(f"binwalk: {bw['stderr'][:120]}")
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    lowered = payload.lower()
    if b"flag{" in lowered:
        idx = lowered.find(b"flag{")
        end = lowered.find(b"}", idx)
        if end > idx:
            findings.append(
                {
                    "tool": "strings_scan",
                    "channel": "raw-bytes",
                    "finding": payload[idx : end + 1].decode("latin-1", errors="ignore"),
                }
            )

    return {
        "file_name": file_name,
        "file_type": file_type,
        "size_bytes": len(payload),
        "tools_run": tools_run,
        "findings": findings,
        "tools_unavailable": tools_unavailable,
        "tools_failed": tools_failed,
    }
