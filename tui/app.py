from __future__ import annotations

import json
import asyncio
import re
import subprocess
import tempfile
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

import httpx
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Footer, Header, Input, Select, Static


def _format_step(step: Dict[str, Any]) -> str:
    head = f"Step {step.get('step', '?')}: {step.get('op', 'unknown')} | ok={step.get('ok', False)}"
    output = f"Output: {str(step.get('output', ''))[:240]}"
    lines = [head, output]

    metadata = step.get("metadata")
    if isinstance(metadata, dict):
        lines.append("Metadata:")
        for key, value in metadata.items():
            if key == "candidates" and isinstance(value, list):
                lines.append(f"  {key}:")
                for idx, candidate in enumerate(value[:3], start=1):
                    lines.append(f"    {idx}. {json.dumps(candidate, ensure_ascii=True)}")
            else:
                lines.append(f"  {key}: {value}")

    return "\n".join(lines)


def _read_clipboard_text() -> str:
    # Use PowerShell clipboard read on Windows to avoid terminal paste limitations.
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"],
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )
    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        raise RuntimeError(stderr or "clipboard read failed")
    return (completed.stdout or "").replace("\r\n", "\n").strip()


class ToolkitApp(App):
    TITLE = "BABA's CTF MASTER TOOLKIT"
    CSS = """
    Screen {
        align: center middle;
    }
    #main {
        width: 95%;
        height: 90%;
    }
    #result {
        border: round #888888;
        padding: 1;
        height: 2fr;
        overflow: auto;
    }
    #history {
        border: round #666666;
        padding: 1;
        height: 1fr;
        overflow: auto;
    }
    Input {
        width: 1fr;
    }
    #actions {
        height: auto;
    }
    .hidden {
        display: none;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="main"):
            yield Static("Backend: http://localhost:8765/api/v1")
            with Horizontal(id="view_mode_row"):
                yield Static("Workspace:")
                yield Select(
                    options=[("All", "all"), ("Crypto", "crypto"), ("Passwords", "passwords"), ("Logs", "logs")],
                    value="all",
                    id="view_mode",
                )
            with Horizontal(id="system_actions"):
                yield Button("Detect Tools", id="detect_tools")
                yield Button("View Capabilities", id="view_capabilities")
                yield Button("Smart Crack", id="smart_crack", variant="primary")
                yield Input(id="crib_hint", placeholder="Crib hint (optional): flag, the, password")
            yield Input(id="cipher_input", placeholder="Ciphertext or encoded input")
            with Horizontal(id="upload_row"):
                yield Input(id="upload_path", placeholder="Upload file path (text/image/audio/punch_card)")
                yield Select(
                    options=[("auto", "auto"), ("text", "text"), ("image", "image"), ("audio", "audio"), ("punch_card", "punch_card")],
                    value="auto",
                    id="upload_mode",
                )
                yield Button("Upload+Run", id="upload_run")
            with Horizontal(id="actions"):
                yield Select(
                    options=[
                        ("auto_strategy", "auto_strategy"),
                        ("byte_shift_break", "byte_shift_break"),
                        ("byte_affine_break", "byte_affine_break"),
                        ("mono_sub_break", "mono_sub_break"),
                        ("xor_repeating_break", "xor_repeating_break"),
                        ("xor_single_byte_break", "xor_single_byte_break"),
                        ("vigenere_break", "vigenere_break"),
                        ("rail_fence_break", "rail_fence_break"),
                        ("affine_break", "affine_break"),
                        ("playfair_break", "playfair_break"),
                    ],
                    value="auto_strategy",
                    id="operation",
                )
                yield Button("Paste Input", id="paste_input")
                yield Button("Run Recipe", id="run", variant="primary")
                yield Button("Explore", id="explore")
                yield Button("Apply Candidate Key", id="apply_key")
                yield Button("Load API History", id="load_history")
                yield Input(id="history_id", placeholder="entry id (history)")
                yield Button("Load Entry", id="load_history_entry")
                yield Button("Rerun Entry", id="rerun_history_entry")
                yield Input(id="compare_id", placeholder="compare id")
                yield Button("Compare", id="compare_history_entries")
            with Horizontal(id="password_actions"):
                yield Input(id="hash_input", placeholder="Hash(es), comma or newline separated")
                yield Select(
                    options=[
                        ("0 (MD5)", "0"),
                        ("1000 (NTLM)", "1000"),
                        ("1400 (SHA256)", "1400"),
                        ("1700 (SHA512)", "1700"),
                        ("9600 (Office 2013)", "9600"),
                    ],
                    value="0",
                    id="hash_mode",
                )
                yield Select(
                    options=[("dictionary", "dictionary"), ("brute", "brute"), ("mask", "mask"), ("hybrid", "hybrid")],
                    value="dictionary",
                    id="attack_mode",
                )
                yield Input(id="wordlist_name", placeholder="Wordlist(s): rockyou,realuniq.lst,realhuman_phill.txt or single path")
                yield Select(
                    options=[
                        ("Rule Preset: none", ""),
                        ("best64.rule", "best64.rule"),
                        ("d3ad0ne.rule", "d3ad0ne.rule"),
                        ("T0XlC.rule", "T0XlC.rule"),
                        ("generated2.rule", "generated2.rule"),
                        ("OneRuleToRuleThemAll.rule", "OneRuleToRuleThemAll.rule"),
                    ],
                    value="",
                    id="rule_preset",
                )
                yield Input(id="rule_file", placeholder="Rule file (optional): best64.rule or path")
                yield Button("Crack Hashes", id="crack_hashes")
                yield Button("Crack WiFi PSK", id="crack_wifi_psk")
                yield Input(id="job_id", placeholder="job id")
                yield Button("Poll Job", id="poll_job")
                yield Button("Cancel Job", id="cancel_job")
            with Horizontal(id="log_actions"):
                yield Input(id="log_limit", placeholder="log limit (default 25)")
                yield Select(
                    options=[
                        ("All Modules", ""),
                        ("Crypto", "crypto"),
                        ("Passwords", "passwords"),
                        ("Forensics", "forensics"),
                        ("Network", "network"),
                        ("OSINT", "osint"),
                    ],
                    value="",
                    id="log_module",
                )
                yield Button("Load Logs", id="load_logs")
                yield Input(id="log_id", placeholder="log id")
                yield Button("View Log", id="view_log")
            yield Select(options=[("No candidates", "")], value="", id="candidate_select")
            yield Static("Waiting for input...", id="result")
            yield Static("Session History\n- none", id="history")
        yield Footer()

    def on_mount(self) -> None:
        self._last_candidates: List[Dict[str, Any]] = []
        self._history: List[str] = []
        self._apply_workspace_mode("all")

    def _set_row_visible(self, row_id: str, visible: bool) -> None:
        row = self.query_one(f"#{row_id}", Horizontal)
        if visible:
            row.remove_class("hidden")
        else:
            row.add_class("hidden")

    def _apply_workspace_mode(self, mode: str) -> None:
        mode_map = {
            "all": {"upload_row", "actions", "password_actions", "log_actions"},
            "crypto": {"upload_row", "actions"},
            "passwords": {"password_actions"},
            "logs": {"log_actions"},
        }
        visible_rows = mode_map.get(mode, mode_map["all"])
        for row_id in {"upload_row", "actions", "password_actions", "log_actions"}:
            self._set_row_visible(row_id, row_id in visible_rows)

    def on_select_changed(self, event: Select.Changed) -> None:
        select_id = event.select.id
        if select_id == "view_mode":
            mode = str(event.value or "all")
            self._apply_workspace_mode(mode)
            return

        if select_id == "rule_preset":
            chosen = str(event.value or "").strip()
            rule_input = self.query_one("#rule_file", Input)
            if not chosen:
                return

            resolved = self._resolve_local_rule_file(chosen)
            rule_input.value = resolved or chosen
            return

    def _append_history(self, line: str) -> None:
        self._history.insert(0, line)
        self._history = self._history[:10]
        history_widget = self.query_one("#history", Static)
        history_widget.update("Session History\n" + "\n".join(f"- {item}" for item in self._history))

    def _looks_like_wifi_psk(self, text: str) -> bool:
        lowered = text.lower()
        return "ssid" in lowered and "psk" in lowered and "network" in lowered

    def _infer_hash_mode(self, value: str, mode_hint: int | None = None) -> int:
        if mode_hint is not None:
            return mode_hint

        v = value.strip()
        if v.startswith("$office$"):
            if "*2013*" in v:
                return 9600
            if "*2010*" in v:
                return 9500
            if "*2007*" in v:
                return 9400
            return 9600

        if v.startswith("$2a$") or v.startswith("$2b$") or v.startswith("$2y$"):
            return 3200

        if re.fullmatch(r"[0-9a-fA-F]{40}", v):
            return 100
        if re.fullmatch(r"[0-9a-fA-F]{64}", v):
            return 1400
        if re.fullmatch(r"[0-9a-fA-F]{128}", v):
            return 1700

        # MD5 vs NTLM are both hex-32; default to MD5 unless parsing hints say NTLM.
        return 0

    def _choose_attack_mode(self, hash_mode: int, hash_count: int, user_selected: str) -> str:
        selected = (user_selected or "dictionary").strip().lower()
        if selected not in {"dictionary", "brute", "mask", "hybrid"}:
            selected = "dictionary"

        # Office and bcrypt are expensive; dictionary/hybrid are the safest first pass.
        if hash_mode in {3200, 9400, 9500, 9600}:
            return "dictionary"

        # For multi-hash jobs, dictionary gives the best throughput/coverage balance.
        if hash_count > 1:
            return "dictionary"

        # Keep user intent for faster hash families when single-target cracking.
        return selected

    def _extract_hash_inputs(self, text: str) -> Dict[str, Any]:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        collected: List[str] = []
        mode_hint: int | None = None
        hints: List[str] = []

        simple_hash_re = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128}|\$2[aby]\$.+|\$office\$.+)$")

        for raw in lines:
            if raw.startswith("$office$"):
                collected.append(raw)
                mode_hint = self._infer_hash_mode(raw, mode_hint)
                hints.append("Detected Office hash format")
                continue

            parts = raw.split(":")
            if len(parts) >= 4 and re.fullmatch(r"[0-9a-fA-F]{32}", parts[3].strip()):
                collected.append(parts[3].strip())
                mode_hint = 1000
                hints.append("Detected pwdump-style NT hash field")
                continue

            if len(parts) == 2:
                left = parts[0].strip()
                right = parts[1].strip()
                if re.fullmatch(r"[0-9a-fA-F]{32}", left) and re.fullmatch(r"[0-9a-fA-F]{32}", right):
                    collected.append(right)
                    mode_hint = 1000
                    hints.append("Detected LM:NTLM pair; using NTLM side")
                    continue

            if simple_hash_re.fullmatch(raw):
                collected.append(raw)
                continue

            for token in re.findall(r"\$office\$\S+|\$2[aby]\$[./A-Za-z0-9]{56}|[0-9a-fA-F]{128}|[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32}", raw):
                collected.append(token)

        deduped: List[str] = []
        seen: set[str] = set()
        for item in collected:
            key = item.lower()
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)

        return {
            "hashes": deduped,
            "mode_hint": mode_hint,
            "hint_text": "; ".join(sorted(set(hints))) if hints else "",
        }

    def _looks_like_numeric_symbol_cipher(self, text: str) -> bool:
        compact = text.strip()
        if not re.fullmatch(r"[\d,\s\[\]\-:;]+", compact):
            return False
        values = [int(part) for part in re.findall(r"\d+", compact)]
        if len(values) < 10:
            return False
        return len(set(values)) >= 6

    def _resolve_local_wordlists(self, spec: str) -> List[str]:
        tokens = [tok.strip() for tok in re.split(r"[,;\n]+", spec or "") if tok.strip()]
        if not tokens:
            tokens = ["rockyou"]

        repo_root = Path.cwd()
        alias_candidates: Dict[str, List[Path]] = {
            "rockyou": [
                repo_root / "wordlists" / "rockyou.txt",
                repo_root / "rockyou_full.txt",
                repo_root / "rockyou_2025_05.txt",
            ],
            "ncl-common": [repo_root / "wordlists" / "ncl-common.txt"],
            "ncl_common": [repo_root / "wordlists" / "ncl-common.txt"],
            "realuniq": [repo_root / "realuniq.lst", repo_root / "wordlists" / "realuniq.lst"],
            "realuniq.lst": [repo_root / "realuniq.lst", repo_root / "wordlists" / "realuniq.lst"],
            "realhuman": [repo_root / "realhuman_phill.txt", repo_root / "wordlists" / "realhuman_phill.txt"],
            "realhuman_phill": [repo_root / "realhuman_phill.txt", repo_root / "wordlists" / "realhuman_phill.txt"],
            "realhuman_phill.txt": [repo_root / "realhuman_phill.txt", repo_root / "wordlists" / "realhuman_phill.txt"],
        }

        resolved: List[str] = []
        seen: set[str] = set()
        for token in tokens:
            low = token.lower()
            picked: Path | None = None

            # 1) direct explicit path
            direct = Path(token)
            if direct.exists() and direct.is_file():
                picked = direct
            else:
                # 2) alias resolution
                for cand in alias_candidates.get(low, []):
                    if cand.exists() and cand.is_file():
                        picked = cand
                        break
                # 3) bare filename in common dirs
                if picked is None:
                    for base in [repo_root, repo_root / "wordlists", repo_root / "wordlists_nonrockyou"]:
                        cand = base / token
                        if cand.exists() and cand.is_file():
                            picked = cand
                            break

            if picked is None:
                continue

            norm = str(picked)
            key = norm.lower()
            if key in seen:
                continue
            seen.add(key)
            resolved.append(norm)

        return resolved

    def _resolve_local_rule_file(self, rule_spec: str | None) -> str | None:
        if not rule_spec:
            return None

        token = str(rule_spec).strip()
        if not token:
            return None

        direct = Path(token)
        if direct.exists() and direct.is_file():
            return str(direct)

        repo_root = Path(__file__).resolve().parents[1]
        for base in [
            repo_root,
            repo_root / "rules",
            repo_root / "tools" / "password_research" / "rules",
            repo_root / "tools" / "hashcat-6.2.6" / "hashcat-6.2.6" / "rules",
        ]:
            cand = base / token
            if cand.exists() and cand.is_file():
                return str(cand)

        return None

    async def _run_local_hashcat_crack(
        self,
        hashes: List[str],
        hash_mode: int,
        attack_mode: str,
        wordlist_spec: str,
        rule_spec: str | None = None,
        timeout_s: int = 600,
    ) -> Dict[str, Any]:
        if attack_mode != "dictionary":
            return {"ok": False, "error": "Local fallback currently supports dictionary mode only"}

        wordlists = self._resolve_local_wordlists(wordlist_spec)
        if not wordlists:
            return {"ok": False, "error": f"No local wordlists resolved from: {wordlist_spec}"}

        rule_path = self._resolve_local_rule_file(rule_spec)
        if rule_spec and not rule_path:
            return {"ok": False, "error": f"Rule file not found: {rule_spec}"}

        def _run(cmd: List[str], timeout_value: int) -> subprocess.CompletedProcess:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_value, check=False)

        try:
            version_proc = await asyncio.to_thread(_run, ["hashcat", "--version"], 8)
            if version_proc.returncode != 0:
                return {"ok": False, "error": (version_proc.stderr or "hashcat unavailable").strip()}
        except Exception as exc:
            return {"ok": False, "error": f"hashcat unavailable: {exc}"}

        try:
            from backend.modules.worker_service import _build_expected_hash_index, _extract_hash_plain_from_line
        except Exception:
            _build_expected_hash_index = None
            _extract_hash_plain_from_line = None

        cracked: Dict[str, str] = {}
        remaining = list(hashes)
        attempts: List[Dict[str, Any]] = []
        rule_hits: Counter[str] = Counter()

        with tempfile.TemporaryDirectory() as td:
            pot_file = Path(td) / "local_hashcat.pot"
            for idx, wordlist in enumerate(wordlists, start=1):
                if not remaining:
                    break

                hash_file = Path(td) / f"hashes_{idx}.txt"
                hash_file.write_text("\n".join(remaining) + "\n", encoding="utf-8")
                debug_file = Path(td) / f"local_debug_{idx}.log"

                crack_cmd = [
                    "hashcat",
                    "-m",
                    str(hash_mode),
                    "-a",
                    "0",
                    str(hash_file),
                    str(wordlist),
                    "--potfile-path",
                    str(pot_file),
                    "--quiet",
                ]
                if rule_path:
                    crack_cmd.extend(["-r", str(rule_path), "--debug-mode", "1", "--debug-file", str(debug_file)])
                crack_proc = await asyncio.to_thread(_run, crack_cmd, max(5, min(timeout_s, 900)))
                attempts.append(
                    {
                        "tool": "hashcat-local",
                        "wordlist": str(wordlist),
                        "rule_file": rule_path,
                        "ok": crack_proc.returncode == 0,
                        "stderr": (crack_proc.stderr or "")[:160],
                    }
                )

                if rule_path and debug_file.exists():
                    for line in debug_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                        rule = line.strip()
                        if not rule:
                            continue
                        rule_hits[rule] += 1

                show_cmd = [
                    "hashcat",
                    "-m",
                    str(hash_mode),
                    str(hash_file),
                    "--show",
                    "--potfile-path",
                    str(pot_file),
                ]
                show_proc = await asyncio.to_thread(_run, show_cmd, 45)
                if show_proc.returncode != 0 or not (show_proc.stdout or "").strip():
                    continue

                found_map: Dict[str, str] = {}
                if _build_expected_hash_index is not None and _extract_hash_plain_from_line is not None:
                    expected = _build_expected_hash_index(remaining)
                    for line in (show_proc.stdout or "").splitlines():
                        parsed = _extract_hash_plain_from_line(line, expected)
                        if not parsed:
                            continue
                        h, p = parsed
                        found_map[h.strip().lower()] = p.strip()
                else:
                    for line in (show_proc.stdout or "").splitlines():
                        if ":" not in line:
                            continue
                        h, p = line.rsplit(":", 1)
                        found_map[h.strip().lower()] = p.strip()

                next_remaining: List[str] = []
                for h in remaining:
                    p = found_map.get(h.lower())
                    if p is not None:
                        cracked[h] = p
                    else:
                        next_remaining.append(h)
                remaining = next_remaining

        return {
            "ok": True,
            "engine": "hashcat-local",
            "results": [{"hash": h, "plaintext": p} for h, p in cracked.items()],
            "uncracked": remaining,
            "wordlists": wordlists,
            "rule_file": rule_path,
            "top_rules": [{"rule": rule, "hits": hits} for rule, hits in rule_hits.most_common(10)],
            "tool_attempts": attempts,
        }

    async def _run_local_wifi_psk_crack(
        self,
        config_text: str,
        wordlist_spec: str,
        timeout_s: int = 180,
        max_attempts: int = 500000,
    ) -> Dict[str, Any]:
        wordlists = self._resolve_local_wordlists(wordlist_spec)
        if not wordlists:
            return {"ok": False, "error": f"No local wordlists resolved from: {wordlist_spec}"}

        try:
            from backend.modules.password_crack_service import crack_wifi_psk_config
        except Exception as exc:
            return {"ok": False, "error": f"WiFi cracker unavailable: {exc}"}

        started = asyncio.get_running_loop().time()
        deadline_ms = max(1000, int(timeout_s * 1000))
        attempts_budget = max(1, int(max_attempts))
        merged_cracked: Dict[str, Dict[str, str]] = {}
        last_uncracked: List[Dict[str, str]] = []
        network_count = 0
        tried: List[str] = []

        for wordlist_path in wordlists:
            if attempts_budget <= 0:
                break

            elapsed_ms = int((asyncio.get_running_loop().time() - started) * 1000)
            remaining_ms = max(0, deadline_ms - elapsed_ms)
            if remaining_ms <= 0:
                break

            per_result = await asyncio.to_thread(
                crack_wifi_psk_config,
                config_text,
                str(wordlist_path),
                remaining_ms,
                attempts_budget,
            )
            tried.append(str(wordlist_path))
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
            "ok": True,
            "engine": "wifi-local",
            "success": success,
            "attempts": max(0, int(max_attempts) - attempts_budget),
            "elapsed_ms": elapsed_ms,
            "network_count": network_count,
            "cracked": cracked_list,
            "uncracked": uncracked,
            "wordlist": tried[0] if tried else None,
            "wordlists": tried,
        }

    @staticmethod
    @lru_cache(maxsize=1)
    def _load_guess_vocab() -> tuple[List[str], bool]:
        try:
            from wordfreq import top_n_list  # type: ignore

            vocab = [w.lower() for w in top_n_list("en", 80000) if w.isalpha()]
            vocab.extend(
                [
                    "windows",
                    "reboot",
                    "update",
                    "minutes",
                    "operation",
                    "launches",
                    "support",
                    "jira",
                ]
            )
            vocab.extend([f"{i:02d}" for i in range(100)])
            return (vocab, True)
        except Exception:
            fallback = [
                "the", "and", "for", "you", "that", "with", "this", "have", "from", "another",
                "would", "there", "their", "could", "should", "about", "other", "group", "hacker",
                "format", "secure", "password", "secret", "valid", "flags", "windows", "will",
                "reboot", "update", "minutes", "for", "an", "in",
            ]
            fallback.extend([f"{i:02d}" for i in range(100)])
            return (fallback, False)

    def _guess_sentence_from_symbol_words(self, words: List[List[int]], symbol_to_plain: Dict[int, str]) -> str:
        vocab, has_wordfreq = self._load_guess_vocab()

        def pattern(seq: List[int] | str) -> List[int]:
            mapping: Dict[Any, int] = {}
            out: List[int] = []
            next_idx = 0
            for item in seq:
                if item not in mapping:
                    mapping[item] = next_idx
                    next_idx += 1
                out.append(mapping[item])
            return out

        vocab_by_len: Dict[int, List[str]] = {}
        for word in vocab:
            vocab_by_len.setdefault(len(word), []).append(word)

        guessed_words: List[str] = []
        for cipher_word in words:
            fixed: Dict[int, str] = {}
            for idx, symbol in enumerate(cipher_word):
                if symbol in symbol_to_plain:
                    fixed[idx] = symbol_to_plain[symbol]

            target_pattern = pattern(cipher_word)
            candidates = []
            for plain_word in vocab_by_len.get(len(cipher_word), []):
                if pattern(plain_word) != target_pattern:
                    continue
                if any(plain_word[idx] != ch for idx, ch in fixed.items()):
                    continue
                candidates.append(plain_word)

            if not candidates:
                guessed_words.append("".join(symbol_to_plain.get(symbol, "?") for symbol in cipher_word))
                continue

            if has_wordfreq:
                try:
                    from wordfreq import zipf_frequency  # type: ignore

                    candidates.sort(key=lambda w: float(zipf_frequency(w, "en")), reverse=True)
                except Exception:
                    pass

            guessed_words.append(candidates[0])

        return " ".join(guessed_words)

    def _crib_decode_numeric_symbol_cipher(self, text: str, crib_hint: str) -> Dict[str, Any] | None:
        hint = "".join(ch for ch in (crib_hint or "").lower() if ch.isalpha())
        if len(hint) < 2:
            return None

        values = [int(part) for part in re.findall(r"\d+", text)]
        if not values:
            return None

        delimiter = Counter(values).most_common(1)[0][0]
        words: List[List[int]] = []
        current: List[int] = []
        for value in values:
            if value == delimiter:
                if current:
                    words.append(current)
                    current = []
                continue
            current.append(value)
        if current:
            words.append(current)

        if not words:
            return None

        def pattern(seq: List[int] | str) -> List[int]:
            mapping: Dict[Any, int] = {}
            out: List[int] = []
            next_idx = 0
            for item in seq:
                if item not in mapping:
                    mapping[item] = next_idx
                    next_idx += 1
                out.append(mapping[item])
            return out

        hint_pattern = pattern(hint)
        candidate_indexes = [
            idx for idx, word in enumerate(words) if len(word) == len(hint) and pattern(word) == hint_pattern
        ]
        if not candidate_indexes:
            return None

        # Prefer anchoring on early words, since challenge clues are often near the start.
        anchor_idx = candidate_indexes[0]
        anchor_word = words[anchor_idx]
        symbol_to_plain: Dict[int, str] = {}
        plain_to_symbol: Dict[str, int] = {}

        for symbol, plain_char in zip(anchor_word, hint):
            existing_plain = symbol_to_plain.get(symbol)
            existing_symbol = plain_to_symbol.get(plain_char)
            if (existing_plain is not None and existing_plain != plain_char) or (
                existing_symbol is not None and existing_symbol != symbol
            ):
                return None
            symbol_to_plain[symbol] = plain_char
            plain_to_symbol[plain_char] = symbol

        decoded_words: List[str] = []
        unknown_symbols = 0
        total_symbols = 0
        for word in words:
            chars: List[str] = []
            for symbol in word:
                total_symbols += 1
                if symbol in symbol_to_plain:
                    chars.append(symbol_to_plain[symbol])
                else:
                    chars.append("?")
                    unknown_symbols += 1
            decoded_words.append("".join(chars))

        decoded_text = " ".join(decoded_words)
        guessed_text = self._guess_sentence_from_symbol_words(words, symbol_to_plain)
        return {
            "decoded": decoded_text,
            "decoded_guess": guessed_text,
            "crib": hint,
            "anchor_word_index": anchor_idx + 1,
            "delimiter": delimiter,
            "unknown_symbols": unknown_symbols,
            "total_symbols": total_symbols,
            "unknown_ratio": round(unknown_symbols / max(1, total_symbols), 3),
            "mapping_size": len(symbol_to_plain),
        }

    def _crib_decode_numeric_symbol_cipher_multi(self, text: str, crib_hints: List[str]) -> Dict[str, Any] | None:
        hints = ["".join(ch for ch in hint.lower() if ch.isalpha()) for hint in crib_hints]
        hints = [hint for hint in hints if len(hint) >= 2]
        if len(hints) < 2:
            return None

        values = [int(part) for part in re.findall(r"\d+", text)]
        if not values:
            return None

        delimiter = Counter(values).most_common(1)[0][0]
        words: List[List[int]] = []
        current: List[int] = []
        for value in values:
            if value == delimiter:
                if current:
                    words.append(current)
                    current = []
                continue
            current.append(value)
        if current:
            words.append(current)
        if not words:
            return None

        def pattern(seq: List[int] | str) -> List[int]:
            mapping: Dict[Any, int] = {}
            out: List[int] = []
            next_idx = 0
            for item in seq:
                if item not in mapping:
                    mapping[item] = next_idx
                    next_idx += 1
                out.append(mapping[item])
            return out

        hint_candidates: List[Dict[str, Any]] = []
        for hint in hints:
            hint_pattern = pattern(hint)
            indexes = [idx for idx, word in enumerate(words) if len(word) == len(hint) and pattern(word) == hint_pattern]
            if not indexes:
                return None
            hint_candidates.append({"hint": hint, "indexes": indexes})

        # Solve most constrained hints first.
        hint_candidates.sort(key=lambda item: len(item["indexes"]))

        best: Dict[str, Any] | None = None
        chosen_indexes: set[int] = set()
        symbol_to_plain: Dict[int, str] = {}
        plain_to_symbol: Dict[str, int] = {}
        assignment: List[Dict[str, Any]] = []

        def backtrack(depth: int) -> None:
            nonlocal best
            if depth == len(hint_candidates):
                decoded_words: List[str] = []
                unknown_symbols = 0
                total_symbols = 0
                for word in words:
                    chars: List[str] = []
                    for symbol in word:
                        total_symbols += 1
                        plain = symbol_to_plain.get(symbol)
                        if plain is None:
                            chars.append("?")
                            unknown_symbols += 1
                        else:
                            chars.append(plain)
                    decoded_words.append("".join(chars))

                guessed_text = self._guess_sentence_from_symbol_words(words, symbol_to_plain)

                candidate = {
                    "decoded": " ".join(decoded_words),
                    "decoded_guess": guessed_text,
                    "crib": ",".join(item["hint"] for item in assignment),
                    "anchor_word_index": assignment[0]["index"] + 1 if assignment else None,
                    "delimiter": delimiter,
                    "unknown_symbols": unknown_symbols,
                    "total_symbols": total_symbols,
                    "unknown_ratio": round(unknown_symbols / max(1, total_symbols), 3),
                    "mapping_size": len(symbol_to_plain),
                }

                if best is None:
                    best = candidate
                    return
                if float(candidate["unknown_ratio"]) < float(best["unknown_ratio"]):
                    best = candidate
                    return
                if (
                    float(candidate["unknown_ratio"]) == float(best["unknown_ratio"])
                    and int(candidate["mapping_size"]) > int(best["mapping_size"])
                ):
                    best = candidate
                return

            entry = hint_candidates[depth]
            hint = str(entry["hint"])
            for idx in list(entry["indexes"]):
                if idx in chosen_indexes:
                    continue
                word = words[idx]
                additions: List[tuple[int, str]] = []
                ok = True
                for symbol, plain_char in zip(word, hint):
                    existing_plain = symbol_to_plain.get(symbol)
                    existing_symbol = plain_to_symbol.get(plain_char)
                    if (existing_plain is not None and existing_plain != plain_char) or (
                        existing_symbol is not None and existing_symbol != symbol
                    ):
                        ok = False
                        break
                    if existing_plain is None and existing_symbol is None:
                        symbol_to_plain[symbol] = plain_char
                        plain_to_symbol[plain_char] = symbol
                        additions.append((symbol, plain_char))

                if not ok:
                    for symbol, plain_char in additions:
                        symbol_to_plain.pop(symbol, None)
                        plain_to_symbol.pop(plain_char, None)
                    continue

                chosen_indexes.add(idx)
                assignment.append({"hint": hint, "index": idx})
                backtrack(depth + 1)
                assignment.pop()
                chosen_indexes.remove(idx)
                for symbol, plain_char in additions:
                    symbol_to_plain.pop(symbol, None)
                    plain_to_symbol.pop(plain_char, None)

        backtrack(0)
        return best

    def _auto_crib_decode_numeric_symbol_cipher(self, text: str, crib_hint: str) -> Dict[str, Any] | None:
        raw_hints = [part.strip() for part in re.split(r"[,;]", crib_hint or "") if part.strip()]
        if len(raw_hints) >= 2:
            multi = self._crib_decode_numeric_symbol_cipher_multi(text, raw_hints)
            if multi is not None:
                return multi

        hints: List[str] = []
        user_hint = (crib_hint or "").strip()
        if user_hint:
            hints.append(user_hint)
        hints.extend([
            "the",
            "flag",
            "this",
            "that",
            "with",
            "from",
            "have",
            "your",
            "password",
            "secure",
        ])

        seen: set[str] = set()
        candidates: List[str] = []
        for hint in hints:
            normalized = "".join(ch for ch in hint.lower() if ch.isalpha())
            if len(normalized) < 2 or normalized in seen:
                continue
            seen.add(normalized)
            candidates.append(normalized)

        best: Dict[str, Any] | None = None
        for hint in candidates:
            result = self._crib_decode_numeric_symbol_cipher(text, hint)
            if result is None:
                continue
            if best is None:
                best = result
                continue
            if float(result.get("unknown_ratio", 1.0)) < float(best.get("unknown_ratio", 1.0)):
                best = result
                continue
            if (
                float(result.get("unknown_ratio", 1.0)) == float(best.get("unknown_ratio", 1.0))
                and int(result.get("mapping_size", 0)) > int(best.get("mapping_size", 0))
            ):
                best = result

        return best

    async def _post_recipe(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.post("http://localhost:8765/api/v1/crypto/recipe/run", json=payload)
        return response.json()

    async def _post_json(self, url: str, payload: Dict[str, Any], timeout_s: float = 12.0) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            response = await client.post(url, json=payload)
        return response.json()

    async def _get_json(self, url: str, params: Dict[str, Any] | None = None, timeout_s: float = 12.0) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            response = await client.get(url, params=params)
        return response.json()

    async def _delete_json(self, url: str, timeout_s: float = 12.0) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            response = await client.delete(url)
        return response.json()

    async def _poll_job_until_done(self, job_id: str, timeout_s: int = 90) -> Dict[str, Any]:
        end_time = asyncio.get_running_loop().time() + timeout_s
        while True:
            body = await self._get_json(f"http://localhost:8765/api/v1/jobs/{job_id}")
            data = body.get("data", {}) if body.get("ok") else {}
            status = str(data.get("status", "")).lower()
            if status in {"complete", "failed", "cancelled"}:
                return body

            if asyncio.get_running_loop().time() >= end_time:
                return body

            await asyncio.sleep(1.0)

    def _refresh_candidate_select(self, candidates: List[Dict[str, Any]]) -> None:
        select = self.query_one("#candidate_select", Select)
        if not candidates:
            select.set_options([("No candidates", "")])
            select.value = ""
            self._last_candidates = []
            return

        options = []
        for idx, candidate in enumerate(candidates[:10], start=1):
            replay = candidate.get("replay_step")
            replay_op = replay.get("op") if isinstance(replay, dict) else ""
            key_text = candidate.get("key_text") or candidate.get("key")
            key_hex = candidate.get("key_hex", "")
            preview = str(candidate.get("preview", ""))[:24]
            key_hint = key_text or key_hex or "n/a"
            label = f"{idx}. {replay_op or 'candidate'} key={key_hint} | {preview}"
            options.append((label, str(idx - 1)))

        select.set_options(options)
        select.value = options[0][1]
        self._last_candidates = candidates[:10]

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id not in {
            "detect_tools",
            "view_capabilities",
            "smart_crack",
            "paste_input",
            "upload_run",
            "run",
            "explore",
            "apply_key",
            "load_history",
            "load_history_entry",
            "rerun_history_entry",
            "compare_history_entries",
            "crack_hashes",
            "crack_wifi_psk",
            "poll_job",
            "cancel_job",
            "load_logs",
            "view_log",
        }:
            return

        if event.button.id == "detect_tools":
            result_widget = self.query_one("#result", Static)
            result_widget.update("Checking tool availability...")
            try:
                body = await self._get_json("http://localhost:8765/api/v1/health")
            except Exception as exc:
                result_widget.update(f"Health request failed: {exc}")
                return

            if not body.get("ok"):
                result_widget.update(json.dumps(body, indent=2, ensure_ascii=True))
                return

            data = body.get("data", {})
            tool_status = data.get("tool_status", {})
            lines = [f"Service Status: {data.get('status')}", f"Version: {data.get('version')}", "", "Tool Status:"]
            for name, status in sorted(tool_status.items()):
                if isinstance(status, dict):
                    lines.append(f"- {name}: available={status.get('available')} fallback={status.get('fallback')}")
                else:
                    lines.append(f"- {name}: {status}")
            result_widget.update("\n".join(lines))
            self._append_history("detected tools")
            return

        if event.button.id == "view_capabilities":
            result_widget = self.query_one("#result", Static)
            result_widget.update("Loading capabilities...")
            try:
                body = await self._get_json("http://localhost:8765/api/v1/capabilities")
            except Exception as exc:
                result_widget.update(f"Capabilities request failed: {exc}")
                return

            if not body.get("ok"):
                result_widget.update(json.dumps(body, indent=2, ensure_ascii=True))
                return

            registry = body.get("data", {}).get("registry", {})
            categories = registry.get("categories", {}) if isinstance(registry, dict) else {}
            lines = ["Capabilities:"]
            for name, item in sorted(categories.items()):
                status = item.get("status") if isinstance(item, dict) else "unknown"
                lines.append(f"- {name}: {status}")
                if isinstance(item, dict):
                    for feature in item.get("features", [])[:6]:
                        lines.append(f"    * {feature}")
            result_widget.update("\n".join(lines))
            self._append_history("viewed capabilities")
            return

        if event.button.id == "smart_crack":
            result_widget = self.query_one("#result", Static)
            cipher_text = self.query_one("#cipher_input", Input).value.strip()
            hash_text = self.query_one("#hash_input", Input).value.strip()
            upload_path = self.query_one("#upload_path", Input).value.strip().strip('"')
            crib_hint = self.query_one("#crib_hint", Input).value.strip()
            wordlist_name = self.query_one("#wordlist_name", Input).value.strip() or "rockyou"
            rule_file = self.query_one("#rule_file", Input).value.strip()

            source_text = hash_text or cipher_text
            if not source_text and not upload_path:
                result_widget.update("Paste a hash, WiFi config, or cipher text first.")
                return

            office_note = ""
            office_ext = {".pptx", ".docx", ".xlsx", ".ppt", ".doc", ".xls"}
            office_candidate: Path | None = None
            if upload_path:
                upath = Path(upload_path)
                if upath.exists() and upath.is_file() and upath.suffix.lower() in office_ext:
                    office_candidate = upath
            if office_candidate is None and source_text:
                as_path = Path(source_text)
                if as_path.exists() and as_path.is_file() and as_path.suffix.lower() in office_ext:
                    office_candidate = as_path

            if office_candidate is not None:
                result_widget.update(f"Smart Crack detected Office file path: {office_candidate.name}. Extracting Office hash...")
                try:
                    with office_candidate.open("rb") as f:
                        files = {"file": (office_candidate.name, f, "application/octet-stream")}
                        data = {"timeout_s": "45"}
                        async with httpx.AsyncClient(timeout=75.0) as client:
                            response = await client.post(
                                "http://localhost:8765/api/v1/passwords/extract/office-hash",
                                files=files,
                                data=data,
                            )
                    body = response.json()
                except Exception as exc:
                    body = {
                        "ok": False,
                        "error": {
                            "message": str(exc).strip() or repr(exc),
                        },
                    }

                if not body.get("ok"):
                    # Fallback to local extraction when API call fails/timeouts.
                    local_result: Dict[str, Any] | None = None
                    try:
                        from backend.modules.password_crack_service import extract_office_hash_from_file_bytes

                        payload = office_candidate.read_bytes()
                        local_result = await asyncio.to_thread(
                            extract_office_hash_from_file_bytes,
                            office_candidate.name,
                            payload,
                            45,
                        )
                    except Exception as local_exc:
                        detail = str(local_exc).strip() or repr(local_exc)
                        result_widget.update(
                            "\n".join(
                                [
                                    f"Office hash extraction failed (API + local fallback): {detail}",
                                    "Tip: backend may be stalled; restart backend then retry.",
                                ]
                            )
                        )
                        return

                    if not local_result or not local_result.get("ok"):
                        result_widget.update(json.dumps(local_result or body, indent=2, ensure_ascii=True))
                        return

                    office_data = local_result
                    office_hash = str(office_data.get("office_hash", "")).strip()
                    if not office_hash:
                        result_widget.update("Local Office hash extraction returned empty hash output.")
                        return

                    self.query_one("#hash_input", Input).value = office_hash
                    source_text = office_hash
                    office_note = f" Extracted Office {office_data.get('version', 'unknown')} hash locally from {office_candidate.name}."
                else:
                    office_data = body.get("data", {}) if isinstance(body.get("data"), dict) else {}
                    office_hash = str(office_data.get("office_hash", "")).strip()
                    if not office_hash:
                        result_widget.update("Office hash extraction returned empty hash output.")
                        return

                    self.query_one("#hash_input", Input).value = office_hash
                    source_text = office_hash
                    office_note = f" Extracted Office {office_data.get('version', 'unknown')} hash from {office_candidate.name}."

            if self._looks_like_wifi_psk(source_text):
                payload = {
                    "config_text": source_text,
                    "wordlist": wordlist_name,
                    "timeout_s": 600,
                    "max_attempts": 500000,
                }
                result_widget.update("Smart Crack detected WiFi PSK config. Submitting job...")
                try:
                    body = await self._post_json("http://localhost:8765/api/v1/passwords/crack/wifi-psk", payload)
                except Exception as exc:
                    local = await self._run_local_wifi_psk_crack(
                        config_text=source_text,
                        wordlist_spec=wordlist_name,
                        timeout_s=180,
                        max_attempts=500000,
                    )
                    if not local.get("ok"):
                        result_widget.update(
                            "\n".join(
                                [
                                    f"Smart Crack submit failed: {exc}",
                                    f"Local WiFi fallback failed: {local.get('error')}",
                                ]
                            )
                        )
                        return

                    cracked = local.get("cracked", []) if isinstance(local.get("cracked"), list) else []
                    uncracked = local.get("uncracked", []) if isinstance(local.get("uncracked"), list) else []
                    lines = [
                        "Smart Crack backend unavailable; local WiFi fallback used.",
                        f"Engine: {local.get('engine')}",
                        f"Success: {local.get('success')}",
                        f"Attempts: {local.get('attempts')}",
                        f"Wordlists: {', '.join(local.get('wordlists', []))}",
                    ]
                    for item in cracked:
                        lines.append(f"- {item.get('ssid')}: {item.get('password')}")
                    if uncracked:
                        lines.append(
                            f"Uncracked SSIDs: {', '.join(str(item.get('ssid')) for item in uncracked if isinstance(item, dict))}"
                        )
                    result_widget.update("\n".join(lines))
                    self._append_history(f"smart crack local-wifi cracked={len(cracked)}")
                    return

                if not body.get("ok"):
                    result_widget.update(json.dumps(body, indent=2, ensure_ascii=True))
                    return

                data = body.get("data", {})
                job_id = str(data.get("job_id", ""))
                self.query_one("#job_id", Input).value = job_id
                result_widget.update(f"WiFi crack job started: {job_id}. Polling for results...")
                poll_body = await self._poll_job_until_done(job_id, timeout_s=180)
                poll_data = poll_body.get("data", {}) if poll_body.get("ok") else {}
                status = str(poll_data.get("status", "")).lower()
                if status != "complete":
                    result_widget.update(
                        f"WiFi crack job still running. Job id: {job_id}\nUse Poll Job to refresh later."
                    )
                    self._append_history(f"smart crack wifi job {job_id}")
                    return

                result = poll_data.get("result", {}) if isinstance(poll_data.get("result"), dict) else {}
                cracked = result.get("cracked", []) if isinstance(result, dict) else []
                uncracked = result.get("uncracked", []) if isinstance(result, dict) else []
                lines = [
                    "Smart Crack detected WiFi PSK config.",
                    f"Job: {job_id}",
                    f"Success: {result.get('success') if isinstance(result, dict) else None}",
                    f"Attempts: {result.get('attempts') if isinstance(result, dict) else None}",
                ]
                for item in cracked:
                    lines.append(f"- {item.get('ssid')}: {item.get('password')}")
                if uncracked:
                    lines.append(f"Uncracked SSIDs: {', '.join(str(item.get('ssid')) for item in uncracked if isinstance(item, dict))}")
                result_widget.update("\n".join(lines))
                self._append_history(f"smart crack wifi job {job_id}")
                return

            hash_parse = self._extract_hash_inputs(source_text)
            hashes = hash_parse.get("hashes", []) if isinstance(hash_parse, dict) else []

            if hashes:
                hash_mode = self._infer_hash_mode(hashes[0], hash_parse.get("mode_hint") if isinstance(hash_parse, dict) else None)
                identify_note = ""
                selected_attack_mode = str(self.query_one("#attack_mode", Select).value or "dictionary")
                try:
                    identify_body = await self._post_json(
                        "http://localhost:8765/api/v1/crypto/hash/identify",
                        {"hash": hashes[0], "timeout_ms": 1000},
                        timeout_s=4.0,
                    )
                    if identify_body.get("ok"):
                        identify_data = identify_body.get("data", {})
                        hash_types = identify_data.get("hash_types", []) if isinstance(identify_data, dict) else []
                        if hash_types:
                            first = hash_types[0] if isinstance(hash_types[0], dict) else {}
                            if hash_parse.get("mode_hint") is None:
                                hash_mode = int(first.get("hashcat_mode", hash_mode) or hash_mode)
                            if len(hash_types) > 1 and any(
                                str(item.get("type", "")).lower() == "ntlm" for item in hash_types if isinstance(item, dict)
                            ):
                                identify_note = " Ambiguous 32-char hash; defaulted to the first match."
                        else:
                            identify_note = " Hash type was not identified, defaulting to MD5."
                except Exception:
                    identify_note = " Hash identify request failed, defaulting to MD5."

                if hash_mode not in {0, 100, 1000, 1400, 1700, 3200, 9400, 9500, 9600}:
                    hash_mode = 0
                    identify_note += " Unsupported mode inferred; using MD5 mode 0."

                parse_hint = str(hash_parse.get("hint_text", "") or "") if isinstance(hash_parse, dict) else ""
                if parse_hint:
                    identify_note = f" {parse_hint}." + identify_note
                if office_note:
                    identify_note = office_note + identify_note

                attack_mode = self._choose_attack_mode(hash_mode=hash_mode, hash_count=len(hashes), user_selected=selected_attack_mode)

                payload = {
                    "hashes": hashes,
                    "hash_mode": hash_mode,
                    "attack_mode": attack_mode,
                    "wordlist": wordlist_name,
                    "rule_file": rule_file or None,
                    "top_rules_limit": 10,
                    "timeout_s": 600,
                }
                result_widget.update(
                    f"Smart Crack detected hashes. Using mode {hash_mode} and attack {attack_mode}.{identify_note} Submitting job..."
                )
                try:
                    body = await self._post_json("http://localhost:8765/api/v1/passwords/crack/hashcat", payload)
                except Exception as exc:
                    local = await self._run_local_hashcat_crack(
                        hashes=hashes,
                        hash_mode=hash_mode,
                        attack_mode=attack_mode,
                        wordlist_spec=wordlist_name,
                        rule_spec=rule_file,
                        timeout_s=600,
                    )
                    if not local.get("ok"):
                        result_widget.update(
                            "\n".join(
                                [
                                    f"Smart Crack submit failed: {exc}",
                                    f"Local fallback failed: {local.get('error')}",
                                ]
                            )
                        )
                        return

                    cracked = local.get("results", []) if isinstance(local.get("results"), list) else []
                    uncracked = local.get("uncracked", []) if isinstance(local.get("uncracked"), list) else []
                    lines = [
                        "Smart Crack backend unavailable; local hashcat fallback used.",
                        f"Engine: {local.get('engine')}",
                        f"Hash Mode: {hash_mode}",
                        f"Attack Mode: {attack_mode}",
                        f"Wordlists: {', '.join(local.get('wordlists', []))}",
                    ]
                    if local.get("rule_file"):
                        lines.append(f"Rule File: {local.get('rule_file')}")
                    top_rules = local.get("top_rules", []) if isinstance(local.get("top_rules"), list) else []
                    if top_rules:
                        lines.append("Top Rules:")
                        for item in top_rules[:5]:
                            lines.append(f"- {item.get('rule')} ({item.get('hits')} hits)")
                    for item in cracked:
                        lines.append(f"- {item.get('hash')}: {item.get('plaintext')}")
                    if uncracked:
                        lines.append(f"Uncracked hashes: {len(uncracked)}")
                    result_widget.update("\n".join(lines))
                    self._append_history(f"smart crack local-hashcat mode={hash_mode} cracked={len(cracked)}")
                    return

                if not body.get("ok"):
                    result_widget.update(json.dumps(body, indent=2, ensure_ascii=True))
                    return

                data = body.get("data", {})
                job_id = str(data.get("job_id", ""))
                self.query_one("#job_id", Input).value = job_id
                result_widget.update(f"Hash crack job started: {job_id}. Polling for results...")
                poll_body = await self._poll_job_until_done(job_id, timeout_s=180)
                poll_data = poll_body.get("data", {}) if poll_body.get("ok") else {}
                status = str(poll_data.get("status", "")).lower()
                if status != "complete":
                    result_widget.update(
                        f"Hash crack job still running. Job id: {job_id}\nUse Poll Job to refresh later."
                    )
                    self._append_history(f"smart crack hash job {job_id} mode={hash_mode}")
                    return

                job_result = poll_data.get("result", {}) if isinstance(poll_data.get("result"), dict) else {}
                cracked = job_result.get("results", []) if isinstance(job_result, dict) else []
                uncracked = job_result.get("uncracked", []) if isinstance(job_result, dict) else []
                engine = str(job_result.get("engine", "") or "").strip().lower()

                if engine in {"", "none"}:
                    local = await self._run_local_hashcat_crack(
                        hashes=hashes,
                        hash_mode=hash_mode,
                        attack_mode=attack_mode,
                        wordlist_spec=wordlist_name,
                        rule_spec=rule_file,
                        timeout_s=600,
                    )
                    if local.get("ok"):
                        local_cracked = local.get("results", []) if isinstance(local.get("results"), list) else []
                        local_uncracked = local.get("uncracked", []) if isinstance(local.get("uncracked"), list) else []
                        lines = [
                            "Smart Crack backend returned no engine; local hashcat fallback used.",
                            f"Job: {job_id}",
                            f"Engine: {local.get('engine')}",
                            f"Hash Mode: {hash_mode}",
                            f"Attack Mode: {attack_mode}",
                            f"Wordlists: {', '.join(local.get('wordlists', []))}",
                        ]
                        if local.get("rule_file"):
                            lines.append(f"Rule File: {local.get('rule_file')}")
                        top_rules = local.get("top_rules", []) if isinstance(local.get("top_rules"), list) else []
                        if top_rules:
                            lines.append("Top Rules:")
                            for item in top_rules[:5]:
                                lines.append(f"- {item.get('rule')} ({item.get('hits')} hits)")
                        for item in local_cracked:
                            lines.append(f"- {item.get('hash')}: {item.get('plaintext')}")
                        if local_uncracked:
                            lines.append(f"Uncracked hashes: {len(local_uncracked)}")
                        result_widget.update("\n".join(lines))
                        self._append_history(f"smart crack local-fallback mode={hash_mode} cracked={len(local_cracked)}")
                        return

                    result_widget.update(
                        "\n".join(
                            [
                                f"Smart Crack backend returned no engine for job {job_id}.",
                                f"Local fallback failed: {local.get('error')}",
                                f"Backend result: {json.dumps(job_result, indent=2, ensure_ascii=True)}",
                            ]
                        )
                    )
                    return

                lines = [
                    "Smart Crack detected hash input.",
                    f"Job: {job_id}",
                    f"Engine: {job_result.get('engine') if isinstance(job_result, dict) else None}",
                    f"Hash Mode: {job_result.get('hash_mode', hash_mode) if isinstance(job_result, dict) else hash_mode}",
                    f"Attack Mode: {attack_mode}",
                ]
                if isinstance(job_result, dict) and job_result.get("rule_file"):
                    lines.append(f"Rule File: {job_result.get('rule_file')}")
                top_rules = job_result.get("top_rules", []) if isinstance(job_result, dict) and isinstance(job_result.get("top_rules"), list) else []
                if top_rules:
                    lines.append("Top Rules:")
                    for item in top_rules[:5]:
                        lines.append(f"- {item.get('rule')} ({item.get('hits')} hits)")
                for item in cracked:
                    lines.append(f"- {item.get('hash')}: {item.get('plaintext')}")
                if uncracked:
                    lines.append(f"Uncracked hashes: {len(uncracked)}")
                result_widget.update("\n".join(lines))
                self._append_history(f"smart crack hash job {job_id} mode={hash_mode}")
                return

            if self._looks_like_numeric_symbol_cipher(source_text):
                crib_result = self._auto_crib_decode_numeric_symbol_cipher(source_text, crib_hint)
                if (
                    crib_result is not None
                    and float(crib_result.get("unknown_ratio", 1.0)) <= 0.45
                    and "?" not in str(crib_result.get("decoded_guess", ""))
                ):
                    lines = [
                        "Smart Crack applied crib-assisted numeric substitution.",
                        f"Crib: {crib_result.get('crib')}",
                        f"Anchor Word #: {crib_result.get('anchor_word_index')}",
                        f"Delimiter Symbol: {crib_result.get('delimiter')}",
                        f"Mapped Symbols: {crib_result.get('mapping_size')}",
                        f"Unknown Ratio: {crib_result.get('unknown_ratio')}",
                        "",
                        f"Best Guess: {crib_result.get('decoded_guess', '')}",
                        "",
                        str(crib_result.get("decoded", "")),
                    ]
                    result_widget.update("\n".join(lines))
                    self._append_history("smart crack crib-substitution")
                    return

                payload = {
                    "input": source_text,
                    "max_depth": 6,
                    "timeout_ms": 12000,
                    "max_candidates": 30,
                }
                result_widget.update("Smart Crack detected numeric-symbol cipher. Running deeper strategy...")
                try:
                    body = await self._post_json("http://localhost:8765/api/v1/crypto/strategy/explore", payload, timeout_s=20.0)
                except Exception as exc:
                    result_widget.update(f"Smart Crack request failed: {exc}")
                    return

                if not body.get("ok"):
                    result_widget.update(json.dumps(body, indent=2, ensure_ascii=True))
                    return

                data = body.get("data", {})
                lines = [
                    "Smart Crack detected numeric-symbol cipher.",
                    f"Best Method: {data.get('best_method')}",
                    f"Best Output: {data.get('best_output')}",
                    f"Timed Out: {data.get('timed_out')}",
                    "",
                ]
                for idx, cand in enumerate(data.get("candidates", []), start=1):
                    lines.append(f"{idx}. method={cand.get('method')} score={cand.get('score')} conf={cand.get('confidence')}")
                    lines.append(f"   preview={cand.get('preview', '')}")
                result_widget.update("\n".join(lines))
                self._append_history("smart crack numeric strategy")
                return

            payload = {
                "input": source_text,
                "max_depth": 5,
                "timeout_ms": 5000,
                "max_candidates": 20,
            }
            result_widget.update("Smart Crack detected cipher/plaintext input. Running auto strategy...")
            try:
                body = await self._post_json("http://localhost:8765/api/v1/crypto/strategy/run", payload)
            except Exception as exc:
                result_widget.update(f"Smart Crack request failed: {exc}")
                return

            if not body.get("ok"):
                result_widget.update(json.dumps(body, indent=2, ensure_ascii=True))
                return

            data = body.get("data", {})
            lines = [
                "Smart Crack detected cipher/plaintext input.",
                f"Best Method: {data.get('best_method')}",
                f"Best Output: {data.get('best_output')}",
                f"Timed Out: {data.get('timed_out')}",
                "",
            ]
            for idx, cand in enumerate(data.get("candidates", []), start=1):
                lines.append(f"{idx}. method={cand.get('method')} score={cand.get('score')} conf={cand.get('confidence')}")
                lines.append(f"   preview={cand.get('preview', '')}")
            result_widget.update("\n".join(lines))
            self._append_history("smart crack crypto")
            return

        if event.button.id == "crack_hashes":
            result_widget = self.query_one("#result", Static)
            hashes_raw = self.query_one("#hash_input", Input).value.strip()
            if not hashes_raw:
                result_widget.update("Hash input is empty.")
                return

            hash_mode_raw = str(self.query_one("#hash_mode", Select).value or "0")
            attack_mode = str(self.query_one("#attack_mode", Select).value or "dictionary")
            wordlist_name = self.query_one("#wordlist_name", Input).value.strip() or "rockyou"
            rule_file = self.query_one("#rule_file", Input).value.strip()
            hashes = [h.strip() for h in hashes_raw.replace(",", "\n").splitlines() if h.strip()]
            if not hashes:
                result_widget.update("No valid hashes parsed.")
                return

            try:
                hash_mode = int(hash_mode_raw)
            except ValueError:
                result_widget.update("Hash mode must be numeric.")
                return

            payload = {
                "hashes": hashes,
                "hash_mode": hash_mode,
                "attack_mode": attack_mode,
                "wordlist": wordlist_name,
                "rule_file": rule_file or None,
                "top_rules_limit": 10,
                "timeout_s": 600,
            }
            result_widget.update(f"Submitting crack job ({len(hashes)} hashes, mode={hash_mode})...")
            try:
                body = await self._post_json("http://localhost:8765/api/v1/passwords/crack/hashcat", payload)
            except Exception as exc:
                local = await self._run_local_hashcat_crack(
                    hashes=hashes,
                    hash_mode=hash_mode,
                    attack_mode=attack_mode,
                    wordlist_spec=wordlist_name,
                    rule_spec=rule_file,
                    timeout_s=600,
                )
                if not local.get("ok"):
                    result_widget.update(
                        "\n".join(
                            [
                                f"Crack submit failed: {exc}",
                                f"Local fallback failed: {local.get('error')}",
                            ]
                        )
                    )
                    return

                cracked = local.get("results", []) if isinstance(local.get("results"), list) else []
                uncracked = local.get("uncracked", []) if isinstance(local.get("uncracked"), list) else []
                lines = [
                    "Crack Hashes backend unavailable; local hashcat fallback used.",
                    f"Engine: {local.get('engine')}",
                    f"Hash Mode: {hash_mode}",
                    f"Attack Mode: {attack_mode}",
                    f"Wordlists: {', '.join(local.get('wordlists', []))}",
                ]
                if local.get("rule_file"):
                    lines.append(f"Rule File: {local.get('rule_file')}")
                top_rules = local.get("top_rules", []) if isinstance(local.get("top_rules"), list) else []
                if top_rules:
                    lines.append("Top Rules:")
                    for item in top_rules[:5]:
                        lines.append(f"- {item.get('rule')} ({item.get('hits')} hits)")
                for item in cracked:
                    lines.append(f"- {item.get('hash')}: {item.get('plaintext')}")
                if uncracked:
                    lines.append(f"Uncracked hashes: {len(uncracked)}")
                result_widget.update("\n".join(lines))
                return

            if not body.get("ok"):
                result_widget.update(json.dumps(body, indent=2, ensure_ascii=True))
                return

            data = body.get("data", {})
            job_id = str(data.get("job_id", ""))
            self.query_one("#job_id", Input).value = job_id
            result_widget.update(
                "\n".join(
                    [
                        f"Crack Job Started: {job_id}",
                        f"Status: {data.get('status')}",
                        f"Poll URL: {data.get('poll_url')}",
                        "Use Poll Job to fetch progress/results.",
                    ]
                )
            )
            self._append_history(f"crack job {job_id} mode={hash_mode}")
            return

        if event.button.id == "crack_wifi_psk":
            result_widget = self.query_one("#result", Static)
            config_text = self.query_one("#cipher_input", Input).value.strip()
            if "ssid" not in config_text.lower() or "psk" not in config_text.lower():
                result_widget.update("Paste WiFi network config text (with ssid and psk) into the main input first.")
                return

            wordlist_name = self.query_one("#wordlist_name", Input).value.strip() or "rockyou"
            payload = {
                "config_text": config_text,
                "wordlist": wordlist_name,
                "timeout_s": 600,
                "max_attempts": 500000,
            }
            result_widget.update("Submitting WiFi PSK crack job...")
            try:
                body = await self._post_json("http://localhost:8765/api/v1/passwords/crack/wifi-psk", payload)
            except Exception as exc:
                local = await self._run_local_wifi_psk_crack(
                    config_text=config_text,
                    wordlist_spec=wordlist_name,
                    timeout_s=180,
                    max_attempts=500000,
                )
                if not local.get("ok"):
                    result_widget.update(
                        "\n".join(
                            [
                                f"WiFi crack submit failed: {exc}",
                                f"Local WiFi fallback failed: {local.get('error')}",
                            ]
                        )
                    )
                    return

                cracked = local.get("cracked", []) if isinstance(local.get("cracked"), list) else []
                uncracked = local.get("uncracked", []) if isinstance(local.get("uncracked"), list) else []
                lines = [
                    "Crack WiFi PSK backend unavailable; local fallback used.",
                    f"Engine: {local.get('engine')}",
                    f"Success: {local.get('success')}",
                    f"Attempts: {local.get('attempts')}",
                    f"Wordlists: {', '.join(local.get('wordlists', []))}",
                ]
                for item in cracked:
                    lines.append(f"- {item.get('ssid')}: {item.get('password')}")
                if uncracked:
                    lines.append(
                        f"Uncracked SSIDs: {', '.join(str(item.get('ssid')) for item in uncracked if isinstance(item, dict))}"
                    )
                result_widget.update("\n".join(lines))
                return

            if not body.get("ok"):
                result_widget.update(json.dumps(body, indent=2, ensure_ascii=True))
                return

            data = body.get("data", {})
            job_id = str(data.get("job_id", ""))
            self.query_one("#job_id", Input).value = job_id
            result_widget.update(
                "\n".join(
                    [
                        f"WiFi Crack Job Started: {job_id}",
                        f"Status: {data.get('status')}",
                        f"Poll URL: {data.get('poll_url')}",
                    ]
                )
            )
            self._append_history(f"wifi crack job {job_id}")
            return

        if event.button.id == "poll_job":
            result_widget = self.query_one("#result", Static)
            job_id = self.query_one("#job_id", Input).value.strip()
            if not job_id:
                result_widget.update("Enter a job id first.")
                return

            result_widget.update(f"Polling job {job_id}...")
            try:
                body = await self._poll_job_until_done(job_id, timeout_s=30)
            except Exception as exc:
                result_widget.update(f"Job poll failed: {exc}")
                return

            if not body.get("ok"):
                result_widget.update(json.dumps(body, indent=2, ensure_ascii=True))
                return

            data = body.get("data", {})
            lines = [
                f"Job: {data.get('job_id')}",
                f"Status: {data.get('status')}",
                f"Progress: {data.get('progress_pct')}%",
                f"Elapsed: {data.get('elapsed_ms')} ms",
            ]
            result = data.get("result")
            if isinstance(result, dict):
                lines.append(f"Engine: {result.get('engine')}")
                cracked = result.get("results", [])
                lines.append(f"Cracked Count: {len(cracked) if isinstance(cracked, list) else 0}")
                if isinstance(cracked, list):
                    for idx, item in enumerate(cracked[:10], start=1):
                        lines.append(f"{idx}. {item.get('hash')} -> {item.get('plaintext')}")
                uncracked = result.get("uncracked", [])
                lines.append(f"Uncracked Count: {len(uncracked) if isinstance(uncracked, list) else 0}")
                wifi_cracked = result.get("cracked", [])
                if isinstance(wifi_cracked, list) and wifi_cracked:
                    lines.append(f"WiFi Cracked Count: {len(wifi_cracked)}")
                    for idx, item in enumerate(wifi_cracked[:10], start=1):
                        lines.append(f"wifi {idx}. ssid={item.get('ssid')} password={item.get('password')}")
                if result.get("wordlist"):
                    lines.append(f"Wordlist: {result.get('wordlist')}")
            if data.get("error"):
                lines.append(f"Error: {data.get('error')}")

            result_widget.update("\n".join(lines))
            self._append_history(f"polled job {job_id} status={data.get('status')}")
            return

        if event.button.id == "cancel_job":
            result_widget = self.query_one("#result", Static)
            job_id = self.query_one("#job_id", Input).value.strip()
            if not job_id:
                result_widget.update("Enter a job id first.")
                return

            result_widget.update(f"Cancelling job {job_id}...")
            try:
                body = await self._delete_json(f"http://localhost:8765/api/v1/jobs/{job_id}")
            except Exception as exc:
                result_widget.update(f"Cancel request failed: {exc}")
                return

            if not body.get("ok"):
                result_widget.update(json.dumps(body, indent=2, ensure_ascii=True))
                return

            result_widget.update(f"Job {job_id} cancelled.")
            self._append_history(f"cancelled job {job_id}")
            return

        if event.button.id == "load_logs":
            result_widget = self.query_one("#result", Static)
            limit_raw = self.query_one("#log_limit", Input).value.strip() or "25"
            module = str(self.query_one("#log_module", Select).value or "")
            try:
                limit = int(limit_raw)
            except ValueError:
                result_widget.update("Log limit must be numeric.")
                return

            params: Dict[str, Any] = {"limit": max(1, min(limit, 200))}
            if module:
                params["module"] = module

            result_widget.update("Loading logs...")
            try:
                body = await self._get_json("http://localhost:8765/api/v1/jobs/history", params=params)
            except Exception as exc:
                result_widget.update(f"Log history request failed: {exc}")
                return

            if not body.get("ok"):
                result_widget.update(json.dumps(body, indent=2, ensure_ascii=True))
                return

            entries = body.get("data", {}).get("entries", [])
            lines = [f"Loaded {len(entries)} log entries (module={module or 'all'}).", ""]
            for item in entries[:30]:
                lines.append(
                    f"#{item.get('id')} {item.get('module')}/{item.get('operation')} success={item.get('success')} elapsed={item.get('elapsed_ms')}ms"
                )
                lines.append(f"  input={str(item.get('input_summary', ''))[:120]}")

            result_widget.update("\n".join(lines).strip())
            self._append_history(f"loaded logs module={module or 'all'} count={len(entries)}")
            return

        if event.button.id == "view_log":
            result_widget = self.query_one("#result", Static)
            log_id_raw = self.query_one("#log_id", Input).value.strip()
            if not log_id_raw.isdigit():
                result_widget.update("Log id must be numeric.")
                return

            result_widget.update(f"Loading log #{log_id_raw}...")
            try:
                body = await self._get_json(f"http://localhost:8765/api/v1/jobs/history/{log_id_raw}")
            except Exception as exc:
                result_widget.update(f"Log detail request failed: {exc}")
                return

            if not body.get("ok"):
                result_widget.update(json.dumps(body, indent=2, ensure_ascii=True))
                return

            entry = body.get("data", {})
            lines = [
                f"Log #{entry.get('id')}",
                f"Module/Operation: {entry.get('module')}/{entry.get('operation')}",
                f"Success: {entry.get('success')}",
                f"Elapsed: {entry.get('elapsed_ms')} ms",
                f"Input: {entry.get('input_summary')}",
                "",
                "Output JSON:",
                json.dumps(entry.get('output', {}), indent=2, ensure_ascii=True)[:3500],
            ]
            result_widget.update("\n".join(lines))
            self._append_history(f"viewed log #{log_id_raw}")
            return

        if event.button.id == "paste_input":
            result_widget = self.query_one("#result", Static)
            input_widget = self.query_one("#cipher_input", Input)
            try:
                clip = _read_clipboard_text()
            except Exception as exc:
                result_widget.update(f"Clipboard read failed: {exc}")
                return

            if not clip:
                result_widget.update("Clipboard is empty.")
                return

            input_widget.value = clip
            preview = clip[:120].replace("\n", " ")
            result_widget.update(f"Pasted {len(clip)} chars into input. Preview: {preview}")
            return

        if event.button.id == "upload_run":
            result_widget = self.query_one("#result", Static)
            upload_path = self.query_one("#upload_path", Input).value.strip().strip('"')
            upload_mode = str(self.query_one("#upload_mode", Select).value or "auto")

            if not upload_path:
                result_widget.update("Upload path is empty.")
                return

            path = Path(upload_path)
            if not path.exists() or not path.is_file():
                result_widget.update(f"Upload path not found: {upload_path}")
                return

            result_widget.update(f"Uploading {path.name} as mode={upload_mode}...")
            try:
                with path.open("rb") as f:
                    files = {"file": (path.name, f, "application/octet-stream")}
                    data = {
                        "mode": upload_mode,
                        "max_depth": "5",
                        "timeout_ms": "5000",
                        "max_candidates": "20",
                    }
                    async with httpx.AsyncClient(timeout=30.0) as client:
                        response = await client.post(
                            "http://localhost:8765/api/v1/crypto/strategy/upload",
                            files=files,
                            data=data,
                        )
                body = response.json()
            except Exception as exc:
                result_widget.update(f"Upload request failed: {exc}")
                return

            if not body.get("ok"):
                result_widget.update(json.dumps(body, indent=2, ensure_ascii=True))
                return

            payload = body.get("data", {})
            extracted = str(payload.get("extracted_text", ""))
            strategy = payload.get("strategy", {}) if isinstance(payload.get("strategy"), dict) else {}

            self.query_one("#cipher_input", Input).value = extracted
            lines = [
                f"Upload Mode: {payload.get('upload', {}).get('mode')}",
                f"Engine: {payload.get('upload', {}).get('engine')}",
                f"Extracted Preview: {extracted[:160].replace(chr(10), ' ')}",
                f"Best Method: {strategy.get('best_method')}",
                f"Best Output: {strategy.get('best_output')}",
                "",
            ]
            for idx, cand in enumerate(strategy.get("candidates", []), start=1):
                lines.append(f"{idx}. method={cand.get('method')} score={cand.get('score')} conf={cand.get('confidence')}")
                lines.append(f"   preview={cand.get('preview', '')}")
            result_widget.update("\n".join(lines).strip())

            strategy_candidates = []
            for cand in strategy.get("candidates", []):
                replay = cand.get("replay_step") or {}
                params = replay.get("params", {}) if isinstance(replay, dict) else {}
                strategy_candidates.append(
                    {
                        "key": params.get("key"),
                        "key_text": params.get("key"),
                        "key_hex": params.get("key_hex", ""),
                        "preview": cand.get("preview", ""),
                        "replay_step": replay if isinstance(replay, dict) else None,
                        "replay_recipe": cand.get("replay_recipe") if isinstance(cand.get("replay_recipe"), list) else [],
                    }
                )
            self._refresh_candidate_select(strategy_candidates)
            self._append_history(f"upload {path.name} mode={upload_mode} candidates={len(strategy.get('candidates', []))}")
            return

        if event.button.id == "load_history":
            result_widget = self.query_one("#result", Static)
            result_widget.update("Loading strategy history...")
            try:
                async with httpx.AsyncClient(timeout=8.0) as client:
                    response = await client.get("http://localhost:8765/api/v1/crypto/strategy/history", params={"limit": 10})
                body = response.json()
            except Exception as exc:
                result_widget.update(f"History request failed: {exc}")
                return

            if not body.get("ok"):
                result_widget.update(json.dumps(body, indent=2, ensure_ascii=True))
                return

            entries = body.get("data", {}).get("entries", [])
            self._history = []
            if entries:
                for item in entries:
                    self._history.append(
                        f"#{item.get('id')} method={item.get('best_method')} cand={item.get('candidate_count')}"
                    )
            else:
                self._history.append("none")

            history_widget = self.query_one("#history", Static)
            history_widget.update("Session History\n" + "\n".join(f"- {item}" for item in self._history[:10]))
            result_widget.update(f"Loaded {len(entries)} strategy history entries.")
            return

        if event.button.id == "compare_history_entries":
            result_widget = self.query_one("#result", Static)
            left_widget = self.query_one("#history_id", Input)
            right_widget = self.query_one("#compare_id", Input)
            left_raw = left_widget.value.strip()
            right_raw = right_widget.value.strip()
            if not left_raw.isdigit() or not right_raw.isdigit():
                result_widget.update("Enter numeric ids in both entry id fields.")
                return

            result_widget.update(f"Comparing entries #{left_raw} vs #{right_raw}...")
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(
                        "http://localhost:8765/api/v1/crypto/strategy/history/compare/runs",
                        params={"left_id": int(left_raw), "right_id": int(right_raw)},
                    )
                body = response.json()
            except Exception as exc:
                result_widget.update(f"Compare request failed: {exc}")
                return

            if not body.get("ok"):
                result_widget.update(json.dumps(body, indent=2, ensure_ascii=True))
                return

            data = body.get("data", {})
            left = data.get("left", {})
            right = data.get("right", {})
            diff = data.get("diff", {})
            lines = [
                f"Left  #{left.get('id')} method={left.get('best_method')} candidates={left.get('candidate_count')} elapsed={left.get('elapsed_ms')}ms",
                f"Right #{right.get('id')} method={right.get('best_method')} candidates={right.get('candidate_count')} elapsed={right.get('elapsed_ms')}ms",
                f"Same Best Output: {diff.get('same_best_output')}",
                f"Shared Methods: {', '.join(diff.get('shared_methods', [])) or 'none'}",
                f"Left-only Methods: {', '.join(diff.get('left_only_methods', [])) or 'none'}",
                f"Right-only Methods: {', '.join(diff.get('right_only_methods', [])) or 'none'}",
                f"Elapsed Delta (left-right): {diff.get('elapsed_delta_ms')} ms",
            ]
            result_widget.update("\n".join(lines))
            self._append_history(f"compare #{left_raw} vs #{right_raw} same={diff.get('same_best_output')}")
            return

        if event.button.id == "rerun_history_entry":
            result_widget = self.query_one("#result", Static)
            history_id_widget = self.query_one("#history_id", Input)
            raw_id = history_id_widget.value.strip()
            if not raw_id.isdigit():
                result_widget.update("Enter a numeric history entry id first.")
                return

            result_widget.update(f"Rerunning strategy entry #{raw_id}...")
            try:
                async with httpx.AsyncClient(timeout=12.0) as client:
                    response = await client.post(
                        f"http://localhost:8765/api/v1/crypto/strategy/history/{raw_id}/rerun",
                        params={"max_depth": 5, "timeout_ms": 5000, "max_candidates": 5},
                    )
                body = response.json()
            except Exception as exc:
                result_widget.update(f"Rerun request failed: {exc}")
                return

            if not body.get("ok"):
                result_widget.update(json.dumps(body, indent=2, ensure_ascii=True))
                return

            data = body.get("data", {})
            lines = [
                f"Rerun of Entry: {data.get('rerun_of_entry_id')}",
                f"Best Method: {data.get('best_method')}",
                f"Best Output: {data.get('best_output')}",
                f"Timed Out: {data.get('timed_out')}",
                "",
            ]
            for idx, cand in enumerate(data.get("candidates", []), start=1):
                lines.append(
                    f"{idx}. method={cand.get('method')} score={cand.get('score')} conf={cand.get('confidence')}"
                )
                lines.append(f"   preview={cand.get('preview', '')}")
                replay = cand.get("replay_step")
                if replay:
                    lines.append(f"   replay={json.dumps(replay, ensure_ascii=True)}")
                lines.append("")

            strategy_candidates = []
            for cand in data.get("candidates", []):
                replay = cand.get("replay_step") or {}
                params = replay.get("params", {}) if isinstance(replay, dict) else {}
                strategy_candidates.append(
                    {
                        "key": params.get("key"),
                        "key_text": params.get("key"),
                        "key_hex": params.get("key_hex", ""),
                        "preview": cand.get("preview", ""),
                        "replay_step": replay if isinstance(replay, dict) else None,
                        "replay_recipe": cand.get("replay_recipe") if isinstance(cand.get("replay_recipe"), list) else [],
                    }
                )
            self._refresh_candidate_select(strategy_candidates)
            self._append_history(
                f"rerun entry #{raw_id} best={data.get('best_method')} candidates={len(data.get('candidates', []))}"
            )
            result_widget.update("\n".join(lines).strip())
            return

        if event.button.id == "load_history_entry":
            result_widget = self.query_one("#result", Static)
            history_id_widget = self.query_one("#history_id", Input)
            raw_id = history_id_widget.value.strip()
            if not raw_id.isdigit():
                result_widget.update("Enter a numeric history entry id first.")
                return

            result_widget.update(f"Loading strategy entry #{raw_id}...")
            try:
                async with httpx.AsyncClient(timeout=8.0) as client:
                    response = await client.get(f"http://localhost:8765/api/v1/crypto/strategy/history/{raw_id}")
                body = response.json()
            except Exception as exc:
                result_widget.update(f"History entry request failed: {exc}")
                return

            if not body.get("ok"):
                result_widget.update(json.dumps(body, indent=2, ensure_ascii=True))
                return

            entry = body.get("data", {})
            output = entry.get("output", {})
            candidates = output.get("candidates", []) if isinstance(output, dict) else []

            strategy_candidates = []
            for cand in candidates:
                replay = cand.get("replay_step") or {}
                params = replay.get("params", {}) if isinstance(replay, dict) else {}
                strategy_candidates.append(
                    {
                        "key": params.get("key"),
                        "key_text": params.get("key"),
                        "key_hex": params.get("key_hex", ""),
                        "preview": cand.get("preview", ""),
                        "replay_step": replay if isinstance(replay, dict) else None,
                        "replay_recipe": cand.get("replay_recipe") if isinstance(cand.get("replay_recipe"), list) else [],
                    }
                )
            self._refresh_candidate_select(strategy_candidates)

            self.query_one("#cipher_input", Input).value = str(entry.get("input_summary", ""))
            lines = [
                f"Loaded entry #{entry.get('id')}",
                f"Best Method: {output.get('best_method') if isinstance(output, dict) else None}",
                f"Best Output: {output.get('best_output') if isinstance(output, dict) else None}",
                f"Candidates: {len(candidates)}",
            ]
            result_widget.update("\n".join(lines))
            self._append_history(f"loaded entry #{entry.get('id')} candidates={len(candidates)}")
            return

        input_widget = self.query_one("#cipher_input", Input)
        operation_widget = self.query_one("#operation", Select)
        candidate_widget = self.query_one("#candidate_select", Select)
        result_widget = self.query_one("#result", Static)

        text = input_widget.value.strip()
        operation = str(operation_widget.value)

        if not text:
            result_widget.update("Input is empty.")
            return

        if event.button.id in {"run", "explore"} and operation == "auto_strategy" and self._looks_like_numeric_symbol_cipher(text):
            crib_hint = self.query_one("#crib_hint", Input).value.strip()
            crib_result = self._auto_crib_decode_numeric_symbol_cipher(text, crib_hint)
            if (
                crib_result is not None
                and float(crib_result.get("unknown_ratio", 1.0)) <= 0.45
                and "?" not in str(crib_result.get("decoded_guess", ""))
            ):
                lines = [
                    "Auto Strategy detected numeric-symbol cipher (crib-assisted).",
                    f"Crib: {crib_result.get('crib')}",
                    f"Anchor Word #: {crib_result.get('anchor_word_index')}",
                    f"Delimiter Symbol: {crib_result.get('delimiter')}",
                    f"Mapped Symbols: {crib_result.get('mapping_size')}",
                    f"Unknown Ratio: {crib_result.get('unknown_ratio')}",
                    "",
                    f"Best Guess: {crib_result.get('decoded_guess', '')}",
                    "",
                    str(crib_result.get("decoded", "")),
                ]
                result_widget.update("\n".join(lines))
                self._append_history("auto strategy crib-substitution")
                return

        if event.button.id in {"run", "explore"}:
            if operation == "auto_strategy":
                payload = {
                    "input": text,
                    "max_depth": 6 if self._looks_like_numeric_symbol_cipher(text) else 5,
                    "timeout_ms": 12000 if self._looks_like_numeric_symbol_cipher(text) else 5000,
                    "max_candidates": 30 if self._looks_like_numeric_symbol_cipher(text) else (20 if event.button.id == "explore" else 5),
                }
            else:
                payload = {
                    "input": text,
                    "steps": [{"op": operation, "params": {"max_key_len": 8}}],
                    "stop_on_flag": False,
                    "timeout_ms": 5000,
                }
        else:
            if not self._last_candidates:
                result_widget.update("No candidate key available. Run a break operation first.")
                return

            try:
                selected_index = int(str(candidate_widget.value))
                candidate = self._last_candidates[selected_index]
            except Exception:
                result_widget.update("Invalid candidate selection.")
                return

            replay = candidate.get("replay_step")
            if isinstance(replay, dict) and isinstance(replay.get("params"), dict) and replay.get("op"):
                replay_recipe = candidate.get("replay_recipe")
                if isinstance(replay_recipe, list) and replay_recipe:
                    payload = {
                        "input": text,
                        "steps": replay_recipe,
                        "stop_on_flag": False,
                        "timeout_ms": 5000,
                    }
                else:
                    payload = {
                        "input": text,
                        "steps": [{"op": str(replay.get("op")), "params": dict(replay.get("params", {}))}],
                        "stop_on_flag": False,
                        "timeout_ms": 5000,
                    }
            else:
                candidate_key = candidate.get("key_text") or candidate.get("key")
                candidate_key_hex = candidate.get("key_hex")
                if candidate_key:
                    payload = {
                        "input": text,
                        "steps": [{"op": "xor_with_key", "params": {"key": str(candidate_key)}}],
                        "stop_on_flag": False,
                        "timeout_ms": 5000,
                    }
                elif candidate_key_hex:
                    payload = {
                        "input": text,
                        "steps": [{"op": "xor_with_key_hex", "params": {"key_hex": str(candidate_key_hex)}}],
                        "stop_on_flag": False,
                        "timeout_ms": 5000,
                    }
                else:
                    result_widget.update("Selected candidate has no replayable key. Choose another candidate.")
                    return

        result_widget.update("Running...")
        try:
            if event.button.id in {"run", "explore"} and operation == "auto_strategy":
                endpoint = "http://localhost:8765/api/v1/crypto/strategy/explore" if event.button.id == "explore" else "http://localhost:8765/api/v1/crypto/strategy/run"
                async with httpx.AsyncClient(timeout=8.0) as client:
                    response = await client.post(endpoint, json=payload)
                body = response.json()
            else:
                body = await self._post_recipe(payload)
        except Exception as exc:
            result_widget.update(f"Request failed: {exc}")
            return

        if not body.get("ok"):
            result_widget.update(json.dumps(body, indent=2, ensure_ascii=True))
            return

        data = body.get("data", {})

        if event.button.id in {"run", "explore"} and operation == "auto_strategy":
            lines = [
                f"Best Method: {data.get('best_method')}",
                f"Best Output: {data.get('best_output')}",
                f"Timed Out: {data.get('timed_out')}",
                f"Requested Max Candidates: {data.get('requested_max_candidates', len(data.get('candidates', [])))}",
                "",
            ]
            method_buckets = data.get("method_buckets")
            if isinstance(method_buckets, dict) and method_buckets:
                bucket_line = ", ".join(f"{name}:{count}" for name, count in sorted(method_buckets.items()))
                lines.append(f"Method Buckets: {bucket_line}")
                lines.append("")

            for idx, cand in enumerate(data.get("candidates", []), start=1):
                lines.append(
                    f"{idx}. method={cand.get('method')} score={cand.get('score')} conf={cand.get('confidence')}"
                )
                lines.append(f"   preview={cand.get('preview', '')}")
                replay = cand.get("replay_step")
                if replay:
                    lines.append(f"   replay={json.dumps(replay, ensure_ascii=True)}")
                lines.append("")

            strategy_candidates = []
            for cand in data.get("candidates", []):
                replay = cand.get("replay_step") or {}
                params = replay.get("params", {}) if isinstance(replay, dict) else {}
                strategy_candidates.append(
                    {
                        "key": params.get("key"),
                        "key_text": params.get("key"),
                        "key_hex": params.get("key_hex", ""),
                        "preview": cand.get("preview", ""),
                        "replay_step": replay if isinstance(replay, dict) else None,
                        "replay_recipe": cand.get("replay_recipe") if isinstance(cand.get("replay_recipe"), list) else [],
                    }
                )
            self._refresh_candidate_select(strategy_candidates)
            self._append_history(
                f"{event.button.id} best={data.get('best_method')} candidates={len(data.get('candidates', []))}"
            )
            result_widget.update("\n".join(lines).strip())
            return

        lines: List[str] = [
            f"Final Output: {data.get('final_output', '')}",
            f"Flag Found: {data.get('flag_found', False)}",
            "",
        ]
        for step in data.get("steps", []):
            lines.append(_format_step(step))
            lines.append("")

        candidates: List[Dict[str, Any]] = []
        for step in data.get("steps", []):
            metadata = step.get("metadata")
            if isinstance(metadata, dict) and isinstance(metadata.get("candidates"), list):
                candidates = metadata["candidates"]
                break
        self._refresh_candidate_select(candidates)
        self._append_history(
            f"recipe op={operation if event.button.id == 'run' else 'candidate_replay'} output={str(data.get('final_output', ''))[:40]}"
        )

        result_widget.update("\n".join(lines).strip())


def run_tui() -> None:
    ToolkitApp().run()
