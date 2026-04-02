# CTF Master Toolkit

Phase 1A scaffold for a local-first CTF toolkit (Textual + FastAPI + SQLite).

## Quickstart

1. Create and activate a virtual environment.
2. Install dependencies:
   - `pip install -r requirements.txt`
3. Copy config template:
   - `copy config.yml.example config.yml` (Windows)
4. Start backend:
   - `uvicorn backend.main:app --host 127.0.0.1 --port 8765 --reload`
5. Launch TUI:
   - `python ctf.py`

## Python-Only PPTX Cracking Workflow

Use `pptx_cracking_python.py` when you want a single, standalone Python entrypoint
for Office/PPTX hash extraction and cracking.

What this script does:

- Extracts `$office$` hash from a password-protected `.pptx` using `office2john.py`.
- Writes the extracted hash to a file (`office_hash.txt` by default).
- Runs `hashcat.exe` through Python `subprocess` for dictionary attacks.

Hashcat mode mapping used by the script:

- Office 2007: `9400`
- Office 2010: `9500`
- Office 2013: `9600`

Examples:

1. Extract hash only:
   - `python pptx_cracking_python.py extract --pptx "protected.pptx" --out "office_hash.txt"`
2. One-shot extract + crack:
   - `python pptx_cracking_python.py run --pptx "protected.pptx" --wordlist "rockyou_full.txt"`

Notes:

- If hashcat is not in the bundled path, pass `--hashcat-path "path\\to\\hashcat.exe"`.
- Optional runtime cap: add `--runtime 600`.
- Optional potfile location: add `--potfile "_office_tmp.pot"`.

## Included in this scaffold

- Global API response envelopes.
- X-Processing-Time-Ms response header middleware.
- Startup tool availability check exposed via `/api/v1/health`.
- SQLite schema at `backend/db/schema.sql`.
- Endpoint stubs under `/api/v1/*` returning 501 for unimplemented routes.
