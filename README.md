# PPTX Password Crack Helper

This repository is focused on one workflow: cracking password-protected PowerPoint files using Python orchestration around office2john and hashcat.

Main files:

- `pptx_cracking_python.py`: command-line helper for extraction and cracking.
- `office2john.py`: extracts Office password hashes from encrypted files.

## Requirements

1. Python 3.10+
2. hashcat installed or available at `tools/hashcat-6.2.6/hashcat-6.2.6/hashcat.exe`
3. A wordlist file (example: `rockyou_full.txt`)

## Commands

### 1) Extract hash from PPTX

```powershell
python .\pptx_cracking_python.py extract --pptx ".\protected.pptx"
```

Optional:

```powershell
python .\pptx_cracking_python.py extract --pptx ".\protected.pptx" --out ".\office_hash.txt" --timeout 90
```

### 2) Extract and crack in one run

```powershell
python .\pptx_cracking_python.py run --pptx ".\protected.pptx" --wordlist ".\rockyou_full.txt"
```

Optional:

```powershell
python .\pptx_cracking_python.py run --pptx ".\protected.pptx" --wordlist ".\rockyou_full.txt" --runtime 600 --potfile ".\_office_tmp.pot"
```

If hashcat is not in the default bundled location, set it explicitly:

```powershell
python .\pptx_cracking_python.py run --pptx ".\protected.pptx" --wordlist ".\rockyou_full.txt" --hashcat-path "C:\path\to\hashcat.exe"
```

## Hashcat Modes Used

- Office 2007 -> `-m 9400`
- Office 2010 -> `-m 9500`
- Office 2013 -> `-m 9600`

The script detects the version from the extracted `$office$` hash and applies the matching mode automatically.

## Troubleshooting

1. If extraction fails, confirm the file is encrypted and ends with `.pptx`.
2. If hashcat fails, verify your GPU/OpenCL setup or run on a supported system.
3. If no password is found, try a larger or more targeted wordlist.
