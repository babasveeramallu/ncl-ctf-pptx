"""
Password-based encryption cracking service.
Attempts to decrypt AES-encrypted data using passwords from wordlists.
"""

from __future__ import annotations

import binascii
import hashlib
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


def _remove_pkcs7_padding(data: bytes) -> bytes:
    """Remove PKCS7 padding from decrypted data."""
    if not data:
        return data
    
    # Last byte indicates padding length
    padding_len = data[-1]
    
    # Validate padding
    if 1 <= padding_len <= 16:
        if all(b == padding_len for b in data[-padding_len:]):
            return data[:-padding_len]
    
    # Return as-is if no valid padding
    return data


def _is_valid_plaintext(data: bytes) -> bool:
    """
    Check if decrypted data looks like valid plaintext.
    For passwords/text, should be mostly ASCII printable or valid UTF-8.
    """
    if not data:
        return False
    
    # Remove padding first
    data = _remove_pkcs7_padding(data)
    if not data:
        return False
    
    # Try ASCII printable first
    ascii_printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    if ascii_printable / len(data) >= 0.75:
        return True
    
    # Try UTF-8 decoding
    try:
        decoded = data.decode('utf-8').strip()
        # At least 2 chars and not all whitespace
        return len(decoded) >= 2 and bool(decoded.strip())
    except UnicodeDecodeError:
        return False


def _try_decrypt_aes_direct_key(ciphertext_bytes: bytes, password: str) -> str | None:
    """
    Try AES decryption with password directly as key (MD5 hashed).
    """
    try:
        # Derive 16-byte key from password via MD5
        key = hashlib.md5(password.encode()).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext_bytes)
        
        # Remove PKCS7 padding
        plaintext = _remove_pkcs7_padding(plaintext)
        
        if _is_valid_plaintext(plaintext):
            try:
                return plaintext.decode('utf-8', errors='replace').strip()
            except Exception:
                return plaintext.decode('latin-1', errors='replace').strip()
        return None
    except Exception:
        return None


def _try_decrypt_aes_pbkdf2(ciphertext_bytes: bytes, password: str, salt: bytes = b'') -> str | None:
    """
    Try AES decryption with PBKDF2-derived key.
    """
    try:
        if not salt:
            salt = b'saltvalue'
        key = PBKDF2(password, salt, dkLen=16, count=10000)
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext_bytes)
        
        # Remove PKCS7 padding
        plaintext = _remove_pkcs7_padding(plaintext)
        
        if _is_valid_plaintext(plaintext):
            try:
                return plaintext.decode('utf-8', errors='replace').strip()
            except Exception:
                return plaintext.decode('latin-1', errors='replace').strip()
        return None
    except Exception:
        return None


def crack_password_encrypted(
    ciphertext_hex: str,
    wordlist_path: str,
    timeout_ms: int = 5000,
    max_attempts: int = 100000,
) -> Dict[str, Any]:
    """
    Attempt to crack password-encrypted AES ciphertext using wordlist.
    
    Args:
        ciphertext_hex: Hex string of encrypted data
        wordlist_path: Path to password wordlist file
        timeout_ms: Maximum time in milliseconds
        max_attempts: Maximum passwords to try
    
    Returns:
        Dict with plaintext (if found), attempts tried, and success status
    """
    started = time.perf_counter()
    attempts = 0
    
    def remaining_ms() -> int:
        return max(0, timeout_ms - int((time.perf_counter() - started) * 1000))
    
    # Convert hex ciphertext to bytes
    try:
        ciphertext_bytes = binascii.unhexlify(ciphertext_hex)
    except (ValueError, binascii.Error):
        return {
            "plaintext": None,
            "password": None,
            "attempts": 0,
            "success": False,
            "error": "Invalid hex ciphertext"
        }
    
    # Read wordlist and try passwords
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if remaining_ms() <= 0:
                    break
                if attempts >= max_attempts:
                    break
                
                password = line.strip()
                if not password:
                    continue
                
                attempts += 1
                
                # Try direct key derivation (MD5)
                plaintext = _try_decrypt_aes_direct_key(ciphertext_bytes, password)
                if plaintext:
                    return {
                        "plaintext": plaintext,
                        "password": password,
                        "attempts": attempts,
                        "success": True,
                        "method": "AES-MD5",
                    }
                
                # Try PBKDF2
                plaintext = _try_decrypt_aes_pbkdf2(ciphertext_bytes, password)
                if plaintext:
                    return {
                        "plaintext": plaintext,
                        "password": password,
                        "attempts": attempts,
                        "success": True,
                        "method": "AES-PBKDF2",
                    }
    
    except FileNotFoundError:
        return {
            "plaintext": None,
            "password": None,
            "attempts": 0,
            "success": False,
            "error": f"Wordlist not found: {wordlist_path}"
        }
    except Exception as e:
        return {
            "plaintext": None,
            "password": None,
            "attempts": attempts,
            "success": False,
            "error": str(e)
        }
    
    # No match found
    return {
        "plaintext": None,
        "password": None,
        "attempts": attempts,
        "success": False,
        "error": "No matching password found in wordlist"
    }


def parse_wifi_psk_config(config_text: str) -> List[Dict[str, str]]:
    blocks = re.findall(r"network\s*=\s*\{(.*?)\}", config_text, flags=re.IGNORECASE | re.DOTALL)
    networks: List[Dict[str, str]] = []

    for block in blocks:
        ssid_match = re.search(r"ssid\s*=\s*\"([^\"]+)\"", block, flags=re.IGNORECASE)
        psk_match = re.search(r"psk\s*=\s*\"?([0-9a-fA-F]{64})\"?", block, flags=re.IGNORECASE)
        if not ssid_match or not psk_match:
            continue

        networks.append(
            {
                "ssid": ssid_match.group(1),
                "psk": psk_match.group(1).lower(),
            }
        )

    return networks


def derive_wpa_psk_hex(passphrase: str, ssid: str) -> str:
    derived = hashlib.pbkdf2_hmac(
        "sha1",
        passphrase.encode("utf-8"),
        ssid.encode("utf-8"),
        4096,
        32,
    )
    return derived.hex()


def crack_wifi_psk_config(
    config_text: str,
    wordlist_path: str,
    timeout_ms: int = 120000,
    max_attempts: int = 250000,
) -> Dict[str, Any]:
    started = time.perf_counter()
    networks = parse_wifi_psk_config(config_text)
    if not networks:
        return {
            "success": False,
            "attempts": 0,
            "cracked": [],
            "uncracked": [],
            "error": "No valid network blocks with ssid + 64-hex psk found",
        }

    unresolved: Dict[str, Dict[str, str]] = {
        n["ssid"]: {"ssid": n["ssid"], "psk": n["psk"]} for n in networks
    }
    cracked: List[Dict[str, str]] = []
    attempts = 0

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                if attempts >= max_attempts:
                    break
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                if elapsed_ms >= timeout_ms:
                    break

                passphrase = line.strip()
                if not passphrase or len(passphrase) < 8 or len(passphrase) > 63:
                    continue

                attempts += 1
                to_remove: List[str] = []
                for ssid, net in unresolved.items():
                    derived_hex = derive_wpa_psk_hex(passphrase, ssid)
                    if derived_hex == net["psk"]:
                        cracked.append(
                            {
                                "ssid": ssid,
                                "password": passphrase,
                                "psk": net["psk"],
                            }
                        )
                        to_remove.append(ssid)

                for ssid in to_remove:
                    unresolved.pop(ssid, None)

                if not unresolved:
                    break
    except FileNotFoundError:
        return {
            "success": False,
            "attempts": 0,
            "cracked": [],
            "uncracked": networks,
            "error": f"Wordlist not found: {wordlist_path}",
        }
    except Exception as exc:
        return {
            "success": False,
            "attempts": attempts,
            "cracked": cracked,
            "uncracked": list(unresolved.values()),
            "error": str(exc),
        }

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return {
        "success": len(unresolved) == 0,
        "attempts": attempts,
        "elapsed_ms": elapsed_ms,
        "network_count": len(networks),
        "cracked": cracked,
        "uncracked": list(unresolved.values()),
    }


def extract_office_hash_from_file_bytes(file_name: str, payload: bytes, timeout_s: int = 20) -> Dict[str, Any]:
    """
    Extract a hashcat-compatible $office$ hash line from an Office encrypted file.
    Uses the repository's bundled office2john.py script.
    """
    if not payload:
        return {"ok": False, "error": "Empty file payload"}

    # OOXML files (.pptx/.docx/.xlsx) that are not password-protected are plain ZIP containers.
    # Encrypted Office files are normally wrapped in OLE/CFB and should not start with PK.
    ext = Path(file_name).suffix.lower()
    if ext in {".pptx", ".docx", ".xlsx"} and payload[:2] == b"PK":
        return {
            "ok": False,
            "error": "File appears to be an unencrypted Office OpenXML document (not password-protected)",
            "file": file_name,
        }

    repo_root = Path(__file__).resolve().parents[2]
    office2john_path = repo_root / "office2john.py"
    if not office2john_path.exists():
        return {"ok": False, "error": "office2john.py not found in repository root"}

    suffix = Path(file_name).suffix or ".bin"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(payload)
        tmp_path = Path(tmp.name)

    try:
        cmd = [sys.executable, str(office2john_path), str(tmp_path)]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max(5, min(timeout_s, 90)), check=False)
        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()

        office_lines = [line.strip() for line in stdout.splitlines() if "$office$" in line]
        if not office_lines:
            msg = "Could not extract an Office hash from file"
            if stderr:
                msg = f"{msg}: {stderr.splitlines()[-1][:300]}"
            return {
                "ok": False,
                "error": msg,
                "stdout": stdout[:800],
                "stderr": stderr[:800],
                "return_code": proc.returncode,
            }

        # Preserve optional filename prefix for hashcat/john compatibility.
        office_hash = office_lines[0]
        version = "unknown"
        for tag in ("*2007*", "*2010*", "*2013*"):
            if tag in office_hash:
                version = tag.strip("*")
                break

        return {
            "ok": True,
            "office_hash": office_hash,
            "format": "office",
            "version": version,
            "stdout": stdout[:800],
            "stderr": stderr[:800],
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Office hash extraction timed out"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        tmp_path.unlink(missing_ok=True)
