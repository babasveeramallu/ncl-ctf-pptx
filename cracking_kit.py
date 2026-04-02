#!/usr/bin/env python3
"""
NCL Cracking Toolkit - Consolidated hash cracking utilities
Supports: MD5, NTLM, LM, SHA1, SHA256, Office 2013
"""
import subprocess
import hashlib
import os
from pathlib import Path
from typing import List, Tuple, Optional
import struct
import hmac


class HashCrackingKit:
    """Unified toolkit for hash cracking"""
    
    def __init__(self, hashcat_path: str = "tools/hashcat-6.2.6/hashcat.exe"):
        self.hashcat_path = Path(hashcat_path)
        if not self.hashcat_path.exists():
            self.hashcat_path = Path("hashcat.exe")
        self.potfile = Path("hashcat.potfile")
    
    # ===== HASH TYPE DETECTION =====
    
    @staticmethod
    def detect_hash_type(hash_string: str) -> str:
        """Auto-detect hash type from string format"""
        hash_string = hash_string.strip().upper()
        
        if ":" in hash_string:
            parts = hash_string.split(":")
            if len(parts) == 2:
                left, right = parts
                if len(left) == 32 and len(right) == 32:
                    return "lm_ntlm"
                elif len(left) == 32:
                    return "md5"
        
        hash_len = len(hash_string)
        if hash_len == 32:
            return "md5"
        elif hash_len == 40:
            return "sha1"
        elif hash_len == 64:
            return "sha256"
        elif hash_len == 128:
            return "sha512"
        
        return "unknown"
    
    # ===== WORDLIST ATTACKS (MD5/NTLM) =====
    
    def crack_md5_rockyou(self, hash_file: str, output_file: str = "cracked_md5.txt") -> dict:
        """Crack MD5 hashes using rockyou wordlist"""
        return self._run_hashcat(hash_type="md5", mode=0, hash_file=hash_file, 
                                 dict_file="rockyou_full.txt", output_file=output_file)
    
    def crack_ntlm_rockyou(self, hash_file: str, output_file: str = "cracked_ntlm.txt") -> dict:
        """Crack NTLM hashes using rockyou wordlist"""
        return self._run_hashcat(hash_type="ntlm", mode=1000, hash_file=hash_file,
                                 dict_file="rockyou_full.txt", output_file=output_file)
    
    def crack_sha1_rockyou(self, hash_file: str, output_file: str = "cracked_sha1.txt") -> dict:
        """Crack SHA1 hashes using rockyou wordlist"""
        return self._run_hashcat(hash_type="sha1", mode=100, hash_file=hash_file,
                                 dict_file="rockyou_full.txt", output_file=output_file)
    
    # ===== PATTERN-BASED ATTACKS =====
    
    def crack_adj_noun_digits(self, hash_file: str, hash_type: str = "md5", 
                              combo_file: str = "adj_noun_combo.txt", 
                              output_file: str = "cracked_pattern.txt") -> dict:
        """Crack using adjective+noun+2digits pattern"""
        mode_map = {"md5": 0, "ntlm": 1000, "sha1": 100, "sha256": 1400}
        mode = mode_map.get(hash_type, 0)
        
        cmd = [
            str(self.hashcat_path), "-m", str(mode), "-a", "6",
            hash_file, combo_file, "?d?d",
            "--status", "--status-timer", "5", "--runtime", "3600"
        ]
        
        return self._execute_hashcat(cmd, output_file)
    
    def crack_hybrid_rockyou_digits(self, hash_file: str, hash_type: str = "md5",
                                   output_file: str = "cracked_hybrid.txt") -> dict:
        """Hybrid attack: rockyou + 2-3 digits"""
        mode_map = {"md5": 0, "ntlm": 1000, "sha1": 100, "sha256": 1400}
        mode = mode_map.get(hash_type, 0)
        
        cmd = [
            str(self.hashcat_path), "-m", str(mode), "-a", "6",
            hash_file, "rockyou_full.txt", "?d?d?d",
            "--status", "--status-timer", "5", "--runtime", "3600"
        ]
        
        return self._execute_hashcat(cmd, output_file)
    
    # ===== LM ATTACKS =====
    
    def crack_lm_bruteforce(self, lm_hash: str, charset_size: int = 26,
                            output_file: str = "cracked_lm.txt") -> dict:
        """Brute-force LM hash (uppercase letters only, 8 chars max)"""
        cmd = [
            str(self.hashcat_path), "-m", "3000", "-a", "3",
            "-o", output_file,
            "--status", "--status-timer", "5",
            lm_hash,
            "?u?u?u?u?u?u?u?u"  # 8 uppercase letters
        ]
        
        return self._execute_hashcat(cmd, output_file)
    
    # ===== OFFICE 2013 ATTACKS =====
    
    def crack_office_2013(self, office_file: str, attack_mode: str = "adj_noun_digits",
                         output_file: str = "cracked_office.txt") -> dict:
        """Crack Office 2013 encrypted document"""
        # Extract hash first
        hash_file = self._extract_office_hash(office_file)
        
        if not hash_file:
            return {"status": "error", "message": "Could not extract Office hash"}
        
        if attack_mode == "adj_noun_digits":
            return self.crack_adj_noun_digits(hash_file, "office2013", output_file=output_file)
        elif attack_mode == "rockyou":
            return self._run_hashcat("office2013", 9500, hash_file, 
                                    "rockyou_full.txt", output_file)
        
        return {"status": "error", "message": f"Unknown attack mode: {attack_mode}"}
    
    # ===== HELPER METHODS =====
    
    def _extract_office_hash(self, office_file: str) -> Optional[str]:
        """Extract Office 2013 hash from .pptx/.docx file"""
        try:
            import zipfile
            import xml.etree.ElementTree as ET
            
            office_path = Path(office_file)
            if not office_path.exists():
                return None
            
            with zipfile.ZipFile(office_path, 'r') as zf:
                # Try to read encryption metadata
                if 'encryptionInfo' in zf.namelist():
                    hash_data = zf.read('encryptionInfo')
                    # Extract hash (Office 2013 format)
                    hash_string = hash_data.hex()
                    
                    hash_file = Path("office_hash.txt")
                    hash_file.write_text(hash_string)
                    return str(hash_file)
        except Exception as e:
            print(f"Error extracting Office hash: {e}")
        
        return None
    
    def _run_hashcat(self, hash_type: str, mode: int, hash_file: str,
                    dict_file: str, output_file: str) -> dict:
        """Run hashcat with dictionary attack"""
        cmd = [
            str(self.hashcat_path), "-m", str(mode), "-a", "0",
            "-o", output_file,
            "--status", "--status-timer", "5",
            hash_file, dict_file
        ]
        
        return self._execute_hashcat(cmd, output_file)
    
    def _execute_hashcat(self, cmd: List[str], output_file: str) -> dict:
        """Execute hashcat command and return results"""
        result = {
            "status": "pending",
            "command": " ".join(cmd),
            "cracked": [],
            "output_file": output_file
        }
        
        try:
            print(f"🔧 Running: {' '.join(cmd[:5])}...")
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            output = ""
            for line in process.stdout:
                output += line
                print(line.rstrip())
            
            process.wait()
            
            if process.returncode == 0:
                result["status"] = "success"
                if Path(output_file).exists():
                    result["cracked"] = Path(output_file).read_text().strip().split('\n')
            else:
                result["status"] = "no_match" if process.returncode == 1 else "error"
            
            result["raw_output"] = output
            
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
        
        return result
    
    def read_results(self) -> List[Tuple[str, str]]:
        """Read cracked hashes from potfile"""
        if not self.potfile.exists():
            return []
        
        results = []
        for line in self.potfile.read_text().strip().split('\n'):
            if ':' in line:
                hash_part, password = line.split(':', 1)
                results.append((hash_part, password))
        
        return results


def generate_adj_noun_combinator(adj_file: str = "adjectives.txt",
                                 noun_file: str = "nouns.txt",
                                 output_file: str = "adj_noun_combo.txt"):
    """Generate combinator dictionary from adjectives + nouns"""
    if not Path(adj_file).exists() or not Path(noun_file).exists():
        print(f"❌ Missing word lists")
        return False
    
    adjectives = Path(adj_file).read_text().strip().split('\n')
    nouns = Path(noun_file).read_text().strip().split('\n')
    
    print(f"📚 Combining {len(adjectives)} adjectives × {len(nouns)} nouns...")
    
    with open(output_file, 'w') as f:
        for adj in adjectives:
            for noun in nouns:
                f.write(f"{adj}{noun}\n")
    
    file_size = Path(output_file).stat().st_size / (1024 * 1024)
    print(f"✅ Generated {output_file} ({file_size:.1f} MB)")
    return True


if __name__ == "__main__":
    # Example usage
    print("🔐 NCL Hash Cracking Toolkit")
    print("="*50)
    
    kit = HashCrackingKit()
    
    # Example: crack MD5 hashes with rockyou
    # result = kit.crack_md5_rockyou("hashes.txt")
    # print(f"Result: {result['status']}")
    # 
    # Example: crack LM:NTLM pairs
    # result = kit.crack_lm_bruteforce("aabbccdd00112233")
