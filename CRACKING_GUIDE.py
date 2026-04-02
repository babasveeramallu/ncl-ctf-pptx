#!/usr/bin/env python3
"""
NCL Cracking Toolkit - Quick Start Guide
"""

QUICK_START = """
╔═══════════════════════════════════════════════════════════════════╗
║           🔐 NCL Hash Cracking Toolkit - Quick Start             ║
╚═══════════════════════════════════════════════════════════════════╝

📦 COMPONENTS:
───────────────────────────────────────────────────────────────────

1. crack_ui.py (Interactive TUI)
   → Full-featured GUI for hash cracking
   → Supports all hash types and attack modes
   → Real-time progress monitoring
   
2. cracking_kit.py (Programmatic API)
   → Reusable library for scripts
   → Direct access to all attack methods
   → Flexible configuration
   
3. examples.py (Quick Examples)
   → Common usage patterns
   → Interactive menu for easy selection
   

🚀 QUICK START (3 STEPS):
───────────────────────────────────────────────────────────────────

OPTION A: Interactive TUI (Recommended)
───────────────────────────────────────
$ python crack_ui.py

Then:
  1. Select hash type (MD5, NTLM, LM:NTLM, Office 2013, etc.)
  2. Paste hashes or load from file
  3. Choose attack mode (Rockyou, Pattern, Brute-force, etc.)
  4. Watch progress and view results


OPTION B: Quick Examples
────────────────────────
$ python examples.py

Then select from interactive menu:
  1. Launch TUI
  2. MD5 + Rockyou
  3. LM:NTLM Pairs
  4. Adjective+Noun+Digits Pattern
  5. Office 2013 Documents


OPTION C: Direct Python API
─────────────────────────────
from cracking_kit import HashCrackingKit

kit = HashCrackingKit()
result = kit.crack_md5_rockyou("hashes.txt")
print(result['cracked'])


💾 HASH FILE FORMAT:
───────────────────────────────────────────────────────────────────

MD5 (one per line):
  5d41402abc4b2a76b9719d911017c592
  098f6bcd4621d373cade4e832627b4f6

NTLM (one per line):
  8846F7EAEE8FB117AD06BDD830B7586C
  3C59DC048E8850243BE8079A5C74D079

LM:NTLM Pairs (LM_HASH:NTLM_HASH):
  AAD3B435B51404EEAAD3B435B51404EE:8846F7EAEE8FB117AD06BDD830B7586C
  AAD3B435B51404EEAAD3B435B51404EE:3C59DC048E8850243BE8079A5C74D079

SHA1 (one per line):
  aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d

SHA256 (one per line):
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855


⚔️  ATTACK MODES EXPLAINED:
───────────────────────────────────────────────────────────────────

1. ROCKYOU WORDLIST (Fast, Best for common passwords)
   ├─ Uses: rockyou_full.txt (~14 million common passwords)
   ├─ Speed: 300-500+ MH/s (depending on hash type)
   ├─ Success Rate: ~70% of default passwords
   └─ Best For: Initial reconnaissance, common passwords
   
   Example: python examples.py → Choose "2"

2. PATTERN-BASED: ADJECTIVE + NOUN + 2 DIGITS (Specialized)
   ├─ Password Scheme: fantasticman41, cruelperson76, etc.
   ├─ Keyspace: 2,500 adj × 6,000 noun × 100 digit pairs = 1.5B
   ├─ Speed: ~300+ MH/s (explores ~9% per 15 seconds)
   ├─ Files Needed: adjectives.txt, nouns.txt, adj_noun_combo.txt
   └─ Quick Time: 15 seconds for MD5 (slow for Office 2013)
   
   Example: python examples.py → Choose "4"

3. HYBRID: ROCKYOU + DIGITS (Popular modifications)
   ├─ Password Scheme: password123, rockyou456, etc.
   ├─ Appends: 1-3 trailing digits to rockyou words
   ├─ Keyspace: 14M words × 1000 digit combos = 14B
   ├─ Speed: Slower than rockyou, faster than brute-force
   └─ Best For: Users who add numbers to passwords
   
   Example Usage:
   ```python
   from cracking_kit import HashCrackingKit
   kit = HashCrackingKit()
   kit.crack_hybrid_rockyou_digits("hashes.txt", "md5")
   ```

4. BRUTE-FORCE (Last resort, slow)
   ├─ Pattern: Custom mask (e.g., ?a?a?a?a = 4 chars all types)
   ├─ Speed: 10-100 MH/s (much slower than wordlist)
   ├─ Keyspace: Limited by pattern complexity
   ├─ Mask Syntax:
   │  ?l = lowercase (a-z)
   │  ?u = UPPERCASE (A-Z)
   │  ?d = digits (0-9)
   │  ?a = all chars
   │  ?s = special chars
   └─ Example: ?u?u?u?u?u?u?u?u = 8 uppercase letters
   
   Use When: All wordlist approach fail


📊 HASH TYPE SPECIFICATIONS:
───────────────────────────────────────────────────────────────────

MD5
  ├─ Length: 32 hex characters
  ├─ Hashcat Mode: 0 (-m 0)
  ├─ Speed: ~300+ MH/s
  ├─ Security: WEAK (deprecated, cryptographically broken)
  └─ Use: Legacy systems, CTF challenges

NTLM (Windows NT LAN Manager)
  ├─ Length: 32 hex characters
  ├─ Hashcat Mode: 1000 (-m 1000)
  ├─ Speed: ~300+ MH/s
  ├─ Security: WEAK (vulnerable to rainbow tables)
  └─ Use: Windows SAM databases, legacy authentication

LM (LAN Manager) + NTLM Pairs
  ├─ Format: LM_HASH:NTLM_HASH
  ├─ LM Length: 32 hex chars
  ├─ Two-stage attack:
  │  Step 1: Brute-force LM (fast, max 8 chars)
  │  Step 2: Use LM result to target NTLM (faster)
  ├─ Speed: LM ~1000 MH/s, then NTLM ~300 MH/s
  └─ Use: Windows NT/2000/XP before Service Pack 1

SHA1
  ├─ Length: 40 hex characters
  ├─ Hashcat Mode: 100 (-m 100)
  ├─ Speed: ~150+ MH/s
  ├─ Security: WEAK (collision attacks feasible)
  └─ Use: Legacy web applications, git commits

SHA256
  ├─ Length: 64 hex characters
  ├─ Hashcat Mode: 1400 (-m 1400)
  ├─ Speed: ~100+ MH/s
  ├─ Security: STRONG (currently secure)
  └─ Use: Modern systems, Linux crypt($5$), etc.

Office 2013 (.pptx, .docx, .xlsx)
  ├─ Hashcat Mode: 9500 (-m 9500)
  ├─ Speed: ~5-10 MH/s (MUCH slower - SHA512+AES)
  ├─ Complexity: Derived from password + salt + iterations
  ├─ Extraction: Automatic from encrypted document
  └─ Estimated Time (adj+noun+2digits):
     MD5:  15 seconds
     Office 2013: 10-15 minutes


📁 REQUIRED FILES:
───────────────────────────────────────────────────────────────────

Essential:
  ✓ tools/hashcat-6.2.6/hashcat.exe (GPU cracker)
  ✓ rockyou_full.txt (14M passwords)
  
Optional (for pattern attacks):
  ✓ adjectives.txt (2,500+ words)
  ✓ nouns.txt (6,000+ words)
  ✓ adj_noun_combo.txt (generated from above)


⚙️  CONFIGURATION:
───────────────────────────────────────────────────────────────────

HashCrackingKit Constructor:
  kit = HashCrackingKit(hashcat_path="tools/hashcat-6.2.6/hashcat.exe")
  
  Default hashcat path is checked in this order:
    1. tools/hashcat-6.2.6/hashcat.exe
    2. hashcat.exe (current directory)

Output Files (automatically generated):
  cracked_md5.txt          → MD5 cracking results
  cracked_ntlm.txt         → NTLM cracking results
  cracked_pattern.txt      → Pattern-based results
  cracked_office.txt       → Office documents results
  hashcat.potfile          → Hashcat's result cache


🎯 USAGE EXAMPLES:
───────────────────────────────────────────────────────────────────

Example 1: Crack MD5 with Rockyou (TUI)
───────────────────────────────────────
$ python crack_ui.py
→ Select "MD5" hash type
→ Paste your hashes
→ Select "Rockyou Wordlist"
→ Click "Start Cracking!"

Example 2: Crack MD5 with Rockyou (CLI)
────────────────────────────────────────
$ python examples.py
→ Choose option "2"
(Auto-generates example, runs cracking)

Example 3: Crack Office Document (TUI)
────────────────────────────────────────
$ python crack_ui.py
→ Select "Office 2013"
→ Upload encrypted_file.pptx
→ Select "Adjective+Noun+2Digits" pattern
→ Click "Start Cracking!"
→ Wait 10-15 minutes

Example 4: Batch Cracking (Python)
────────────────────────────────────
from cracking_kit import HashCrackingKit

kit = HashCrackingKit()

hashes = [
    ("md5", "hashes_md5.txt"),
    ("ntlm", "hashes_ntlm.txt"),
    ("sha256", "hashes_sha256.txt"),
]

for hash_type, hash_file in hashes:
    result = kit.crack_md5_rockyou(hash_file) \\
        if hash_type == "md5" else None
    print(f"{hash_type}: {result['status']}")


🔧 TROUBLESHOOTING:
───────────────────────────────────────────────────────────────────

Q: "hashcat.exe not found"
A: Check tools/hashcat-6.2.6/hashcat.exe exists, or 
   extract hashcat in current directory

Q: "rockyou_full.txt not found"
A: Download from SecLists:
   wget https://github.com/danielmiessler/SecLists/blob/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz

Q: "No hashes cracked after 10 minutes"
A: Try different attack mode:
   - Switch from Rockyou to Pattern-based
   - Use Hybrid attack (wordlist + digits)
   - Check hash format is correct

Q: "TUI not launching"
A: Install Textual:
   pip install textual

Q: "Office password not found"
A: Office 2013 is 50x slower than MD5
   - Try Rockyou attack first
   - Use pattern-based if time-limited
   - Expected time: 10-15 minutes for common patterns

Q: "GPU not detected / slow speed"
A: Check GPU support:
   hashcat.exe -I
   
   If Intel/AMD iGPU not used:
   - Install latest GPU drivers
   - Use -d 1 (GPU device 1) if multiple GPUs


📚 FURTHER READING:
───────────────────────────────────────────────────────────────────

Hashcat Wiki:
  https://hashcat.net/wiki/

Hashcat Attack Modes:
  -a 0  Dictionary
  -a 1  Combination
  -a 3  Brute-force (Mask)
  -a 6  Hybrid (Wordlist + Mask)
  -a 7  Hybrid (Mask + Wordlist)

Password Cracking Techniques:
  https://www.khanacademy.org/...

NCL Competition Tips:
  - Start with Rockyou (covers ~70% of weak passwords)
  - If no hits, move to pattern recognition
  - Use context clues (company names, dates, themes)
  - LM:NTLM pairs: Always recover LM first (much faster)


✨ TIPS FOR SUCCESS:
───────────────────────────────────────────────────────────────────

1. Pattern Recognition is KEY
   Look for hints in challenge description:
   - "password format: adjective+noun+numbers"
   - "8-character memorable password"
   - "3-word passphrase with numbers"
   
2. Parallel Attacks
   - Run multiple hashcat instances on different hashes
   - Combine wordlists for faster coverage
   
3. Wordlist Ordering
   - Best passwords first (Rockyou is pre-sorted by frequency)
   - Custom wordlists: sort by frequency for faster hits
   
4. GPU Memory Management
   - Distributed attack if low VRAM
   - Use --workload-profile 3 for fast terminals
   
5. Time Estimation
   - MD5/NTLM wordlist: 1-5 seconds per 14M words
   - Pattern-based: Calculate (dictsize × pattern_size) / speed
   - Office 2013: Expect 50x slower than MD5


═══════════════════════════════════════════════════════════════════

For more help, run:
  python examples.py      (Interactive menu)
  python crack_ui.py      (Full TUI)
  python cracking_kit.py  (See code examples)

═══════════════════════════════════════════════════════════════════
"""

if __name__ == "__main__":
    print(QUICK_START)
