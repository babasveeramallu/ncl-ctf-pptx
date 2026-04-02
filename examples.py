#!/usr/bin/env python3
"""
Quick examples for running the cracking toolkit
"""
from cracking_kit import HashCrackingKit, generate_adj_noun_combinator
from pathlib import Path

def example_md5_rockyou():
    """Example: Crack MD5 hashes with rockyou"""
    print("📋 MD5 + Rockyou Example")
    print("-" * 50)
    
    # Prepare hash file
    hashes_file = Path("example_md5.txt")
    hashes_file.write_text("""
5d41402abc4b2a76b9719d911017c592
098f6bcd4621d373cade4e832627b4f6
""")
    
    # Run cracking
    kit = HashCrackingKit()
    result = kit.crack_md5_rockyou("example_md5.txt", "cracked_md5_example.txt")
    
    print(f"Status: {result['status']}")
    if result.get('cracked'):
        print("Cracked passwords:")
        for password in result['cracked']:
            print(f"  → {password}")


def example_lm_ntlm_pairs():
    """Example: Crack LM:NTLM hash pairs"""
    print("\n📋 LM:NTLM Pairs Example")
    print("-" * 50)
    
    # Example LM:NTLM pairs
    hashes_file = Path("example_lm_ntlm.txt")
    hashes_file.write_text("""
AAD3B435B51404EEAAD3B435B51404EE:8846F7EAEE8FB117AD06BDD830B7586C
AAD3B435B51404EEAAD3B435B51404EE:3C59DC048E8850243BE8079A5C74D079
""")
    
    kit = HashCrackingKit()
    # Would need to set up LM brute-force
    print("LM:NTLM cracking requires multi-stage approach:")
    print("1. Brute-force LM hash (generates keyspace)")
    print("2. Use recovered LM prefix to target NTLM")


def example_adj_noun_digits():
    """Example: Crack pattern-based hashes (adjective+noun+2digits)"""
    print("\n📋 Adjective+Noun+Digits Pattern Example")
    print("-" * 50)
    
    # Check if combo file exists, generate if needed
    if not Path("adj_noun_combo.txt").exists():
        print("Generating adjective+noun combinator...")
        generate_adj_noun_combinator("adjectives_auto.txt", "nouns_auto.txt")
    
    hashes_file = Path("example_pattern.txt")
    hashes_file.write_text("""
e1ca1097c9b328f0b1e57f6da7e842bc
2e99758548972a8e8287953e4e3d64e1
""")
    
    kit = HashCrackingKit()
    result = kit.crack_adj_noun_digits("example_pattern.txt", "md5")
    
    print(f"Status: {result['status']}")
    if result.get('cracked'):
        print("Cracked passwords:")
        for password in result['cracked']:
            print(f"  → {password}")


def example_office_2013():
    """Example: Crack Office 2013 encrypted document"""
    print("\n📋 Office 2013 Encrypted Document Example")
    print("-" * 50)
    
    office_file = "encrypted_presentation.pptx"
    
    if Path(office_file).exists():
        kit = HashCrackingKit()
        result = kit.crack_office_2013(office_file, "adj_noun_digits")
        print(f"Status: {result['status']}")
        if result.get('cracked'):
            print(f"Office password: {result['cracked'][0]}")
    else:
        print(f"Office file not found: {office_file}")


def interactive_menu():
    """Interactive menu for choosing cracking method"""
    print("🔐 NCL Hash Cracking Toolkit - Quick Examples")
    print("=" * 50)
    print("")
    print("1. Launch Interactive TUI (Recommended)")
    print("2. MD5 + Rockyou Wordlist")
    print("3. LM:NTLM Hash Pairs")
    print("4. Pattern-Based (Adjective+Noun+Digits)")
    print("5. Office 2013 Documents")
    print("0. Exit")
    print("")
    
    choice = input("Select option (0-5): ").strip()
    
    if choice == "1":
        print("\n🚀 Launching TUI...")
        import crack_ui
        app = crack_ui.HashCrackingApp()
        app.run()
    
    elif choice == "2":
        example_md5_rockyou()
    
    elif choice == "3":
        example_lm_ntlm_pairs()
    
    elif choice == "4":
        example_adj_noun_digits()
    
    elif choice == "5":
        example_office_2013()
    
    elif choice == "0":
        print("Goodbye!")
        return
    
    else:
        print("Invalid option!")


if __name__ == "__main__":
    interactive_menu()
