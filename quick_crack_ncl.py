import hashlib
from pathlib import Path

HASH_FILE = Path("hashes_pairs.txt")
WORDLIST_CANDIDATES = [Path("rockyou_full.txt"), Path("rockyou_2025_05.txt")]


def pick_wordlist() -> Path | None:
    for p in WORDLIST_CANDIDATES:
        if p.exists():
            return p
    return None


def load_pairs(path: Path) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or ":" not in line:
            continue
        left, right = line.split(":", 1)
        pairs.append((left.lower(), right.lower()))
    return pairs


def main() -> None:
    if not HASH_FILE.exists():
        print("Missing hashes_pairs.txt")
        print("Create it with lines like: LEFTHEX:RIGHTHEX")
        return

    wordlist = pick_wordlist()
    if wordlist is None:
        print("No wordlist found. Need rockyou_full.txt or rockyou_2025_05.txt")
        return

    pairs = load_pairs(HASH_FILE)
    if not pairs:
        print("No valid hash pairs found in hashes_pairs.txt")
        return

    right_targets = {r for _, r in pairs}
    found_md5: dict[str, str] = {}
    found_ntlm: dict[str, str] = {}

    checked = 0
    with wordlist.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            pw = line.rstrip("\n\r")
            if not pw:
                continue

            checked += 1

            md5 = hashlib.md5(pw.encode("utf-8", errors="ignore")).hexdigest()
            if md5 in right_targets and md5 not in found_md5:
                found_md5[md5] = pw

            try:
                ntlm = hashlib.new("md4", pw.encode("utf-16le")).hexdigest()
            except Exception:
                ntlm = ""
            if ntlm in right_targets and ntlm not in found_ntlm:
                found_ntlm[ntlm] = pw

    print(f"Using wordlist: {wordlist}")
    print(f"Checked passwords: {checked:,}")
    print()

    for idx, (left, right) in enumerate(pairs, start=1):
        print(f"Pair {idx}")
        print(f"  LEFT : {left}")
        print(f"  RIGHT: {right}")
        print(f"  RIGHT as MD5  -> {found_md5.get(right)}")
        print(f"  RIGHT as NTLM -> {found_ntlm.get(right)}")
        print()


if __name__ == "__main__":
    main()
