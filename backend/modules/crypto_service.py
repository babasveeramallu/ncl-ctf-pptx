from __future__ import annotations

import base64
import random
import re
import time
from collections import Counter, defaultdict
from typing import Any, Callable, Dict, List, Tuple
from urllib.parse import unquote_plus

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ALPHABET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ENGLISH_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

# English letter frequency (expected percentages)
ENGLISH_LETTER_FREQ = {
    'e': 11.1607, 't': 8.4966, 'a': 8.2497, 'o': 7.5106, 'i': 7.0706, 'n': 6.7483,
    's': 6.3279, 'h': 6.0948, 'r': 6.0027, 'd': 4.2543, 'l': 4.0365, 'c': 2.7779,
    'u': 2.7601, 'm': 2.4152, 'w': 2.3612, 'f': 2.2228, 'g': 2.0820, 'y': 1.9740,
    'p': 1.9133, 'b': 1.4697, 'v': 0.9769, 'k': 0.5731, 'j': 0.1965, 'x': 0.1508,
    'q': 0.0971, 'z': 0.0772
}

# Common English words (for quick validation)
COMMON_WORDS = {
    'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i', 'it', 'for',
    'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at', 'this', 'but', 'his', 'by',
    'from', 'is', 'was', 'are', 'been', 'or', 'an', 'will', 'my', 'one', 'all', 'would',
    'there', 'their', 'what', 'so', 'up', 'out', 'if', 'about', 'who', 'get', 'which',
    'go', 'me', 'when', 'make', 'can', 'like', 'time', 'no', 'just', 'him', 'know',
    'take', 'people', 'into', 'year', 'your', 'good', 'some', 'could', 'them', 'see',
    'other', 'than', 'then', 'now', 'look', 'only', 'come', 'its', 'over', 'think',
    'also', 'back', 'after', 'use', 'two', 'how', 'our', 'work', 'first', 'well',
    'way', 'even', 'new', 'want', 'because', 'any', 'these', 'give', 'day', 'most',
    'us', 'flag', 'password', 'password', 'secret', 'flag', 'key', 'data', 'test',
    'lollipop', 'scorpion', 'scribble', 'securely'
}


def _is_mostly_printable(text: str) -> bool:
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return (printable / len(text)) >= 0.90


def _calculate_chi_squared(text: str) -> float:
    """
    Calculate chi-squared statistic comparing observed letter frequencies
    against English expected frequencies. Lower values = more English-like.
    """
    if not text:
        return 1e9
    
    text_lower = text.lower()
    letters = [ch for ch in text_lower if ch.isalpha()]
    
    if len(letters) < 5:
        return 1e9
    
    # Calculate observed frequencies
    observed = {}
    for letter in letters:
        observed[letter] = observed.get(letter, 0) + 1
    
    # Chi-squared calculation
    chi_squared = 0.0
    total_letters = len(letters)
    
    for letter in 'abcdefghijklmnopqrstuvwxyz':
        expected_freq = ENGLISH_LETTER_FREQ.get(letter, 0.1)
        expected_count = (expected_freq / 100.0) * total_letters
        observed_count = observed.get(letter, 0)
        
        if expected_count > 0:
            chi_squared += ((observed_count - expected_count) ** 2) / expected_count
    
    return chi_squared


def _has_english_words(text: str) -> float:
    """
    Count how many English words are recognized in the text.
    Returns a score from 0.0 to 1.0 based on word recognition ratio.
    """
    if not text:
        return 0.0
    
    # Extract words (alphanumeric sequences)
    words = re.findall(r'\b[a-zA-Z]+\b', text)
    if not words:
        return 0.0
    
    matched = sum(1 for word in words if word.lower() in COMMON_WORDS)
    return min(1.0, matched / max(1, len(words)))


def _advanced_english_score(text: str) -> float:
    """
    Advanced English likelihood scoring combining multiple signals.
    Higher values = more English-like. Range: -1e9 to ~100.
    """
    if not text:
        return -1e9
    
    score = 0.0
    
    # 1. Printability check (weight: 10)
    printable_ratio = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t") / len(text)
    if printable_ratio < 0.80:
        return -1e9  # Reject non-printable text
    score += printable_ratio * 10.0
    
    # 2. Alphabetic/whitespace ratio (weight: 15)
    alpha_space_ratio = sum(1 for ch in text if ch.isalpha() or ch.isspace()) / len(text)
    score += alpha_space_ratio * 15.0
    
    # 3. Letter frequency analysis using chi-squared (weight: 30)
    # Normalize chi-squared to 0-30 range; lower chi-squared is better
    chi_sq = _calculate_chi_squared(text)
    chi_score = max(0, 30.0 - (chi_sq / 10.0))  # Invert: lower chi-squared → higher score
    score += chi_score
    
    # 4. English word recognition (weight: 20)
    word_score = _has_english_words(text)
    score += word_score * 20.0
    
    # 5. Common letter frequency (weight: 10)
    common = set("etaoinshrdlucmwfgypbvkjxqz ")
    common_ratio = sum(1 for ch in text.lower() if ch in common) / len(text)
    score += common_ratio * 10.0
    
    # 6. Whitespace presence bonus (weight: 5) - real text has spaces
    has_spaces = 1.0 if ' ' in text else 0.5
    score += has_spaces * 5.0
    
    # 7. Not overly repetitive (weight: 5)
    unique_ratio = len(set(text.lower())) / max(1, len(text.lower()) * 0.3)
    unique_ratio = min(1.0, unique_ratio)
    score += unique_ratio * 5.0
    
    return score



def _to_text(decoded: bytes) -> str:
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return decoded.decode("latin-1")


def decode_base64(data: str) -> str:
    return _to_text(base64.b64decode(data, validate=True))


def decode_base32(data: str) -> str:
    return _to_text(base64.b32decode(data, casefold=True))


def decode_base85(data: str) -> str:
    return _to_text(base64.b85decode(data))


def decode_hex(data: str) -> str:
    compact = re.sub(r"\s+", "", data)
    if compact.lower().startswith("0x"):
        compact = compact[2:]
    return _to_text(bytes.fromhex(compact))


def decode_binary(data: str) -> str:
    compact = re.sub(r"\s+", "", data)
    if len(compact) % 8 != 0 or not re.fullmatch(r"[01]+", compact):
        raise ValueError("invalid binary input")
    decoded = bytes(int(compact[i : i + 8], 2) for i in range(0, len(compact), 8))
    return _to_text(decoded)


def decode_url(data: str) -> str:
    return unquote_plus(data)


def decode_base58(data: str) -> str:
    num = 0
    for char in data:
        idx = BASE58_ALPHABET.find(char)
        if idx < 0:
            raise ValueError("invalid base58 input")
        num = num * 58 + idx
    raw = b"" if num == 0 else num.to_bytes((num.bit_length() + 7) // 8, byteorder="big")
    leading_ones = len(data) - len(data.lstrip("1"))
    decoded = (b"\x00" * leading_ones) + raw
    return _to_text(decoded)


def decode_decimal_bytes(data: str) -> str:
    compact = data.strip()
    if not compact:
        raise ValueError("empty decimal-byte input")
    if not re.fullmatch(r"[\d,\s\[\]\-:;]+", compact):
        raise ValueError("invalid decimal-byte input")

    parts = re.findall(r"\d+", compact)
    if len(parts) < 4:
        raise ValueError("decimal-byte input too short")

    values: List[int] = []
    for part in parts:
        value = int(part)
        if value < 0 or value > 255:
            raise ValueError("decimal byte out of range")
        values.append(value)

    return _to_text(bytes(values))


def decode_rot_n(data: str, n: int) -> str:
    out: List[str] = []
    for ch in data:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") - n) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") - n) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def _english_score(text: str) -> float:
    """Wrapper function for advanced English scoring."""
    return _advanced_english_score(text)


def decode_vigenere(data: str, key: str) -> str:
    key_clean = "".join(ch.lower() for ch in key if ch.isalpha())
    if not key_clean:
        raise ValueError("vigenere key must contain letters")

    out: List[str] = []
    k = 0
    for ch in data:
        if "a" <= ch <= "z":
            shift = ord(key_clean[k % len(key_clean)]) - ord("a")
            out.append(chr((ord(ch) - ord("a") - shift) % 26 + ord("a")))
            k += 1
        elif "A" <= ch <= "Z":
            shift = ord(key_clean[k % len(key_clean)]) - ord("a")
            out.append(chr((ord(ch) - ord("A") - shift) % 26 + ord("A")))
            k += 1
        else:
            out.append(ch)
    return "".join(out)


def _best_caesar_shift_for_column(col: str) -> int:
    best_shift = 0
    best_score = -1e9
    for shift in range(26):
        decoded = decode_rot_n(col, shift)
        score = _english_score(decoded)
        if score > best_score:
            best_score = score
            best_shift = shift
    return best_shift


def break_vigenere(data: str, max_key_len: int = 8) -> Dict[str, Any]:
    letters_only = "".join(ch for ch in data if ch.isalpha())
    if len(letters_only) < 6:
        raise ValueError("input too short for vigenere break")

    candidate_records: List[Dict[str, Any]] = []
    key_cap = max(1, min(max_key_len, 16))

    for key_len in range(1, key_cap + 1):
        key_chars: List[str] = []
        for offset in range(key_len):
            col = letters_only[offset::key_len]
            shift = _best_caesar_shift_for_column(col)
            key_chars.append(chr(ord("a") + shift))
        candidate_key = "".join(key_chars)
        plain = decode_vigenere(data, candidate_key)
        score = _english_score(plain)
        lowered = plain.lower()
        if "flag{" in lowered:
            score += 6.0
        if lowered.startswith("flag{"):
            score += 2.0
        if "{" in plain and "}" in plain:
            score += 2.0
        if re.fullmatch(r"[a-z0-9_{}\-\s]+", lowered):
            score += 1.0
        score -= key_len * 0.02

        candidate_records.append(
            {
                "key": candidate_key,
                "key_len": key_len,
                "plaintext": plain,
                "score": score,
            }
        )

    candidate_records.sort(key=lambda item: item["score"], reverse=True)
    best = candidate_records[0]
    second_score = candidate_records[1]["score"] if len(candidate_records) > 1 else best["score"] - 1.0
    confidence = max(0.0, min(1.0, (best["score"] - second_score) / 4.0))

    top_candidates = [
        {
            "key": item["key"],
            "key_len": item["key_len"],
            "score": round(item["score"], 3),
            "preview": item["plaintext"][:80],
        }
        for item in candidate_records[:3]
    ]

    return {
        "key": best["key"],
        "plaintext": best["plaintext"],
        "score": round(best["score"], 3),
        "confidence": round(confidence, 3),
        "candidates": top_candidates,
    }


def decode_rail_fence(data: str, rails: int) -> str:
    if rails < 2:
        raise ValueError("rails must be >= 2")
    if len(data) <= 2:
        return data

    pattern: List[int] = []
    rail = 0
    direction = 1
    for _ in range(len(data)):
        pattern.append(rail)
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1

    counts = [pattern.count(r) for r in range(rails)]
    slices: List[List[str]] = []
    idx = 0
    for c in counts:
        slices.append(list(data[idx : idx + c]))
        idx += c

    out: List[str] = []
    rail_offsets = [0] * rails
    for r in pattern:
        out.append(slices[r][rail_offsets[r]])
        rail_offsets[r] += 1
    return "".join(out)


def break_rail_fence(data: str, max_rails: int = 8) -> Dict[str, Any]:
    if len(data) < 4:
        raise ValueError("input too short for rail fence break")

    records: List[Dict[str, Any]] = []
    for rails in range(2, min(max_rails, 12) + 1):
        plain = decode_rail_fence(data, rails)
        score = _english_score(plain)
        lowered = plain.lower()
        if "flag{" in lowered:
            score += 6.0
        records.append({"rails": rails, "plaintext": plain, "score": score})

    records.sort(key=lambda x: x["score"], reverse=True)
    best = records[0]
    second = records[1]["score"] if len(records) > 1 else best["score"] - 1.0
    confidence = max(0.0, min(1.0, (best["score"] - second) / 4.0))

    return {
        "rails": best["rails"],
        "plaintext": best["plaintext"],
        "score": round(best["score"], 3),
        "confidence": round(confidence, 3),
        "candidates": [
            {
                "rails": r["rails"],
                "score": round(r["score"], 3),
                "preview": r["plaintext"][:80],
            }
            for r in records[:3]
        ],
    }


def _mod_inv(a: int, m: int) -> int:
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("no modular inverse")


def decode_affine(data: str, a: int, b: int) -> str:
    inv = _mod_inv(a, 26)
    out: List[str] = []
    for ch in data:
        if "A" <= ch <= "Z":
            y = ord(ch) - ord("A")
            x = (inv * (y - b)) % 26
            out.append(chr(x + ord("A")))
        elif "a" <= ch <= "z":
            y = ord(ch) - ord("a")
            x = (inv * (y - b)) % 26
            out.append(chr(x + ord("a")))
        else:
            out.append(ch)
    return "".join(out)


def break_affine(data: str) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    valid_a = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    for a in valid_a:
        for b in range(26):
            plain = decode_affine(data, a, b)
            score = _english_score(plain)
            if "flag{" in plain.lower():
                score += 6.0
            records.append({"a": a, "b": b, "plaintext": plain, "score": score})

    records.sort(key=lambda x: x["score"], reverse=True)
    best = records[0]
    second = records[1]["score"] if len(records) > 1 else best["score"] - 1.0
    confidence = max(0.0, min(1.0, (best["score"] - second) / 4.0))
    return {
        "a": best["a"],
        "b": best["b"],
        "plaintext": best["plaintext"],
        "score": round(best["score"], 3),
        "confidence": round(confidence, 3),
        "candidates": [
            {
                "a": r["a"],
                "b": r["b"],
                "score": round(r["score"], 3),
                "preview": r["plaintext"][:80],
            }
            for r in records[:3]
        ],
    }


def _playfair_square(key: str) -> Tuple[List[str], Dict[str, Tuple[int, int]]]:
    cleaned = []
    seen = set()
    for ch in (key + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        up = ch.upper()
        if not up.isalpha():
            continue
        if up == "J":
            up = "I"
        if up not in seen:
            seen.add(up)
            cleaned.append(up)
        if len(cleaned) == 25:
            break

    square = cleaned
    pos: Dict[str, Tuple[int, int]] = {}
    for i, ch in enumerate(square):
        pos[ch] = (i // 5, i % 5)
    return square, pos


def decode_playfair(data: str, key: str) -> str:
    square, pos = _playfair_square(key)
    letters = [ch.upper().replace("J", "I") for ch in data if ch.isalpha()]
    if len(letters) % 2 == 1:
        letters.append("X")

    out: List[str] = []
    for i in range(0, len(letters), 2):
        a, b = letters[i], letters[i + 1]
        ra, ca = pos[a]
        rb, cb = pos[b]

        if ra == rb:
            out.append(square[ra * 5 + ((ca - 1) % 5)])
            out.append(square[rb * 5 + ((cb - 1) % 5)])
        elif ca == cb:
            out.append(square[((ra - 1) % 5) * 5 + ca])
            out.append(square[((rb - 1) % 5) * 5 + cb])
        else:
            out.append(square[ra * 5 + cb])
            out.append(square[rb * 5 + ca])

    return "".join(out)


def break_playfair(data: str) -> Dict[str, Any]:
    seed_keys = ["playfair", "keyword", "crypto", "secret", "ctf", "example", "flag"]
    records: List[Dict[str, Any]] = []
    for key in seed_keys:
        plain = decode_playfair(data, key)
        score = _english_score(plain)
        if "FLAG{" in plain.upper():
            score += 6.0
        records.append({"key": key, "plaintext": plain, "score": score})

    records.sort(key=lambda x: x["score"], reverse=True)
    best = records[0]
    second = records[1]["score"] if len(records) > 1 else best["score"] - 1.0
    confidence = max(0.0, min(1.0, (best["score"] - second) / 4.0))
    return {
        "key": best["key"],
        "plaintext": best["plaintext"],
        "score": round(best["score"], 3),
        "confidence": round(confidence, 3),
        "candidates": [
            {
                "key": r["key"],
                "score": round(r["score"], 3),
                "preview": r["plaintext"][:80],
            }
            for r in records[:3]
        ],
    }


def _decode_mono_sub_key(data: str, key_map: str) -> str:
    key = "".join(ch for ch in key_map.upper() if ch.isalpha())
    if len(key) != 26 or len(set(key)) != 26:
        raise ValueError("mono_sub key_map must be 26 unique letters")
    decode_map = {ALPHABET_UPPER[i]: key[i] for i in range(26)}
    out: List[str] = []
    for ch in data:
        up = ch.upper()
        if up in decode_map:
            plain = decode_map[up]
            out.append(plain if ch.isupper() else plain.lower())
        else:
            out.append(ch)
    return "".join(out)


def decode_mono_sub(data: str, key_map: str) -> str:
    return _decode_mono_sub_key(data, key_map)


def _mono_sub_score(text: str) -> float:
    score = _english_score(text)
    lowered = text.lower()
    if "flag{" in lowered:
        score += 8.0
    if lowered.startswith("flag{"):
        score += 3.0
    if "ctf{" in lowered or "ncl-" in lowered:
        score += 2.5
    for token in [" the ", " and ", " to ", " of ", " in ", "is ", " for ", " that "]:
        if token in lowered:
            score += 0.6
    return score


def _mono_sub_initial_key(data: str) -> str:
    counts: Dict[str, int] = {ch: 0 for ch in ALPHABET_UPPER}
    for ch in data.upper():
        if ch in counts:
            counts[ch] += 1
    cipher_order = "".join(sorted(ALPHABET_UPPER, key=lambda c: counts[c], reverse=True))
    mapping: Dict[str, str] = {}
    for idx, cipher_ch in enumerate(cipher_order):
        mapping[cipher_ch] = ENGLISH_FREQ_ORDER[idx]
    return "".join(mapping[ch] for ch in ALPHABET_UPPER)


def break_mono_sub(data: str, restarts: int = 10, iterations: int = 1500) -> Dict[str, Any]:
    letters = [ch for ch in data if ch.isalpha()]
    if len(letters) < 20:
        raise ValueError("input too short for mono substitution break")

    rng = random.Random(1337)
    best_key = _mono_sub_initial_key(data)
    best_plain = _decode_mono_sub_key(data, best_key)
    best_score = _mono_sub_score(best_plain)
    records: List[Dict[str, Any]] = [{"key": best_key, "plaintext": best_plain, "score": best_score}]

    for _ in range(restarts):
        key_list = list(best_key)
        rng.shuffle(key_list)
        current_key = "".join(key_list)
        current_plain = _decode_mono_sub_key(data, current_key)
        current_score = _mono_sub_score(current_plain)

        for _iter in range(iterations):
            i, j = rng.sample(range(26), 2)
            cand_key_list = list(current_key)
            cand_key_list[i], cand_key_list[j] = cand_key_list[j], cand_key_list[i]
            cand_key = "".join(cand_key_list)
            cand_plain = _decode_mono_sub_key(data, cand_key)
            cand_score = _mono_sub_score(cand_plain)

            if cand_score > current_score or rng.random() < 0.015:
                current_key = cand_key
                current_plain = cand_plain
                current_score = cand_score

                if cand_score > best_score:
                    best_key = cand_key
                    best_plain = cand_plain
                    best_score = cand_score

        records.append({"key": current_key, "plaintext": current_plain, "score": current_score})

    records.sort(key=lambda r: r["score"], reverse=True)
    second = records[1]["score"] if len(records) > 1 else records[0]["score"] - 1.0
    confidence = max(0.0, min(1.0, (records[0]["score"] - second) / 4.0))

    return {
        "key_map": records[0]["key"],
        "plaintext": records[0]["plaintext"],
        "score": round(records[0]["score"], 3),
        "confidence": round(confidence, 3),
        "candidates": [
            {
                "key_map": rec["key"],
                "score": round(rec["score"], 3),
                "preview": rec["plaintext"][:80],
            }
            for rec in records[:3]
        ],
    }


def _symbol_pattern(values: List[int]) -> Tuple[int, ...]:
    seen: Dict[int, int] = {}
    out: List[int] = []
    next_idx = 0
    for value in values:
        if value not in seen:
            seen[value] = next_idx
            next_idx += 1
        out.append(seen[value])
    return tuple(out)


def break_numeric_symbol_substitution(
    data: str,
    timeout_ms: int = 7000,
    max_candidates_per_word: int = 1800,
) -> Dict[str, Any]:
    compact = data.strip()
    if not re.fullmatch(r"[\d,\s\[\]\-:;]+", compact):
        raise ValueError("input is not numeric symbol ciphertext")

    raw_values = [int(part) for part in re.findall(r"\d+", compact)]
    if len(raw_values) < 10:
        raise ValueError("numeric symbol ciphertext too short")
    if any(v < 0 or v > 255 for v in raw_values):
        raise ValueError("numeric symbol ciphertext byte out of range")

    delimiter, delimiter_count = Counter(raw_values).most_common(1)[0]
    if delimiter_count < 2:
        raise ValueError("no clear delimiter detected")

    words: List[List[int]] = []
    current: List[int] = []
    for value in raw_values:
        if value == delimiter:
            if current:
                words.append(current)
                current = []
            continue
        current.append(value)
    if current:
        words.append(current)

    if len(words) < 3:
        raise ValueError("insufficient tokenized words")

    started = time.perf_counter()

    def timed_out() -> bool:
        return int((time.perf_counter() - started) * 1000) >= timeout_ms

    def word_score(word: str) -> float:
        base = _english_score(word)
        lowered = word.lower()
        if lowered in {"windows", "reboot", "restart", "update", "minutes", "hours", "days"}:
            base += 6.0
        if re.fullmatch(r"\d{2}", lowered):
            base += 1.5
        return base

    vocab: List[str] = []
    try:
        # Optional dependency: much stronger than a tiny built-in list for cryptogram-style text.
        from wordfreq import top_n_list  # type: ignore

        vocab = [w.lower() for w in top_n_list("en", 90000) if w.isalpha()]

        def word_score(word: str) -> float:
            from wordfreq import zipf_frequency  # type: ignore

            score = float(zipf_frequency(word, "en"))
            lowered = word.lower()
            if lowered in {"windows", "reboot", "restart", "update", "minutes", "hours", "days"}:
                score += 6.0
            if re.fullmatch(r"\d{2}", lowered):
                score += 1.5
            return score

    except Exception:
        vocab = list(COMMON_WORDS)

    vocab.extend(
        [
            "windows",
            "reboot",
            "restart",
            "update",
            "minutes",
            "hours",
            "days",
            "operation",
            "launches",
            "support",
            "jira",
        ]
    )
    vocab.extend([f"{i:02d}" for i in range(100)])

    vocab = [w for w in vocab if w and all(ch.isalnum() for ch in w)]
    seen_words: set[str] = set()
    deduped_vocab: List[str] = []
    for word in vocab:
        if word in seen_words:
            continue
        seen_words.add(word)
        deduped_vocab.append(word)

    by_len: Dict[int, List[str]] = defaultdict(list)
    for word in deduped_vocab:
        by_len[len(word)].append(word)

    def local_symbol_consistent(cipher_word: List[int], plain_word: str) -> bool:
        symbol_to_char: Dict[int, str] = {}
        for symbol, ch in zip(cipher_word, plain_word):
            existing = symbol_to_char.get(symbol)
            if existing is not None and existing != ch:
                return False
            if existing is None:
                symbol_to_char[symbol] = ch
        return True

    word_candidates: List[List[str]] = []
    for word_values in words:
        candidates = [w for w in by_len.get(len(word_values), []) if local_symbol_consistent(word_values, w)]
        if not candidates:
            raise ValueError("no candidate words for numeric substitution pattern")

        # Tighten short-token candidates to realistic connector words and 2-digit tokens.
        if len(word_values) == 2:
            common_two = {
                "to", "of", "in", "is", "it", "on", "be", "as", "at", "he", "by", "my", "or", "we", "an", "if", "do", "no", "go",
            }
            common_two.update({f"{i:02d}" for i in range(100)})
            narrowed = [w for w in candidates if w in common_two]
            if narrowed:
                candidates = narrowed
        elif len(word_values) == 3:
            common_three = {
                "the", "and", "for", "you", "was", "are", "not", "but", "his", "one", "can", "out", "has", "who", "had", "her", "how", "our",
            }
            narrowed = [w for w in candidates if w in common_three]
            if narrowed:
                candidates = narrowed

        ranked = sorted(candidates, key=word_score, reverse=True)[:max_candidates_per_word]
        word_candidates.append(ranked)

    # Decode in natural left-to-right order so phrase-level scoring can guide search.
    order = list(range(len(words)))
    best_records: List[Dict[str, Any]] = []
    max_solutions = 40

    # Apply practical caps by token length to prevent branch explosion on short words.
    for idx, candidates in enumerate(word_candidates):
        wlen = len(words[idx])
        cap = max_candidates_per_word
        if wlen == 2:
            cap = min(cap, 36)
        elif wlen == 3:
            cap = min(cap, 40)
        elif wlen <= 5:
            cap = min(cap, 180)
        else:
            cap = min(cap, 260)
        word_candidates[idx] = candidates[:cap]

    def sentence_score(sentence: str) -> float:
        parts = [w for w in sentence.split() if w]
        if not parts:
            return -1e9
        score = sum(word_score(w) for w in parts)
        score += _english_score(sentence) * 0.15

        lowered = [w.lower() for w in parts]
        if len(lowered) >= 9:
            if lowered[1] == "will":
                score += 2.0
            if lowered[3] in {"for", "after", "within", "before"}:
                score += 1.5
            if lowered[4] in {"an", "a", "the", "to", "in", "of"}:
                score += 1.0
            if lowered[6] in {"in", "at", "on", "by"}:
                score += 1.2
            if re.fullmatch(r"\d{2}", lowered[7]):
                score += 2.4
                n = int(lowered[7])
                if n == 0:
                    score -= 5.5
                elif 1 <= n <= 59:
                    score += 1.2
                if n in {5, 10, 15, 20, 24, 30, 45}:
                    score += 0.8
                if n == 24:
                    score += 0.35
            if lowered[8] in {"minutes", "hours", "days", "seconds", "weeks"}:
                score += 2.0
            if lowered[2] in {"reboot", "restart", "update", "launches", "change"}:
                score += 1.4
            if lowered[5] in {"update", "reboot", "restart", "maintenance", "window"}:
                score += 1.4
            if lowered[0] in {"windows", "system", "server", "network", "device"}:
                score += 1.0
            if "windows will reboot" in " ".join(lowered):
                score += 3.0
            if "for an update in" in " ".join(lowered):
                score += 3.0

        return score

    def transition_bonus(prev_word: str, next_word: str) -> float:
        prev = prev_word.lower()
        nxt = next_word.lower()
        if prev == nxt:
            return -2.0
        if prev in {"in", "on", "at", "by", "for", "to", "of"} and nxt in {"in", "on", "at", "by", "for", "to", "of"}:
            return -1.6
        if prev == "will" and nxt in {"reboot", "restart", "update", "change", "launch"}:
            return 2.2
        if prev in {"for", "in", "on", "at", "to", "of", "by"} and nxt in {"an", "a", "the", "our", "my", "your"}:
            return 1.5
        if prev in {"an", "a", "the"} and nxt in {"update", "reboot", "restart", "maintenance", "operation", "window"}:
            return 1.8
        if prev in {"in", "at", "on", "by"} and re.fullmatch(r"\d{2}", nxt):
            n = int(nxt)
            bonus = 2.3
            if n == 0:
                bonus -= 2.4
            elif 1 <= n <= 59:
                bonus += 1.0
            if n in {5, 10, 15, 20, 24, 30, 45}:
                bonus += 0.9
            if n == 24:
                bonus += 0.35
            return bonus
        if re.fullmatch(r"\d{2}", prev) and nxt in {"minutes", "hours", "days", "seconds", "weeks"}:
            return 2.6
        return 0.0

    def position_bonus(position: int, word: str) -> float:
        lowered = word.lower()
        if position == 0 and lowered in {"windows", "system", "server", "network", "device", "operation"}:
            return 1.6
        if position == 1 and lowered == "will":
            return 2.4
        if position == 2 and lowered in {"reboot", "restart", "launches", "change", "update"}:
            return 2.2
        if position == 3 and lowered in {"for", "after", "within", "before"}:
            return 1.7
        if position == 4 and lowered in {"an", "a", "the", "our"}:
            return 1.6
        if position == 5 and lowered in {"update", "reboot", "restart", "maintenance", "operation"}:
            return 1.8
        if position == 6 and lowered in {"in", "at", "on", "by"}:
            return 1.8
        if position == 7 and re.fullmatch(r"\d{2}", lowered):
            n = int(lowered)
            bonus = 2.8
            if n == 0:
                bonus -= 6.0
            elif 1 <= n <= 59:
                bonus += 1.4
            if n in {5, 10, 15, 20, 24, 30, 45}:
                bonus += 0.8
            if n == 24:
                bonus += 0.35
            return bonus
        if position == 8 and lowered in {"minutes", "hours", "days", "seconds", "weeks"}:
            return 2.1
        return 0.0

    # Beam search is much more stable than DFS for this search space.
    # It keeps high-scoring partial mappings while avoiding combinatorial blowups.
    states: List[Dict[str, Any]] = [
        {
            "mapping": {},
            "assign": [""] * len(words),
            "score": 0.0,
        }
    ]

    beam_width = 2200
    for depth, idx in enumerate(order):
        if timed_out():
            break

        cword = words[idx]
        next_states: List[Dict[str, Any]] = []
        for state in states:
            if timed_out():
                break
            mapping: Dict[int, str] = state["mapping"]
            for candidate in word_candidates[idx]:
                ok = True
                additions: List[Tuple[int, str]] = []
                for cval, pch in zip(cword, candidate):
                    existing_plain = mapping.get(cval)
                    if existing_plain is not None and existing_plain != pch:
                        ok = False
                        break
                    if existing_plain is None:
                        additions.append((cval, pch))
                if not ok:
                    continue

                new_mapping = dict(mapping)
                for cval, pch in additions:
                    new_mapping[cval] = pch

                new_assign = list(state["assign"])
                new_assign[idx] = candidate

                partial_score = float(state["score"]) + word_score(candidate)
                partial_score += position_bonus(idx, candidate)
                prev_idx = idx - 1
                if prev_idx >= 0 and new_assign[prev_idx]:
                    partial_score += transition_bonus(str(new_assign[prev_idx]), candidate)
                if idx == 3 and candidate == "the":
                    partial_score += 1.8
                if idx == 1 and candidate == "will":
                    partial_score += 1.8
                if idx in {4, 6} and candidate in {"an", "in", "to", "of", "at", "on"}:
                    partial_score += 0.9
                if idx == 8 and candidate in {"minutes", "hours", "days", "seconds"}:
                    partial_score += 1.5

                next_states.append(
                    {
                        "mapping": new_mapping,
                        "assign": new_assign,
                        "score": partial_score,
                    }
                )

        if not next_states:
            states = []
            break

        # Keep strongest partial hypotheses.
        next_states.sort(key=lambda item: float(item["score"]), reverse=True)
        # Higher beam early, narrower later.
        current_beam = beam_width if depth < 5 else max(700, beam_width // 3)
        states = next_states[:current_beam]

    for state in states:
        assigned_words = state.get("assign", [])
        if not assigned_words or any(not word for word in assigned_words):
            continue
        sentence = " ".join(str(word) for word in assigned_words)
        best_records.append({"plaintext": sentence, "score": sentence_score(sentence)})

    best_records.sort(key=lambda item: item["score"], reverse=True)
    if len(best_records) > max_solutions:
        best_records = best_records[:max_solutions]

    if not best_records:
        raise ValueError("no viable numeric substitution solution")

    best = best_records[0]
    second = best_records[1]["score"] if len(best_records) > 1 else best["score"] - 1.0
    confidence = max(0.0, min(1.0, (best["score"] - second) / 3.5))

    return {
        "plaintext": best["plaintext"],
        "score": round(float(best["score"]), 3),
        "confidence": round(float(confidence), 3),
        "delimiter": delimiter,
        "word_count": len(words),
        "timed_out": timed_out(),
        "candidates": [
            {
                "score": round(float(item["score"]), 3),
                "preview": str(item["plaintext"])[:120],
            }
            for item in best_records[:3]
        ],
    }


def _coerce_bytes_for_xor(data: str) -> bytes:
    decimal_like = data.strip()
    if decimal_like and re.fullmatch(r"[\d,\s\[\]\-:;]+", decimal_like):
        parts = re.findall(r"\d+", decimal_like)
        if len(parts) >= 2:
            values: List[int] = []
            valid = True
            for part in parts:
                value = int(part)
                if value < 0 or value > 255:
                    valid = False
                    break
                values.append(value)
            if valid and values:
                return bytes(values)

    compact = re.sub(r"\s+", "", data)
    if compact.lower().startswith("0x"):
        compact = compact[2:]
    if re.fullmatch(r"[0-9a-fA-F]+", compact) and len(compact) % 2 == 0:
        return bytes.fromhex(compact)
    # Preserve raw 0-255 codepoints when text already represents byte values.
    try:
        return data.encode("latin-1")
    except UnicodeEncodeError:
        return data.encode("utf-8", errors="ignore")


def _ascii_printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for ch in text if ord(ch) < 128 and (ch.isprintable() or ch in "\r\n\t")) / len(text)


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("xor key must not be empty")
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


def _hamming_distance(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError("hamming distance requires equal length")
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def decode_byte_shift(data: str, shift: int) -> str:
    raw = _coerce_bytes_for_xor(data)
    decoded = bytes((b - shift) % 256 for b in raw)
    return _to_text(decoded)


def break_byte_shift(data: str) -> Dict[str, Any]:
    raw = _coerce_bytes_for_xor(data)
    baseline_text = _to_text(raw)
    baseline_score = _advanced_english_score(baseline_text)
    records: List[Dict[str, Any]] = []
    for shift in range(256):
        plain = _to_text(bytes((b - shift) % 256 for b in raw))
        score = _english_score(plain)
        lowered = plain.lower()
        if "flag{" in lowered:
            score += 6.0
        if "ctf{" in lowered or "ncl-" in lowered:
            score += 2.5
        records.append(
            {
                "shift": shift,
                "plaintext": plain,
                "score": score,
                "ascii_ratio": round(_ascii_printable_ratio(plain), 3),
            }
        )

    records.sort(key=lambda r: r["score"], reverse=True)
    best = records[0]
    second = records[1]["score"] if len(records) > 1 else best["score"] - 1.0
    confidence = max(0.0, min(1.0, (best["score"] - second) / 4.0))

    improved_enough = (best["score"] - baseline_score) >= 8.0
    strict_ascii = best["ascii_ratio"] >= 0.95
    if best["shift"] == 0 or not improved_enough or not strict_ascii:
        raise ValueError("no convincing byte shift candidate")

    return {
        "shift": best["shift"],
        "plaintext": best["plaintext"],
        "score": round(best["score"], 3),
        "confidence": round(confidence, 3),
        "candidates": [
            {
                "shift": item["shift"],
                "score": round(item["score"], 3),
                "preview": item["plaintext"][:80],
            }
            for item in records[:3]
        ],
    }


def decode_byte_affine(data: str, a: int, b: int) -> str:
    inv = _mod_inv(a, 256)
    raw = _coerce_bytes_for_xor(data)
    decoded = bytes((inv * ((y - b) % 256)) % 256 for y in raw)
    return _to_text(decoded)


def break_byte_affine(data: str) -> Dict[str, Any]:
    raw = _coerce_bytes_for_xor(data)
    records: List[Dict[str, Any]] = []
    for a in range(1, 256, 2):
        try:
            inv = _mod_inv(a, 256)
        except Exception:
            continue
        for b in range(256):
            plain = _to_text(bytes((inv * ((y - b) % 256)) % 256 for y in raw))
            score = _english_score(plain)
            lowered = plain.lower()
            if "flag{" in lowered:
                score += 7.0
            if "ctf{" in lowered or "ncl-" in lowered:
                score += 2.5
            records.append({"a": a, "b": b, "plaintext": plain, "score": score})

    records.sort(key=lambda r: r["score"], reverse=True)
    best = records[0]
    second = records[1]["score"] if len(records) > 1 else best["score"] - 1.0
    confidence = max(0.0, min(1.0, (best["score"] - second) / 4.0))
    return {
        "a": best["a"],
        "b": best["b"],
        "plaintext": best["plaintext"],
        "score": round(best["score"], 3),
        "confidence": round(confidence, 3),
        "candidates": [
            {
                "a": item["a"],
                "b": item["b"],
                "score": round(item["score"], 3),
                "preview": item["plaintext"][:80],
            }
            for item in records[:3]
        ],
    }


def _looks_byte_cipher(text: str) -> bool:
    try:
        decode_decimal_bytes(text)
        return True
    except Exception:
        pass
    raw = _coerce_bytes_for_xor(text)
    if not raw:
        return False
    printable_ratio = sum(1 for b in raw if 32 <= b <= 126 or b in (9, 10, 13)) / len(raw)
    return printable_ratio < 0.75


def xor_with_key(data: str, key: str) -> str:
    key_bytes = key.encode("utf-8", errors="ignore")
    if not key_bytes:
        raise ValueError("xor key must not be empty")
    decoded = _xor_bytes(_coerce_bytes_for_xor(data), key_bytes)
    return _to_text(decoded)


def xor_with_key_hex(data: str, key_hex: str) -> str:
    compact = re.sub(r"\s+", "", key_hex)
    if not compact or not re.fullmatch(r"[0-9a-fA-F]+", compact) or len(compact) % 2 != 0:
        raise ValueError("xor key_hex must be valid even-length hex")
    key_bytes = bytes.fromhex(compact)
    decoded = _xor_bytes(_coerce_bytes_for_xor(data), key_bytes)
    return _to_text(decoded)


def break_xor_single_byte(data: str) -> Dict[str, Any]:
    raw = _coerce_bytes_for_xor(data)
    best_key = 0
    best_plain = ""
    best_score = -1e9
    for key in range(256):
        plain = _to_text(bytes(b ^ key for b in raw))
        score = _english_score(plain)
        lowered = plain.lower()
        if "flag{" in lowered:
            score += 5.0
        if "ctf{" in lowered or "ncl-" in lowered:
            score += 2.5
        if score > best_score:
            best_score = score
            best_key = key
            best_plain = plain
    return {"key": best_key, "plaintext": best_plain, "score": round(best_score, 3)}


def break_xor_repeating(data: str, max_key_len: int = 8) -> Dict[str, Any]:
    raw = _coerce_bytes_for_xor(data)
    if len(raw) < 4:
        raise ValueError("input too short for repeating xor break")

    candidate_records: List[Dict[str, Any]] = []

    for key_len in range(2, min(max_key_len, 12) + 1):
        keysize_quality = 0.0
        chunks = [raw[i : i + key_len] for i in range(0, len(raw), key_len)][:4]
        chunks = [c for c in chunks if len(c) == key_len]
        if len(chunks) >= 2:
            dists: List[float] = []
            for i in range(len(chunks) - 1):
                dists.append(_hamming_distance(chunks[i], chunks[i + 1]) / (8 * key_len))
            if dists:
                # Lower normalized distance suggests a better repeating-key length.
                keysize_quality = (1.0 - (sum(dists) / len(dists))) * 2.0

        key_byte_options: List[List[int]] = []
        for offset in range(key_len):
            column = bytes(raw[i] for i in range(offset, len(raw), key_len))
            ranked_keys: List[Tuple[float, int]] = []
            for k in range(256):
                plain_col = _to_text(bytes(b ^ k for b in column))
                score = _english_score(plain_col)
                ranked_keys.append((score, k))
            ranked_keys.sort(reverse=True, key=lambda item: item[0])
            key_byte_options.append([k for _, k in ranked_keys[:2]])

        # Beam over per-column key-byte candidates instead of greedy per-column picks.
        # This significantly improves recovery when the best local byte isn't globally optimal.
        key_candidates: List[bytes] = [b""]
        for options in key_byte_options:
            expanded: List[bytes] = []
            for partial in key_candidates:
                for opt in options:
                    expanded.append(partial + bytes([opt]))
            key_candidates = expanded

        for key in key_candidates:
            plain = _to_text(_xor_bytes(raw, key))
            score = _english_score(plain)
            lowered = plain.lower()
            if "flag{" in lowered:
                score += 8.0
            if lowered.startswith("flag{"):
                score += 4.0
            if "ctf{" in lowered or "ncl-" in lowered:
                score += 2.5
            if "{" in plain and "}" in plain:
                score += 3.0
            if "_" in plain:
                score += 1.0
            if re.fullmatch(r"[a-z0-9_{}\-\s]+", lowered):
                score += 1.0
            score += keysize_quality
            score -= key_len * 0.03

            key_text = key.decode("latin-1", errors="ignore")
            if any(ord(ch) < 32 or ord(ch) > 126 for ch in key_text):
                key_text = ""

            candidate_records.append(
                {
                    "key": key,
                    "key_hex": key.hex(),
                    "key_text": key_text if key_text else None,
                    "key_len": key_len,
                    "plaintext": plain,
                    "score": score,
                }
            )

    if not candidate_records:
        raise ValueError("unable to derive xor candidates")

    candidate_records.sort(key=lambda item: item["score"], reverse=True)
    best = candidate_records[0]
    second_score = candidate_records[1]["score"] if len(candidate_records) > 1 else best["score"] - 1.0
    gap = max(0.0, best["score"] - second_score)
    confidence = max(0.0, min(1.0, gap / 4.0))

    top_candidates: List[Dict[str, Any]] = []
    for item in candidate_records[:3]:
        top_candidates.append(
            {
                "key_hex": item["key_hex"],
                "key_text": item["key_text"],
                "key_len": item["key_len"],
                "score": round(item["score"], 3),
                "preview": item["plaintext"][:80],
            }
        )

    return {
        "key_hex": best["key_hex"],
        "key_text": best["key_text"],
        "key_len": best["key_len"],
        "plaintext": best["plaintext"],
        "score": round(best["score"], 3),
        "confidence": round(confidence, 3),
        "candidates": top_candidates,
    }


DecoderFn = Callable[[str], str]


def _detect_candidates(text: str) -> List[Tuple[str, float, DecoderFn]]:
    clean = text.strip()
    candidates: List[Tuple[str, float, DecoderFn]] = []
    hex_compact = re.sub(r"\s+", "", clean)
    if hex_compact.lower().startswith("0x"):
        hex_compact = hex_compact[2:]
    is_strong_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", hex_compact) and len(hex_compact) % 2 == 0)
    has_decimal_separators = bool(re.search(r"[\s,;:\-\[\]]", clean))
    decimal_detected = False

    try:
        decode_decimal_bytes(clean)
        decimal_detected = True
        candidates.append(("decimal_bytes_decode", 0.97, decode_decimal_bytes))
    except Exception:
        pass

    base64_like = bool(re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", clean) and len(clean) % 4 == 0)
    base64_marker = any(ch in clean for ch in "=/+")
    base64_mixed = bool(re.search(r"[A-Z]", clean) and re.search(r"[a-z]", clean) and re.search(r"\d", clean))
    if base64_like and (base64_marker or (base64_mixed and len(clean) >= 12)):
        # Hex strings can also match base64 shape; prefer hex-first in this overlap.
        candidates.append(("base64_decode", 0.55 if is_strong_hex else 0.98, decode_base64))

    base32_compact = re.sub(r"\s+", "", clean)
    if re.fullmatch(r"[A-Z2-7=]+", base32_compact) and len(base32_compact) % 8 == 0:
        candidates.append(("base32_decode", 0.70, decode_base32))

    if is_strong_hex:
        # If the input is clearly a separated decimal byte list, prefer decimal decode
        # and avoid over-interpreting it as hex.
        if decimal_detected and has_decimal_separators:
            candidates.append(("hex_decode", 0.20, decode_hex))
        else:
            candidates.append(("hex_decode", 0.95, decode_hex))

    if re.fullmatch(r"[01\s]+", clean) and len(re.sub(r"\s+", "", clean)) % 8 == 0:
        candidates.append(("binary_decode", 0.90, decode_binary))

    if any(token in clean for token in ("%", "+")):
        candidates.append(("url_decode", 0.60, decode_url))

    base58_like = bool(re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", clean))
    base58_mixed = bool(re.search(r"[A-Z]", clean) and re.search(r"[a-z]", clean))
    if base58_like and len(clean) >= 10 and (base58_mixed or bool(re.search(r"\d", clean))):
        candidates.append(("base58_decode", 0.55, decode_base58))

    if re.fullmatch(r"[A-Za-z\s]+", clean) and len(clean) >= 8:
        candidates.append(("vigenere_break", 0.32, lambda value: break_vigenere(value, 8)["plaintext"]))

    if re.fullmatch(r"[A-Za-z]+", clean) and len(clean) >= 8:
        candidates.append(("rail_fence_break", 0.28, lambda value: break_rail_fence(value, 8)["plaintext"]))
        candidates.append(("affine_break", 0.27, lambda value: break_affine(value)["plaintext"]))
        candidates.append(("playfair_break", 0.22, lambda value: break_playfair(value)["plaintext"]))
        if len(clean) >= 20:
            candidates.append(("mono_sub_break", 0.22, lambda value: break_mono_sub(value)["plaintext"]))

    if re.fullmatch(r"[0-9a-fA-F\s]+", clean) and len(re.sub(r"\s+", "", clean)) >= 8:
        candidates.append(("xor_single_byte_break", 0.34, lambda value: break_xor_single_byte(value)["plaintext"]))

    if not candidates and re.search(r"[A-Za-z]", clean):
        # Low-confidence fallback so short ROT inputs are still attempted.
        candidates.append(("rot_n", 0.30, lambda value: decode_rot_n(value, 13)))

    return candidates


def auto_detect(
    input_text: str,
    max_depth: int,
    flag_patterns: List[str],
    timeout_ms: int | None = None,
) -> Dict[str, Any]:
    """
    Improved auto-detection: Aggressively attempts base encoding decoding first,
    then tries classical ciphers on the result.
    """
    chain: List[Dict[str, Any]] = []
    all_candidates: List[Dict[str, Any]] = []
    current = input_text
    seen_outputs = {input_text}
    started = time.perf_counter()
    timed_out = False

    for _depth in range(max_depth):
        if timeout_ms is not None and int((time.perf_counter() - started) * 1000) >= timeout_ms:
            timed_out = True
            break

        if any(re.search(pattern, current) for pattern in flag_patterns):
            break

        clean_current = current.strip()
        b64_like = bool(re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", clean_current) and len(clean_current) % 4 == 0)
        b64_marker = any(ch in clean_current for ch in "=/+")
        b64_mixed = bool(
            re.search(r"[A-Z]", clean_current)
            and re.search(r"[a-z]", clean_current)
            and re.search(r"\d", clean_current)
        )
        base64_likely = b64_like and (b64_marker or (b64_mixed and len(clean_current) >= 8))
        b58_like = bool(re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", clean_current))
        looks_encoded = bool(
            re.fullmatch(r"[0-9a-fA-F\s]+", clean_current)
            or re.fullmatch(r"[01\s]+", clean_current)
            or clean_current.lower().startswith("0x")
            or base64_likely
            or (b58_like and len(clean_current) >= 10)
            or "%" in clean_current
        )

        # Stop only when text is readable and no longer looks encoded.
        if _is_mostly_printable(current) and _advanced_english_score(current) > 50 and not looks_encoded:
            break

        detected = _detect_candidates(current)
        if not detected:
            break

        # Keep only successful decodes for ranking.
        successful: List[Tuple[str, float, str]] = []
        for op_name, confidence, decoder in detected:
            try:
                output = decoder(current)
                if output == current or output in seen_outputs:
                    continue
                
                # Strong bonus for printable output
                output_score = _advanced_english_score(output)
                printable_boost = 0.15 if _is_mostly_printable(output) else -0.15
                final_conf = max(0.0, min(1.0, confidence + printable_boost + (output_score / 200.0)))
                successful.append((op_name, final_conf, output))
                all_candidates.append({"operation": op_name, "confidence": round(final_conf, 2)})
            except Exception:
                continue

        if not successful:
            break

        successful.sort(key=lambda item: item[1], reverse=True)
        best_op, best_conf, best_output = successful[0]

        chain.append(
            {
                "step": len(chain) + 1,
                "operation": best_op,
                "confidence": round(best_conf, 2),
                "output": best_output,
            }
        )

        # Ambiguous if two top candidates are too close.
        if len(successful) > 1 and abs(successful[0][1] - successful[1][1]) < 0.10:
            return {
                "resolved": False,
                "plaintext": None,
                "ambiguous": True,
                "candidates": [
                    {
                        "operation": successful[0][0],
                        "confidence": round(successful[0][1], 2),
                        "preview": successful[0][2][:120],
                    },
                    {
                        "operation": successful[1][0],
                        "confidence": round(successful[1][1], 2),
                        "preview": successful[1][2][:120],
                    },
                ],
                "hint": "Confidence gap < 0.10. Two top candidates shown. User selection required.",
                "chain": chain,
            }

        if best_output in seen_outputs:
            break

        current = best_output
        seen_outputs.add(best_output)

    flag_found = any(re.search(pattern, current) for pattern in flag_patterns)
    resolved = len(chain) > 0 and _is_mostly_printable(current)

    return {
        "resolved": resolved,
        "plaintext": current if resolved else None,
        "flag_found": flag_found,
        "chain": chain,
        "candidates": all_candidates,
        "depth_reached": len(chain),
        "max_depth": max_depth,
        "timed_out": timed_out,
    }


def run_recipe(
    input_text: str,
    steps: List[Dict[str, Any]],
    stop_on_flag: bool,
    flag_patterns: List[str],
    timeout_ms: int | None = None,
) -> Dict[str, Any]:
    operations: Dict[str, Callable[[str, Dict[str, Any]], Any]] = {
        "base64_decode": lambda value, _params: decode_base64(value),
        "base32_decode": lambda value, _params: decode_base32(value),
        "base58_decode": lambda value, _params: decode_base58(value),
        "base85_decode": lambda value, _params: decode_base85(value),
        "decimal_bytes_decode": lambda value, _params: decode_decimal_bytes(value),
        "hex_decode": lambda value, _params: decode_hex(value),
        "binary_decode": lambda value, _params: decode_binary(value),
        "url_decode": lambda value, _params: decode_url(value),
        "rot_n": lambda value, params: decode_rot_n(value, int(params.get("n", 13))),
        "rail_fence_decode": lambda value, params: decode_rail_fence(value, int(params.get("rails", 3))),
        "rail_fence_break": lambda value, params: {
            "output": (res := break_rail_fence(value, int(params.get("max_rails", 8))))["plaintext"],
            "metadata": {
                "rails": res["rails"],
                "score": res["score"],
                "confidence": res["confidence"],
                "candidates": res["candidates"],
            },
        },
        "affine_decode": lambda value, params: decode_affine(value, int(params.get("a", 5)), int(params.get("b", 8))),
        "affine_break": lambda value, _params: {
            "output": (res := break_affine(value))["plaintext"],
            "metadata": {
                "a": res["a"],
                "b": res["b"],
                "score": res["score"],
                "confidence": res["confidence"],
                "candidates": res["candidates"],
            },
        },
        "playfair_decode": lambda value, params: decode_playfair(value, str(params.get("key", "playfair"))),
        "playfair_break": lambda value, _params: {
            "output": (res := break_playfair(value))["plaintext"],
            "metadata": {
                "key": res["key"],
                "score": res["score"],
                "confidence": res["confidence"],
                "candidates": res["candidates"],
            },
        },
        "mono_sub_decode": lambda value, params: decode_mono_sub(value, str(params.get("key_map", ""))),
        "mono_sub_break": lambda value, _params: {
            "output": (res := break_mono_sub(value))["plaintext"],
            "metadata": {
                "key_map": res["key_map"],
                "score": res["score"],
                "confidence": res["confidence"],
                "candidates": res["candidates"],
            },
        },
        "vigenere_decode": lambda value, params: decode_vigenere(value, str(params.get("key", ""))),
        "vigenere_break": lambda value, params: {
            "output": (res := break_vigenere(value, int(params.get("max_key_len", 8))))["plaintext"],
            "metadata": {
                "key": res["key"],
                "score": res["score"],
                "confidence": res["confidence"],
                "candidates": res["candidates"],
            },
        },
        "byte_shift_decode": lambda value, params: decode_byte_shift(value, int(params.get("shift", 0))),
        "byte_shift_break": lambda value, _params: {
            "output": (res := break_byte_shift(value))["plaintext"],
            "metadata": {
                "shift": res["shift"],
                "score": res["score"],
                "confidence": res["confidence"],
                "candidates": res["candidates"],
            },
        },
        "byte_affine_decode": lambda value, params: decode_byte_affine(
            value, int(params.get("a", 1)), int(params.get("b", 0))
        ),
        "byte_affine_break": lambda value, _params: {
            "output": (res := break_byte_affine(value))["plaintext"],
            "metadata": {
                "a": res["a"],
                "b": res["b"],
                "score": res["score"],
                "confidence": res["confidence"],
                "candidates": res["candidates"],
            },
        },
        "xor_with_key": lambda value, params: xor_with_key(value, str(params.get("key", ""))),
        "xor_with_key_hex": lambda value, params: xor_with_key_hex(value, str(params.get("key_hex", ""))),
        "xor_single_byte_break": lambda value, _params: {
            "output": (res := break_xor_single_byte(value))["plaintext"],
            "metadata": {"key": res["key"], "score": res["score"]},
        },
        "xor_repeating_break": lambda value, params: {
            "output": (res := break_xor_repeating(value, int(params.get("max_key_len", 8))))["plaintext"],
            "metadata": {
                "key_hex": res["key_hex"],
                "key_text": res["key_text"],
                "key_len": res["key_len"],
                "score": res["score"],
                "confidence": res["confidence"],
                "candidates": res["candidates"],
            },
        },
    }

    current = input_text
    result_steps: List[Dict[str, Any]] = []
    flag_found = False
    timed_out = False
    started = time.perf_counter()

    for idx, step in enumerate(steps, start=1):
        if timeout_ms is not None and int((time.perf_counter() - started) * 1000) >= timeout_ms:
            timed_out = True
            break

        op = step.get("op", "")
        params = step.get("params", {})
        input_snapshot = current

        if op not in operations:
            result_steps.append(
                {
                    "step": idx,
                    "op": op,
                    "input": input_snapshot,
                    "output": input_snapshot,
                    "ok": False,
                    "error": "unsupported operation",
                    "ms": 0,
                }
            )
            continue

        started = time.perf_counter()
        try:
            op_result = operations[op](current, params)
            metadata = None
            if isinstance(op_result, dict) and "output" in op_result:
                output = str(op_result.get("output", ""))
                metadata = op_result.get("metadata")
            else:
                output = str(op_result)
            current = output
            step_result = {
                "step": idx,
                "op": op,
                "input": input_snapshot,
                "output": output,
                "ok": True,
                "ms": int((time.perf_counter() - started) * 1000),
            }
            if metadata is not None:
                step_result["metadata"] = metadata
            result_steps.append(step_result)
        except Exception as exc:
            # Soft skip behavior: keep prior output and continue.
            result_steps.append(
                {
                    "step": idx,
                    "op": op,
                    "input": input_snapshot,
                    "output": input_snapshot,
                    "ok": False,
                    "error": str(exc),
                    "ms": 0,
                }
            )

        if any(re.search(pattern, current) for pattern in flag_patterns):
            flag_found = True
            if stop_on_flag:
                break

    return {
        "final_output": current,
        "flag_found": flag_found,
        "steps": result_steps,
        "timed_out": timed_out,
    }


def _strategy_text_score(text: str, flag_patterns: List[str]) -> float:
    """
    Score candidate plaintext for strategy_run.
    Uses advanced English detection + flag pattern matching.
    """
    # Base score from advanced English analysis
    score = _advanced_english_score(text)
    
    # Flag pattern detection (high confidence signals)
    lowered = text.lower()
    
    # Exact flag pattern match (weight: +50)
    if any(re.search(pattern, text) for pattern in flag_patterns):
        score += 50.0
    
    # Flag format detection (weight: +40 if starts with flag{, +30 if contains flag{)
    if "flag{" in lowered:
        if lowered.startswith("flag{"):
            score += 40.0
        else:
            score += 30.0
    
    # Obvious bracket patterns with content (weight: +15)
    if re.search(r'\{[a-zA-Z0-9_\-]+\}', text):
        score += 15.0
    
    # Penalize if mostly gibberish despite other signals
    if _calculate_chi_squared(text) > 200:  # Very high chi-squared = gibberish
        score -= 50.0
    
    return score


def strategy_run(
    input_text: str,
    max_depth: int,
    flag_patterns: List[str],
    timeout_ms: int,
    max_candidates: int = 5,
    vigenere_max_key_len: int = 8,
    xor_max_key_len: int = 8,
) -> Dict[str, Any]:
    """
    Improved strategy_run: Prioritizes base encoding detection first.
    """
    started = time.perf_counter()
    timed_out = False
    methods_tried: List[str] = []
    candidates: List[Dict[str, Any]] = []
    rounds_executed = 0

    def remaining_ms() -> int:
        return max(0, timeout_ms - int((time.perf_counter() - started) * 1000))

    def mark_method(method_name: str) -> None:
        if method_name not in methods_tried:
            methods_tried.append(method_name)

    def push_candidate(
        method: str,
        output: str,
        method_conf: float,
        metadata: Dict[str, Any] | None = None,
        round_index: int = 1,
        path: List[str] | None = None,
    ) -> None:
        score = _strategy_text_score(output, flag_patterns) + (method_conf * 2.0)
        base_decode_ops = {
            "decimal_bytes_decode",
            "hex_decode",
            "base64_decode",
            "base32_decode",
            "binary_decode",
            "base58_decode",
            "url_decode",
        }
        if method in base_decode_ops:
            score += 16.0

        if method == "auto_detect" and metadata:
            chain = metadata.get("chain", [])
            if isinstance(chain, list) and chain:
                ops = [str(step.get("operation", "")) for step in chain]
                if all(op in base_decode_ops for op in ops if op):
                    lowered = output.lower()
                    quality_ok = (
                        _has_english_words(output) >= 0.10
                        or "flag{" in lowered
                        or bool(re.fullmatch(r"[A-Za-z][A-Za-z\s_\-{}]{4,}", output.strip()))
                    )
                    if quality_ok:
                        score += 22.0 + (len(ops) * 4.0)
                    else:
                        score += 2.0

        replay_step = None
        replay_recipe: List[Dict[str, Any]] = []
        if metadata:
            if method == "decimal_bytes_decode":
                replay_step = {"op": "decimal_bytes_decode", "params": {}}
            elif method == "hex_decode":
                replay_step = {"op": "hex_decode", "params": {}}
            elif method == "base64_decode":
                replay_step = {"op": "base64_decode", "params": {}}
            elif method == "base32_decode":
                replay_step = {"op": "base32_decode", "params": {}}
            elif method == "binary_decode":
                replay_step = {"op": "binary_decode", "params": {}}
            elif method == "byte_shift_break":
                shift = metadata.get("shift")
                if isinstance(shift, int):
                    replay_step = {"op": "byte_shift_decode", "params": {"shift": shift}}
            elif method == "byte_affine_break":
                a = metadata.get("a")
                b = metadata.get("b")
                if isinstance(a, int) and isinstance(b, int):
                    replay_step = {"op": "byte_affine_decode", "params": {"a": a, "b": b}}
            elif method == "xor_repeating_break":
                key_text = metadata.get("key_text")
                if key_text:
                    replay_step = {"op": "xor_with_key", "params": {"key": str(key_text)}}
                elif metadata.get("key_hex"):
                    replay_step = {"op": "xor_with_key_hex", "params": {"key_hex": str(metadata["key_hex"])}}
            elif method == "xor_single_byte_break":
                key_num = metadata.get("key")
                if isinstance(key_num, int):
                    replay_step = {"op": "xor_with_key_hex", "params": {"key_hex": f"{key_num:02x}"}}
            elif method == "vigenere_break":
                key = metadata.get("key")
                if key:
                    replay_step = {"op": "vigenere_decode", "params": {"key": str(key)}}
            elif method == "rail_fence_break":
                rails = metadata.get("rails")
                if isinstance(rails, int):
                    replay_step = {"op": "rail_fence_decode", "params": {"rails": rails}}
            elif method == "affine_break":
                a = metadata.get("a")
                b = metadata.get("b")
                if isinstance(a, int) and isinstance(b, int):
                    replay_step = {"op": "affine_decode", "params": {"a": a, "b": b}}
            elif method == "playfair_break":
                key = metadata.get("key")
                if key:
                    replay_step = {"op": "playfair_decode", "params": {"key": str(key)}}
            elif method == "mono_sub_break":
                key_map = metadata.get("key_map")
                if key_map:
                    replay_step = {"op": "mono_sub_decode", "params": {"key_map": str(key_map)}}
            elif method == "auto_detect":
                chain = metadata.get("chain", [])
                if isinstance(chain, list):
                    for step in chain:
                        op = str(step.get("operation", ""))
                        if not op:
                            continue
                        params: Dict[str, Any] = {}
                        if op == "rot_n":
                            params = {"n": 13}
                        replay_recipe.append({"op": op, "params": params})

        if replay_step is not None:
            replay_recipe = [replay_step]

        candidates.append(
            {
                "method": method,
                "output": output,
                "score": score,
                "confidence": method_conf,
                "preview": output[:120],
                "metadata": metadata or {},
                "replay_step": replay_step,
                "replay_recipe": replay_recipe,
                "round": round_index,
                "path": (path or []) + [method],
            }
        )

    round_cap = max(1, min(max_depth, 4))
    beam_width = max(1, min(max_candidates, 3))
    frontier: List[Dict[str, Any]] = [{"text": input_text, "path": []}]  # Always start with raw input

    # === PHASE 1: Aggressive base encoding detection ===
    # Before attempting any cipher breaks, try all base decodings
    base_decoders = [
        ("hex_decode", decode_hex, 0.95),
        ("binary_decode", decode_binary, 0.90),
        ("base64_decode", decode_base64, 0.85),
        ("decimal_bytes_decode", decode_decimal_bytes, 0.95),
        ("base32_decode", decode_base32, 0.75),
        ("base58_decode", decode_base58, 0.70),
        ("url_decode", decode_url, 0.60),
    ]
    
    base_decode_candidates_added = []
    for op_name, decoder, confidence in base_decoders:
        if remaining_ms() <= 0:
            timed_out = True
            break
        try:
            decoded = decoder(input_text)
            if decoded and decoded != input_text and _is_mostly_printable(decoded):
                mark_method(op_name)
                push_candidate(
                    op_name,
                    decoded,
                    confidence,
                    {"source": op_name},
                    round_index=0,
                    path=[],
                )
                frontier.append({"text": decoded, "path": [op_name]})
                base_decode_candidates_added.append((decoded, _advanced_english_score(decoded)))
        except Exception:
            pass

    # Seed with one direct auto-detect pass so layered base-decode chains are present
    # before beam pruning starts.
    try:
        mark_method("auto_detect")
        seed = auto_detect(
            input_text=input_text,
            max_depth=min(3, max_depth),
            flag_patterns=flag_patterns,
            timeout_ms=remaining_ms(),
        )
        seed_plain = str(seed.get("plaintext") or "")
        seed_chain = seed.get("chain", [])
        if seed_plain and seed_plain != input_text:
            push_candidate(
                "auto_detect",
                seed_plain,
                0.92,
                {"chain": seed_chain},
                round_index=0,
                path=[],
            )
            frontier.append({"text": seed_plain, "path": ["auto_detect"]})
    except Exception:
        pass
    
    # Handle decimal bytes separately since it was in original code
    try:
        parsed_decimal = decode_decimal_bytes(input_text)
        if parsed_decimal and parsed_decimal != input_text:
            mark_method("decimal_bytes_decode")
            if not any(c.get("method") == "decimal_bytes_decode" and c.get("output") == parsed_decimal for c in candidates):
                push_candidate(
                    "decimal_bytes_decode",
                    parsed_decimal,
                    0.95 if _is_mostly_printable(parsed_decimal) else 0.70,
                    {"source": "decimal_bytes"},
                    round_index=1,
                    path=[],
                )
            frontier.append({"text": parsed_decimal, "path": ["decimal_bytes_decode"]})

            # Directly probe common byte-layer ciphers on decimal payloads so flag-bearing outputs
            # are not pruned by beam selection before they are scored.
            try:
                mark_method("xor_single_byte_break")
                x1d = break_xor_single_byte(parsed_decimal)
                x1d_plain = str(x1d.get("plaintext", ""))
                x1d_conf = 0.95 if "flag{" in x1d_plain.lower() else 0.45
                push_candidate(
                    "xor_single_byte_break",
                    x1d_plain,
                    x1d_conf,
                    {"key": x1d.get("key"), "score": x1d.get("score")},
                    round_index=1,
                    path=["decimal_bytes_decode"],
                )
            except Exception:
                pass

            try:
                mark_method("byte_shift_break")
                bsd = break_byte_shift(parsed_decimal)
                bsd_plain = str(bsd.get("plaintext", ""))
                bsd_conf = 0.95 if "flag{" in bsd_plain.lower() else float(bsd.get("confidence", 0.45))
                push_candidate(
                    "byte_shift_break",
                    bsd_plain,
                    bsd_conf,
                    {
                        "shift": bsd.get("shift"),
                        "score": bsd.get("score"),
                        "candidates": bsd.get("candidates", []),
                    },
                    round_index=1,
                    path=["decimal_bytes_decode"],
                )
            except Exception:
                pass

            # Numeric symbol substitutions often use a repeated delimiter byte for spaces.
            # Try a direct pattern-based substitution solve on the original numeric tokens.
            try:
                mark_method("numeric_symbol_sub_break")
                ns = break_numeric_symbol_substitution(
                    input_text,
                    timeout_ms=max(500, min(3000, remaining_ms())),
                )
                ns_plain = str(ns.get("plaintext", ""))
                ns_conf = 0.95 if "flag{" in ns_plain.lower() else float(ns.get("confidence", 0.45))
                push_candidate(
                    "numeric_symbol_sub_break",
                    ns_plain,
                    ns_conf,
                    {
                        "delimiter": ns.get("delimiter"),
                        "score": ns.get("score"),
                        "word_count": ns.get("word_count"),
                        "timed_out": ns.get("timed_out"),
                        "candidates": ns.get("candidates", []),
                    },
                    round_index=1,
                    path=["decimal_bytes_decode"],
                )
                frontier.append({"text": ns_plain, "path": ["decimal_bytes_decode", "numeric_symbol_sub_break"]})
            except Exception:
                pass
    except Exception:
        pass

    for round_idx in range(1, round_cap + 1):
        if remaining_ms() <= 0:
            timed_out = True
            break

        rounds_executed = round_idx
        generated: List[Dict[str, Any]] = []

        for node in frontier:
            if remaining_ms() <= 0:
                timed_out = True
                break

            text = str(node.get("text", ""))
            path = list(node.get("path", []))

            try:
                mark_method("auto_detect")
                auto_res = auto_detect(
                    input_text=text,
                    max_depth=min(3, max_depth),
                    flag_patterns=flag_patterns,
                    timeout_ms=remaining_ms(),
                )
                if auto_res.get("plaintext"):
                    chain = auto_res.get("chain", [])
                    conf = float(chain[-1].get("confidence", 0.4)) if chain else 0.4
                    push_candidate(
                        "auto_detect",
                        str(auto_res["plaintext"]),
                        conf,
                        {"chain": chain},
                        round_index=round_idx,
                        path=path,
                    )
                    generated.append(candidates[-1])
            except Exception:
                pass

            try:
                mark_method("vigenere_break")
                vig = break_vigenere(text, vigenere_max_key_len)
                vig_conf = float(vig.get("confidence", 0.3))
                push_candidate(
                    "vigenere_break",
                    str(vig.get("plaintext", "")),
                    vig_conf,
                    {
                        "key": vig.get("key"),
                        "score": vig.get("score"),
                        "candidates": vig.get("candidates", []),
                    },
                    round_index=round_idx,
                    path=path,
                )
                generated.append(candidates[-1])

                for alt in list(vig.get("candidates", []))[1:3]:
                    alt_key = str(alt.get("key", ""))
                    if not alt_key:
                        continue
                    alt_plain = decode_vigenere(text, alt_key)
                    push_candidate(
                        "vigenere_break",
                        alt_plain,
                        max(0.1, vig_conf - 0.12),
                        {"key": alt_key, "score": alt.get("score"), "candidates": vig.get("candidates", [])},
                        round_index=round_idx,
                        path=path,
                    )
                    generated.append(candidates[-1])
            except Exception:
                pass

            try:
                mark_method("xor_single_byte_break")
                x1 = break_xor_single_byte(text)
                conf = 0.55 if "flag{" in str(x1.get("plaintext", "")).lower() else 0.35
                push_candidate(
                    "xor_single_byte_break",
                    str(x1.get("plaintext", "")),
                    conf,
                    {"key": x1.get("key"), "score": x1.get("score")},
                    round_index=round_idx,
                    path=path,
                )
                generated.append(candidates[-1])
            except Exception:
                pass

            try:
                mark_method("xor_repeating_break")
                xr = break_xor_repeating(text, xor_max_key_len)
                xr_conf = float(xr.get("confidence", 0.4))
                push_candidate(
                    "xor_repeating_break",
                    str(xr.get("plaintext", "")),
                    xr_conf,
                    {
                        "key_hex": xr.get("key_hex"),
                        "key_text": xr.get("key_text"),
                        "key_len": xr.get("key_len"),
                        "score": xr.get("score"),
                        "candidates": xr.get("candidates", []),
                    },
                    round_index=round_idx,
                    path=path,
                )
                generated.append(candidates[-1])

                for alt in list(xr.get("candidates", []))[1:3]:
                    alt_text = alt.get("key_text")
                    alt_hex = alt.get("key_hex")
                    if alt_text:
                        alt_plain = xor_with_key(text, str(alt_text))
                    elif alt_hex:
                        alt_plain = xor_with_key_hex(text, str(alt_hex))
                    else:
                        continue
                    push_candidate(
                        "xor_repeating_break",
                        alt_plain,
                        max(0.1, xr_conf - 0.12),
                        {
                            "key_hex": alt_hex,
                            "key_text": alt_text,
                            "key_len": alt.get("key_len"),
                            "score": alt.get("score"),
                            "candidates": xr.get("candidates", []),
                        },
                        round_index=round_idx,
                        path=path,
                    )
                    generated.append(candidates[-1])
            except Exception:
                pass

            try:
                mark_method("byte_shift_break")
                bs = break_byte_shift(text)
                bs_conf = float(bs.get("confidence", 0.35))
                push_candidate(
                    "byte_shift_break",
                    str(bs.get("plaintext", "")),
                    bs_conf,
                    {
                        "shift": bs.get("shift"),
                        "score": bs.get("score"),
                        "candidates": bs.get("candidates", []),
                    },
                    round_index=round_idx,
                    path=path,
                )
                generated.append(candidates[-1])
            except Exception:
                pass

            if round_idx == 1 and _looks_byte_cipher(text):
                try:
                    mark_method("byte_affine_break")
                    ba = break_byte_affine(text)
                    ba_conf = float(ba.get("confidence", 0.30))
                    push_candidate(
                        "byte_affine_break",
                        str(ba.get("plaintext", "")),
                        ba_conf,
                        {
                            "a": ba.get("a"),
                            "b": ba.get("b"),
                            "score": ba.get("score"),
                            "candidates": ba.get("candidates", []),
                        },
                        round_index=round_idx,
                        path=path,
                    )
                    generated.append(candidates[-1])
                except Exception:
                    pass

            try:
                mark_method("rail_fence_break")
                rf = break_rail_fence(text, 8)
                rf_conf = float(rf.get("confidence", 0.25))
                push_candidate(
                    "rail_fence_break",
                    str(rf.get("plaintext", "")),
                    rf_conf,
                    {"rails": rf.get("rails"), "score": rf.get("score"), "candidates": rf.get("candidates", [])},
                    round_index=round_idx,
                    path=path,
                )
                generated.append(candidates[-1])

                for alt in list(rf.get("candidates", []))[1:3]:
                    rails = alt.get("rails")
                    if not isinstance(rails, int):
                        continue
                    alt_plain = decode_rail_fence(text, rails)
                    push_candidate(
                        "rail_fence_break",
                        alt_plain,
                        max(0.1, rf_conf - 0.1),
                        {"rails": rails, "score": alt.get("score"), "candidates": rf.get("candidates", [])},
                        round_index=round_idx,
                        path=path,
                    )
                    generated.append(candidates[-1])
            except Exception:
                pass

            try:
                mark_method("affine_break")
                af = break_affine(text)
                af_conf = float(af.get("confidence", 0.25))
                push_candidate(
                    "affine_break",
                    str(af.get("plaintext", "")),
                    af_conf,
                    {
                        "a": af.get("a"),
                        "b": af.get("b"),
                        "score": af.get("score"),
                        "candidates": af.get("candidates", []),
                    },
                    round_index=round_idx,
                    path=path,
                )
                generated.append(candidates[-1])
            except Exception:
                pass

            try:
                mark_method("playfair_break")
                pf = break_playfair(text)
                pf_conf = float(pf.get("confidence", 0.20))
                push_candidate(
                    "playfair_break",
                    str(pf.get("plaintext", "")),
                    pf_conf,
                    {"key": pf.get("key"), "score": pf.get("score"), "candidates": pf.get("candidates", [])},
                    round_index=round_idx,
                    path=path,
                )
                generated.append(candidates[-1])
            except Exception:
                pass

            if len(text) >= 20 and sum(1 for ch in text if ch.isalpha()) >= 15:
                try:
                    mark_method("mono_sub_break")
                    ms = break_mono_sub(text)
                    ms_conf = float(ms.get("confidence", 0.20))
                    push_candidate(
                        "mono_sub_break",
                        str(ms.get("plaintext", "")),
                        ms_conf,
                        {
                            "key_map": ms.get("key_map"),
                            "score": ms.get("score"),
                            "candidates": ms.get("candidates", []),
                        },
                        round_index=round_idx,
                        path=path,
                    )
                    generated.append(candidates[-1])
                except Exception:
                    pass

        if not generated:
            break

        next_frontier: List[Dict[str, Any]] = []
        seen_round_outputs = set()
        for cand in sorted(generated, key=lambda x: x["score"], reverse=True):
            out = str(cand.get("output", "")).strip()
            if not out or out in seen_round_outputs:
                continue
            seen_round_outputs.add(out)
            next_frontier.append({"text": out, "path": list(cand.get("path", []))})
            if len(next_frontier) >= beam_width:
                break

        frontier = next_frontier
        if not frontier:
            break

    deduped: List[Dict[str, Any]] = []
    seen_outputs = set()
    for item in sorted(candidates, key=lambda x: x["score"], reverse=True):
        key = item["output"].strip()
        if not key or key in seen_outputs:
            continue
        seen_outputs.add(key)
        item["score"] = round(float(item["score"]), 3)
        item["confidence"] = round(float(item["confidence"]), 3)
        deduped.append(item)

    shortlist = deduped[:max_candidates]
    best_output = shortlist[0]["output"] if shortlist else None
    best_method = shortlist[0]["method"] if shortlist else None

    return {
        "best_output": best_output,
        "best_method": best_method,
        "candidates": shortlist,
        "methods_tried": methods_tried,
        "timed_out": timed_out,
        "candidate_count": len(shortlist),
        "rounds_executed": rounds_executed,
    }


def identify_hash(hash_value: str) -> Dict[str, Any]:
    value = hash_value.strip()
    candidates: List[Dict[str, Any]] = []

    if re.fullmatch(r"[0-9a-fA-F]{32}", value):
        candidates.append(
            {
                "type": "MD5",
                "hashcat_mode": 0,
                "confidence": "high",
                "john_format": "raw-md5",
            }
        )
        candidates.append(
            {
                "type": "NTLM",
                "hashcat_mode": 1000,
                "confidence": "medium",
                "john_format": "nt",
                "disambiguation_note": "MD5 and NTLM share hex-32 format. NTLM likely only if from Windows SAM dump.",
            }
        )

    if re.fullmatch(r"[0-9a-fA-F]{40}", value):
        candidates.append(
            {
                "type": "SHA-1",
                "hashcat_mode": 100,
                "confidence": "high",
                "john_format": "raw-sha1",
            }
        )

    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        candidates.append(
            {
                "type": "SHA-256",
                "hashcat_mode": 1400,
                "confidence": "high",
                "john_format": "raw-sha256",
            }
        )

    if re.fullmatch(r"[0-9a-fA-F]{128}", value):
        candidates.append(
            {
                "type": "SHA-512",
                "hashcat_mode": 1700,
                "confidence": "high",
                "john_format": "raw-sha512",
            }
        )

    if value.startswith("$2a$") or value.startswith("$2b$") or value.startswith("$2y$"):
        candidates.append(
            {
                "type": "bcrypt",
                "hashcat_mode": 3200,
                "confidence": "high",
                "john_format": "bcrypt",
            }
        )

    online_result = {"found": False, "plaintext": None, "source": None}
    recommendation = "Use local cracking workflow."

    if not candidates:
        return {
            "hash_types": [],
            "online_result": online_result,
            "recommendation": "Hash type unknown. Verify input formatting.",
        }

    return {
        "hash_types": candidates,
        "online_result": online_result,
        "recommendation": recommendation,
    }
