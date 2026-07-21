from __future__ import annotations
import hashlib
import re

def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())

def _token_hash(token: str, bits: int) -> int:
    digest = hashlib.blake2b(token.encode(), digest_size=8).digest()
    return int.from_bytes(digest, "big") & ((1 << bits) - 1)

def simhash(text: str, bits: int = 64) -> int:
    vector = [0] * bits
    tokens = _tokens(text)
    if not tokens:
        return 0
    for token in tokens:
        h = _token_hash(token, bits)
        for i in range(bits):
            vector[i] += 1 if (h >> i) & 1 else -1
    result = 0
    for i in range(bits):
        if vector[i] > 0:
            result |= (1 << i)
    return result

def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")

def to_hex(value: int) -> str:
    return format(value, "016x")

def from_hex(s: str) -> int:
    return int(s, 16)
