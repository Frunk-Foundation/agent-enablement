from __future__ import annotations

import uuid

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ID_BYTES = 16
ID_LENGTH = 22


def encode_16bytes_base58(raw: bytes) -> str:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != ID_BYTES:
        raise ValueError("base58 id encoder requires exactly 16 bytes")
    n = int.from_bytes(raw, "big")
    chars: list[str] = []
    while n > 0:
        n, rem = divmod(n, 58)
        chars.append(BASE58_ALPHABET[rem])
    encoded = "".join(reversed(chars)) if chars else BASE58_ALPHABET[0]
    if len(encoded) > ID_LENGTH:
        raise ValueError("base58 encoded id exceeds fixed 22-char width")
    return (BASE58_ALPHABET[0] * (ID_LENGTH - len(encoded))) + encoded


def uuid4_base58_22() -> str:
    return encode_16bytes_base58(uuid.uuid4().bytes)


def uuid_text_to_base58_22(value: str) -> str:
    return encode_16bytes_base58(uuid.UUID(str(value)).bytes)


def is_base58_22(value: str) -> bool:
    if not isinstance(value, str) or len(value) != ID_LENGTH:
        return False
    return all(ch in BASE58_ALPHABET for ch in value)
