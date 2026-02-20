from __future__ import annotations

import secrets
import struct
import time
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


def uuid7_base58_22() -> str:
    ts_ms = int(time.time() * 1000)
    ts_bytes = struct.pack(">Q", ts_ms)[2:]  # last 6 bytes
    rand_bytes = secrets.token_bytes(10)
    raw = bytearray(ts_bytes + rand_bytes)
    raw[6] = (raw[6] & 0x0F) | 0x70
    raw[8] = (raw[8] & 0x3F) | 0x80
    return encode_16bytes_base58(bytes(raw))


def is_base58_22(value: str) -> bool:
    if not isinstance(value, str) or len(value) != ID_LENGTH:
        return False
    return all(ch in BASE58_ALPHABET for ch in value)
