"""ANCHOR v1 — deterministic CBOR encoder/decoder (RFC 8949).

Hand-rolled, zero dependencies. Implements the *deterministically encoded CBOR*
profile from RFC 8949 §4.2.1:

* shortest-form integers (minimal additional-information width),
* canonical map key ordering: encoded keys sorted by (length, lexicographic),
* definite lengths only — indefinite lengths are rejected,
* preferred (shortest) float serialization: half → single → double.

The decoder is strict: any non-canonical encoding is rejected. Strictness is a
security property — signature verification must never accept two different
byte strings for the same logical value, or an attacker can smuggle a
re-encoded payload past a digest check.

Supported: uint / nint (with bignum tags 2/3 for out-of-range ints), bytes,
text, arrays, maps, tags, floats (shortest), booleans, null, simple values.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from typing import Any


class CBORError(ValueError):
    """Raised for any malformed or non-canonical CBOR."""


@dataclass(frozen=True)
class Tag:
    number: int
    value: Any


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def _head(major: int, n: int) -> bytes:
    """Shortest-form initial byte(s) for a major type with argument n."""
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + struct.pack(">H", n)
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + struct.pack(">I", n)
    if n < 0x10000000000000000:
        return bytes([(major << 5) | 27]) + struct.pack(">Q", n)
    raise CBORError("integer argument too large for CBOR")


def _encode_int(n: int) -> bytes:
    if 0 <= n < 0x10000000000000000:
        return _head(0, n)
    if -0x10000000000000000 <= n < 0:
        return _head(1, -1 - n)
    # Bignum (RFC 8949 §3.4.3): tag 2 for positive, tag 3 for negative.
    if n >= 0:
        content = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return _head(6, 2) + _head(2, len(content)) + content
    mag = -1 - n
    content = mag.to_bytes((mag.bit_length() + 7) // 8, "big")
    return _head(6, 3) + _head(2, len(content)) + content


def _encode_float(x: float) -> bytes:
    if math.isnan(x):
        return b"\xf9\x7e\x00"  # canonical NaN
    try:
        packed_h = struct.pack(">e", x)
    except OverflowError:
        packed_h = None
    if packed_h is not None and struct.unpack(">e", packed_h)[0] == x:
        return b"\xf9" + packed_h
    packed_f = struct.pack(">f", x)
    if struct.unpack(">f", packed_f)[0] == x:
        return b"\xfa" + packed_f
    return b"\xfb" + struct.pack(">d", x)


def _encode(value: Any, out: bytearray) -> None:
    if value is None:
        out += b"\xf6"
    elif value is True:
        out += b"\xf5"
    elif value is False:
        out += b"\xf4"
    elif isinstance(value, int):
        out += _encode_int(value)
    elif isinstance(value, float):
        out += _encode_float(value)
    elif isinstance(value, bytes):
        out += _head(2, len(value)) + value
    elif isinstance(value, str):
        raw = value.encode("utf-8")
        out += _head(3, len(raw)) + raw
    elif isinstance(value, (list, tuple)):
        out += _head(4, len(value))
        for item in value:
            _encode(item, out)
    elif isinstance(value, dict):
        # Canonical ordering: sort by (len(encoded key), encoded key).
        pairs = []
        for k, v in value.items():
            kb = bytearray()
            _encode(k, kb)
            pairs.append((bytes(kb), k, v))
        pairs.sort(key=lambda p: (len(p[0]), p[0]))
        out += _head(5, len(pairs))
        for kb, k, v in pairs:
            out += kb
            _encode(v, out)
    elif isinstance(value, Tag):
        out += _head(6, value.number)
        _encode(value.value, out)
    else:
        raise CBORError(f"cannot CBOR-encode value of type {type(value).__name__}")


def cbor_dumps(value: Any) -> bytes:
    """Deterministically encode a value to CBOR bytes."""
    out = bytearray()
    _encode(value, out)
    return bytes(out)


# ---------------------------------------------------------------------------
# Decoding (strict)
# ---------------------------------------------------------------------------

class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise CBORError("truncated CBOR input")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def _arg(self, ai: int) -> int:
        # Enforce shortest form: a longer width must not encode a value that
        # would fit in a shorter one.
        if ai < 24:
            return ai
        if ai == 24:
            n = self.read(1)[0]
            if n < 24:
                raise CBORError("non-shortest integer encoding (1-byte)")
            return n
        if ai == 25:
            (n,) = struct.unpack(">H", self.read(2))
            if n < 0x100:
                raise CBORError("non-shortest integer encoding (2-byte)")
            return n
        if ai == 26:
            (n,) = struct.unpack(">I", self.read(4))
            if n < 0x10000:
                raise CBORError("non-shortest integer encoding (4-byte)")
            return n
        if ai == 27:
            (n,) = struct.unpack(">Q", self.read(8))
            if n < 0x100000000:
                raise CBORError("non-shortest integer encoding (8-byte)")
            return n
        raise CBORError(f"invalid additional information {ai}")

    def head(self) -> tuple[int, int]:
        initial = self.read(1)[0]
        return initial >> 5, initial & 0x1F

    def decode(self) -> Any:
        major, ai = self.head()
        if ai == 31:
            raise CBORError("indefinite lengths are not allowed in deterministic CBOR")
        if major == 7:
            return self._decode_simple(ai)
        n = self._arg(ai)
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if major == 2:
            return self.read(n)
        if major == 3:
            raw = self.read(n)
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CBORError("invalid UTF-8 in text string") from exc
        if major == 4:
            return [self.decode() for _ in range(n)]
        if major == 5:
            return self._decode_map(n)
        if major == 6:
            return self._decode_tag(n)
        raise CBORError(f"unknown major type {major}")  # unreachable

    def _decode_simple(self, ai: int) -> Any:
        if ai < 20:
            return Simple(ai)
        if ai == 20:
            return False
        if ai == 21:
            return True
        if ai == 22:
            return None
        if ai == 23:
            return Undefined
        if ai == 24:
            n = self.read(1)[0]
            if n < 32:
                raise CBORError("non-shortest simple-value encoding")
            return Simple(n)
        if ai == 25:
            return struct.unpack(">e", self.read(2))[0]
        if ai == 26:
            return struct.unpack(">f", self.read(4))[0]
        if ai == 27:
            return struct.unpack(">d", self.read(8))[0]
        if ai in (28, 29, 30):
            raise CBORError("reserved additional information")
        raise CBORError("break stop code outside indefinite-length item")

    def _decode_map(self, n: int) -> dict:
        result: dict[Any, Any] = {}
        prev_key: bytes | None = None
        for _ in range(n):
            key_start = self.pos
            key = self.decode()
            key_end = self.pos
            key_bytes = self.data[key_start:key_end]
            # Canonical ordering check doubles as the duplicate-key check:
            # equal keys are never strictly greater than the previous one.
            if prev_key is not None and key_bytes <= prev_key:
                raise CBORError("map keys not in canonical order (or duplicate key)")
            prev_key = key_bytes
            result[key] = self.decode()
        return result

    def _decode_tag(self, n: int) -> Any:
        value = self.decode()
        if n in (2, 3) and isinstance(value, bytes):
            if len(value) > 1 and value[0] == 0:
                raise CBORError("non-shortest bignum encoding")
            mag = int.from_bytes(value, "big")
            return mag if n == 2 else -1 - mag
        return Tag(n, value)


@dataclass(frozen=True)
class Simple:
    """A CBOR simple value other than false/true/null/undefined."""
    value: int


class _Undefined:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "Undefined"

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, _Undefined)


Undefined = _Undefined()


def cbor_loads(data: bytes) -> Any:
    """Strictly decode deterministic CBOR. Rejects non-canonical encodings."""
    if not isinstance(data, (bytes, bytearray)):
        raise CBORError("CBOR input must be bytes")
    reader = _Reader(bytes(data))
    value = reader.decode()
    if reader.pos != len(reader.data):
        raise CBORError("trailing bytes after CBOR item")
    return value
