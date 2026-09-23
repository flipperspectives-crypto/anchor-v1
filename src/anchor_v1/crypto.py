from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes
from .models import SignedEnvelope


class Ed25519Signer:
    def __init__(self, key_id: str, private_key: Ed25519PrivateKey):
        self.key_id = key_id
        self._private_key = private_key

    @classmethod
    def generate(cls, key_id: str) -> "Ed25519Signer":
        return cls(key_id, Ed25519PrivateKey.generate())

    @classmethod
    def from_private_pem(cls, key_id: str, pem: bytes) -> "Ed25519Signer":
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("expected Ed25519 private key")
        return cls(key_id, key)

    @classmethod
    def load(cls, key_id: str, path: str | Path) -> "Ed25519Signer":
        return cls.from_private_pem(key_id, Path(path).read_bytes())

    def private_pem(self) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def save_private(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.private_pem())
        try:
            target.chmod(0o600)
        except OSError:
            pass

    def public_key_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key_bytes()).decode("ascii")

    def sign_bytes(self, data: bytes) -> bytes:
        """Sign raw bytes with this signer's Ed25519 private key.

        Added in Wave 1 follow-up: the COSE layer (cose.py) signs
        Sig_structure bytes directly instead of the v0 canonical-JSON
        payload format. Callers needing v0 envelopes keep using
        sign_payload(); new protocol code uses this.
        """
        return self._private_key.sign(data)

    def sign_payload(self, payload: dict[str, Any]) -> SignedEnvelope:
        signature = self._private_key.sign(canonical_bytes(payload))
        return SignedEnvelope(
            key_id=self.key_id,
            payload=payload,
            signature=base64.b64encode(signature).decode("ascii"),
        )


def verify_envelope(envelope: SignedEnvelope, public_key_bytes: bytes) -> dict[str, Any]:
    if envelope.alg != "Ed25519":
        raise ValueError(f"unsupported signature algorithm: {envelope.alg}")
    key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        key.verify(base64.b64decode(envelope.signature), canonical_bytes(envelope.payload))
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("invalid signature") from exc
    return envelope.payload


def public_key_from_b64(value: str) -> bytes:
    return base64.b64decode(value)
