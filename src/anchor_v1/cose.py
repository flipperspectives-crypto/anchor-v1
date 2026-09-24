"""ANCHOR v1 — hand-rolled COSE_Sign1 (RFC 9052) over Ed25519.

The signed object is:

    COSE_Sign1 = [ body_protected : bstr, unprotected : map,
                   payload : bstr, signature : bstr ]

with Sig_structure = ["Signature1", body_protected, external_aad, payload].

Protocol hardening (fail-closed by design):

* Algorithm allowlist: only EdDSA (-8) is accepted. Any other ``alg`` value in
  the protected header is rejected before signature verification.
* The protected header must contain exactly {1: -8, 4: kid}. No extra labels.
* The unprotected header must be empty. Header parameters smuggled outside the
  integrity-protected header are a classic downgrade vector.
* CBOR is decoded with the strict deterministic decoder — non-canonical
  encodings of the COSE structure are rejected.
* The ``kid`` selects the verification key from an explicit caller-supplied
  trust set; unknown kids are rejected.

Zero new dependencies: Ed25519 comes from the ``cryptography`` library already
used by ``anchor_v1.crypto``.
"""

from __future__ import annotations

from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .cbor import CBORError, cbor_dumps, cbor_loads


class COSEError(ValueError):
    """Raised when a COSE_Sign1 object is malformed or fails verification."""


# COSE algorithm + header label registry values (RFC 9053 / RFC 9052).
ALG_EDDSA = -8
_LABEL_ALG = 1
_LABEL_KID = 4


def cose_sign_bytes(
    payload: bytes,
    sign_fn: "Callable[[bytes], bytes]",
    kid: bytes,
    external_aad: bytes = b"",
) -> bytes:
    """Create a COSE_Sign1 message, signing via a caller-supplied function.

    Same wire format as :func:`cose_sign`; the only difference is that the
    Ed25519 signature over the Sig_structure is produced by ``sign_fn``
    (e.g. ``Ed25519Signer.sign_bytes``) instead of a raw private-key object.
    """
    protected = cbor_dumps({_LABEL_ALG: ALG_EDDSA, _LABEL_KID: bytes(kid)})
    sig_structure = cbor_dumps(
        ["Signature1", protected, bytes(external_aad), bytes(payload)]
    )
    signature = sign_fn(sig_structure)
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        raise COSEError("sign_fn must return a 64-byte Ed25519 signature")
    return cbor_dumps([protected, {}, bytes(payload), signature])


def cose_sign(
    payload: bytes,
    private_key: Ed25519PrivateKey,
    kid: bytes,
    external_aad: bytes = b"",
) -> bytes:
    """Create a COSE_Sign1 message over ``payload``.

    ``kid`` is placed in the protected header as label 4 (bstr). The protected
    header is ``{1: -8, 4: kid}`` and nothing else.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise COSEError("payload must be bytes")
    if not isinstance(kid, (bytes, bytearray)) or len(kid) == 0:
        raise COSEError("kid must be a non-empty byte string")
    if not isinstance(external_aad, (bytes, bytearray)):
        raise COSEError("external_aad must be bytes")

    protected = cbor_dumps({_LABEL_ALG: ALG_EDDSA, _LABEL_KID: bytes(kid)})
    sig_structure = cbor_dumps(
        ["Signature1", protected, bytes(external_aad), bytes(payload)]
    )
    signature = private_key.sign(sig_structure)
    return cbor_dumps([protected, {}, bytes(payload), signature])


def _validate_cose_headers(protected: Any, unprotected: Any) -> tuple[int, bytes]:
    """Validate protected and unprotected COSE header maps (ATTACK-12 / ATTACK-15). Fail-closed."""
    if not isinstance(unprotected, dict):
        raise COSEError("unprotected header must be a map")
    if unprotected != {}:
        raise COSEError("unprotected header must be empty")
    if not isinstance(protected, dict):
        raise COSEError("protected header must be a map")
    if set(protected.keys()) != {_LABEL_ALG, _LABEL_KID}:
        raise COSEError("protected header must contain exactly alg and kid")
    alg = protected[_LABEL_ALG]
    if alg != ALG_EDDSA:
        raise COSEError(f"algorithm not allowed: {alg!r} (only EdDSA/-8)")
    kid = protected[_LABEL_KID]
    if not isinstance(kid, bytes):
        raise COSEError("kid must be a byte string")
    return alg, kid


def cose_verify(
    message: bytes,
    trusted_keys: Mapping[bytes, Ed25519PublicKey],
    external_aad: bytes = b"",
) -> tuple[bytes, bytes]:
    """Verify a COSE_Sign1 message. Returns ``(payload, kid)``.

    ``trusted_keys`` maps kid bytes to Ed25519 public keys. Raises COSEError on
    any malformed input, disallowed algorithm, unknown kid, or bad signature.
    """
    if not isinstance(message, (bytes, bytearray)):
        raise COSEError("COSE message must be bytes")
    try:
        outer = cbor_loads(bytes(message))
    except CBORError as exc:
        raise COSEError(f"malformed COSE_Sign1: {exc}") from exc

    if not isinstance(outer, list) or len(outer) != 4:
        raise COSEError("COSE_Sign1 must be an array of 4 elements")
    body_protected, unprotected, payload, signature = outer
    if not isinstance(body_protected, bytes):
        raise COSEError("body_protected must be a byte string")
    if not isinstance(unprotected, dict):
        raise COSEError("unprotected header must be a map")
    if not isinstance(payload, bytes):
        raise COSEError("payload must be a byte string")
    if not isinstance(signature, bytes):
        raise COSEError("signature must be a byte string")

    try:
        protected = cbor_loads(body_protected)
    except CBORError as exc:
        raise COSEError(f"malformed protected header: {exc}") from exc

    alg, kid = _validate_cose_headers(protected, unprotected)

    key = trusted_keys.get(kid)
    if key is None:
        raise COSEError("unknown kid: no trusted key")

    sig_structure = cbor_dumps(["Signature1", body_protected, bytes(external_aad), payload])
    try:
        key.verify(signature, sig_structure)
    except InvalidSignature as exc:
        raise COSEError("signature verification failed") from exc
    return payload, kid
