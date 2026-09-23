"""ANCHOR v1 — upstream identity adapters (consume-only).

These adapters AUTHENTICATE subjects presented by upstream identity systems
(SPIFFE/X.509 SVIDs, OIDC JWTs, Entra ID, Okta). They never *issue* identity:
there is no mint/sign/enroll API anywhere in this module. A successful
``authenticate()`` yields a :class:`Subject` whose ``subject_id`` is suitable
for ``ActionEnvelope.principal`` (the subject id string the envelope binds).

Fail-closed throughout: ANY verification failure — bad signature, expired
token, wrong audience/issuer/tenant, algorithm confusion, unknown ``kid``,
untrusted certificate chain, missing URI SAN — raises :class:`IdentityError`
(a :class:`ValueError` subclass). Callers must treat ``IdentityError`` as
"identity unverified, deny the action".

Trust material is INJECTED at construction (CA bundle, JWKS dict). No network
I/O is performed: no JWKS fetch, no certificate download, no OCSP/CRL.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import time
import urllib.parse
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtensionOID

from .models import StrictModel


class IdentityError(ValueError):
    """Raised when an identity token cannot be verified. Fail closed: the
    subject is unauthenticated and the action must be denied."""


class Subject(StrictModel):
    """An authenticated upstream subject.

    ``subject_id`` is the string that becomes ``ActionEnvelope.principal``
    (the full SPIFFE ID for SVIDs, the ``sub`` claim for OIDC).
    ``issuer`` names the authority that vouched for the subject.
    ``claims`` carries the verified upstream claims verbatim.
    """

    subject_id: str
    issuer: str
    claims: dict[str, Any]


class IdentityAdapter(ABC):
    """Consume-only identity verifier. Implementations authenticate tokens
    issued by upstream identity providers; none of them issue identity."""

    @abstractmethod
    def authenticate(self, token: bytes | str) -> Subject:
        """Verify ``token`` and return the authenticated :class:`Subject`.

        Raises :class:`IdentityError` on ANY failure — never returns an
        unverified subject.
        """


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def _b64url_decode(part: str, *, what: str) -> bytes:
    if not _B64URL_RE.fullmatch(part):
        raise IdentityError(f"malformed base64url in JWT {what}")
    try:
        return base64.b64decode(part + "=" * (-len(part) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise IdentityError(f"malformed base64url in JWT {what}") from exc


def _b64url_decode_int(value: Any, *, what: str, exact_len: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise IdentityError(f"malformed JWK: {what} must be a base64url string")
    raw = _b64url_decode(value, what=f"JWK {what}")
    if exact_len is not None and len(raw) != exact_len:
        raise IdentityError(f"malformed JWK: {what} has wrong length")
    if not raw:
        raise IdentityError(f"malformed JWK: {what} is empty")
    return raw


def _json_object(raw: bytes, *, what: str) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IdentityError(f"JWT {what} is not valid UTF-8") from exc
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IdentityError(f"JWT {what} is not valid JSON") from exc
    if not isinstance(obj, dict):
        raise IdentityError(f"JWT {what} must be a JSON object")
    return obj


def _coerce_token_text(token: bytes | str) -> str:
    if isinstance(token, bytes):
        try:
            return token.decode("ascii")
        except UnicodeDecodeError as exc:
            raise IdentityError("token is not ASCII") from exc
    if isinstance(token, str):
        try:
            token.encode("ascii")
        except UnicodeEncodeError as exc:
            raise IdentityError("token is not ASCII") from exc
        return token
    raise IdentityError("token must be bytes or str")


def _as_number(value: Any, *, claim: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise IdentityError(f"JWT claim {claim!r} must be a JSON number")
    number = float(value)
    if not math.isfinite(number):
        # Defense in depth: a non-finite exp (e.g. Infinity) would compare
        # greater than any clock time and never expire. NaN would make every
        # comparison False, silently defeating the check. Fail closed.
        raise IdentityError(f"JWT claim {claim!r} must be a finite number")
    return number


# ---------------------------------------------------------------------------
# JWK handling (injected trust material — never fetched)
# ---------------------------------------------------------------------------

_RSA_MIN_BITS = 2048


def _jwk_to_public_key(jwk: Mapping[str, Any]) -> Any:
    """Strictly convert a JWK dict to a cryptography public key.

    Only public parameters are accepted; the presence of private material
    (``d``) is a hard failure. Supported: RSA, EC P-256, OKP Ed25519.
    """
    if not isinstance(jwk, Mapping):
        raise IdentityError("JWKS entry must be a mapping")
    if "d" in jwk:
        raise IdentityError("JWKS entry must not contain private key material")
    kty = jwk.get("kty")
    if kty == "RSA":
        n = int.from_bytes(_b64url_decode_int(jwk.get("n"), what="n"), "big")
        e = int.from_bytes(_b64url_decode_int(jwk.get("e"), what="e"), "big")
        if n.bit_length() < _RSA_MIN_BITS:
            raise IdentityError("JWK RSA key is below 2048 bits")
        if e < 3 or e % 2 == 0:
            raise IdentityError("JWK RSA exponent is invalid")
        try:
            return rsa.RSAPublicNumbers(e, n).public_key()
        except ValueError as exc:
            raise IdentityError("JWK RSA parameters are invalid") from exc
    if kty == "EC":
        if jwk.get("crv") != "P-256":
            raise IdentityError("JWK EC curve must be P-256")
        x = int.from_bytes(_b64url_decode_int(jwk.get("x"), what="x", exact_len=32), "big")
        y = int.from_bytes(_b64url_decode_int(jwk.get("y"), what="y", exact_len=32), "big")
        try:
            return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        except ValueError as exc:
            raise IdentityError("JWK EC coordinates are not on P-256") from exc
    if kty == "OKP":
        if jwk.get("crv") != "Ed25519":
            raise IdentityError("JWK OKP curve must be Ed25519")
        raw = _b64url_decode_int(jwk.get("x"), what="x", exact_len=32)
        try:
            return ed25519.Ed25519PublicKey.from_public_bytes(raw)
        except ValueError as exc:
            raise IdentityError("JWK Ed25519 key bytes are invalid") from exc
    raise IdentityError(f"unsupported JWK kty/crv: {kty!r}/{jwk.get('crv')!r}")


def _coerce_public_key(value: Any, *, kid: str) -> Any:
    """Accept an injected public key: a cryptography key object or a strict
    JWK dict. Anything else is rejected (fail closed)."""
    if isinstance(value, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey)):
        if isinstance(value, rsa.RSAPublicKey) and value.key_size < _RSA_MIN_BITS:
            raise IdentityError(f"injected RSA key for kid {kid!r} is below 2048 bits")
        return value
    if isinstance(value, Mapping):
        return _jwk_to_public_key(value)
    raise IdentityError(f"JWKS entry for kid {kid!r} is not a usable public key")


# ---------------------------------------------------------------------------
# OIDC adapter — hand-rolled JWT verification
# ---------------------------------------------------------------------------

_ALLOWED_ALGS = ("RS256", "ES256", "EdDSA")

# Maximum clock_skew the OIDC adapter will accept (24h, in seconds). Clock
# skew exists to absorb real clock drift between issuer and verifier, which is
# measured in seconds-to-minutes; anything larger silently disables the
# exp/nbf lifetime checks (exp > now - skew is always true for huge skew).
# Values above this bound are rejected at construction.
_MAX_CLOCK_SKEW_SECONDS = 86400.0

# Header parameters that would smuggle trust material or network fetches.
_FORBIDDEN_JWT_HEADERS = ("jwk", "jku", "x5u", "x5c", "x5t", "x5t#S256")


class OidcAdapter(IdentityAdapter):
    """Verify OIDC ID tokens with hand-rolled JWT validation.

    Trust is fully injected: ``jwks`` maps ``kid`` -> public key (a
    cryptography public-key object or a strict JWK dict). No network fetch
    is ever performed.

    Enforced, fail-closed:
    * ``alg`` allowlist: RS256, ES256, EdDSA only. ``none`` and every other
      algorithm are rejected before any crypto runs.
    * ``kid`` must be present and resolve in the injected JWKS.
    * The key TYPE must match the ``alg`` (RS256<->RSA>=2048bit,
      ES256<->EC P-256, EdDSA<->Ed25519). Cross-type ``kid`` (algorithm
      confusion) is rejected even if the signature would verify.
    * No embedded keys (``jwk``) and no key-location hints (``jku``/``x5u``);
      ``crit`` extensions are rejected outright.
    * ``iss`` must exactly equal the pinned issuer; ``aud`` must contain the
      pinned audience; ``exp``/``iat``/``nbf`` must be finite JSON numbers and
      are validated against the clock with configurable skew (default 60s,
      capped at 86400s / 24h — skew absorbs clock drift measured in
      seconds-to-minutes, so anything larger would silently disable the
      lifetime checks); ``sub`` must be a non-empty string.
    """

    def __init__(
        self,
        *,
        jwks: Mapping[str, Any],
        issuer: str | Sequence[str],
        audience: str,
        clock_skew: float = 60.0,
    ) -> None:
        if not isinstance(jwks, Mapping) or not jwks:
            raise IdentityError("jwks must be a non-empty mapping of kid to public key")
        self._keys: dict[str, Any] = {}
        for kid, key in jwks.items():
            if not isinstance(kid, str) or not kid:
                raise IdentityError("JWKS kid must be a non-empty string")
            self._keys[kid] = _coerce_public_key(key, kid=kid)
        if isinstance(issuer, str):
            accepted = (issuer,)
        else:
            accepted = tuple(issuer)
        if not accepted or any(not isinstance(i, str) or not i for i in accepted):
            raise IdentityError("issuer must be a non-empty string (or sequence of them)")
        if not isinstance(audience, str) or not audience:
            raise IdentityError("audience must be a non-empty string")
        if (
            not isinstance(clock_skew, (int, float))
            or not math.isfinite(clock_skew)
            or clock_skew < 0
            or clock_skew > _MAX_CLOCK_SKEW_SECONDS
        ):
            # Integrator footgun: clock_skew=float("inf") would silently
            # disable expiry (exp > now - inf is always true), and NaN would
            # make every time comparison False, silently defeating the
            # checks. A huge FINITE skew (e.g. 10**18) is the same footgun:
            # exp > now - 10**18 is always true, so an expired token — or
            # one with nbf a year in the future — would authenticate. Skew
            # exists to absorb clock drift measured in seconds-to-minutes,
            # so cap it at 24h. Fail at construction, not at first
            # authenticate().
            raise IdentityError(
                "clock_skew must be a finite number >= 0 and "
                f"<= {_MAX_CLOCK_SKEW_SECONDS:g} seconds (24h)"
            )
        self._accepted_issuers = accepted
        self._audience = audience
        self._skew = float(clock_skew)

    # -- JWT parsing -----------------------------------------------------

    def _parse_compact(self, token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
        parts = token.split(".")
        if len(parts) != 3 or not all(parts):
            raise IdentityError("JWT must have three non-empty dot-separated parts")
        header_b64, payload_b64, sig_b64 = parts
        header = _json_object(_b64url_decode(header_b64, what="header"), what="header")
        payload = _json_object(_b64url_decode(payload_b64, what="payload"), what="payload")
        signature = _b64url_decode(sig_b64, what="signature")
        if not signature:
            raise IdentityError("JWT signature is empty")
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        return header, payload, signing_input, signature

    def _check_header(self, header: dict[str, Any]) -> tuple[str, Any]:
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in _ALLOWED_ALGS:
            # Covers alg=none, HS256, and every non-allowlisted algorithm.
            raise IdentityError(f"JWT alg {alg!r} is not in the allowlist {_ALLOWED_ALGS}")
        if "crit" in header:
            raise IdentityError("JWT uses crit extensions, which are not supported")
        for forbidden in _FORBIDDEN_JWT_HEADERS:
            if forbidden in header:
                raise IdentityError(f"JWT header {forbidden!r} would inject trust material; rejected")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise IdentityError("JWT header is missing a usable kid")
        try:
            key = self._keys[kid]
        except KeyError:
            raise IdentityError(f"JWT kid {kid!r} is not in the injected JWKS") from None
        return alg, key

    @staticmethod
    def _verify_signature(alg: str, key: Any, signing_input: bytes, signature: bytes) -> None:
        """Verify the signature, enforcing alg<->key-type binding.

        A key of the wrong type for ``alg`` is rejected even if the bytes
        could verify — this is the algorithm-confusion defense.
        """
        try:
            if alg == "RS256":
                if not isinstance(key, rsa.RSAPublicKey):
                    raise IdentityError("alg RS256 requires an RSA public key")
                if key.key_size < _RSA_MIN_BITS:
                    raise IdentityError("RSA key below 2048 bits is rejected for RS256")
                key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
            elif alg == "ES256":
                if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
                    key.curve, ec.SECP256R1
                ):
                    raise IdentityError("alg ES256 requires a P-256 EC public key")
                key.verify(signature, signing_input, ec.ECDSA(hashes.SHA256()))
            elif alg == "EdDSA":
                if not isinstance(key, ed25519.Ed25519PublicKey):
                    raise IdentityError("alg EdDSA requires an Ed25519 public key")
                key.verify(signature, signing_input)
            else:  # unreachable: alg was allowlisted
                raise IdentityError(f"unsupported alg {alg!r}")
        except InvalidSignature as exc:
            raise IdentityError("JWT signature verification failed") from exc

    # -- claims -----------------------------------------------------------

    def _check_claims(self, payload: dict[str, Any], *, now: float) -> str:
        iss = payload.get("iss")
        if not isinstance(iss, str) or iss not in self._accepted_issuers:
            raise IdentityError(f"JWT iss {iss!r} does not match the pinned issuer")

        aud = payload.get("aud")
        if isinstance(aud, str):
            audiences = (aud,)
        elif isinstance(aud, list) and aud and all(isinstance(a, str) and a for a in aud):
            audiences = tuple(aud)
        else:
            raise IdentityError("JWT aud must be a non-empty string or list of strings")
        if self._audience not in audiences:
            raise IdentityError("JWT aud does not contain the pinned audience")

        if "exp" not in payload:
            raise IdentityError("JWT is missing exp")
        exp = _as_number(payload["exp"], claim="exp")
        if not exp > now - self._skew:
            raise IdentityError("JWT is expired")

        if "nbf" in payload:
            nbf = _as_number(payload["nbf"], claim="nbf")
            if nbf > now + self._skew:
                raise IdentityError("JWT is not yet valid (nbf)")

        if "iat" not in payload:
            raise IdentityError("JWT is missing iat")
        iat = _as_number(payload["iat"], claim="iat")
        if iat > now + self._skew:
            raise IdentityError("JWT iat is in the future beyond clock skew")

        sub = payload.get("sub")
        if not isinstance(sub, str) or not sub:
            raise IdentityError("JWT sub must be a non-empty string")
        return sub

    # -- entry point ------------------------------------------------------

    def authenticate(self, token: bytes | str) -> Subject:
        text = _coerce_token_text(token)
        header, payload, signing_input, signature = self._parse_compact(text)
        alg, key = self._check_header(header)
        self._verify_signature(alg, key, signing_input, signature)
        sub = self._check_claims(payload, now=time.time())
        return Subject(subject_id=sub, issuer=payload["iss"], claims=payload)


class EntraAdapter(OidcAdapter):
    """OIDC adapter pinned to a Microsoft Entra ID tenant.

    Accepts both the v2 issuer (``https://login.microsoftonline.com/<tenant>/v2.0``)
    and the v1 issuer (``https://sts.windows.net/<tenant>/``) for the pinned
    tenant. Any other tenant — or any other issuer shape — fails closed.
    """

    def __init__(
        self,
        *,
        tenant: str,
        jwks: Mapping[str, Any],
        audience: str,
        clock_skew: float = 60.0,
    ) -> None:
        if not isinstance(tenant, str) or not tenant or re.search(r"[\s/]", tenant):
            raise IdentityError("tenant must be a bare tenant id or domain (no slashes)")
        self.tenant = tenant
        super().__init__(
            jwks=jwks,
            issuer=(
                f"https://login.microsoftonline.com/{tenant}/v2.0",
                f"https://sts.windows.net/{tenant}/",
            ),
            audience=audience,
            clock_skew=clock_skew,
        )


class OktaAdapter(OidcAdapter):
    """OIDC adapter pinned to an Okta authorization server.

    The issuer is pinned to ``https://<domain>/oauth2/<auth_server>`` exactly;
    tokens from any other domain or authorization server fail closed.
    """

    def __init__(
        self,
        *,
        domain: str,
        auth_server: str = "default",
        jwks: Mapping[str, Any],
        audience: str,
        clock_skew: float = 60.0,
    ) -> None:
        for label, value in (("domain", domain), ("auth_server", auth_server)):
            if not isinstance(value, str) or not value or re.search(r"[\s/]", value):
                raise IdentityError(f"{label} must be a bare host/path segment (no slashes)")
        if "." not in domain:
            raise IdentityError("domain must look like a DNS host")
        self.domain = domain
        self.auth_server = auth_server
        super().__init__(
            jwks=jwks,
            issuer=f"https://{domain}/oauth2/{auth_server}",
            audience=audience,
            clock_skew=clock_skew,
        )


# ---------------------------------------------------------------------------
# SPIFFE adapter — X.509 SVID chain verification
# ---------------------------------------------------------------------------

_MAX_CHAIN_DEPTH = 10


def _cert_fingerprint(cert: x509.Certificate) -> bytes:
    return cert.fingerprint(hashes.SHA256())


def _verify_cert_signature(child: x509.Certificate, issuer: x509.Certificate) -> None:
    """Verify ``child`` was signed by ``issuer``'s key. Fail closed."""
    pub = issuer.public_key()
    tbs = child.tbs_certificate_bytes
    sig = child.signature
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            if child.signature_hash_algorithm is None:
                raise IdentityError("certificate signature hash algorithm is missing")
            pub.verify(sig, tbs, padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            if child.signature_hash_algorithm is None:
                raise IdentityError("certificate signature hash algorithm is missing")
            pub.verify(sig, tbs, ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(sig, tbs)
        else:
            raise IdentityError("certificate issuer uses an unsupported key type")
    except InvalidSignature as exc:
        raise IdentityError("certificate signature is invalid") from exc


def _check_validity(cert: x509.Certificate, *, now: datetime, what: str) -> None:
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise IdentityError(f"{what} certificate is not valid at the current time")


def _check_ca_constraints(
    cert: x509.Certificate, *, what: str, ca_certs_below: int = 0
) -> None:
    """Enforce that ``cert`` may act as a CA, including RFC 5280 S4.2.1.9
    pathLenConstraint: an intermediate with ``path_length=N`` may have at most
    N CA certificates below it (the end entity does not count). ``ca_certs_below``
    is the number of CA certs already chained beneath ``cert``.

    An absent ``path_length`` on a non-self-signed intermediate means
    unconstrained (per RFC); a violated explicit ``path_length`` is fatal.
    """
    try:
        basic = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    except x509.ExtensionNotFound:
        raise IdentityError(f"{what} certificate is missing BasicConstraints") from None
    if not basic.ca:
        raise IdentityError(f"{what} certificate is not a CA but is used as one")
    if basic.path_length is not None and ca_certs_below > basic.path_length:
        raise IdentityError(
            f"{what} certificate violates path_length={basic.path_length}: "
            f"{ca_certs_below} CA certificate(s) appear below it"
        )
    try:
        usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        usage = None
    if usage is not None and not usage.key_cert_sign:
        raise IdentityError(f"{what} certificate keyUsage forbids cert signing")


def _parse_spiffe_id(uri: str, *, trust_domain: str) -> tuple[str, str]:
    """Parse and pin a SPIFFE ID. Returns (spiffe_id, path). Fail closed."""
    try:
        parts = urllib.parse.urlsplit(uri)
    except ValueError as exc:
        raise IdentityError(f"SPIFFE ID {uri!r} is not a valid URI") from exc
    if parts.scheme.lower() != "spiffe":
        raise IdentityError(f"SPIFFE ID {uri!r} does not use the spiffe scheme")
    if "@" in parts.netloc or parts.port is not None:
        raise IdentityError(f"SPIFFE ID {uri!r} has an illegal authority component")
    if (parts.hostname or "").lower() != trust_domain:
        raise IdentityError(
            f"SPIFFE ID trust domain {(parts.hostname or '')!r} does not match pinned {trust_domain!r}"
        )
    if not parts.path or not parts.path.startswith("/"):
        raise IdentityError(f"SPIFFE ID {uri!r} has an empty path")
    if parts.query or parts.fragment:
        raise IdentityError(f"SPIFFE ID {uri!r} must not carry query or fragment")
    return uri, parts.path


class SpiffeAdapter(IdentityAdapter):
    """Verify X.509 SVIDs against an injected trust bundle.

    ``token`` is PEM (bytes or str) holding the leaf SVID followed by any
    intermediates. The trust bundle is a list of trusted root CA certificates,
    matched by SHA-256 fingerprint — a look-alike root with the same subject
    DN but a different key does NOT chain.

    Checks, all fail-closed:
    * the chain builds from the leaf through intermediates to a root whose
      fingerprint is in the injected bundle; every link's signature verifies;
    * every intermediate is a real CA (BasicConstraints ca=True, keyUsage
      keyCertSign when present) and its BasicConstraints.path_length budget
      is enforced per RFC 5280 S4.2.1.9: at most N CA certificates may appear
      below an intermediate with path_length=N (absent path_length on a
      non-self-signed intermediate means unconstrained); the root is
      self-signed and currently valid;
    * the leaf is currently valid, is not a CA, and carries keyUsage
      digitalSignature;
    * the leaf's SubjectAlternativeName holds a URI SAN of the form
      ``spiffe://<trust_domain>/<path>`` with the pinned trust domain —
      that URI string is the ``subject_id``.
    """

    def __init__(
        self,
        *,
        trust_bundle: Sequence[x509.Certificate],
        trust_domain: str,
    ) -> None:
        roots = list(trust_bundle) if not isinstance(trust_bundle, (str, bytes)) else []
        if not roots or any(not isinstance(c, x509.Certificate) for c in roots):
            raise IdentityError("trust_bundle must be a non-empty list of CA certificates")
        if not isinstance(trust_domain, str) or not trust_domain or re.search(r"[\s/:]", trust_domain):
            raise IdentityError("trust_domain must be a bare domain (no scheme, slashes, or spaces)")
        self._trust_domain = trust_domain.lower()
        self._roots = roots
        self._root_fps = {_cert_fingerprint(c) for c in roots}
        # Roots must be self-signed at injection time (validity is checked per use).
        for root in roots:
            if root.issuer != root.subject:
                raise IdentityError("trust bundle entry is not self-signed")
            _verify_cert_signature(root, root)

    @staticmethod
    def _load_pem_chain(token: str) -> list[x509.Certificate]:
        certs: list[x509.Certificate] = []
        blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", token, re.DOTALL
        )
        if not blocks:
            raise IdentityError("token contains no PEM certificates")
        for block in blocks:
            try:
                certs.append(x509.load_pem_x509_certificate(block.encode("ascii")))
            except ValueError as exc:
                raise IdentityError("token contains a malformed PEM certificate") from exc
        return certs

    def _build_chain(
        self, leaf: x509.Certificate, material: list[x509.Certificate], *, now: datetime
    ) -> list[x509.Certificate]:
        chain = [leaf]
        seen = {_cert_fingerprint(leaf)}
        current = leaf
        for _ in range(_MAX_CHAIN_DEPTH):
            issuer = next(
                (c for c in list(material) + self._roots if c.subject == current.issuer),
                None,
            )
            if issuer is None:
                raise IdentityError("SVID chain does not terminate at a trusted root")
            _check_validity(issuer, now=now, what="issuer")
            _verify_cert_signature(current, issuer)
            fp = _cert_fingerprint(issuer)
            if fp in seen:
                raise IdentityError("SVID chain contains a loop")
            seen.add(fp)
            chain.append(issuer)
            if fp in self._root_fps:
                # Trusted root reached: confirm it is genuinely self-signed.
                if issuer.issuer != issuer.subject:
                    raise IdentityError("trusted root is not self-signed")
                _verify_cert_signature(issuer, issuer)
                return chain
            # At this point chain == [end entity, ca_1, ..., ca_k == issuer]:
            # every cert below the issuer except chain[0] is a verified CA, so
            # the CA-cert count below the issuer is len(chain) - 2.
            _check_ca_constraints(
                issuer, what="intermediate", ca_certs_below=len(chain) - 2
            )
            current = issuer
        raise IdentityError("SVID chain exceeds maximum depth")

    def _check_leaf(self, leaf: x509.Certificate, *, now: datetime) -> str:
        _check_validity(leaf, now=now, what="leaf SVID")
        try:
            basic = leaf.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        except x509.ExtensionNotFound:
            basic = None
        if basic is not None and basic.ca:
            raise IdentityError("leaf SVID must not be a CA")
        try:
            usage = leaf.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        except x509.ExtensionNotFound:
            raise IdentityError("leaf SVID is missing keyUsage") from None
        if not usage.digital_signature:
            raise IdentityError("leaf SVID keyUsage must include digitalSignature")
        try:
            san = leaf.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value
        except x509.ExtensionNotFound:
            raise IdentityError("leaf SVID is missing the subjectAlternativeName extension") from None
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        if not uris:
            raise IdentityError("leaf SVID has no URI SAN")
        for uri in uris:
            try:
                spiffe_id, _path = _parse_spiffe_id(uri, trust_domain=self._trust_domain)
            except IdentityError:
                continue
            return spiffe_id
        raise IdentityError("leaf SVID has no URI SAN for the pinned trust domain")

    def authenticate(self, token: bytes | str) -> Subject:
        text = _coerce_token_text(token)
        material = self._load_pem_chain(text)
        now = datetime.now(timezone.utc)
        last_error: IdentityError | None = None
        for leaf in material:
            try:
                chain = self._build_chain(leaf, material, now=now)
                spiffe_id = self._check_leaf(chain[0], now=now)
            except IdentityError as exc:
                last_error = exc
                continue
            _path = urllib.parse.urlsplit(spiffe_id).path
            return Subject(
                subject_id=spiffe_id,
                issuer=f"spiffe://{self._trust_domain}",
                claims={
                    "spiffe_id": spiffe_id,
                    "trust_domain": self._trust_domain,
                    "path": _path,
                    "subject_dn": chain[0].subject.rfc4514_string(),
                    "issuer_dn": chain[0].issuer.rfc4514_string(),
                    "serial_number": format(chain[0].serial_number, "x"),
                    "not_before": chain[0].not_valid_before_utc.isoformat(),
                    "not_after": chain[0].not_valid_after_utc.isoformat(),
                    "chain_length": len(chain),
                },
            )
        raise last_error if last_error is not None else IdentityError("no verifiable SVID found")
