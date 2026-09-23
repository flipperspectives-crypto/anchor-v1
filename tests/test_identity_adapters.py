"""Tests for anchor_v1.identity_adapters — BUILDER B.

Unit tests verify the happy paths; attack tests verify fail-closed behavior
against a battery of adversarial inputs. Keys and certificates are generated
in-test with `cryptography` — no fixtures, no network.
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

from anchor_v1.envelope import ActionEnvelope, Effect
from anchor_v1.identity_adapters import (
    EntraAdapter,
    IdentityAdapter,
    IdentityError,
    OidcAdapter,
    OktaAdapter,
    SpiffeAdapter,
    Subject,
)

ISS = "https://issuer.example.com"
AUD = "anchor-api"
TRUST_DOMAIN = "example.org"
SPIFFE_ID = f"spiffe://{TRUST_DOMAIN}/ns/default/sa/web"


# ---------------------------------------------------------------------------
# Key / token / certificate factories
# ---------------------------------------------------------------------------

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_KEY2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # attacker key
RSA_WEAK = rsa.generate_private_key(public_exponent=65537, key_size=1024)
EC_KEY = ec.generate_private_key(ec.SECP256R1())
EC_KEY2 = ec.generate_private_key(ec.SECP256R1())  # attacker key
ED_KEY = ed25519.Ed25519PrivateKey.generate()
ED_KEY2 = ed25519.Ed25519PrivateKey.generate()  # attacker key

JWKS = {
    "rsa1": RSA_KEY.public_key(),
    "ec1": EC_KEY.public_key(),
    "ed1": ED_KEY.public_key(),
}


def _sign_compact(header: dict, payload: dict, key) -> str:
    hb = _b64u(json.dumps(header, separators=(",", ":")).encode())
    pb = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{hb}.{pb}".encode("ascii")
    alg = header["alg"]
    if alg == "RS256":
        sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "ES256":
        sig = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    elif alg == "EdDSA":
        sig = key.sign(signing_input)
    else:  # for crafting hostile tokens; signature content is irrelevant
        sig = b"\x00" * 32
    return f"{hb}.{pb}.{_b64u(sig)}"


def _claims(**overrides) -> dict:
    now = time.time()
    claims = {
        "iss": ISS,
        "aud": AUD,
        "sub": "user-123",
        "exp": now + 3600,
        "iat": now,
        "nbf": now - 10,
    }
    claims.update(overrides)
    return claims


def _jwt(alg: str, kid: str, key, **claim_overrides) -> str:
    return _sign_compact({"alg": alg, "kid": kid, "typ": "JWT"}, _claims(**claim_overrides), key)


ADAPTER = OidcAdapter(jwks=JWKS, issuer=ISS, audience=AUD)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=True,
        crl_sign=True, encipher_only=False, decipher_only=False,
    )


def _make_ca(cn, key, *, issuer_cert=None, issuer_key=None, days=3650, path_length=None):
    now = datetime.now(timezone.utc)
    subject = _name(cn)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert is not None else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
    )
    return builder.sign(private_key=issuer_key or key, algorithm=hashes.SHA256())


def _make_svid(
    key,
    spiffe_id,
    issuer_cert,
    issuer_key,
    *,
    san=None,
    omit_san: bool = False,
    digital_signature=True,
    include_key_usage=True,
    is_ca=False,
    not_before=None,
    not_after=None,
):
    now = datetime.now(timezone.utc)
    if san is None:
        san = [x509.UniformResourceIdentifier(spiffe_id)]
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name("svid-leaf"))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or (now - timedelta(days=1)))
        .not_valid_after(not_after or (now + timedelta(days=1)))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if include_key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False, encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if san is not None and not omit_san:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


def _pem(*certs) -> str:
    return "".join(c.public_bytes(serialization.Encoding.PEM).decode("ascii") for c in certs)


ROOT_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ROOT_CERT = _make_ca("Test Root CA", ROOT_KEY)
INT_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
INT_CERT = _make_ca("Test Intermediate CA", INT_KEY, issuer_cert=ROOT_CERT, issuer_key=ROOT_KEY)
LEAF_KEY = ec.generate_private_key(ec.SECP256R1())
LEAF_CERT = _make_svid(LEAF_KEY, SPIFFE_ID, INT_CERT, INT_KEY)

SPIFFE_ADAPTER = SpiffeAdapter(trust_bundle=[ROOT_CERT], trust_domain=TRUST_DOMAIN)


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

def test_subject_is_strict_model():
    s = Subject(subject_id="spiffe://x/y", issuer="spiffe://x", claims={"a": 1})
    assert s.subject_id == "spiffe://x/y"
    with pytest.raises(Exception):
        Subject(subject_id="a", issuer="b", claims={}, extra_field="nope")


def test_identity_error_is_value_error():
    assert issubclass(IdentityError, ValueError)


def test_adapter_is_abstract():
    with pytest.raises(TypeError):
        IdentityAdapter()  # type: ignore[abstract]


def test_oidc_rs256_happy_path():
    subject = ADAPTER.authenticate(_jwt("RS256", "rsa1", RSA_KEY))
    assert subject.subject_id == "user-123"
    assert subject.issuer == ISS
    assert subject.claims["sub"] == "user-123"


def test_oidc_es256_happy_path():
    subject = ADAPTER.authenticate(_jwt("ES256", "ec1", EC_KEY))
    assert subject.subject_id == "user-123"


def test_oidc_eddsa_happy_path():
    subject = ADAPTER.authenticate(_jwt("EdDSA", "ed1", ED_KEY))
    assert subject.subject_id == "user-123"


def test_oidc_accepts_bytes_token():
    token = _jwt("RS256", "rsa1", RSA_KEY).encode("ascii")
    assert ADAPTER.authenticate(token).subject_id == "user-123"


def test_oidc_aud_list_containing_pinned_audience():
    token = _jwt("RS256", "rsa1", RSA_KEY, aud=["other", AUD])
    assert ADAPTER.authenticate(token).subject_id == "user-123"


def test_oidc_expired_within_skew_is_accepted():
    token = _jwt("RS256", "rsa1", RSA_KEY, exp=time.time() - 30)  # skew is 60s
    assert ADAPTER.authenticate(token).subject_id == "user-123"


def test_oidc_nbf_within_skew_is_accepted():
    token = _jwt("RS256", "rsa1", RSA_KEY, nbf=time.time() + 30)
    assert ADAPTER.authenticate(token).subject_id == "user-123"


def test_oidc_nbf_absent_is_ok():
    claims = _claims()
    del claims["nbf"]
    token = _sign_compact({"alg": "RS256", "kid": "rsa1"}, claims, RSA_KEY)
    assert ADAPTER.authenticate(token).subject_id == "user-123"


def test_oidc_jwk_dict_form_accepted():
    pub = RSA_KEY.public_key().public_numbers()
    n = _b64u(pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big"))
    e = _b64u(pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big"))
    adapter = OidcAdapter(
        jwks={"rsa-jwk": {"kty": "RSA", "n": n, "e": e}},
        issuer=ISS,
        audience=AUD,
    )
    assert adapter.authenticate(_jwt("RS256", "rsa-jwk", RSA_KEY)).subject_id == "user-123"


def test_oidc_jwk_with_private_material_rejected_at_construction():
    with pytest.raises(IdentityError):
        OidcAdapter(
            jwks={"bad": {"kty": "RSA", "n": "x", "e": "y", "d": "z"}},
            issuer=ISS,
            audience=AUD,
        )


def test_oidc_clock_skew_rejects_nonfinite_and_negative():
    # Integrator footgun: clock_skew=inf silently disables expiry, and NaN
    # silently defeats every time comparison. Both (and negatives, and
    # non-numbers) must fail AT CONSTRUCTION. IdentityError is a ValueError.
    for bad in (float("inf"), float("-inf"), float("nan"), -1, -0.5, "60", None):
        with pytest.raises(ValueError):
            OidcAdapter(jwks=JWKS, issuer=ISS, audience=AUD, clock_skew=bad)


def test_oidc_clock_skew_accepts_zero_and_normal_values():
    # Zero and ordinary positive skews keep working end to end.
    for skew in (0, 60, 120.5):
        adapter = OidcAdapter(jwks=JWKS, issuer=ISS, audience=AUD, clock_skew=skew)
        assert adapter.authenticate(_jwt("EdDSA", "ed1", ED_KEY)).subject_id == "user-123"


def test_entra_accepts_v2_and_v1_issuer_forms():
    tenant = "contoso-tenant-id"
    adapter = EntraAdapter(tenant=tenant, jwks=JWKS, audience=AUD)
    v2 = _jwt("RS256", "rsa1", RSA_KEY, iss=f"https://login.microsoftonline.com/{tenant}/v2.0")
    v1 = _jwt("RS256", "rsa1", RSA_KEY, iss=f"https://sts.windows.net/{tenant}/")
    assert adapter.authenticate(v2).subject_id == "user-123"
    assert adapter.authenticate(v1).subject_id == "user-123"
    assert adapter.authenticate(v2).issuer == f"https://login.microsoftonline.com/{tenant}/v2.0"


def test_okta_issuer_pinned():
    domain = "login.example.okta.com"
    adapter = OktaAdapter(domain=domain, auth_server="default", jwks=JWKS, audience=AUD)
    token = _jwt("RS256", "rsa1", RSA_KEY, iss=f"https://{domain}/oauth2/default")
    assert adapter.authenticate(token).subject_id == "user-123"


def test_spiffe_happy_path_root_intermediate_leaf():
    subject = SPIFFE_ADAPTER.authenticate(_pem(LEAF_CERT, INT_CERT))
    assert subject.subject_id == SPIFFE_ID
    assert subject.issuer == f"spiffe://{TRUST_DOMAIN}"
    assert subject.claims["trust_domain"] == TRUST_DOMAIN
    assert subject.claims["chain_length"] == 3


def test_spiffe_accepts_bytes_and_str():
    pem_bytes = _pem(LEAF_CERT, INT_CERT).encode("ascii")
    assert SPIFFE_ADAPTER.authenticate(pem_bytes).subject_id == SPIFFE_ID


def test_spiffe_leaf_directly_under_root():
    leaf = _make_svid(LEAF_KEY, SPIFFE_ID, ROOT_CERT, ROOT_KEY)
    subject = SPIFFE_ADAPTER.authenticate(_pem(leaf))
    assert subject.subject_id == SPIFFE_ID
    assert subject.claims["chain_length"] == 2


def test_adapters_expose_no_issuance_api():
    for adapter in (
        ADAPTER,
        SPIFFE_ADAPTER,
        EntraAdapter(tenant="t", jwks=JWKS, audience=AUD),
        OktaAdapter(domain="x.okta.com", jwks=JWKS, audience=AUD),
    ):
        for name in ("issue", "mint", "sign", "enroll", "create_token", "generate"):
            assert not hasattr(adapter, name), f"{type(adapter).__name__} exposes {name}"


def test_principal_wires_into_action_envelope():
    subject = ADAPTER.authenticate(_jwt("RS256", "rsa1", RSA_KEY))
    now = datetime.now(timezone.utc)
    env = ActionEnvelope(
        action_id=uuid.uuid4(),
        principal=subject.subject_id,
        effect=Effect(plane="shell", verb="exec", target="t", args_digest="00" * 32),
        policy_ref="constitution-v1",
        issued_at=now,
        not_before=now,
        not_after=now + timedelta(minutes=5),
        nonce="n1",
    )
    assert env.principal == "user-123"


# ---------------------------------------------------------------------------
# Adversarial / attack tests — every one must raise IdentityError
# ---------------------------------------------------------------------------

def test_attack_expired_token():
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(_jwt("RS256", "rsa1", RSA_KEY, exp=time.time() - 3600))


def test_attack_expired_beyond_skew():
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(_jwt("RS256", "rsa1", RSA_KEY, exp=time.time() - 61))


def test_attack_bad_signature():
    token = _jwt("RS256", "rsa1", RSA_KEY)
    head, payload, sig = token.split(".")
    bad_sig = ("A" if sig[0] != "A" else "B") + sig[1:]
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(f"{head}.{payload}.{bad_sig}")


def test_attack_wrong_audience():
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(_jwt("RS256", "rsa1", RSA_KEY, aud="someone-else"))


def test_attack_aud_list_missing_pinned():
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(_jwt("RS256", "rsa1", RSA_KEY, aud=["a", "b"]))


def test_attack_wrong_issuer():
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(_jwt("RS256", "rsa1", RSA_KEY, iss="https://evil.example.com"))


def test_attack_entra_tenant_mismatch():
    adapter = EntraAdapter(tenant="tenant-a", jwks=JWKS, audience=AUD)
    token = _jwt("RS256", "rsa1", RSA_KEY, iss="https://login.microsoftonline.com/tenant-b/v2.0")
    with pytest.raises(IdentityError):
        adapter.authenticate(token)


def test_attack_entra_rejects_wrong_issuer_shape():
    adapter = EntraAdapter(tenant="tenant-a", jwks=JWKS, audience=AUD)
    token = _jwt("RS256", "rsa1", RSA_KEY, iss="https://login.microsoftonline.com/tenant-a/")
    with pytest.raises(IdentityError):
        adapter.authenticate(token)


def test_attack_okta_domain_mismatch():
    adapter = OktaAdapter(domain="login.example.okta.com", jwks=JWKS, audience=AUD)
    token = _jwt("RS256", "rsa1", RSA_KEY, iss="https://login.evil.okta.com/oauth2/default")
    with pytest.raises(IdentityError):
        adapter.authenticate(token)


def test_attack_okta_auth_server_mismatch():
    adapter = OktaAdapter(domain="login.example.okta.com", auth_server="default",
                          jwks=JWKS, audience=AUD)
    token = _jwt("RS256", "rsa1", RSA_KEY, iss="https://login.example.okta.com/oauth2/other")
    with pytest.raises(IdentityError):
        adapter.authenticate(token)


def test_attack_alg_none():
    header = _b64u(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64u(json.dumps(_claims()).encode())
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(f"{header}.{payload}.")


def test_attack_alg_not_in_allowlist():
    token = _sign_compact({"alg": "HS256", "kid": "rsa1"}, _claims(), RSA_KEY)
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(token)


def test_attack_alg_confusion_rs256_with_ec_kid():
    # RS256-signed bytes, but kid resolves to an EC key: must fail closed.
    token = _sign_compact({"alg": "RS256", "kid": "ec1"}, _claims(), RSA_KEY)
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(token)


def test_attack_alg_confusion_es256_with_rsa_kid():
    token = _sign_compact({"alg": "ES256", "kid": "rsa1"}, _claims(), EC_KEY)
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(token)


def test_attack_alg_confusion_eddsa_with_rsa_kid():
    token = _sign_compact({"alg": "EdDSA", "kid": "rsa1"}, _claims(), ED_KEY)
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(token)


def test_attack_kid_not_in_jwks():
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(_jwt("RS256", "unknown-kid", RSA_KEY))


def test_attack_missing_kid():
    token = _sign_compact({"alg": "RS256"}, _claims(), RSA_KEY)
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(token)


def test_attack_token_used_before_nbf():
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(_jwt("RS256", "rsa1", RSA_KEY, nbf=time.time() + 3600))


def test_attack_tampered_sub_keeps_old_signature():
    token = _jwt("RS256", "rsa1", RSA_KEY)
    head, payload_b64, sig = token.split(".")
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded).decode())
    payload["sub"] = "admin-root"
    new_payload_b64 = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(f"{head}.{new_payload_b64}.{sig}")


def test_attack_signature_from_another_key():
    # Signed by the attacker's key but presented under the victim's kid.
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(_jwt("RS256", "rsa1", RSA_KEY2))


def test_attack_embedded_jwk_header_rejected():
    header = {"alg": "RS256", "kid": "rsa1", "jwk": {"kty": "RSA", "n": "x", "e": "y"}}
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(_sign_compact(header, _claims(), RSA_KEY))


def test_attack_x5u_header_rejected():
    header = {"alg": "RS256", "kid": "rsa1", "x5u": "https://evil.example.com/keys.json"}
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(_sign_compact(header, _claims(), RSA_KEY))


def test_attack_crit_header_rejected():
    header = {"alg": "RS256", "kid": "rsa1", "crit": ["exp2"], "exp2": 999}
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(_sign_compact(header, _claims(), RSA_KEY))


def test_attack_missing_exp():
    claims = _claims()
    del claims["exp"]
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(_sign_compact({"alg": "RS256", "kid": "rsa1"}, claims, RSA_KEY))


def test_attack_non_numeric_exp():
    claims = _claims(exp="tomorrow")
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(_sign_compact({"alg": "RS256", "kid": "rsa1"}, claims, RSA_KEY))


def test_attack_missing_iat():
    claims = _claims()
    del claims["iat"]
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(_sign_compact({"alg": "RS256", "kid": "rsa1"}, claims, RSA_KEY))


def test_attack_iat_in_future_beyond_skew():
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(_jwt("RS256", "rsa1", RSA_KEY, iat=time.time() + 3600))


def test_attack_missing_sub():
    claims = _claims()
    del claims["sub"]
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(_sign_compact({"alg": "RS256", "kid": "rsa1"}, claims, RSA_KEY))


def test_attack_weak_rsa_key_rejected_at_construction():
    with pytest.raises(IdentityError):
        OidcAdapter(jwks={"weak": RSA_WEAK.public_key()}, issuer=ISS, audience=AUD)


def test_attack_malformed_tokens():
    for bad in ("", "abc", "a.b", "a.b.c.d", "..", "\xff\xfe binary"):
        with pytest.raises(IdentityError):
            ADAPTER.authenticate(bad)


def test_attack_non_ascii_bytes():
    with pytest.raises(IdentityError):
        ADAPTER.authenticate("é".encode("utf-8"))


def test_attack_svid_chain_to_untrusted_root():
    evil_root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    evil_root = _make_ca("Evil Root CA", evil_root_key)
    evil_int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    evil_int = _make_ca("Evil Intermediate", evil_int_key,
                        issuer_cert=evil_root, issuer_key=evil_root_key)
    evil_leaf = _make_svid(LEAF_KEY, SPIFFE_ID, evil_int, evil_int_key)
    # Evil root deliberately NOT in the token: chain cannot terminate in trust.
    with pytest.raises(IdentityError):
        SPIFFE_ADAPTER.authenticate(_pem(evil_leaf, evil_int))


def test_attack_svid_lookalike_root_same_dn_rejected():
    # Attacker copies the trusted root's subject DN but uses their own key.
    # Fingerprint pinning must still reject the chain.
    fake_root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    fake_root = _make_ca("Test Root CA", fake_root_key)  # same CN, different key
    fake_int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    fake_int = _make_ca("Fake Intermediate", fake_int_key,
                        issuer_cert=fake_root, issuer_key=fake_root_key)
    fake_leaf = _make_svid(LEAF_KEY, SPIFFE_ID, fake_int, fake_int_key)
    with pytest.raises(IdentityError):
        SPIFFE_ADAPTER.authenticate(_pem(fake_leaf, fake_int, fake_root))


def test_attack_svid_wrong_trust_domain():
    leaf = _make_svid(LEAF_KEY, "spiffe://evil.test/ns/x", INT_CERT, INT_KEY)
    with pytest.raises(IdentityError):
        SPIFFE_ADAPTER.authenticate(_pem(leaf, INT_CERT))


def test_attack_svid_missing_uri_san():
    leaf = _make_svid(LEAF_KEY, SPIFFE_ID, INT_CERT, INT_KEY,
                      san=[x509.DNSName("example.org")])
    with pytest.raises(IdentityError):
        SPIFFE_ADAPTER.authenticate(_pem(leaf, INT_CERT))


def test_attack_svid_no_san_extension():
    leaf = _make_svid(LEAF_KEY, SPIFFE_ID, INT_CERT, INT_KEY, omit_san=True)
    with pytest.raises(IdentityError):
        SPIFFE_ADAPTER.authenticate(_pem(leaf, INT_CERT))


def test_attack_svid_expired_leaf():
    now = datetime.now(timezone.utc)
    leaf = _make_svid(
        LEAF_KEY, SPIFFE_ID, INT_CERT, INT_KEY,
        not_before=now - timedelta(days=2), not_after=now - timedelta(days=1),
    )
    with pytest.raises(IdentityError):
        SPIFFE_ADAPTER.authenticate(_pem(leaf, INT_CERT))


def test_attack_svid_leaf_without_digital_signature_key_usage():
    leaf = _make_svid(LEAF_KEY, SPIFFE_ID, INT_CERT, INT_KEY, digital_signature=False)
    with pytest.raises(IdentityError):
        SPIFFE_ADAPTER.authenticate(_pem(leaf, INT_CERT))


def test_attack_svid_leaf_missing_key_usage():
    leaf = _make_svid(LEAF_KEY, SPIFFE_ID, INT_CERT, INT_KEY, include_key_usage=False)
    with pytest.raises(IdentityError):
        SPIFFE_ADAPTER.authenticate(_pem(leaf, INT_CERT))


def test_attack_svid_leaf_marked_as_ca():
    leaf = _make_svid(LEAF_KEY, SPIFFE_ID, INT_CERT, INT_KEY, is_ca=True)
    with pytest.raises(IdentityError):
        SPIFFE_ADAPTER.authenticate(_pem(leaf, INT_CERT))


def test_attack_svid_intermediate_signature_tampered():
    # Intermediate carries the right subject DN but the attacker's key, so the
    # leaf's signature cannot verify against it.
    evil_int_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    evil_int = _make_ca("Test Intermediate CA", evil_int_key,
                        issuer_cert=ROOT_CERT, issuer_key=ROOT_KEY)
    with pytest.raises(IdentityError):
        SPIFFE_ADAPTER.authenticate(_pem(LEAF_CERT, evil_int))


def test_attack_svid_garbage_pem():
    with pytest.raises(IdentityError):
        SPIFFE_ADAPTER.authenticate("not a certificate at all")


def test_attack_spiffe_trust_domain_with_scheme_rejected():
    with pytest.raises(IdentityError):
        SpiffeAdapter(trust_bundle=[ROOT_CERT], trust_domain="spiffe://example.org")


def test_attack_entra_tenant_with_slash_rejected():
    with pytest.raises(IdentityError):
        EntraAdapter(tenant="../evil", jwks=JWKS, audience=AUD)


# ---------------------------------------------------------------------------
# RT-005 regression: X.509 BasicConstraints.path_length enforcement
# (RFC 5280 S4.2.1.9). An intermediate with path_length=N may have at most N
# CA certificates below it; absent path_length means unconstrained.
# ---------------------------------------------------------------------------

def _rsa_ca_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def test_attack_svid_pathlen_zero_intermediate_issues_sub_ca_rejected():
    # Exact RT-005 construction: root(pathlen=1) -> mid(pathlen=0) ->
    # sub-CA (no pathlen) -> leaf. The sub-CA beneath mid violates mid's
    # path_length=0 budget, so the chain must be rejected.
    root_key = _rsa_ca_key()
    root = _make_ca("RT005 Root", root_key, path_length=1)
    mid_key = _rsa_ca_key()
    mid = _make_ca("RT005 Mid", mid_key, issuer_cert=root, issuer_key=root_key,
                   path_length=0)
    sub_key = _rsa_ca_key()
    sub = _make_ca("RT005 Sub CA", sub_key, issuer_cert=mid, issuer_key=mid_key)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _make_svid(leaf_key, SPIFFE_ID, sub, sub_key)
    adapter = SpiffeAdapter(trust_bundle=[root], trust_domain=TRUST_DOMAIN)
    with pytest.raises(IdentityError):
        adapter.authenticate(_pem(leaf, sub, mid))


def test_attack_svid_pathlen_budget_exceeded_deeper_rejected():
    # root -> mid(pathlen=1) -> sub1 -> sub2 -> leaf: two CAs below mid.
    root_key = _rsa_ca_key()
    root = _make_ca("RT005b Root", root_key)
    mid_key = _rsa_ca_key()
    mid = _make_ca("RT005b Mid", mid_key, issuer_cert=root, issuer_key=root_key,
                   path_length=1)
    sub1_key = _rsa_ca_key()
    sub1 = _make_ca("RT005b Sub1", sub1_key, issuer_cert=mid, issuer_key=mid_key)
    sub2_key = _rsa_ca_key()
    sub2 = _make_ca("RT005b Sub2", sub2_key, issuer_cert=sub1, issuer_key=sub1_key)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _make_svid(leaf_key, SPIFFE_ID, sub2, sub2_key)
    adapter = SpiffeAdapter(trust_bundle=[root], trust_domain=TRUST_DOMAIN)
    with pytest.raises(IdentityError):
        adapter.authenticate(_pem(leaf, sub2, sub1, mid))


def test_svid_deep_chain_within_pathlen_budget_verifies():
    # root -> int1(pathlen=1) -> int2(pathlen=0) -> leaf: exactly one CA
    # below int1 (budget 1) and none below int2 (budget 0). Must verify.
    root_key = _rsa_ca_key()
    root = _make_ca("PL Root", root_key, path_length=2)
    int1_key = _rsa_ca_key()
    int1 = _make_ca("PL Int1", int1_key, issuer_cert=root, issuer_key=root_key,
                    path_length=1)
    int2_key = _rsa_ca_key()
    int2 = _make_ca("PL Int2", int2_key, issuer_cert=int1, issuer_key=int1_key,
                    path_length=0)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _make_svid(leaf_key, SPIFFE_ID, int2, int2_key)
    adapter = SpiffeAdapter(trust_bundle=[root], trust_domain=TRUST_DOMAIN)
    subject = adapter.authenticate(_pem(leaf, int2, int1))
    assert subject.subject_id == SPIFFE_ID


def test_svid_pathlen_zero_intermediate_issuing_leaf_verifies():
    # root -> mid(pathlen=0) -> leaf: no CA below mid, so the budget is
    # satisfied and the SVID must verify.
    root_key = _rsa_ca_key()
    root = _make_ca("PL0 Root", root_key)
    mid_key = _rsa_ca_key()
    mid = _make_ca("PL0 Mid", mid_key, issuer_cert=root, issuer_key=root_key,
                   path_length=0)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _make_svid(leaf_key, SPIFFE_ID, mid, mid_key)
    adapter = SpiffeAdapter(trust_bundle=[root], trust_domain=TRUST_DOMAIN)
    subject = adapter.authenticate(_pem(leaf, mid))
    assert subject.subject_id == SPIFFE_ID


def test_svid_absent_pathlen_on_intermediate_is_unconstrained():
    # root -> mid (no pathlen) -> sub (no pathlen) -> leaf: missing
    # path_length on a non-self-signed intermediate means unconstrained.
    root_key = _rsa_ca_key()
    root = _make_ca("U Root", root_key)
    mid_key = _rsa_ca_key()
    mid = _make_ca("U Mid", mid_key, issuer_cert=root, issuer_key=root_key)
    sub_key = _rsa_ca_key()
    sub = _make_ca("U Sub", sub_key, issuer_cert=mid, issuer_key=mid_key)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _make_svid(leaf_key, SPIFFE_ID, sub, sub_key)
    adapter = SpiffeAdapter(trust_bundle=[root], trust_domain=TRUST_DOMAIN)
    subject = adapter.authenticate(_pem(leaf, sub, mid))
    assert subject.subject_id == SPIFFE_ID


# ---------------------------------------------------------------------------
# RT-008 regression: non-finite numeric JWT claims (exp/iat/nbf).
# A non-finite exp (Infinity) compares greater than any clock time and would
# never expire; NaN would defeat every comparison. All must fail closed.
# ---------------------------------------------------------------------------

def test_attack_oidc_exp_infinity_rejected():
    # json round-trips Infinity, so the signed token parses fine; the guard
    # must live in claim parsing, not JSON decoding.
    token = _jwt("RS256", "rsa1", RSA_KEY, exp=float("inf"))
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(token)


def test_attack_oidc_exp_nan_rejected():
    token = _jwt("RS256", "rsa1", RSA_KEY, exp=float("nan"))
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(token)


def test_attack_oidc_iat_infinity_rejected():
    token = _jwt("RS256", "rsa1", RSA_KEY, iat=float("inf"))
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(token)


def test_attack_oidc_iat_negative_infinity_rejected():
    # -inf would pass the "iat not in the future" check; it must still be
    # rejected as a non-finite claim value.
    token = _jwt("RS256", "rsa1", RSA_KEY, iat=float("-inf"))
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(token)


def test_attack_oidc_nbf_negative_infinity_rejected():
    # -inf passes the "nbf not in the future" check, so without the finiteness
    # guard this token would be accepted.
    token = _jwt("RS256", "rsa1", RSA_KEY, nbf=float("-inf"))
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(token)


def test_attack_oidc_nbf_infinity_rejected():
    token = _jwt("RS256", "rsa1", RSA_KEY, nbf=float("inf"))
    with pytest.raises(IdentityError):
        ADAPTER.authenticate(token)


def test_oidc_finite_float_exp_still_accepted():
    token = _jwt("RS256", "rsa1", RSA_KEY, exp=time.time() + 3600.5)
    assert ADAPTER.authenticate(token).subject_id == "user-123"


# ---------------------------------------------------------------------------
# FIX-B2 regression: clock_skew must have a sane upper bound. A huge finite
# skew (e.g. 10**18) passes the finite->=0 check but makes exp > now - skew
# always true, so an EXPIRED token (and a token with nbf a year in the future)
# would authenticate — the same footgun as clock_skew=inf. The bound is
# 86400s (24h): skew absorbs clock drift measured in seconds-to-minutes, so
# anything larger silently disables the lifetime checks.
# ---------------------------------------------------------------------------

def test_fixb2_clock_skew_above_24h_rejected_at_construction():
    for bad in (10**18, 86401, 10**9, 86400.5):
        with pytest.raises(ValueError):
            OidcAdapter(jwks=JWKS, issuer=ISS, audience=AUD, clock_skew=bad)


def test_fixb2_clock_skew_at_24h_boundary_constructs():
    adapter = OidcAdapter(jwks=JWKS, issuer=ISS, audience=AUD, clock_skew=86400)
    assert adapter.authenticate(_jwt("EdDSA", "ed1", ED_KEY)).subject_id == "user-123"


def test_fixb2_subclass_inherits_skew_cap():
    # The cap lives in OidcAdapter.__init__; Entra/Okta route through it via
    # super().__init__, so a huge skew must fail at construction on subclasses.
    with pytest.raises(ValueError):
        EntraAdapter(tenant="t", jwks=JWKS, audience=AUD, clock_skew=10**18)
    with pytest.raises(ValueError):
        OktaAdapter(domain="x.okta.com", jwks=JWKS, audience=AUD, clock_skew=10**18)
    # And the boundary value is accepted on subclasses too.
    adapter = OktaAdapter(domain="x.okta.com", jwks=JWKS, audience=AUD, clock_skew=86400)
    token = _jwt("RS256", "rsa1", RSA_KEY, iss="https://x.okta.com/oauth2/default")
    assert adapter.authenticate(token).subject_id == "user-123"


def test_fixb2_expired_token_rejected_with_largest_allowed_skew():
    # exp 1h ago with the maximum legal skew (1h): exp == now - skew, and the
    # check is `exp > now - skew` (strict), so this must be rejected.
    adapter = OidcAdapter(jwks=JWKS, issuer=ISS, audience=AUD, clock_skew=3600)
    with pytest.raises(IdentityError):
        adapter.authenticate(_jwt("RS256", "rsa1", RSA_KEY, exp=time.time() - 3600))


def test_fixb2_far_future_nbf_rejected_with_large_skew():
    # nbf a year in the future must still be rejected even with a 1h skew.
    adapter = OidcAdapter(jwks=JWKS, issuer=ISS, audience=AUD, clock_skew=3600)
    with pytest.raises(IdentityError):
        adapter.authenticate(
            _jwt("RS256", "rsa1", RSA_KEY, nbf=time.time() + 365 * 86400)
        )


def test_fixb2_within_skew_tokens_still_accepted():
    adapter = OidcAdapter(jwks=JWKS, issuer=ISS, audience=AUD, clock_skew=60)
    assert adapter.authenticate(_jwt("RS256", "rsa1", RSA_KEY, exp=time.time() - 30)).subject_id == "user-123"
    assert adapter.authenticate(_jwt("RS256", "rsa1", RSA_KEY, nbf=time.time() + 30)).subject_id == "user-123"
