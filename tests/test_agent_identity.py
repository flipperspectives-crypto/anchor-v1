"""ANCHOR v1 — agent identity tests (BUILDER D).

Unit tests cover the happy paths; adversarial tests attack every fail-closed
claim in the spec. Each attack test asserts that the malicious input is
REJECTED (raises AgentIdentityError or returns False) — never silently
accepted.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from anchor_v1.agent_identity import (
    AgentIdentityError,
    AgentRegistry,
    AssertionPayload,
    CapabilityPattern,
    DIDDocument,
    PatternError,
    authorize_capability_claim,
    base58_decode,
    base58_encode,
    did_for_pubkey,
    issue_assertion,
    resolve_did,
    subject_id_for,
    verify_assertion,
)
from anchor_v1.canonical import canonical_bytes
from anchor_v1.cose import cose_sign_bytes
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.envelope import ActionEnvelope, Effect

NOW = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)


def _signer(key_id: str = "k1") -> Ed25519Signer:
    return Ed25519Signer.generate(key_id)


def _caps() -> list[CapabilityPattern]:
    return [
        CapabilityPattern(plane="shell", verb="exec", target_pattern="/bin/*"),
        CapabilityPattern(plane="http", verb="post", target_pattern="https://api.example.com/**", max_spend=25.0),
    ]


def _self_assertion(signer: Ed25519Signer, now: datetime = NOW, ttl=timedelta(hours=1)):
    did = did_for_pubkey(signer.public_key_bytes())
    message = issue_assertion(signer, did, did, _caps(), issued_at=now, ttl=ttl)
    return did, message


def _registered(did: str, message: bytes, trusted: set[str] | None = None, now: datetime = NOW):
    registry = AgentRegistry(trusted_attesters=trusted)
    registry.register(did, resolve_did(did), [message], now=now)
    return registry


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------


def test_did_roundtrip_and_document_fields():
    signer = _signer()
    did = did_for_pubkey(signer.public_key_bytes())
    assert did.startswith("did:key:z")
    doc = resolve_did(did)
    assert isinstance(doc, DIDDocument)
    assert doc.id == did
    assert len(doc.verificationMethod) == 1
    vm = doc.verificationMethod[0]
    assert vm.type == "Ed25519VerificationKey2020"
    assert vm.controller == did
    assert vm.publicKeyMultibase.startswith("z")
    assert vm.id in doc.authentication
    # The document's multibase key decodes back to the signer's public key.
    assert base58_decode(vm.publicKeyMultibase[1:])[2:] == signer.public_key_bytes()


def test_base58_roundtrip_preserves_leading_zeros():
    raw = b"\x00\x00\x01\x02\xff" + bytes(range(32))
    assert base58_decode(base58_encode(raw)) == raw


def test_self_assertion_verify_happy_path():
    signer = _signer()
    did, message = _self_assertion(signer)
    payload = verify_assertion(message, now=NOW)
    assert isinstance(payload, AssertionPayload)
    assert payload.did == did
    assert payload.attester_did == did
    assert payload.assertion_id
    assert len(payload.capabilities) == 2
    assert payload.capabilities[1].max_spend == 25.0
    assert payload.issued_at <= NOW < payload.expires_at


def test_registry_register_resolve_and_authorize_happy_path():
    signer = _signer()
    did, message = _self_assertion(signer)
    registry = _registered(did, message)
    identity = registry.resolve(did, now=NOW)
    assert identity.did == did
    assert identity.document.id == did
    assert len(identity.assertions) == 1
    # Wildcard pattern match authorizes; subject id binds to the envelope.
    assert authorize_capability_claim(did, "shell", "exec", "/bin/ls", registry, now=NOW)
    assert authorize_capability_claim(did, "http", "post", "https://api.example.com/v1/jobs", registry, now=NOW)
    assert subject_id_for(did) == did
    envelope = ActionEnvelope(
        action_id="12345678-1234-5678-1234-567812345678",
        principal=subject_id_for(did),
        effect=Effect(plane="shell", verb="exec", target="/bin/ls", args_digest="ab" * 32),
        policy_ref="test",
        issued_at=NOW,
        not_before=NOW,
        not_after=NOW + timedelta(minutes=5),
        nonce="n1",
    )
    assert envelope.principal == did


def test_third_party_assertion_accepted_when_attester_trusted():
    subject = _signer("subject")
    attester = _signer("attester")
    subject_did = did_for_pubkey(subject.public_key_bytes())
    attester_did = did_for_pubkey(attester.public_key_bytes())
    message = issue_assertion(
        attester, attester_did, subject_did, _caps(), issued_at=NOW, ttl=timedelta(hours=1)
    )
    payload = verify_assertion(message, trusted_attesters={attester_did}, now=NOW)
    assert payload.attester_did == attester_did
    assert payload.did == subject_did
    registry = _registered(subject_did, message, trusted={attester_did})
    assert authorize_capability_claim(subject_did, "shell", "exec", "/bin/true", registry, now=NOW)


def test_issue_assertion_rejects_attester_did_key_mismatch():
    signer = _signer()
    other = _signer("other")
    other_did = did_for_pubkey(other.public_key_bytes())
    with pytest.raises(AgentIdentityError):
        issue_assertion(signer, other_did, other_did, _caps(), issued_at=NOW)


def test_revoke_unknown_assertion_id_raises():
    registry = AgentRegistry()
    with pytest.raises(AgentIdentityError):
        registry.revoke_assertion("no-such-assertion")


# ---------------------------------------------------------------------------
# Adversarial tests (fail-closed claims)
# ---------------------------------------------------------------------------


def test_attack_assertion_signed_by_different_key_than_did():
    """An attacker signs an assertion about the victim's DID with the
    attacker's own key. The attester is neither the subject nor trusted, so
    verification must fail."""
    victim = _signer("victim")
    attacker = _signer("attacker")
    victim_did = did_for_pubkey(victim.public_key_bytes())
    attacker_did = did_for_pubkey(attacker.public_key_bytes())
    forged = issue_assertion(
        attacker, attacker_did, victim_did, _caps(), issued_at=NOW, ttl=timedelta(hours=1)
    )
    with pytest.raises(AgentIdentityError):
        verify_assertion(forged, now=NOW)
    # ...and the registry refuses to store it under the victim's DID.
    with pytest.raises(AgentIdentityError):
        _registered(victim_did, forged)


def test_attack_kid_claims_victim_did_but_attacker_signed():
    """Attacker crafts COSE with kid=victim DID but signs with their own key.
    Signature verification against the victim's key must fail."""
    victim = _signer("victim")
    attacker = _signer("attacker")
    victim_did = did_for_pubkey(victim.public_key_bytes())
    payload = AssertionPayload(
        did=victim_did,
        capabilities=_caps(),
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        assertion_id="forged-1",
        attester_did=victim_did,  # lies about who signed
    )
    forged = cose_sign_bytes(
        canonical_bytes(payload.model_dump(mode="json")),
        attacker.sign_bytes,  # wrong key
        victim_did.encode("utf-8"),
    )
    with pytest.raises(AgentIdentityError):
        verify_assertion(forged, now=NOW)


def test_attack_kid_attester_mismatch_replay():
    """Valid signature by key B, but payload names attester A: kid/attester
    binding must reject the DID replay."""
    signer_a = _signer("a")
    signer_b = _signer("b")
    did_a = did_for_pubkey(signer_a.public_key_bytes())
    did_b = did_for_pubkey(signer_b.public_key_bytes())
    payload = AssertionPayload(
        did=did_a,
        capabilities=_caps(),
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        assertion_id="replay-1",
        attester_did=did_a,  # payload claims A attested...
    )
    forged = cose_sign_bytes(
        canonical_bytes(payload.model_dump(mode="json")),
        signer_b.sign_bytes,  # ...but B signed, with B's kid
        did_b.encode("utf-8"),
    )
    with pytest.raises(AgentIdentityError):
        verify_assertion(forged, trusted_attesters={did_a, did_b}, now=NOW)


def test_attack_expired_assertion_resolves_as_invalid():
    signer = _signer()
    did, message = _self_assertion(signer, now=NOW, ttl=timedelta(minutes=1))
    with pytest.raises(AgentIdentityError):
        verify_assertion(message, now=NOW + timedelta(hours=2))
    registry = _registered(did, message)  # registered while live...
    identity = registry.resolve(did, now=NOW + timedelta(hours=2))  # ...but dead later
    assert identity.assertions == []
    assert not authorize_capability_claim(did, "shell", "exec", "/bin/ls", registry, now=NOW + timedelta(hours=2))


def test_attack_revoked_assertion_never_resolves():
    signer = _signer()
    did, message = _self_assertion(signer)
    payload = verify_assertion(message, now=NOW)
    registry = _registered(did, message)
    assert authorize_capability_claim(did, "shell", "exec", "/bin/ls", registry, now=NOW)
    registry.revoke_assertion(payload.assertion_id)
    identity = registry.resolve(did, now=NOW)
    assert identity.assertions == []
    assert not authorize_capability_claim(did, "shell", "exec", "/bin/ls", registry, now=NOW)


def test_attack_assertion_replayed_under_different_did():
    """A valid self-assertion for DID A is submitted for registration under
    DID B. Subject/DID binding must reject it."""
    signer_a = _signer("a")
    signer_b = _signer("b")
    did_a = did_for_pubkey(signer_a.public_key_bytes())
    did_b = did_for_pubkey(signer_b.public_key_bytes())
    _, message_a = _self_assertion(signer_a)
    registry = AgentRegistry()
    with pytest.raises(AgentIdentityError):
        registry.register(did_b, resolve_did(did_b), [message_a], now=NOW)
    assert did_b not in registry


def test_star_does_not_cross_path_separator_but_double_star_does():
    """``/bin/*`` must not cover ``/bin/../etc/shadow`` (traversal), while an
    explicit ``**`` pattern does cover multi-segment targets."""
    from anchor_v1.agent_identity import _target_matches

    assert _target_matches("/bin/*", "/bin/ls")
    assert not _target_matches("/bin/*", "/bin/../etc/shadow")
    assert not _target_matches("/bin/*", "/bin/sub/ls")
    assert _target_matches("/bin/**", "/bin/sub/ls")
    assert _target_matches("https://api.example.com/**", "https://api.example.com/v1/jobs")
    assert not _target_matches("https://api.example.com/*", "https://api.example.com/v1/jobs")
    assert _target_matches("/tmp/file?.txt", "/tmp/file1.txt")
    assert not _target_matches("/tmp/file?.txt", "/tmp/file12.txt")
    assert _target_matches("/data/[0-9]*", "/data/42")
    assert not _target_matches("/data/[0-9]*", "/data/x")


def test_attack_capability_claim_outside_asserted_patterns():
    signer = _signer()
    did, message = _self_assertion(signer)
    registry = _registered(did, message)
    # Wrong verb, wrong plane, and target outside the glob pattern.
    assert not authorize_capability_claim(did, "shell", "write", "/bin/ls", registry, now=NOW)
    assert not authorize_capability_claim(did, "http", "exec", "/bin/ls", registry, now=NOW)
    assert not authorize_capability_claim(did, "shell", "exec", "/etc/passwd", registry, now=NOW)
    assert not authorize_capability_claim(did, "shell", "exec", "/bin/../etc/shadow", registry, now=NOW)
    # Unknown DID fails closed too.
    assert not authorize_capability_claim(did_for_pubkey(_signer("x").public_key_bytes()),
                                          "shell", "exec", "/bin/ls", registry, now=NOW)


def test_attack_registry_entry_tampered_doc_hash_mismatch():
    """An attacker mutates the stored DID document in place. The stored doc
    hash must detect it on the next resolve."""
    signer = _signer()
    did, message = _self_assertion(signer)
    registry = _registered(did, message)
    entry = registry._entries[did]
    entry["doc"] = entry["doc"].model_copy(update={"id": did_for_pubkey(_signer("evil").public_key_bytes())})
    with pytest.raises(AgentIdentityError, match="tampered"):
        registry.resolve(did, now=NOW)
    assert not authorize_capability_claim(did, "shell", "exec", "/bin/ls", registry, now=NOW)


def test_attack_registry_document_must_match_did():
    signer = _signer()
    did, message = _self_assertion(signer)
    registry = AgentRegistry()
    forged_doc = resolve_did(did_for_pubkey(_signer("evil").public_key_bytes()))
    with pytest.raises(AgentIdentityError):
        registry.register(did, forged_doc, [message], now=NOW)
    assert did not in registry


@pytest.mark.parametrize(
    "make_bad_did",
    [
        # Bad multibase character ('0' is not in the base58 alphabet).
        lambda good: good[:-1] + "0",
        # Wrong multicodec prefix (0xec01 instead of 0xed01).
        lambda good: "did:key:z" + base58_encode(b"\xec\x01" + base58_decode(good[8:])[2:]),
        # Truncated key (31 bytes instead of 32).
        lambda good: "did:key:z" + base58_encode(b"\xed\x01" + base58_decode(good[8:])[2:31]),
        # Padded key (33 bytes).
        lambda good: "did:key:z" + base58_encode(b"\xed\x01" + base58_decode(good[8:])[2:] + b"\x00"),
        # Method mismatch.
        lambda good: "did:example:z" + good[8:],
        # Multibase mismatch (not base58btc).
        lambda good: "did:key:f" + good[8:],
        # Truncated DID string.
        lambda good: good[:-4],
    ],
    ids=["bad-multibase-char", "wrong-multicodec-prefix", "truncated-key",
         "padded-key", "method-mismatch", "multibase-mismatch", "truncated-did"],
)
def test_attack_malformed_dids_rejected(make_bad_did):
    good = did_for_pubkey(_signer().public_key_bytes())
    bad = make_bad_did(good)
    with pytest.raises(AgentIdentityError):
        resolve_did(bad)
    with pytest.raises(AgentIdentityError):
        subject_id_for(bad)


def test_attack_third_party_attester_not_in_trusted_set():
    """A correctly-signed third-party assertion is worthless when the
    attester is not trusted — it must be rejected, not treated as authority."""
    subject = _signer("subject")
    stranger = _signer("stranger")
    subject_did = did_for_pubkey(subject.public_key_bytes())
    stranger_did = did_for_pubkey(stranger.public_key_bytes())
    message = issue_assertion(
        stranger, stranger_did, subject_did, _caps(), issued_at=NOW, ttl=timedelta(hours=1)
    )
    with pytest.raises(AgentIdentityError, match="not in trusted set"):
        verify_assertion(message, now=NOW)
    with pytest.raises(AgentIdentityError):
        _registered(subject_did, message, trusted=set())


def test_attack_tampered_cose_payload_rejected():
    """Flipping a byte anywhere in the COSE message breaks the signature."""
    signer = _signer()
    _, message = _self_assertion(signer)
    tampered = bytearray(message)
    tampered[len(tampered) // 2] ^= 0x01
    with pytest.raises(AgentIdentityError):
        verify_assertion(bytes(tampered), now=NOW)


def test_attack_non_canonical_payload_rejected():
    """Re-serializing the payload with non-canonical JSON (extra whitespace)
    breaks both the signature and the canonical-form check."""
    signer = _signer()
    did = did_for_pubkey(signer.public_key_bytes())
    payload = AssertionPayload(
        did=did,
        capabilities=_caps(),
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        assertion_id="malleable-1",
        attester_did=did,
    )
    non_canonical = json.dumps(
        payload.model_dump(mode="json"), indent=2, sort_keys=False
    ).encode("utf-8")
    forged = cose_sign_bytes(non_canonical, signer.sign_bytes, did.encode("utf-8"))
    with pytest.raises(AgentIdentityError):
        verify_assertion(forged, now=NOW)


def test_attack_assertion_not_yet_valid():
    signer = _signer()
    did = did_for_pubkey(signer.public_key_bytes())
    message = issue_assertion(
        signer, did, did, _caps(), issued_at=NOW + timedelta(hours=1), ttl=timedelta(hours=1)
    )
    with pytest.raises(AgentIdentityError, match="not yet valid"):
        verify_assertion(message, now=NOW)


def test_attack_unknown_did_and_kid_rejected():
    # Resolving an unknown DID raises; a COSE kid that is not a DID raises.
    with pytest.raises(AgentIdentityError):
        AgentRegistry().resolve(did_for_pubkey(_signer().public_key_bytes()), now=NOW)
    signer = _signer()
    forged = cose_sign_bytes(b"{}", signer.sign_bytes, b"not-a-did")
    with pytest.raises(AgentIdentityError):
        verify_assertion(forged, now=NOW)


# ---------------------------------------------------------------------------
# FIX-D regression tests: AI-N3 (non-finite floats), AI-N4 (ReDoS), AI-N2 ([!x])
# ---------------------------------------------------------------------------


def _nonfinite_assertion_message(
    signer: Ed25519Signer,
    spend: float,
    now: datetime = NOW,
    target_pattern: str = "https://api.example.com/**",
):
    """Hand-roll a validly self-signed assertion whose max_spend is inf/nan,
    bypassing model validation (raw dict -> allow_nan JSON -> COSE sign)."""
    did = did_for_pubkey(signer.public_key_bytes())
    raw = {
        "did": did,
        "capabilities": [
            {
                "plane": "http",
                "verb": "post",
                "target_pattern": target_pattern,
                "max_spend": spend,
            }
        ],
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "assertion_id": "nonfinite-1",
        "attester_did": did,
    }
    payload_bytes = json.dumps(raw, allow_nan=True).encode("utf-8")
    message = cose_sign_bytes(payload_bytes, signer.sign_bytes, did.encode("utf-8"))
    return did, message


@pytest.mark.parametrize(
    "spend", [float("inf"), float("-inf"), float("nan")], ids=["inf", "-inf", "nan"]
)
def test_attack_nonfinite_max_spend_verify_raises_agent_identity_error(spend):
    """AI-N3: a validly self-signed assertion with non-finite max_spend must
    raise AgentIdentityError — never a raw ValueError from canonicalization."""
    signer = _signer()
    _, message = _nonfinite_assertion_message(signer, spend)
    with pytest.raises(AgentIdentityError):
        verify_assertion(message, now=NOW)


@pytest.mark.parametrize(
    "spend", [float("inf"), float("-inf"), float("nan")], ids=["inf", "-inf", "nan"]
)
def test_attack_nonfinite_float_rejected_at_model_validation(spend):
    """AI-N3a: any float field must be math.isfinite — rejected by the model."""
    with pytest.raises(ValidationError):
        CapabilityPattern(
            plane="http",
            verb="post",
            target_pattern="https://api.example.com/**",
            max_spend=spend,
        )


def test_attack_nonfinite_payload_canonical_check_never_leaks_raw_valueerror(monkeypatch):
    """AI-N3b: if canonical_bytes raises a raw ValueError, verify_assertion
    converts it to AgentIdentityError instead of letting it escape."""
    import anchor_v1.agent_identity as mod

    signer = _signer()
    _, message = _self_assertion(signer)

    def boom(_value):
        raise ValueError("Out of range float values are not JSON compliant")

    monkeypatch.setattr(mod, "canonical_bytes", boom)
    with pytest.raises(AgentIdentityError):
        verify_assertion(message, now=NOW)


@pytest.mark.parametrize("spend", [float("inf"), float("nan")], ids=["inf", "nan"])
def test_attack_nonfinite_assertion_register_raises_agent_identity_error(spend):
    """AI-N3c: register() must raise AgentIdentityError (not raw ValueError)
    and store nothing."""
    signer = _signer()
    did, message = _nonfinite_assertion_message(signer, spend)
    registry = AgentRegistry()
    with pytest.raises(AgentIdentityError):
        registry.register(did, resolve_did(did), [message], now=NOW)
    assert did not in registry


def test_attack_nonfinite_assertion_authorize_returns_false_never_raises():
    """AI-N3c: authorize_capability_claim returns False on ANY failure — a
    hostile assertion planted in the store must not raise."""
    signer = _signer()
    did, good_message = _self_assertion(signer)
    # Hostile assertion claims "**" (would authorize anything) but carries a
    # non-finite max_spend, so it must be dead on arrival.
    _, bad_message = _nonfinite_assertion_message(
        signer, float("inf"), target_pattern="**"
    )
    registry = _registered(did, good_message)
    # Plant the hostile assertion bytes directly in the store (as if a
    # compromised writer bypassed register()).
    registry._entries[did]["assertions"]["planted-evil"] = bad_message
    assert (
        authorize_capability_claim(
            did, "http", "post", "https://anything.example.com/x", registry, now=NOW
        )
        is False
    )
    # The pre-existing good assertion still authorizes.
    assert authorize_capability_claim(did, "shell", "exec", "/bin/ls", registry, now=NOW)


def test_authorize_capability_claim_false_on_garbage_inputs_never_raises():
    """Contract: authorize_capability_claim returns False on ANY failure."""
    signer = _signer()
    did, message = _self_assertion(signer)
    registry = _registered(did, message)
    assert (
        authorize_capability_claim(did, "shell", "exec", "/bin/ls", None, now=NOW) is False
    )
    assert (
        authorize_capability_claim(None, "shell", "exec", "/bin/ls", registry, now=NOW)
        is False
    )
    assert (
        authorize_capability_claim(
            did, "shell", "exec", "/bin/ls", registry, now="not-a-time"
        )
        is False
    )
    with pytest.raises(AgentIdentityError):
        registry.resolve(None, now=NOW)
    with pytest.raises(AgentIdentityError):
        registry.revoke_assertion(["not", "a", "string"])


def test_target_matches_pathological_star_groups_completes_fast():
    """AI-N4: 12 `*a` groups vs a 34-char target took >6s with the regex
    engine (ReDoS). The linear engine must finish well under 1s — and match
    correctly."""
    from anchor_v1.agent_identity import _target_matches

    pattern = "*a" * 12
    cases = [("a" * 33 + "b", False), ("a" * 34, True), ("b" * 34, False)]
    start = time.perf_counter()
    for target, expected in cases:
        assert _target_matches(pattern, target) is expected
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"glob matching took {elapsed:.2f}s (ReDoS?)"


def test_target_matches_pathological_double_star_groups_completes_fast():
    """AI-N4: the `**`-separated variant must also be fast and correct."""
    from anchor_v1.agent_identity import _target_matches

    pattern = "**a" * 12
    start = time.perf_counter()
    assert _target_matches(pattern, "a" * 33 + "b") is False
    assert _target_matches(pattern, "x/y/" + "a" * 34) is True
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"glob matching took {elapsed:.2f}s (ReDoS?)"


def test_target_matches_rejects_overlong_pattern_fail_closed():
    """AI-N4: patterns past the documented length bound never match (False),
    and tokenizing them raises PatternError."""
    from anchor_v1.agent_identity import (
        _MAX_TARGET_PATTERN_LEN,
        _target_matches,
        _tokenize_target_pattern,
    )

    long_pattern = "a" * (_MAX_TARGET_PATTERN_LEN + 1)
    assert _target_matches(long_pattern, "a") is False
    with pytest.raises(PatternError):
        _tokenize_target_pattern(long_pattern)


def test_authorize_with_overlong_pattern_returns_false():
    signer = _signer()
    did = did_for_pubkey(signer.public_key_bytes())
    caps = [CapabilityPattern(plane="shell", verb="exec", target_pattern="a" * 3000)]
    message = issue_assertion(signer, did, did, caps, issued_at=NOW, ttl=timedelta(hours=1))
    registry = _registered(did, message)
    assert (
        authorize_capability_claim(did, "shell", "exec", "a" * 3000, registry, now=NOW)
        is False
    )


def test_negated_character_class_never_matches_slash():
    """AI-N2: [!x] must not match `/` — like `*`/`?`, negated classes never
    cross the path separator. /a/[!x]b must NOT cover /a//b."""
    from anchor_v1.agent_identity import _target_matches

    assert _target_matches("/a/[!x]b", "/a//b") is False
    assert _target_matches("/a/[!x]b", "/a/yb") is True
    assert _target_matches("[!x]", "/") is False
    assert _target_matches("[!x]", "x") is False
    assert _target_matches("[!x]", "y") is True
    assert _target_matches("[!ab]", "c") is True


def test_double_star_segments_match_across_separators():
    """AI-N4 engine: `**` segmentation preserves multi-segment semantics."""
    from anchor_v1.agent_identity import _target_matches

    assert _target_matches("**", "anything/at/all") is True
    assert _target_matches("**/x", "/a/b/x") is True
    assert _target_matches("a/**", "a/") is True
    assert _target_matches("**a**", "xx/ayy") is True
    assert _target_matches("a/**/b", "a/x/y/b") is True
    # `**` is "anything" (documented `.*` semantics, as before): it does not
    # absorb the slashes around it, so a/**/b needs two literal slashes.
    assert _target_matches("a/**/b", "a/b") is False
    assert _target_matches("a/**/b", "a/x/c") is False
    assert _target_matches("***", "zzz") is True


def test_target_matches_rejects_oversized_target_fail_closed():
    """Quadratic `**` glob residual: `**a...a**b` vs a 64KB target measured
    12.9s (O(n*m), not ReDoS, but a real CPU sink a self-issuing agent could
    plant). Targets past _MAX_TARGET_LEN fail closed (False) BEFORE matching
    starts, so the hostile path is unreachable and completes instantly."""
    from anchor_v1.agent_identity import _MAX_TARGET_LEN, _target_matches

    hostile = "**a" * 100 + "**b"  # 100 `**`-separated segments
    target = "a" * 65536
    start = time.perf_counter()
    assert _target_matches(hostile, target) is False
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"oversized target took {elapsed:.2f}s (quadratic?)"
    # Even a pattern that WOULD match fails closed on length alone.
    start = time.perf_counter()
    assert _target_matches("**", "a" * 65536) is False
    assert time.perf_counter() - start < 1.0


def test_target_matches_target_length_boundary():
    """The bound is exact: _MAX_TARGET_LEN matches, _MAX_TARGET_LEN + 1 does
    not (fail closed)."""
    from anchor_v1.agent_identity import _MAX_TARGET_LEN, _target_matches

    assert _target_matches("**", "a" * _MAX_TARGET_LEN) is True
    assert _target_matches("**", "a" * (_MAX_TARGET_LEN + 1)) is False


def test_target_matches_normal_use_within_target_bound():
    """The length bound must not break legitimate patterns: ordinary globs —
    including `**` multi-segment ones — still match targets under the cap."""
    from anchor_v1.agent_identity import _target_matches

    assert _target_matches("/bin/*", "/bin/ls") is True
    assert _target_matches("/bin/**", "/bin/sub/ls") is True
    assert _target_matches("**a**b", "xx/ayy/b") is True
    assert _target_matches("**a**b", "xx/ayy/c") is False
    assert _target_matches("/data/[0-9]*/file?.txt", "/data/42/file1.txt") is True
    # A 4096-char target (the max) still matches end-to-end.
    assert _target_matches("**/end", "x" * 4091 + "/end") is True


def test_authorize_with_oversized_target_returns_false():
    """End to end: authorize_capability_claim fails closed (False) for an
    oversized claim target even when an assertion's pattern would match."""
    from anchor_v1.agent_identity import _MAX_TARGET_LEN

    signer = _signer()
    did = did_for_pubkey(signer.public_key_bytes())
    caps = [CapabilityPattern(plane="shell", verb="exec", target_pattern="**")]
    message = issue_assertion(signer, did, did, caps, issued_at=NOW, ttl=timedelta(hours=1))
    registry = _registered(did, message)
    assert (
        authorize_capability_claim(
            did, "shell", "exec", "a" * (_MAX_TARGET_LEN + 1), registry, now=NOW
        )
        is False
    )
