"""Regression tests for red-team-2 findings (R&D battle-test, 2026-09-23).

Each test fails on the pre-fix code and passes after the fix:
  P4  guardian.pending returned a shallow copy — mutating it rewrote a
      stored ASK's params pre-approval (fixed: copy.deepcopy).
  P9  verify_capability never checked issued_at <= now — a capability
      minted with a far-future issued_at verified as valid at the real
      now (fixed: fail closed).
  P5  _validate_presented_envelope checks principal/args_digest/
      policy_ref/window but NOT verb/target against the decided event.
      NOT fixed as specified: the Wave 7 seam is cross-plane by design
      (shell verb/target legitimately differ from acs action/resource) and
      no plane mapping exists in the protocol, so equality would break the
      integration — documented as residual risk (THREAT_MODEL.md item 12).
      Tests lock in the intended cross-plane contract instead.
  P1b _prune_nonces was not thread-safe — RuntimeError ("dictionary
      changed size during iteration") under concurrency, spuriously
      DENY'ing legitimate requests (fixed: nonce lock).
  P7  LocalTransparencyLog() without trusted_issuers is permissive —
      forged statements get genuine receipts (fixed: loud UserWarning +
      docs note; production must pass trusted_issuers).
  P3  wire subject is self-asserted under the PSK channel (mitigation:
      optional wire_allowed_subjects allowlist, default off).
"""

from __future__ import annotations

import secrets
import threading
import uuid
import warnings
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from anchor_v1 import authority
from anchor_v1.acs_guardian import AcsGuardian, GuardianEvent, WirePeer
from anchor_v1.authority import CapabilityError
from anchor_v1.canonical import sha256_hex
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.scitt import LocalTransparencyLog

NOW = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)
PSK = b"rt2fix-psk-16bytes-long-enough"
CONSTITUTION_HASH = "rt2fix-constitution"


def _make_guardian(subject_sub, decision_fn=None, **kwargs):
    issuer = Ed25519Signer.generate("rt2fix-guardian")
    holder = Ed25519Signer.generate("rt2fix-holder")
    sub = subject_sub or holder.public_key_b64()
    g = AcsGuardian(
        psk=PSK,
        issuer=issuer,
        constitution_hash=CONSTITUTION_HASH,
        decision_fn=decision_fn or (lambda ev: "ALLOW"),
        holder_keys={sub: holder.public_key_bytes()},
        now_fn=lambda: NOW,
        **kwargs,
    )
    trusted = {
        issuer.key_id.encode(): Ed25519PublicKey.from_public_bytes(
            issuer.public_key_bytes()
        )
    }
    return g, issuer, trusted, sub


def _event(subject, action="read_file", resource="/tmp/a", params=None):
    return GuardianEvent(
        event_id=f"ev-{secrets.token_hex(4)}",
        event_type="pre_tool_call",
        session_id="sess-1",
        subject=subject,
        action=action,
        resource=resource,
        params=params if params is not None else {"path": resource},
        ts=NOW,
    )


def _envelope_dict(subject, params, verb, target, when=NOW):
    return {
        "action_id": str(uuid.uuid4()),
        "principal": subject,
        "effect": {
            "plane": "shell",
            "verb": verb,
            "target": target,
            "args_digest": sha256_hex(params),
        },
        "policy_ref": CONSTITUTION_HASH,
        "issued_at": when.isoformat(),
        "not_before": (when - timedelta(seconds=10)).isoformat(),
        "not_after": (when + timedelta(seconds=300)).isoformat(),
        "nonce": secrets.token_hex(16),
    }


# ---------------------------------------------------------------------------
# P4: pending must be a deep copy
# ---------------------------------------------------------------------------


def test_p4_pending_mutation_cannot_rewrite_stored_intent():
    g, _, _, sub = _make_guardian(None, decision_fn=lambda ev: "ASK")
    d = g.handle_event(_event(sub, params={"path": "/tmp/benign"}))
    assert d.decision == "ASK"
    pid = d.pending_id
    # Attacker mutates through the public property (pre-fix: shallow copy
    # shared the inner dicts, so this rewrote the stored ASK).
    g.pending[pid]["event"]["params"]["path"] = "/etc/shadow"
    # The stored intent must be untouched.
    assert g._pending[pid]["event"]["params"]["path"] == "/tmp/benign"
    # Resolving with an envelope for the ORIGINAL params still works.
    r = g.resolve_pending(
        pid,
        approved=True,
        presented_envelope=_envelope_dict(
            sub, {"path": "/tmp/benign"}, verb="read_file", target="/tmp/a"
        ),
    )
    assert r.decision == "ALLOW" and r.capability is not None


def test_p4_pending_mutation_cannot_sneak_mismatched_envelope():
    g, _, _, sub = _make_guardian(None, decision_fn=lambda ev: "ASK")
    d = g.handle_event(_event(sub, params={"path": "/tmp/benign"}))
    pid = d.pending_id
    g.pending[pid]["event"]["params"]["path"] = "/etc/shadow"
    # The stored ASK still says /tmp/benign, so an envelope digesting the
    # attacker's /etc/shadow params must be denied (args_digest mismatch).
    r = g.resolve_pending(
        pid,
        approved=True,
        presented_envelope=_envelope_dict(
            sub, {"path": "/etc/shadow"}, verb="read_file", target="/tmp/a"
        ),
    )
    assert r.decision == "DENY"


# ---------------------------------------------------------------------------
# P9: issued_at must not be in the future
# ---------------------------------------------------------------------------


def test_p9_future_issued_at_capability_rejected():
    issuer = Ed25519Signer.generate("rt2fix-p9")
    holder = Ed25519Signer.generate("rt2fix-p9-holder")
    trusted = {
        issuer.key_id.encode(): Ed25519PublicKey.from_public_bytes(
            issuer.public_key_bytes()
        )
    }
    future = NOW + timedelta(days=3650)
    cose = authority.issue_execution(
        issuer,
        action_digest="ab" * 32,
        holder_pubkey=holder.public_key_bytes(),
        now=future,
    )
    # Pre-fix: this verified as VALID at the real now. Post-fix: fail closed.
    with pytest.raises(CapabilityError, match="issued_at is in the future"):
        authority.verify_capability(cose, trusted, now=NOW)


def test_p9_normal_capability_still_verifies():
    issuer = Ed25519Signer.generate("rt2fix-p9b")
    holder = Ed25519Signer.generate("rt2fix-p9b-holder")
    trusted = {
        issuer.key_id.encode(): Ed25519PublicKey.from_public_bytes(
            issuer.public_key_bytes()
        )
    }
    cose = authority.issue_execution(
        issuer,
        action_digest="ab" * 32,
        holder_pubkey=holder.public_key_bytes(),
        now=NOW,
    )
    payload = authority.verify_capability(cose, trusted, now=NOW)
    assert payload.action_digest == "ab" * 32


# ---------------------------------------------------------------------------
# P5: presented envelope verb/target are the presenting plane's labels.
#
# Red-team-2 P5 proposed equating them with the acs-plane event.action /
# event.resource, but the Wave 7 seam is cross-plane BY DESIGN: the shell
# shim presents verb="exec"/target="trial-cmd" for a guardian event with
# action="shell.exec"/resource="sandbox://host". No cross-plane mapping
# exists in the protocol, so the guardian has no ground truth to equate
# against — enforcing equality would break the integration (documented
# residual risk, docs/THREAT_MODEL.md item 12). The enforced backstops
# remain principal / args_digest / policy_ref / validity window.
# ---------------------------------------------------------------------------


def test_p5_cross_plane_envelope_allowed_by_design():
    # The Wave 7 seam: shell-plane labels differ from the acs event and
    # that is legitimate. A future "fix" must not silently break this.
    g, _, trusted, sub = _make_guardian(None)
    ev = _event(sub, action="shell.exec", resource="sandbox://host",
                params={"cmd": "echo hi"})
    env = _envelope_dict(
        sub, {"cmd": "echo hi"}, verb="exec", target="trial-cmd"
    )
    d = g.handle_event(ev, presented_envelope=env)
    assert d.decision == "ALLOW" and d.capability is not None
    authority.verify_capability(d.capability, trusted, now=NOW)


def test_p5_envelope_args_tampering_still_denied():
    # The real backstop on the seam: the args digest must match the
    # decided params, whatever the verb/target labels say.
    g, _, _, sub = _make_guardian(None)
    ev = _event(sub, action="shell.exec", resource="sandbox://host",
                params={"cmd": "echo hi"})
    env = _envelope_dict(
        sub, {"cmd": "rm -rf /"}, verb="exec", target="trial-cmd"
    )
    d = g.handle_event(ev, presented_envelope=env)
    assert d.decision == "DENY"


def test_p5_envelope_matching_verb_target_allowed():
    g, _, trusted, sub = _make_guardian(None)
    ev = _event(sub, action="read_file", resource="/tmp/a",
                params={"path": "/tmp/a"})
    env = _envelope_dict(
        sub, {"path": "/tmp/a"}, verb="read_file", target="/tmp/a"
    )
    d = g.handle_event(ev, presented_envelope=env)
    assert d.decision == "ALLOW" and d.capability is not None
    # And the minted capability verifies.
    authority.verify_capability(d.capability, trusted, now=NOW)


# ---------------------------------------------------------------------------
# P1b: nonce pruning must be thread-safe
# ---------------------------------------------------------------------------


def test_p1b_concurrent_prune_and_wire_traffic_no_errors():
    g, _, _, sub = _make_guardian(None)
    now = datetime.now(timezone.utc)
    # Seed a large stale set so pruning iterates long enough for a
    # concurrent mutation to hit the old unlocked iteration.
    stale_cutoff = now - timedelta(seconds=10000)
    for i in range(3000):
        g._seen_nonces[f"seed-stale-{i}"] = stale_cutoff
    errors: list[BaseException] = []
    stop = threading.Event()

    def pruner():
        try:
            while not stop.is_set():
                g._prune_nonces(datetime.now(timezone.utc))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def churner(worker):
        # All real mutations of _seen_nonces go through the nonce lock
        # (the wire path holds it across prune+check+record); the churner
        # respects the same discipline, exactly like _authenticate_frame.
        try:
            for i in range(300):
                with g._nonce_lock:
                    g._seen_nonces[f"live-{worker}-{i}"] = datetime.now(
                        timezone.utc
                    )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=pruner) for _ in range(4)]
    threads += [threading.Thread(target=churner, args=(w,)) for w in range(4)]
    for t in threads:
        t.start()
    for t in threads[4:]:
        t.join()
    stop.set()
    for t in threads[:4]:
        t.join()
    assert not errors, f"concurrent nonce ops raised: {errors!r}"


def test_p1b_wire_frames_still_replay_protected_under_lock():
    g, _, _, sub = _make_guardian(None)
    peer = WirePeer(PSK, now_fn=lambda: NOW)
    frame = peer.build_event_frame(_event(sub), ts=NOW)
    d1 = peer.parse_decision_frame(g.handle_frame(frame))
    assert d1.decision == "ALLOW"
    d2 = peer.parse_decision_frame(g.handle_frame(frame))
    assert d2.decision == "DENY"
    assert "replay" in d2.reason


# ---------------------------------------------------------------------------
# P7: permissive log construction must warn loudly
# ---------------------------------------------------------------------------


def test_p7_log_without_trusted_issuers_warns():
    signer = Ed25519Signer.generate("rt2fix-p7-log")
    with pytest.warns(UserWarning, match="PERMISSIVE"):
        LocalTransparencyLog(signer)


def test_p7_log_with_trusted_issuers_does_not_warn():
    signer = Ed25519Signer.generate("rt2fix-p7-log2")
    trusted = {
        signer.key_id.encode(): Ed25519PublicKey.from_public_bytes(
            signer.public_key_bytes()
        )
    }
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # any warning becomes an error
        LocalTransparencyLog(signer, trusted_issuers=trusted)


# ---------------------------------------------------------------------------
# P3: optional wire subject allowlist
# ---------------------------------------------------------------------------


def test_p3_wire_subject_allowlist_denies_unknown_subject():
    issuer = Ed25519Signer.generate("rt2fix-p3")
    alice = Ed25519Signer.generate("rt2fix-alice")
    bob = Ed25519Signer.generate("rt2fix-bob")
    g = AcsGuardian(
        psk=PSK,
        issuer=issuer,
        constitution_hash=CONSTITUTION_HASH,
        decision_fn=lambda ev: "ALLOW",
        holder_keys={
            alice.public_key_b64(): alice.public_key_bytes(),
            bob.public_key_b64(): bob.public_key_bytes(),
        },
        now_fn=lambda: NOW,
        wire_allowed_subjects=frozenset({alice.public_key_b64()}),
    )
    peer = WirePeer(PSK, now_fn=lambda: NOW)
    d_bob = peer.send_event(g, _event(bob.public_key_b64()), ts=NOW)
    assert d_bob.decision == "DENY"
    assert "wire auth failed" in d_bob.reason
    d_alice = peer.send_event(g, _event(alice.public_key_b64()), ts=NOW)
    assert d_alice.decision == "ALLOW" and d_alice.capability is not None


def test_p3_wire_subject_allowlist_defaults_off():
    g, _, _, sub = _make_guardian(None)  # no wire_allowed_subjects
    peer = WirePeer(PSK, now_fn=lambda: NOW)
    d = peer.send_event(g, _event(sub), ts=NOW)
    assert d.decision == "ALLOW"
