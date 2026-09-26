#!/usr/bin/env python3
"""Generate cross-implementation fixtures with the REAL anchor_v1 Python code.

Every fixture is produced by the audited Python implementation; the Rust
verifier must agree on all of them (accept the valid ones, reject the
tampered ones). Fixtures are deterministic (fixed keys, fixed timestamps).
"""

import base64
import copy
import json
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "/tmp/release-src/src")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from anchor_v1 import anchored_checkpoints as ac
from anchor_v1 import authority
from anchor_v1.cbor import cbor_dumps, cbor_loads
from anchor_v1.cose import cose_sign
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.envelope import ActionEnvelope, Effect

FIX = "/home/hatch/workspace/anchor-v1-verifier/fixtures"
UTC = timezone.utc
T0 = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def write(name: str, obj) -> None:
    with open(f"{FIX}/{name}", "w") as f:
        json.dump(obj, f, indent=1)
    print(f"wrote {name}")


def fixed_signer(key_id: str, seed: int) -> Ed25519Signer:
    priv = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    return Ed25519Signer(key_id, priv)


# ---------------------------------------------------------------- cose ---
def gen_cose():
    signer = fixed_signer("cose-key-1", 11)
    kid = b"cose-key-1"
    payload = b'{"hello": "world"}'
    msg = cose_sign(payload, signer._private_key, kid)
    trusted = {b64(kid): b64(signer.public_key_bytes())}

    def flip(data: bytes, idx: int) -> bytes:
        b = bytearray(data)
        b[idx] ^= 0x01
        return bytes(b)

    outer = cbor_loads(msg)
    body_protected, _, _, _ = outer

    # Non-canonical protected header: alg -8 as 0x38 0x07 (non-shortest).
    assert body_protected[:3] == b"\xa2\x01\x27", body_protected[:3].hex()
    bad_protected = b"\xa2\x01\x38\x07" + body_protected[3:]
    noncanonical = cbor_dumps([bad_protected, {}, payload, outer[3]])

    # Hand-built policy violations, signed properly with the real key.
    def hand_sign(protected_dict, unprotected):
        protected = cbor_dumps(protected_dict)
        sig_struct = cbor_dumps(["Signature1", protected, b"", payload])
        sig = signer._private_key.sign(sig_struct)
        return cbor_dumps([protected, unprotected, payload, sig])

    fixtures = {
        "valid": {
            "message_b64": b64(msg),
            "payload_b64": b64(payload),
            "kid_b64": b64(kid),
        },
        "trusted_keys": trusted,
        "tampered_sig": {"message_b64": b64(flip(msg, len(msg) - 1))},
        "tampered_payload": {"message_b64": b64(flip(msg, len(msg) - 10))},
        "noncanonical_protected": {"message_b64": b64(noncanonical)},
        "wrong_kid": {
            "message_b64": b64(cose_sign(payload, signer._private_key, b"unknown-kid"))
        },
        "extra_protected_field": {
            "message_b64": b64(hand_sign({1: -8, 4: kid, 5: "smuggled"}, {}))
        },
        "nonempty_unprotected": {
            "message_b64": b64(hand_sign({1: -8, 4: kid}, {1: 2}))
        },
        "wrong_alg": {
            "message_b64": b64(hand_sign({1: -7, 4: kid}, {}))
        },
        "truncated": {"message_b64": b64(msg[: len(msg) // 2])},
    }
    write("cose.json", fixtures)


# ------------------------------------------------------------- envelope ---
def gen_envelope():
    signer = fixed_signer("env-key-1", 21)

    def make_env(issued, nb, na, nonce="n-1", extra=None):
        effect = Effect(plane="shell", verb="exec", target="sha256:abc",
                        args_digest="00" * 32)
        env = ActionEnvelope(
            action_id="12345678-1234-5678-1234-567812345678",
            principal="spiffe://example/agent",
            effect=effect,
            policy_ref="constitution-v3",
            issued_at=issued, not_before=nb, not_after=na, nonce=nonce,
        )
        raw = env.model_dump(mode="json")
        if extra:
            raw.update(extra)
        payload = cbor_dumps(raw)
        msg = cose_sign(payload, signer._private_key, b"env-key-1")
        return msg, env.action_digest

    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
    valid_msg, valid_digest = make_env(T0, T0, T0 + timedelta(days=365))
    expired_msg, _ = make_env(T0, T0, T0 + timedelta(hours=1))
    future_msg, _ = make_env(T0, T0 + timedelta(days=365), T0 + timedelta(days=730))
    tampered = bytearray(valid_msg)
    tampered[len(tampered) - 5] ^= 0x02
    extra_msg, _ = make_env(T0, T0, T0 + timedelta(days=365), extra={"evil": "field"})

    write("envelope.json", {
        "valid": {"message_b64": b64(valid_msg), "action_digest": valid_digest},
        "trusted_keys": {"env-key-1": b64(signer.public_key_bytes())},
        "now": now.isoformat(),
        "expired": {"message_b64": b64(expired_msg)},
        "not_yet_valid": {"message_b64": b64(future_msg)},
        "tampered": {"message_b64": b64(bytes(tampered))},
        "extra_field": {"message_b64": b64(extra_msg)},
    })


# ---------------------------------------------------------------- chain ---
def build_chain():
    """Build a 2-checkpoint chain with signer rotation. Returns dict of parts."""
    ck1 = fixed_signer("ckpt-key-1", 31)
    ck2 = fixed_signer("ckpt-key-2", 32)
    anchor_signer = fixed_signer("anchor-key-1", 33)
    anchor = ac.LocalEmulatedAnchor(anchor_signer)

    events = []
    prev_hash = None
    for i in range(6):
        e = ac.EvidenceEvent(
            sequence=i,
            event_type="test.event",
            data={"i": i, "note": "héllo wörld ✓"},
            timestamp=T0 + timedelta(seconds=i),
            previous_hash=prev_hash,
        )
        prev_hash = ac.event_hash(e)
        events.append(e)

    next_signer = ac.NextCheckpointSigner(
        key_id="ckpt-key-2",
        public_key=b64(ck2.public_key_bytes()),
    )
    env1 = ac.seal_checkpoint(
        events[:3], ck1, anchor, None,
        next_signer=next_signer, timestamp=T0 + timedelta(seconds=100),
    )
    env2 = ac.seal_checkpoint(
        events[3:], ck2, anchor, ac._parse_checkpoint(env1).merkle_root,
        timestamp=T0 + timedelta(seconds=200),
    )
    chain = [env1.model_dump(mode="json"), env2.model_dump(mode="json")]
    bootstrap = {"key_id": "ckpt-key-1", "public_key_b64": b64(ck1.public_key_bytes())}
    anchor_json = {
        "key_id": "anchor-key-1",
        "public_key_b64": b64(anchor_signer.public_key_bytes()),
        "log": [p.model_dump(mode="json") for p in anchor.log],
    }
    return {
        "chain": chain, "bootstrap": bootstrap, "anchor": anchor_json,
        "ck1": ck1, "ck2": ck2, "anchor_signer": anchor_signer,
        "events": events,
    }


def resign(payload: dict, signer: Ed25519Signer) -> dict:
    return signer.sign_payload(payload).model_dump(mode="json")


def gen_chain():
    parts = build_chain()
    chain, bootstrap, anchor_json = parts["chain"], parts["bootstrap"], parts["anchor"]
    ck1, ck2 = parts["ck1"], parts["ck2"]

    cases = []

    def case(name, ch, bs=bootstrap, anc=anchor_json, expected=True):
        cases.append({"name": name, "chain": ch, "bootstrap": bs,
                      "anchor": anc, "expected": expected})

    case("valid", chain)

    # Tampered signature on checkpoint 2.
    bad = copy.deepcopy(chain)
    sig = bytearray(base64.b64decode(bad[1]["signature"]))
    sig[0] ^= 0x01
    bad[1]["signature"] = b64(bytes(sig))
    case("bad_signature", bad, expected=False)

    # Broken hash link (re-signed so only the link check can fail).
    bad = copy.deepcopy(chain)
    bad[1]["payload"]["previous_checkpoint_root"] = "00" * 32
    bad[1] = resign(bad[1]["payload"], ck2)
    case("broken_link", bad, expected=False)

    # Sequence gap.
    bad = copy.deepcopy(chain)
    bad[1]["payload"]["start_seq"] = 4
    bad[1]["payload"]["event_count"] = 2
    bad[1] = resign(bad[1]["payload"], ck2)
    case("seq_gap", bad, expected=False)

    # Timestamp going backwards.
    bad = copy.deepcopy(chain)
    bad[1]["payload"]["timestamp"] = chain[0]["payload"]["timestamp"]
    bad[1] = resign(bad[1]["payload"], ck2)
    case("time_travel", bad, expected=False)

    # Checkpoint 2 signed by the ROTATED-OUT key (key_id mismatch).
    bad = copy.deepcopy(chain)
    bad[1] = resign(bad[1]["payload"], ck1)
    case("wrong_key_after_rotation", bad, expected=False)

    # Anchor proof bound to a different root (re-signed checkpoint).
    bad = copy.deepcopy(chain)
    bad[1]["payload"]["anchor_proof"]["root_hash"] = "ff" * 32
    bad[1] = resign(bad[1]["payload"], ck2)
    case("bad_anchor_root", bad, expected=False)

    # Genesis checkpoint carrying a previous root.
    bad = copy.deepcopy(chain)
    bad[0]["payload"]["previous_checkpoint_root"] = "00" * 32
    bad[0] = resign(bad[0]["payload"], ck1)
    case("genesis_with_prev", bad, expected=False)

    # Empty chain.
    case("empty_chain", [], expected=False)

    # Wrong anchor trust (different anchor key).
    other_anchor = fixed_signer("anchor-key-9", 39)
    bad_anchor = dict(anchor_json)
    bad_anchor["key_id"] = "anchor-key-9"
    bad_anchor["public_key_b64"] = b64(other_anchor.public_key_bytes())
    case("wrong_anchor_key", chain, anc=bad_anchor, expected=False)

    # Anchor proof missing from the operator log.
    bad_anchor = copy.deepcopy(anchor_json)
    bad_anchor["log"] = []
    case("anchor_not_in_log", chain, anc=bad_anchor, expected=False)

    # Inclusion fixtures from checkpoint 1.
    cp1 = ac._parse_checkpoint(ac.SignedEnvelope.model_validate(chain[0]))
    events = parts["events"][:3]
    proof = ac.prove_event(cp1, events, 1)
    inclusion = {
        "checkpoint": chain[0]["payload"],
        "event": events[1].model_dump(mode="json"),
        "proof": proof.model_dump(mode="json"),
        "expected": True,
    }
    wrong_event = copy.deepcopy(events[1].model_dump(mode="json"))
    wrong_event["data"] = {"i": 999}
    inclusion_wrong_event = {
        "checkpoint": chain[0]["payload"],
        "event": wrong_event,
        "proof": proof.model_dump(mode="json"),
        "expected": False,
    }
    bad_proof = proof.model_dump(mode="json")
    bad_proof["steps"][0]["sibling"] = "ab" * 32
    inclusion_bad_proof = {
        "checkpoint": chain[0]["payload"],
        "event": events[1].model_dump(mode="json"),
        "proof": bad_proof,
        "expected": False,
    }

    write("chain.json", {"cases": cases})
    write("inclusion.json", {
        "cases": [inclusion, inclusion_wrong_event, inclusion_bad_proof],
    })


# --------------------------------------------------------------- holder ---
def gen_holder():
    holder = fixed_signer("holder-1", 41)
    other = fixed_signer("holder-2", 42)
    cap_id = "cap_0123456789abcdef"
    challenge = bytes(range(1, 33))
    proof = authority.make_holder_proof(holder, cap_id, challenge)

    def flip(b: bytes) -> bytes:
        b = bytearray(b)
        b[0] ^= 0x01
        return bytes(b)

    write("holder.json", {
        "valid": {
            "pubkey_b64": b64(holder.public_key_bytes()),
            "capability_id": cap_id,
            "challenge_b64": b64(challenge),
            "proof_b64": b64(proof),
            "expected": True,
        },
        "wrong_challenge": {
            "pubkey_b64": b64(holder.public_key_bytes()),
            "capability_id": cap_id,
            "challenge_b64": b64(bytes(range(2, 34))),
            "proof_b64": b64(proof),
            "expected": False,
        },
        "wrong_key": {
            "pubkey_b64": b64(other.public_key_bytes()),
            "capability_id": cap_id,
            "challenge_b64": b64(challenge),
            "proof_b64": b64(proof),
            "expected": False,
        },
        "tampered_proof": {
            "pubkey_b64": b64(holder.public_key_bytes()),
            "capability_id": cap_id,
            "challenge_b64": b64(challenge),
            "proof_b64": b64(flip(proof)),
            "expected": False,
        },
        "empty_challenge": {
            "pubkey_b64": b64(holder.public_key_bytes()),
            "capability_id": cap_id,
            "challenge_b64": b64(b""),
            "proof_b64": b64(proof),
            "expected": False,
        },
    })


# ------------------------------------------------------ canonical json ---
def gen_canonical():
    from anchor_v1.canonical import canonical_bytes
    values = [
        {"b": 1, "a": [1, 2], "c": {"z": True, "a": None}},
        {"unicode": "héllo wörld ✓ \u0001 \u007f",
         "escapes": "a\"b\\c\nd\te\bf\fx"},
        {"float": 0.30000000000000004, "big": 1e16, "small": 1e-5,
         "neg": -0.0, "int": 2**70},
        {"empty": {}, "list": [], "nested": {"x": [{"y": 1}]}},
        "just a string",
        42,
        True,
        None,
    ]
    write("canonical.json", [
        {"value": v, "expected_hex": canonical_bytes(v).hex()} for v in values
    ])


# ----------------------------------------------------------------- cbor ---
def gen_cbor():
    from anchor_v1.cbor import Tag
    valid = [
        ("uint", 42, "182a"),
        ("nint", -1000, "3903e7"),
        ("bignum_pos", 2**70, "c249400000000000000000"),
        ("bignum_neg", -(2**70) - 1, "c349400000000000000000"),
        ("float_half", 1.5, "f93e00"),
        ("float_single", 100000.0, "fa47c35000"),
        ("float_double", 1.1, "fb3ff199999999999a"),
        ("float_nan", float("nan"), "f97e00"),
        ("bytes", b"\x01\x02", "420102"),
        ("text", "a", "6161"),
        ("array", [1, "a"], "82016161"),
        ("map_sorted", {"b": 1, "a": 2}, "a2616102616201"),
        ("tag", Tag(100, "x"), "d8646178"),
        ("bool_null", [True, False, None], "83f5f4f6"),
        ("nested", {"k": [{"n": -1}]}, None),  # computed below
    ]
    out_valid = []
    for name, value, expected in valid:
        enc = cbor_dumps(value).hex()
        if expected is not None:
            assert enc == expected, (name, enc, expected)
        out_valid.append({"name": name, "hex": enc})

    invalid = [
        ("non_shortest_1byte", "1817"),          # 23 in 1-byte form (should be 0x17)
        ("non_shortest_2byte", "1900ff"),       # 255 in 2-byte form (should be 0x18ff)
        ("indefinite_array", "9f0180ff"),
        ("unordered_map", "a2616201616102"),    # keys b then a
        ("duplicate_key", "a2616101616102"),
        ("trailing_bytes", "0102"),
        ("truncated", "5810" + "00" * 8),
        ("non_shortest_bignum", "c2420001"),
        ("reserved_ai", "fc"),
        ("bad_utf8", "62ffb0"),
        ("simple_nonshortest", "f800"),
    ]
    write("cbor.json", {"valid": out_valid, "invalid": invalid})


if __name__ == "__main__":
    gen_cose()
    gen_envelope()
    gen_chain()
    gen_holder()
    gen_canonical()
    gen_cbor()
    print("all fixtures generated")
