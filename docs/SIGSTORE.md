# ANCHOR v1 — Sigstore Provenance Run-book

**Honest status, first: nothing is signed YET.** There are no signatures on any
ANCHOR v1 artifact today, no release has been cut, and no Rekor entries exist.
This document is the release-day run-book for making that happen — what gets
signed, the exact keyless flow, and what is already in place versus what must
be executed at release time.

## 1. What release artifacts will be signed

On release day the coordinator produces, from a clean checkout at the tagged
commit, and hashes (SHA-256) each of:

| Artifact | How it is produced |
|---|---|
| `anchor_v1-<version>.tar.gz` (sdist) | `python -m build --sdist` from the tag |
| `anchor_v1-<version>-py3-none-any.whl` (wheel) | `python -m build --wheel` from the tag |
| `SBOM.md` (this trust package) | `anchor-v1/docs/SBOM.md` at the tag |
| `SPEC.md`, `THREAT_MODEL.md` | `anchor-v1/docs/` at the tag |

The hashes (not the artifacts alone) are what gets signed; the artifacts are
published alongside the signatures and the hashes.

**Already in place:** hash-pinned test expectations — the full suite
(1017/1017) asserts exact digests, exact COSE bytes, and exact canonical
encodings throughout (`tests/`), so a tampered release tree fails its own
tests. This is not a substitute for signing; it is defense in depth.

## 2. Keyless signing flow (Fulcio + Rekor) — release-day steps

No long-lived signing keys. Identity comes from an OIDC identity (e.g. the
release engineer's GitHub/CI identity); Fulcio issues a short-lived
certificate binding that identity; Rekor records the signing event in the
public transparency log.

```
Step 1.  Freeze the release commit.
         git tag -s v1.0.0  <commit>        # annotated tag of the release commit

Step 2.  Build from the tag on a clean machine.
         git archive v1.0.0 | tar -x -C /tmp/release-src
         cd /tmp/release-src/anchor-v1
         python -m build --sdist --wheel --outdir /tmp/release-artifacts

Step 3.  Hash everything to be signed.
         cd /tmp/release-artifacts
         sha256sum anchor_v1-*.tar.gz anchor_v1-*.whl > SHA256SUMS
         sha256sum /tmp/release-src/anchor-v1/docs/SBOM.md \
                   /tmp/release-src/anchor-v1/docs/SPEC.md \
                   /tmp/release-src/anchor-v1/docs/THREAT_MODEL.md >> SHA256SUMS

Step 4.  Keyless-sign the hash list with Sigstore.
         # Requires network access to Fulcio + Rekor and an OIDC identity.
         cosign sign-blob --yes SHA256SUMS \
             --output-signature SHA256SUMS.sig \
             --output-certificate SHA256SUMS.pem
         # cosign handles: OIDC auth -> Fulcio short-lived cert ->
         #               signature -> Rekor transparency entry.

Step 5.  Capture the Rekor inclusion proof.
         REKOR_UUID=$(rekor-cli get --artifact SHA256SUMS --format json \
                      | jq -r '.[0].uuid')     # or from cosign's bundle output
         rekor-cli get --uuid "$REKOR_UUID" --format json > rekor-entry.json

Step 6.  Publish: artifacts + SHA256SUMS + SHA256SUMS.sig + SHA256SUMS.pem
         (+ cosign bundle) + rekor-entry.json + docs/ next to the tag.
```

Verification by a downstream consumer:

```
cosign verify-blob --cert SHA256SUMS.pem --signature SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS          # artifacts match the signed hashes
# Optionally: check the Rekor entry independently via rekor-cli verify.
```

## 3. In place vs at release

| Item | Status |
|---|---|
| Hash-pinned test expectations (1017 tests assert exact bytes/digests) | IN PLACE |
| SBOM with exact frozen versions | IN PLACE (`docs/SBOM.md`) |
| Reproducible-build recipe | IN PLACE (`docs/REPRODUCIBLE_BUILDS.md`) |
| Signed sdist/wheel/SBOM | NOT DONE — Steps 1–6 above, release day |
| Rekor transparency entries | NOT DONE — Step 4–5 above, release day |
| OIDC identity for the signer (who signs releases) | NOT DECIDED — coordinator must name it before release |
| Verification instructions published with the tag | NOT DONE — Step 6 above |

## 4. Residual notes

* Keyless signing authenticates the *signer's identity*, not code correctness —
  it proves "this artifact came from this release pipeline", not "this code is
  safe". The safety argument remains the test suite + the TLA+ model + the
  verifier/red-team process (see LOG.md).
* The transparency-log story inside ANCHOR (SCITT receipts, Merkle checkpoints)
  and the Sigstore story above are independent: one proves governance events
  happened, the other proves the release bits are what the signer published.
* Until release day, treat any `anchor-v1` artifact circulating without the
  signatures above as **unprovenanced** — verify it by rebuilding from source
  and running the suite (`docs/REPRODUCIBLE_BUILDS.md`), not by trusting the
  bits.
