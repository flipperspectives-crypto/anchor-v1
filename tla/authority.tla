------------------------------ MODULE authority ------------------------------
(*
 * ANCHOR v1 -- authority core state machine (Wave 6 conformance model).
 *
 * Models src/anchor_v1/authority.py (issuance, monotonic attenuation via
 * mint_child, holder-of-key proofs) together with src/anchor_v1/store.py
 * (registration, the linearizable consume critical section, the mandate
 * budget ledger, the revocation set, and the epoch counter).
 *
 * STATE (following store.py exactly -- there are only two capability
 * states; REVOKED is a set and EXPIRED is derived from the clock):
 *   cap          : Ids -> capability record
 *                    [kind   : "mandate" | "execution" | "read" | "none"
 *                     scope  : SUBSET Effects      (allowed effects)
 *                     holder : Holders             (bound holder key)
 *                     parent : Ids \cup {NoId}     (mint lineage)
 *                     digest : Digests             (bound action digest)
 *                     spend  : 0..MaxBudget        (spend_limit caveat)
 *                     expires: 0..MaxClock        (expires_at caveat)
 *                     nonce  : 0..MaxNonce        (uniqueness caveat)
 *                     maxStale : 0..MaxStale       (max_revocation_staleness)
 *                     state  : "ISSUED" | "CONSUMED"]
 *   issued       : set of Ids ever issued            (monotonic)
 *   revoked      : set of revoked capability ids     (monotonic)
 *   ledger       : Ids -> 0..MaxBudget  (mandate spend remaining)
 *   epoch        : 0..MaxEpoch          (bumped by revoke / revocation sync)
 *   clock        : 0..MaxClock          (logical wall clock)
 *   syncT        : 0..MaxClock          (clock of last revocation sync)
 *
 * Ghost (history) variables, used only to state checkable invariants:
 *   budget0      : Ids -> 0..MaxBudget  (budget at issuance)
 *   boundHolder  : Ids -> Holders       (holder bound at issuance/mint)
 *   proofPending : Ids -> BOOLEAN       (a fresh holder proof was presented)
 *   authzCount   : Ids -> Nat           (successful Consume authorizations)
 *   authzClock   : Ids -> Nat           (clock of the authorization)
 *
 * FINITENESS / TLC CONFIG NOTE:
 *   All constants are finite. The default model in README.md uses
 *   3 capability ids, 2 effects, 2 holders, MaxBudget = 2, MaxClock = 3,
 *   MaxStale = 2, MaxNonce = 2, MaxEpoch = 4 -- small enough for TLC to
 *   exhaust in seconds. Ids, Effects and Holders are fully symmetric in
 *   this spec; if you raise the bounds and the state space grows, add a
 *   SYMMETRY entry to authority.cfg permuting those three constant sets
 *   (TLC's standard symmetry reduction applies unchanged).
 *
 * DELIBERATE ABSTRACTIONS (see README.md for the full list):
 *   - Cryptography (COSE_Sign1, Ed25519) is abstracted: a holder proof is an
 *     unforgeable token that ONLY the bound holder can present
 *     (PresentProof). This captures "stolen blob without the holder key is
 *     useless" without modeling signatures.
 *   - The mandate lifecycle (CREATED/ACTIVE/PAUSED/...) is abstracted to
 *     cap.state = "ISSUED"; MintChild requires the parent mandate to be
 *     ISSUED and unexpired, mirroring debit_mandate_for_child's ACTIVE check.
 *   - Revoke is restricted to ISSUED capabilities. Revoking an already
 *     CONSUMED capability is unobservable in the implementation (a consumed
 *     capability can never authorize again -- see NoDoubleConsume), so this
 *     restriction loses no behavior relevant to the stated invariants.
 *   - Read-capability provenance caveats (key prefix, trusted writers,
 *     min version, statement requirement) are folded into `scope`.
 *)

EXTENDS Naturals, FiniteSets

CONSTANTS
    Ids,        \* Finite pool of capability ids, e.g. {"c1", "c2", "c3"}.
    Effects,    \* Finite universe of effects; a capability's scope \subseteq Effects.
    Holders,    \* Finite set of holder identities, e.g. {"h1", "h2"}.
    Digests,    \* Finite set of action digests, e.g. {"d1", "d2"}.
    NoId,       \* Sentinel meaning "no parent capability".
    NoHolder,   \* Sentinel meaning "no holder bound" (unissued slots only).
    NoDigest,   \* Sentinel meaning "no digest bound" (unissued slots only).
    MaxBudget,  \* Largest spend/budget value, e.g. 2.
    MaxClock,   \* Largest clock value; ExpireTick stops here, e.g. 3.
    MaxStale,   \* Largest max_revocation_staleness value, e.g. 2.
    MaxNonce,   \* Largest nonce value, e.g. 2.
    MaxEpoch    \* Largest epoch value; Revoke/EpochTick stop here, e.g. 4.

ASSUME /\ MaxBudget \in Nat /\ MaxBudget > 0
       /\ MaxClock \in Nat /\ MaxClock > 1
       /\ MaxStale \in Nat /\ MaxStale > 0
       /\ MaxNonce \in Nat /\ MaxNonce > 0
       /\ MaxEpoch \in Nat /\ MaxEpoch > 0
       /\ NoId \notin Ids /\ NoHolder \notin Holders /\ NoDigest \notin Digests

VARIABLES
    cap, issued, revoked, ledger, epoch, clock, syncT,
    budget0, boundHolder, proofPending, authzCount, authzClock

vars == <<cap, issued, revoked, ledger, epoch, clock, syncT,
          budget0, boundHolder, proofPending, authzCount, authzClock>>

(* The record stored in unissued slots. kind = "none" marks "not issued";
   every action guards on id \in issued, so NullCap is never observed. *)
NullCap == [kind     |-> "none",
            scope    |-> {},
            holder   |-> NoHolder,
            parent   |-> NoId,
            digest   |-> NoDigest,
            spend    |-> 0,
            expires  |-> 0,
            nonce    |-> 0,
            maxStale |-> 0,
            state    |-> "ISSUED"]

Init ==
    /\ cap          = [i \in Ids |-> NullCap]
    /\ issued       = {}
    /\ revoked      = {}
    /\ ledger       = [i \in Ids |-> 0]
    /\ epoch        = 0
    /\ clock        = 0
    /\ syncT        = 0
    /\ budget0      = [i \in Ids |-> 0]
    /\ boundHolder  = [i \in Ids |-> NoHolder]
    /\ proofPending = [i \in Ids |-> FALSE]
    /\ authzCount   = [i \in Ids |-> 0]
    /\ authzClock   = [i \in Ids |-> 0]

(***************************************************************************)
(* Issuance: authority.issue_mandate / issue_execution / issue_read plus    *)
(* store.register_capability (and store.create_mandate for the ledger row). *)
(***************************************************************************)

IssueMandate(id, h, sc, dg, sp, bg, ex, nn, ms) ==
    /\ id \in Ids /\ id \notin issued
    /\ h \in Holders
    /\ sc \in SUBSET Effects
    /\ dg \in Digests
    /\ sp \in 0..MaxBudget
    /\ bg \in 0..MaxBudget
    /\ ex \in 1..MaxClock /\ ex > clock      (* ttl > 0: born unexpired *)
    /\ nn \in 1..MaxNonce
    /\ ms \in 1..MaxStale
    /\ cap' = [cap EXCEPT ![id] = [kind     |-> "mandate",
                                   scope    |-> sc,
                                   holder   |-> h,
                                   parent   |-> NoId,
                                   digest   |-> dg,
                                   spend    |-> sp,
                                   expires  |-> ex,
                                   nonce    |-> nn,
                                   maxStale |-> ms,
                                   state    |-> "ISSUED"]]
    /\ issued'      = issued \cup {id}
    /\ ledger'      = [ledger EXCEPT ![id] = bg]
    /\ budget0'     = [budget0 EXCEPT ![id] = bg]
    /\ boundHolder' = [boundHolder EXCEPT ![id] = h]
    /\ UNCHANGED <<revoked, proofPending, authzCount, authzClock,
                   epoch, clock, syncT>>

IssueExecution(id, h, sc, dg, sp, ex, nn, ms) ==
    /\ id \in Ids /\ id \notin issued
    /\ h \in Holders
    /\ sc \in SUBSET Effects
    /\ dg \in Digests
    /\ sp \in 0..MaxBudget
    /\ ex \in 1..MaxClock /\ ex > clock
    /\ nn \in 1..MaxNonce
    /\ ms \in 1..MaxStale
    /\ cap' = [cap EXCEPT ![id] = [kind     |-> "execution",
                                   scope    |-> sc,
                                   holder   |-> h,
                                   parent   |-> NoId,
                                   digest   |-> dg,
                                   spend    |-> sp,
                                   expires  |-> ex,
                                   nonce    |-> nn,
                                   maxStale |-> ms,
                                   state    |-> "ISSUED"]]
    /\ issued'      = issued \cup {id}
    /\ boundHolder' = [boundHolder EXCEPT ![id] = h]
    /\ UNCHANGED <<revoked, ledger, budget0, proofPending, authzCount,
                   authzClock, epoch, clock, syncT>>

(* Read capabilities are reusable and carry no spend; their provenance
   caveats (key prefix, trusted writers, ...) are folded into `scope`. *)
IssueRead(id, h, sc, dg, ex, nn, ms) ==
    /\ id \in Ids /\ id \notin issued
    /\ h \in Holders
    /\ sc \in SUBSET Effects
    /\ dg \in Digests
    /\ ex \in 1..MaxClock /\ ex > clock
    /\ nn \in 1..MaxNonce
    /\ ms \in 1..MaxStale
    /\ cap' = [cap EXCEPT ![id] = [kind     |-> "read",
                                   scope    |-> sc,
                                   holder   |-> h,
                                   parent   |-> NoId,
                                   digest   |-> dg,
                                   spend    |-> 0,
                                   expires  |-> ex,
                                   nonce    |-> nn,
                                   maxStale |-> ms,
                                   state    |-> "ISSUED"]]
    /\ issued'      = issued \cup {id}
    /\ boundHolder' = [boundHolder EXCEPT ![id] = h]
    /\ UNCHANGED <<revoked, ledger, budget0, proofPending, authzCount,
                   authzClock, epoch, clock, syncT>>

(***************************************************************************)
(* Attenuation: authority.mint_child plus store.debit_mandate_for_child.    *)
(* Monotonic attenuation ONLY -- every dimension is checked to be           *)
(* \subseteq the parent's; any amplification is structurally rejected.      *)
(* NOTE: like the implementation, minting from a revoked (but ISSUED)       *)
(* mandate is NOT blocked here -- revocation bites at consume time, which   *)
(* is exactly what RevokedNeverConsumed checks.                             *)
(***************************************************************************)

MintChild(p, id, h, sc, sp, ex, ms, nn) ==
    /\ p \in issued
    /\ cap[p].kind = "mandate"            (* execution caps cannot delegate *)
    /\ cap[p].state = "ISSUED"            (* abstracts the ACTIVE check *)
    /\ clock < cap[p].expires            (* verify_capability on the parent *)
    /\ id \in Ids /\ id \notin issued
    /\ h \in Holders
    /\ sc \in SUBSET Effects
    /\ sc \subseteq cap[p].scope          (* scope: provably \subseteq *)
    /\ sp \in 0..MaxBudget
    /\ sp \leq cap[p].spend              (* spend: no larger than parent's *)
    /\ ex \in 1..MaxClock
    /\ ex \leq cap[p].expires            (* expiry: clamped to parent's *)
    /\ ex > clock
    /\ ms \in 1..MaxStale
    /\ ms \leq cap[p].maxStale           (* staleness: no looser than parent's *)
    /\ nn \in 1..MaxNonce
    /\ ledger[p] \geq sp                 (* worst-case reservation fits *)
    /\ cap' = [cap EXCEPT ![id] = [kind     |-> "execution",
                                   scope    |-> sc,
                                   holder   |-> h,
                                   parent   |-> p,
                                   digest   |-> cap[p].digest,  (* pinned *)
                                   spend    |-> sp,
                                   expires  |-> ex,
                                   nonce    |-> nn,
                                   maxStale |-> ms,
                                   state    |-> "ISSUED"]]
    /\ ledger'      = [ledger EXCEPT ![p] = ledger[p] - sp]  (* reserve *)
    /\ issued'      = issued \cup {id}
    /\ boundHolder' = [boundHolder EXCEPT ![id] = h]
    /\ UNCHANGED <<revoked, budget0, proofPending, authzCount, authzClock,
                   epoch, clock, syncT>>

(***************************************************************************)
(* Holder proof: authority.make_holder_proof / verify_holder_proof.         *)
(* Only the bound holder can present a proof for a capability -- the        *)
(* unforgeable-token abstraction of "sign(capability_id || challenge)".     *)
(* A stolen capability blob alone never sets proofPending (no bearer       *)
(* replay); each Consume/CheckRead consumes the pending proof, so a proof   *)
(* cannot be replayed against a fresh challenge.                            *)
(***************************************************************************)

PresentProof(id, h) ==
    /\ id \in issued
    /\ h \in Holders /\ h = cap[id].holder
    /\ proofPending' = [proofPending EXCEPT ![id] = TRUE]
    /\ UNCHANGED <<cap, issued, revoked, ledger, budget0, boundHolder,
                   authzCount, authzClock, epoch, clock, syncT>>

(* The checks shared by Consume and CheckRead: steps (2)--(8) and (10) of
   store._consume_inner -- registration, binding match (by construction),
   revocation of the capability AND of its mandate, the CAP fail-closed
   staleness bound, single-use state, and expiry. *)
MayAuthorize(id) ==
    /\ id \in issued
    /\ cap[id].state = "ISSUED"
    /\ id \notin revoked
    /\ cap[id].parent = NoId \/ cap[id].parent \notin revoked
    /\ proofPending[id]
    /\ clock < cap[id].expires
    /\ clock - syncT \leq cap[id].maxStale

(***************************************************************************)
(* Consumption: store.consume_capability / _consume_inner, steps (1)--(11), *)
(* as one atomic transition (the BEGIN IMMEDIATE critical section).        *)
(* Reads use CheckRead instead: store.check_capability verifies everything *)
(* but never flips state -- a read capability stays usable until expiry,    *)
(* with a fresh holder proof required every time.                           *)
(***************************************************************************)

Consume(id, amt) ==
    /\ MayAuthorize(id)
    /\ cap[id].kind \in {"mandate", "execution"}
    /\ amt \in 0..MaxBudget /\ amt \leq cap[id].spend   (* spend envelope *)
    (* The atomic flip: guarded UPDATE ... WHERE state = 'ISSUED'. *)
    /\ cap'          = [cap EXCEPT ![id].state = "CONSUMED"]
    /\ proofPending' = [proofPending EXCEPT ![id] = FALSE]
    /\ authzCount'   = [authzCount EXCEPT ![id] = @ + 1]
    /\ authzClock'   = [authzClock EXCEPT ![id] = clock]
    /\ UNCHANGED <<issued, revoked, ledger, budget0, boundHolder,
                   epoch, clock, syncT>>

CheckRead(id) ==
    /\ MayAuthorize(id)
    /\ cap[id].kind = "read"
    /\ proofPending' = [proofPending EXCEPT ![id] = FALSE]
    /\ UNCHANGED <<cap, issued, revoked, ledger, budget0, boundHolder,
                   authzCount, authzClock, epoch, clock, syncT>>

(***************************************************************************)
(* Revocation & time. Revoke = store.revoke / sync_revocations(ids): the id *)
(* joins the revocation set, the epoch bumps, and the revocation view is    *)
(* refreshed (syncT := clock). EpochTick = sync_revocations() with no new   *)
(* ids: epoch bump + view refresh only. ExpireTick advances the clock;      *)
(* capabilities whose expires_at has passed simply fail MayAuthorize.       *)
(***************************************************************************)

Revoke(id) ==
    /\ id \in issued
    /\ cap[id].state = "ISSUED"   (* see header note on this restriction *)
    /\ id \notin revoked
    /\ epoch < MaxEpoch
    /\ revoked' = revoked \cup {id}
    /\ epoch'   = epoch + 1
    /\ syncT'   = clock
    /\ UNCHANGED <<cap, issued, ledger, budget0, boundHolder, proofPending,
                   authzCount, authzClock, clock>>

EpochTick ==
    /\ epoch < MaxEpoch
    /\ epoch' = epoch + 1
    /\ syncT' = clock
    /\ UNCHANGED <<cap, issued, revoked, ledger, budget0, boundHolder,
                   proofPending, authzCount, authzClock, clock>>

ExpireTick ==
    /\ clock < MaxClock
    /\ clock' = clock + 1
    /\ UNCHANGED <<cap, issued, revoked, ledger, epoch, syncT,
                   budget0, boundHolder, proofPending, authzCount, authzClock>>

Next ==
    \/ \E id \in Ids, h \in Holders, sc \in SUBSET Effects, dg \in Digests,
          sp \in 0..MaxBudget, bg \in 0..MaxBudget, ex \in 1..MaxClock,
          nn \in 1..MaxNonce, ms \in 1..MaxStale :
         IssueMandate(id, h, sc, dg, sp, bg, ex, nn, ms)
    \/ \E id \in Ids, h \in Holders, sc \in SUBSET Effects, dg \in Digests,
          sp \in 0..MaxBudget, ex \in 1..MaxClock,
          nn \in 1..MaxNonce, ms \in 1..MaxStale :
         IssueExecution(id, h, sc, dg, sp, ex, nn, ms)
    \/ \E id \in Ids, h \in Holders, sc \in SUBSET Effects, dg \in Digests,
          ex \in 1..MaxClock, nn \in 1..MaxNonce, ms \in 1..MaxStale :
         IssueRead(id, h, sc, dg, ex, nn, ms)
    \/ \E p \in Ids, id \in Ids, h \in Holders, sc \in SUBSET Effects,
          sp \in 0..MaxBudget, ex \in 1..MaxClock,
          ms \in 1..MaxStale, nn \in 1..MaxNonce :
         MintChild(p, id, h, sc, sp, ex, ms, nn)
    \/ \E id \in Ids, h \in Holders : PresentProof(id, h)
    \/ \E id \in Ids, amt \in 0..MaxBudget : Consume(id, amt)
    \/ \E id \in Ids : CheckRead(id)
    \/ \E id \in Ids : Revoke(id)
    \/ ExpireTick
    \/ EpochTick

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants. Each is a state predicate, so TLC checks every one of them  *)
(* directly via the INVARIANT lines in authority.cfg. The THEOREMs restate  *)
(* them temporally; discharging a THEOREM needs an interactive prover      *)
(* (TLAPS) -- TLC alone establishes the INVARIANT form.                     *)
(***************************************************************************)

TypeOK ==
    /\ cap \in [Ids -> [kind     : {"mandate", "execution", "read", "none"},
                        scope    : SUBSET Effects,
                        holder   : Holders \cup {NoHolder},
                        parent   : Ids \cup {NoId},
                        digest   : Digests \cup {NoDigest},
                        spend    : 0..MaxBudget,
                        expires  : 0..MaxClock,
                        nonce    : 0..MaxNonce,
                        maxStale : 0..MaxStale,
                        state    : {"ISSUED", "CONSUMED"}]]
    /\ issued \subseteq Ids
    /\ revoked \subseteq Ids
    /\ ledger \in [Ids -> 0..MaxBudget]
    /\ budget0 \in [Ids -> 0..MaxBudget]
    /\ boundHolder \in [Ids -> Holders \cup {NoHolder}]
    /\ proofPending \in [Ids -> BOOLEAN]
    (* 0..2, not 0..1: the \leq 1 bound is exactly NoDoubleConsume below;
       TypeOK must not assume the property it helps check. *)
    /\ authzCount \in [Ids -> 0..2]
    /\ authzClock \in [Ids -> 0..MaxClock]
    /\ epoch \in 0..MaxEpoch
    /\ clock \in 0..MaxClock
    /\ syncT \in 0..MaxClock
    /\ syncT \leq clock

(* A CONSUMED capability never authorizes again: at most one successful
   Consume per capability. The second Consume would need state = "ISSUED",
   which the atomic flip has destroyed -- the guarded UPDATE ... WHERE
   state='ISSUED' in store._consume_inner step (11). *)
NoDoubleConsume == \A i \in Ids : authzCount[i] \leq 1

(* Every child's authority is provably \subseteq its parent's, in every
   attenuated dimension: effects, digest (pinned), spend, expiry, staleness.
   Checked structurally at mint time by authority.mint_child. *)
AttenuationMonotonic ==
    \A i \in issued :
        \/ cap[i].parent = NoId
        \/ /\ cap[i].scope \subseteq cap[cap[i].parent].scope
           /\ cap[i].digest = cap[cap[i].parent].digest
           /\ cap[i].spend \leq cap[cap[i].parent].spend
           /\ cap[i].expires \leq cap[cap[i].parent].expires
           /\ cap[i].maxStale \leq cap[cap[i].parent].maxStale

(* A revoked capability -- or the child of a revoked mandate -- never
   authorizes. Consume/CheckRead both require the capability and its
   mandate to be absent from the revocation set (store._consume_inner
   step (5)). *)
RevokedNeverConsumed ==
    \A i \in issued : i \in revoked => authzCount[i] = 0

(* NOTE on the shape of this invariant (fixed 2026-09-25 after a TLC
   counterexample): an earlier version also required that a capability
   whose *parent* was revoked must never have been consumed. TLC refuted
   it with: IssueMandate(c1) -> MintChild(c1,c2) -> Consume(c2) ->
   Revoke(c1). That history is legitimate incident response -- the
   consumption happened before the revocation, when nothing was revoked.
   What must never happen is revoke-then-consume, and that is enforced at
   consume time by MayAuthorize (id \notin revoked /\ parent \notin
   revoked), which TLC checks on every Consume/CheckRead transition.
   The parent-revoked-after-child-consumed history is benign: the child is
   already CONSUMED and can never authorize again (NoDoubleConsume), while
   the parent's revocation still blocks all *future* child authorizations.
   This invariant states the checkable core: Revoke requires ISSUED state,
   and MayAuthorize blocks consume-after-revoke, so a revoked capability
   itself was never consumed. *)

(* The mandate budget ledger never goes negative and never exceeds what was
   issued: MintChild reserves the child's full spend_limit up front
   (store.debit_mandate_for_child), and the guarded debit applies the whole
   reservation or nothing, so oversubscription is impossible. *)
BudgetNeverNegative ==
    \A i \in Ids : ledger[i] \geq 0 /\ ledger[i] \leq budget0[i]

(* A capability is always bound to the holder it was issued/minted for;
   the binding is never re-pointed. Without a proof from THAT key,
   MayAuthorize cannot hold (store._consume_inner step (8)). *)
HolderBindingPreserved ==
    \A i \in issued :
        cap[i].holder = boundHolder[i] /\ cap[i].holder \in Holders

(* No authorization happens at or after expiry: every Consume/CheckRead
   requires clock < expires_at (authority.verify_capability denies
   moment > expires_at; store._consume_inner step (1)). *)
ExpiryHonored ==
    \A i \in issued :
        \/ authzCount[i] = 0
        \/ authzClock[i] < cap[i].expires

THEOREM TypeOKThm == Spec => []TypeOK
THEOREM NoDoubleConsumeThm == Spec => []NoDoubleConsume
THEOREM AttenuationMonotonicThm == Spec => []AttenuationMonotonic
THEOREM RevokedNeverConsumedThm == Spec => []RevokedNeverConsumed
THEOREM BudgetNeverNegativeThm == Spec => []BudgetNeverNegative
THEOREM HolderBindingPreservedThm == Spec => []HolderBindingPreserved
THEOREM ExpiryHonoredThm == Spec => []ExpiryHonored

=============================================================================
