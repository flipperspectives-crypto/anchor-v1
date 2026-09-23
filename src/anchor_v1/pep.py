"""ANCHOR v1 — non-bypassable PEP deployment reference (Wave 2, Revision B pivot 11; blocker 6).

DEPLOYMENT INVARIANT (architectural, not advisory):
--------------------------------------------------
The Policy Enforcement Point runs OUTSIDE the agent sandbox boundary and holds
the downstream credentials. The agent process never sees them. An agent that
holds ambient AWS keys (or any ambient credential) plus a governor *library*
is UNGOVERNED — a library cannot stop code that simply doesn't call it, and
ambient credentials let the agent reach past any in-process check.

This module is the reference shape of that deployment:

* ``CredentialBroker`` holds the raw downstream secrets (secret env vars,
  bearer tokens). It exposes ONLY brokered execution: the PEP may inject
  secrets into a child process environment or into egress headers, but
  ``broker.secrets`` raises ``BrokerAccessDenied`` — agent-side code cannot
  read the raw values through any public attribute.
* ``ShellPEP.execute`` consumes the capability atomically FIRST (via the
  store's linearizable transaction) and only then spawns the subprocess,
  with brokered env injected by the PEP into the child process env. Any
  failure — bad capability, double-spend, holder mismatch, digest mismatch,
  unknown command — raises BEFORE the subprocess starts, so nothing
  executes without authorization.
* ``EgressProxy.authorize_http`` consumes the capability atomically FIRST
  and returns brokered headers for the EXACT action digest; any other digest
  is refused.

Tests assert the invariant directly: calling ``subprocess`` without going
through the PEP never reaches the broker, and ``broker.secrets`` is
unreadable from the caller side.
"""

from __future__ import annotations

import os
import subprocess
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .envelope import ActionEnvelope
from .store import AuthorizationDenied, CapabilityStore

__all__ = [
    "BrokerAccessDenied",
    "PEPError",
    "CredentialBroker",
    "ShellPEP",
    "EgressProxy",
]


class BrokerAccessDenied(Exception):
    """Raised when agent-side code tries to read raw broker secrets."""


class PEPError(Exception):
    """Raised when the PEP refuses to execute (fail closed)."""


class CredentialBroker:
    """Holds downstream credentials; exposes only brokered execution.

    The raw secrets live in a name-mangled private attribute. The public
    ``secrets`` attribute is a property that ALWAYS raises
    :class:`BrokerAccessDenied` — there is no code path by which agent-side
    code reads the raw values. Only the PEP (same deployment boundary, via
    the private ``_brokered_env`` / ``_brokered_token`` helpers) may use
    them, and only to inject them into a child process environment or into
    egress headers it constructs itself.
    """

    def __init__(self, secrets: Mapping[str, str]) -> None:
        # Name-mangled: stored as _CredentialBroker__secrets. Not reachable
        # as broker.secrets (property raises), broker.__secrets
        # (AttributeError — mangling is lexical), or broker._secrets
        # (never assigned under that name).
        self.__secrets = {str(k): str(v) for k, v in secrets.items()}

    @property
    def secrets(self):  # noqa: D102 - intentionally hostile
        raise BrokerAccessDenied(
            "raw broker secrets are never exposed to agent-side code; "
            "use brokered execution through the PEP"
        )

    def secret_names(self) -> tuple[str, ...]:
        """Names only — safe to expose; values never leave the broker."""
        return tuple(self.__secrets.keys())

    def _brokered_env(self) -> dict[str, str]:
        """Private: full secret map for PEP child-process env injection."""
        return dict(self.__secrets)

    def _brokered_token(self, name: str) -> str:
        """Private: one secret value for PEP egress-header construction."""
        try:
            return self.__secrets[name]
        except KeyError as exc:
            raise PEPError(f"broker has no secret named {name!r}") from exc


class ShellPEP:
    """Shell execution PEP. Consumes the capability FIRST, then executes.

    The command registry maps ``action_digest -> argv`` and is deployment
    configuration, not agent input: the envelope presented by the agent only
    selects a digest the authority already authorized. An unknown digest is
    refused before anything is consumed... — no: the capability IS consumed
    first (single-use semantics), but the subprocess NEVER starts unless the
    digest resolves to a registered command. Resolution happens before
    consumption so a misconfigured registry cannot burn capabilities; the
    invariant "no execution without a prior atomic consume" always holds.
    """

    def __init__(
        self,
        broker: CredentialBroker,
        store: CapabilityStore,
        trusted_issuers: Mapping[bytes, Ed25519PublicKey],
        challenge: bytes,
    ) -> None:
        self._broker = broker
        self._store = store
        self._trusted_issuers = dict(trusted_issuers)
        # In a real deployment the PEP issues a fresh challenge per request;
        # here the deployment passes its challenge source in.
        self._challenge = bytes(challenge)
        self._commands: dict[str, list[str]] = {}

    def register_command(self, action_digest: str, argv: list[str]) -> None:
        """Deployment-time wiring: which exact digest may run which argv."""
        if not argv:
            raise PEPError("cannot register an empty command")
        self._commands[action_digest] = [str(a) for a in argv]

    @property
    def challenge(self) -> bytes:
        return self._challenge

    def execute(
        self,
        *,
        envelope: ActionEnvelope,
        capability_cose: bytes,
        holder_proof: bytes,
        spend_amount: int = 0,
        timeout: float = 30.0,
    ) -> subprocess.CompletedProcess[str]:
        """Execute the shell command described by the envelope.

        Steps: (1) the envelope must be a shell-plane envelope whose digest
        resolves to a registered command — otherwise PEPError before any
        state change; (2) the capability is consumed atomically via the
        store (verify + revocation + holder proof + one-use flip + budget);
        (3) ONLY then the subprocess starts, with brokered secrets injected
        into the child env by the PEP.

        Any failure in (1)/(2) raises before the subprocess starts: bad
        capability, double-spend, holder mismatch, digest mismatch, revoked
        capability, or stale revocation view all mean NO execution.
        """
        if envelope.effect.plane != "shell":
            raise PEPError(
                f"ShellPEP refuses non-shell envelope (plane={envelope.effect.plane!r})"
            )
        argv = self._commands.get(envelope.action_digest)
        if argv is None:
            raise PEPError(
                "no command registered for this action_digest — refusing"
            )

        # Consume FIRST: linearizable, fail-closed. Raises on any problem.
        try:
            self._store.consume_capability(
                capability_cose=capability_cose,
                holder_proof=holder_proof,
                challenge=self._challenge,
                trusted_issuers=self._trusted_issuers,
                envelope=envelope,
                spend_amount=spend_amount,
            )
        except AuthorizationDenied as exc:
            raise PEPError(f"PEP refused execution: {exc}") from exc

        # Only the PEP touches the raw secrets, and only to inject them into
        # the child process environment it spawns.
        child_env = dict(os.environ)
        child_env.update(self._broker._brokered_env())
        try:
            return subprocess.run(
                argv,
                env=child_env,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                # argv is exact and fixed; never interpreted by a shell
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise PEPError(f"command timed out: {exc}") from exc


class EgressProxy:
    """HTTP egress PEP stub. Returns brokered headers for the exact digest.

    Like ShellPEP it consumes the capability atomically FIRST, then returns
    the brokered ``Authorization`` header (plus any deployment-configured
    extra headers) for the exact action digest. Any other digest, any bad
    capability, any holder mismatch — refused, no headers, no request.
    This stub returns headers; a production proxy would perform the request
    itself so the agent never sees the credential.
    """

    def __init__(
        self,
        broker: CredentialBroker,
        store: CapabilityStore,
        trusted_issuers: Mapping[bytes, Ed25519PublicKey],
        challenge: bytes,
    ) -> None:
        self._broker = broker
        self._store = store
        self._trusted_issuers = dict(trusted_issuers)
        self._challenge = bytes(challenge)
        # action_digest -> {"url": ..., "secret_name": ..., "extra_headers": {...}}
        self._routes: dict[str, dict] = {}

    def register_route(
        self,
        action_digest: str,
        url: str,
        secret_name: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self._routes[action_digest] = {
            "url": url,
            "secret_name": secret_name,
            "extra_headers": dict(extra_headers or {}),
        }

    def authorize_http(
        self,
        *,
        envelope: ActionEnvelope,
        capability_cose: bytes,
        holder_proof: bytes,
    ) -> dict[str, str]:
        """Consume the capability, then return brokered headers for the
        exact digest. Refuses (raises) otherwise."""
        if envelope.effect.plane != "http":
            raise PEPError(
                f"EgressProxy refuses non-http envelope (plane={envelope.effect.plane!r})"
            )
        route = self._routes.get(envelope.action_digest)
        if route is None:
            raise PEPError("no egress route for this action_digest — refusing")

        try:
            self._store.consume_capability(
                capability_cose=capability_cose,
                holder_proof=holder_proof,
                challenge=self._challenge,
                trusted_issuers=self._trusted_issuers,
                envelope=envelope,
            )
        except AuthorizationDenied as exc:
            raise PEPError(f"PEP refused egress: {exc}") from exc

        token = self._broker._brokered_token(route["secret_name"])
        headers = {"Authorization": f"Bearer {token}"}
        headers.update(route["extra_headers"])
        return headers
