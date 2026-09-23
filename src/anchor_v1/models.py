"""ANCHOR v1 — shared foundation models (coordinator-owned).

This module holds only primitives that every capability module imports.
Capability-specific payloads live in their own modules (one owner each).
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SignedEnvelope(StrictModel):
    alg: Literal["Ed25519"] = "Ed25519"
    key_id: str
    payload: dict[str, Any]
    signature: str
