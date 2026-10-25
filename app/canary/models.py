"""Canary credential and topology models for ScopeSentry-R.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


CanaryRole = Literal["parent", "child", "sibling", "replacement"]


class CanaryCredential(BaseModel):
    """A synthetic or disposable credential issued within a canary family."""
    credential_id: str
    role: CanaryRole
    token: str
    scopes: List[str]
    parent_id: Optional[str] = None
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    status: Literal["active", "revoked", "invalidated", "unknown"] = "active"


class CanaryTopology(BaseModel):
    """The dependency relationship topology of a canary credential family."""
    family_id: str
    provider: str
    credentials: Dict[str, CanaryCredential]
    edges: List[Dict[str, str]]
    topology_hash: str = ""

    def compute_hash(self) -> str:
        """Computes deterministic SHA256 of the canary topology structure."""
        normalized = {
            "provider": self.provider,
            "roles": sorted([c.role for c in self.credentials.values()]),
            "edges": sorted([f"{e.get('from')}->{e.get('to')}" for e in self.edges]),
        }
        raw = json.dumps(normalized, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
