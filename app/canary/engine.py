"""Canary topology construction engine for ScopeSentry-R.
"""
from __future__ import annotations

import uuid
from typing import Dict, List, Optional
from app.canary.models import CanaryCredential, CanaryRole, CanaryTopology


def build_canary_family(
    provider: str,
    target_scopes: List[str],
    parent_scopes: Optional[List[str]] = None,
    sibling_scopes: Optional[List[str]] = None,
) -> CanaryTopology:
    """Builds a dependency-equivalent canary credential family with 4 roles.
    
    Roles:
      - parent: original authorizing identity
      - child: downstream/delegated token derived from parent
      - sibling: parallel token authorized by the same authority
      - replacement: candidate replacement credential that will take over duties
    """
    family_id = f"canary-fam-{uuid.uuid4().hex[:8]}"

    p_scopes = parent_scopes or list(target_scopes)
    c_scopes = list(target_scopes)
    s_scopes = sibling_scopes or list(target_scopes)
    r_scopes = list(target_scopes)

    parent_id = f"{family_id}-parent"
    child_id = f"{family_id}-child"
    sibling_id = f"{family_id}-sibling"
    replacement_id = f"{family_id}-replacement"

    creds: Dict[str, CanaryCredential] = {
        "parent": CanaryCredential(
            credential_id=parent_id,
            role="parent",
            token=f"tok-{uuid.uuid4().hex[:12]}",
            scopes=p_scopes,
            parent_id=None,
        ),
        "child": CanaryCredential(
            credential_id=child_id,
            role="child",
            token=f"tok-{uuid.uuid4().hex[:12]}",
            scopes=c_scopes,
            parent_id=parent_id,
        ),
        "sibling": CanaryCredential(
            credential_id=sibling_id,
            role="sibling",
            token=f"tok-{uuid.uuid4().hex[:12]}",
            scopes=s_scopes,
            parent_id=None,
        ),
        "replacement": CanaryCredential(
            credential_id=replacement_id,
            role="replacement",
            token=f"tok-{uuid.uuid4().hex[:12]}",
            scopes=r_scopes,
            parent_id=None,
        ),
    }

    edges = [
        {"from": "parent", "to": "child", "type": "delegation"},
        {"from": "parent", "to": "sibling", "type": "parallel_authority"},
        {"from": "parent", "to": "replacement", "type": "candidate_successor"},
    ]

    topo = CanaryTopology(
        family_id=family_id,
        provider=provider,
        credentials=creds,
        edges=edges,
    )
    topo.topology_hash = topo.compute_hash()
    return topo
