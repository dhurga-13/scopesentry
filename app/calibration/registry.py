"""Calibration fixture registry for ScopeSentry-R.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional
from app.calibration.models import ProviderGroundTruthFixture


class FixtureRegistry:
    """Registry managing calibrated provider ground truth records."""

    def __init__(self, fixtures_dir: Optional[Path] = None):
        self.fixtures_dir = fixtures_dir or (Path(__file__).parent / "fixtures")
        self._fixtures: Dict[str, ProviderGroundTruthFixture] = {}
        self._load_fixtures()

    def _load_fixtures(self) -> None:
        if not self.fixtures_dir.exists():
            return
        for file in self.fixtures_dir.glob("*.json"):
            try:
                data = json.loads(file.read_text(encoding="utf-8"))
                fixture = ProviderGroundTruthFixture(**data)
                if not fixture.signature:
                    fixture.signature = fixture.compute_signature()
                self._fixtures[fixture.fixture_id] = fixture
            except Exception:
                continue

    def register(self, fixture: ProviderGroundTruthFixture) -> None:
        if not fixture.signature:
            fixture.signature = fixture.compute_signature()
        self._fixtures[fixture.fixture_id] = fixture

    def get(self, fixture_id: str) -> Optional[ProviderGroundTruthFixture]:
        return self._fixtures.get(fixture_id)

    def find_applicable(
        self,
        provider: str,
        provider_config_version: str,
        topology_hash: str,
        revoked_role: str = "parent",
    ) -> Optional[ProviderGroundTruthFixture]:
        """Finds a matching ground-truth fixture.
        
        Matches precisely on topology_hash when present.
        If topology_hash is "__placeholder__", falls back to matching on
        provider, provider_config_version, and revoked_role.
        """
        for fixture in self._fixtures.values():
            if (
                fixture.provider == provider
                and fixture.provider_config_version == provider_config_version
                and fixture.revoked_role == revoked_role
            ):
                if fixture.topology_hash == topology_hash or fixture.topology_hash == "__placeholder__":
                    return fixture
        return None

    def list_all(self) -> List[ProviderGroundTruthFixture]:
        return list(self._fixtures.values())


_GLOBAL_REGISTRY: Optional[FixtureRegistry] = None


def get_fixture_registry() -> FixtureRegistry:
    global _GLOBAL_REGISTRY
    if _GLOBAL_REGISTRY is None:
        _GLOBAL_REGISTRY = FixtureRegistry()
    return _GLOBAL_REGISTRY
