"""Zone-related utilities for mreg_cli."""

from __future__ import annotations

from typing import Any

from mreg_cli.exceptions import EntityOwnershipMismatch, ForceMissing
from mreg_cli.utilities.api import get


def zoneinfo_for_hostname(host: str) -> dict[str, Any] | None:
    """Return zoneinfo for a hostname, or None if not found or invalid."""
    if "." not in host:
        return None

    path = f"/api/v1/zones/forward/hostname/{host}"
    zoneinfo = get(path, ok404=True)
    return None if zoneinfo is None else zoneinfo.json()


def zone_check_for_hostname(name: str, force: bool, require_zone: bool = False) -> None:
    """Check if a hostname is in a zone controlled by MREG."""
    # Require force if FQDN not in MREG zone
    zoneinfo = zoneinfo_for_hostname(name)
    if zoneinfo is None:
        if require_zone:
            raise EntityOwnershipMismatch(f"{name} isn't in a zone controlled by MREG.")
        if not force:
            raise ForceMissing(f"{name} isn't in a zone controlled by MREG, must force")
    elif "delegation" in zoneinfo and not force:
        delegation = zoneinfo["delegation"]["name"]
        raise ForceMissing(f"{name} is in zone delegation {delegation}, must force")
