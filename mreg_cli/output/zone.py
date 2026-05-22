"""Zone output functions."""

from __future__ import annotations

from collections.abc import Sequence

from mreg_api.models import ForwardZone, NameServer, ReverseZone, Zone

from mreg_cli.output.base import output_ttl
from mreg_cli.outputmanager import OutputManager


def output_zone(zone: Zone, padding: int = 20) -> None:
    """Output a single zone.

    :param zone: Zone to output.
    :param padding: Number of spaces for left-padding the labels.
    """
    manager = OutputManager()

    def fmt(label: str, text: str) -> None:
        manager.add_line(f"{label:<{padding}}{text}")

    fmt("Name:", zone.name)
    output_nameservers(zone.nameservers, padding=padding)
    fmt("Primary NS:", zone.primary_ns)
    fmt("Email:", zone.email)
    fmt("Serial:", str(zone.serialno))
    fmt("Refresh:", str(zone.refresh))
    fmt("Retry:", str(zone.retry))
    fmt("Expire:", str(zone.expire))
    output_ttl(zone, "SOA TTL", "soa_ttl", padding)
    output_ttl(zone, "Default TTL", "default_ttl", padding)


def output_zones(
    zones: Sequence[ForwardZone | ReverseZone],
) -> None:
    """Output a list of zones.

    :param zones: List of zones to output.
    """
    manager = OutputManager()
    if not zones:
        manager.add_line("No zones found.")
        return

    manager.add_line("Zones:")
    for zone in zones:
        manager.add_line(f" {zone.name}")


def output_nameservers(
    nameservers: Sequence[NameServer],
    padding: int = 20,
) -> None:
    """Output nameservers for a zone.

    :param nameservers: List of nameservers to output.
    :param padding: Number of spaces for left-padding the output.
    """
    manager = OutputManager()

    def fmt_ns(label: str, hostname: str, ttl: str) -> None:
        manager.add_line(f"        {label:<{padding}}{hostname:<20}{ttl}")

    fmt_ns("Nameservers:", "hostname", "TTL")
    for ns in nameservers:
        # We don't have a TTL value for nameservers from the API
        fmt_ns("", ns.name, "<not set>")


def output_delegations(zone: Zone, padding: int = 20) -> None:
    """Output the delegations of a zone.

    :param zone: Zone whose delegations to output.
    :param padding: Number of spaces for left-padding the output.
    """
    delegations = zone.get_delegations()

    manager = OutputManager()
    if not delegations:
        manager.add_line(f"No delegations for {zone.name}.")
        return

    manager.add_line("Delegations:")
    for delegation in sorted(delegations, key=lambda d: d.name):
        manager.add_line(f"    {delegation.name}")
        if delegation.comment:
            manager.add_line(f"        Comment: {delegation.comment}")
        output_nameservers(delegation.nameservers, padding=padding)
