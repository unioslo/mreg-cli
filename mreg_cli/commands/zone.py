"""Zone commands for mreg_cli."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_api.models import ForwardZone, ReverseZone
from typing_extensions import NotRequired, TypedDict

from mreg_cli.client import get_client
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import InputFailure
from mreg_cli.output import output_delegations, output_zone, output_zones
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag

command_registry = CommandRegistry()


def _output_zones_by_type(forward: bool, reverse: bool) -> None:
    """Fetch and output zones of the given type(s).

    :param forward: Whether to list forward zones.
    :param reverse: Whether to list reverse zones.
    """
    client = get_client()
    zones: list[ForwardZone | ReverseZone] = []
    if forward:
        zones.extend(client.zone.list_forward())
    if reverse:
        zones.extend(client.zone.list_reverse())
    output_zones(zones)


class ZoneCommands(BaseCommand):
    """Zone commands for the CLI."""

    def __init__(self, cli: Any) -> None:
        """Initialize the zone commands."""
        super().__init__(cli, command_registry, "zone", "Manage zones.", "Manage zones")


@command_registry.register_command(
    prog="create",
    description="Create new zone.",
    short_desc="Create new zone.",
    flags=[
        Flag("zone", description="Zone name.", metavar="ZONE"),
        Flag("email", description="Contact email.", metavar="EMAIL"),
        Flag("ns", description="Nameservers of the zone.", nargs="+", metavar="NS"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def create(args: argparse.Namespace) -> None:
    """Create a new zone.

    :param args: argparse.Namespace (ns, force, zone, email)
    """
    zone: str = args.zone
    email: str = args.email
    ns: list[str] = args.ns
    force: bool = args.force

    client = get_client()
    zone_obj = client.zone.create(name=zone, email=email, primary_ns=ns, force=force)
    OutputManager().add_ok(f"Created zone {zone_obj.name}")


@command_registry.register_command(
    prog="delegation_create",
    description=(
        "Create new zone delegation. Requires force if ns or zone doesn't exist in MREG."
    ),
    short_desc="Create new zone delegation.",
    flags=[
        Flag("zone", description="Zone name.", metavar="ZONE"),
        Flag("delegation", description="Delegation", metavar="DELEGATION"),
        Flag("ns", description="Nameservers for the delegation.", nargs="+", metavar="NS"),
        Flag("-comment", description="Comment with a description", metavar="COMMENT"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def delegation_create(args: argparse.Namespace) -> None:
    """Create a new zone delegation.

    :param args: argparse.Namespace (ns, force, zone, delegation, comment)
    """
    zone: str = args.zone
    delegation: str = args.delegation
    ns: list[str] = args.ns
    comment: str | None = args.comment
    force: bool = args.force

    client = get_client()
    zone_obj = client.zone.get_by_name(zone)
    dele = client.delegation.create(
        zone_obj,
        name=delegation,
        nameservers=ns,
        comment=comment or "",
        force=force,
    )
    OutputManager().add_ok(f"Created zone delegation {dele.name}")


@command_registry.register_command(
    prog="delete",
    description="Delete a zone",
    short_desc="Delete a zone",
    flags=[
        Flag("zone", description="Zone name.", metavar="ZONE"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def zone_delete(args: argparse.Namespace) -> None:
    """Delete a zone.

    :param args: argparse.Namespace (zone, force)
    """
    zone: str = args.zone
    force: bool = args.force

    client = get_client()
    zone_obj = client.zone.get_by_name(zone)
    client.zone.delete(zone_obj, force=force)
    OutputManager().add_ok(f"Deleted zone {zone_obj.name}")


@command_registry.register_command(
    prog="delegation_delete",
    description="Delete a zone delegation",
    short_desc="Delete a zone delegation",
    flags=[
        Flag("zone", description="Zone name.", metavar="ZONE"),
        Flag("delegation", description="Delegation", metavar="DELEGATION"),
    ],
)
def delegation_delete(args: argparse.Namespace) -> None:
    """Delete a zone delegation.

    :param args: argparse.Namespace (zone, delegation)
    """
    # NOTE: how to handle delegation that has delegation?
    # i.e. uio.no -> pederhan.uio.no -> sub.pederhan.uio.no
    # and we try to delete pederhan.uio.no?
    zone: str = args.zone
    delegation: str = args.delegation

    client = get_client()
    zone_obj = client.zone.get_by_name(zone)
    client.delegation.delete(zone_obj, delegation)
    OutputManager().add_ok(f"Removed zone delegation {delegation}")


@command_registry.register_command(
    prog="info",
    description="Delete a zone",
    short_desc="Delete a zone",
    flags=[
        Flag("zone", description="Zone name.", metavar="ZONE"),
    ],
)
def info(args: argparse.Namespace) -> None:
    """Show SOA info for a existing zone.

    :param args: argparse.Namespace (zone)
    """
    zone: str = args.zone

    client = get_client()
    zone_obj = client.zone.get_by_name(zone)
    output_zone(zone_obj)


@command_registry.register_command(
    prog="list",
    description="List zones",
    short_desc="List zones",
    flags=[
        Flag(
            "-forward",
            action="store_true",
            short_desc="List all forward zones",
            description="List all forward zones",
        ),
        Flag(
            "-reverse",
            action="store_true",
            short_desc="List all reverse zones",
            description="List all reverse zones",
        ),
    ],
)
def zone_list(args: argparse.Namespace) -> None:
    """List all zones.

    :param args: argparse.Namespace (forward, reverse)
    """
    if not (args.forward or args.reverse):
        raise InputFailure("Add either -forward or -reverse as argument")
    _output_zones_by_type(args.forward, args.reverse)


@command_registry.register_command(
    prog="delegation_list",
    description="List a zone's delegations",
    short_desc="List a zone's delegations",
    flags=[
        Flag("zone", description="Zone name.", metavar="ZONE"),
    ],
)
def zone_delegation_list(args: argparse.Namespace) -> None:
    """List a zone's delegations.

    :param args: argparse.Namespace (zone)
    """
    zone: str = args.zone
    client = get_client()
    zone_obj = client.zone.get_by_name(zone)
    output_delegations(zone_obj)


@command_registry.register_command(
    prog="delegation_comment_set",
    description="Set a comment for zone delegation",
    short_desc="Set a comment for zone delegation",
    flags=[
        Flag("zone", description="Zone name", metavar="ZONE"),
        Flag("delegation", description="Delegation", metavar="DELEGATION"),
        Flag("comment", description="Comment", metavar="COMMENT"),
    ],
)
def zone_delegation_comment_set(args: argparse.Namespace) -> None:
    """Set a delegation's comment.

    :param args: argparse.Namespace (zone, delegation, comment)
    """
    zone: str = args.zone
    delegation: str = args.delegation
    comment: str = args.comment

    client = get_client()
    zone_obj = client.zone.get_by_name(zone)
    client.delegation.set_comment(zone_obj, delegation, comment)
    OutputManager().add_ok(f"Updated comment for {delegation}")


@command_registry.register_command(
    prog="delegation_comment_remove",
    description="Remove a comment for zone delegation",
    short_desc="Remove a comment for zone delegation",
    flags=[
        Flag("zone", description="Zone name", metavar="ZONE"),
        Flag("delegation", description="Delegation", metavar="DELEGATION"),
    ],
)
def zone_delegation_comment_remove(args: argparse.Namespace) -> None:
    """Remove a delegation's comment.

    :param args: argparse.Namespace (zone, delegation)
    """
    zone: str = args.zone
    delegation: str = args.delegation

    client = get_client()
    zone_obj = client.zone.get_by_name(zone)
    client.delegation.set_comment(zone_obj, delegation, "")
    OutputManager().add_ok(f"Removed comment for {delegation}")


@command_registry.register_command(
    prog="set_ns",
    description="Update nameservers for an existing zone.",
    short_desc="Update nameservers for an existing zone.",
    flags=[
        Flag("zone", description="Zone name.", metavar="ZONE"),
        Flag("ns", description="Nameservers of the zone.", nargs="+", metavar="NS"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def set_ns(args: argparse.Namespace) -> None:
    """Update nameservers for an existing zone.

    If multiple nameservers are provided, the first one is set as the primary nameserver.

    :param args: argparse.Namespace (zone, ns, force)
    """
    zone: str = args.zone
    ns: list[str] = args.ns
    force: bool = args.force

    client = get_client()
    zone_obj = client.zone.get_by_name(zone)
    client.zone.set_nameservers(zone_obj, ns, force=force)
    OutputManager().add_ok(f"Updated nameservers for {zone}")


class ZoneSetSoaKwargs(TypedDict, total=False):
    """Keyword arguments for creating a network."""

    primary_ns: NotRequired[str]
    email: NotRequired[str]
    serialno: NotRequired[int]
    refresh: NotRequired[int]
    retry: NotRequired[int]
    expire: NotRequired[int]
    soa_ttl: NotRequired[int]


@command_registry.register_command(
    prog="set_soa",
    description="Updated the SOA of a zone.",
    short_desc="Updated the SOA of a zone.",
    flags=[
        Flag("zone", description="Zone name.", metavar="ZONE"),
        Flag("-ns", description="Primary nameserver (SOA MNAME).", metavar="PRIMARY-NS"),
        Flag("-email", description="Zone contact email.", metavar="EMAIL"),
        Flag("-serialno", description="Serial number.", flag_type=int, metavar="SERIALNO"),
        Flag("-refresh", description="Refresh time.", flag_type=int, metavar="REFRESH"),
        Flag("-retry", description="Retry time.", flag_type=int, metavar="RETRY"),
        Flag("-expire", description="Expire time.", flag_type=int, metavar="EXPIRE"),
        Flag("-soa-ttl", description="SOA Time To Live", flag_type=int, metavar="TTL"),
    ],
)
def set_soa(args: argparse.Namespace) -> None:
    """Update the SOA of a zone.

    :param args: argparse.Namespace (zone, ns, email, serialno, retry, expire, soa_ttl)
    """
    client = get_client()
    zone: str = args.zone
    primary_ns: str | None = args.ns
    email: str | None = args.email
    serialno: int | None = args.serialno
    refresh: int | None = args.refresh
    retry: int | None = args.retry
    expire: int | None = args.expire
    soa_ttl: int | None = args.soa_ttl

    kwargs: ZoneSetSoaKwargs = {}
    if primary_ns is not None:
        kwargs["primary_ns"] = primary_ns
    if email is not None:
        kwargs["email"] = email
    if serialno is not None:
        kwargs["serialno"] = serialno
    if refresh is not None:
        kwargs["refresh"] = refresh
    if retry is not None:
        kwargs["retry"] = retry
    if expire is not None:
        kwargs["expire"] = expire
    if soa_ttl is not None:
        kwargs["soa_ttl"] = soa_ttl

    if not kwargs:
        raise InputFailure(
            "At least one of the following must be provided: ns, email, serialno, refresh, retry, expire, soa_ttl"
        )

    zone_obj = client.zone.get_by_name(zone)
    client.zone.update_soa(zone_obj, **kwargs)
    OutputManager().add_ok(f"Updated SOA for {zone}")


@command_registry.register_command(
    prog="set_default_ttl",
    description="Set the default TTL of a zone.",
    short_desc="Set the default TTL of a zone.",
    flags=[
        Flag("zone", description="Zone name.", metavar="ZONE"),
        Flag("ttl", description="Default Time To Live.", flag_type=int, metavar="TTL"),
    ],
)
def set_default_ttl(args: argparse.Namespace) -> None:
    """Update the default TTL of a zone.

    :param args: argparse.Namespace (zone, ttl)
    """
    zone: str = args.zone
    ttl: int = args.ttl

    client = get_client()
    zone_obj = client.zone.get_by_name(zone)
    client.zone.set_default_ttl(zone_obj, ttl)
    OutputManager().add_ok(f"Set default TTL for {zone}")
