"""Zone commands for mreg_cli."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_cli.api.models import Zone
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import DeleteError, InputFailure
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag

command_registry = CommandRegistry()


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
    Zone.create_zone(args.zone, args.email, args.ns, args.force)
    OutputManager().add_ok(f"Created zone {args.zone}")


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
    zone = Zone.get_zone_or_raise(args.zone)
    zone.create_delegation(args.delegation, args.ns, args.comment, args.force)
    OutputManager().add_ok(f"Created zone delegation {args.delegation}")


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
    zone = Zone.get_zone_or_raise(args.zone)
    if zone.delete_zone(args.force):
        OutputManager().add_ok(f"Deleted zone {zone.name}")
    else:
        raise DeleteError(f"Unable to delete zone {zone.name}")


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
    zone = Zone.get_zone_or_raise(args.zone)
    if zone.delete_delegation(args.delegation):
        OutputManager().add_ok(f"Removed zone delegation {args.delegation}")
    else:
        raise DeleteError(f"Unable to delete delegation {args.delegation}")


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
    zone = Zone.get_zone_or_raise(args.zone)
    zone.output()


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
    Zone.output_zones(args.forward, args.reverse)


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
    zone = Zone.get_zone_or_raise(args.zone)
    zone.output_delegations()


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
    zone = Zone.get_zone_or_raise(args.zone)
    zone.set_delegation_comment(args.delegation, args.comment)
    OutputManager().add_ok(f"Updated comment for {args.delegation}")


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
    """Set a delegation's comment.

    :param args: argparse.Namespace (zone, delegation)
    """
    zone = Zone.get_zone_or_raise(args.zone)
    zone.set_delegation_comment(args.delegation, "")
    OutputManager().add_ok(f"Removed comment for {args.delegation}")


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
    zone = Zone.get_zone_or_raise(args.zone)
    zone.update_nameservers(args.ns, args.force)
    OutputManager().add_ok(f"Updated nameservers for {args.zone}")


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
    zone = Zone.get_zone_or_raise(args.zone)
    zone.update_soa(
        primary_ns=args.ns,
        email=args.email,
        serialno=args.serialno,
        refresh=args.refresh,
        retry=args.retry,
        expire=args.expire,
        soa_ttl=args.soa_ttl,
    )
    OutputManager().add_ok(f"Updated SOA for {args.zone}")


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
    zone = Zone.get_zone_or_raise(args.zone)
    zone.set_default_ttl(args.ttl)
    OutputManager().add_ok(f"Set default TTL for {args.zone}")
