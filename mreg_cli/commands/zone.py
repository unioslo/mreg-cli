"""Zone commands for mreg_cli."""
from __future__ import annotations

import argparse
from typing import Any

from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import HostNotFoundWarning
from mreg_cli.log import cli_error, cli_info, cli_warning
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag
from mreg_cli.utilities.api import delete, get, get_list, patch, post
from mreg_cli.utilities.host import host_info_by_name

command_registry = CommandRegistry()


class ZoneCommands(BaseCommand):
    """Zone commands for the CLI."""

    def __init__(self, cli: Any) -> None:
        """Initialize the zone commands."""
        super().__init__(cli, command_registry, "zone", "Manage zones.", "Manage zones")


def _verify_nameservers(nameservers: str, force: bool) -> None:
    """Verify that nameservers are in mreg and have A-records."""
    if not nameservers:
        cli_warning("At least one nameserver is required")

    errors = []
    for nameserver in nameservers:
        try:
            info = host_info_by_name(nameserver)
        except HostNotFoundWarning:
            if not force:
                errors.append(f"{nameserver} is not in mreg, must force")
        else:
            if info["zone"] is not None:
                if not info["ipaddresses"] and not force:
                    errors.append(f"{nameserver} has no A-record/glue, must force")
    if errors:
        cli_warning("\n".join(errors))


def format_ns(info: str, hostname: str, ttl: str, padding: int = 20) -> None:
    """Format nameserver output."""
    OutputManager().add_line(
        "        {1:<{0}}{2:<{3}}{4}".format(padding, info, hostname, 20, ttl)
    )


def zone_basepath(name: str) -> str:
    """Return the basepath for a zone."""
    basepath = "/api/v1/zones/"
    if name.endswith(".arpa"):
        return f"{basepath}reverse/"
    return f"{basepath}forward/"


def zone_path(name: str) -> str:
    """Return the path for a zone."""
    return zone_basepath(name) + name


def get_zone(name: str) -> tuple[dict[str, Any], str]:
    """Return the zone and path for a zone."""
    path = zone_path(name)
    zone = get(path, ok404=True)
    if zone is None:
        cli_warning(f"Zone '{name}' does not exist")
    return zone.json(), path


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
    _verify_nameservers(args.ns, args.force)
    path = zone_basepath(args.zone)
    post(path, name=args.zone, email=args.email, primary_ns=args.ns)
    cli_info(f"created zone {args.zone}", True)


@command_registry.register_command(
    prog="delegation_create",
    description="Create new zone delegation.",
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
    _, path = get_zone(args.zone)
    if not args.delegation.endswith(f".{args.zone}"):
        cli_warning(f"Delegation '{args.delegation}' is not in '{args.zone}'")
    _verify_nameservers(args.ns, args.force)
    post(
        f"{path}/delegations/",
        name=args.delegation,
        nameservers=args.ns,
        comment=args.comment,
    )
    cli_info(f"created zone delegation {args.delegation}", True)


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
    zone, path = get_zone(args.zone)
    hosts = get_list("/api/v1/hosts/", params={"zone": zone["id"]})
    zones = get_list(zone_basepath(args.zone), params={"name__endswith": f".{args.zone}"})

    # XXX: Not a fool proof check, as e.g. SRVs are not hosts. (yet.. ?)
    if hosts:
        cli_warning(f"Zone has {len(hosts)} registered entries. Can not delete.")
    other_zones = [z["name"] for z in zones if z["name"] != args.zone]
    if other_zones:
        zone_desc = ", ".join(sorted(other_zones))
        cli_warning(f"Zone has registered subzones: '{zone_desc}'. Can not delete")

    delete(path)
    cli_info("deleted zone {}".format(zone["name"]), True)


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
    _, path = get_zone(args.zone)
    if not args.delegation.endswith(f".{args.zone}"):
        cli_warning(f"Delegation '{args.delegation}' is not in '{args.zone}'")
    delete(f"{path}/delegations/{args.delegation}")
    cli_info(f"Removed zone delegation {args.delegation}", True)


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

    def print_soa(info: str, text: str, padding: int = 20) -> None:
        OutputManager().add_line("{1:<{0}}{2}".format(padding, info, text))

    if not args.zone:
        cli_warning("Name is required")

    zone, _ = get_zone(args.zone)
    print_soa("Zone:", zone["name"])
    format_ns("Nameservers:", "hostname", "TTL")
    for ns in zone["nameservers"]:
        ttl = ns["ttl"] if ns["ttl"] else "<not set>"
        format_ns("", ns["name"], ttl)
    print_soa("Primary ns:", zone["primary_ns"])
    print_soa("Email:", zone["email"])
    print_soa("Serialnumber:", zone["serialno"])
    print_soa("Refresh:", zone["refresh"])
    print_soa("Retry:", zone["retry"])
    print_soa("Expire:", zone["expire"])
    print_soa("SOA TTL:", zone["soa_ttl"])
    print_soa("Default TTL:", zone["default_ttl"])


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
    all_zones = []

    def _get_zone_list(zonetype: str) -> None:
        zones = get_list(f"/api/v1/zones/{zonetype}/")
        all_zones.extend(zones)

    if not (args.forward or args.reverse):
        cli_warning("Add either -forward or -reverse as argument")

    if args.forward:
        _get_zone_list("forward")
    if args.reverse:
        _get_zone_list("reverse")

    manager = OutputManager()

    if all_zones:
        manager.add_line("Zones:")
        for zone in all_zones:
            manager.add_line("   {}".format(zone["name"]))
    else:
        manager.add_line("No zones found.")


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
    _, path = get_zone(args.zone)
    manager = OutputManager()
    delegations = get_list(f"{path}/delegations/")
    if delegations:
        manager.add_line("Delegations:")
        for i in sorted(delegations, key=lambda kv: kv["name"]):
            manager.add_line("    {}".format(i["name"]))
            if i["comment"]:
                manager.add_line("        Comment: {}".format(i["comment"]))
            format_ns("Nameservers:", "hostname", "TTL")
            for ns in i["nameservers"]:
                ttl = ns["ttl"] if ns["ttl"] else "<not set>"
                format_ns("", ns["name"], ttl)
    else:
        cli_info(f"No delegations for {args.zone}", True)


def _get_delegation_path(zone: str, delegation: str) -> str:
    """Return the path for a delegation."""
    if not delegation.endswith(f".{zone}"):
        cli_warning(f"Delegation '{delegation}' is not in '{zone}'")
    _, path = get_zone(zone)
    path = f"{path}/delegations/{delegation}"
    response = get(path, ok404=True)
    if response is not None:
        return path
    else:
        cli_error("Delegation {delegation} not found")


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
    path = _get_delegation_path(args.zone, args.delegation)
    patch(path, comment=args.comment)
    cli_info(f"Updated comment for {args.delegation}", True)


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
    path = _get_delegation_path(args.zone, args.delegation)
    patch(path, comment="")
    cli_info(f"Removed comment for {args.delegation}", True)


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

    :param args: argparse.Namespace (zone, ns, force)
    """
    _verify_nameservers(args.ns, args.force)
    _, path = get_zone(args.zone)
    patch(f"{path}/nameservers", primary_ns=args.ns)
    cli_info(f"updated nameservers for {args.zone}", True)


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
    _, path = get_zone(args.zone)
    data = {}
    for i in (
        "email",
        "expire",
        "refresh",
        "retry",
        "serialno",
        "soa_ttl",
    ):
        value = getattr(args, i, None)
        if value is not None:
            data[i] = value
    if args.ns:
        data["primary_ns"] = args.ns

    if data:
        patch(path, **data)
        cli_info(f"set soa for {args.zone}", True)
    else:
        cli_info("No options set, so unchanged.", True)


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
    _, path = get_zone(args.zone)
    data = {"default_ttl": args.ttl}
    patch(path, **data)
    cli_info(f"set default TTL for {args.zone}", True)
