"""Manage zones."""
import argparse
from typing import Any, Dict, Tuple

from .cli import Flag, cli
from .exceptions import HostNotFoundWarning
from .log import cli_error, cli_info, cli_warning
from .outputmanager import OutputManager
from .util import delete, get, get_list, host_info_by_name, patch, post

#################################
#  Add the main command 'zone'  #
#################################

zone = cli.add_command(
    prog="zone",
    description="Manage zones.",
)


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


def get_zone(name: str) -> Tuple[Dict[str, Any], str]:
    """Return the zone and path for a zone."""
    path = zone_path(name)
    zone = get(path, ok404=True)
    if zone is None:
        cli_warning(f"Zone '{name}' does not exist")
    return zone.json(), path


##########################################
# Implementation of sub command 'create' #
##########################################


def create(args: argparse.Namespace) -> None:
    """Create a new zone.

    :param args: argparse.Namespace (ns, force, zone, email)
    """
    _verify_nameservers(args.ns, args.force)
    path = zone_basepath(args.zone)
    post(path, name=args.zone, email=args.email, primary_ns=args.ns)
    cli_info("created zone {}".format(args.zone), True)


zone.add_command(
    prog="create",
    description="Create new zone.",
    short_desc="Create new zone.",
    callback=create,
    flags=[
        Flag("zone", description="Zone name.", metavar="ZONE"),
        Flag("email", description="Contact email.", metavar="EMAIL"),
        Flag("ns", description="Nameservers of the zone.", nargs="+", metavar="NS"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)


#####################################################
# Implementation of sub command 'delegation_create' #
#####################################################


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
    cli_info("created zone delegation {}".format(args.delegation), True)


zone.add_command(
    prog="delegation_create",
    description="Create new zone delegation.",
    short_desc="Create new zone delegation.",
    callback=delegation_create,
    flags=[
        Flag("zone", description="Zone name.", metavar="ZONE"),
        Flag("delegation", description="Delegation", metavar="DELEGATION"),
        Flag("ns", description="Nameservers for the delegation.", nargs="+", metavar="NS"),
        Flag("-comment", description="Comment with a description", metavar="COMMENT"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)


##########################################
# Implementation of sub command 'delete' #
##########################################


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


zone.add_command(
    prog="delete",
    description="Delete a zone",
    short_desc="Delete a zone",
    callback=zone_delete,
    flags=[
        Flag("zone", description="Zone name.", metavar="ZONE"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)


#####################################################
# Implementation of sub command 'delegation_delete' #
#####################################################


def delegation_delete(args: argparse.Namespace) -> None:
    """Delete a zone delegation.

    :param args: argparse.Namespace (zone, delegation)
    """
    _, path = get_zone(args.zone)
    if not args.delegation.endswith(f".{args.zone}"):
        cli_warning(f"Delegation '{args.delegation}' is not in '{args.zone}'")
    delete(f"{path}/delegations/{args.delegation}")
    cli_info("Removed zone delegation {}".format(args.delegation), True)


zone.add_command(
    prog="delegation_delete",
    description="Delete a zone delegation",
    short_desc="Delete a zone delegation",
    callback=delegation_delete,
    flags=[
        Flag("zone", description="Zone name.", metavar="ZONE"),
        Flag("delegation", description="Delegation", metavar="DELEGATION"),
    ],
)


##########################################
# Implementation of sub command 'info' #
##########################################


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


zone.add_command(
    prog="info",
    description="Delete a zone",
    short_desc="Delete a zone",
    callback=info,
    flags=[
        Flag("zone", description="Zone name.", metavar="ZONE"),
    ],
)


##########################################
# Implementation of sub command 'list' #
##########################################


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


zone.add_command(
    prog="list",
    description="List zones",
    short_desc="List zones",
    callback=zone_list,
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


###################################################
# Implementation of sub command 'delegation_list' #
###################################################


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


zone.add_command(
    prog="delegation_list",
    description="List a zone's delegations",
    short_desc="List a zone's delegations",
    callback=zone_delegation_list,
    flags=[
        Flag("zone", description="Zone name.", metavar="ZONE"),
    ],
)

##########################################################
# Implementation of sub command 'delegation_comment_set' #
##########################################################


def _get_delegation_path(zone: str, delegation: str) -> str:
    """Return the path for a delegation."""
    if not delegation.endswith(f".{zone}"):
        cli_warning(f"Delegation '{delegation}' is not in '{zone}'")
    _, path = get_zone(zone)
    path = f"{path}/delegations/{delegation}"
    delegation = get(path, ok404=True)
    if delegation is not None:
        return path
    else:
        cli_error("Delegation {delegation} not found")


def zone_delegation_comment_set(args: argparse.Namespace) -> None:
    """Set a delegation's comment.

    :param args: argparse.Namespace (zone, delegation, comment)
    """
    path = _get_delegation_path(args.zone, args.delegation)
    patch(path, comment=args.comment)
    cli_info(f"Updated comment for {args.delegation}", True)


zone.add_command(
    prog="delegation_comment_set",
    description="Set a comment for zone delegation",
    short_desc="Set a comment for zone delegation",
    callback=zone_delegation_comment_set,
    flags=[
        Flag("zone", description="Zone name", metavar="ZONE"),
        Flag("delegation", description="Delegation", metavar="DELEGATION"),
        Flag("comment", description="Comment", metavar="COMMENT"),
    ],
)


def zone_delegation_comment_remove(args: argparse.Namespace) -> None:
    """Set a delegation's comment.

    :param args: argparse.Namespace (zone, delegation)
    """
    path = _get_delegation_path(args.zone, args.delegation)
    patch(path, comment="")
    cli_info(f"Removed comment for {args.delegation}", True)


zone.add_command(
    prog="delegation_comment_remove",
    description="Remove a comment for zone delegation",
    short_desc="Remove a comment for zone delegation",
    callback=zone_delegation_comment_remove,
    flags=[
        Flag("zone", description="Zone name", metavar="ZONE"),
        Flag("delegation", description="Delegation", metavar="DELEGATION"),
    ],
)


##########################################
# Implementation of sub command 'set_ns' #
##########################################


def set_ns(args: argparse.Namespace) -> None:
    """Update nameservers for an existing zone.

    :param args: argparse.Namespace (zone, ns, force)
    """
    _verify_nameservers(args.ns, args.force)
    _, path = get_zone(args.zone)
    patch(f"{path}/nameservers", primary_ns=args.ns)
    cli_info("updated nameservers for {}".format(args.zone), True)


zone.add_command(
    prog="set_ns",
    description="Update nameservers for an existing zone.",
    short_desc="Update nameservers for an existing zone.",
    callback=set_ns,
    flags=[
        Flag("zone", description="Zone name.", metavar="ZONE"),
        Flag("ns", description="Nameservers of the zone.", nargs="+", metavar="NS"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)


###########################################
# Implementation of sub command 'set_soa' #
###########################################


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
        cli_info("set soa for {}".format(args.zone), True)
    else:
        cli_info("No options set, so unchanged.", True)


zone.add_command(
    prog="set_soa",
    description="Updated the SOA of a zone.",
    short_desc="Updated the SOA of a zone.",
    callback=set_soa,
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

###################################################
# Implementation of sub command 'set_default_ttl' #
###################################################


def set_default_ttl(args: argparse.Namespace) -> None:
    """Update the default TTL of a zone.

    :param args: argparse.Namespace (zone, ttl)
    """
    _, path = get_zone(args.zone)
    data = {"default_ttl": args.ttl}
    patch(path, **data)
    cli_info("set default TTL for {}".format(args.zone), True)


zone.add_command(
    prog="set_default_ttl",
    description="Set the default TTL of a zone.",
    short_desc="Set the default TTL of a zone.",
    callback=set_default_ttl,
    flags=[
        Flag("zone", description="Zone name.", metavar="ZONE"),
        Flag("ttl", description="Default Time To Live.", flag_type=int, metavar="TTL"),
    ],
)
