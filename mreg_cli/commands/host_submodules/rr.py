"""Resource record related subcommands for the host command.

Commands implemented:
    - hinfo_add
    - hinfo_remove
    - hinfo_show
    - loc_add
    - loc_remove
    - loc_show
    - mx_add
    - mx_remove
    - mx_show
    - naptr_add
    - naptr_remove
    - naptr_show
    - ptr_change
    - ptr_remove
    - ptr_add
    - ptr_show
    - srv_add
    - srv_remove
    - srv_show
    - mx_add
    - mx_remove
    - mx_show
    - txt_add
    - txt_remove
    - txt_show
    - sshfp_add
    - sshfp_remove
    - sshfp_show
    - ttl_set
    - ttl_show
    - cname_add
    - cname_remove
    - cname_replace
    - cname_show
"""

from __future__ import annotations

import argparse
from typing import Any

from mreg_cli.commands.host import registry as command_registry
from mreg_cli.log import cli_info, cli_warning
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag
from mreg_cli.utilities.api import delete, get_list, patch, post
from mreg_cli.utilities.host import get_info_by_name, host_info_by_name
from mreg_cli.utilities.network import get_network_reserved_ips, ip_in_mreg_net
from mreg_cli.utilities.output import (
    output_hinfo,
    output_loc,
    output_mx,
    output_naptr,
    output_ptr,
    output_sshfp,
    output_ttl,
    output_txt,
)
from mreg_cli.utilities.shared import clean_hostname
from mreg_cli.utilities.validators import is_valid_ip, is_valid_ttl
from mreg_cli.utilities.zone import zone_check_for_hostname


@command_registry.register_command(
    prog="hinfo_add",
    description="Add HINFO for host. If NAME is an alias the cname host is updated.",
    short_desc="Set HINFO.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
        Flag("cpu", description="CPU/hardware", metavar="CPU"),
        Flag("os", description="Operating system", metavar="OS"),
    ],
)
def hinfo_add(args: argparse.Namespace) -> None:
    """Add hinfo for host.

    If <name> is an alias the cname host is updated.

    :param args: argparse.Namespace (name, cpu, os)
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)

    if info["hinfo"]:
        cli_warning(f"{info['name']} already has hinfo set.")

    data = {"host": info["id"], "cpu": args.cpu, "os": args.os}
    # Add HINFO record to host
    path = "/api/v1/hinfos/"
    post(path, **data)
    cli_info("Added HINFO record to {}".format(info["name"]), print_msg=True)


@command_registry.register_command(
    prog="hinfo_remove",
    description="Remove hinfo for host. If NAME is an alias the cname host is updated.",
    short_desc="Remove HINFO.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
    ],
)
def hinfo_remove(args: argparse.Namespace) -> None:
    """Remove hinfo for host.

    If <name> is an alias the cname host is updated.

    :param args: argparse.Namespace (name)
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)

    if not info["hinfo"]:
        cli_warning(f"{info['name']} already has no hinfo set.")
    host_id = info["id"]
    path = f"/api/v1/hinfos/{host_id}"
    delete(path)
    cli_info("deleted HINFO from {}".format(info["name"]), True)


@command_registry.register_command(
    prog="hinfo_show",
    description="Show hinfo for host. If NAME is an alias the cname hosts hinfo is shown.",
    short_desc="Show HINFO.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
    ],
)
def hinfo_show(args: argparse.Namespace) -> None:
    """Show hinfo for host.

    If <name> is an alias the cname hosts hinfo is shown.

    :param args: argparse.Namespace (name)
    """
    info = host_info_by_name(args.name)
    if info["hinfo"]:
        output_hinfo(info["hinfo"])
    else:
        cli_info(f"No hinfo for {args.name}", print_msg=True)
    cli_info("showed hinfo for {}".format(info["name"]))


@command_registry.register_command(
    prog="loc_remove",
    description="Remove location from host. If NAME is an alias the cname host is updated.",
    short_desc="Remove LOC record.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
    ],
)
def loc_remove(args: argparse.Namespace) -> None:
    """Remove location from host.

    If <name> is an alias the cname host is updated.

    :param args: argparse.Namespace (name)
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)
    if not info["loc"]:
        cli_warning(f"{info['name']} already has no loc set.")
    host_id = info["id"]
    path = f"/api/v1/locs/{host_id}"
    delete(path)

    cli_info("removed LOC for {}".format(info["name"]), print_msg=True)


@command_registry.register_command(
    prog="loc_add",
    description="Set location of host. If NAME is an alias the cname host is updated.",
    short_desc="Set LOC record.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
        Flag("loc", description="New LOC.", metavar="LOC"),
    ],
)
def loc_add(args: argparse.Namespace) -> None:
    """Set location of host.

    If <name> is an alias the cname host is updated.

    :param args: argparse.Namespace (name, loc)
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)

    if info["loc"]:
        cli_warning(f"{info['name']} already has loc set.")

    data = {"host": info["id"], "loc": args.loc}
    path = "/api/v1/locs/"
    post(path, **data)
    cli_info("added LOC '{}' for {}".format(args.loc, info["name"]), print_msg=True)


@command_registry.register_command(
    prog="loc_show",
    description="Show location of host. If NAME is an alias the cname hosts LOC is shown.",
    short_desc="Show LOC record.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
    ],
)
def loc_show(args: argparse.Namespace) -> None:
    """Show location of host.

    If <name> is an alias the cname hosts LOC is shown.

    :param args: argparse.Namespace (name)
    """
    info = host_info_by_name(args.name)
    if info["loc"]:
        output_loc(info["loc"])
    else:
        cli_info(f"No LOC for {args.name}", print_msg=True)
    cli_info("showed LOC for {}".format(info["name"]))


def _mx_in_mxs(mxs: list[dict[str, str]], priority: str, mx: str) -> str | None:
    """Check that a matching mx record exists in the list of mxs.

    :param mxs: list of mx records (Dict[str, str])
    :param priority: priority of the target mx record
    :param mx: mail exchange of the target mx record
    """
    for info in mxs:
        if info["priority"] == priority and info["mx"] == mx:
            return info["id"]
    return None


@command_registry.register_command(
    prog="mx_add",
    description="Add a MX record to host.",
    short_desc="Add MX record.",
    flags=[
        Flag("name", description="Host target name.", metavar="NAME"),
        Flag("priority", description="Priority", flag_type=int, metavar="PRIORITY"),
        Flag("mx", description="Mail Server", metavar="MX"),
    ],
)
def mx_add(args: argparse.Namespace) -> None:
    """Add a mx record to host.

    <text> must be enclosed in double quotes if it contains more than one word.

    :param args: argparse.Namespace (name, priority, mx)
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)
    if _mx_in_mxs(info["mxs"], args.priority, args.mx):
        cli_warning("{} already has that MX defined".format(info["name"]))

    data = {"host": info["id"], "priority": args.priority, "mx": args.mx}
    # Add MX record to host
    path = "/api/v1/mxs/"
    post(path, **data)
    cli_info("Added MX record to {}".format(info["name"]), print_msg=True)


@command_registry.register_command(
    prog="mx_remove",
    description=" Remove MX record for host.",
    short_desc="Remove MX record.",
    flags=[
        Flag("name", description="Host target name.", metavar="NAME"),
        Flag("priority", description="Priority", flag_type=int, metavar="PRIORITY"),
        Flag("mx", description="Mail Server", metavar="TEXT"),
    ],
)
def mx_remove(args: argparse.Namespace) -> None:
    """Remove MX record for host.

    :param args: argparse.Namespace (name, priority, mx)
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)

    mx_id = _mx_in_mxs(info["mxs"], args.priority, args.mx)
    if mx_id is None:
        cli_warning(
            "{} has no MX records with priority {} and mail exhange {}".format(
                info["name"], args.priority, args.mx
            )
        )
    path = f"/api/v1/mxs/{mx_id}"
    delete(path)
    cli_info("deleted MX from {}".format(info["name"]), True)


@command_registry.register_command(
    prog="mx_show",
    description="Show all MX records for host.",
    short_desc="Show MX records.",
    flags=[
        Flag("name", description="Host target name.", metavar="NAME"),
    ],
)
def mx_show(args: argparse.Namespace) -> None:
    """Show all MX records for host.

    :param args: argparse.Namespace (name)
    """
    info = host_info_by_name(args.name)
    path = "/api/v1/mxs/"
    params = {
        "host": info["id"],
    }
    mxs = get_list(path, params=params)
    output_mx(mxs, padding=5)
    cli_info("showed MX records for {}".format(info["name"]))


@command_registry.register_command(
    prog="naptr_add",
    description="Add a NAPTR record to host.",
    short_desc="Add NAPTR record.",
    flags=[
        Flag(
            "-name",
            description="Name of the target host.",
            required=True,
            metavar="NAME",
        ),
        Flag(
            "-preference",
            description="NAPTR preference.",
            flag_type=int,
            required=True,
            metavar="PREFERENCE",
        ),
        Flag(
            "-order",
            description="NAPTR order.",
            flag_type=int,
            required=True,
            metavar="ORDER",
        ),
        Flag("-flag", description="NAPTR flag.", required=True, metavar="FLAG"),
        Flag("-service", description="NAPTR service.", required=True, metavar="SERVICE"),
        Flag("-regex", description="NAPTR regexp.", required=True, metavar="REGEXP"),
        Flag(
            "-replacement",
            description="NAPTR replacement.",
            required=True,
            metavar="REPLACEMENT",
        ),
    ],
)
def naptr_add(args: argparse.Namespace) -> None:
    """Add a NAPTR record to host.

    :param args: argparse.Namespace (name, preference, order, flag, service, regex, replacement)
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)

    data: dict[str, str] = {
        "preference": args.preference,
        "order": args.order,
        "flag": args.flag,
        "service": args.service,
        "regex": args.regex,
        "replacement": args.replacement,
        "host": info["id"],
    }

    path = "/api/v1/naptrs/"
    post(path, params=None, **data)
    cli_info("created NAPTR record for {}".format(info["name"]), print_msg=True)


@command_registry.register_command(
    prog="naptr_remove",
    description="Remove NAPTR record.",
    short_desc="Remove NAPTR record.",
    flags=[
        Flag(
            "-name",
            description="Name of the target host.",
            required=True,
            metavar="NAME",
        ),
        Flag(
            "-preference",
            description="NAPTR preference.",
            flag_type=int,
            required=True,
            metavar="PREFERENCE",
        ),
        Flag(
            "-order",
            description="NAPTR order.",
            flag_type=int,
            required=True,
            metavar="ORDER",
        ),
        Flag("-flag", description="NAPTR flag.", required=True, metavar="FLAG"),
        Flag("-service", description="NAPTR service.", required=True, metavar="SERVICE"),
        Flag("-regex", description="NAPTR regexp.", required=True, metavar="REGEXP"),
        Flag(
            "-replacement",
            description="NAPTR replacement.",
            required=True,
            metavar="REPLACEMENT",
        ),
    ],
)
def naptr_remove(args: argparse.Namespace) -> None:
    """Remove NAPTR record.

    :param args: argparse.Namespace (name, preference, order, flag, service, regex, replacement)
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)

    # get the hosts NAPTR records where repl is a substring of the replacement
    # field
    path = "/api/v1/naptrs/"
    params = {
        "replacement__contains": args.replacement,
        "host": info["id"],
    }
    naptrs = get_list(path, params=params)

    data = None
    attrs = (
        "preference",
        "order",
        "flag",
        "service",
        "regex",
        "replacement",
    )
    for naptr in naptrs:
        if all(naptr[attr] == getattr(args, attr) for attr in attrs):
            data = naptr

    if data is None:
        cli_warning("Did not find any matching NAPTR record.")

    # Delete NAPTR record
    path = f"/api/v1/naptrs/{data['id']}"
    delete(path)
    cli_info("deleted NAPTR record for {}".format(info["name"]), print_msg=True)


@command_registry.register_command(
    prog="naptr_show",
    description="Show all NAPTR records for host.",
    short_desc="Show NAPTR records.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
    ],
)
def naptr_show(args: argparse.Namespace) -> None:
    """Show all NAPTR records for host.

    :param args: argparse.Namespace (name)
    """
    info = host_info_by_name(args.name)
    num_naptrs = output_naptr(info)
    if num_naptrs == 0:
        OutputManager().add_line(f"No naptrs for {info['name']}")
    cli_info("showed {} NAPTR records for {}".format(num_naptrs, info["name"]))


@command_registry.register_command(
    prog="ptr_change",
    description="Move PTR record from OLD to NEW.",
    short_desc="Move PTR record.",
    flags=[
        Flag(
            "-ip",
            description="IP of PTR record. May be IPv4 or IPv6.",
            short_desc="IP of PTR record.",
            required=True,
            metavar="IP",
        ),
        Flag("-old", description="Name of old host.", required=True, metavar="NAME"),
        Flag("-new", description="Name of new host.", required=True, metavar="NAME"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def ptr_change(args: argparse.Namespace) -> None:
    """Move PTR record from <old-name> to <new-name>.

    :param args: argparse.Namespace (ip, old, new, force)
    """
    # Get host info or raise exception
    old_info = host_info_by_name(args.old)
    new_info = host_info_by_name(args.new)

    # check that new host haven't got a ptr record already
    if len(new_info["ptr_overrides"]):
        cli_warning("{} already got a PTR record".format(new_info["name"]))

    # check that old host has a PTR record with the given ip
    if not len(old_info["ptr_overrides"]):
        cli_warning("no PTR record for {} with ip {}".format(old_info["name"], args.ip))
    if old_info["ptr_overrides"][0]["ipaddress"] != args.ip:
        cli_warning("{} PTR record doesn't match {}".format(old_info["name"], args.ip))

    # change PTR record
    data = {
        "host": new_info["id"],
    }

    path = "/api/v1/ptroverrides/{}".format(old_info["ptr_overrides"][0]["id"])
    patch(path, **data)
    cli_info(
        "changed owner of PTR record {} from {} to {}".format(
            args.ip,
            old_info["name"],
            new_info["name"],
        ),
        print_msg=True,
    )


@command_registry.register_command(
    prog="ptr_remove",
    description="Remove PTR record from host.",
    short_desc="Remove PTR record.",
    flags=[
        Flag("ip", description="IP of PTR record. May be IPv4 or IPv6.", metavar="IP"),
        Flag("name", description="Name of host.", metavar="NAME"),
    ],
)
def ptr_remove(args: argparse.Namespace) -> None:
    """Remove PTR record from host.

    :param args: argparse.Namespace (ip, name)
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)

    for ptr in info["ptr_overrides"]:
        if ptr["ipaddress"] == args.ip:
            ptr_id = ptr["id"]
            break
    else:
        cli_warning("no PTR record for {} with ip {}".format(info["name"], args.ip))

    # Delete record
    path = f"/api/v1/ptroverrides/{ptr_id}"
    delete(path)
    cli_info("deleted PTR record {} for {}".format(args.ip, info["name"]), print_msg=True)


@command_registry.register_command(
    prog="ptr_add",
    description="Create a PTR record for host.",
    short_desc="Add PTR record.",
    flags=[
        Flag("ip", description="IP of PTR record. May be IPv4 or IPv6.", metavar="IP"),
        Flag("name", description="Name of host.", metavar="NAME"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def ptr_add(args: argparse.Namespace) -> None:
    """Create a PTR record for host.

    :param args: argparse.Namespace (ip, name, force)
    """
    # Ip sanity check
    if not is_valid_ip(args.ip):
        cli_warning(f"invalid ip: {args.ip}")
    if not ip_in_mreg_net(args.ip):
        cli_warning(f"{args.ip} isn't in a network controlled by MREG")

    # Get host info or raise exception
    info = host_info_by_name(args.name)

    # check that a PTR record with the given ip doesn't exist
    path = "/api/v1/ptroverrides/"
    params = {
        "ipaddress": args.ip,
    }
    ptrs = get_list(path, params=params)
    if len(ptrs):
        cli_warning(f"{args.ip} already exist in a PTR record")
    # check if host is in mreg controlled zone, must force if not
    if info["zone"] is None and not args.force:
        cli_warning("{} isn't in a zone controlled by MREG, must force".format(info["name"]))

    import ipaddress

    from mreg_cli.api.models import Network

    network = Network.get_by_ip(ipaddress.ip_address(args.ip))

    reserved_addresses = get_network_reserved_ips(str(network.network))
    if args.ip in reserved_addresses and not args.force:
        cli_warning("Address is reserved. Requires force")

    # create PTR record
    data = {
        "host": info["id"],
        "ipaddress": args.ip,
    }
    path = "/api/v1/ptroverrides/"
    post(path, **data)
    cli_info("Added PTR record {} to {}".format(args.ip, info["name"]), print_msg=True)


@command_registry.register_command(
    prog="ptr_show",
    description="Show PTR record matching given ip (empty input shows all PTR records).",
    short_desc="Show PTR record.",
    flags=[
        Flag("ip", description="IP of PTR record. May be IPv4 or IPv6.", metavar="IP"),
    ],
)
def ptr_show(args: argparse.Namespace) -> None:
    """Show PTR record matching given ip.

    :param args: argparse.Namespace (ip)
    """
    if not is_valid_ip(args.ip):
        cli_warning(f"{args.ip} is not a valid IP")

    path = "/api/v1/hosts/"
    params = {
        "ptr_overrides__ipaddress": args.ip,
    }
    hosts = get_list(path, params=params)

    if hosts:
        host = hosts[0]
        for ptr in host["ptr_overrides"]:
            if args.ip == ptr["ipaddress"]:
                padding = len(args.ip)
                output_ptr(args.ip, host["name"], padding)
    else:
        OutputManager().add_line(f"No PTR found for IP '{args.ip}'")


@command_registry.register_command(
    prog="srv_add",
    description="Add SRV record.",
    short_desc="Add SRV record.",
    flags=[
        Flag("-name", description="SRV service.", required=True, metavar="SERVICE"),
        Flag("-priority", description="SRV priority.", required=True, metavar="PRIORITY"),
        Flag("-weight", description="SRV weight.", required=True, metavar="WEIGHT"),
        Flag("-port", description="SRV port.", required=True, metavar="PORT"),
        Flag("-host", description="Host target name.", required=True, metavar="NAME"),
        Flag("-ttl", description="TTL value", metavar="TTL"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def srv_add(args: argparse.Namespace) -> None:
    """Add SRV record.

    :param args: argparse.Namespace (name, priority, weight, port, host, ttl, force)
    """
    sname = clean_hostname(args.name)
    zone_check_for_hostname(sname, False, require_zone=True)

    # Require host target
    info = host_info_by_name(args.host)

    # Require force if target host not in MREG zone
    zone_check_for_hostname(info["name"], args.force)

    data = {
        "name": sname,
        "priority": args.priority,
        "weight": args.weight,
        "port": args.port,
        "host": info["id"],
        "ttl": args.ttl,
    }

    # Create new SRV record
    path = "/api/v1/srvs/"
    post(path, **data)
    cli_info("Added SRV record {} with target {}".format(sname, info["name"]), print_msg=True)


@command_registry.register_command(
    prog="srv_remove",
    description="Remove SRV record.",
    short_desc="Remove SRV record.",
    flags=[
        Flag("-name", description="SRV service.", required=True, metavar="SERVICE"),
        Flag(
            "-priority",
            description="SRV priority.",
            flag_type=int,
            required=True,
            metavar="PRIORITY",
        ),
        Flag(
            "-weight",
            description="SRV weight.",
            flag_type=int,
            required=True,
            metavar="WEIGHT",
        ),
        Flag(
            "-port",
            description="SRV port.",
            flag_type=int,
            required=True,
            metavar="PORT",
        ),
        Flag("-host", description="Host target name.", required=True, metavar="NAME"),
    ],
)
def srv_remove(args: argparse.Namespace) -> None:
    """Remove SRV record.

    :param args: argparse.Namespace (name, priority, weight, port, host)
    """
    info = host_info_by_name(args.host)
    sname = clean_hostname(args.name)

    # Check if service exist
    path = "/api/v1/srvs/"
    params = {
        "name": sname,
        "host": info["id"],
    }
    srvs = get_list(path, params=params)
    if len(srvs) == 0:
        cli_warning(f"no service named {sname}")

    data = None
    attrs = (
        "name",
        "priority",
        "weight",
        "port",
    )
    for srv in srvs:
        if all(srv[attr] == getattr(args, attr) for attr in attrs):
            data = srv
            break

    if data is None:
        cli_warning("Did not find any matching SRV records.")

    # Delete SRV record
    path = f"/api/v1/srvs/{data['id']}"
    delete(path)
    cli_info("deleted SRV record for {}".format(info["name"]), print_msg=True)


def _srv_show(srvs: list[dict[str, Any]] | None = None, host_id: str | None = None) -> None:
    assert srvs is not None or host_id is not None
    hostid2name = dict()
    host_ids = set()

    def print_srv(srv: dict[str, Any], hostname: str, padding: int = 14) -> None:
        """Pretty print given srv."""
        OutputManager().add_line(
            "SRV: {1:<{0}} {2:^6} {3:^6} {4:^6} {5}".format(
                padding,
                srv["name"],
                srv["priority"],
                srv["weight"],
                srv["port"],
                hostname,
            )
        )

    if srvs is None:
        path = "/api/v1/srvs/"
        params = {
            "host": host_id,
        }
        srvs = get_list(path, params=params)

    if len(srvs) == 0:
        return

    padding = 0

    # The assert at the start of the method doesn't catch the None case,
    # so to make linters happy, we need to check for it explicitly here.
    if srvs is not None:
        for srv in srvs:
            if len(srv["name"]) > padding:
                padding = len(srv["name"])
            host_ids.add(str(srv["host"]))

    arg = ",".join(host_ids)
    hosts = get_list("/api/v1/hosts/", params={"id__in": arg})
    for host in hosts:
        hostid2name[host["id"]] = host["name"]

    prev_name = ""
    if srvs is not None:
        for srv in srvs:
            if prev_name == srv["name"]:
                srv["name"] = ""
            else:
                prev_name = srv["name"]
            print_srv(srv, hostid2name[srv["host"]], padding)


@command_registry.register_command(
    prog="srv_show",
    description="Show SRV records for the service.",
    short_desc="Show SRV records.",
    flags=[
        Flag("service", description="Host target name.", metavar="SERVICE"),
    ],
)
def srv_show(args: argparse.Namespace) -> None:
    """Show SRV records for the service.

    :param args: argparse.Namespace (service)
    """
    sname = clean_hostname(args.service)

    # Get all matching SRV records
    path = "/api/v1/srvs/"
    params = {
        "name": sname,
    }
    srvs = get_list(path, params=params)
    if len(srvs) == 0:
        cli_warning(f"no service matching {sname}")
    else:
        _srv_show(srvs=srvs)
    cli_info(f"showed entries for SRV {sname}")


@command_registry.register_command(
    prog="sshfp_add",
    description="Add SSHFP record.",
    short_desc="Add SSHFP record.",
    flags=[
        Flag("name", description="Host target name.", metavar="NAME"),
        Flag("algorithm", description="SSH algorithm.", metavar="ALGORITHM"),
        Flag("hash_type", description="Hash type.", metavar="HASH_TYPE"),
        Flag("fingerprint", description="Hexadecimal fingerprint.", metavar="FINGERPRINT"),
    ],
)
def sshfp_add(args: argparse.Namespace) -> None:
    """Add SSHFP record.

    :param args: argparse.Namespace (name, algorithm, hash_type, fingerprint)
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)

    data = {
        "algorithm": args.algorithm,
        "hash_type": args.hash_type,
        "fingerprint": args.fingerprint,
        "host": info["id"],
    }

    # Create new SSHFP record
    path = "/api/v1/sshfps/"
    post(path, **data)
    cli_info(
        "Added SSHFP record {} for host {}".format(args.fingerprint, info["name"]),
        print_msg=True,
    )


@command_registry.register_command(
    prog="sshfp_remove",
    description=(
        "Remove SSHFP record with a given fingerprint from the host. "
        "A missing fingerprint removes all SSHFP records for the host."
    ),
    short_desc="Remove SSHFP record.",
    flags=[
        Flag("name", description="Host target name.", metavar="NAME"),
        Flag(
            "-fingerprint",
            description="Hexadecimal fingerprint.",
            metavar="FINGERPRINT",
        ),
    ],
)
def sshfp_remove(args: argparse.Namespace) -> None:
    """Remove SSHFP record from the host.

    A missing fingerprint removes all SSHFP records for the host.

    :param args: argparse.Namespace (name, fingerprint)
    """

    def _delete_sshfp_record(sshfp: dict[str, Any], hname: str) -> None:
        """Delete SSHFP record from the host."""
        path = f"/api/v1/sshfps/{sshfp['id']}"
        delete(path)
        cli_info(
            "removed SSHFP record with fingerprint {} for {}".format(sshfp["fingerprint"], hname),
            print_msg=True,
        )

    # Get host info or raise exception
    info = host_info_by_name(args.name)
    hid = info["id"]

    # Get all matching SSHFP records
    path = "/api/v1/sshfps/"
    params = {
        "host": hid,
    }
    sshfps = get_list(path, params=params)
    if len(sshfps) < 1:
        cli_warning("no SSHFP records matching {}".format(info["name"]))

    if args.fingerprint:
        found = False
        for sshfp in sshfps:
            if sshfp["fingerprint"] == args.fingerprint:
                _delete_sshfp_record(sshfp, info["name"])
                found = True
        if not found:
            cli_info(
                "found no SSHFP record with fingerprint {} for {}".format(
                    args.fingerprint, info["name"]
                ),
                print_msg=True,
            )
    else:
        for sshfp in sshfps:
            _delete_sshfp_record(sshfp, info["name"])


@command_registry.register_command(
    prog="sshfp_show",
    description="Show SSHFP records for the host.",
    short_desc="Show SSHFP record.",
    flags=[
        Flag("name", description="Host target name.", metavar="NAME"),
    ],
)
def sshfp_show(args: argparse.Namespace) -> None:
    """Show SSHFP records for the host.

    :param args: argparse.Namespace (name)
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)
    num_sshfps = output_sshfp(info)
    if num_sshfps == 0:
        cli_warning(f"no SSHFP records for {info['name']}")


@command_registry.register_command(
    prog="ttl_remove",
    description="Remove explicit TTL for host. If NAME is an alias the alias host is updated.",
    short_desc="Remove TTL record.",
    flags=[
        Flag("name", description="Host target name.", metavar="NAME"),
    ],
)
def ttl_remove(args: argparse.Namespace) -> None:
    """Remove explicit TTL for host.

    If <name> is an alias the alias host is updated.

    :param args: argparse.Namespace (name)
    """
    target_type, info = get_info_by_name(args.name)
    path = f"/api/v1/{target_type}s/{info['name']}"
    patch(path, ttl="")
    cli_info("removed TTL for {}".format(info["name"]), print_msg=True)


@command_registry.register_command(
    prog="ttl_set",
    description=(
        "Set ttl for host. Valid values are 300 <= TTL <= 68400 or "
        '"default". If NAME is an alias the alias host is updated.'
    ),
    short_desc="Set TTL record.",
    flags=[
        Flag("name", description="Host target name.", metavar="NAME"),
        Flag("ttl", description="New TTL.", metavar="TTL"),
    ],
)
def ttl_set(args: argparse.Namespace) -> None:
    """Set ttl for name.

    Valid values are 300 <= TTL <= 68400 or "default".
    If <name> is an alias the alias host is updated.

    :param args: argparse.Namespace (name, ttl)
    """
    target_type, info = get_info_by_name(args.name)

    # TTL sanity check
    if not is_valid_ttl(args.ttl):
        cli_warning("invalid TTL value: {} (target host {})".format(args.ttl, info["name"]))

    new_data = {"ttl": args.ttl if args.ttl != "default" else ""}

    # Update TTL
    path = f"/api/v1/{target_type}s/{info['name']}"
    patch(path, **new_data)
    cli_info("updated TTL to {} for {}".format(args.ttl, info["name"]), print_msg=True)


##############################################
#  Implementation of sub command 'ttl_show'  #
##############################################


@command_registry.register_command(
    prog="ttl_show",
    description="Show ttl for name.",
    short_desc="Show TTL.",
    flags=[
        Flag("name", description="Name", metavar="NAME"),
    ],
)
def ttl_show(args: argparse.Namespace) -> None:
    """Show ttl for name.

    If <name> is an alias the alias hosts TTL is shown.

    :param args: argparse.Namespace (name)
    """
    info = host_info_by_name(args.name)
    _, info = get_info_by_name(args.name)
    output_ttl(info["ttl"])
    cli_info("showed TTL for {}".format(info["name"]))


@command_registry.register_command(
    prog="txt_add",
    description=(
        "Add a txt record to host. TEXT must be enclosed in double "
        "quotes if it contains more than one word."
    ),
    short_desc="Add TXT record.",
    flags=[
        Flag("name", description="Host target name.", metavar="NAME"),
        Flag(
            "text",
            description="TXT record text. Must be quoted if contains spaces.",
            metavar="TEXT",
        ),
    ],
)
def txt_add(args: argparse.Namespace) -> None:
    """Add a txt record to host.

    <text> must be enclosed in double quotes if it contains more than one word.

    :param args: argparse.Namespace (name, text)
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)
    if any(args.text == i["txt"] for i in info["txts"]):
        cli_warning("The TXT record already exists for {}".format(info["name"]))

    data = {"host": info["id"], "txt": args.text}
    # Add TXT record to host
    path = "/api/v1/txts/"
    post(path, **data)
    cli_info("Added TXT record to {}".format(info["name"]), print_msg=True)


@command_registry.register_command(
    prog="txt_remove",
    description=" Remove TXT record for host matching TEXT.",
    short_desc="Remove TXT record.",
    flags=[
        Flag("name", description="Host target name.", metavar="NAME"),
        Flag(
            "text",
            description="TXT record text. Must be quoted if contains spaces.",
            metavar="TEXT",
        ),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def txt_remove(args: argparse.Namespace) -> None:
    """Remove TXT record for host with <text>.

    :param args: argparse.Namespace (name, text)
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)
    hostname = info["name"]

    # Check for matching TXT records for host
    path = "/api/v1/txts/"
    txts = get_list(path, params={"host": info["id"], "txt": args.text})
    if len(txts) == 0:
        cli_warning(f"{hostname} has no TXT records equal: {args.text}")

    txt = txts[0]
    path = f"/api/v1/txts/{txt['id']}"
    delete(path)
    cli_info(f"deleted TXT records from {hostname}", print_msg=True)


@command_registry.register_command(
    prog="txt_show",
    description="Show all TXT records for host.",
    short_desc="Show TXT records.",
    flags=[
        Flag("name", description="Host target name.", metavar="NAME"),
    ],
)
def txt_show(args: argparse.Namespace) -> None:
    """Show all TXT records for host.

    :param args: argparse.Namespace (name)
    """
    info = host_info_by_name(args.name)
    path = "/api/v1/txts/"
    params = {
        "host": info["id"],
    }
    txts = get_list(path, params=params)
    for txt in txts:
        output_txt(txt["txt"], padding=5)
    cli_info("showed TXT records for {}".format(info["name"]))
