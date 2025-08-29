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

from mreg_cli.api.fields import HostName
from mreg_cli.api.models import (
    MX,
    NAPTR,
    SSHFP,
    TXT,
    ForwardZone,
    HInfo,
    Host,
    Location,
    Network,
    NetworkOrIP,
    PTR_override,
    Srv,
)
from mreg_cli.commands.host import registry as command_registry
from mreg_cli.exceptions import (
    CreateError,
    DeleteError,
    EntityAlreadyExists,
    EntityNotFound,
    ForceMissing,
    InputFailure,
    PatchError,
)
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag, QueryParams


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
    host = Host.get_by_any_means_or_raise(args.name)
    if host.hinfo:
        raise EntityAlreadyExists(f"{host} already has hinfo set.")

    HInfo.create({"host": host.id, "cpu": args.cpu, "os": args.os})
    host = host.refetch()

    if host.hinfo and host.hinfo.cpu == args.cpu and host.hinfo.os == args.os:
        OutputManager().add_ok(f"Added HINFO record for {host.name}.")
    else:
        raise CreateError(f"Failed to add correct HINFO for {host}")


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
    host = Host.get_by_any_means_or_raise(args.name)
    if not host.hinfo:
        raise EntityNotFound(f"{host} already has no hinfo set.")

    hinfo = HInfo.get_by_field("host", host.id)
    if hinfo and hinfo.delete():
        OutputManager().add_ok(f"Removed HINFO record for {host.name}.")
    else:
        raise DeleteError(f"Failed to remove HINFO for {host}")


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
    host = Host.get_by_any_means_or_raise(args.name)
    if not host.hinfo:
        OutputManager().add_line(f"No hinfo for {host.name}")

    hinfo = HInfo.get_by_field("host", host.id)
    if hinfo:
        hinfo.output()
    else:
        OutputManager().add_line(f"No hinfo for {host.name}")


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
    host = Host.get_by_any_means_or_raise(args.name)
    if not host.loc:
        raise EntityNotFound(f"{host} already has no loc set.")

    if host.loc.delete():
        OutputManager().add_ok(f"Removed LOC for {host.name}.")
    else:
        raise DeleteError(f"Failed to remove LOC for {host}")


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
    host = Host.get_by_any_means_or_raise(args.name)

    if host.loc:
        raise EntityAlreadyExists(f"{host} already has loc set.")

    Location.create({"host": host.id, "loc": args.loc})
    host = host.refetch()

    if host.loc and host.loc.loc == args.loc:
        OutputManager().add_ok(f"Added LOC record for {host.name}.")
    else:
        CreateError(f"Failed to set LOC for {host}")


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
    host = Host.get_by_any_means_or_raise(args.name)
    if not host.loc:
        raise EntityNotFound(f"No loc for {host.name}")

    host.loc.output()


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
    host = Host.get_by_any_means_or_raise(args.name)
    if host.has_mx_with_priority(args.priority, args.mx):
        raise EntityAlreadyExists(f"{host} already has that MX defined.")

    MX.create({"host": host.id, "priority": args.priority, "mx": args.mx})
    OutputManager().add_ok(f"Added MX record to {host.name}.")


@command_registry.register_command(
    prog="mx_remove",
    description="Remove MX record for host.",
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
    host = Host.get_by_any_means_or_raise(args.name)
    mx = MX.get_by_all(host.id, args.mx, args.priority)
    if not mx:
        raise EntityNotFound(
            f"{host} has no MX record with priority {args.priority} and mail exhange {args.mx}"
        )

    if mx.delete():
        OutputManager().add_ok(f"deleted MX from {host.name}.")
    else:
        raise DeleteError(f"Failed to remove MX for {host}")


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
    MX.output_multiple(Host.get_by_any_means_or_raise(args.name).mxs)


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
    host = Host.get_by_any_means_or_raise(args.name)
    params: QueryParams = {
        "preference": args.preference,
        "order": args.order,
        "flag": args.flag,
        "service": args.service,
        "regex": args.regex,
        "replacement": args.replacement,
        "host": host.id,
    }
    existing_naptr = NAPTR.get_by_query_unique(params)
    if existing_naptr:
        raise EntityAlreadyExists(f"{host} already has that NAPTR defined.")
    NAPTR.create(params=params)
    OutputManager().add_ok(f"Added NAPTR record to {host.name}.")


@command_registry.register_command(
    prog="naptr_remove",
    description="Remove matching NAPTR records from a host.",
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
        Flag("-force", action="store_true", description="Force deletion for multiple records."),
    ],
)
def naptr_remove(args: argparse.Namespace) -> None:
    """Remove NAPTR matching records from host.

    :param args: argparse.Namespace (name, preference, order, flag, service, regex, replacement)
    """
    host = Host.get_by_any_means_or_raise(args.name)
    naptrs = host.naptrs

    to_delete: list[NAPTR] = []

    for naptr in naptrs:
        for attribute in ("preference", "order", "flag", "service", "regex", "replacement"):
            if getattr(args, attribute) and getattr(naptr, attribute) != getattr(args, attribute):
                break

        to_delete.append(naptr)

    if not to_delete:
        raise EntityNotFound(f"No matching NAPTR record found for {host}")

    if len(to_delete) > 1 and not args.force:
        OutputManager().add_line("Found multiple matching NAPTR records:")
        NAPTR.output_multiple(to_delete)
        raise ForceMissing("Use --force to delete all matching records.")

    # This should ideally be done in a transaction, but the API doesn't support it.
    # Right now we may end up in a situation where some records are deleted and some are not.
    for naptr in to_delete:
        if naptr.delete():
            OutputManager().add_ok(f"Deleted NAPTR record from {host.name}.")
        else:
            raise DeleteError(f"Failed to remove NAPTR for {host}")


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
    NAPTR.output_multiple(Host.get_by_any_means_or_raise(args.name).naptrs)


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
    old_host = Host.get_by_any_means_or_raise(args.old)
    new_host = Host.get_by_any_means_or_raise(args.new)

    if new_host.ptr_overrides:
        raise InputFailure(f"{new_host} already has a PTR record.")

    if not old_host.ptr_overrides:
        raise EntityNotFound(f"No PTR records for {old_host}")

    ip = NetworkOrIP.parse_or_raise(args.ip, mode="ip")
    ptr_override = old_host.get_ptr_override(ip)
    if not ptr_override:
        raise EntityNotFound(f"No PTR record for {old_host} with IP {ip}")

    data = {"host": new_host.id}
    if not ptr_override.patch(data):
        raise PatchError(f"Failed to move PTR record from {old_host} to {new_host}")
    else:
        OutputManager().add_ok(f"Moved PTR record {ip} from {old_host.name} to {new_host.name}.")


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
    host = Host.get_by_any_means_or_raise(args.name)
    ip = NetworkOrIP.parse_or_raise(args.ip, mode="ip")
    ptr_override = host.get_ptr_override(ip)
    if not ptr_override:
        raise EntityNotFound(f"No PTR record for {host} with IP {ip}")

    if ptr_override.delete():
        OutputManager().add_ok(f"Removed PTR record {ip} from {host.name}.")
    else:
        raise DeleteError(f"Failed to remove PTR record from {host}")


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
    ip = NetworkOrIP.parse_or_raise(args.ip, mode="ip")

    host = Host.get_by_any_means_or_raise(args.name)
    existing_ptrs = PTR_override.get_list_by_field("ipaddress", str(ip))
    if existing_ptrs:
        raise EntityAlreadyExists(f"{ip} already exists in a PTR record.")

    network = Network.get_by_ip(ip)
    if not args.force:
        if host.zone is None:
            raise ForceMissing(f"{host} isn't in a zone controlled by MREG, must force")
        elif not network:
            raise ForceMissing(f"{ip} isn't in a network controlled by MREG, must force")
        elif network and network.is_reserved_ip(ip):
            raise ForceMissing(f"{ip} is reserved, must force")

    PTR_override.create({"host": host.id, "ipaddress": str(ip)})
    OutputManager().add_ok(f"Added PTR record {ip} to {host.name}.")


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
    ip = NetworkOrIP.parse_or_raise(args.ip, mode="ip")
    host = Host.get_by_any_means_or_raise(str(ip), inform_as_ptr=False)
    if not host.ptr_overrides:
        OutputManager().add_line(f"No PTR records for {host.name}")

    for ptr in host.ptr_overrides:
        if ip == ptr.ipaddress:
            ptr.output()


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
    name: str = args.name

    sname = HostName.parse_or_raise(name)
    host = Host.get_by_any_means_or_raise(args.host)

    szone = ForwardZone.get_from_hostname(sname)
    if not szone:
        raise EntityNotFound(f"{sname} isn't in a zone controlled by MREG")

    hzone = ForwardZone.get_from_hostname(host.name)
    if not hzone:
        raise EntityNotFound(f"{host} isn't in a zone controlled by MREG")

    data: QueryParams = {
        "name": sname,
        "priority": args.priority,
        "weight": args.weight,
        "port": args.port,
        "host": host.id,
        "ttl": args.ttl,
    }

    existing_srv = Srv.get_by_query_unique(data)
    if existing_srv:
        raise EntityAlreadyExists(f"{sname} already has that SRV defined.")
    Srv.create(data)
    OutputManager().add_ok(f"Added SRV record {sname} with target {host}.")


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
    name: str = args.name
    host_arg: str = args.host

    host = Host.get_by_any_means_or_raise(host_arg)
    sname = HostName.parse_or_raise(name)

    data: QueryParams = {
        "name": sname,
        "host": host.id,
        "priority": args.priority,
        "port": args.port,
        "weight": args.weight,
    }

    srv = Srv.get_by_query_unique(data)
    if not srv:
        raise EntityNotFound(
            f"No SRV record for {sname} with target {host} matching the given values."
        )

    if srv.delete():
        OutputManager().add_ok(f"Removed SRV record {sname} from {host.name}.")
    else:
        raise DeleteError(f"Failed to remove SRV for {sname}")


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
    service: str = args.service

    sname = HostName.parse_or_raise(service)
    srvs = Srv.get_list_by_field("name", sname)

    if len(srvs) == 0:
        raise EntityNotFound(f"No SRV records for {sname}")

    Srv.output_multiple(srvs)


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
    host = Host.get_by_any_means_or_raise(args.name)

    data: QueryParams = {
        "algorithm": args.algorithm,
        "hash_type": args.hash_type,
        "fingerprint": args.fingerprint,
        "host": host.id,
    }

    existing_sshfp = SSHFP.get_by_query_unique(data)
    if existing_sshfp:
        raise EntityAlreadyExists(f"{host} already has that SSHFP defined.")

    SSHFP.create(data)
    OutputManager().add_ok(f"Added SSHFP record for {host.name}.")


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
    host = Host.get_by_any_means_or_raise(args.name)
    sshfps = None

    if args.fingerprint:
        sshfps = [
            SSHFP.get_by_query_unique_or_raise({"fingerprint": args.fingerprint, "host": host.id})
        ]
    else:
        sshfps = host.sshfps

    if not sshfps:
        raise EntityNotFound(f"No matching SSHFP records for {host}")
    else:
        for sshfp in sshfps:
            if not sshfp.delete():
                raise DeleteError(f"Failed to remove SSHFP for {host}")
            else:
                fp = sshfp.fingerprint
                OutputManager().add_ok(f"Removed SSHFP record with fingerprint {fp} for {host}.")


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
    host = Host.get_by_any_means_or_raise(args.name)
    sshfps = host.sshfps

    if not sshfps:
        raise EntityNotFound(f"No SSHFP records for {host}")

    SSHFP.output_multiple(sshfps)


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
    args.ttl = "default"
    ttl_set(args)


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
    name: str = args.name
    ttl: str = args.ttl

    target = Host.get_by_any_means(name)
    if not target:
        target = Srv.get_by_field("name", name)

    if not target:
        raise EntityNotFound(f"No host or SRV record found for {name}")

    result = target.set_ttl(ttl)
    new_ttl = result.ttl or ttl  # prefer the actual value if it exists
    if result:
        OutputManager().add_ok(f"Set TTL for {target} to {new_ttl}.")
    else:
        raise PatchError(f"Failed to set TTL for {target}")


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
    Host.get_by_any_means_or_raise(args.name).output_ttl()


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
    host = Host.get_by_any_means_or_raise(args.name)
    if host.has_txt(args.text):
        raise EntityAlreadyExists(f"{host} already has that TXT defined.")

    TXT.create({"host": host.id, "txt": args.text})
    OutputManager().add_ok(f"Added TXT record to {host}.")


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
    host = Host.get_by_any_means_or_raise(args.name)
    txt = TXT.get_by_query_unique({"host": host.id, "txt": args.text})

    if not txt:
        raise EntityNotFound(f"{host} has no TXT record matching '{args.text}'")

    if txt.delete():
        OutputManager().add_ok(f"Removed TXT record '{args.text}' from {host}.")
    else:
        raise DeleteError(f"Failed to remove TXT with '{args.text}' for {host}")


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
    host = Host.get_by_any_means_or_raise(args.name)
    txts = host.txts

    if not txts:
        raise EntityNotFound(f"No TXT records for {host}")

    TXT.output_multiple(txts, padding=5)
