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

from mreg_api.models import (
    NAPTR,
    Srv,
)

from mreg_cli.client import get_client
from mreg_cli.commands.host import registry as command_registry
from mreg_cli.exceptions import (
    DeleteError,
    EntityAlreadyExists,
    EntityNotFound,
    ForceMissing,
    InputFailure,
    handle_exception,
)
from mreg_cli.output.host import (
    output_hinfo,
    output_host_ttl,
    output_location,
    output_mxs,
    output_naptrs,
    output_ptr_override,
    output_srvs,
    output_sshfps,
    output_txts,
)
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag


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
    name: str = args.name
    cpu: str = args.cpu
    os: str = args.os

    client = get_client()
    host = client.resolve_host(name)
    if host.hinfo:
        raise EntityAlreadyExists(f"{host} already has hinfo set.")

    client.hinfo.create(host=host, cpu=cpu, os=os)
    OutputManager().add_ok(f"Added HINFO record for {host.name}.")


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
    client = get_client()
    host = client.resolve_host(args.name)
    if not host.hinfo:
        raise EntityNotFound(f"{host} already has no hinfo set.")

    hinfo = client.hinfo.get_by_host(host)
    if hinfo:
        client.hinfo.delete(hinfo)
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
    client = get_client()
    host = client.resolve_host(args.name)
    if not host.hinfo:
        OutputManager().add_line(f"No hinfo for {host.name}")

    hinfo = client.hinfo.get_by_host(host)
    if hinfo:
        output_hinfo(hinfo)
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
    client = get_client()
    host = client.resolve_host(args.name)
    if not host.loc:
        raise EntityNotFound(f"{host} already has no loc set.")

    loc = client.location.get_by_host(host)
    if loc:
        client.location.delete(loc)
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
    name: str = args.name
    loc: str = args.loc

    client = get_client()
    host = client.resolve_host(name)

    if host.loc:
        raise EntityAlreadyExists(f"{host} already has loc set.")

    client.location.create(host=host, loc=loc)
    OutputManager().add_ok(f"Added LOC record for {host.name}.")


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
    client = get_client()
    host = client.resolve_host(args.name)
    if not host.loc:
        raise EntityNotFound(f"No loc for {host.name}")

    output_location(host.loc)


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
    client = get_client()
    mx: str = args.mx
    priority: int = args.priority
    name: str = args.name

    host = client.resolve_host(name)
    client.mx.create(host=host, mx=mx, priority=priority)

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
    client = get_client()
    name: str = args.name
    mx_arg: str = args.mx
    priority: int = args.priority

    host = client.resolve_host(name)
    mx_obj = client.mx.get_by_all(host, mx_arg, priority)
    client.mx.delete(mx_obj)
    OutputManager().add_ok(
        f"Deleted MX {mx_obj.mx} with priority {priority} from {host.name}.",
    )


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
    client = get_client()
    host = client.resolve_host(args.name)
    output_mxs(host.mxs)


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
    client = get_client()
    host = client.resolve_host(args.name)

    existing_naptr = client.naptr.first(
        host=host.id,
        preference=args.preference,
        order=args.order,
        flag=args.flag,
        service=args.service,
        regex=args.regex,
        replacement=args.replacement,
        required=False,
    )
    if existing_naptr:
        raise EntityAlreadyExists(f"{host} already has that NAPTR defined.")

    client.naptr.create(
        host=host,
        preference=args.preference,
        order=args.order,
        flag=args.flag,
        service=args.service,
        regex=args.regex,
        replacement=args.replacement,
    )
    OutputManager().add_ok(f"Added NAPTR record to {host.name}.")


def filter_naptrs(
    naptrs: list[NAPTR],
    preference: int,
    order: int,
    flag: str | None,
    service: str | None,
    regex: str | None,
    replacement: str,
) -> list[NAPTR]:
    """Filter NAPTRs, matching on all required fields and any optional fields that are provided."""
    return [
        naptr
        for naptr in naptrs
        if (
            naptr.preference == preference
            and naptr.order == order
            and naptr.replacement == replacement
            # These 3 fields can be blank, and we need to
            # know if we should filter on them or not based on user input
            and (flag is None or naptr.flag == flag)
            and (service is None or naptr.service == service)
            and (regex is None or naptr.regex == regex)
        )
    ]


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
        Flag(
            "-replacement",
            description="NAPTR replacement.",
            required=True,
            metavar="REPLACEMENT",
        ),
        Flag("-flag", description="NAPTR flag.", default=None, metavar="FLAG"),
        Flag("-service", description="NAPTR service.", default=None, metavar="SERVICE"),
        Flag("-regex", description="NAPTR regexp.", default=None, metavar="REGEXP"),
        Flag("-force", action="store_true", description="Force deletion for multiple records."),
    ],
)
def naptr_remove(args: argparse.Namespace) -> None:
    """Remove NAPTR matching records from host.

    :param args: argparse.Namespace (name, preference, order, flag, service, regex, replacement)
    """
    client = get_client()
    host = client.resolve_host(args.name)
    to_delete = filter_naptrs(
        host.naptrs,
        preference=args.preference,
        order=args.order,
        flag=args.flag,
        service=args.service,
        regex=args.regex,
        replacement=args.replacement,
    )

    if not to_delete:
        raise EntityNotFound(f"No matching NAPTR record found for {host}")

    if len(to_delete) > 1 and not args.force:
        OutputManager().add_line("Found multiple matching NAPTR records:")
        output_naptrs(to_delete)
        raise ForceMissing("Use --force to delete all matching records.")

    # This should ideally be done in a transaction, but the API doesn't support it.
    # Right now we may end up in a situation where some records are deleted and some are not.
    # Best-effort lets us delete as many as possible at the very least.
    for naptr in to_delete:
        try:
            client.naptr.delete(naptr)
            OutputManager().add_ok(f"Deleted NAPTR record from {host.name}.")
        except Exception as e:
            handle_exception(e)


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
    client = get_client()
    host = client.resolve_host(args.name)
    output_naptrs(host.naptrs)


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
    from mreg_api.models import NetworkOrIP

    client = get_client()
    old_host = client.resolve_host(args.old)
    new_host = client.resolve_host(args.new)

    if new_host.ptr_overrides:
        raise InputFailure(f"{new_host} already has a PTR record.")

    if not old_host.ptr_overrides:
        raise EntityNotFound(f"No PTR records for {old_host}")

    ip = NetworkOrIP.parse_or_raise(args.ip, mode="ip")
    ptr_override = old_host.get_ptr_override(ip)
    if not ptr_override:
        raise EntityNotFound(f"No PTR record for {old_host} with IP {ip}")

    client.ptroverride.update(ptr_override, host=new_host)
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
    from mreg_api.models import NetworkOrIP

    client = get_client()
    host = client.resolve_host(args.name)
    ip = NetworkOrIP.parse_or_raise(args.ip, mode="ip")
    ptr_override = host.get_ptr_override(ip)
    if not ptr_override:
        raise EntityNotFound(f"No PTR record for {host} with IP {ip}")

    client.ptroverride.delete(ptr_override)
    OutputManager().add_ok(f"Removed PTR record {ip} from {host.name}.")


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
    from mreg_api.models import NetworkOrIP

    client = get_client()
    ip = NetworkOrIP.parse_or_raise(args.ip, mode="ip")

    host = client.resolve_host(args.name)
    existing_ptrs = client.ptroverride.list(ipaddress=str(ip))
    if existing_ptrs:
        raise EntityAlreadyExists(f"{ip} already exists in a PTR record.")

    network = client.network.get_by_ip(str(ip))
    if not args.force:
        if host.zone is None:
            raise ForceMissing(f"{host} isn't in a zone controlled by MREG, must force")
        elif not network:
            raise ForceMissing(f"{ip} isn't in a network controlled by MREG, must force")
        elif network:
            reserved_ips = client.network.get_reserved_ips(network)
            if ip in reserved_ips:
                raise ForceMissing(f"{ip} is reserved, must force")

    client.ptroverride.create(host=host, ipaddress=ip)
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
    from mreg_api.models import NetworkOrIP

    client = get_client()
    ip = NetworkOrIP.parse_or_raise(args.ip, mode="ip")

    # Suppress PTR override events from being printed when we resolve PTR overrides
    with OutputManager().suppress_events():
        host = client.resolve_host(str(ip))
        if not host.ptr_overrides:
            OutputManager().add_line(f"No PTR records for {host.name}")

        for ptr in host.ptr_overrides:
            if ip == ptr.ipaddress:
                output_ptr_override(ptr)


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
    client = get_client()
    name: str = args.name

    sname = client.fqdn(name)
    host = client.resolve_host(args.host)

    szone = client.zone.get_from_host(sname)
    if not szone:
        raise EntityNotFound(f"{sname} isn't in a zone controlled by MREG")

    hzone = client.zone.get_from_host(host.name)
    if not hzone:
        raise EntityNotFound(f"{host} isn't in a zone controlled by MREG")

    existing_srv = client.srv.first(
        name=str(sname),
        host=host.id,
        priority=args.priority,
        weight=args.weight,
        port=args.port,
        required=False,
    )
    if existing_srv:
        raise EntityAlreadyExists(f"{sname} already has that SRV defined.")

    client.srv.create(
        host=host,
        name=str(sname),
        priority=args.priority,
        weight=args.weight,
        port=args.port,
        ttl=args.ttl if args.ttl is not None else None,
    )
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
    client = get_client()
    name: str = args.name
    host_arg: str = args.host

    host = client.resolve_host(host_arg)
    sname = client.fqdn(name)

    srv = client.srv.first(
        name=str(sname),
        host=host.id,
        priority=args.priority,
        port=args.port,
        weight=args.weight,
        required=False,
    )
    if not srv:
        raise EntityNotFound(
            f"No SRV record for {sname} with target {host} matching the given values."
        )

    client.srv.delete(srv)
    OutputManager().add_ok(f"Removed SRV record {sname} from {host.name}.")


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
    client = get_client()
    service: str = args.service

    sname = client.fqdn(service)
    srvs = client.srv.list(name=str(sname))

    if len(srvs) == 0:
        raise EntityNotFound(f"No SRV records for {sname}")

    output_srvs(srvs)


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
    client = get_client()
    host = client.resolve_host(args.name)

    existing_sshfp = client.sshfp.first(
        host=host.id,
        algorithm=args.algorithm,
        hash_type=args.hash_type,
        fingerprint=args.fingerprint,
        required=False,
    )
    if existing_sshfp:
        raise EntityAlreadyExists(f"{host} already has that SSHFP defined.")

    client.sshfp.create(
        host=host,
        algorithm=args.algorithm,
        hash_type=args.hash_type,
        fingerprint=args.fingerprint,
    )
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
    client = get_client()
    host = client.resolve_host(args.name)
    sshfps = None

    if args.fingerprint:
        sshfp = client.sshfp.first(required=True, fingerprint=args.fingerprint, host=host.id)
        sshfps = [sshfp]
    else:
        sshfps = host.sshfps

    if not sshfps:
        raise EntityNotFound(f"No matching SSHFP records for {host}")
    else:
        for sshfp in sshfps:
            fp = sshfp.fingerprint
            client.sshfp.delete(sshfp)
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
    client = get_client()
    host = client.resolve_host(args.name)
    sshfps = host.sshfps

    if not sshfps:
        raise EntityNotFound(f"No SSHFP records for {host}")

    output_sshfps(sshfps)


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
    client = get_client()
    name: str = args.name
    ttl: str = args.ttl

    # Convert "default" to None (API uses None for default TTL)
    ttl_value: int | None = None if ttl == "default" else int(ttl)

    target_host = client.resolve_host(name, required=False)
    target_srv: Srv | None = None

    if target_host is None:
        target_srv = client.srv.first(name=name, required=False)

    if target_host is None and target_srv is None:
        raise EntityNotFound(f"No host or SRV record found for {name}")

    # NOTE: do we really need to confirm that we set the TTL by refreshing?
    if target_host is not None:
        client.host.update(target_host, ttl=ttl_value)
        result = client.host.refresh(target_host)
        new_ttl = result.ttl if result.ttl is not None else ttl
        OutputManager().add_ok(f"Set TTL for {target_host} to {new_ttl}.")
    else:
        assert target_srv is not None
        client.srv.update(target_srv, ttl=ttl_value)
        result = client.srv.refresh(target_srv)
        new_ttl = result.ttl if result.ttl is not None else ttl
        OutputManager().add_ok(f"Set TTL for {target_srv} to {new_ttl}.")


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
    client = get_client()
    host = client.resolve_host(args.name)
    output_host_ttl(host)


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
    client = get_client()
    host = client.resolve_host(args.name)

    if host.has_txt(args.text):
        raise EntityAlreadyExists(f"{host} already has that TXT defined.")

    client.txt.create(host=host, txt=args.text)
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
    client = get_client()
    host = client.resolve_host(args.name)
    txt = client.txt.first(host=host.id, txt=args.text, required=False)

    if not txt:
        raise EntityNotFound(f"{host} has no TXT record matching '{args.text}'")

    client.txt.delete(txt)
    OutputManager().add_ok(f"Removed TXT record '{args.text}' from {host}.")


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
    client = get_client()
    host = client.resolve_host(args.name)
    txts = host.txts

    if not txts:
        raise EntityNotFound(f"No TXT records for {host}")

    output_txts(host.txts, padding=5)
