"""Core commands for the host sub-module.

Commands implemented:

    - add
    - remove
    - rename
    - info
    - find
    - set_comment
    - set_contact
"""

from __future__ import annotations

import argparse
import ipaddress

from mreg_cli.api.models import Host, HostT, MACAddressField, Zone
from mreg_cli.commands.host import registry as command_registry
from mreg_cli.exceptions import HostNotFoundWarning
from mreg_cli.log import cli_info, cli_warning
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag
from mreg_cli.utilities.api import get, get_list, patch
from mreg_cli.utilities.history import format_history_items, get_history_items
from mreg_cli.utilities.host import (
    cname_exists,
    get_host_by_name,
    get_requested_ip,
    host_info_by_name,
)
from mreg_cli.utilities.output import output_host_info, output_ip_info
from mreg_cli.utilities.shared import clean_hostname, convert_wildcard_to_regex, format_mac
from mreg_cli.utilities.validators import is_valid_email, is_valid_ip, is_valid_mac
from mreg_cli.utilities.zone import zone_check_for_hostname

#########################################
#  Implementation of sub command 'add'  #
#########################################


@command_registry.register_command(
    prog="add",
    description=(
        "Add a new host with the given name, ip or network and contact. comment is optional."
    ),
    short_desc="Add a new host",
    flags=[
        Flag(
            "name",
            short_desc="Name of new host (req)",
            description="Name of new host (req)",
        ),
        Flag(
            "-ip",
            short_desc="An ip or net",
            description=(
                "The hosts ip or a network. If it's a network the first free IP is "
                "selected from the network"
            ),
            metavar="IP/NET",
        ),
        Flag(
            "-contact",
            short_desc="Contact mail for the host",
            description="Contact mail for the host",
        ),
        Flag("-comment", short_desc="A comment.", description="A comment."),
        Flag("-macaddress", description="Mac address", metavar="MACADDRESS"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def add(args: argparse.Namespace) -> None:
    """Add a new host with the given name.

    Required arguments in argparse:
        - name: Name of new host
        - ip: An ip or network

    Optional arguments in argparse:
        - contact: Contact mail for the host
        - comment: A comment
        - macaddress: Mac address for assocation to the IP

    :param args: argparse.Namespace (name, ip, contact, comment, force, macaddress)

    """
    ip = args.ip
    hname = HostT(hostname=args.name)
    macaddress = args.macaddress
    host = Host.get_by_any_means(hname)

    if macaddress is not None:
        try:
            macaddress = MACAddressField(address=macaddress).address
        except ValueError:
            cli_warning(f"invalid MAC address: {macaddress}")

    host = Host.get_by_any_means(hname)
    if host:
        if host.name.hostname != hname.hostname:
            cli_warning(f"{hname} is a CNAME pointing to {host.name}")
        else:
            cli_warning(f"Host {hname} already exists.")

    zone = Zone.get_from_hostname(hname)
    if not zone and not args.force:
        cli_warning(f"{hname} isn't in a zone controlled by MREG, must force")
    if zone and zone.is_delegated() and not args.force:
        cli_warning(f"{hname} is in zone delegation {zone.name}, must force")

    if "*" in hname.hostname and not args.force:
        cli_warning("Wildcards must be forced.")

    if args.ip:
        ip = get_requested_ip(args.ip, args.force)

    # Contact sanity check
    if args.contact and not is_valid_email(args.contact):
        cli_warning(f"invalid mail address ({args.contact}) when trying to add {args.name}")

    if macaddress is not None:
        try:
            macaddress = MACAddressField(address=macaddress)
        except ValueError:
            cli_warning(f"invalid MAC address: {macaddress}")

    data: dict[str, str | None] = {
        "name": hname.hostname,
        "contact": args.contact or None,
        "comment": args.comment or None,
    }

    ip = None
    network = None
    if args.ip:
        valid_input = False
        try:
            ip = ipaddress.ip_address(args.ip)
            data["ipaddress"] = str(ip)
            valid_input = True
        except ValueError:
            pass

        if not valid_input:
            try:
                network = ipaddress.ip_network(args.ip)
                data["network"] = str(network)
                valid_input = True
            except ValueError:
                pass

        if not valid_input:
            cli_warning(f"Invalid ip or network: {args.ip}")

    host = Host.create(data)
    if not host:
        cli_warning("Failed to add host.")

    if macaddress is not None:
        if ip:
            host.associate_mac_to_ip(macaddress, str(ip))
        else:
            # We passed a network to create the host, so we need to find the IP
            # that was assigned to the host. We don't get that in the response
            # per se, so we check to see if there is only one IP in the host and
            # use that. If there are more than one, we can't know which one was
            # assigned to the host during create, so we abort.
            if len(host.ipaddresses) == 1:
                host.associate_mac_to_ip(macaddress, host.ipaddresses[0].ipaddress)
            else:
                cli_info(
                    "Failed to associate MAC address to IP, multiple IP addresses after creation.",
                    print_msg=True,
                )
    msg = f"created host {hname}"
    if ip or len(host.ipaddresses) == 1:
        output_ip = ip or host.ipaddresses[0].ipaddress
        msg += f" with IP {output_ip}"

    cli_info(msg, print_msg=True)


@command_registry.register_command(
    prog="remove",
    description="Remove the given host.",
    short_desc="Remove a host",
    flags=[
        Flag(
            "name",
            short_desc="Name or ip.",
            description="Name of host or an ip belonging to the host.",
            metavar="NAME/IP",
        ),
        Flag("-force", action="store_true", description="Enable force."),
        Flag(
            "-override",
            short_desc="Comma separated override list, requires -force.",
            description=(
                "Comma separated overrides for forced removal. Requires -force."
                "Accepted overrides: 'cname', 'ipadress', 'mx', 'srv', 'ptr', 'naptr'."
                "Example usage: '-override cname,ipaddress,mx'"
            ),
            metavar="OVERRIDE",
        ),
    ],
)
def remove(args: argparse.Namespace) -> None:
    """Remove host.

    :param args: argparse.Namespace (name, force, override)
    """
    import mreg_cli.api as api

    hostname = args.name
    host = api.get_host(hostname)

    if host is None:
        cli_warning(f"Host {args.name} not found.")

    overrides: list[str] = args.override.split(",") if args.override else []

    accepted_overrides = ["cname", "ipaddress", "mx", "srv", "ptr", "naptr"]
    for override in overrides:
        if override not in accepted_overrides:
            cli_warning(f"Invalid override: {override}. Accepted overrides: {accepted_overrides}")

    def forced(override_required: str | None = None) -> bool:
        # If we require an override, check if it's in the list of provided overrides.
        if override_required:
            return override_required in overrides

        # We didn't require an override, so we only need to check for force.
        if args.force:
            return True

        # And the fallback is "no".
        return False

    warnings: list[str] = []
    # Require force if host has any cnames.
    if host.cnames and not args.force:
        warnings.append(f"  {len(host.cnames)} cnames, override with 'cname'")
        for cname in host.cnames:
            warnings.append(f"    - {cname.name}")

    # Require force if host has multiple A/AAAA records and they are not in the same VLAN.
    if len(host.ipaddresses) > 1:
        host_vlans = host.vlans()
        same_vlan = len(host_vlans) == 1

        if same_vlan and not forced():
            warnings.append("  multiple ipaddresses on the same VLAN. Must use 'force'.")
        elif not same_vlan and not forced("ipaddresses"):
            warnings.append(
                "  {} ipaddresses on distinct VLANs, override with 'ipadress'".format(
                    len(host.ipaddresses)
                )
            )
            for vlan in host_vlans:
                vlan = host_vlans[vlan]
                ip_strings = [str(ip.ipaddress.address) for ip in vlan]
                ip_strings.sort()
                warnings.append(f"    - {', '.join(ip_strings)} (vlan: {vlan})")

    if host.mxs and not forced("mx"):
        warnings.append(f"  {len(host.mxs)} MX records, override with 'mx'")
        for mx in host.mxs:
            warnings.append(f"    - {mx.mx} (priority: {mx.priority})")

    # Require force if host has any NAPTR records. Delete the NAPTR records if
    # force
    naptrs = host.naptrs()
    if len(naptrs) > 0:
        if not forced("naptr"):
            warnings.append(f"  {len(naptrs)} NAPTR records, override with 'naptr'")
            for naptr in naptrs:
                warnings.append(f"    - {naptr.replacement}")
        else:
            for naptr in naptrs:
                cli_info(
                    "deleted NAPTR record {} when removing {}".format(
                        naptr.replacement,
                        host.name,
                    )
                )

    # Require force if host has any SRV records. Delete the SRV records if force
    srvs = host.srvs()
    if len(srvs) > 0:
        if not forced("srv"):
            warnings.append(f"  {len(srvs)} SRV records, override with 'srv'")
            for srv in srvs:
                warnings.append(f"    - {srv.name}")
        else:
            for srv in srvs:
                cli_info(
                    "deleted SRV record {} when removing {}".format(
                        srv.name,
                        host.name,
                    )
                )

    # Require force if host has any PTR records. Delete the PTR records if force
    if len(host.ptr_overrides) > 0:
        if not forced("ptr"):
            warnings.append(f"  {len(host.ptr_overrides)} PTR records, override with 'ptr'")
            for ptr in host.ptr_overrides:
                warnings.append(f"    - {ptr.ipaddress}")
        else:
            for ptr in host.ptr_overrides:
                cli_info(
                    "deleted PTR record {} when removing {}".format(
                        ptr.ipaddress,
                        host.name,
                    )
                )

    # Warn user and raise exception if any force requirements was found
    if warnings:
        warn_msg = "\n".join(warnings)
        cli_warning(f"{host.name} requires force and override for deletion:\n{warn_msg}")

    if host.delete():
        cli_info(f"removed {host.name}", print_msg=True)
    else:
        cli_warning(f"failed to remove {host.name}")


@command_registry.register_command(
    prog="info_pydantic",
    description="Print info about one or more hosts.",
    short_desc="Print info about one or more hosts.",
    flags=[
        Flag(
            "hosts",
            description="One or more hosts given by their name, ip or mac.",
            short_desc="One or more names, ips or macs.",
            nargs="+",
            metavar="NAME/IP/MAC",
        )
    ],
)
def host_info_pydantic(args: argparse.Namespace) -> None:
    """Print information about host."""
    host = Host.get_by_any_means(args.hosts[0], inform_as_cname=True)
    if host is None:
        cli_warning(f"Host {args.hosts[0]} not found.")

    host.output()


@command_registry.register_command(
    prog="info",
    description="Print info about one or more hosts.",
    short_desc="Print info about one or more hosts.",
    flags=[
        Flag(
            "hosts",
            description="One or more hosts given by their name, ip or mac.",
            short_desc="One or more names, ips or macs.",
            nargs="+",
            metavar="NAME/IP/MAC",
        )
    ],
)
def host_info(args: argparse.Namespace) -> None:
    """Print information about host.

    If <name> is an alias the cname hosts info is shown.

    :param args: argparse.Namespace (hosts)
    """
    for name_or_ip in args.hosts:
        # Get host info or raise exception
        if is_valid_ip(name_or_ip):
            output_ip_info(name_or_ip)
        elif is_valid_mac(name_or_ip):
            mac = format_mac(name_or_ip)
            ret = get_list("api/v1/hosts/", params={"ipaddresses__macaddress": mac})
            if ret:
                output_host_info(ret[0])
            else:
                cli_warning(f"Found no host with macaddress: {mac}")
        else:
            from mreg_cli.api import clean_hostname

            info = host_info_by_name(name_or_ip)
            name = clean_hostname(name_or_ip)
            if any(cname["name"] == name for cname in info["cnames"]):
                OutputManager().add_line(f'{name} is a CNAME for {info["name"]}')
            output_host_info(info)


@command_registry.register_command(
    prog="find",
    description="Lists hosts matching search criteria",
    short_desc="Lists hosts matching search criteria",
    flags=[
        Flag(
            "-name",
            description="Name or part of name",
            short_desc="Name or part of name",
            metavar="NAME",
        ),
        Flag(
            "-comment",
            description="Comment or part of comment",
            short_desc="Comment or part of comment",
            metavar="COMMENT",
        ),
        Flag(
            "-contact",
            description="Contact or part of contact",
            short_desc="Contact or part of contact",
            metavar="CONTACT",
        ),
    ],
)
def find(args: argparse.Namespace) -> None:
    """List hosts maching search criteria.

    :param args: argparse.Namespace (name, comment, contact)
    """

    def _add_param(param: str, value: str) -> None:
        param, value = convert_wildcard_to_regex(param, value, True)
        params[param] = value

    if not any([args.name, args.comment, args.contact]):
        cli_warning("Need at least one search critera")

    params: dict[str, str | int] = {
        "ordering": "name",
        "page_size": 1,
    }

    for param in ("contact", "comment", "name"):
        value = getattr(args, param)
        if value:
            _add_param(param, value)

    path = "/api/v1/hosts/"
    ret = get(path, params=params).json()

    if ret["count"] == 0:
        cli_warning("No hosts found.")
    elif ret["count"] > 500:
        cli_warning(f'Too many hits, {ret["count"]}, more than limit of 500. Refine search.')

    del params["page_size"]
    ret = get_list(path, params=params)
    max_name = max_contact = 20
    for i in ret:
        max_name = max(max_name, len(i["name"]))
        max_contact = max(max_contact, len(i["contact"]))

    def _print(name: str, contact: str, comment: str) -> None:
        OutputManager().add_line(
            "{0:<{1}} {2:<{3}} {4}".format(name, max_name, contact, max_contact, comment)
        )

    _print("Name", "Contact", "Comment")
    for i in ret:
        _print(i["name"], i["contact"], i["comment"])


@command_registry.register_command(
    prog="find_pydantic",
    description="Lists hosts matching search criteria",
    short_desc="Lists hosts matching search criteria",
    flags=[
        Flag(
            "-name",
            description="Name or part of name",
            short_desc="Name or part of name",
            metavar="NAME",
        ),
        Flag(
            "-comment",
            description="Comment or part of comment",
            short_desc="Comment or part of comment",
            metavar="CONTACT",
        ),
        Flag(
            "-contact",
            description="Contact or part of contact",
            short_desc="Contact or part of contact",
            metavar="CONTACT",
        ),
    ],
)
def find_pydantic(args: argparse.Namespace) -> None:
    """List hosts maching search criteria.

    :param args: argparse.Namespace (name, comment, contact)
    """
    import mreg_cli.api as api

    def _add_param(param: str, value: str) -> None:
        param, value = convert_wildcard_to_regex(param, value, True)
        params[param] = value

    if not any([args.name, args.comment, args.contact]):
        cli_warning("Need at least one search critera")

    params: dict[str, str | int] = {
        "ordering": "name",
    }

    for param in ("contact", "comment", "name"):
        value = getattr(args, param)
        if value:
            _add_param(param, value)

    hostlist = api.get_hosts(params)
    hostlist.output_host_list()


@command_registry.register_command(
    prog="rename",
    description="Rename host. If the old name is an alias then the alias is renamed.",
    short_desc="Rename a host",
    flags=[
        Flag(
            "old_name",
            description=(
                "Host name of the host to rename. May be an alias. "
                "If it is an alias then the alias is renamed."
            ),
            short_desc="Existing host name.",
            metavar="OLD",
        ),
        Flag(
            "new_name",
            description="New name for the host, or alias.",
            short_desc="New name",
            metavar="NEW",
        ),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def rename(args: argparse.Namespace) -> None:
    """Rename host. If <old-name> is an alias then the alias is renamed.

    :param args: argparse.Namespace (old_name, new_name, force)
    """
    # Find old host
    old_name = get_host_by_name(args.old_name)

    # Make sure new hostname does not exist.
    new_name = clean_hostname(args.new_name)
    try:
        new_name = get_host_by_name(new_name)
    except HostNotFoundWarning:
        pass
    else:
        if not args.force:
            cli_warning(f"host {new_name} already exists")

    if cname_exists(new_name):
        cli_warning("the name is already in use by a cname")

    # Require force if FQDN not in MREG zone
    zone_check_for_hostname(new_name, args.force)

    if "*" in new_name and not args.force:
        cli_warning("Wildcards must be forced.")

    # Rename host
    path = f"/api/v1/hosts/{old_name}"
    # Cannot redo/undo now since it changes name
    patch(path, name=new_name)

    cli_info(f"renamed {old_name} to {new_name}", print_msg=True)


# Add 'set_comment' as a sub command to the 'host' command
@command_registry.register_command(
    prog="set_comment",
    description="Set comment for host. If NAME is an alias the cname host is updated.",
    short_desc="Set comment.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
        Flag(
            "comment",
            description=(
                "The new comment. If it contains spaces then it must be enclosed in quotes."
            ),
            metavar="COMMENT",
        ),
    ],
)
def set_comment(args: argparse.Namespace) -> None:
    """Set comment for host. If <name> is an alias the cname host is updated.

    :param args: argparse.Namespace (name, comment)
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)
    # Update comment
    path = f"/api/v1/hosts/{info['name']}"
    patch(path, comment=args.comment)
    cli_info(
        'Updated comment of {} to "{}"'.format(info["name"], args.comment),
        print_msg=True,
    )


@command_registry.register_command(
    prog="set_contact",
    description="Set contact for host. If <name> is an alias the cname host is updated.",
    short_desc="Set contact.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
        Flag("contact", description="Mail address of the contact.", metavar="CONTACT"),
    ],
)
def set_contact(args: argparse.Namespace) -> None:
    """Set contact for host. If <name> is an alias the cname host is updated.

    :param args: argparse.Namespace (name, contact)
    """
    # Contact sanity check
    if not is_valid_email(args.contact):
        cli_warning(f"invalid mail address {args.contact} (target host: {args.name})")

    # Get host info or raise exception
    info = host_info_by_name(args.name)

    # Update contact information
    path = f"/api/v1/hosts/{info['name']}"
    patch(path, contact=args.contact)
    cli_info("Updated contact of {} to {}".format(info["name"], args.contact), print_msg=True)


@command_registry.register_command(
    prog="history",
    description="Show history for host.",
    short_desc="Show history.",
    flags=[
        Flag("name", description="Host name", metavar="NAME"),
    ],
)
def history(args: argparse.Namespace) -> None:
    """Show host history for name.

    :param args: argparse.Namespace (name)
    """
    hostname = clean_hostname(args.name)
    items = get_history_items(hostname, "host", data_relation="hosts")
    format_history_items(hostname, items)
