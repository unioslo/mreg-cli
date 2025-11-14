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
import re
from enum import Enum

from mreg_cli.api.fields import HostName, MacAddress
from mreg_cli.api.models import (
    ForwardZone,
    Host,
    HostList,
    IPAddress,
    Network,
    NetworkOrIP,
)
from mreg_cli.commands.host import registry as command_registry
from mreg_cli.exceptions import (
    APIError,
    CreateError,
    DeleteError,
    EntityAlreadyExists,
    EntityNotFound,
    EntityOwnershipMismatch,
    ForceMissing,
    InputFailure,
    InvalidIPAddress,
    PatchError,
)
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag, JsonMapping, QueryParams
from mreg_cli.utilities.shared import convert_wildcard_to_regex


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
    hname = HostName.parse_or_raise(args.name)
    network_or_ip: str = args.ip
    macaddress: str | None = args.macaddress
    force: bool = args.force

    if macaddress is not None:
        macaddress = MacAddress.parse_or_raise(macaddress)
        IPAddress.ensure_associable(macaddress, force=force)

    host = Host.get_by_any_means(hname)
    if host:
        if host.name != hname:
            raise EntityOwnershipMismatch(f"{hname} is a CNAME pointing to {host.name}")
        else:
            raise EntityAlreadyExists(f"Host {hname} already exists.")

    zone = ForwardZone.get_from_hostname(hname)
    if not zone and not force:
        raise ForceMissing(f"{hname} isn't in a zone controlled by MREG, must force")
    if zone and zone.is_delegated() and not force:
        raise ForceMissing(f"{hname} is in zone delegation {zone.name}, must force")

    if "*" in hname and not force:
        raise ForceMissing("Wildcards must be forced.")

    data: JsonMapping = {
        "name": hname,
        "contact": args.contact or None,
        "comment": args.comment or None,
    }

    if network_or_ip:
        autodetect = False
        network = None

        # Combine multiple slashes, in case anyone is trying to be funny
        network_or_ip = re.sub(r"/+", "/", network_or_ip)

        if network_or_ip.endswith("/32"):
            network_or_ip = network_or_ip[:-3]
        elif network_or_ip.endswith("/"):
            autodetect = True
            network_or_ip = network_or_ip.rstrip("/")

        net_or_ip = NetworkOrIP.validate(network_or_ip)

        if net_or_ip.is_ip() and not autodetect:
            ipaddr = net_or_ip.as_ip()
            try:
                network = Network.get_by_ip(ipaddr)
                if network:
                    if ipaddr == network.network_address and not force:
                        raise InvalidIPAddress(
                            f"IP {ipaddr} is a network address, not a host address, must force"
                        )
                    elif ipaddr == network.broadcast_address and not force:
                        raise InvalidIPAddress(
                            f"IP {ipaddr} is a broadcast address, not a host address, must force"
                        )
            except (EntityNotFound, APIError) as e:
                if not force:
                    raise ForceMissing(f"IP {ipaddr} is not in a network, must force") from e
            data["ipaddress"] = str(network_or_ip)

        elif net_or_ip.is_network() or autodetect:
            network = (
                Network.get_by_ip(net_or_ip.as_ip())
                if autodetect
                else Network.get_by_network(str(network_or_ip))
            )
            if network:
                data["network"] = str(network.network)
            else:
                raise EntityNotFound(f"Invalid ip or network: {network_or_ip}")

        else:
            raise EntityNotFound(f"Invalid ip or network: {network_or_ip}")

        if network:
            if network.frozen and not force:
                raise ForceMissing(f"Network {network.network} is frozen, must force")
            else:
                net_or_ip = NetworkOrIP.validate(network.network)
    else:
        net_or_ip = None

    host = Host.create(data)
    if not host:
        raise CreateError("Failed to add host.")
    OutputManager().add_ok(f"Created host {host.name}")

    if macaddress is not None and net_or_ip is not None:
        if net_or_ip.is_ip():
            host = host.associate_mac_to_ip(macaddress, network_or_ip, force=force)
        else:
            # We passed a network to create the host, so we need to find the IP
            # that was assigned to the host. We don't get that in the response
            # per se, so we check to see if there is only one IP in the host and
            # use that. If there are more than one, we can't know which one was
            # assigned to the host during create, so we abort.
            if len(host.ipaddresses) == 1:
                host = host.associate_mac_to_ip(
                    macaddress, host.ipaddresses[0].ipaddress, force=force
                )
            else:
                OutputManager().add_ok(
                    "Failed to associate MAC address to IP, multiple IP addresses after creation."
                )

    host.output()


class Override(str, Enum):
    """Override types for forced removal."""

    CNAME = "cname"
    IPADDRESS = "ipaddress"
    MX = "mx"
    SRV = "srv"
    PTR = "ptr"
    NAPTR = "naptr"

    @classmethod
    def values(cls) -> list[str]:
        """Return a list with all available values."""
        return list(cls)

    @classmethod
    def values_str(cls) -> str:
        """Return a string with all available values, comma-separated, single-quoted."""
        return ", ".join([f"'{override.value}'" for override in cls])


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
                f"Accepted overrides: {Override.values_str()}"
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
    hostname = args.name
    host = Host.get_by_any_means_or_raise(hostname, inform_as_cname=True)

    overrides: list[str] = args.override.split(",") if args.override else []

    accepted_overrides = Override.values()
    for override in overrides:
        if override not in accepted_overrides:
            raise InputFailure(
                f"Invalid override: {override}. Accepted overrides: {accepted_overrides}"
            )

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
    overrides_required: set[str] = set()
    # Require force if host has any cnames.
    if host.cnames and not forced(Override.CNAME):
        overrides_required.add(Override.CNAME)
        warnings.append(f"  {len(host.cnames)} cnames")
        for cname in host.cnames:
            warnings.append(f"    - {cname.name}")

    # Require force if host has multiple A/AAAA records and they are not in the same VLAN.
    if len(host.ipaddresses) > 1:
        host_vlans = host.vlans()
        same_vlan = len(host_vlans) == 1

        if same_vlan and not forced():
            warnings.append("  multiple ipaddresses on the same VLAN")
        elif not same_vlan and not forced(Override.IPADDRESS):
            overrides_required.add(Override.IPADDRESS)
            warnings.append("  {} ipaddresses on distinct VLANs".format(len(host.ipaddresses)))
            for vlan_id, vlans in host_vlans.items():
                ip_strings = [str(ip.ipaddress) for ip in vlans]
                ip_strings.sort()
                warnings.append(f"    - {', '.join(ip_strings)} (vlan: {vlan_id})")

    if host.mxs and not forced(Override.MX):
        overrides_required.add(Override.MX)
        warnings.append(f"  {len(host.mxs)} MX records")
        for mx in host.mxs:
            warnings.append(f"    - {mx.mx} (priority: {mx.priority})")

    # Require force if host has any NAPTR records. Delete the NAPTR records if
    # force
    naptrs = host.naptrs
    if len(naptrs) > 0:
        if not forced(Override.NAPTR):
            overrides_required.add(Override.NAPTR)
            warnings.append(f"  {len(naptrs)} NAPTR records")
            for naptr in naptrs:
                warnings.append(f"    - {naptr.replacement}")
        else:
            for naptr in naptrs:
                OutputManager().add_ok(
                    "deleted NAPTR record {} when removing {}".format(
                        naptr.replacement,
                        host.name,
                    )
                )

    # Require force if host has any SRV records. Delete the SRV records if force
    srvs = host.srvs
    if len(srvs) > 0:
        if not forced(Override.SRV):
            overrides_required.add(Override.SRV)
            warnings.append(f"  {len(srvs)} SRV records")
            for srv in srvs:
                warnings.append(f"    - {srv.name}")
        else:
            for srv in srvs:
                OutputManager().add_ok(
                    "deleted SRV record {} when removing {}".format(
                        srv.name,
                        host.name,
                    )
                )

    # Require force if host has any PTR records. Delete the PTR records if force
    if len(host.ptr_overrides) > 0:
        if not forced(Override.PTR):
            overrides_required.add(Override.PTR)
            warnings.append(f"  {len(host.ptr_overrides)} PTR records")
            for ptr in host.ptr_overrides:
                warnings.append(f"    - {ptr.ipaddress}")
        else:
            for ptr in host.ptr_overrides:
                OutputManager().add_ok(
                    "deleted PTR record {} when removing {}".format(
                        ptr.ipaddress,
                        host.name,
                    )
                )

    # Warn user and raise exception if any force requirements was found
    if warnings:
        # Build the force command suggestion
        force_cmd = ["-force"]
        if overrides_required:
            force_cmd.extend(sorted(overrides_required))

        # Add the override command to warnings
        command_suggestion = f"Use `{' '.join(force_cmd)}` to override."
        warnings.append(command_suggestion)

        # Build the error message
        error_msg_parts = [f"{host.name} requires force"]
        if overrides_required:
            error_msg_parts.append("and override")
        error_msg_parts.append("for deletion:")

        # Format the complete error message
        base_msg = " ".join(error_msg_parts)
        warn_msg = "\n".join(warnings)
        complete_error_msg = f"{base_msg}\n{warn_msg}"

        # Raise the exception with the formatted message
        raise ForceMissing(complete_error_msg)

    if host.delete():
        OutputManager().add_ok(f"removed {host.name}")
    else:
        raise DeleteError(f"failed to remove {host.name}")


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
        ),
        Flag(
            "-traverse-hostgroups",
            action="store_true",
            description="Show memberships of all parent groups as well as direct groups.",
            short_desc="Traverse hostgroups.",
        ),
    ],
)
def host_info(args: argparse.Namespace) -> None:
    """Print information about host.

    :param args: argparse.Namespace (hosts, traverse_hostgroups)

    Setting traverse hostgroups will show memberships of all parent groups as well as
    direct groups.
    """
    for host in args.hosts:
        hosts = Host.get_list_by_any_means_or_raise(host, inform_as_cname=True)
        if hosts:
            Host.output_multiple(hosts, traverse_hostgroups=args.traverse_hostgroups)


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
        raise InputFailure("Need at least one search critera")

    params: QueryParams = {
        "ordering": "name",
    }

    for param in ("contact", "comment", "name"):
        value = getattr(args, param)
        if value:
            _add_param(param, value)

    HostList.get(params=params).output()


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

    :return: The updated Host or None
    """
    old_name: str = args.old_name
    new_name: str = args.new_name

    old_host = Host.get_by_any_means_or_raise(old_name)
    new_name = HostName.parse_or_raise(new_name)

    new_host = Host.get_by_any_means(new_name, inform_as_cname=True)
    if new_host:
        raise EntityAlreadyExists(f"host {new_host} already exists")

    # Require force if FQDN not in MREG zone
    zone = ForwardZone.get_from_hostname(new_name)
    if not zone and not args.force:
        raise ForceMissing(f"{new_name} isn't in a zone controlled by MREG, must force")

    if "*" in new_name and not args.force:
        raise ForceMissing("Wildcards must be forced.")

    new_host = old_host.rename(new_name)
    OutputManager().add_ok(f"renamed {old_host} to {new_name}")


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
    host = Host.get_by_any_means_or_raise(args.name, inform_as_cname=True)
    updated_host = host.set_comment(args.comment)

    if not updated_host:
        raise PatchError(f"Failed to update comment of {host.name}")

    OutputManager().add_ok(f"Updated comment of {host} to {args.comment}")


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
    host = Host.get_by_any_means_or_raise(args.name, inform_as_cname=True)
    updated_host = host.set_contact(args.contact)

    if not updated_host:
        raise PatchError(f"Failed to update contact of {host.name}")

    OutputManager().add_ok(f"Updated contact of {host} to {args.contact}")


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
    name: str = args.name

    hostname = HostName.parse_or_raise(name)
    Host.output_history(hostname)
