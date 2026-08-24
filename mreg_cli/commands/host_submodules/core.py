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
from typing import Any, Generic, NamedTuple, Self, TypeVar

from mreg_api.models import (
    CNAME,
    MX,
    NAPTR,
    Host,
    NetworkOrIP,
    PTR_override,
    Srv,
)
from mreg_api.models.fields import HostName, MacAddress
from typing_extensions import NotRequired, TypedDict, override

from mreg_cli.client import get_client
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
from mreg_cli.output import output_host, output_hostlist, output_hosts
from mreg_cli.output.history import output_host_history
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag, QueryParams
from mreg_cli.utilities.resolution import resolve_host
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
        Flag("-comment", short_desc="A comment.", description="A comment."),
        Flag("-macaddress", description="Mac address", metavar="MACADDRESS"),
        Flag(
            "-contact",
            short_desc="Contact mail(s) for the host",
            description="Contact mail(s) for the host",
            action="append",
            metavar="CONTACT",
        ),
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
    client = get_client()

    hname = client.fqdn(args.name)
    network_or_ip: str = args.ip
    macaddress: str | None = args.macaddress
    force: bool = args.force
    contact: list[str] = args.contact or []
    comment: str | None = args.comment

    if macaddress is not None:
        macaddress = MacAddress.parse_or_raise(macaddress)
        if not force:
            existing_ips = client.ipaddress.list_by_mac(macaddress)
            if len(existing_ips) == 1:
                raise EntityAlreadyExists(
                    f"MAC address {macaddress} is already associated with IP address "
                    f"{existing_ips[0].ipaddress}, must force."
                )
            elif len(existing_ips) > 1:
                ips_str = ", ".join(str(ip.ipaddress) for ip in existing_ips)
                raise EntityAlreadyExists(
                    f"MAC address {macaddress} is already associated with multiple IP addresses: "
                    f"{ips_str}, must force."
                )

    host = resolve_host(client, hname, required=False)
    if host:
        if host.name != hname:
            raise EntityOwnershipMismatch(f"{hname} is a CNAME pointing to {host.name}")
        else:
            raise EntityAlreadyExists(f"Host {hname} already exists.")

    zone = client.zone.get_from_host(hname)
    if not zone and not force:
        raise ForceMissing(f"{hname} isn't in a zone controlled by MREG, must force")
    if zone and zone.is_delegated() and not force:
        raise ForceMissing(f"{hname} is in zone delegation {zone.name}, must force")

    if "*" in hname and not force:
        raise ForceMissing("Wildcards must be forced.")

    data = _host_create_payload(hname, contact, comment)

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
                network = client.network.get_by_ip(str(ipaddr))
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
                client.network.get_by_ip(str(net_or_ip.as_ip()))
                if autodetect
                else client.network.get(str(network_or_ip))
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

    host = client.host.create(
        name=data["name"],
        comment=data["comment"],
        contacts=data.get("contacts"),
        ipaddress=data.get("ipaddress"),
        network=data.get("network"),
    )
    OutputManager().add_ok(f"Created host {host.name}")

    if macaddress is not None and net_or_ip is not None:
        if net_or_ip.is_ip():
            ip_objs = client.ipaddress.list_by_ip(str(network_or_ip))
            if ip_objs:
                host_ip = ip_objs[0]
                client.ipaddress.associate_mac(host_ip, macaddress, force=force)
                host = resolve_host(client, str(host.name))
        else:
            # We passed a network to create the host, so we need to find the IP
            # that was assigned to the host. We don't get that in the response
            # per se, so we check to see if there is only one IP in the host and
            # use that. If there are more than one, we can't know which one was
            # assigned to the host during create, so we abort.
            if len(host.ipaddresses) == 1:
                host_ip = host.ipaddresses[0]
                client.ipaddress.associate_mac(host_ip, macaddress, force=force)
                host = resolve_host(client, str(host.name))
            else:
                OutputManager().add_ok(
                    "Failed to associate MAC address to IP, multiple IP addresses after creation."
                )

    output_host(host)


class HostCreatePayload(TypedDict):
    """Payload for creating a host."""

    name: HostName
    comment: str  # TODO: mark NotRequired after API parity!
    contacts: NotRequired[list[str]]
    ipaddress: NotRequired[str]
    network: NotRequired[str]


def _host_create_payload(
    hname: HostName, contact: list[str], comment: str | None
) -> HostCreatePayload:
    """Build the API payload for creating a host."""
    # Note: The JSON test results relies on the order of these keys to produce consistent diffs.
    data: HostCreatePayload = {
        "name": hname,
        "comment": comment or "",
    }
    if contact:
        data["contacts"] = contact

    return data


class Override(str, Enum):
    """Override types for forced host removal."""

    CNAME = "cname"
    IPADDRESS = "ipaddress"
    MX = "mx"
    SRV = "srv"
    PTR = "ptr"
    NAPTR = "naptr"

    @classmethod
    @override
    def _missing_(cls, value: object) -> Self | None:
        if isinstance(value, str):
            val = value.lower().strip()
            if val in cls.values():
                return cls(val)
        return None

    @classmethod
    def from_string(cls, s: str) -> Override:
        """Return the Override enum member matching the given string.

        :param s: The string representation of the override.
        :returns: The corresponding Override enum member.
        :raises ValueError: If the string does not match any Override member.
        """
        try:
            return cls(s)
        except ValueError as e:
            raise InputFailure(
                f"Invalid override: {s}. Accepted overrides: {cls.values_str()}"
            ) from e

    @classmethod
    def values(cls) -> list[str]:
        """Return a list of all available values."""
        return [override.value for override in cls]

    @classmethod
    def values_str(cls) -> str:
        """Return a string with all available values, comma-separated, single-quoted.

        Used in help and error messages.
        """
        return ", ".join([f"'{val}'" for val in cls.values()])

    @classmethod
    def parse_overrides(cls, overrides: str) -> list[Override]:
        """Split a comma-separated string of overrides into a list of strings.

        :param overrides: Comma-separated string of overrides.
        :returns: List of override strings.
        """
        return [
            cls.from_string(override.strip())
            for override in overrides.split(",")
            if override.strip()
        ]


def get_record_identifier(record: CNAME | MX | NAPTR | PTR_override | Srv) -> str:
    """Get a human readable identifier for a record.

    :param record: The record to get the identifier for.
    :returns: A human readable identifier for the record.
    """
    match record:
        case CNAME() | Srv():
            return record.name
        case PTR_override():
            return str(record.ipaddress)
        case NAPTR():
            return record.replacement
        case MX():
            return f"{record.mx} (priority: {record.priority})"
        case _:
            return repr(record)  # pyright: ignore[reportUnreachable] # for safety


T = TypeVar("T")


class OverrideRequired(NamedTuple, Generic[T]):
    """Check for overrides required for a specific host record type."""

    override: Override
    name: str
    items: list[T]


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
                "Confirm force deletion of dependent records. "
                "Overrides signify requestor is aware of the dependent records and "
                "understands that they will be deleted alongside the host. "
                f"Accepted overrides: {Override.values_str()}. "
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
    client = get_client()

    hostname = args.name
    host = resolve_host(client, hostname, inform_if_cname=True)

    override_arg = args.override or ""
    overrides: list[Override] = Override.parse_overrides(override_arg)

    def forced(override_required: Override | None = None) -> bool:
        # If we require an override, check if it's in the list of provided overrides.
        if override_required:
            return override_required in overrides

        # We didn't require an override, so we only need to check for force.
        if args.force:
            return True

        # And the fallback is "no".
        return False

    override_checks: list[OverrideRequired[Any]] = [
        OverrideRequired(Override.CNAME, "CNAME", host.cnames),
        OverrideRequired(Override.MX, "MX", host.mxs),
        OverrideRequired(Override.SRV, "SRV", host.srvs),
        OverrideRequired(Override.PTR, "PTR", host.ptr_overrides),
        OverrideRequired(Override.NAPTR, "NAPTR", host.naptrs),
    ]

    # Determine required overrides and build warning message
    # if force and override requirements are not met
    warnings: list[str] = []
    overrides_required: set[Override] = set()
    for check in override_checks:
        if check.items and not forced(check.override):
            overrides_required.add(check.override)
            warnings.append(f"  {len(check.items)} {check.name} records")
            for item in check.items:
                value = get_record_identifier(item)
                warnings.append(f"    - {value}")

    # Require force if host has multiple A/AAAA records and they are not in the same VLAN.
    if len(host.ipaddresses) > 1:
        host_vlans = client.host.vlans(host)
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

    # Warn user and raise exception if any force requirements was found
    if warnings:
        # Build the override command suggestion
        flags = ["-force"]
        if overrides_required:
            flags.append("-override")
            flags.append(",".join(sorted(overrides_required)))

        # Add the override command to warnings
        command_suggestion = f"Use `{' '.join(flags)}` to override."
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

    # Delete the host and any associated records
    client.host.delete(host)

    # Print messages for associated records that were deleted
    for check in override_checks:
        for item in check.items:
            OutputManager().add_ok(
                (
                    f"deleted {check.name} record "
                    f"{get_record_identifier(item)} when removing {host.name}"
                )
            )
    OutputManager().add_ok(f"removed {host.name}")


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
    client = get_client()

    for host_arg in args.hosts:
        # Try IP lookup first (may return multiple hosts)
        hosts: list[Host] = []
        try:
            hosts = client.host.list_by_ip(host_arg)
        except Exception:
            pass

        # Try MAC lookup if IP lookup returned nothing
        if not hosts:
            try:
                hosts = client.host.list_by_mac(host_arg)
            except Exception:
                pass

        # Fall back to single host resolution by name/CNAME
        if not hosts:
            host = resolve_host(client, host_arg, inform_if_cname=True)
            hosts = [host]

        if hosts:
            output_hosts(hosts, traverse_hostgroups=args.traverse_hostgroups)


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
    """List hosts matching search criteria.

    :param args: argparse.Namespace (name, comment, contact)
    """
    client = get_client()

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

    hosts = client.host.list(limit=500, **params)
    output_hostlist(hosts)


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
    client = get_client()

    old_name: str = args.old_name
    new_name: str = args.new_name

    old_host = resolve_host(client, old_name)
    new_name = client.fqdn(new_name)

    new_host = resolve_host(client, new_name, required=False, inform_if_cname=True)
    if new_host:
        raise EntityAlreadyExists(f"host {new_host} already exists")

    # Require force if FQDN not in MREG zone
    zone = client.zone.get_from_host(new_name)
    if not zone and not args.force:
        raise ForceMissing(f"{new_name} isn't in a zone controlled by MREG, must force")

    if "*" in new_name and not args.force:
        raise ForceMissing("Wildcards must be forced.")

    client.host.update(old_host, name=new_name)
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
    client = get_client()

    host = resolve_host(client, args.name, inform_if_cname=True)
    client.host.update(host, comment=args.comment)

    OutputManager().add_ok(f"Updated comment of {host} to {args.comment}")


@command_registry.register_command(
    prog="set_contact",
    description=(
        "Set contact emails for host. Replaces existing contacts. "
        "If <name> is an alias the cname host is updated."
    ),
    short_desc="Set contact.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
        Flag("contact", description="Mail address of the contact.", nargs="+", metavar="CONTACT"),
    ],
)
def set_contact(args: argparse.Namespace) -> None:
    """Set contact for host. If <name> is an alias the cname host is updated.

    :param args: argparse.Namespace (name, contact)
    """
    client = get_client()

    name: str = args.name
    contact: list[str] = args.contact

    host = resolve_host(client, name, inform_if_cname=True)
    client.host.update(host, contacts=contact)

    OutputManager().add_ok(f"Set contact of {host} to {', '.join(contact)}")


@command_registry.register_command(
    prog="unset_contact",
    description=(
        "Remove all contact emails for host. If <name> is an alias the cname host is updated."
    ),
    short_desc="Unset contact.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def unset_contact(args: argparse.Namespace) -> None:
    """Set contact for host. If <name> is an alias the cname host is updated.

    :param args: argparse.Namespace (name, contact)
    """
    client = get_client()

    name: str = args.name
    force: bool = args.force

    host = resolve_host(client, name, inform_if_cname=True)
    if not host.contacts:
        raise DeleteError(f"Host {host.name} has no contacts to remove.")

    if len(host.contacts) > 1 and not force:
        raise ForceMissing(
            f"Host {host.name} has multiple contacts, must use -force to remove all contacts."
        )

    updated = client.host.clear_contacts(host)
    if not updated.removed:
        raise PatchError(f"Failed to update contact of {host.name}")

    OutputManager().add_ok(f"Removed contact from {host}: {', '.join(updated.removed)}")


@command_registry.register_command(
    prog="add_contact",
    description="Add contact email for host. If <name> is an alias the cname host is updated.",
    short_desc="Add contact.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
        Flag("contact", description="Mail address of the contact.", nargs="+", metavar="CONTACT"),
    ],
)
def add_contact(args: argparse.Namespace) -> None:
    """Add contact for host. If <name> is an alias the cname host is updated.

    :param args: argparse.Namespace (name, contact)
    """
    client = get_client()

    name: str = args.name
    contact: list[str] = args.contact

    host = resolve_host(client, name, inform_if_cname=True)
    updated = client.host.add_contacts(host, contact)

    if not updated.added:
        # TODO: add not_found warning?
        raise PatchError(f"Host already has the given contacts: {', '.join(contact)}")

    OutputManager().add_ok(f"Updated contact of {host} to {', '.join(contact)}")


@command_registry.register_command(
    prog="remove_contact",
    description="Remove contact email for host. If <name> is an alias the cname host is updated.",
    short_desc="Remove contact.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
        Flag("contact", description="Mail address of the contact.", nargs="+", metavar="CONTACT"),
    ],
)
def remove_contact(args: argparse.Namespace) -> None:
    """Remove contact for host. If <name> is an alias the cname host is updated.

    :param args: argparse.Namespace (name, contact)
    """
    client = get_client()

    name: str = args.name
    contact: list[str] = args.contact

    if not contact:
        raise InputFailure("At least one contact must be specified.")

    host = resolve_host(client, name, inform_if_cname=True)

    updated = client.host.remove_contacts(host, contact)
    if not updated.removed:
        if updated.not_found:
            not_found = ", ".join(updated.not_found)
            raise PatchError(f"Host does not have the given contacts: {not_found}")
        raise PatchError(f"Failed to remove contacts from {host.name}")

    OutputManager().add_ok(f"Removed contact {', '.join(updated.removed)} from {host}")


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

    client = get_client()
    hostname = client.fqdn(name)
    output_host_history(hostname)
