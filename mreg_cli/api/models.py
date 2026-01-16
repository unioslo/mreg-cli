"""Pydantic models for the mreg_cli package."""

from __future__ import annotations

import ipaddress
import logging
from typing import (
    Any,
    Callable,
    Iterable,
    Literal,
    Self,
    Sequence,
    TypeVar,
    cast,
    overload,
    override,
)

import mreg_api.models
from pydantic import (
    BaseModel,
    computed_field,
    field_validator,
)
from pydantic import ValidationError as PydanticValidationError

from mreg_cli.api.abstracts import (
    TimestampMixin,
    TTLMixin,
)
from mreg_cli.api.endpoints import Endpoint
from mreg_cli.choices import CommunitySortOrder
from mreg_cli.exceptions import (
    EntityNotFound,
    InputFailure,
    InvalidIPAddress,
    InvalidIPv4Address,
    InvalidIPv6Address,
    InvalidNetwork,
)
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import IP_AddressT, IP_NetworkT, IP_Version
from mreg_cli.utilities.api import (
    get,
    get_list_in,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")

IPNetMode = Literal["ipv4", "ipv6", "ip", "network", "networkv4", "networkv6"]


class NetworkOrIP(BaseModel):
    """A model for either a network or an IP address."""

    ip_or_network: IP_AddressT | IP_NetworkT

    @classmethod
    def validate(cls, value: str | IP_AddressT | IP_NetworkT | Self) -> Self:
        """Create a NetworkOrIP model instance from a value.

        This constructor validates and wraps the IP/network in the model.

        :param value:The value to convert (string or IP object)
        :returns: A NetworkOrIP model instance
        :raises InputFailure: If validation fails
        """
        if isinstance(value, NetworkOrIP):
            return cls.validate(value.ip_or_network)
        try:
            return cls(ip_or_network=value)  # pyright: ignore[reportArgumentType] # validator handles this
        except PydanticValidationError as e:
            raise InputFailure(f"Invalid IP address or network: {value}") from e

    @overload
    @classmethod
    def parse_or_raise(cls, value: Any, mode: None = None) -> IP_AddressT | IP_NetworkT: ...

    @overload
    @classmethod
    def parse_or_raise(cls, value: Any, mode: Literal["ip"]) -> IP_AddressT: ...

    @overload
    @classmethod
    def parse_or_raise(cls, value: Any, mode: Literal["ipv4"]) -> ipaddress.IPv4Address: ...

    @overload
    @classmethod
    def parse_or_raise(cls, value: Any, mode: Literal["ipv6"]) -> ipaddress.IPv6Address: ...

    @overload
    @classmethod
    def parse_or_raise(cls, value: Any, mode: Literal["network"]) -> IP_NetworkT: ...

    @overload
    @classmethod
    def parse_or_raise(cls, value: Any, mode: Literal["networkv4"]) -> ipaddress.IPv4Network: ...

    @overload
    @classmethod
    def parse_or_raise(cls, value: Any, mode: Literal["networkv6"]) -> ipaddress.IPv6Network: ...

    @classmethod
    def parse_or_raise(
        cls, value: Any, mode: IPNetMode | None = None
    ) -> IP_AddressT | IP_NetworkT:
        """Parse a value as an IP address or network.

        Optionally specify the mode to validate the input as.

        :param value:The value to parse.
        :param mode: The mode to validate the input as.
        :returns: The parsed value as an IP address or network.
        :raises IPNetworkWarning: If the value is not an IP address or network.
        """
        ipnet = cls.validate(value)
        funcmap: dict[IPNetMode, Callable[..., IP_AddressT | IP_NetworkT]] = {
            "ip": cls.as_ip,
            "ipv4": cls.as_ipv4,
            "ipv6": cls.as_ipv6,
            "network": cls.as_network,
            "networkv4": cls.as_ipv4_network,
            "networkv6": cls.as_ipv6_network,
        }
        if mode and (func := funcmap.get(mode)):
            return func(ipnet)
        return ipnet.ip_or_network

    @overload
    @classmethod
    def parse(cls, value: Any, mode: None = None) -> IP_AddressT | IP_NetworkT | None: ...

    @overload
    @classmethod
    def parse(cls, value: Any, mode: Literal["ip"]) -> IP_AddressT | None: ...

    @overload
    @classmethod
    def parse(cls, value: Any, mode: Literal["ipv4"]) -> ipaddress.IPv4Address | None: ...

    @overload
    @classmethod
    def parse(cls, value: Any, mode: Literal["ipv6"]) -> ipaddress.IPv6Address | None: ...

    @overload
    @classmethod
    def parse(cls, value: Any, mode: Literal["network"]) -> IP_NetworkT | None: ...

    @overload
    @classmethod
    def parse(cls, value: Any, mode: Literal["networkv4"]) -> ipaddress.IPv4Network | None: ...

    @overload
    @classmethod
    def parse(cls, value: Any, mode: Literal["networkv6"]) -> ipaddress.IPv6Network | None: ...

    @classmethod
    def parse(cls, value: Any, mode: IPNetMode | None = None) -> IP_AddressT | IP_NetworkT | None:
        """Parse a value as an IP address or network, or None if parsing fails.

        Optionally specify the mode to validate the input as.

        :param value:The value to parse.
        :param mode: The mode to validate the input as.
        :returns: The parsed value as an IP address or network, or None.
        """
        try:
            return cls.parse_or_raise(value, mode)
        except ValueError:
            return None

    @field_validator("ip_or_network", mode="before")
    @classmethod
    def validate_ip_or_network(cls, value: Any) -> IP_AddressT | IP_NetworkT:
        """Validate and convert the input to an IP address or network."""
        if not isinstance(value, str):
            return value

        value = value.removesuffix("/")

        try:
            return ipaddress.ip_address(value)
        except ValueError:
            pass

        try:
            return ipaddress.ip_network(value)
        except ValueError:
            pass

        raise InputFailure(f"Invalid input for IP address or network: {value}")

    def __str__(self) -> str:
        """Return the value as a string."""
        return str(self.ip_or_network)

    def is_ipv4(self) -> bool:
        """Return True if the value is an IPv4 address."""
        return isinstance(self.ip_or_network, ipaddress.IPv4Address)

    def as_ipv4(self) -> ipaddress.IPv4Address:
        """Return the value as an IPv4 address."""
        if not self.is_ipv4():
            raise InvalidIPv4Address("Value is not an IPv4 address.")
        return cast(ipaddress.IPv4Address, self.ip_or_network)

    def as_ipv6(self) -> ipaddress.IPv6Address:
        """Return the value as an IPv6 address."""
        if not self.is_ipv6():
            raise InvalidIPv6Address("Value is not an IPv6 address.")
        return cast(ipaddress.IPv6Address, self.ip_or_network)

    def as_ip(self) -> IP_AddressT:
        """Return the value as an IP address."""
        if not self.is_ip():
            raise InvalidIPAddress(f"{self.ip_or_network} is not an IP address.")
        return cast(IP_AddressT, self.ip_or_network)

    def as_network(self) -> IP_NetworkT:
        """Return the value as a network."""
        if not self.is_network():
            raise InvalidNetwork(f"{self.ip_or_network} is not a network.")
        return cast(IP_NetworkT, self.ip_or_network)

    def as_ipv4_network(self) -> ipaddress.IPv4Network:
        """Return the value as a network."""
        if not self.is_ipv4_network():
            raise InvalidNetwork(f"{self.ip_or_network} is not an IPv4 network.")
        return cast(ipaddress.IPv4Network, self.ip_or_network)

    def as_ipv6_network(self) -> IP_NetworkT:
        """Return the value as a network."""
        if not self.is_ipv6_network():
            raise InvalidNetwork(f"{self.ip_or_network} is not an IPv6 network.")
        return cast(ipaddress.IPv6Network, self.ip_or_network)

    def is_ipv6(self) -> bool:
        """Return True if the value is an IPv6 address."""
        return isinstance(self.ip_or_network, ipaddress.IPv6Address)

    def is_ipv4_network(self) -> bool:
        """Return True if the value is an IPv4 network."""
        return isinstance(self.ip_or_network, ipaddress.IPv4Network)

    def is_ipv6_network(self) -> bool:
        """Return True if the value is an IPv6 network."""
        return isinstance(self.ip_or_network, ipaddress.IPv6Network)

    def is_ip(self) -> bool:
        """Return True if the value is an IP address."""
        return self.is_ipv4() or self.is_ipv6()

    def is_network(self) -> bool:
        """Return True if the value is a network."""
        return self.is_ipv4_network() or self.is_ipv6_network()


class NameServer(mreg_api.models.NameServer):
    """Model for representing a nameserver within a DNS zone."""

    id: int  # noqa: A003
    name: str


class Permission(mreg_api.models.Permission):
    """Model for a permission object."""

    @classmethod
    def output_multiple(cls, permissions: list[Permission], indent: int = 4) -> None:
        """Print multiple permissions to the console."""
        if not permissions:
            return

        OutputManager().add_formatted_table(
            ("IP range", "Group", "Reg.exp."),
            ("range", "group", "regex"),
            permissions,
            indent=indent,
        )


class Zone(mreg_api.models.Zone, TTLMixin):
    """Model representing a DNS zone with various attributes and related nameservers."""

    nameservers: list[NameServer]

    def output(self, padding: int = 20) -> None:
        """Output the zone to the console."""
        manager = OutputManager()

        def fmt(label: str, text: str) -> None:
            manager.add_line("{1:<{0}}{2}".format(padding, label, text))

        fmt("Name:", self.name)
        self.output_nameservers(self.nameservers)
        fmt("Primary NS:", self.primary_ns)
        fmt("Email:", self.email)
        fmt("Serial:", str(self.serialno))
        fmt("Refresh:", str(self.refresh))
        fmt("Retry:", str(self.retry))
        fmt("Expire:", str(self.expire))
        self.output_ttl("SOA TTL", "soa_ttl", padding)
        self.output_ttl("Default TTL", "default_ttl", padding)

    @classmethod
    @override
    def get_zone(cls, name: str) -> ForwardZone | ReverseZone | None:
        zone = super().get_zone(name)
        if zone is None:
            return zone
        if isinstance(zone, mreg_api.models.ForwardZone):
            return ForwardZone.model_validate(zone, from_attributes=True)
        else:
            return ReverseZone.model_validate(zone, from_attributes=True)

    @classmethod
    @override
    def get_zone_or_raise(cls, name: str) -> ForwardZone | ReverseZone:
        zone = cls.get_zone(name)
        if not zone:
            raise EntityNotFound(f"Zone with name '{name}' not found.")
        return zone

    @classmethod
    def output_zones(cls, forward: bool, reverse: bool) -> None:
        """Output all zones of the given type(s)."""
        # Determine types of zones to list
        zones_types: list[type[ForwardZone | ReverseZone]] = []
        if forward:
            zones_types.append(ForwardZone)
        if reverse:
            zones_types.append(ReverseZone)

        # Fetch all zones of the given type(s)
        zones: list[ForwardZone | ReverseZone] = []
        for zone_type in zones_types:
            zones.extend(zone_type.get_list())

        manager = OutputManager()
        if not zones:
            manager.add_line("No zones found.")
            return
        manager.add_line("Zones:")
        for zone in zones:
            manager.add_line(f" {zone.name}")

    @classmethod
    def output_nameservers(cls, nameservers: list[NameServer], padding: int = 20) -> None:
        """Output the nameservers of the zone."""
        manager = OutputManager()

        def fmt_ns(label: str, hostname: str, ttl: str) -> None:
            manager.add_line(
                "        {1:<{0}}{2:<{3}}{4}".format(padding, label, hostname, 20, ttl)
            )

        fmt_ns("Nameservers:", "hostname", "TTL")
        for ns in nameservers:
            # We don't have a TTL value for nameservers from the API
            fmt_ns("", ns.name, "<not set>")

    def output_delegations(self, padding: int = 20) -> None:
        """Output the delegations of the zone."""
        delegations = self.get_delegations()
        delegations = [Delegation.model_validate(d, from_attributes=True) for d in delegations]

        manager = OutputManager()
        if not delegations:
            manager.add_line(f"No delegations for {self.name}.")
            return
        manager.add_line("Delegations:")
        for delegation in sorted(delegations, key=lambda d: d.name):
            manager.add_line(f"    {delegation.name}")
            if delegation.comment:
                manager.add_line(f"        Comment: {delegation.comment}")
            self.output_nameservers(delegation.nameservers, padding=padding)


class ForwardZone(mreg_api.models.ForwardZone, Zone):
    """A forward zone."""


class ReverseZone(mreg_api.models.ReverseZone, Zone):
    """A reverse zone."""


class Delegation(mreg_api.models.Delegation):
    """A delegated zone."""

    nameservers: list[NameServer]


class ForwardZoneDelegation(Delegation):
    """A forward zone delegation."""


class ReverseZoneDelegation(Delegation):
    """A reverse zone delegation."""


class HostPolicy(mreg_api.models.HostPolicy):
    """Base model for Host Policy objects.

    Note:
    ----
    Host policy models in MREG have a different `created_at` field than
    other models. It is called `create_date` and is a date - not a datetime.

    This model has a custom validator to validate and convert the `create_date`
    field to a datetime object with the expected `created_at` name.

    """

    name: str
    description: str

    def output_timestamps(self, padding: int = 14) -> None:
        """Output the created and updated timestamps to the console."""
        output_manager = OutputManager()
        output_manager.add_line(f"{'Created:':<{padding}}{self.created_at:%c}")
        output_manager.add_line(f"{'Updated:':<{padding}}{self.updated_at:%c}")

    def output(self, padding: int = 14) -> None:
        """Output the host policy object to the console.

        Subclasses should provide their own output method and call this method
        first to output the commmon fields.
        """
        output_manager = OutputManager()
        output_manager.add_line(f"{'Name:':<{padding}}{self.name}")
        self.output_timestamps(padding=padding)
        output_manager.add_line(f"{'Description:':<{padding}}{self.description}")

    @classmethod
    @override
    def get_role_or_atom(cls, name: str) -> Atom | Role | None:
        role_or_atom = super().get_role_or_atom(name)
        if not role_or_atom:
            return role_or_atom
        if isinstance(role_or_atom, mreg_api.models.Role):
            return Role.model_validate(role_or_atom, from_attributes=True)
        else:
            return Atom.model_validate(role_or_atom, from_attributes=True)

    @classmethod
    @override
    def get_role_or_atom_or_raise(cls, name: str) -> Atom | Role:
        role_or_atom = cls.get_role_or_atom(name)
        if not role_or_atom:
            raise EntityNotFound(f"Role or atom with name '{name}' not found.")
        return role_or_atom


class Role(mreg_api.models.Role):
    """Model for a role."""

    def output_timestamps(self, padding: int = 14) -> None:
        """Output the created and updated timestamps to the console."""
        output_manager = OutputManager()
        output_manager.add_line(f"{'Created:':<{padding}}{self.created_at:%c}")
        output_manager.add_line(f"{'Updated:':<{padding}}{self.updated_at:%c}")

    def output(self, padding: int = 14) -> None:
        """Output the role to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        output_manager = OutputManager()
        output_manager.add_line(f"{'Name:':<{padding}}{self.name}")
        self.output_timestamps(padding=padding)
        output_manager.add_line(f"{'Description:':<{padding}}{self.description}")

        output_manager.add_line("Atom members:")
        for atom in self.atoms:
            output_manager.add_formatted_line("", atom, padding)
        labels = self.get_labels()
        output_manager.add_line("Labels:")
        for label in labels:
            output_manager.add_formatted_line("", label.name, padding)

    def output_hosts(self, _padding: int = 14, exclude_roles: list[Role] | None = None) -> None:
        """Output the hosts that use the role.

        :param padding: Number of spaces for left-padding the output.
        :param exclude_roles: List of other roles to exclude hosts with.
        """
        manager = OutputManager()
        hosts = self.hosts

        if exclude_roles:
            # Exclude any hosts that are found in the excluded roles
            excluded_hosts: set[str] = set()
            for host in hosts:
                for role in exclude_roles:
                    if host in role.hosts:
                        excluded_hosts.add(host)
                        break
            hosts = [host for host in hosts if host not in excluded_hosts]

        if hosts:
            manager.add_line("Name:")
            for host in hosts:
                manager.add_line(f" {host}")
        else:
            manager.add_line("No host uses this role")

    def output_atoms(self, _padding: int = 14) -> None:
        """Output the atoms that are members of the role.

        :param padding: Number of spaces for left-padding the output.
        """
        manager = OutputManager()
        if self.atoms:
            manager.add_line("Name:")
            for atom in self.atoms:
                manager.add_line(f" {atom}")
        else:
            manager.add_line("No atom members")

    @classmethod
    def output_multiple(cls, roles: list[Role] | list[str], padding: int = 14) -> None:
        """Output multiple roles to the console.

        :param roles: List of roles to output.
        :param padding: Number of spaces for left-padding the output.
        """
        if not roles:
            return

        rolenames: list[str] = []
        for role in roles:
            if isinstance(role, str):
                rolenames.append(role)
            else:
                rolenames.append(role.name)

        OutputManager().add_line("{1:<{0}}{2}".format(padding, "Roles:", ", ".join(rolenames)))

    @classmethod
    def output_multiple_table(cls, roles: list[Role], _padding: int = 14) -> None:
        """Output multiple roles to the console in a table.

        :param roles: List of roles to output.
        :param padding: Number of spaces for left-padding the output.
        """
        if not roles:
            return

        class RoleTableRow(BaseModel):
            name: str
            description: str
            labels: str

        rows: list[RoleTableRow] = []
        for role in roles:
            labels = role.get_labels()
            row = RoleTableRow(
                name=role.name,
                description=role.description,
                labels=", ".join([label.name for label in labels]),
            )
            rows.append(row)

        keys = list(RoleTableRow.model_fields.keys())
        headers = [h.capitalize() for h in keys]
        OutputManager().add_formatted_table(
            headers=headers,
            keys=keys,
            data=rows,
        )


class Atom(mreg_api.models.Atom):
    """Model for an atom."""

    def output_timestamps(self, padding: int = 14) -> None:
        """Output the created and updated timestamps to the console."""
        output_manager = OutputManager()
        output_manager.add_line(f"{'Created:':<{padding}}{self.created_at:%c}")
        output_manager.add_line(f"{'Updated:':<{padding}}{self.updated_at:%c}")

    def output(self, padding: int = 14) -> None:
        """Output the role to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        output_manager = OutputManager()
        output_manager.add_line(f"{'Name:':<{padding}}{self.name}")
        self.output_timestamps(padding=padding)
        output_manager.add_line(f"{'Description:':<{padding}}{self.description}")

        output_manager.add_line("Roles where this atom is a member:")
        for role in self.roles:
            output_manager.add_formatted_line("", role, padding)

    @classmethod
    def output_multiple(cls, atoms: list[Atom], padding: int = 14) -> None:
        """Output multiple atoms to the console as a single formatted string.

        :param atoms: List of atoms to output.
        :param padding: Number of spaces for left-padding the output.
        """
        if not atoms:
            return

        OutputManager().add_line(
            "{1:<{0}}{2}".format(padding, "Atoms:", ", ".join([atom.name for atom in atoms]))
        )

    @classmethod
    def output_multiple_lines(cls, atoms: list[Atom], padding: int = 20) -> None:
        """Output multiple atoms to the console, one atom per line.

        :param atoms: List of atoms to output.
        :param padding: Number of spaces for left-padding the output.
        """
        manager = OutputManager()
        for atom in atoms:
            manager.add_formatted_line(atom.name, f"{atom.description!r}", padding)


class Label(mreg_api.models.Label):
    """Model for a label."""

    def output(self, padding: int = 14) -> None:
        """Output the label to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        short_padding = 4
        output_manager = OutputManager()
        output_manager.add_line(f"{'Name:':<{padding}}{self.name}")
        output_manager.add_line(f"{'Description:':<{padding}}{self.description}")
        output_manager.add_line("Roles with this label:")

        roles = Role.get_list_by_field("labels", self.id)
        if roles:
            for role in roles:
                output_manager.add_line(f"{'':<{short_padding}}{role.name}")
        else:
            output_manager.add_line(f"{'None':<{short_padding}}")

        permission_list = Permission.get_list_by_field("labels", self.id)

        output_manager.add_line("Permissions with this label:")
        if permission_list:
            Permission.output_multiple(permission_list, indent=4)
        else:
            output_manager.add_line(f"{'None':<{short_padding}}")


class Network(mreg_api.models.Network):
    """Model for a network."""

    def output(self, padding: int = 25) -> None:
        """Output the network to the console."""
        manager = OutputManager()

        def fmt(label: str, value: Any) -> None:
            manager.add_line(f"{label:<{padding}}{value}")

        ipnet = NetworkOrIP.parse_or_raise(self.network, mode="network")
        reserved_ips = self.get_reserved_ips()
        # Remove network address and broadcast address from reserved IPs
        reserved_ips_filtered = [
            ip for ip in reserved_ips if ip not in (ipnet.network_address, ipnet.broadcast_address)
        ]

        community_list: list[str] = []
        for community in self.communities:
            host_count = len(community.hosts)
            global_name = f" ({community.global_name})" if community.global_name else ""
            community_list.append(f"{community.name}{global_name} [{host_count}]")

        fmt("Network:", self.network)
        fmt("Netmask:", ipnet.netmask)
        fmt("Description:", self.description)
        fmt("Category:", self.category)
        fmt("Network policy: ", self.policy.name if self.policy else "")
        fmt("Communities:", ", ".join(sorted(community_list)))
        if self.max_communities is not None:
            fmt("Max communities:", self.max_communities)
        fmt("Location:", self.location)
        fmt("VLAN:", self.vlan)
        fmt("DNS delegated:", str(self.dns_delegated))
        fmt("Frozen:", self.frozen)
        fmt("IP-range:", f"{ipnet.network_address} - {ipnet.broadcast_address}")
        fmt("Reserved host addresses:", self.reserved)
        fmt("", f"{ipnet.network_address} (net)")
        for ip in reserved_ips_filtered:
            fmt("", ip)
        if ipnet.broadcast_address in reserved_ips:
            fmt("", f"{ipnet.broadcast_address} (broadcast)")
        if self.excluded_ranges:
            excluded_ips = 0
            for ex_range in self.excluded_ranges:
                excluded_ips += ex_range.excluded_ips()
            fmt("Excluded ranges:", f"{excluded_ips} ipaddresses")
            self.output_excluded_ranges(padding=padding)
        fmt("Used addresses:", self.get_used_count())
        fmt("Unused addresses:", f"{self.get_unused_count()} (excluding reserved adr.)")

    @classmethod
    def output_multiple(cls, networks: list[Network], padding: int = 25) -> None:
        """Print multiple networks to the console."""
        for i, network in enumerate(networks, start=1):
            network.output(padding=padding)
            if i != len(networks):  # add newline between networks (except last one)
                OutputManager().add_line("")

    def output_unused_addresses(self, padding: int = 25) -> None:
        """Output the unused addresses of the network."""
        unused = self.get_unused_list()

        manager = OutputManager()
        if not unused:
            manager.add_line(f"No free addresses remaining on network {self.network}")
            return

        for ip in unused:
            manager.add_line("{1:<{0}}".format(padding, str(ip)))

    def output_used_addresses(self, padding: int = 46) -> None:
        """Output the used addresses and their corresponding hosts."""
        # Reason for 46 padding:
        # https://stackoverflow.com/questions/166132/maximum-length-of-the-textual-representation-of-an-ipv6-address/166157#comment2055398_166157
        used = self.get_used_host_list()
        ptr_overrides = self.get_ptroverride_host_list()
        ips = set(list(used.keys()) + list(ptr_overrides.keys()))
        ips = sorted(ips, key=ipaddress.ip_address)

        manager = OutputManager()
        if not ips:
            manager.add_line(f"No used addresses on network {self.network}")
            return

        for ip in ips:
            if ip in ptr_overrides:
                manager.add_line(f"{ip:<{padding}}{ptr_overrides[ip]} (PTR override)")
            elif ip in used:
                hosts = used[ip]
                msg = f"{ip:<{padding}}{', '.join(hosts)}"
                if len(hosts) > 1:
                    msg += " (NO ptr override!!)"
                manager.add_line(msg)

    def output_excluded_ranges(self, padding: int = 32) -> None:
        """Output the excluded ranges of the network."""
        manager = OutputManager()
        if not self.excluded_ranges:
            manager.add_line(f"No excluded ranges for network {self.network}")
            return

        # manager.add_line(f"{'Start IP':<{padding}}End IP")
        for exrange in self.excluded_ranges:
            manager.add_line(f" {str(exrange.start_ip):<{padding}} -> {exrange.end_ip}")


class NetworkPolicyAttribute(mreg_api.models.NetworkPolicyAttribute):
    """The definition of a network policy attribute.

    See NetworkPolicyAttr for the representation of attributes in Policies.
    """

    @classmethod
    def output_multiple(cls, attributes: list[Self], padding: int = 20) -> None:
        """Output multiple attributes to the console, one attribute per line.

        :param attributes: List of attributes to output.
        :param padding: Number of spaces for left-padding the output.
        """
        manager = OutputManager()
        for attr in attributes:
            manager.add_formatted_line(attr.name, f"{attr.description!r}", padding)


class Community(mreg_api.models.Community, TimestampMixin):
    """Network community."""

    id: int
    name: str
    description: str
    network: int
    hosts: list[str] = []
    global_name: str | None = None

    @classmethod
    def output_multiple(
        cls,
        communities: list[Self],
        padding: int = 14,
        show_hosts: bool = True,
        sort: CommunitySortOrder = CommunitySortOrder.NAME,
    ) -> None:
        """Output multiple communities to the console."""

        def sort_key(community: Community) -> Any:
            if sort == CommunitySortOrder.NAME:
                return community.name
            elif sort == CommunitySortOrder.GLOBAL_NAME:
                return community.global_name or ""

        communities = sorted(communities, key=sort_key)
        for community in communities:
            community.output(padding=padding, show_hosts=show_hosts)
            OutputManager().add_line("")  # add newline between communities

    def output(self, *, padding: int = 14, show_hosts: bool = True) -> None:
        """Output the community to the console."""
        manager = OutputManager()
        manager.add_line(f"{'Name:':<{padding}}{self.name}")
        manager.add_line(f"{'Description:':<{padding}}{self.description}")
        if self.global_name:
            manager.add_line(f"{'Global name:':<{padding}}{self.global_name}")
        self.output_timestamps()

        if show_hosts and self.hosts:
            manager.add_line("Hosts:")
            for host in self.hosts:
                manager.add_line(f"{'':{padding}}{host}")
        else:
            manager.add_line(f"{'Hosts:':<{padding}}{len(self.hosts)}")


class NetworkPolicy(mreg_api.models.NetworkPolicy, TimestampMixin):
    """Network policy used in a community."""

    @classmethod
    def output_multiple(cls, policies: list[Self]) -> None:
        """Output multiple network policies to the console."""
        for policy in policies:
            policy.output()
            OutputManager().add_line("")  # add newline between policies

    def output(self) -> None:
        """Output the network policy to the console."""
        manager = OutputManager()
        manager.add_line(f"Name: {self.name}")
        if self.description:
            manager.add_line(f"Description: {self.description}")
        if self.community_template_pattern:
            manager.add_line(f"Community template pattern: {self.community_template_pattern}")
        if self.attributes:
            manager.add_line("Attributes:")
            for attribute in self.attributes:
                manager.add_line(f" {attribute.name}: {attribute.value}")

        networks = self.networks()
        if networks:
            manager.add_line("Networks:")
            for network in networks:
                manager.add_line(f" {network.network}")

        self.output_timestamps()


class IPAddress(mreg_api.models.IPAddress):
    """Represents an IP address with associated details."""

    def output(self, len_ip: int, len_names: int, names: bool = False):
        """Output the IP address to the console."""
        ip = self.ipaddress.__str__()
        mac = self.macaddress if self.macaddress else "<not set>"

        name = ""
        if names:
            name = Host.get_by_id(self.host)
            name = name.name if name else "<Not found>"

        OutputManager().add_line(f"{name:<{len_names}}{ip:<{len_ip}}{mac}")

    @classmethod
    def output_multiple(cls, ips: list[IPAddress], padding: int = 14, names: bool = False):
        """Output IP addresses to the console."""
        output_manager = OutputManager()
        len_ip = max(padding, max([len(str(ip.ipaddress)) for ip in ips], default=0) + 2)

        # This seems completely broken, we need to look up all the hosts and get their names.
        # This again requires a fetch_hosts() call that takes a series of identifiers using
        # id__in.
        len_names = (
            padding
            if not names
            else max(padding, max([len(str(ip.host)) for ip in ips], default=0) + 2)
        )

        # Separate and output A and AAAA records
        for record_type, records in (
            ("A_Records", [ip for ip in ips if ip.is_ipv4()]),
            ("AAAA_Records", [ip for ip in ips if ip.is_ipv6()]),
        ):
            if records:
                output_manager.add_line(f"{record_type:<{len_names}}IP{' ' * (len_ip - 2)}MAC")
                for record in records:
                    record.output(len_ip=len_ip, len_names=len_names, names=names)


class HInfo(mreg_api.models.HInfo):
    """Represents a HINFO record."""

    def output(self, padding: int = 14):
        """Output the HINFO record to the console."""
        OutputManager().add_line(
            "{1:<{0}}cpu={2} os={3}".format(padding, "Hinfo:", self.cpu, self.os)
        )


class CNAME(mreg_api.models.CNAME):
    """Represents a CNAME record."""

    def output(self, host: Host | None = None, padding: int = 14) -> None:
        """Output the CNAME record to the console.

        :param host: Host CNAME points to. Attempts to resolve the host if not provided.
        :param padding: Number of spaces for left-padding the output.
        """
        if host:
            hostname = host.name
        elif not host and (actual_host := self.resolve_host()):
            hostname = actual_host.name
        else:
            hostname = "<Not found>"
        OutputManager().add_line(f"{'Cname:':<{padding}}{self.name} -> {hostname}")

    @classmethod
    def output_multiple(
        cls, cnames: list[CNAME], host: Host | None = None, padding: int = 14
    ) -> None:
        """Output multiple CNAME records to the console.

        :param cnames: List of CNAME records to output.
        :param host: Host CNAMEs point to. Attempts to resolve the host if not provided.
        :param padding: Number of spaces for left-padding the output.
        """
        for cname in cnames:
            cname.output(host=host, padding=padding)


class TXT(mreg_api.models.TXT):
    """Represents a TXT record."""

    def output(self, padding: int = 14) -> None:
        """Output the TXT record to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        OutputManager().add_line(f"{'TXT:':<{padding}}{self.txt}")

    @classmethod
    def output_multiple(cls, txts: Sequence[TXT], padding: int = 14) -> None:
        """Output multiple TXT records to the console.

        :param txts: List of TXT records to output.
        :param padding: Number of spaces for left-padding the output.
        """
        for txt in txts:
            txt.output(padding=padding)


class MX(mreg_api.models.MX):
    """Represents a MX record."""

    def output(self, padding: int = 14) -> None:
        """Output the MX record to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        len_pri = len("Priority")
        OutputManager().add_line(
            "{1:<{0}}{2:>{3}} {4}".format(padding, "", self.priority, len_pri, self.mx)
        )

    @classmethod
    def output_multiple(cls, mxs: list[MX], padding: int = 14) -> None:
        """Output MX records to the console."""
        if not mxs:
            return

        OutputManager().add_line("{1:<{0}}{2} {3}".format(padding, "MX:", "Priority", "Server"))
        for mx in sorted(mxs, key=lambda i: i.priority):
            mx.output(padding=padding)


class NAPTR(mreg_api.models.NAPTR):
    """Represents a NAPTR record."""

    def output(self, padding: int = 14) -> None:
        """Output the NAPTR record to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        row_format = f"{{:<{padding}}}" * len(NAPTR.headers())
        OutputManager().add_line(
            row_format.format(
                "",
                self.preference,
                self.order,
                self.flag,
                self.service,
                self.regex or '""',
                self.replacement,
            )
        )

    @classmethod
    def headers(cls) -> list[str]:
        """Return the headers for the NAPTR record."""
        return [
            "NAPTRs:",
            "Preference",
            "Order",
            "Flag",
            "Service",
            "Regex",
            "Replacement",
        ]

    @classmethod
    def output_multiple(cls, naptrs: list[NAPTR], padding: int = 14) -> None:
        """Output multiple NAPTR records to the console."""
        headers = cls.headers()
        row_format = f"{{:<{padding}}}" * len(headers)
        manager = OutputManager()
        if naptrs:
            manager.add_line(row_format.format(*headers))
            for naptr in naptrs:
                naptr.output(padding=padding)


class Srv(mreg_api.models.Srv):
    """Represents a SRV record."""

    def output(self, padding: int = 14, host_id_name_map: dict[int, str] | None = None) -> None:
        """Output the SRV record to the console.

        The output will include the record name, priority, weight, port,
        and the associated host name. Optionally uses a mapping of host IDs
        to host names to avoid repeated lookups.

        :param padding: Number of spaces for left-padding the output.
        :param host_names: Optional dictionary mapping host IDs to host names.
        """
        host_name = "<Not found>"
        if host_id_name_map and self.host in host_id_name_map:
            host_name = host_id_name_map[self.host]
        elif not host_id_name_map or self.host not in host_id_name_map:
            host = self.resolve_host()
            if host:
                host_name = host.name

        # Format the output string to include padding and center alignment
        # for priority, weight, and port.
        output_manager = OutputManager()
        format_str = "SRV: {:<{padding}} {:^6} {:^6} {:^6} {}"
        output_manager.add_line(
            format_str.format(
                self.name,
                str(self.priority),
                str(self.weight),
                str(self.port),
                host_name,
                padding=padding,
            )
        )

    @classmethod
    def output_multiple(cls, srvs: Sequence[Srv], padding: int = 14) -> None:
        """Output multiple SRV records.

        This method adjusts the padding dynamically based on the longest record name.

        :param srvs: List of Srv records to output.
        :param padding: Minimum number of spaces for left-padding the output.
        """
        if not srvs:
            return

        host_ids = {srv.host for srv in srvs}

        host_data = get_list_in(Endpoint.Hosts, "id", list(host_ids))
        hosts = [Host.model_validate(host) for host in host_data]

        host_id_name_map = {host.id: str(host.name) for host in hosts}

        host_id_name_map.update(
            {host_id: host_id_name_map.get(host_id, "<Not found>") for host_id in host_ids}
        )

        padding = max((len(srv.name) for srv in srvs), default=padding)

        # Output each SRV record with the optimized host name lookup
        for srv in srvs:
            srv.output(padding=padding, host_id_name_map=host_id_name_map)

    def __str__(self) -> str:
        """Return a string representation of the SRV record."""
        return self.name


class PTR_override(mreg_api.models.PTR_override):
    """Represents a PTR override record."""

    @classmethod
    def output_multiple(cls, ptrs: list[PTR_override], padding: int = 14):
        """Output multiple PTR override records to the console.

        :param ptrs: List of PTR override records to output.
        :param padding: Number of spaces for left-padding the output.
        """
        if not ptrs:
            return

        for ptr in ptrs:
            ptr.output(padding=padding)

    def output(self, padding: int = 14):
        """Output the PTR override record to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        host = self.resolve_host()
        hostname = host.name if host else "<Not found>"

        OutputManager().add_line(f"{'PTR override:':<{padding}}{self.ipaddress} -> {hostname}")


class SSHFP(mreg_api.models.SSHFP):
    """Represents a SSHFP record."""

    @classmethod
    def output_multiple(cls, sshfps: list[SSHFP], padding: int = 14):
        """Output multiple SSHFP records to the console.

        :param sshfps: List of SSHFP records to output.
        :param padding: Number of spaces for left-padding the output.
        """
        headers = cls.headers()
        row_format = f"{{:<{padding}}}" * len(headers)
        manager = OutputManager()
        if sshfps:
            manager.add_line(row_format.format(*headers))
            for sshfp in sshfps:
                sshfp.output(padding=padding)

    @classmethod
    def headers(cls) -> list[str]:
        """Return the headers for the SSHFP record."""
        return ["SSHFPs:", "Algorithm", "Hash Type", "Fingerprint"]

    def output(self, padding: int = 14):
        """Output the SSHFP record to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        row_format = f"{{:<{padding}}}" * len(SSHFP.headers())
        OutputManager().add_line(
            row_format.format("", self.algorithm, self.hash_type, self.fingerprint)
        )


class BacnetID(mreg_api.models.BacnetID):
    """Represents a Bacnet ID record."""

    @classmethod
    def output_multiple(cls, bacnetids: list[BacnetID]):
        """Output multiple Bacnet ID records to the console.

        :param bacnetids: List of Bacnet ID records to output.
        """
        if not bacnetids:
            return

        OutputManager().add_formatted_table(("ID", "Hostname"), ("id", "hostname"), bacnetids)


class Location(mreg_api.models.Location):
    """Represents a LOC record."""

    def output(self, padding: int = 14):
        """Output the LOC record to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        OutputManager().add_line(f"{'LOC:':<{padding}}{self.loc}")


class HostCommunity(mreg_api.models.HostCommunity):
    """Model for a host's community.

    Communities are associated with hosts via IP addresses.
    """


class Host(mreg_api.models.Host, TimestampMixin, TTLMixin):
    """Model for an individual host."""

    ipaddresses: list[IPAddress]
    cnames: list[CNAME] = []
    mxs: list[MX] = []
    txts: list[TXT] = []
    ptr_overrides: list[PTR_override] = []
    hinfo: HInfo | None = None
    loc: Location | None = None
    srvs: list[Srv] = []
    naptrs: list[NAPTR] = []
    sshfps: list[SSHFP] = []

    @classmethod
    def output_multiple(
        cls, hosts: list[Host], names: bool = False, traverse_hostgroups: bool = False
    ):
        """Output multiple hosts to the console.

        :param hosts: List of Host objects to output.
        :param names: If True, output the host names only.
        :param traverse_hostgroups: If True, traverse the hostgroups and include them in the output.
        """
        for i, host in enumerate(hosts, start=1):
            host.output(names=names, traverse_hostgroups=traverse_hostgroups)
            if i != len(hosts):
                OutputManager().add_line("")

    def output(self, names: bool = False, traverse_hostgroups: bool = False):
        """Output host information to the console with padding."""
        padding = 14

        output_manager = OutputManager()
        output_manager.add_line(f"{'Name:':<{padding}}{self.name}")
        output_manager.add_line(f"{'Contact:':<{padding}}{self.contact}")

        if self.comment:
            output_manager.add_line(f"{'Comment:':<{padding}}{self.comment}")

        self.output_networks()
        PTR_override.output_multiple(self.ptr_overrides, padding=padding)

        self.output_ttl(padding=padding)

        MX.output_multiple(self.mxs, padding=padding)

        if self.hinfo:
            self.hinfo.output(padding=padding)

        if self.loc:
            self.loc.output(padding=padding)

        self.output_cnames(padding=padding)

        TXT.output_multiple(self.txts, padding=padding)
        Srv.output_multiple(self.srvs, padding=padding)
        NAPTR.output_multiple(self.naptrs, padding=padding)
        SSHFP.output_multiple(self.sshfps, padding=padding)

        if self.bacnetid is not None:  # This may be zero.
            output_manager.add_line(f"{'Bacnet ID:':<{padding}}{self.bacnetid}")

        Role.output_multiple(self.roles, padding=padding)
        if traverse_hostgroups:
            hostgroups = self.get_hostgroups(traverse=True)
            hostgroups = [HostGroup.model_validate(hg, from_attributes=True) for hg in hostgroups]
        else:
            hostgroups = self.hostgroups
        HostGroup.output_multiple(hostgroups, padding=padding)

        self.output_timestamps()

    def output_networks(self, padding: int = 14, only: Literal[4, 6, None] = None) -> None:
        """Output all A(AAA) records along with the MAC address and network policy for the host."""
        networks = self.networks()
        if not networks:
            return

        output_manager = OutputManager()

        v4: list[tuple[Network, IPAddress]] = []
        v6: list[tuple[Network, IPAddress]] = []

        for network, ips in networks.items():
            network = Network.model_validate(network, from_attributes=True)
            for ip in ips:
                ip = IPAddress.model_validate(ip, from_attributes=True)
                if network.ip_network.version == 4:
                    v4.append((network, ip))
                elif network.ip_network.version == 6:
                    v6.append((network, ip))

        def output_a_records(networks: list[tuple[Network, IPAddress]], version: int):
            if not networks:
                return
            record_type = "A" if version == 4 else "AAAA"
            output_manager.add_line(f"{record_type}_Records:")
            data: list[dict[str, str]] = []

            headers = ("IP", "MAC")
            keys = ("ip", "mac")

            ip_to_community: dict[IPAddress, Community] = {}
            if self.communities:
                for com in self.communities:
                    ip = self.get_ip_by_id(com.ipaddress)
                    ip = IPAddress.model_validate(ip, from_attributes=True)

                    if ip:
                        ip_to_community[ip] = Community.model_validate(
                            com.community, from_attributes=True
                        )

            if ip_to_community:
                for net, ip in networks:
                    policy = ""
                    if net.policy:
                        policy = net.policy.name
                    d: dict[str, str] = {
                        "ip": str(ip.ipaddress),
                        "mac": ip.macaddress or "<not set>",
                        "policy": policy,
                        "community": "",
                    }
                    if ip in ip_to_community:
                        d["community"] = ip_to_community[ip].name
                        if ip_to_community[ip].global_name:
                            d["community"] += f" ({ip_to_community[ip].global_name})"

                    data.append(d)

                headers = ("IP", "MAC", "Policy", "Community")
                keys = ("ip", "mac", "policy", "community")

            else:
                for _, ip in networks:
                    d: dict[str, str] = {
                        "ip": str(ip.ipaddress),
                        "mac": ip.macaddress or "<not set>",
                    }
                    data.append(d)

            output_manager.add_formatted_table(
                headers=headers,
                keys=keys,
                data=data,
                indent=padding,
            )

        if only is None or only == 4:
            output_a_records(v4, 4)
        if only is None or only == 6:
            output_a_records(v6, 6)

    def output_ipaddresses(
        self, padding: int = 14, names: bool = False, only: IP_Version | None = None
    ):
        """Output the IP addresses for the host."""
        if not self.ipaddresses:
            return

        if only and only == 4:
            ips = [ip for ip in self.ipaddresses if ip.is_ipv4()]
            IPAddress.output_multiple(ips, padding=padding, names=names)
        elif only and only == 6:
            ips = [ip for ip in self.ipaddresses if ip.is_ipv6()]
            IPAddress.output_multiple(ips, padding=padding, names=names)
        else:
            IPAddress.output_multiple(self.ipaddresses, padding=padding, names=names)

    def output_cnames(self, padding: int = 14):
        """Output the CNAME records for the host."""
        if not self.cnames:
            return
        CNAME.output_multiple(self.cnames, host=self, padding=padding)

    def output_roles(self, _padding: int = 14) -> None:
        """Output the roles for the host."""
        roles = self.roles
        manager = OutputManager()
        if not roles:
            manager.add_line(f"Host {self.name} has no roles")
        else:
            manager.add_line(f"Roles for {self.name}:")
            for role in roles:
                manager.add_line(f"  {role}")

    def __str__(self) -> str:
        """Return the host name as a string."""
        return self.name

    def __hash__(self):
        """Return a hash of the host."""
        return hash((self.id, self.name))


class HostList(mreg_api.models.HostList):
    """Model for a list of hosts.

    This is the endpoint at /api/v1/hosts/.
    """

    def output(self):
        """Output a list of hosts to the console."""
        if not self.results:
            raise EntityNotFound("No hosts found.")

        max_name = max_contact = 20
        for i in self.results:
            max_name = max(max_name, len(str(i.name)))
            max_contact = max(max_contact, max((len(c) for c in i.contact_emails), default=0))

        def _format(name: str, contact: str, comment: str) -> None:
            OutputManager().add_line(
                "{0:<{1}} {2:<{3}} {4}".format(name, max_name, contact, max_contact, comment)
            )

        _format("Name", "Contact", "Comment")
        for i in self.results:
            _format(str(i.name), ", ".join(i.contact_emails), i.comment)


class HostGroup(mreg_api.models.HostGroup, TimestampMixin):
    """Model for a hostgroup."""

    @classmethod
    def output_multiple(
        cls, hostgroups: list[HostGroup] | list[str], padding: int = 14, multiline: bool = False
    ) -> None:
        """Output multiple hostgroups to the console.

        :param hostgroups: List of HostGroup records to output.
        :param multiline: If True, output each group on a new line.
        :param padding: Number of spaces for left-padding the output.
        """
        manager = OutputManager()
        if not hostgroups:
            return

        groups: list[str] = []
        for hg in hostgroups:
            if isinstance(hg, str):
                groups.append(hg)
            else:
                groups.append(hg.name)

        if multiline:
            manager.add_line("Groups:")
            for group in groups:
                manager.add_line(f"  {group}")
        else:
            manager.add_line("{1:<{0}}{2}".format(padding, "Groups:", ", ".join(sorted(groups))))

    def output(self, padding: int = 14) -> None:
        """Output the hostgroup to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        outputmanager = OutputManager()

        parents = self.parent
        inherited: list[str] = []

        for p in self.get_all_parents():
            if p.name not in parents:
                inherited.append(p.name)

        parentlist = ", ".join(parents)
        if inherited:
            parentlist += f" (Inherits: {', '.join(inherited)})"

        output_tuples = (
            ("Name:", self.name),
            ("Description:", self.description or ""),
            ("Owners:", ", ".join(self.owners if self.owners else [])),
            ("Parents:", parentlist),
            ("Groups:", ", ".join(self.groups if self.groups else [])),
            ("Hosts:", len(self.hosts)),
        )
        for key, value in output_tuples:
            outputmanager.add_line(f"{key:<{padding}}{value}")

        self.output_timestamps()

    def output_members(self, expand: bool = False) -> None:
        """Output the members of the hostgroup to the console.

        :param expand: If True, expand the members to include all hosts in all parent groups.
        """
        if expand:
            self._output_members_expanded()
        else:
            self._output_members()

    def _output_members(self) -> None:
        """Output the members of the hostgroup to the console, not expanded."""
        manager = OutputManager()
        manager.add_formatted_line("Type", "Name")

        for group in self.groups:
            manager.add_formatted_line("group", group)

        for host in self.hosts:
            manager.add_formatted_line("host", host)

    def _output_members_expanded(self):
        """Output the members of the hostgroup to the console, expanded."""
        manager = OutputManager()
        manager.add_formatted_line_with_source("Type", "Name", "Source")

        for parent in self.get_all_parents():
            for host in parent.hosts:
                manager.add_formatted_line_with_source("host", host, parent.name)

        for host in self.hosts:
            manager.add_formatted_line_with_source("host", host, self.name)


### Meta models


class UserDjangoStatus(BaseModel):
    """Model for Django status in the user response."""

    superuser: bool
    staff: bool
    active: bool


class UserMregStatus(mreg_api.models.UserMregStatus):
    """Model for Mreg status in the user response."""


class UserPermission(mreg_api.models.UserPermission):
    """Model for permissions in the user response."""

    group: str
    range: str
    regex: str
    labels: list[str]

    # NOTE: _needs_ to be a computed field in order to use it in
    # OutputManager.add_formatted_table, since we dump the model to a dict
    # inside that method.
    @computed_field
    @property
    def labels_str(self) -> str:
        """Return the labels as a string."""
        return ", ".join(self.labels)

    @classmethod
    def output_multiple(cls, permissions: Iterable[Self]) -> None:
        """Output multiple permissions to the console.

        :param permissions: List of UserPermission records to output.
        """
        # NOTE: this is more or less identical to `Permission.output_multiple()`
        # with the addition of printing labels.
        # Since UserPermission is a different model from Permission, sharing a
        # common method is difficult to make type safe without declaring some sort
        # of protocol class, which seems a bit overkill.
        manager = OutputManager()
        manager.add_line("Permissions:")
        if not permissions:
            manager.add_line("  None")
            return

        OutputManager().add_formatted_table(
            ("IP range", "Group", "Reg.exp.", "Labels"),
            ("range", "group", "regex", "labels_str"),
            permissions,
            indent=2,
        )


class ServerVersion(mreg_api.models.ServerVersion):
    """Model for server version metadata."""

    def output(self) -> None:
        """Output the server version to the console."""
        manager = OutputManager()
        manager.add_line(f"mreg-server: {self.version}")


class Library(BaseModel):
    """Model for library metadata."""

    name: str
    version: str


class ServerLibraries(BaseModel):
    """Model for server libraries metadata."""

    libraries: list[Library]

    @classmethod
    def endpoint(cls) -> str:
        """Return the endpoint for the class."""
        return Endpoint.MetaLibraries

    @classmethod
    def fetch(cls, *, ignore_errors: bool = True) -> ServerLibraries:
        """Fetch the server libraries from the endpoint.

        :param ignore_errors: Whether to ignore errors.
        :raises ValidationError: If the response data is invalid and ignore_errors is False.
        :raises requests.RequestException: If the HTTP request fails and ignore_errors is False.
        :returns: An instance of ServerLibraries with the fetched data.
        """
        try:
            response = get(cls.endpoint())
            libraries: list[Library] = []

            for name, version in response.json().items():
                libraries.append(Library(name=name, version=version))
            return cls(libraries=libraries)
        except Exception as e:
            if ignore_errors:
                return cls(libraries=[])
            raise e

    def output(self, indent: int = 4) -> None:
        """Output the server libraries to the console."""
        manager = OutputManager()
        if not self.libraries:
            return

        manager.add_line("Libraries:")
        for lib in self.libraries:
            manager.add_line(f"{' ' * indent}{lib.name}: {lib.version}")


class TokenInfo(BaseModel):
    """Model for token information."""

    is_valid: bool
    created: str
    expire: str
    last_used: str | None = None
    lifespan: str


class UserInfo(mreg_api.models.UserInfo):
    """Model for the user information."""

    permissions: list[UserPermission] = []

    def output(self, django: bool = False) -> None:
        """Output the user information to the console."""
        outputmanager = OutputManager()
        outputmanager.add_line(f"Username: {self.username}")
        outputmanager.add_line(f"Last login: {self.last_login or 'Never'}")

        if self.token:
            outputmanager.add_line("Token:")
            outputmanager.add_line(f"  Valid: {self.token.is_valid}")
            outputmanager.add_line(f"  Created: {self.token.created}")
            outputmanager.add_line(f"  Expires: {self.token.expire}")
            outputmanager.add_line(f"  Last used: {self.token.last_used or 'Never'}")
            outputmanager.add_line(f"  Lifespan: {self.token.lifespan}")
        else:
            outputmanager.add_line("Token: None")

        if django:
            outputmanager.add_line("Django roles:")
            outputmanager.add_line(f"  Superuser: {self.django_status.superuser}")
            outputmanager.add_line(f"  Staff: {self.django_status.staff}")
            outputmanager.add_line(f"  Active: {self.django_status.active}")

        outputmanager.add_line("Mreg roles:")
        outputmanager.add_line(f"  Superuser: {self.mreg_status.superuser}")
        outputmanager.add_line(f"  Admin: {self.mreg_status.admin}")
        outputmanager.add_line(f"  Group admin: {self.mreg_status.group_admin}")
        outputmanager.add_line(f"  Network admin: {self.mreg_status.network_admin}")
        outputmanager.add_line(f"  Hostpolicy admin: {self.mreg_status.hostpolicy_admin}")
        outputmanager.add_line(f"  DNS wildcard admin: {self.mreg_status.dns_wildcard_admin}")
        outputmanager.add_line(f"  Underscore admin: {self.mreg_status.underscore_admin}")

        outputmanager.add_line("Groups:")
        for group in self.groups:
            outputmanager.add_line(f"  {group}")

        UserPermission.output_multiple(self.permissions)


class HealthInfo(mreg_api.models.HealthInfo):
    """Combined information from all health endpoints."""

    def output(self) -> None:
        """Output the health information to the console."""
        manager = OutputManager()
        manager.add_line("Health Information:")
        manager.add_line(f"  Uptime: {self.heartbeat.as_str()}")
        manager.add_line(f"  LDAP: {self.ldap.status}")
