"""Pydantic models for the mreg_cli package."""

from __future__ import annotations

import ipaddress
import re
from datetime import date, datetime
from typing import Any, cast

from pydantic import (
    AliasChoices,
    BaseModel,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

from mreg_cli.api.abstracts import APIMixin, FrozenModel, FrozenModelWithTimestamps
from mreg_cli.api.endpoints import Endpoint
from mreg_cli.api.fields import IPAddressField, MACAddressField, NameList
from mreg_cli.config import MregCliConfig
from mreg_cli.exceptions import CliWarning
from mreg_cli.log import cli_error, cli_warning
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import IP_AddressT, IP_NetworkT, IP_Version
from mreg_cli.utilities.api import (
    delete,
    get,
    get_item_by_key_value,
    get_list,
    get_list_in,
    get_list_unique,
)

_mac_regex = re.compile(r"^([0-9A-Fa-f]{2}[.:-]){5}([0-9A-Fa-f]{2})$")


class NetworkOrIP(BaseModel):
    """A model for either a network or an IP address."""

    ip_or_network: str | IP_AddressT | IP_NetworkT

    @field_validator("ip_or_network", mode="before")
    @classmethod
    def validate_ip_or_network(cls, value: str) -> IP_AddressT | IP_NetworkT:
        """Validate and convert the input to an IP address or network."""
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            pass

        try:
            return ipaddress.ip_network(value)
        except ValueError:
            pass

        cli_warning(f"Invalid input for IP address or network: {value}")

    def __str__(self) -> str:
        """Return the value as a string."""
        return str(self.ip_or_network)

    def is_ipv4(self) -> bool:
        """Return True if the value is an IPv4 address."""
        return isinstance(self.ip_or_network, ipaddress.IPv4Address)

    def as_ipv4(self) -> ipaddress.IPv4Address:
        """Return the value as an IPv4 address."""
        if not self.is_ipv4():
            raise ValueError("Value is not an IPv4 address.")
        return cast(ipaddress.IPv4Address, self.ip_or_network)

    def as_ipv6(self) -> ipaddress.IPv6Address:
        """Return the value as an IPv6 address."""
        if not self.is_ipv6():
            raise ValueError("Value is not an IPv6 address.")
        return cast(ipaddress.IPv6Address, self.ip_or_network)

    def as_ip(self) -> IP_AddressT:
        """Return the value as an IP address."""
        return cast(IP_AddressT, self.ip_or_network)

    def as_network(self) -> IP_NetworkT:
        """Return the value as a network."""
        return cast(IP_NetworkT, self.ip_or_network)

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


class HostT(BaseModel):
    """A type for a hostname."""

    hostname: str

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, value: str) -> str:
        """Validate the hostname."""
        value = value.lower()

        if re.search(r"^(\*\.)?([a-z0-9_][a-z0-9\-]*\.?)+$", value) is None:
            cli_warning(f"Invalid input for hostname: {value}")

        # Assume user is happy with domain, but strip the dot.
        if value.endswith("."):
            return value[:-1]

        # If a dot in name, assume long name.
        if "." in value:
            return value

        config = MregCliConfig()
        default_domain = config.get("domain")
        # Append domain name if in config and it does not end with it
        if default_domain and not value.endswith(default_domain):
            return f"{value}.{default_domain}"
        return value

    def __str__(self) -> str:
        """Return the hostname as a string."""
        return self.hostname

    def __repr__(self) -> str:
        """Return the hostname as a string."""
        return self.hostname


class WithHost(BaseModel):
    """Model for an object that has a host element."""

    host: int

    def resolve_host(self) -> Host | None:
        """Resolve the host ID to a Host object.

        Notes
        -----
            - This method will call the API to resolve the host ID to a Host object.
            - This assumes that there is a host attribute in the object.

        """
        data = get_item_by_key_value(Endpoint.Hosts, "id", str(self.host))

        if not data:
            return None

        return Host(**data)


class WithZone(BaseModel):
    """Model for an object that has a zone element."""

    zone: int

    def resolve_zone(self) -> Zone | None:
        """Resolve the zone ID to a (Forward)Zone object.

        Notes
        -----
            - This method will call the API to resolve the zone ID to a Zone object.
            - This assumes that there is a zone attribute in the object.

        """
        data = get_item_by_key_value(Endpoint.ForwardZones, "id", str(self.zone))

        if not data:
            return None

        return Zone(**data)


class NameServer(FrozenModelWithTimestamps):
    """Model for representing a nameserver within a DNS zone."""

    id: int  # noqa: A003
    name: str
    ttl: int | None = None


class Zone(FrozenModelWithTimestamps):
    """Model representing a DNS zone with various attributes and related nameservers."""

    id: int  # noqa: A003
    nameservers: list[NameServer]
    updated: bool
    primary_ns: str
    email: str
    serialno: int
    serialno_updated_at: datetime
    refresh: int
    retry: int
    expire: int
    soa_ttl: int
    default_ttl: int
    name: str

    def is_delegated(self) -> bool:
        """Return True if the zone is delegated."""
        return False


class ForwardZone(Zone, APIMixin["ForwardZone"]):
    """A forward zone."""

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.ForwardZones

    @classmethod
    def get_from_hostname(cls, hostname: HostT) -> Delegation | Zone | None:
        """Get the zone from a hostname.

        Note: This method may return either a Delegation or a Zone object.

        :param hostname: The hostname to search for.
        :returns: The zone if found, None otherwise.
        """
        data = get(Endpoint.ForwardZoneForHost.with_id(hostname.hostname), ok404=True)
        if not data:
            return None

        zoneblob = data.json()

        if "delegate" in zoneblob:
            return Delegation(**zoneblob)

        if "zone" in zoneblob:
            return ForwardZone(**zoneblob["zone"])

        cli_warning(f"Unexpected response from server: {zoneblob}")


class Delegation(FrozenModelWithTimestamps, WithZone):
    """A delegated zone."""

    id: int  # noqa: A003
    nameservers: list[NameServer]
    name: str
    comment: str | None = None

    def is_delegated(self) -> bool:
        """Return True if the zone is delegated."""
        return True


class HostPolicy(FrozenModel):
    """Base model for Host Policy objects.

    Note:
    ----
    Host policy models in MREG have a different `created_at` field than
    other models. It is called `create_date` and is a date - not a datetime.

    This model has a custom validator to validate and convert the `create_date`
    field to a datetime object with the expected `created_at` name.

    """

    created_at_tz_naive: datetime = Field(
        ...,
        validation_alias=AliasChoices("create_date", "created_at", "created_at_tz_naive"),
        exclude=True,
        repr=False,
    )
    """Constructed datetime field from `create_date` in the API.

    WARNING
    ----
    DO NOT USE THIS FIELD FOR TIMEZONE-AWARE COMPARISONS!
    Always use `created_at` instead when comparing with timezone-aware
    fields such as `update_time`."""
    updated_at: datetime
    name: str
    description: str

    @field_validator("created_at_tz_naive", mode="before")
    @classmethod
    def validate_created_at(cls, value: Any) -> datetime:
        """Convert a datetime string to a datetime object.

        :param value: The input value - should be a datetime string.
        :returns: The input value converted to a datetime object.
        """
        # Fast path for str (most likely input type)
        if isinstance(value, str):
            return datetime.fromisoformat(value)
        elif isinstance(value, datetime):
            return value
        elif isinstance(value, date):
            return datetime.combine(value, datetime.min.time())
        return value  # let pydantic throw the ValidationError

    @computed_field
    def created_at(self) -> datetime:
        """Creation time."""
        return self.created_at_tz_naive.replace(tzinfo=self.updated_at.tzinfo)

    @classmethod
    def get_by_name(cls, name: str) -> Atom | Role:
        """Get an Atom or Role by name.

        :param name: The name to search for.
        :returns: The Atom or Role if found.
        :raises CliWarning: If the Atom or Role is not found.
        """
        role_or_atom: Role | Atom
        for func in [Atom.get_by_name, Role.get_by_name]:
            try:
                role_or_atom = func(name)
            except CliWarning:
                pass  # try next function
            else:
                break  # found a match
        else:
            cli_warning(f"Could not find an atom or a role with name: {name!r}")
        return role_or_atom

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


class Role(HostPolicy, APIMixin["Role"]):
    """Model for a role."""

    id: int  # noqa: A003
    hosts: NameList
    atoms: NameList
    labels: list[int]

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.HostPolicyRoles

    @classmethod
    def get_by_name(cls, name: str) -> Role:
        """Get a Role by name.

        :param name: The role name to search for.
        :returns: The role if found.
        :raises CliWarning: If the role is not found.
        """
        data = get_item_by_key_value(Endpoint.HostPolicyRoles, "name", name)
        if not data:
            cli_warning(f"Role with name {name} not found.")
        return cls(**data)

    def output(self, padding: int = 14) -> None:
        """Output the role to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        super().output(padding=padding)
        output_manager = OutputManager()
        output_manager.add_line("Atom members:")
        for atom in self.atoms:
            output_manager.add_formatted_line("", atom, padding)
        labels = self.get_labels()
        output_manager.add_line("Labels:")
        for label in labels:
            output_manager.add_formatted_line("", label.name, padding)

    @classmethod
    def output_multiple(cls, roles: list[Role], padding: int = 14) -> None:
        """Output multiple roles to the console.

        :param roles: List of roles to output.
        :param padding: Number of spaces for left-padding the output.
        """
        if not roles:
            return

        OutputManager().add_line(
            "{1:<{0}}{2}".format(padding, "Roles:", ", ".join([role.name for role in roles]))
        )

    def get_labels(self) -> list[Label]:
        """Get the labels associated with the role.

        :returns: A list of Label objects.
        """
        return [Label.get_by_id_or_raise(id_) for id_ in self.labels]


class Atom(HostPolicy, APIMixin["Atom"]):
    """Model for an atom."""

    id: int  # noqa: A003
    roles: NameList

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.HostPolicyAtoms

    @classmethod
    def get_by_name(cls, name: str) -> Atom:
        """Get an Atom by name.

        :param name: The atom name to search for.
        :returns: The atom if found.
        :raises CliWarning: If the atom is not found.
        """
        data = get_item_by_key_value(Endpoint.HostPolicyAtoms, "name", name)
        if not data:
            cli_warning(f"Atom with name {name} not found.")
        return cls(**data)

    def output(self, padding: int = 14) -> None:
        """Output the role to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        super().output(padding=padding)
        output_manager = OutputManager()
        output_manager.add_line("Roles where this atom is a member:")
        for role in self.roles:
            output_manager.add_formatted_line("", role, padding)


class Label(FrozenModelWithTimestamps, APIMixin["Label"]):
    """Model for a label."""

    id: int  # noqa: A003
    name: str
    description: str

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Labels

    @classmethod
    def get_by_name(cls, name: str) -> Label:
        """Get a Label by name.

        :param name: The Label name to search for.
        :returns: The Label if found.
        :raises CliWarning: If the Label is not found.
        """
        data = get_item_by_key_value(Endpoint.Labels, "name", name)
        if not data:
            cli_warning(f"Label with name {name} not found.")
        return cls(**data)

    @classmethod
    def get_by_id_or_raise(cls, _id: int) -> Label:
        """Get a Label by ID.

        :param _id: The Label ID to search for.
        :returns: The Label if found.
        :raises CliWarning: If the Label is not found.
        """
        label = cls.get_by_id(_id)
        if not label:
            cli_warning(f"Label with ID {_id} not found.")
        return label


class Network(FrozenModelWithTimestamps, APIMixin["Network"]):
    """Model for a network."""

    id: int  # noqa: A003
    excluded_ranges: list[str]
    network: str  # for now
    description: str
    vlan: int | None = None
    dns_delegated: bool
    category: str
    location: str
    frozen: bool
    reserved: int

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Networks

    @classmethod
    def get_by_ip(cls, ip: IP_AddressT) -> Network:
        """Get a network by IP address.

        :param ip: The IP address to search for.
        :returns: The network if found, None otherwise.
        :raises cli_warning: If the network is not found.
        """
        data = get(Endpoint.NetworksByIP.with_id(str(ip)))
        if not data:
            cli_warning(f"Network with IP address {ip} not found.")
        return Network(**data.json())

    @classmethod
    def get_by_netmask(cls, netmask: str) -> Network:
        """Get a network by netmask.

        :param netmask: The netmask to search for.
        :returns: The network if found, None otherwise.
        :raises ValueError: If the netmask is invalid.
        :raises cli_warning: If the network is not found.
        """
        data = get_item_by_key_value(Endpoint.Networks, "network", netmask)
        if not data:
            cli_warning(f"Network with netmask {netmask} not found.")
        return Network(**data)

    def get_first_available_ip(self) -> IP_AddressT:
        """Return the first available IPv4 address of the network."""
        data = get(Endpoint.NetworksFirstUnused.with_params(self.network))
        return ipaddress.ip_address(data.json())

    def __hash__(self):
        """Return a hash of the network."""
        return hash((self.id, self.network))


class IPAddress(FrozenModelWithTimestamps, WithHost, APIMixin["IPAddress"]):
    """Represents an IP address with associated details."""

    id: int  # noqa: A003
    macaddress: MACAddressField | None = None
    ipaddress: IPAddressField

    @field_validator("macaddress", mode="before")
    @classmethod
    def create_valid_macadress_or_none(cls, v: str) -> MACAddressField | None:
        """Create macaddress or convert empty strings to None."""
        if v:
            return MACAddressField(address=v)

        return None

    @model_validator(mode="before")
    @classmethod
    def convert_ip_address(cls, values: Any):
        """Convert ipaddress string to IPAddressField if necessary."""
        ip_address = values.get("ipaddress")
        if isinstance(ip_address, str):
            values["ipaddress"] = {"address": ip_address}
        return values

    @classmethod
    def get_by_ip(cls, ip: IP_AddressT) -> list[IPAddress]:
        """Get a list of IP address objects by IP address.

        Note that the IP addresses can be duplicated across hosts,
        so this method may return multiple IP addresses.

        :param ip: The IP address to search for.
        :returns: The IP address if found, None otherwise.
        """
        params = {"ipaddress": str(ip)}
        data = get_list(Endpoint.Ipaddresses, params=params)
        return [IPAddress(**item) for item in data]

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Ipaddresses

    def __str__(self):
        """Return the IP address as a string."""
        return self.ipaddress.__str__()

    def is_ipv4(self) -> bool:
        """Return True if the IP address is IPv4."""
        return self.ipaddress.is_ipv4()

    def is_ipv6(self) -> bool:
        """Return True if the IP address is IPv6."""
        return self.ipaddress.is_ipv6()

    def network(self) -> Network:
        """Return the network of the IP address."""
        data = get(Endpoint.NetworksByIP.with_id(str(self.ip())))
        return Network(**data.json())

    def vlan(self) -> int | None:
        """Return the VLAN of the IP address."""
        return self.network().vlan

    def ip(self) -> IP_AddressT:
        """Return the IP address."""
        return self.ipaddress.address

    def associate_mac(self, mac: MACAddressField | str, force: bool = False) -> IPAddress:
        """Associate a MAC address with the IP address.

        :param mac: The MAC address to associate.
        :param force: If True, force the association even if the IP address already has
                      a MAC address.

        :returns: A new IPAddress object fetched from the API with the updated MAC address.
        """
        if isinstance(mac, str):
            mac = MACAddressField(address=mac)

        if self.macaddress and not force:
            cli_warning(f"IP address {self.ipaddress} already has MAC address {self.macaddress}.")

        return self.patch(fields={"macaddress": mac.address})

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

    def __hash__(self):
        """Return a hash of the IP address."""
        return hash((self.id, self.ipaddress.address, self.macaddress))


class HInfo(FrozenModelWithTimestamps, WithHost, APIMixin["HInfo"]):
    """Represents a HINFO record."""

    cpu: str
    os: str

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Hinfos

    def output(self, padding: int = 14):
        """Output the HINFO record to the console."""
        OutputManager().add_line(
            "{1:<{0}}cpu={2} os={3}".format(padding, "Hinfo:", self.cpu, self.os)
        )


class CNAME(FrozenModelWithTimestamps, WithHost, WithZone, APIMixin["CNAME"]):
    """Represents a CNAME record."""

    id: int  # noqa: A003
    name: HostT
    ttl: int | None = None

    @field_validator("name", mode="before")
    @classmethod
    def validate_name(cls, value: str) -> HostT:
        """Validate the hostname."""
        return HostT(hostname=value)

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Cnames

    @classmethod
    def get_by_name(cls, name: HostT) -> CNAME:
        """Get a CNAME record by name.

        :param name: The name to search for.
        :returns: The CNAME record if found, None otherwise.
        """
        data = get_item_by_key_value(Endpoint.Cnames, "name", name.hostname)
        if not data:
            cli_warning(f"CNAME record for {name} not found.")
        return CNAME(**data)

    @classmethod
    def get_by_host_and_name(cls, host: HostT | int, name: HostT) -> CNAME:
        """Get a CNAME record by host and name.

        :param host: The host to search for, either a hostname or an ID.
        :param name: The name to search for.
        :returns: The CNAME record if found, None otherwise.
        """
        target_hostname = None
        if isinstance(host, HostT):
            hostobj = Host.get_by_any_means(host, inform_as_cname=False)
            if not hostobj:
                cli_warning(f"Host with name {host.hostname} not found.")

            host = hostobj.id
            target_hostname = hostobj.name.hostname
        else:
            hostobj = Host.get_by_id(host)
            if not hostobj:
                cli_warning(f"Host with ID {host} not found.")
            target_hostname = hostobj.name.hostname

        results = cls.get_by_query({"host": str(host), "name": name.hostname})

        if not results or len(results) == 0:
            cli_warning(f"CNAME record for {name} not found for {target_hostname}.")

        if len(results) > 1:
            cli_error(f"Multiple CNAME records found for {host} with {name}!")

        return results[0]

    def output(self, padding: int = 14) -> None:
        """Output the CNAME record to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        actual_host = self.resolve_host()
        host = actual_host.name if actual_host else "<Not found>"

        OutputManager().add_line(f"{'Cname:':<{padding}}{self.name} -> {host}")

    @classmethod
    def output_multiple(cls, cnames: list[CNAME], padding: int = 14) -> None:
        """Output multiple CNAME records to the console.

        :param cnames: List of CNAME records to output.
        :param padding: Number of spaces for left-padding the output.
        """
        for cname in cnames:
            cname.output(padding=padding)


class TXT(FrozenModelWithTimestamps, WithHost, APIMixin["TXT"]):
    """Represents a TXT record."""

    id: int  # noqa: A003
    txt: str

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Txts

    def output(self, padding: int = 14) -> None:
        """Output the TXT record to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        OutputManager().add_line(f"{'TXT:':<{padding}}{self.txt}")

    @classmethod
    def output_multiple(cls, txts: list[TXT], padding: int = 14) -> None:
        """Output multiple TXT records to the console.

        :param txts: List of TXT records to output.
        :param padding: Number of spaces for left-padding the output.
        """
        for txt in txts:
            txt.output(padding=padding)


class MX(FrozenModelWithTimestamps, WithHost, APIMixin["MX"]):
    """Represents a MX record."""

    id: int  # noqa: A003
    mx: str
    priority: int

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Mxs

    @classmethod
    def get_by_all(cls, host: int, mx: str, priority: int) -> MX:
        """Get an MX record by all fields.

        :param host: The host ID.
        :param mx: The MX record.
        :param priority: The priority.
        :returns: The MX record if found, None otherwise.
        """
        data = get_list_unique(
            Endpoint.Mxs, params={"host": str(host), "mx": mx, "priority": str(priority)}
        )
        if not data:
            cli_warning(f"MX record for {mx} not found.")
        return MX(**data)

    def has_mx_with_priority(self, mx: str, priority: int) -> bool:
        """Return True if the MX record has the given MX and priority.

        :param mx: The MX record to check.
        :param priority: The priority to check.
        :returns: True if the MX record has the given MX and priority.
        """
        return self.mx == mx and self.priority == priority

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


class NAPTR(FrozenModelWithTimestamps, WithHost, APIMixin["NAPTR"]):
    """Represents a NAPTR record."""

    id: int  # noqa: A003
    preference: int
    order: int
    flag: str | None = None
    service: str | None = None
    regex: str | None = None
    replacement: str

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
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Naptrs

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


class Srv(FrozenModelWithTimestamps, WithHost, WithZone, APIMixin["Srv"]):
    """Represents a SRV record."""

    id: int  # noqa: A003
    name: str
    priority: int
    weight: int
    port: int
    ttl: int | None = None

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Srvs

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
    def output_multiple(cls, srvs: list[Srv], padding: int = 14) -> None:
        """Output multiple SRV records.

        This method adjusts the padding dynamically based on the longest record name.

        :param srvs: List of Srv records to output.
        :param padding: Minimum number of spaces for left-padding the output.
        """
        if not srvs:
            return

        host_ids = {srv.host for srv in srvs}

        host_data = get_list_in(Endpoint.Hosts, "id", list(host_ids))
        hosts = [Host(**host) for host in host_data]

        host_id_name_map = {host.id: str(host.name) for host in hosts}

        host_id_name_map.update(
            {host_id: host_id_name_map.get(host_id, "<Not found>") for host_id in host_ids}
        )

        padding = max((len(srv.name) for srv in srvs), default=padding)

        # Output each SRV record with the optimized host name lookup
        for srv in srvs:
            srv.output(padding=padding, host_id_name_map=host_id_name_map)


class PTR_override(FrozenModelWithTimestamps, WithHost, APIMixin["PTR_override"]):
    """Represents a PTR override record."""

    id: int  # noqa: A003
    ipaddress: str  # For now, should be an IP address

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.PTR_overrides

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


class SSHFP(FrozenModelWithTimestamps, WithHost, APIMixin["SSHFP"]):
    """Represents a SSHFP record."""

    id: int  # noqa: A003
    algorithm: int
    hash_type: int
    fingerprint: str
    ttl: int | None = None

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Sshfps

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


class BacnetID(FrozenModel, WithHost, APIMixin["BacnetID"]):
    """Represents a Bacnet ID record."""

    id: int  # noqa: A003
    hostname: str

    @classmethod
    def MAX_ID(cls) -> int:
        """Return the maximum ID for a Bacnet ID."""
        return 4194302

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.BacnetID

    @classmethod
    def get_in_range(cls, start: int, end: int) -> list[BacnetID]:
        """Get Bacnet IDs in a range.

        :param start: The start of the range.
        :param end: The end of the range.
        :returns: List of BacnetID objects in the range.
        """
        params = {"id__range": f"{start},{end}"}
        data = get_list(Endpoint.BacnetID, params=params)
        return [BacnetID(**item) for item in data]

    @classmethod
    def output_multiple(cls, bacnetids: list[BacnetID]):
        """Output multiple Bacnet ID records to the console.

        :param bacnetids: List of Bacnet ID records to output.
        """
        if not bacnetids:
            return

        OutputManager().add_formatted_table(("ID", "Hostname"), ("id", "hostname"), bacnetids)


class Location(FrozenModelWithTimestamps, WithHost, APIMixin["Location"]):
    """Represents a LOC record."""

    loc: str

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Locs

    def output(self, padding: int = 14):
        """Output the LOC record to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        OutputManager().add_line(f"{'LOC:':<{padding}}{self.loc}")


class Host(FrozenModelWithTimestamps, APIMixin["Host"]):
    """Model for an individual host."""

    id: int  # noqa: A003
    name: HostT
    ipaddresses: list[IPAddress]
    cnames: list[CNAME] = []
    mxs: list[MX] = []
    txts: list[TXT] = []
    ptr_overrides: list[PTR_override] = []
    hinfo: HInfo | None = None
    loc: Location | None = None
    bacnetid: int | None = None
    contact: str
    ttl: int | None = None
    comment: str | None = None

    # Note, we do not use WithZone here as this is optional and we resolve it differently.
    zone: int | None = None

    @field_validator("name", mode="before")
    @classmethod
    def validate_name(cls, value: str) -> HostT:
        """Validate the hostname."""
        return HostT(hostname=value)

    @field_validator("comment", mode="before")
    @classmethod
    def empty_string_to_none(cls, v: str) -> str | None:
        """Convert empty strings to None."""
        return v or None

    @field_validator("bacnetid", mode="before")
    @classmethod
    def convert_bacnetid(cls, v: dict[str, int] | None) -> int | None:
        """Convert json id field to int or None."""
        if v and "id" in v:
            return v["id"]

        return None

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Hosts

    @classmethod
    def get_by_any_means_or_raise(
        cls, identifier: str | HostT, inform_as_cname: bool = True
    ) -> Host:
        """Get a host by the given identifier or raise a CliWarning.

        See also `get_by_any_means`.

        :param identifier: The identifier to search for.
        :param inform_as_cname: If True, inform the user if the host is a CNAME.

        :raises CliWarning: If the host is not found.

        :returns: A Host object if the host was found.
        """
        host = cls.get_by_any_means(identifier, inform_as_cname=inform_as_cname)
        if not host:
            cli_warning(f"Host {identifier} not found.")
        return host

    @classmethod
    def get_by_any_means(
        cls, identifier: str | HostT, inform_as_cname: bool = True
    ) -> Host | None:
        """Get a host by the given identifier.

        - If the identifier is numeric, it will be treated as an ID.
        - If the identifier is an IP address, it will be treated as an IP address (v4 or v6).
        - If the identifier is a MAC address, it will be treated as a MAC address.
        - Otherwise, it will be treated as a hostname. If the hostname is a CNAME,
        the host it points to will be returned.

        To check if a returned host is a cname, one can do the following:

        ```python
        hostname = "host.example.com"
        host = get_host(hostname, ok404=True)
        if host is None:
            print("Host not found.")
        elif host.name != hostname:
            print(f"{hostname} is a CNAME pointing to {host.name}")
        else:
            print(f"{host.name} is a host.")
        ```

        Note that get_host will perform a case-insensitive search for a fully qualified version
        of the hostname, so the comparison above may fail.

        :param identifier: The identifier to search for.
        :param ok404: If True, don't raise a CliWarning if the host is not found.
        :param inform_as_cname: If True, inform the user if the host is a CNAME.

        :raises CliWarning: If we don't find the host and `ok404` is False.

        :returns: A Host object if the host was found, otherwise None.
        """
        host = None
        if not isinstance(identifier, HostT):
            if identifier.isdigit():
                return Host.get_by_id(int(identifier))

            try:
                ipaddress.ip_address(identifier)

                hosts = Host.get_list_by_field(
                    "ipaddresses__ipaddress", identifier, ordering="name"
                )

                if len(hosts) == 1:
                    return hosts[0]

                if len(hosts) > 1:
                    cli_warning(f"Multiple hosts found with IP address {identifier}.")

            except ValueError:
                pass

            try:
                mac = MACAddressField(address=identifier)
                return Host.get_by_field("macaddress", mac.address)
            except ValueError:
                pass

            # Let us try to find the host by name...
            name = HostT(hostname=identifier)
        else:
            name = identifier

        host = Host.get_by_field("name", name.hostname)

        if host:
            return host

        cname = CNAME.get_by_field("name", name.hostname)
        # If we found a CNAME, get the host it points to. We're not interested in the
        # CNAME itself.
        if cname is not None:
            host = Host.get_by_id(cname.host)

            if host and inform_as_cname:
                OutputManager().add_line(f"{name} is a CNAME for {host.name}")

        return host

    def delete(self) -> bool:
        """Delete the host.

        :raises CliWarning: If the operation to delete the host fails.

        :returns: True if the host was deleted successfully, False otherwise.
        """
        # Note, we can't use .id as the identifier here, as the host name is used
        # in the endpoint URL...
        op = delete(Endpoint.Hosts.with_id(str(self.name)))
        if not op:
            cli_warning(f"Failed to delete host {self.name}, operation failed.")

        return op.status_code >= 200 and op.status_code < 300

    def rename(self, new_name: HostT) -> Host:
        """Rename the host.

        :param new_name: The new name for the host.

        :returns: A new Host object fetched from the API with the updated name.
        """
        return self.patch(fields={"name": new_name.hostname})

    def set_comment(self, comment: str) -> Host:
        """Set the comment for the host.

        :param comment: The comment to set.

        :returns: A new Host object fetched from the API with the updated comment.
        """
        return self.patch(fields={"comment": comment})

    def set_contact(self, contact: str) -> Host:
        """Set the contact for the host.

        :param contact: The contact to set. Should be a valid email, but we leave it to the
                        server to validate the data.

        :returns: A new Host object fetched from the API with the updated contact.
        """
        return self.patch(fields={"contact": contact})

    def add_ip(self, ip: IP_AddressT, mac: MACAddressField | None = None) -> Host:
        """Add an IP address to the host.

        :param ip: The IP address to add. IPv4 or IPv6.

        :returns: A new Host object fetched from the API with the updated IP address.
        """
        params: dict[str, str | None] = {"ipaddress": str(ip), "host": str(self.id)}
        if mac:
            params["macaddress"] = mac.address

        print(params)

        IPAddress.create(params=params)
        return self.refetch()

    def has_ip(self, arg_ip: IP_AddressT) -> bool:
        """Check if the host has the given IP address.

        :param ip: The IP address to check for.

        :returns: True if the host has the IP address, False otherwise.
        """
        return any([ip.ipaddress.address == arg_ip for ip in self.ipaddresses])

    def get_ip(self, arg_ip: IP_AddressT) -> IPAddress | None:
        """Get the IP address object for the given IP address.

        :param ip: The IP address to search for.

        :returns: The IP address object if found, None otherwise.
        """
        return next((ip for ip in self.ipaddresses if ip.ipaddress.address == arg_ip), None)

    def get_ptr_override(self, ip: IP_AddressT) -> PTR_override | None:
        """Get the PTR override for the given IP address.

        :param ip: The IP address to search for.

        :returns: The PTR override object if found, None otherwise.
        """
        return next((ptr for ptr in self.ptr_overrides if ptr.ipaddress == ip), None)

    def ipv4_addresses(self):
        """Return a list of IPv4 addresses."""
        return [ip for ip in self.ipaddresses if ip.is_ipv4()]

    def ipv6_addresses(self):
        """Return a list of IPv6 addresses."""
        return [ip for ip in self.ipaddresses if ip.is_ipv6()]

    def associate_mac_to_ip(
        self, mac: MACAddressField | str, ip: IPAddressField | str, force: bool = False
    ) -> Host:
        """Associate a MAC address to an IP address.

        :param mac: The MAC address to associate.
        :param ip: The IP address to associate.

        :returns: A new Host object fetched from the API after updating the IP address.
        """
        if isinstance(mac, str):
            mac = MACAddressField(address=mac)

        if isinstance(ip, str):
            ip = IPAddressField(address=ipaddress.ip_address(ip))

        params = {
            "macaddress": mac.address,
            "ordering": "ipaddress",
        }

        data = get_list(Endpoint.Ipaddresses, params=params)
        ipadresses = [IPAddress(**ip) for ip in data]

        if ip in [ip.ipaddress for ip in ipadresses]:
            cli_warning(f"IP address {ip} already has MAC address {mac} associated.")

        if len(ipadresses) and not force:
            cli_warning(
                "mac {} already in use by: {}. Use force to add {} -> {} as well.".format(
                    mac, ipadresses, ip.address, mac
                )
            )

        ip_found_in_host = False
        new_ips: list[IPAddress] = []
        for myip in self.ipaddresses:
            current_ip = myip.model_copy()

            if myip.ipaddress.address == ip.address:
                current_ip = myip.associate_mac(mac, force=force)
                ip_found_in_host = True

            new_ips.append(current_ip)

        if not ip_found_in_host:
            cli_warning(f"IP address {ip} not found in host {self.name}.")

        return self.refetch()

    def networks(self) -> dict[Network, list[IPAddress]]:
        """Return a dict of unique networks and a list of associated IP addresses for the host.

        :returns: A dictionary of networks and the associated IP addresses.
        """
        ret_dict: dict[Network, list[IPAddress]] = {}

        for ip in self.ipaddresses:
            network = ip.network()
            if network not in ret_dict:
                ret_dict[network] = []

            ret_dict[network].append(ip)

        return ret_dict

    def vlans(self) -> dict[int, list[IPAddress]]:
        """Return a dict of unique VLANs ID and a list of associated IP addresses for the host.

        IP addresses without a VLAN are assigned to VLAN 0.

        Note that this method will call self.networks() to determine the networks associated with
        the IP addresses. If you wish to report more details about what networks the IP addresses
        (ie, beyond simply the VLAN ID), use self.networks() and parse the VLAN from the network
        manually.

        :returns: A dictionary of VLAN ID and the associated IP addresses.
        """
        ret_dict: dict[int, list[IPAddress]] = {}

        for network, ips in self.networks().items():
            vlan = network.vlan or 0
            if vlan not in ret_dict:
                ret_dict[vlan] = []

            ret_dict[vlan].extend(ips)

        return ret_dict

    def resolve_zone(
        self, accept_delegation: bool = False, validate_zone_resolution: bool = False
    ) -> Zone | Delegation | None:
        """Return the zone for the host.

        :param accept_delegation: If True, accept delegation and return a Delegation object if the
                                    zone of the host is delegated. Otherwise raise a cli_warning.
        :param validate_zone_resolution: If True, validate that the resolved zone matches the
                                          expected zone ID. Fail with a cli_warning if it does not.
        """
        if not self.zone:
            return None

        data = get(Endpoint.ForwardZoneForHost.with_id(str(self.name)))
        data_as_dict = data.json()

        if data_as_dict["zone"]:
            zone = Zone(**data_as_dict["zone"])
            if validate_zone_resolution and zone.id != self.zone:
                cli_warning(f"Expected zone ID {self.zone} but resovled as {zone.id}.")
            return zone

        if data_as_dict["delegation"]:
            if not accept_delegation:
                cli_warning(
                    f"Host {self.name} is delegated to zone {data_as_dict['delegation']['name']}."
                )
            return Delegation(**data_as_dict["delegation"])

        cli_warning(f"Failed to resolve zone for host {self.name}.")

    # This would be greatly improved by having a proper error returned to avoid the need for
    # manually calling networks() or vlans() to determine the issue. One option is to use
    # a custom exception, or to return a tuple of (bool, str) where the str is the error message.
    def all_ips_on_same_vlan(self) -> bool:
        """Return True if all IP addresses are on the same VLAN.

        - If there are no IP addresses, return True.
        - If there is only one IP address, return True.
        - If there are multiple IP addresses and they are all on the same VLAN, return True.

        Note that this method will call self.vlans() to determine if all IP addresses are on the
        same VLAN, which in turn calls self.networks() to determine the networks associated with
        the IP addresses.

        If you wish to report more details about what VLANs the IP addresses are on, use
        self.vlans() or self.networks().

        :returns: True if all IP addresses are on the same VLAN, False otherwise.
        """
        vlans = self.vlans()
        if not vlans:
            return True

        if len(vlans) == 1:
            return True

        return False

    def naptrs(self) -> list[NAPTR]:
        """Return a list of NAPTR records."""
        return NAPTR.get_list_by_field("host", self.id)

    def srvs(self) -> list[Srv]:
        """Return a list of SRV records."""
        return Srv.get_list_by_field("host", self.id)

    def sshfps(self) -> list[SSHFP]:
        """Return a list of SSHFP records."""
        return SSHFP.get_list_by_field("host", self.id)

    def roles(self) -> list[Role]:
        """List all roles for the host."""
        return Role.get_list_by_field("hosts", self.id)

    def bacnet(self) -> BacnetID | None:
        """Return the BacnetID for the host."""
        if not self.bacnetid:
            return None

        return BacnetID.get_by_id(self.bacnetid)

    def has_mx_with_priority(self, mx_arg: str, priority: int) -> MX | None:
        """Check if the host has an MX record.

        :param mx: The MX record to check for.
        :param priority: The priority of the MX record.

        :returns: True if the host has the MX record, False otherwise.
        """
        return next((mx for mx in self.mxs if mx.has_mx_with_priority(mx_arg, priority)), None)

    def hostgroups(self, traverse: bool = False) -> list[HostGroup]:
        """List all hostgroups for the host.

        :param traverse: If True, traverse the parent groups and include them in the list.

        :returns: A list of HostGroup objects.
        """
        groups: list[HostGroup] = []
        direct = HostGroup.get_list_by_field("hosts", self.id)
        groups.extend(direct)

        if traverse:
            for group in direct:
                groups.extend(group.get_all_parents())

        return groups

    def output(self, names: bool = False, traverse_hostgroups: bool = False):
        """Output host information to the console with padding."""
        padding = 14

        output_manager = OutputManager()
        output_manager.add_line(f"{'Name:':<{padding}}{self.name}")
        output_manager.add_line(f"{'Contact:':<{padding}}{self.contact}")

        if self.comment is not None and self.comment != "":
            output_manager.add_line(f"{'Comment:':<{padding}}{self.comment}")

        self.output_ipaddresses(padding=padding, names=names)
        PTR_override.output_multiple(self.ptr_overrides, padding=padding)

        output_manager.add_line("{1:<{0}}{2}".format(padding, "TTL:", self.ttl or "(Default)"))

        MX.output_multiple(self.mxs, padding=padding)

        if self.hinfo:
            self.hinfo.output(padding=padding)

        if self.loc:
            self.loc.output(padding=padding)

        self.output_cnames(padding=padding)

        TXT.output_multiple(self.txts, padding=padding)
        Srv.output_multiple(self.srvs(), padding=padding)
        NAPTR.output_multiple(self.naptrs(), padding=padding)
        SSHFP.output_multiple(self.sshfps(), padding=padding)

        if self.bacnetid is not None:  # This may be zero.
            output_manager.add_line(f"{'Bacnet ID:':<{padding}}{self.bacnetid}")

        Role.output_multiple(self.roles(), padding=padding)
        HostGroup.output_multiple(self.hostgroups(traverse=traverse_hostgroups), padding=padding)

        self.output_timestamps()

    def output_ipaddresses(
        self, padding: int = 14, names: bool = False, only: IP_Version | None = None
    ):
        """Output the IP addresses for the host."""
        if not self.ipaddresses:
            return

        if only and only == 4:
            IPAddress.output_multiple(self.ipv4_addresses(), padding=padding, names=names)
        elif only and only == 6:
            IPAddress.output_multiple(self.ipv6_addresses(), padding=padding, names=names)
        else:
            IPAddress.output_multiple(self.ipaddresses, padding=padding, names=names)

    def output_cnames(self, padding: int = 14):
        """Output the CNAME records for the host."""
        if not self.cnames:
            return

        CNAME.output_multiple(self.cnames, padding=padding)

    def __str__(self) -> str:
        """Return the host name as a string."""
        return self.name.hostname

    def __hash__(self):
        """Return a hash of the host."""
        return hash((self.id, self.name))


class HostList(FrozenModel):
    """Model for a list of hosts.

    This is the endpoint at /api/v1/hosts/.
    """

    results: list[Host]

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Hosts

    @classmethod
    def get(cls, params: dict[str, Any] | None = None) -> HostList:
        """Get a list of hosts.

        :param params: Optional parameters to pass to the API.

        :returns: A HostList object.
        """
        if params is None:
            params = {}

        if "ordering" not in params:
            params["ordering"] = "name"

        data = get_list(cls.endpoint(), params=params)
        return cls(results=[Host(**host) for host in data])

    @classmethod
    def get_by_ip(cls, ip: IP_AddressT) -> HostList:
        """Get a list of hosts by IP address.

        :param ip: The IP address to search for.

        :returns: A HostList object.
        """
        return cls.get(params={"ipaddresses__ipaddress": str(ip), "ordering": "name"})

    @field_validator("results", mode="before")
    @classmethod
    def check_results(cls, v: list[dict[str, str]]) -> list[dict[str, str]]:
        """Check that the results are valid."""
        return v

    def __len__(self):
        """Return the number of results."""
        return len(self.results)

    def __getitem__(self, key: int) -> Host:
        """Get a result by index."""
        return self.results[key]

    def __str__(self):
        """Return a string representation of the results."""
        return str(self.results)

    def __repr__(self):
        """Return a string representation of the results."""
        return repr(self.results)

    def hostnames(self) -> list[str]:
        """Return a list of hostnames."""
        return [host.name.hostname for host in self.results]

    def count(self):
        """Return the number of results."""
        return len(self.results)

    def output(self):
        """Output a list of hosts to the console."""
        if not self.results:
            cli_warning("No hosts found.")

        max_name = max_contact = 20
        for i in self.results:
            max_name = max(max_name, len(str(i.name)))
            max_contact = max(max_contact, len(i.contact))

        def _format(name: str, contact: str, comment: str) -> None:
            OutputManager().add_line(
                "{0:<{1}} {2:<{3}} {4}".format(name, max_name, contact, max_contact, comment)
            )

        _format("Name", "Contact", "Comment")
        for i in self.results:
            _format(str(i.name), i.contact, i.comment or "")


class HostGroup(FrozenModelWithTimestamps, APIMixin["HostGroup"]):
    """Model for a hostgroup."""

    id: int  # noqa: A003
    name: str
    description: str | None = None
    parent: list[str]
    groups: list[str]
    hosts: list[str]
    owners: list[str]

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.HostGroups

    @field_validator("parent", "groups", "hosts", "owners", mode="before")
    @classmethod
    def collapse_name(cls, v: list[dict[str, str]]) -> list[str]:
        """Collapse the name field."""
        if not v:
            return []

        return [i["name"] for i in v]

    @classmethod
    def output_multiple(cls, hostgroups: list[HostGroup], padding: int = 14) -> None:
        """Output multiple hostgroups to the console.

        :param hostgroups: List of HostGroup records to output.
        :param padding: Number of spaces for left-padding the output.
        """
        if not hostgroups:
            return

        groups = ", ".join(sorted([group.name for group in hostgroups]))

        OutputManager().add_line("{1:<{0}}{2}".format(padding, "Groups:", groups))

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

    def get_all_parents(self) -> list[HostGroup]:
        """Return a list of all parent groups."""
        parents: list[HostGroup] = []
        for parent in self.parent:
            pobj = HostGroup.get_by_field("name", parent)
            if pobj:
                parents.append(pobj)
                parents.extend(pobj.get_all_parents())

        return parents
