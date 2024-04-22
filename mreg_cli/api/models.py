"""Pydantic models for the mreg_cli package."""

import ipaddress
import re
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Generic, List, Optional, Set, TypeVar, Union, cast

from pydantic import AliasChoices, BaseModel, Field, root_validator, validator
from pydantic.fields import FieldInfo

from mreg_cli.api.endpoints import Endpoint
from mreg_cli.config import MregCliConfig
from mreg_cli.log import cli_warning
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import IP_AddressT
from mreg_cli.utilities.api import (
    delete,
    get,
    get_item_by_key_value,
    get_list,
    get_list_in,
    patch,
    post,
)

_mac_regex = re.compile(r"^([0-9A-Fa-f]{2}[.:-]){5}([0-9A-Fa-f]{2})$")

BMT = TypeVar("BMT", bound="BaseModel")


def get_field_aliases(field_info: FieldInfo) -> Set[str]:
    """Get all aliases for a Pydantic field."""
    aliases: set[str] = set()

    if field_info.alias:
        aliases.add(field_info.alias)

    if field_info.validation_alias:
        if isinstance(field_info.validation_alias, str):
            aliases.add(field_info.validation_alias)
        elif isinstance(field_info.validation_alias, AliasChoices):
            for choice in field_info.validation_alias.choices:
                if isinstance(choice, str):
                    aliases.add(choice)
    return aliases


def get_model_aliases(model: BaseModel) -> Dict[str, str]:
    """Get a mapping of aliases to field names for a Pydantic model.

    Includes field names, alias, and validation alias(es).
    """
    fields = {}  # type: Dict[str, str]

    for field_name, field_info in model.model_fields.items():
        aliases = get_field_aliases(field_info)
        if model.model_config.get("populate_by_name"):
            aliases.add(field_name)
        # Assign aliases to field name in mapping
        for alias in aliases:
            fields[alias] = field_name

    return fields


class HostT(BaseModel):
    """A type for a hostname."""

    hostname: str

    @validator("hostname")
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


class FrozenModel(BaseModel):
    """Model for an immutable object."""

    def __setattr__(self, name: str, value: Any):
        """Raise an exception when trying to set an attribute."""
        raise AttributeError("Cannot set attribute on a frozen object")

    def __delattr__(self, name: str):
        """Raise an exception when trying to delete an attribute."""
        raise AttributeError("Cannot delete attribute on a frozen object")

    class Config:
        """Pydantic configuration.

        Set the class to frozen to make it immutable and thus hashable.
        """

        frozen = True


class FrozenModelWithTimestamps(FrozenModel):
    """Model with created_at and updated_at fields."""

    created_at: datetime
    updated_at: datetime

    def output_timestamps(self, padding: int = 14) -> None:
        """Output the created and updated timestamps to the console."""
        output_manager = OutputManager()
        output_manager.add_line(f"{'Created:':<{padding}}{self.created_at:%c}")
        output_manager.add_line(f"{'Updated:':<{padding}}{self.updated_at:%c}")


class WithHost(BaseModel):
    """Model for an object that has a host element."""

    host: int

    def resolve_host(self) -> Union["Host", None]:
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

    def resolve_zone(self) -> Union["Zone", None]:
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


class APIMixin(Generic[BMT], ABC):
    """A mixin for API-related methods."""

    id: int  # noqa: A003

    def id_for_endpoint(self) -> Union[int, str]:
        """Return the appropriate id for the object for its endpoint.

        :returns: The correct identifier for the endpoint.
        """
        field = self.endpoint().external_id_field()
        return getattr(self, field)

    @classmethod
    def field_for_endpoint(cls) -> str:
        """Return the appropriate field for the object for its endpoint.

        :param field: The field to return.
        :returns: The correct field for the endpoint.
        """
        return cls.endpoint().external_id_field()

    @classmethod
    @abstractmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the method."""
        raise NotImplementedError("You must define an endpoint.")

    @classmethod
    def get(cls, _id: int) -> Optional[BMT]:
        """Get an object.

        This function is at its base a wrapper around the get_by_id function,
        but it can be overridden to provide more specific functionality.

        :param _id: The ID of the object.
        :returns: The object if found, None otherwise.
        """
        return cls.get_by_id(_id)

    @classmethod
    def get_by_id(cls, _id: int) -> Optional[BMT]:
        """Get an object by its ID.

        Note that for Hosts, the ID is the name of the host.

        :param _id: The ID of the object.
        :returns: The object if found, None otherwise.
        """
        endpoint = cls.endpoint()

        # Some endpoints do not use the ID field as the endpoint identifier,
        # and in these cases we need to search for the ID... Lovely.
        if endpoint.requires_search_for_id():
            data = get_item_by_key_value(cls.endpoint(), "id", str(_id))
        else:
            data = get(cls.endpoint().with_id(_id), ok404=True)
            if not data:
                return None
            data = data.json()

        if not data:
            return None

        return cast(BMT, cls(**data))

    @classmethod
    def get_by_field(cls, field: str, value: str) -> Optional[BMT]:
        """Get an object by a field.

        Note that some endpoints do not use the ID field for lookups. We do some
        magic mapping via endpoint introspection to perform the following mapping for
        classes and their endpoint "id" fields:

          - Hosts -> name
          - Networks -> network

        This implies that doing a get_by_field("name", value) on Hosts will *not*
        result in a search, but a direct lookup at ../endpoint/name which is what
        the mreg server expects for Hosts (and similar for Network).

        :param field: The field to search by.
        :param value: The value to search for.

        :returns: The object if found, None otherwise.
        """
        endpoint = cls.endpoint()

        if endpoint.requires_search_for_id() and field == endpoint.external_id_field():
            data = get(endpoint.with_id(value), ok404=True)
            if not data:
                return None
            data = data.json()
        else:
            data = get_item_by_key_value(cls.endpoint(), field, value, ok404=True)

        if not data:
            return None

        return cast(BMT, cls(**data))

    @classmethod
    def get_list_by_field(
        cls, field: str, value: Union[str, int], ordering: Optional[str] = None
    ) -> List[BMT]:
        """Get a list of objects by a field.

        :param field: The field to search by.
        :param value: The value to search for.
        :param ordering: The ordering to use when fetching the list.

        :returns: A list of objects if found, an empty list otherwise.
        """
        params = {field: value}
        if ordering:
            params["ordering"] = ordering

        data = get_list(cls.endpoint(), params=params)
        return [cast(BMT, cls(**item)) for item in data]

    def refetch(self) -> BMT:
        """Fetch an updated version of the object.

        Note that the caller (self) of this method will remain unchanged and can contain
        outdated information. The returned object will be the updated version.

        :returns: The fetched object.
        """
        obj = self.__class__.get_by_id(self.id)
        if not obj:
            cli_warning(f"Could not refresh {self.__class__.__name__} with ID {self.id}.")

        return obj

    def patch(self, fields: Dict[str, Any]) -> BMT:
        """Patch the object with the given values.

        :param kwargs: The values to patch.
        :returns: The object refetched from the server.
        """
        patch(self.endpoint().with_id(self.id), **fields)

        new_object = self.refetch()

        aliases = get_model_aliases(new_object)
        for key, value in fields.items():
            field_name = aliases.get(key)
            if field_name is None:
                cli_warning(f"Unknown field {key} in patch request.")
            try:
                nval = getattr(new_object, field_name)
            except AttributeError:
                cli_warning(f"Could not get value for {field_name} in patched object.")
            if str(nval) != str(value):
                cli_warning(
                    # Should this reference `field_name` instead of `key`?
                    f"Patch failure! Tried to set {key} to {value}, but server returned {nval}."
                )

        return new_object

    def delete(self) -> bool:
        """Delete the object.

        :returns: True if the object was deleted, False otherwise.
        """
        response = delete(self.endpoint().with_id(self.id_for_endpoint()))

        if response and response.ok:
            return True

        return False

    @classmethod
    def create(cls, kwargs: Dict[str, Union[str, None]]) -> Union[None, BMT]:
        """Create the object.

        :returns: The object if created, None otherwise.
        """
        response = post(cls.endpoint(), params=None, **kwargs)

        if response and response.ok:
            location = response.headers.get("Location")
            if location:
                obj = None
                if cls.endpoint() is Endpoint.Hosts:
                    obj = cls.get_by_field("name", location.split("/")[-1])
                else:
                    obj = cls.get_by_id(int(location.split("/")[-1]))

                if obj:
                    return obj

                cli_warning(f"Could not fetch object from location {location}.")

            else:
                cli_warning("No location header in response.")

        return None


class NameServer(FrozenModelWithTimestamps):
    """Model for representing a nameserver within a DNS zone."""

    id: int  # noqa: A003
    name: str
    ttl: Optional[int] = None


class Zone(FrozenModelWithTimestamps):
    """Model representing a DNS zone with various attributes and related nameservers."""

    id: int  # noqa: A003
    nameservers: List[NameServer]
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

    @classmethod
    def get_from_hostname(cls, hostname: HostT) -> Union["Delegation", "Zone", None]:
        """Get the zone from a hostname.

        Note: This method may return either a Delegation or a Zone object.

        :param hostname: The hostname to search for.
        :returns: The zone if found, None otherwise.
        """
        data = get(Endpoint.ZoneForHost.with_id(hostname.hostname), ok404=True)
        if not data:
            return None

        zoneblob = data.json()

        if "delegate" in zoneblob:
            return Delegation(**zoneblob)

        if "zone" in zoneblob:
            return Zone(**zoneblob["zone"])

        cli_warning(f"Unexpected response from server: {zoneblob}")


class Delegation(FrozenModelWithTimestamps, WithZone):
    """A delegated zone."""

    id: int  # noqa: A003
    nameservers: List[NameServer]
    name: str
    comment: Optional[str] = None

    def is_delegated(self) -> bool:
        """Return True if the zone is delegated."""
        return True


class Role(FrozenModelWithTimestamps, APIMixin["Role"]):
    """Model for a role.

    Note that HostPolicy throws out `create_date` as the date only, not as a
    proper datetime object, and not with the expected name `created_at`.
    """

    id: int  # noqa: A003
    created_at: datetime = Field(..., validation_alias=AliasChoices("create_date", "created_at"))
    hosts: List[str]
    atoms: List[str]
    description: str
    name: str
    labels: List[int]

    @validator("created_at", pre=True)
    def validate_created_at(cls, value: str) -> datetime:
        """Validate and convert the created_at field to datetime.

        :param value: Input date string from the JSON.
        :returns: Converted datetime object.
        """
        return datetime.fromisoformat(value)

    @validator("hosts", "atoms", pre=True, each_item=True)
    def extract_name(cls, v: Dict[str, str]) -> str:
        """Extract the name from the dictionary.

        :param v: Dictionary containing the name.
        :returns: Extracted name as a string.
        """
        return v["name"]

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.HostPolicyRoles

    def output(self, padding: int = 14) -> None:
        """Output the role to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        OutputManager().add_line(f"{'Role:':<{padding}}{self.name} ({self.description})")

    @classmethod
    def output_multiple(cls, roles: List["Role"], padding: int = 14) -> None:
        """Output multiple roles to the console.

        :param roles: List of roles to output.
        :param padding: Number of spaces for left-padding the output.
        """
        if not roles:
            return

        OutputManager().add_line(
            "{1:<{0}}{2}".format(padding, "Roles:", ", ".join([role.name for role in roles]))
        )


class Network(FrozenModelWithTimestamps, APIMixin["Network"]):
    """Model for a network."""

    id: int  # noqa: A003
    excluded_ranges: List[str]
    network: str  # for now
    description: str
    vlan: Optional[int]
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
    def get_by_ip(cls, ip: IP_AddressT) -> "Network":
        """Get a network by IP address.

        :param ip: The IP address to search for.
        :returns: The network if found, None otherwise.
        """
        data = get(Endpoint.NetworksByIP.with_id(str(ip)))
        return Network(**data.json())

    @classmethod
    def get_by_netmask(cls, netmask: str) -> "Network":
        """Get a network by netmask.

        :param netmask: The netmask to search for.
        :returns: The network if found, None otherwise.
        """
        data = get(Endpoint.Networks.with_params(netmask))
        return Network(**data.json())

    def get_first_available_ip(self) -> IP_AddressT:
        """Return the first available IPv4 address of the network."""
        data = get(Endpoint.NetworkFirstUnused.with_params(self.network))
        return ipaddress.ip_address(data.json())

    def __hash__(self):
        """Return a hash of the network."""
        return hash((self.id, self.network))


class MACAddressField(FrozenModel):
    """Represents a MAC address."""

    address: str

    @validator("address", pre=True)
    def validate_and_format_mac(cls, v: str) -> str:
        """Validate and normalize MAC address to 'aa:bb:cc:dd:ee:ff' format.

        :param v: The input MAC address string.
        :raises ValueError: If the input does not match the expected MAC address pattern.
        :returns: The normalized MAC address.
        """
        # Validate input format
        if not _mac_regex.match(v):
            raise ValueError("Invalid MAC address format")

        # Normalize MAC address
        v = re.sub(r"[.:-]", "", v).lower()
        return ":".join(v[i : i + 2] for i in range(0, 12, 2))

    def __str__(self) -> str:
        """Return the MAC address as a string."""
        return self.address


class IPAddressField(FrozenModel):
    """Represents an IP address, automatically determines if it's IPv4 or IPv6."""

    address: IP_AddressT

    @validator("address", pre=True)
    def parse_ip_address(cls, value: str) -> IP_AddressT:
        """Parse and validate the IP address."""
        try:
            return ipaddress.ip_address(value)
        except ValueError as e:
            raise ValueError(f"Invalid IP address '{value}'.") from e

    def is_ipv4(self) -> bool:
        """Check if the IP address is IPv4."""
        return isinstance(self.address, ipaddress.IPv4Address)

    def is_ipv6(self) -> bool:
        """Check if the IP address is IPv6."""
        return isinstance(self.address, ipaddress.IPv6Address)

    def __str__(self) -> str:
        """Return the IP address as a string."""
        return str(self.address)

    def __hash__(self):
        """Return a hash of the IP address."""
        return hash(self.address)


class IPAddress(FrozenModelWithTimestamps, WithHost, APIMixin["IPAddress"]):
    """Represents an IP address with associated details."""

    id: int  # noqa: A003
    macaddress: Optional[MACAddressField] = None
    ipaddress: IPAddressField

    @validator("macaddress", pre=True, allow_reuse=True)
    def create_valid_macadress_or_none(cls, v: str):
        """Create macaddress or convert empty strings to None."""
        if v:
            return MACAddressField(address=v)

        return None

    @root_validator(pre=True)
    def convert_ip_address(cls, values: Any):
        """Convert ipaddress string to IPAddressField if necessary."""
        ip_address = values.get("ipaddress")
        if isinstance(ip_address, str):
            values["ipaddress"] = {"address": ip_address}
        return values

    @classmethod
    def get_by_ip(cls, ip: IP_AddressT) -> Union["IPAddress", None]:
        """Get an IP address object by IP address.

        :param ip: The IP address to search for.
        :returns: The IP address if found, None otherwise.
        """
        data = get_item_by_key_value(Endpoint.Ipaddresses, "ipaddress", str(ip))
        if not data:
            return None
        return cls(**data)

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

    def vlan(self) -> Optional[int]:
        """Return the VLAN of the IP address."""
        return self.network().vlan

    def ip(self) -> IP_AddressT:
        """Return the IP address."""
        return self.ipaddress.address

    def associate_mac(self, mac: Union[MACAddressField, str], force: bool = False) -> "IPAddress":
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
    def output_multiple(cls, ips: List["IPAddress"], padding: int = 14, names: bool = False):
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


class HInfo(FrozenModelWithTimestamps, WithHost):
    """Represents a HINFO record."""

    cpu: str
    os: str

    def output(self, padding: int = 14):
        """Output the HINFO record to the console."""
        OutputManager().add_line(
            "{1:<{0}}cpu={2} os={3}".format(padding, "Hinfo:", self.cpu, self.os)
        )


class CNAME(FrozenModelWithTimestamps, WithHost, WithZone, APIMixin["CNAME"]):
    """Represents a CNAME record."""

    name: HostT
    ttl: Optional[int] = None

    @validator("name", pre=True)
    def validate_name(cls, value: str) -> HostT:
        """Validate the hostname."""
        return HostT(hostname=value)

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Cnames

    def output(self, padding: int = 14) -> None:
        """Output the CNAME record to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        actual_host = self.resolve_host()
        host = actual_host.name if actual_host else "<Not found>"

        OutputManager().add_line(f"{'Cname:':<{padding}}{self.name} -> {host}")

    @classmethod
    def output_multiple(cls, cnames: List["CNAME"], padding: int = 14) -> None:
        """Output multiple CNAME records to the console.

        :param cnames: List of CNAME records to output.
        :param padding: Number of spaces for left-padding the output.
        """
        if not cnames:
            return

        for cname in cnames:
            cname.output(padding=padding)


class TXT(FrozenModelWithTimestamps, WithHost):
    """Represents a TXT record."""

    txt: str

    def output(self, padding: int = 14) -> None:
        """Output the TXT record to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        OutputManager().add_line(f"{'TXT:':<{padding}}{self.txt}")

    @classmethod
    def output_multiple(cls, txts: List["TXT"], padding: int = 14) -> None:
        """Output multiple TXT records to the console.

        :param txts: List of TXT records to output.
        :param padding: Number of spaces for left-padding the output.
        """
        if not txts:
            return

        for txt in txts:
            txt.output(padding=padding)


class MX(FrozenModelWithTimestamps, WithHost):
    """Represents a MX record."""

    mx: str
    priority: int

    def output(self, padding: int = 14) -> None:
        """Output the MX record to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        len_pri = len("Priority")
        OutputManager().add_line(
            "{1:<{0}}{2:>{3}} {4}".format(padding, "", self.priority, len_pri, self.mx)
        )

    @classmethod
    def output_multiple(cls, mxs: List["MX"], padding: int = 14) -> None:
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
    flag: Optional[str]
    service: Optional[str]
    regex: Optional[str]
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
    def headers(cls) -> List[str]:
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
    def output_multiple(cls, naptrs: List["NAPTR"], padding: int = 14) -> None:
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
    ttl: Optional[int]

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Srvs

    def output(self, padding: int = 14, host_id_name_map: Optional[Dict[int, str]] = None) -> None:
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
    def output_multiple(cls, srvs: List["Srv"], padding: int = 14) -> None:
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


class PTR_override(FrozenModelWithTimestamps, WithHost):
    """Represents a PTR override record."""

    id: int  # noqa: A003
    ipaddress: str  # For now, should be an IP address

    @classmethod
    def output_multiple(cls, ptrs: List["PTR_override"], padding: int = 14):
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
    ttl: Optional[int] = None

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Sshfps

    @classmethod
    def output_multiple(cls, sshfps: List["SSHFP"], padding: int = 14):
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
    def headers(cls) -> List[str]:
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


class Host(FrozenModelWithTimestamps, APIMixin["Host"]):
    """Model for an individual host."""

    id: int  # noqa: A003
    name: HostT
    ipaddresses: List[IPAddress]
    cnames: List[CNAME] = []
    mxs: List[MX] = []
    txts: List[TXT] = []
    ptr_overrides: List[PTR_override] = []
    hinfo: Optional[HInfo] = None
    loc: Optional[str] = None
    bacnetid: Optional[str] = None
    contact: str
    ttl: Optional[int] = None
    comment: Optional[str] = None

    # Note, we do not use WithZone here as this is optional and we resolve it differently.
    zone: Optional[int] = None

    @validator("name", pre=True)
    def validate_name(cls, value: str) -> HostT:
        """Validate the hostname."""
        return HostT(hostname=value)

    @validator("comment", pre=True, allow_reuse=True)
    def empty_string_to_none(cls, v: str):
        """Convert empty strings to None."""
        return v or None

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Hosts

    @classmethod
    def get_by_any_means(
        cls, identifier: Union[str, HostT], inform_as_cname: bool = True
    ) -> Optional["Host"]:
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

    def ipv4_addresses(self):
        """Return a list of IPv4 addresses."""
        return [ip for ip in self.ipaddresses if ip.is_ipv4()]

    def ipv6_addresses(self):
        """Return a list of IPv6 addresses."""
        return [ip for ip in self.ipaddresses if ip.is_ipv6()]

    def associate_mac_to_ip(
        self, mac: Union[MACAddressField, str], ip: Union[IPAddressField, str], force: bool = False
    ) -> "Host":
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
        new_ips: List[IPAddress] = []
        for myip in self.ipaddresses:
            current_ip = myip.model_copy()

            if myip.ipaddress.address == ip.address:
                current_ip = myip.associate_mac(mac, force=force)
                ip_found_in_host = True

            new_ips.append(current_ip)

        if not ip_found_in_host:
            cli_warning(f"IP address {ip} not found in host {self.name}.")

        return self.refetch()

    def networks(self) -> Dict[Network, List[IPAddress]]:
        """Return a dict of unique networks and a list of associated IP addresses for the host.

        :returns: A dictionary of networks and the associated IP addresses.
        """
        ret_dict: Dict[Network, List[IPAddress]] = {}

        for ip in self.ipaddresses:
            network = ip.network()
            if network not in ret_dict:
                ret_dict[network] = []

            ret_dict[network].append(ip)

        return ret_dict

    def vlans(self) -> Dict[int, List[IPAddress]]:
        """Return a dict of unique VLANs ID and a list of associated IP addresses for the host.

        IP addresses without a VLAN are assigned to VLAN 0.

        Note that this method will call self.networks() to determine the networks associated with
        the IP addresses. If you wish to report more details about what networks the IP addresses
        (ie, beyond simply the VLAN ID), use self.networks() and parse the VLAN from the network
        manually.

        :returns: A dictionary of VLAN ID and the associated IP addresses.
        """
        ret_dict: Dict[int, List[IPAddress]] = {}

        for network, ips in self.networks().items():
            vlan = network.vlan or 0
            if vlan not in ret_dict:
                ret_dict[vlan] = []

            ret_dict[vlan].extend(ips)

        return ret_dict

    def resolve_zone(
        self, accept_delegation: bool = False, validate_zone_resolution: bool = False
    ) -> Optional[Union[Zone, Delegation]]:
        """Return the zone for the host.

        :param accept_delegation: If True, accept delegation and return a Delegation object if the
                                    zone of the host is delegated. Otherwise raise a cli_warning.
        :param validate_zone_resolution: If True, validate that the resolved zone matches the
                                          expected zone ID. Fail with a cli_warning if it does not.
        """
        if not self.zone:
            return None

        data = get(Endpoint.ZoneForHost.with_id(str(self.name)))
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

    def naptrs(self) -> List[NAPTR]:
        """Return a list of NAPTR records."""
        return NAPTR.get_list_by_field("host", self.id)

    def srvs(self) -> List[Srv]:
        """Return a list of SRV records."""
        return Srv.get_list_by_field("host", self.id)

    def sshfps(self) -> List[SSHFP]:
        """Return a list of SSHFP records."""
        return SSHFP.get_list_by_field("host", self.id)

    def roles(self) -> List[Role]:
        """List all roles for the host."""
        return Role.get_list_by_field("hosts", self.id)

    def output(self, names: bool = False):
        """Output host information to the console with padding."""
        padding = 14

        output_manager = OutputManager()
        output_manager.add_line(f"{'Name:':<{padding}}{self.name}")
        output_manager.add_line(f"{'Contact:':<{padding}}{self.contact}")

        if self.comment:
            output_manager.add_line(f"{'Comment:':<{padding}}{self.comment}")

        IPAddress.output_multiple(self.ipaddresses, padding=padding, names=names)
        PTR_override.output_multiple(self.ptr_overrides, padding=padding)

        output_manager.add_line("{1:<{0}}{2}".format(padding, "TTL:", self.ttl or "(Default)"))

        MX.output_multiple(self.mxs, padding=padding)

        if self.hinfo:
            self.hinfo.output(padding=padding)

        if self.loc:
            output_manager.add_line(f"{'Loc:':<{padding}}{self.loc}")

        CNAME.output_multiple(self.cnames, padding=padding)
        TXT.output_multiple(self.txts, padding=padding)
        Srv.output_multiple(self.srvs(), padding=padding)
        NAPTR.output_multiple(self.naptrs(), padding=padding)
        SSHFP.output_multiple(self.sshfps(), padding=padding)
        Role.output_multiple(self.roles(), padding=padding)

        # output_hinfo(info["hinfo"])

        # if info["loc"]:
        #     output_loc(info["loc"])
        # for cname in info["cnames"]:
        #     output_cname(cname["name"], info["name"])
        # for txt in info["txts"]:
        #     output_txt(txt["txt"])
        # output_srv(host_id=info["id"])
        # output_naptr(info)
        # output_sshfp(info)
        # if "bacnetid" in info:
        #     output_bacnetid(info.get("bacnetid"))

        # policies = get_list("/api/v1/hostpolicy/roles/", params={"hosts__name": info["name"]})
        # output_policies([p["name"] for p in policies])

        # cli_info("printed host info for {}".format(info["name"]))

        self.output_timestamps()

    def __hash__(self):
        """Return a hash of the host."""
        return hash((self.id, self.name))


class HostList(FrozenModel):
    """Model for a list of hosts.

    This is the endpoint at /api/v1/hosts/.
    """

    results: List[Host]

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Hosts

    @classmethod
    def get(cls, params: Optional[Dict[str, Any]] = None) -> "HostList":
        """Get a list of hosts.

        :param params: Optional parameters to pass to the API.

        :returns: A HostList object.
        """
        if params is None:
            params = {}

        data = get_list(cls.endpoint(), params=params)
        return cls(results=[Host(**host) for host in data])

    @validator("results", pre=True)
    def check_results(cls, v: List[Dict[str, str]]):
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

    def count(self):
        """Return the number of results."""
        return len(self.results)

    def output_host_list(self):
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
