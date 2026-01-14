"""Pydantic models for the mreg_cli package."""

from __future__ import annotations

import ipaddress
import logging
from datetime import date, datetime, timedelta
from functools import cached_property
from typing import (
    Any,
    Callable,
    ClassVar,
    Iterable,
    Literal,
    Protocol,
    Self,
    Sequence,
    TypeVar,
    cast,
    overload,
)

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
)
from pydantic import ValidationError as PydanticValidationError
from typing_extensions import Unpack

from mreg_cli.api.abstracts import (
    APIMixin,
    FrozenModel,
    FrozenModelWithTimestamps,
    TTLMixin,
    TimestampMixin,
)
from mreg_cli.api.endpoints import Endpoint
from mreg_cli.api.fields import HostName, MacAddress, NameList
from mreg_cli.api.history import HistoryItem, HistoryResource
from mreg_cli.choices import CommunitySortOrder
from mreg_cli.exceptions import (
    APIError,
    CreateError,
    DeleteError,
    EntityAlreadyExists,
    EntityNotFound,
    EntityOwnershipMismatch,
    ForceMissing,
    InputFailure,
    InternalError,
    InvalidIPAddress,
    InvalidIPv4Address,
    InvalidIPv6Address,
    InvalidNetwork,
    IPNetworkWarning,
    MultipleEntitiesFound,
    PatchError,
    UnexpectedDataError,
    ValidationError,
)
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import IP_AddressT, IP_NetworkT, IP_Version, QueryParams
from mreg_cli.utilities.api import (
    delete,
    get,
    get_item_by_key_value,
    get_list_in,
    get_list_unique,
    get_typed,
    patch,
    post,
)
from mreg_cli.utilities.shared import convert_wildcard_to_regex
from mreg_cli.utilities.validators import is_valid_category_tag, is_valid_location_tag
import mreg_api.models

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

        return Host.model_validate(data)


class WithZone(BaseModel, APIMixin):
    """Model for an object that has a zone element."""

    zone: int

    def resolve_zone(self) -> ForwardZone | None:
        """Resolve the zone ID to a (Forward)Zone object.

        Notes
        -----
            - This method will call the API to resolve the zone ID to a Zone object.
            - This assumes that there is a zone attribute in the object.

        """
        data = get_item_by_key_value(Endpoint.ForwardZones, "id", str(self.zone))

        if not data:
            return None

        return ForwardZone.model_validate(data)


class WithTTL(BaseModel, APIMixin):
    """Model for an object that needs to work with TTL values."""

    _ttl_nullable: ClassVar[bool] = True
    """TTL field(s) of model are nullable."""

    @property
    def MAX_TTL(self) -> int:
        """Return the maximum TTL value."""
        return 68400

    @property
    def MIN_TTL(self) -> int:
        """Return the minimum TTL value."""
        return 300

    def output_ttl(self, label: str = "TTL", field: str = "ttl", padding: int = 14) -> None:
        """Output a TTL value.

        :param padding: Number of spaces for left-padding the output.
        :param field: The field to output (defaults to 'ttl')
        """
        if not hasattr(self, field):
            raise InternalError(f"Outputting TTL field {field} failed, field not found in object.")

        ttl_value = getattr(self, field)
        label = f"{label.removesuffix(':')}:"
        OutputManager().add_line("{1:<{0}}{2}".format(padding, label, ttl_value or "(Default)"))

    def set_ttl(self, ttl: str | int | None, field: str | None = None) -> Self:
        """Set a new TTL for the object and returns the updated object.

        Updates the `ttl` field of the object unless a different field name
        is specified.

        :param ttl: The TTL value to set. Can be an integer, "default", or None.
        :param field: The field to set the TTL value in.
        :raises InputFailure: If the TTL value is outside the bounds.
        :returns: The updated object.
        """
        # NOTE: could add some sort of validation that model has `field`
        ttl_field = field or "ttl"

        # str args can either be numeric or "default"
        # Turn it into an int or None
        if isinstance(ttl, str):
            if self._ttl_nullable and ttl == "default":
                ttl = None
            else:
                try:
                    ttl = int(ttl)
                except ValueError as e:
                    raise InputFailure(f"Invalid TTL value: {ttl}") from e

        if isinstance(ttl, int):
            ttl = self.valid_numeric_ttl(ttl)

        return self.patch({ttl_field: ttl})

    def valid_numeric_ttl(self, ttl: int) -> int:
        """Return a valid TTL value.

        Valid TTL values are: 300 - 68400.

        :param ttl: The TTL target to set.
        :raises InputFailure: If the TTL value is outside the bounds.
        :returns: A valid TTL vale
        """
        if ttl < self.MIN_TTL or ttl > self.MAX_TTL:
            raise InputFailure(f"Invalid TTL value: {ttl} ({self.MIN_TTL}->{self.MAX_TTL})")

        return ttl


class WithName(BaseModel, APIMixin):
    """Mixin type for an object that has a name element."""

    __name_field__: str = "name"
    """Name of the API field that holds the object's name."""

    __name_lowercase__: bool = False
    """Lower case name in API requests."""

    @classmethod
    def _case_name(cls, name: str) -> str:
        """Set the name case based on the class attribute."""
        return name.lower() if cls.__name_lowercase__ else name

    @classmethod
    def get_by_name(cls, name: str) -> Self | None:
        """Get a resource by name.

        :param name: The resource name to search for.
        :returns: The resource if found.
        """
        return cls.get_by_field(cls.__name_field__, cls._case_name(name))

    @classmethod
    def get_by_name_and_raise(cls, name: str) -> None:
        """Get a resource by name, raising EntityAlreadyExists if found.

        :param name: The resource name to search for.
        :raises EntityAlreadyExists: If the resource is found.
        """
        return cls.get_by_field_and_raise(cls.__name_field__, cls._case_name(name))

    @classmethod
    def get_by_name_or_raise(cls, name: str) -> Self:
        """Get a resource by name, raising EntityNotFound if not found.

        :param name: The resource name to search for.
        :returns: The resource.
        :raises EntityNotFound: If the resource is not found.
        """
        return cls.get_by_field_or_raise(cls.__name_field__, cls._case_name(name))

    @classmethod
    def get_list_by_name_regex(cls, name: str) -> list[Self]:
        """Get multiple resources by a name regex.

        :param name: The regex pattern for names to search for.
        :returns: A list of resource objects.
        """
        param, value = convert_wildcard_to_regex(cls.__name_field__, cls._case_name(name), True)
        return get_typed(cls.endpoint(), list[cls], params={param: value})

    def rename(self, new_name: str) -> Self:
        """Rename the resource.

        :param new_name: The new name to set.
        :returns: The patched resource.
        """
        return self.patch({self.__name_field__: self._case_name(new_name)})


ClassVarNotSet = object()


def AbstractClassVar() -> Any:
    """Hack to implement an abstract class variable on a Pydantic model."""
    return ClassVarNotSet


class WithHistory(BaseModel, APIMixin):
    """Resource that supports history lookups.

    Subclasses must implement the `history_resource` class variable.
    """

    history_resource: ClassVar[HistoryResource] = AbstractClassVar()

    def __init_subclass__(cls, **kwargs: Unpack[ConfigDict]):
        """Ensure that subclasses implement the history_resource class var."""
        # NOTE: Only works for Pydantic model subclasses!
        for attr in cls.__class_vars__:
            if getattr(cls, attr) == ClassVarNotSet:
                raise NotImplementedError(
                    f"Subclass {cls.__name__} must implement abstract class var `{attr}`."
                )
        return super().__init_subclass__(**kwargs)

    @classmethod
    def get_history(cls, name: str) -> list[HistoryItem]:
        """Get the history for the object."""
        return HistoryItem.get(name, cls.history_resource)

    @classmethod
    def output_history(cls, name: str) -> None:
        """Output the history for the object."""
        history = cls.get_history(name)
        HistoryItem.output_multiple(name, history)


class NameServer(FrozenModelWithTimestamps, WithTTL):
    """Model for representing a nameserver within a DNS zone."""

    id: int  # noqa: A003
    name: str

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.Nameservers


class Permission(FrozenModelWithTimestamps, APIMixin):
    """Model for a permission object."""

    id: int  # noqa: A003
    group: str
    range: IP_NetworkT  # noqa: A003
    regex: str
    labels: list[int]

    @field_validator("range", mode="before")
    @classmethod
    def validate_ip_or_network(cls, value: Any) -> IP_NetworkT:
        """Validate and convert the input to a network."""
        try:
            return ipaddress.ip_network(value)
        except ValueError as e:
            raise InputFailure(f"Invalid input for network: {value}") from e

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.PermissionNetgroupRegex

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

    def add_label(self, label_name: str) -> Self:
        """Add a label to the permission.

        :param label_name: The name of the label to add.
        :returns: The updated Permission object.
        """
        label = Label.get_by_name_or_raise(label_name)
        if label.id in self.labels:
            raise EntityAlreadyExists(f"The permission already has the label {label_name!r}")

        label_ids = self.labels.copy()
        label_ids.append(label.id)
        return self.patch({"labels": label_ids})

    def remove_label(self, label_name: str) -> Self:
        """Remove a label from the permission.

        :param label_name: The name of the label to remove.
        :returns: The updated Permission object.
        """
        label = Label.get_by_name_or_raise(label_name)
        if label.id not in self.labels:
            raise EntityNotFound(f"The permission does not have the label {label_name!r}")

        label_ids = self.labels.copy()
        label_ids.remove(label.id)
        return self.patch({"labels": label_ids})


def is_reverse_zone_name(name: str) -> bool:
    """Determine if a zone is a reverse zone by its name.

    :param name: The name of the zone.
    :returns: True if the zone is a reverse zone.
    """
    return name.endswith(".arpa")


class Zone(FrozenModelWithTimestamps, WithTTL, APIMixin):
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

    # Specify that TTL fields are NOT nullable for Zone objects
    _ttl_nullable: ClassVar[bool] = False

    def is_delegated(self) -> bool:
        """Return True if the zone is delegated."""
        return False

    def is_reverse(self) -> bool:
        """Return True if the zone is a reverse zone."""
        return is_reverse_zone_name(self.name)

    # Default to forward zone endpoints for the base class
    # This can be overridden in the subclasses
    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.ForwardZones

    @classmethod
    def endpoint_nameservers(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.ForwardZonesNameservers

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
    def output_zones(cls, forward: bool, reverse: bool) -> None:
        """Output all zones of the given type(s)."""
        # Determine types of zones to list
        zones_types: list[type[Zone]] = []
        if forward:
            zones_types.append(ForwardZone)
        if reverse:
            zones_types.append(ReverseZone)

        # Fetch all zones of the given type(s)
        zones: list[Zone] = []
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

    def ensure_delegation_in_zone(self, name: str) -> None:
        """Ensure a delegation is in the zone.

        :param name: The name of the delegation to check.
        :returns: True if the delegation is in the zone.
        """
        if not name.endswith(f".{self.name}"):
            raise InputFailure(f"Delegation '{name}' is not in '{self.name}'")

    @classmethod
    def type_by_name(cls, name: str) -> type[ForwardZone | ReverseZone]:
        """Determine the zone type based on the name.

        :param name: The name of the zone.
        :returns: The zone type.
        """
        if is_reverse_zone_name(name):
            return ReverseZone
        return ForwardZone

    @classmethod
    def verify_nameservers(cls, nameservers: list[str], force: bool = False) -> None:
        """Verify that nameservers are in mreg and have A-records."""
        if not nameservers:
            raise InputFailure("At least one nameserver is required")

        errors: list[str] = []
        for nameserver in nameservers:
            try:
                host = Host.get_by_any_means_or_raise(nameserver)
            except EntityNotFound:
                if not force:
                    errors.append(f"{nameserver} is not in mreg, must force")
            else:
                if host.zone is None:
                    if not host.ipaddresses and not force:
                        errors.append(f"{nameserver} has no A-record/glue, must force")
        if errors:
            raise ForceMissing("\n".join(errors))

    @classmethod
    def create_zone(
        cls,
        name: str,
        email: str,
        primary_ns: list[str],
        force: bool,
    ) -> ForwardZone | ReverseZone | None:
        """Create a forward or reverse zone based on zone name.

        :param name: The name of the zone to create.
        :param email: The email address for the zone.
        :param primary_ns: The primary nameserver for the zone.
        :returns: The created zone object.
        """
        cls.verify_nameservers(primary_ns, force=force)
        zone_t = cls.type_by_name(name)
        zone_t.get_zone_and_raise(name)
        return zone_t.create({"name": name, "email": email, "primary_ns": primary_ns})

    @classmethod
    def get_zone(cls, name: str) -> ForwardZone | ReverseZone | None:
        """Get a zone by name.

        :param name: The name of the zone to get.
        :returns: The zone object.
        """
        zone_t = cls.type_by_name(name)
        return zone_t.get_by_name(name)

    @classmethod
    def get_zone_or_raise(cls, name: str) -> ForwardZone | ReverseZone:
        """Get a zone by name, and raise if not found.

        :param name: The name of the zone to get.
        :returns: The zone object.
        """
        zone_t = cls.type_by_name(name)
        return zone_t.get_by_name_or_raise(name)

    @classmethod
    def get_zone_and_raise(cls, name: str) -> None:
        """Get a zone by name, and raise if found.

        :param name: The name of the zone to get.
        """
        zone_t = cls.type_by_name(name)
        return zone_t.get_by_name_and_raise(name)

    def get_subzones(self) -> list[Self]:
        """Get subzones of the zone, excluding self.

        :returns: A list of subzones.
        """
        zones = self.get_list_by_field("name__endswith", f".{self.name}")
        return [zone for zone in zones if zone.name != self.name]

    def ensure_deletable(self) -> None:
        """Ensure the zone can be deleted. Raises exception if not.

        :raises DeleteError: If zone has entries or subzones.
        """
        # XXX: Not a fool proof check, as e.g. SRVs are not hosts. (yet.. ?)
        hosts = Host.get_list_by_field("zone", self.id)
        if hosts:
            raise DeleteError(f"Zone has {len(hosts)} registered entries. Can not delete.")

        zones = self.get_subzones()
        if zones:
            names = ", ".join(zone.name for zone in zones)
            raise DeleteError(f"Zone has registered subzones: '{names}'. Can not delete")

    def delete_zone(self, force: bool) -> bool:
        """Delete the zone.

        :param force: Whether to force the deletion.
        :returns: True if the deletion was successful.
        """
        if not force:
            self.ensure_deletable()
        return self.delete()

    def update_soa(
        self,
        primary_ns: str | None = None,
        email: str | None = None,
        serialno: int | None = None,
        refresh: int | None = None,
        retry: int | None = None,
        expire: int | None = None,
        soa_ttl: int | None = None,
    ) -> Self:
        """Update SOA (Start of Authority) record for the zone.

        :param primary_ns: The primary nameserver for the zone.
        :param email: The email address for the zone.
        :param serialno: The serial number for the zone.
        :param refresh: The refresh interval for the zone.
        :param retry: The retry interval for the zone.
        :param expire: The expire interval for the zone.
        :param soa_ttl: The TTL for the zone.
        """
        params: QueryParams = {
            "primary_ns": primary_ns,
            "email": email,
            "serialno": serialno,
            "refresh": refresh,
            "retry": retry,
            "expire": expire,
            "soa_ttl": self.valid_numeric_ttl(soa_ttl) if soa_ttl is not None else None,
        }
        params = {k: v for k, v in params.items() if v is not None}
        if not params:
            raise InputFailure("No parameters to update")
        return self.patch(params)

    def create_delegation(
        self,
        delegation: str,
        nameservers: list[str],
        comment: str,
        force: bool = False,
        fetch_after_create: bool = True,
    ) -> Delegation | None:
        """Create a delegation for the zone.

        :param delegation: The name of the delegation.
        :param nameservers: The nameservers for the delegation.
        :param comment: A comment for the delegation.
        :param force: Force creation if ns/zone doesn't exist.
        :returns: The created delegation object.
        """
        self.ensure_delegation_in_zone(delegation)
        self.verify_nameservers(nameservers, force=force)

        if not force:
            # Ensure delegated zone exists and is same type as parent zone
            delegated_zone = Zone.get_zone(delegation)
            if not delegated_zone:
                raise InputFailure(f"Zone {delegation!r} does not exist. Must force.")
            if delegated_zone.is_reverse() != self.is_reverse():
                raise InputFailure(
                    f"Delegation '{delegation}' is not a {self.__class__.__name__} zone"
                )

        self.get_delegation_and_raise(delegation)

        cls = Delegation.type_by_zone(self)
        resp = post(
            cls.endpoint().with_params(self.name),
            name=delegation,
            nameservers=nameservers,
            comment=comment,
        )
        if not resp or not resp.ok:
            raise CreateError(f"Failed to create delegation {delegation!r} in zone {self.name!r}")

        if fetch_after_create:
            return self.get_delegation_or_raise(delegation)
        return None

    def get_delegation(self, name: str) -> ForwardZoneDelegation | ReverseZoneDelegation | None:
        """Get a delegation for the zone by name.

        :param name: The name of the delegation to get.
        :returns: The delegation object if found.
        """
        self.ensure_delegation_in_zone(name)
        cls = Delegation.type_by_zone(self)
        resp = get(cls.endpoint_with_id(self, name), ok404=True)
        if not resp:
            return None
        return cls.model_validate_json(resp.text)

    def get_delegation_or_raise(self, name: str) -> ForwardZoneDelegation | ReverseZoneDelegation:
        """Get a delegation for the zone by name, raising EntityNotFound if not found.

        :param zone: The zone to search in.
        :param name: The name of the delegation to get.
        :returns: The delegation object.
        :raises EntityNotFound: If the delegation is not found.
        """
        delegation = self.get_delegation(name)
        if not delegation:
            raise EntityNotFound(f"Could not find delegation {name!r} in zone {name!r}")
        return delegation

    def get_delegation_and_raise(self, name: str) -> None:
        """Get a delegation for the zone by name, raising EntityAlreadyExists if found.

        :param zone: The zone to search in.
        :param name: The name of the delegation to get.
        :raises EntityAlreadyExists: If the delegation is found.
        """
        delegation = self.get_delegation(name)
        if delegation:
            raise EntityAlreadyExists(
                f"Zone {self.name!r} already has a delegation named {name!r}"
            )

    def get_delegations(self) -> list[ForwardZoneDelegation | ReverseZoneDelegation]:
        """Get all delegations for a zone.

        :param zone: The zone to search in.
        :param name: The name of the delegation to get.
        :returns: The delegation object.
        """
        cls = Delegation.type_by_zone(self)
        return get_typed(cls.endpoint().with_params(self.name), list[cls])

    def delete_delegation(self, name: str) -> bool:
        """Delete a delegation from the zone.

        :param delegation: The name of the delegation.
        :returns: True if the deletion was successful.
        """
        # Check if delegation exists
        self.ensure_delegation_in_zone(name)  # check name
        delegation = self.get_delegation_or_raise(name)
        resp = delete(delegation.endpoint_with_id(self, name))
        return resp.ok if resp else False

    def set_delegation_comment(self, name: str, comment: str) -> None:
        """Set the comment for a delegation.

        :param name: The name of the delegation.
        :param comment: The comment to set.
        """
        delegation = self.get_delegation_or_raise(name)
        resp = patch(delegation.endpoint_with_id(self, delegation.name), comment=comment)
        if not resp or not resp.ok:
            raise PatchError(f"Failed to update comment for delegation {delegation.name!r}")

    def set_default_ttl(self, ttl: int) -> Self:
        """Set the default TTL for the zone.

        :param ttl: The TTL to set.
        """
        return self.set_ttl(ttl, "default_ttl")

    def update_nameservers(self, nameservers: list[str], force: bool = False) -> None:
        """Update the nameservers of the zone.

        :param nameservers: The new nameservers for the zone.
        :param force: Whether to force the update.
        :returns: True if the update was successful.
        """
        self.verify_nameservers(nameservers, force=force)
        path = self.endpoint_nameservers().with_params(self.name)
        resp = patch(path, primary_ns=nameservers)
        if not resp or not resp.ok:
            raise PatchError(
                f"Failed to update nameservers for {self.__class__.__name__} {self.name!r}"
            )


class ForwardZone(Zone, WithName, APIMixin):
    """A forward zone."""

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.ForwardZones

    @classmethod
    def endpoint_nameservers(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.ForwardZonesNameservers

    @classmethod
    def get_from_hostname(cls, hostname: HostName) -> ForwardZoneDelegation | ForwardZone | None:
        """Get the zone from a hostname.

        Note: This method may return either a ForwardZoneDelegation or a ForwardZone object.

        :param hostname: The hostname to search for.
        :returns: The zone if found, None otherwise.
        """
        resp = get(Endpoint.ForwardZoneForHost.with_id(hostname), ok404=True)
        if not resp:
            return None

        zoneblob = resp.json()

        if "delegate" in zoneblob:
            return ForwardZoneDelegation.model_validate(zoneblob)

        if "zone" in zoneblob:
            return ForwardZone.model_validate(zoneblob["zone"])

        if "delegation" in zoneblob:
            return ForwardZoneDelegation.model_validate(zoneblob["delegation"])

        raise UnexpectedDataError(f"Unexpected response from server: {zoneblob}", resp)


class ReverseZone(Zone, WithName, APIMixin):
    """A reverse zone."""

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.ReverseZones

    @classmethod
    def endpoint_nameservers(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.ReverseZonesNameservers


class Delegation(FrozenModelWithTimestamps, WithZone):
    """A delegated zone."""

    id: int  # noqa: A003
    nameservers: list[NameServer]
    name: str
    comment: str | None = None

    # NOTE: Delegations are created through zone objects!
    # Call Zone.create_delegation() on an existing zone to create one.
    # We do not implement APIMixin here, since we cannot determine
    # the path and type of a delegation to create without information
    # about the zone in which to create it.

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.ForwardZonesDelegations

    @classmethod
    def endpoint_with_id(cls, zone: Zone, name: str) -> str:
        """Return the path to a delegation in a specific zone."""
        if cls.is_reverse():
            endpoint = Endpoint.ReverseZonesDelegationsZone
        else:
            endpoint = Endpoint.ForwardZonesDelegationsZone
        return endpoint.with_params(zone.name, name)

    def is_delegated(self) -> bool:
        """Return True if the zone is delegated."""
        return True

    @classmethod
    def is_reverse(cls) -> bool:
        """Return True if the delegation is for a reverse zone."""
        return False

    @classmethod
    def type_by_zone(cls, zone: Zone) -> type[ForwardZoneDelegation | ReverseZoneDelegation]:
        """Get the delegation type for a zone."""
        if zone.is_reverse():
            return ReverseZoneDelegation
        return ForwardZoneDelegation


class ForwardZoneDelegation(Delegation, APIMixin):
    """A forward zone delegation."""

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.ForwardZonesDelegations


class ReverseZoneDelegation(Delegation, APIMixin):
    """A reverse zone delegation."""

    @classmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the class."""
        return Endpoint.ReverseZonesDelegations

    @classmethod
    def is_reverse(cls) -> bool:
        """Return True if the delegation is for a reverse zone."""
        return True


class HostPolicy(TimestampMixin):
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
    def output_multiple(cls, txts: Sequence[mreg_api.models.TXT], padding: int = 14) -> None:
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
            hostgroups = [HostGroup.model_validate(hg) for hg in hostgroups]
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
            network = Network.model_validate(network)
            for ip in ips:
                ip = IPAddress.model_validate(ip)
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

                    if ip:
                        ip_to_community[ip] = com.community

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
