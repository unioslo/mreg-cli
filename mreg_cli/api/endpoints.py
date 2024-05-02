"""API endpoints for mreg."""

from __future__ import annotations

from enum import Enum
from typing import Any, Callable
from urllib.parse import quote


class hybridmethod:
    """Decorator to allow a method to be called both as a class method and an instance method."""

    def __init__(self, func: Callable[..., Any]):
        """Initialize the hybrid method."""
        self.func = func

    def __get__(self, obj: object | None, cls: type | None = None):
        """Return a method that can be called both as a class method and an instance method."""
        if obj is None:
            return classmethod(self.func).__get__(None, cls)
        else:
            # Called on an instance, act like an instance method
            return self.func.__get__(obj)

    def __call__(self, *args: Any, **kwargs: Any):
        """Caller method."""
        return self.func(*args, **kwargs)


class Endpoint(str, Enum):
    """API endpoints."""

    Hosts = "/api/v1/hosts/"
    Ipaddresses = "/api/v1/ipaddresses/"
    Naptrs = "/api/v1/naptrs/"
    Srvs = "/api/v1/srvs/"
    Hinfos = "/api/v1/hinfos/"
    Cnames = "/api/v1/cnames/"
    Sshfps = "/api/v1/sshfps/"
    Zones = "/api/v1/zones/"
    History = "/api/v1/history/"
    Txts = "/api/v1/txts/"
    PTR_overrides = "/api/v1/ptroverrides/"
    Locs = "/api/v1/locs/"
    Mxs = "/api/v1/mxs/"
    NAPTRs = "/api/v1/naptrs/"
    HostGroups = "/api/v1/hostgroups/"

    BacnetID = "/api/v1/bacnet/ids/"

    Networks = "/api/v1/networks/"
    NetworksByIP = "/api/v1/networks/ip/"
    NetworksUsedCount = "/api/v1/networks/{}/used_count"
    NetworksUsedList = "/api/v1/networks/{}/used_list"
    NetworksUnusedCount = "/api/v1/networks/{}/unused_count"
    NetworksUnusedList = "/api/v1/networks/{}/unused_list"
    NetworksFirstUnused = "/api/v1/networks/{}/first_unused"

    HostPolicyRoles = "/api/v1/hostpolicy/roles/"
    HostPolicyAtoms = "/api/v1/hostpolicy/atoms/"

    ForwardZones = f"{Zones}forward/"
    ReverseZones = f"{Zones}reverse/"
    ForwardZoneForHost = f"{ForwardZones}hostname/"

    def __str__(self):
        """Prevent direct usage without parameters where needed."""
        if "{}" in self.value:
            raise ValueError(f"Endpoint {self.name} requires parameters. Use `with_params`.")
        return self.value

    def requires_search_for_id(self) -> bool:
        """Return True if this endpoint requires a search for an ID."""
        return self in (
            Endpoint.Hosts,
            Endpoint.Networks,
            Endpoint.Cnames,
            Endpoint.Hinfos,
            Endpoint.Locs,
            Endpoint.ForwardZones,
            Endpoint.ReverseZones,
        )

    @hybridmethod
    def external_id_field(self) -> str:
        """Return the name of the field that holds the external ID."""
        if self in (
            Endpoint.Hosts,
            Endpoint.HostGroups,
            Endpoint.Cnames,
            Endpoint.ForwardZones,
            Endpoint.ReverseZones,
        ):
            return "name"
        if self == Endpoint.Networks:
            return "network"
        if self in (Endpoint.Hinfos, Endpoint.Locs):
            return "host"
        return "id"

    def with_id(self, identity: str | int) -> str:
        """Return the endpoint with an ID."""
        id_field = quote(str(identity))

        return f"{self.value}{id_field}"

    def with_params(self, *params: str | int) -> str:
        """Construct and return an endpoint URL by inserting parameters.

        :param params: A sequence of parameters to be inserted into the URL.
        :raises ValueError: If the number of provided parameters does not match the
                            number of placeholders.
        :returns: A fully constructed endpoint URL with parameters.
        """
        placeholders_count = self.value.count("{}")
        if placeholders_count != len(params):
            raise ValueError(
                f"{self.name} endpoint expects {placeholders_count} parameters, got {len(params)}."
            )

        encoded_params = (quote(str(param)) for param in params)
        return self.value.format(*encoded_params)

    def with_query(self, query: dict[str, str]) -> str:
        """Construct and return an endpoint URL with a query string.

        :param query: A dictionary of query parameters.
        :returns: A fully constructed endpoint URL with a query string.
        """
        query_string = "&".join(f"{quote(key)}={quote(value)}" for key, value in query.items())
        return f"{self.value}?{query_string}"
