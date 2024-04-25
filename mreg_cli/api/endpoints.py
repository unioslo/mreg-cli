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
    Networks = "/api/v1/networks/"
    NetworksByIP = "/api/v1/networks/ip/"
    Naptrs = "/api/v1/naptrs/"
    Srvs = "/api/v1/srvs/"
    Cnames = "/api/v1/cnames/"
    Sshfps = "/api/v1/sshfps/"
    Zones = "/api/v1/zones/"
    History = "/api/v1/history/"

    BacnetID = "/api/v1/bacnet/ids/"

    HostGroups = "/api/v1/hostgroups/"

    HostPolicyRoles = "/api/v1/hostpolicy/roles/"

    ForwardZones = f"{Zones}forward/"
    ReverseZones = f"{Zones}reverse/"
    ZoneForHost = f"{ForwardZones}hostname/"

    # Endpoints that require parameters
    NetworkFirstUnused = "/api/v1/networks/{}/first_unused/"

    def __str__(self):
        """Prevent direct usage without parameters where needed."""
        if "{}" in self.value:
            raise ValueError(f"Endpoint {self.name} requires parameters. Use `with_params`.")
        return self.value

    def requires_search_for_id(self) -> bool:
        """Return True if this endpoint requires a search for an ID."""
        return self in (Endpoint.Hosts, Endpoint.Networks)

    @hybridmethod
    def external_id_field(self) -> str:
        """Return the name of the field that holds the external ID."""
        if self in (Endpoint.Hosts, Endpoint.HostGroups):
            return "name"
        if self == Endpoint.Networks:
            return "network"
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
