"""Typing definitions for mreg_cli."""
import ipaddress
from typing import TYPE_CHECKING, Literal, Union

IP_network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IP_Version = Literal[4, 6]


if TYPE_CHECKING:
    from typing import Any

    from typing_extensions import Protocol

    class ResponseLike(Protocol):
        """Interface for objects that resemble a requests.Response object."""

        @property
        def ok(self) -> bool:
            """Return True if the response was successful."""
            ...

        @property
        def status_code(self) -> int:
            """Return the HTTP status code."""
            ...

        @property
        def reason(self) -> str:
            """Return the HTTP status reason."""
            ...

        def json(self, **kwargs: Any) -> Any:
            """Return the response body as JSON."""
            ...
