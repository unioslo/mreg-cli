"""Typing definitions for mreg_cli."""
import ipaddress
import sys
from typing import TYPE_CHECKING, Union

# Horrible heck to support Literal on Python 3.6
if sys.version_info >= (3, 7):
    from typing_extensions import Literal

    IP_Version = Literal[4, 6]
else:
    from typing import int

    IP_Version = int

IP_network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


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
