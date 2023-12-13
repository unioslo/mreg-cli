"""Type definitions for mreg_cli."""

import ipaddress
import sys
from typing import TYPE_CHECKING, Dict, List, Optional, Union

if sys.version_info >= (3, 8):
    from typing import Literal, TypedDict

    class TimeInfo(TypedDict):
        """Type definition for time-related information in the recording entry."""

        timestamp: str
        timestamp_as_epoch: int
        runtime_in_ms: int

    class RecordingEntry(TypedDict):
        """Type definition for a recording entry."""

        command: str
        command_filter: Optional[str]
        command_filter_negate: bool
        command_issued: str
        ok: List[str]
        warning: List[str]
        error: List[str]
        output: List[str]
        api_requests: List[str]
        time: Optional[TimeInfo]

    IP_Version = Literal[4, 6]

else:
    from typing import Any

    TimeInfo = Dict[str, Any]
    RecordingEntry = Dict[str, Any]
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
