"""Typing definitions for mreg_cli."""

from __future__ import annotations

import argparse
import ipaddress
from collections.abc import Callable
from typing import Any, Literal, NamedTuple, Protocol, TypeAlias, TypedDict, TypeVar

from requests.structures import CaseInsensitiveDict

CommandFunc = Callable[[argparse.Namespace], None]


class TimeInfo(TypedDict):
    """Type definition for time-related information in the recording entry."""

    timestamp: str
    timestamp_as_epoch: int
    runtime_in_ms: int


class RecordingEntry(TypedDict):
    """Type definition for a recording entry."""

    command: str
    command_filter: str | None
    command_filter_negate: bool
    command_issued: str
    ok: list[str]
    warning: list[str]
    error: list[str]
    output: list[str]
    api_requests: list[dict[str, Any]]
    time: TimeInfo | None


IP_Version: TypeAlias = Literal[4, 6]
IP_AddressT = ipaddress.IPv4Address | ipaddress.IPv6Address
IP_NetworkT = ipaddress.IPv4Network | ipaddress.IPv6Network

IP_networkTV = TypeVar("IP_networkTV", ipaddress.IPv4Network, ipaddress.IPv6Network)


# https://github.com/python/typeshed/blob/16933b838eef7be92ee02f66b87aa1a7532cee63/stdlib/argparse.pyi#L40-L43
NargsStr = Literal["?", "*", "+", "...", "A...", "==SUPPRESS=="]
NargsType = int | NargsStr


class Flag:
    """Class for flag information available to commands in the CLI."""

    def __init__(
        self,
        name: str,
        description: str = "",
        short_desc: str = "",
        nargs: NargsType | None = None,
        default: Any = None,
        flag_type: Any = None,
        choices: list[str] | None = None,
        required: bool = False,
        metavar: str | None = None,
        action: str | None = None,
    ):
        """Initialize a Flag object."""
        self.name = name
        self.short_desc = short_desc
        self.description = description
        self.nargs = nargs
        self.default = default
        self.type = flag_type
        self.choices = choices
        self.required = required
        self.metavar = metavar
        self.action = action


class Command(NamedTuple):
    """A command that can be registered with the CLI."""

    prog: str
    description: str
    short_desc: str
    callback: CommandFunc
    flags: list[Flag] | None = None


# Config
DefaultType = TypeVar("DefaultType")


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

    @property
    def headers(self) -> CaseInsensitiveDict[str]:
        """Return the dictionary of response headers."""
        ...

    @property
    def text(self) -> str:
        """Return the response body as text."""
        ...

    def json(self, **kwargs: Any) -> Any:
        """Return the response body as JSON."""
        ...
