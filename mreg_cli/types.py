"""Typing definitions for mreg_cli."""

from __future__ import annotations

import argparse
import ipaddress
import logging
from collections.abc import Callable
from enum import StrEnum
from functools import lru_cache
from typing import (
    Annotated,
    Any,
    Literal,
    Mapping,
    MutableMapping,
    NamedTuple,
    Sequence,
    TypeAlias,
    TypedDict,
    TypeVar,
    Union,
)

from pydantic import (
    TypeAdapter,
    ValidationError,
    ValidationInfo,
    ValidatorFunctionWrapHandler,
    WrapValidator,
)
from pydantic_core import PydanticCustomError
from typing_extensions import TypeAliasType

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


# Source: https://docs.pydantic.dev/2.7/concepts/types/#named-recursive-types
def json_custom_error_validator(
    value: Any, handler: ValidatorFunctionWrapHandler, _info: ValidationInfo
) -> Any:
    """Simplify the error message to avoid a gross error stemming from
    exhaustive checking of all union options.
    """  # noqa: D205
    try:
        return handler(value)
    except ValidationError:
        raise PydanticCustomError(
            "invalid_json",
            "Input is not valid json",
        ) from None


Json = TypeAliasType(
    "Json",
    Annotated[
        Union[Mapping[str, "Json"], Sequence["Json"], str, int, float, bool, None],
        WrapValidator(json_custom_error_validator),
    ],
)
JsonMapping = Mapping[str, Json]
QueryParams = MutableMapping[str, str | int | None]


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
        choices: Sequence[str] | None = None,
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


class LogLevel(StrEnum):
    """Enum for log levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

    @classmethod
    def _missing_(cls, value: Any) -> LogLevel:
        """Case-insensitive lookup when normal lookup fails."""
        try:
            return LogLevel(value.upper())
        except (ValueError, TypeError):
            from mreg_cli.exceptions import InputFailure  # noqa: PLC0415

            raise InputFailure(f"Invalid log level: {value}") from None

    @classmethod
    def choices(cls) -> list[str]:
        """Return a list of all log levels as strings."""
        return [str(c) for c in list(cls)]

    def as_int(self) -> int:
        """Convert the log level to an integer."""
        # logging.getLevelName considered a mistake - let's implement our own
        _nameToLevel = {
            self.CRITICAL: logging.CRITICAL,
            self.ERROR: logging.ERROR,
            self.WARNING: logging.WARNING,
            self.INFO: logging.INFO,
            self.DEBUG: logging.DEBUG,
        }
        return _nameToLevel[self]


T = TypeVar("T")


@lru_cache(maxsize=100)
def get_type_adapter(t: type[T]) -> TypeAdapter[T]:
    """Get the type adapter for a given type.

    :param t: The type to get the adapter for.
    :returns: The type adapter.

    """
    return TypeAdapter(t)
