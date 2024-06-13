"""Typing definitions for mreg_cli."""

from __future__ import annotations

import argparse
import ipaddress
from collections.abc import Callable
from typing import (
    Annotated,
    Any,
    Literal,
    Mapping,
    NamedTuple,
    Sequence,
    TypeAlias,
    TypedDict,
    TypeVar,
    Union,
)

from pydantic import (
    BeforeValidator,
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


def to_uppercase(v: Any) -> Any:
    """Uppercases any string arguments before validation."""
    if isinstance(v, str):
        return v.upper()
    return v


UpperCaser = BeforeValidator(to_uppercase)


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


def get_typealiastype_literals(alias: TypeAliasType) -> tuple[str, ...]:
    """Get a tuple of an annotated Literal type alias type."""
    return alias.__value__.__args__[0].__args__


LogLevel = TypeAliasType(
    "LogLevel",
    Annotated[
        Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        UpperCaser,
    ],
)


LogLevelValidator = TypeAdapter(LogLevel)
LogLevelChoices = get_typealiastype_literals(LogLevel)


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
