from __future__ import annotations

from typing import ClassVar, Protocol

from mreg_api.models import Atom, Host, HostGroup, Role
from mreg_api.models.history import HistoryItem, HistoryResource

from mreg_cli.exceptions import InternalError
from mreg_cli.outputmanager import OutputManager


class HasHistoryResource(Protocol):
    """Protocol for classes with a history resource."""

    history_resource: ClassVar[HistoryResource]


def get_history_item_message(item: HistoryItem, _basename: str) -> str:
    """Attempt to make a history item human readable."""
    msg = ""
    action = item.action
    model = item.model
    if action in ("add", "remove"):
        if action == "add":
            direction = "to"
        elif action == "remove":
            direction = "from"
        else:
            raise InternalError(f"Unhandled history entry: {action}")
        rel = item.data["relation"][:-1]
        cls = str(item.resource)
        if "." in cls:
            cls = cls[cls.rindex(".") + 1 :]
        cls = cls.replace("HostPolicy_", "")
        cls = cls.lower()
        msg = f"{rel} {item.data['name']} {direction} {cls} {item.name}"
    elif action == "create":
        msg = ", ".join(f"{k} = '{v}'" for k, v in item.data.items())
    elif action == "update":
        if model in ("Ipaddress",):
            msg = item.data["current_data"]["ipaddress"] + ", "
        changes: list[str] = []
        for key, newval in item.data["update"].items():
            oldval = item.data["current_data"].get(key) or "not set"
            newval = newval or "not set"
            changes.append(f"{key}: {oldval} -> {newval}")
        msg += ",".join(changes)
    elif action == "destroy":
        if model == "Host":
            msg = "deleted " + item.name
        else:
            msg = ", ".join(f"{k} = '{v}'" for k, v in item.data.items())
    else:
        raise InternalError(f"Unhandled history entry: {action}")

    return msg


def _output_object_history(basename: str, item: HistoryItem) -> None:
    """Output the history item."""
    ts = item.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    msg = get_history_item_message(item, basename)
    OutputManager().add_line(f"{ts} [{item.user}]: {item.model} {item.action}: {msg}")


def _output_history_items(basename: str, items: list[HistoryItem]) -> None:
    """Output multiple history items."""
    for item in sorted(items, key=lambda i: i.timestamp):
        _output_object_history(basename, item)


def output_history(name: str, obj: type[HasHistoryResource]) -> None:
    """Output the history for the object."""
    history = HistoryItem.get(name, obj.history_resource)
    _output_history_items(name, history)


def output_atom_history(name: str) -> None:
    """Output the history for an atom."""
    output_history(name, Atom)


def output_role_history(name: str) -> None:
    """Output the history for a role."""
    output_history(name, Role)


def output_host_history(name: str) -> None:
    """Output the history for a host."""
    output_history(name, Host)


def output_hostgroup_history(name: str) -> None:
    """Output the history for a hostgroup."""
    output_history(name, HostGroup)


# NOTE: NYI? Permission does not have a history_resource field
# def output_permission_history(name: str) -> None:
#     """Output the history for a permission."""
#     output_history(name, Permission)
