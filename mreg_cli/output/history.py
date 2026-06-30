"""History output functions."""

from __future__ import annotations

from mreg_api.models.history import HistoryItem

from mreg_cli.exceptions import CliWarning, InternalError
from mreg_cli.outputmanager import OutputManager


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


def output_atom_history(name: str) -> None:
    """Output the history for an atom."""
    from mreg_cli.client import get_client  # noqa: PLC0415

    client = get_client()
    history = client.atom.history(name)
    if not history:
        raise CliWarning(f"No history found for atom {name!r}.")
    _output_history_items(name, history)


def output_role_history(name: str) -> None:
    """Output the history for a role."""
    from mreg_cli.client import get_client  # noqa: PLC0415

    client = get_client()
    history = client.role.history(name)
    if not history:
        raise CliWarning(f"No history found for role {name!r}.")
    _output_history_items(name, history)


def output_host_history(name: str) -> None:
    """Output the history for a host."""
    from mreg_cli.client import get_client  # noqa: PLC0415

    client = get_client()
    history = client.host.history(name)
    if not history:
        raise CliWarning(f"No history found for host {name!r}.")
    _output_history_items(name, history)


def output_hostgroup_history(name: str) -> None:
    """Output the history for a hostgroup."""
    from mreg_cli.client import get_client  # noqa: PLC0415

    client = get_client()
    history = client.hostgroup.history(name)
    if not history:
        raise CliWarning(f"No history found for hostgroup {name!r}.")
    _output_history_items(name, history)
