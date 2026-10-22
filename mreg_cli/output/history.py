"""History output functions."""

from __future__ import annotations

from mreg_api.models.history import HistoryItem

from mreg_cli.client import get_client
from mreg_cli.exceptions import CliWarning
from mreg_cli.outputmanager import OutputManager


def _output_object_history(item: HistoryItem) -> None:
    """Output the history item."""
    ts = item.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    OutputManager().add_line(f"{ts} [{item.user}]: {item.model} {item.action}: {item.message}")


def _output_history_items(items: list[HistoryItem]) -> None:
    """Output multiple history items."""
    for item in sorted(items, key=lambda i: i.timestamp):
        _output_object_history(item)


def output_atom_history(name: str) -> None:
    """Output the history for an atom."""
    client = get_client()
    history = client.atom.history(name)
    if not history:
        raise CliWarning(f"No history found for atom {name!r}.")
    _output_history_items(history)


def output_role_history(name: str) -> None:
    """Output the history for a role."""
    client = get_client()
    history = client.role.history(name)
    if not history:
        raise CliWarning(f"No history found for role {name!r}.")
    _output_history_items(history)


def output_host_history(name: str) -> None:
    """Output the history for a host."""
    client = get_client()
    history = client.host.history(name)
    if not history:
        raise CliWarning(f"No history found for host {name!r}.")
    _output_history_items(history)


def output_hostgroup_history(name: str) -> None:
    """Output the history for a hostgroup."""
    client = get_client()
    history = client.hostgroup.history(name)
    if not history:
        raise CliWarning(f"No history found for hostgroup {name!r}.")
    _output_history_items(history)
