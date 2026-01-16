"""HostGroup output functions."""

from __future__ import annotations

from typing import TYPE_CHECKING, Sequence

from mreg_cli.output.base import output_timestamps
from mreg_cli.outputmanager import OutputManager

if TYPE_CHECKING:
    import mreg_api.models


def output_hostgroup(hostgroup: mreg_api.models.HostGroup, padding: int = 14) -> None:
    """Output a hostgroup.

    :param hostgroup: HostGroup to output.
    :param padding: Number of spaces for left-padding the output.
    """
    manager = OutputManager()

    parents = hostgroup.parent
    inherited: list[str] = []

    for p in hostgroup.get_all_parents():
        if p.name not in parents:
            inherited.append(p.name)

    parentlist = ", ".join(parents)
    if inherited:
        parentlist += f" (Inherits: {', '.join(inherited)})"

    output_tuples = (
        ("Name:", hostgroup.name),
        ("Description:", hostgroup.description or ""),
        ("Owners:", ", ".join(hostgroup.owners if hostgroup.owners else [])),
        ("Parents:", parentlist),
        ("Groups:", ", ".join(hostgroup.groups if hostgroup.groups else [])),
        ("Hosts:", len(hostgroup.hosts)),
    )
    for key, value in output_tuples:
        manager.add_line(f"{key:<{padding}}{value}")

    output_timestamps(hostgroup)


def output_hostgroups(
    hostgroups: Sequence[mreg_api.models.HostGroup] | Sequence[str],
    padding: int = 14,
    multiline: bool = False,
) -> None:
    """Output multiple hostgroups.

    :param hostgroups: List of HostGroup objects or group names to output.
    :param padding: Number of spaces for left-padding the output.
    :param multiline: If True, output each group on a new line.
    """
    manager = OutputManager()
    if not hostgroups:
        return

    groups: list[str] = []
    for hg in hostgroups:
        if isinstance(hg, str):
            groups.append(hg)
        else:
            groups.append(hg.name)

    if multiline:
        manager.add_line("Groups:")
        for group in groups:
            manager.add_line(f"  {group}")
    else:
        manager.add_line(f"{'Groups:':<{padding}}{', '.join(sorted(groups))}")


def output_hostgroup_members(
    hostgroup: mreg_api.models.HostGroup,
    expand: bool = False,
) -> None:
    """Output the members of a hostgroup.

    :param hostgroup: HostGroup whose members to output.
    :param expand: If True, expand to include all hosts in parent groups.
    """
    if expand:
        _output_members_expanded(hostgroup)
    else:
        _output_members(hostgroup)


def _output_members(hostgroup: mreg_api.models.HostGroup) -> None:
    """Output the members of a hostgroup (not expanded).

    :param hostgroup: HostGroup whose members to output.
    """
    manager = OutputManager()
    manager.add_formatted_line("Type", "Name")

    for group in hostgroup.groups:
        manager.add_formatted_line("group", group)

    for host in hostgroup.hosts:
        manager.add_formatted_line("host", host)


def _output_members_expanded(hostgroup: mreg_api.models.HostGroup) -> None:
    """Output the members of a hostgroup (expanded).

    :param hostgroup: HostGroup whose members to output.
    """
    manager = OutputManager()
    manager.add_formatted_line_with_source("Type", "Name", "Source")

    for parent in hostgroup.get_all_parents():
        for host in parent.hosts:
            manager.add_formatted_line_with_source("host", host, parent.name)

    for host in hostgroup.hosts:
        manager.add_formatted_line_with_source("host", host, hostgroup.name)
