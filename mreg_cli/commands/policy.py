"""Policy commands for mreg_cli."""

from __future__ import annotations

import argparse
import itertools
from typing import Any

from mreg_api.exceptions import APIError
from mreg_api.models import Role

from mreg_cli.client import get_client
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import EntityAlreadyExists, handle_exception
from mreg_cli.output import (
    output_atoms_lines,
    output_host_policy,
    output_host_roles,
    output_role_atoms,
    output_role_hosts,
    output_roles_table,
)
from mreg_cli.output.history import output_atom_history, output_role_history
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag
from mreg_cli.utilities.resolution import resolve_host, resolve_policy

command_registry = CommandRegistry()


class PolicyCommands(BaseCommand):
    """Policy commands for the CLI."""

    def __init__(self, cli: Any) -> None:
        """Initialize the policy commands."""
        super().__init__(
            cli, command_registry, "policy", "Manage policies for hosts.", "Manage policies"
        )


@command_registry.register_command(
    prog="atom_create",
    description="Create a new atom",
    short_desc="Create a new atom",
    flags=[
        Flag("name", description="Atom name", metavar="NAME"),
        Flag("description", description="Description", metavar="DESCRIPTION"),
        Flag(
            "-created",
            description="DEPRECATED: Created date.",
            metavar="CREATED",
            hidden=True,
        ),
    ],
)
def atom_create(args: argparse.Namespace) -> None:
    """Create a new atom.

    :param args: argparse.Namespace (name, description, created)
    """
    client = get_client()
    name: str = args.name
    description: str = args.description

    # Check if atom with that name already exists
    client.atom.ensure_absent(name)
    client.atom.create(name=name, description=description)
    OutputManager().add_ok(f"Created new atom {name}")


@command_registry.register_command(
    prog="atom_delete",
    description="Delete an atom",
    short_desc="Delete an atom",
    flags=[
        Flag("name", description="Atom name", metavar="NAME"),
    ],
)
def atom_delete(args: argparse.Namespace) -> None:
    """Delete an atom.

    :param args: argparse.Namespace (name)
    """
    client = get_client()
    name: str = args.name

    atom = client.atom.get_by_name(name)
    client.atom.delete(atom)
    OutputManager().add_ok(f"Deleted atom {name}")


@command_registry.register_command(
    prog="role_create",
    description="Create a new role",
    short_desc="Create a new role",
    flags=[
        Flag("name", description="Role name", metavar="NAME"),
        Flag("description", description="Description", metavar="DESCRIPTION"),
        Flag("-created", description="DEPRECATED: Created date", hidden=True, metavar="CREATED"),
    ],
)
def role_create(args: argparse.Namespace) -> None:
    """Create a new role.

    :param args: argparse.Namespace (name, description, created)
    """
    client = get_client()
    name: str = args.name
    description: str = args.description

    # Check if role with that name already exists
    client.role.ensure_absent(name)
    client.role.create(name=name, description=description)
    OutputManager().add_ok(f"Created new role {name!r}")


@command_registry.register_command(
    prog="role_delete",
    description="Delete a role",
    short_desc="Delete a role",
    flags=[
        Flag("name", description="Role name", metavar="NAME"),
    ],
)
def role_delete(args: argparse.Namespace) -> None:
    """Delete a role.

    :param args: argparse.Namespace (name)
    """
    client = get_client()
    name: str = args.name

    role = client.role.get_by_name(name)
    client.role.delete(role)
    OutputManager().add_ok(f"Deleted role {name!r}")


@command_registry.register_command(
    prog="add_atom",
    description="Make an atom member of a role",
    short_desc="Make an atom member of a role",
    flags=[
        Flag("role", description="Role name", metavar="ROLE"),
        Flag("atom", description="Atom name", metavar="ATOM"),
    ],
)
def add_atom(args: argparse.Namespace) -> None:
    """Make an atom member of a role.

    :param args: argparse.Namespace (role, atom)
    """
    client = get_client()
    role_name: str = args.role
    atom_name: str = args.atom

    role = client.role.get_by_name(role_name)
    client.role.add_atom(role, atom_name)
    OutputManager().add_ok(f"Added atom {atom_name!r} to role {role_name!r}")


@command_registry.register_command(
    prog="remove_atom",
    description="Remove an atom member from a role",
    short_desc="Remove an atom member from a role",
    flags=[
        Flag("role", description="Role name", metavar="ROLE"),
        Flag("atom", description="Atom name", metavar="ATOM"),
    ],
)
def remove_atom(args: argparse.Namespace) -> None:
    """Remove an atom member from a role.

    :param args: argparse.Namespace (role, atom)
    """
    client = get_client()
    role_name: str = args.role
    atom_name: str = args.atom

    role = client.role.get_by_name(role_name)
    client.role.remove_atom(role, atom_name)
    OutputManager().add_ok(f"Removed atom {atom_name!r} from role {role_name!r}")


@command_registry.register_command(
    prog="info",
    description="Show info about an atom or role",
    short_desc="atom/role info",
    flags=[
        Flag("name", description="atom/role name", nargs="+", metavar="NAME"),
    ],
)
def info(args: argparse.Namespace) -> None:
    """Show info about an atom or role.

    :param args: argparse.Namespace (name)
    """
    client = get_client()
    names: list[str] = args.name
    for name in names:
        role_or_atom = resolve_policy(client, name)
        output_host_policy(role_or_atom)


@command_registry.register_command(
    prog="list_atoms",
    description="List all atoms by given filters",
    short_desc="List all atoms by given filters",
    flags=[
        Flag(
            "name",
            description="Atom name, or part of name. You can use * as a wildcard.",
            metavar="FILTER",
        ),
    ],
)
def list_atoms(args: argparse.Namespace) -> None:
    """List all atoms by given filters.

    :param args: argparse.Namespace (name)
    """
    client = get_client()
    name: str = args.name

    atoms = client.atom.list_by_name_regex(name)
    if atoms:
        output_atoms_lines(atoms)
    else:
        OutputManager().add_line("No match")


@command_registry.register_command(
    prog="list_roles",
    description="List all roles by given filters",
    short_desc="List all roles by given filters",
    flags=[
        Flag(
            "name",
            description="Role name, or part of name. You can use * as a wildcard.",
            metavar="FILTER",
        ),
    ],
)
def list_roles(args: argparse.Namespace) -> None:
    """List all roles by given filters.

    :param args: argparse.Namespace (name)
    """
    client = get_client()
    name: str = args.name

    roles = client.role.list_by_name_regex(name)
    if not roles:
        OutputManager().add_line("No match")
        return
    output_roles_table(roles)


@command_registry.register_command(
    prog="list_hosts",
    description="List hosts which use the given role",
    short_desc="List hosts which use the given role",
    flags=[
        Flag("name", description="Role name", metavar="ROLE"),
        Flag(
            "-exclude",
            description=(
                "Exclude hosts that have these roles. "
                "Supports regular expressions and multiple arguments."
            ),
            metavar="EXCLUDEROLE",
            nargs="+",
        ),
    ],
)
def list_hosts(args: argparse.Namespace) -> None:
    """List hosts which use the given role.

    :param args: argparse.Namespace (name)
    """
    client = get_client()
    name: str = args.name
    exclude: list[str] = args.exclude if args.exclude else []

    role = client.role.get_by_name(name)

    exclude_roles = list(
        itertools.chain.from_iterable(client.role.list_by_name_regex(r) for r in exclude)
    )
    output_role_hosts(role, exclude_roles=exclude_roles)


@command_registry.register_command(
    prog="list_members",
    description="List all members of a role",
    short_desc="List role members",
    flags=[
        Flag("name", description="Role name", metavar="ROLE"),
    ],
)
def list_members(args: argparse.Namespace) -> None:
    """List atom members for a role.

    :param args: argparse.Namespace (name)
    """
    client = get_client()
    name: str = args.name

    role = client.role.get_by_name(name)
    output_role_atoms(role)


@command_registry.register_command(
    prog="host_add",
    description="Add host(s) to role",
    short_desc="Add host(s) to role",
    flags=[
        Flag("role", description="role", metavar="ROLE"),
        Flag("hosts", description="hosts", nargs="+", metavar="HOST"),
    ],
)
def host_add(args: argparse.Namespace) -> None:
    """Add host(s) to role.

    :param args: argparse.Namespace (role, hosts)
    """
    client = get_client()
    role_name: str = args.role
    host_names: list[str] = args.hosts

    role = client.role.get_by_name(role_name)
    hosts = [resolve_host(client, host) for host in host_names]

    for host in hosts:
        # Best-effort approach -- try to assign roles to all hosts
        try:
            client.role.add_host(role, host.name)
            OutputManager().add_ok(f"Added host {host.name} to role {role_name!r}")
        except APIError as e:
            if e.response and e.response.status_code == 409:
                OutputManager().add_line(
                    f"Host {host.name} is already a member of role {role_name!r}"
                )
            else:
                # Print and log exception, but continue iterating
                handle_exception(e)


@command_registry.register_command(
    prog="host_copy",
    description="Copy roles from one host to another",
    short_desc="Copy roles between hosts",
    flags=[
        Flag("source", description="Source host", metavar="SOURCE"),
        Flag("destination", description="Destination host", nargs="+", metavar="DESTINATION"),
    ],
)
def host_copy(args: argparse.Namespace) -> None:
    """Copy roles from one host to another.

    :param args: argparse.Namespace (source, destination)
    """
    client = get_client()
    source_name: str = args.source
    source = resolve_host(client, source_name)
    source_roles = set(client.role.list_by_host(source))

    for destination_name in args.destination:
        destination = resolve_host(client, destination_name)
        destination_roles = set(client.role.list_by_host(destination))
        OutputManager().add_line(f"Copying roles from from {source_name} to {destination_name}")

        # Check if role already exists in destination
        for role in source_roles & destination_roles:
            OutputManager().add_line(f"    + {role.name} (existing membership)")

        # Check what roles need to be added
        for role in source_roles - destination_roles:
            client.role.add_host(role, destination.name)
            OutputManager().add_line(f"    + {role.name}")


@command_registry.register_command(
    prog="host_list",
    description="List roles for host(s)",
    short_desc="List roles for host(s)",
    flags=[
        Flag("hosts", description="hosts", nargs="+", metavar="HOST"),
    ],
)
def host_list(args: argparse.Namespace) -> None:
    """List host roles.

    :param args: argparse.Namespace (hosts)
    """
    client = get_client()
    hosts: list[str] = args.hosts

    for name in hosts:
        host = resolve_host(client, name)
        output_host_roles(host)


@command_registry.register_command(
    prog="host_remove",
    description="Remove host(s) from role",
    short_desc="Remove host(s) from role",
    flags=[
        Flag("role", description="role", metavar="ROLE"),
        Flag("hosts", description="host", nargs="+", metavar="HOST"),
    ],
)
def host_remove(args: argparse.Namespace) -> None:
    """Remove host(s) from role.

    :param args: argparse.Namespace (role, hosts)
    """
    client = get_client()
    role_name: str = args.role
    host_names: list[str] = args.hosts

    role = client.role.get_by_name(role_name)
    hosts = [resolve_host(client, host) for host in host_names]

    for host in hosts:
        client.role.remove_host(role, host.name)
        OutputManager().add_ok(f"Removed host {host.name!r} from role {role_name!r}")


@command_registry.register_command(
    prog="rename",
    description="Rename an atom or role",
    short_desc="Rename an atom or role",
    flags=[
        Flag("oldname", description="Existing name", metavar="OLDNAME"),
        Flag("newname", description="New name", metavar="NEWNAME"),
    ],
)
def rename(args: argparse.Namespace) -> None:
    """Rename an atom/role.

    :param args: argparse.Namespace (oldname, newname)
    """
    client = get_client()
    oldname: str = args.oldname
    newname: str = args.newname

    if oldname == newname:
        raise EntityAlreadyExists("Old and new names are the same")

    # Check if role or atom with the new name already exists
    if client.atom.get_by_name(newname, required=False) or client.role.get_by_name(
        newname, required=False
    ):
        raise EntityAlreadyExists(f"An atom or role named {newname!r} already exists")

    role_or_atom = resolve_policy(client, oldname)
    if isinstance(role_or_atom, Role):
        client.role.rename(role_or_atom, newname)
    else:
        client.atom.rename(role_or_atom, newname)
    OutputManager().add_ok(f"Renamed {oldname!r} to {newname!r}")


@command_registry.register_command(
    prog="set_description",
    description="Set description for an atom or role",
    short_desc="Set description for an atom or role",
    flags=[
        Flag("name", description="Name", metavar="NAME"),
        Flag("description", description="Description.", metavar="DESC"),
    ],
)
def set_description(args: argparse.Namespace) -> None:
    """Set description for atom/role.

    :param args: argparse.Namespace (name, description)
    """
    client = get_client()
    name: str = args.name
    description: str = args.description

    role_or_atom = resolve_policy(client, name)
    if isinstance(role_or_atom, Role):
        client.role.set_description(role_or_atom, description)
    else:
        client.atom.set_description(role_or_atom, description)
    OutputManager().add_ok(f"updated description to {description!r} for {name!r}")


@command_registry.register_command(
    prog="label_add",
    description="Add a label to a role",
    short_desc="Add label",
    flags=[
        Flag("label", description="Label name", metavar="LABEL"),
        Flag("role", description="Role name", metavar="ROLE"),
    ],
)
def add_label_to_role(args: argparse.Namespace) -> None:
    """Add a label to a role.

    :param args: argparse.Namespace (role, label)
    """
    client = get_client()
    role_name: str = args.role
    label_name: str = args.label

    role = client.role.get_by_name(role_name)
    client.role.add_label(role, label_name)
    OutputManager().add_ok(f"Added the label {label_name!r} to the role {role_name!r}.")


@command_registry.register_command(
    prog="label_remove",
    description="Remove a label from a role",
    short_desc="Remove label",
    flags=[
        Flag("label", description="Label name", metavar="LABEL"),
        Flag("role", description="Role name", metavar="ROLE"),
    ],
)
def remove_label_from_role(args: argparse.Namespace) -> None:
    """Remove a label from a role.

    :param args: argparse.Namespace (role, label)
    """
    client = get_client()
    role_name: str = args.role
    label_name: str = args.label

    role = client.role.get_by_name(role_name)
    client.role.remove_label(role, label_name)
    OutputManager().add_ok(f"Removed the label {label_name!r} from the role {role_name!r}.")


@command_registry.register_command(
    prog="atom_history",
    description="Show history for atom name",
    short_desc="Show history for atom name",
    flags=[
        Flag("name", description="Atom name", metavar="NAME"),
    ],
)
def atom_history(args: argparse.Namespace) -> None:
    """Show history for name.

    :param args: argparse.Namespace (name)
    """
    name: str = args.name
    output_atom_history(name)


@command_registry.register_command(
    prog="role_history",
    description="Show history for role name",
    short_desc="Show history for role name",
    flags=[
        Flag("name", description="Role name", metavar="NAME"),
    ],
)
def role_history(args: argparse.Namespace) -> None:
    """Show history for name.

    :param args: argparse.Namespace (name)
    """
    name: str = args.name

    output_role_history(name)
