"""Policy commands for mreg_cli."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_cli.api.history import HistoryResource
from mreg_cli.api.models import Atom, Host, HostPolicy, Role
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.log import cli_error, cli_info, cli_warning
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag

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
        Flag("-created", description="Created date", metavar="CREATED"),
    ],
)
def atom_create(args: argparse.Namespace) -> None:
    """Create a new atom.

    :param args: argparse.Namespace (name, description, created)
    """
    name: str = args.name
    description: str = args.description
    created: str = args.created

    # Check if atom with that name already exists
    Atom.get_by_name_and_raise(name)

    params = {"name": name, "description": description}
    if created:
        params["create_date"] = created

    Atom.create(params)
    cli_info(f"Created new atom {name}", print_msg=True)


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
    name: str = args.name

    atom = Atom.get_by_name_or_raise(name)
    if atom.delete():
        cli_info(f"Deleted atom {name}", print_msg=True)
    else:
        cli_error(f"Failed to delete atom {name}")


@command_registry.register_command(
    prog="role_create",
    description="Create a new role",
    short_desc="Create a new role",
    flags=[
        Flag("name", description="Role name", metavar="NAME"),
        Flag("description", description="Description", metavar="DESCRIPTION"),
        Flag("-created", description="Created date", metavar="CREATED"),
    ],
)
def role_create(args: argparse.Namespace) -> None:
    """Create a new role.

    :param args: argparse.Namespace (name, description, created)
    """
    name: str = args.name
    description: str = args.description
    created: str = args.created

    # Check if role with that name already exists
    Role.get_by_name_and_raise(name)

    params = {"name": name, "description": description}
    if created:
        params["create_date"] = created

    Role.create(params)
    cli_info(f"Created new role {name!r}", print_msg=True)


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
    name: str = args.name

    role = Role.get_by_name_or_raise(name)
    if role.delete():
        cli_info(f"Deleted role {name!r}", print_msg=True)
    else:
        cli_error(f"Failed to delete role {name!r}")


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
    role_name: str = args.role
    atom_name: str = args.atom

    role = Role.get_by_name_or_raise(role_name)
    if role.add_atom(atom_name):
        cli_info(f"Added atom {atom_name!r} to role {role_name!r}", print_msg=True)
    else:
        cli_error(f"Failed to add atom {atom_name!r} to role {role_name!r}")


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
    role_name: str = args.role
    atom_name: str = args.atom

    role = Role.get_by_name_or_raise(role_name)
    if role.remove_atom(atom_name):
        cli_info(f"Removed atom {atom_name!r} from role {role_name!r}", print_msg=True)
    else:
        cli_error(f"Failed to remove atom {atom_name!r} from role {role_name!r}")


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
    names: list[str] = args.name
    for name in names:
        role_or_atom = HostPolicy.get_role_or_atom_or_raise(name)
        role_or_atom.output()


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
    name: str = args.name

    atoms = Atom.get_list_by_name_regex(name)
    if atoms:
        Atom.output_multiple_lines(atoms)
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
    name: str = args.name

    roles = Role.get_list_by_name_regex(name)
    if not roles:
        OutputManager().add_line("No match")
        return
    Role.output_multiple_table(roles)


@command_registry.register_command(
    prog="list_hosts",
    description="List hosts which use the given role",
    short_desc="List hosts which use the given role",
    flags=[
        Flag("name", description="Role name", metavar="ROLE"),
    ],
)
def list_hosts(args: argparse.Namespace) -> None:
    """List hosts which use the given role.

    :param args: argparse.Namespace (name)
    """
    name: str = args.name

    role = Role.get_by_name_or_raise(name)
    role.output_hosts()


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
    name: str = args.name

    role = Role.get_by_name_or_raise(name)
    role.output_atoms()


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
    role_name: str = args.role
    host_names: list[str] = args.hosts

    role = Role.get_by_name_or_raise(role_name)
    hosts = [Host.get_by_any_means_or_raise(host) for host in host_names]

    for host in hosts:
        role.add_host(host.name.hostname)
        cli_info(f"Added host {host.name!r} to role {role_name!r}", print_msg=True)


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
    hosts: list[str] = args.hosts

    for name in hosts:
        host = Host.get_by_any_means_or_raise(name)
        host.output_roles()


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
    role_name: str = args.role
    host_names: list[str] = args.hosts

    role = Role.get_by_name_or_raise(role_name)
    hosts = [Host.get_by_any_means_or_raise(host) for host in host_names]

    for host in hosts:
        role.remove_host(host.name.hostname)
        cli_info(f"Removed host {host.name!r} from role {role_name!r}", print_msg=True)


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
    oldname: str = args.oldname
    newname: str = args.newname

    if oldname == newname:
        cli_warning("Old and new names are the same")

    # Check if role or atom with the new name already exists
    HostPolicy.get_role_or_atom_and_raise(newname)

    role_or_atom = HostPolicy.get_role_or_atom_or_raise(oldname)
    role_or_atom.rename(newname)
    cli_info(f"Renamed {oldname!r} to {newname!r}", True)


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
    name: str = args.name
    description: str = args.description

    role_or_atom = HostPolicy.get_role_or_atom_or_raise(name)
    role_or_atom.set_description(description)
    cli_info(f"updated description to {description!r} for {name!r}", print_msg=True)


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
    role_name: str = args.role
    label_name: str = args.label

    role = Role.get_by_name_or_raise(role_name)
    role.add_label(label_name)
    cli_info(f"Added the label {label_name!r} to the role {role_name!r}.", print_msg=True)


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
    role_name: str = args.role
    label_name: str = args.label

    role = Role.get_by_name_or_raise(role_name)
    role.remove_label(label_name)
    cli_info(f"Removed the label {label_name!r} from the role {role_name!r}.", print_msg=True)


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

    Atom.output_history(name)


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

    Role.output_history(name)
