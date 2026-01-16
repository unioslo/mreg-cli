"""Policy output functions (Role, Atom, Label, Permission)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Sequence

from pydantic import BaseModel

from mreg_cli.output.base import output_timestamps
from mreg_cli.outputmanager import OutputManager

if TYPE_CHECKING:
    import mreg_api.models


# -----------------------------------------------------------------------------
# Host Policy (role or atom) output functions
# -----------------------------------------------------------------------------


def output_host_policy(
    host_policy: mreg_api.models.Role | mreg_api.models.Atom,
    padding: int = 14,
) -> None:
    """Output a host policy (role or atom).

    :param host_policy: Host policy to output.
    :param padding: Number of spaces for left-padding the output.
    """
    if isinstance(host_policy, mreg_api.models.Role):
        output_role(host_policy, padding)
    else:
        output_atom(host_policy, padding)


# -----------------------------------------------------------------------------
# Role output functions
# -----------------------------------------------------------------------------


def output_role(role: mreg_api.models.Role, padding: int = 14) -> None:
    """Output a role.

    :param role: Role to output.
    :param padding: Number of spaces for left-padding the output.
    """
    manager = OutputManager()
    manager.add_line(f"{'Name:':<{padding}}{role.name}")
    output_timestamps(role)
    manager.add_line(f"{'Description:':<{padding}}{role.description}")

    manager.add_line("Atom members:")
    for atom in role.atoms:
        manager.add_formatted_line("", atom, padding)
    labels = role.get_labels()
    manager.add_line("Labels:")
    for label in labels:
        manager.add_formatted_line("", label.name, padding)


def output_roles(
    roles: Sequence[mreg_api.models.Role] | Sequence[str],
    padding: int = 14,
) -> None:
    """Output multiple roles as a single line.

    :param roles: List of roles or role names to output.
    :param padding: Number of spaces for left-padding the output.
    """
    if not roles:
        return

    rolenames: list[str] = []
    for role in roles:
        if isinstance(role, str):
            rolenames.append(role)
        else:
            rolenames.append(role.name)

    OutputManager().add_line(f"{'Roles:':<{padding}}{', '.join(rolenames)}")


def output_roles_table(roles: Sequence[mreg_api.models.Role], padding: int = 14) -> None:
    """Output multiple roles in a table format.

    :param roles: List of roles to output.
    :param padding: Number of spaces for left-padding the output.
    """
    if not roles:
        return

    class RoleTableRow(BaseModel):
        name: str
        description: str
        labels: str

    rows: list[RoleTableRow] = []
    for role in roles:
        labels = role.get_labels()
        row = RoleTableRow(
            name=role.name,
            description=role.description,
            labels=", ".join([label.name for label in labels]),
        )
        rows.append(row)

    keys = list(RoleTableRow.model_fields.keys())
    headers = [h.capitalize() for h in keys]
    OutputManager().add_formatted_table(
        headers=headers,
        keys=keys,
        data=rows,
    )


def output_role_hosts(
    role: mreg_api.models.Role,
    padding: int = 14,
    exclude_roles: Sequence[mreg_api.models.Role] | None = None,
) -> None:
    """Output the hosts that use a role.

    :param role: Role whose hosts to output.
    :param padding: Number of spaces for left-padding the output.
    :param exclude_roles: List of other roles to exclude hosts with.
    """
    manager = OutputManager()
    hosts = list(role.hosts)

    if exclude_roles:
        # Exclude any hosts that are found in the excluded roles
        excluded_hosts: set[str] = set()
        for host in hosts:
            for excl_role in exclude_roles:
                if host in excl_role.hosts:
                    excluded_hosts.add(host)
                    break
        hosts = [host for host in hosts if host not in excluded_hosts]

    if hosts:
        manager.add_line("Name:")
        for host in hosts:
            manager.add_line(f" {host}")
    else:
        manager.add_line("No host uses this role")


def output_role_atoms(role: mreg_api.models.Role, padding: int = 14) -> None:
    """Output the atoms that are members of a role.

    :param role: Role whose atoms to output.
    :param padding: Number of spaces for left-padding the output.
    """
    manager = OutputManager()
    if role.atoms:
        manager.add_line("Name:")
        for atom in role.atoms:
            manager.add_line(f" {atom}")
    else:
        manager.add_line("No atom members")


# -----------------------------------------------------------------------------
# Atom output functions
# -----------------------------------------------------------------------------


def output_atom(atom: mreg_api.models.Atom, padding: int = 14) -> None:
    """Output an atom.

    :param atom: Atom to output.
    :param padding: Number of spaces for left-padding the output.
    """
    manager = OutputManager()
    manager.add_line(f"{'Name:':<{padding}}{atom.name}")
    output_timestamps(atom)
    manager.add_line(f"{'Description:':<{padding}}{atom.description}")

    manager.add_line("Roles where this atom is a member:")
    for role in atom.roles:
        manager.add_formatted_line("", role, padding)


def output_atoms(atoms: Sequence[mreg_api.models.Atom], padding: int = 14) -> None:
    """Output multiple atoms as a single line.

    :param atoms: List of atoms to output.
    :param padding: Number of spaces for left-padding the output.
    """
    if not atoms:
        return

    OutputManager().add_line(f"{'Atoms:':<{padding}}{', '.join([atom.name for atom in atoms])}")


def output_atoms_lines(atoms: Sequence[mreg_api.models.Atom], padding: int = 20) -> None:
    """Output multiple atoms, one per line.

    :param atoms: List of atoms to output.
    :param padding: Number of spaces for left-padding the output.
    """
    manager = OutputManager()
    for atom in atoms:
        manager.add_formatted_line(atom.name, f"{atom.description!r}", padding)


# -----------------------------------------------------------------------------
# Label output function
# -----------------------------------------------------------------------------


def output_label(label: mreg_api.models.Label, padding: int = 14) -> None:
    """Output a label.

    :param label: Label to output.
    :param padding: Number of spaces for left-padding the output.
    """
    # Import here to avoid circular imports
    import mreg_api.models

    short_padding = 4
    manager = OutputManager()
    manager.add_line(f"{'Name:':<{padding}}{label.name}")
    manager.add_line(f"{'Description:':<{padding}}{label.description}")
    manager.add_line("Roles with this label:")

    roles = mreg_api.models.Role.get_list_by_field("labels", label.id)
    if roles:
        for role in roles:
            manager.add_line(f"{'':<{short_padding}}{role.name}")
    else:
        manager.add_line(f"{'None':<{short_padding}}")

    permission_list = mreg_api.models.Permission.get_list_by_field("labels", label.id)

    manager.add_line("Permissions with this label:")
    if permission_list:
        output_permissions(permission_list, indent=4)
    else:
        manager.add_line(f"{'None':<{short_padding}}")


# -----------------------------------------------------------------------------
# Permission output functions
# -----------------------------------------------------------------------------


def output_permission(permission: mreg_api.models.Permission, indent: int = 4) -> None:
    """Output a single permission.

    :param permission: Permission to output.
    :param indent: Number of spaces for indentation.
    """
    # This outputs as a table row, so we use output_permissions for consistency
    output_permissions([permission], indent=indent)


def output_permissions(
    permissions: Sequence[mreg_api.models.Permission],
    indent: int = 4,
) -> None:
    """Output multiple permissions.

    :param permissions: List of permissions to output.
    :param indent: Number of spaces for indentation.
    """
    if not permissions:
        return

    OutputManager().add_formatted_table(
        ("IP range", "Group", "Reg.exp."),
        ("range", "group", "regex"),
        permissions,
        indent=indent,
    )
