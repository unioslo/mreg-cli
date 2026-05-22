"""Meta/user output functions (UserInfo, ServerVersion, HealthInfo, etc.)."""

from __future__ import annotations

from typing import Iterable

from mreg_api.models import HealthInfo, ServerLibraries, ServerVersion, UserInfo, UserPermission

from mreg_cli.outputmanager import OutputManager


def output_user_info(user: UserInfo, django: bool = False) -> None:
    """Output user information.

    :param user: UserInfo to output.
    :param django: If True, include Django-specific roles.
    """
    manager = OutputManager()
    manager.add_line(f"Username: {user.username}")
    manager.add_line(f"Last login: {user.last_login or 'Never'}")

    if user.token:
        manager.add_line("Token:")
        manager.add_line(f"  Valid: {user.token.is_valid}")
        manager.add_line(f"  Created: {user.token.created}")
        manager.add_line(f"  Expires: {user.token.expire}")
        manager.add_line(f"  Last used: {user.token.last_used or 'Never'}")
        manager.add_line(f"  Lifespan: {user.token.lifespan}")
    else:
        manager.add_line("Token: None")

    if django:
        manager.add_line("Django roles:")
        manager.add_line(f"  Superuser: {user.django_status.superuser}")
        manager.add_line(f"  Staff: {user.django_status.staff}")
        manager.add_line(f"  Active: {user.django_status.active}")

    manager.add_line("Mreg roles:")
    manager.add_line(f"  Superuser: {user.mreg_status.superuser}")
    manager.add_line(f"  Admin: {user.mreg_status.admin}")
    manager.add_line(f"  Group admin: {user.mreg_status.group_admin}")
    manager.add_line(f"  Network admin: {user.mreg_status.network_admin}")
    manager.add_line(f"  Hostpolicy admin: {user.mreg_status.hostpolicy_admin}")
    manager.add_line(f"  DNS wildcard admin: {user.mreg_status.dns_wildcard_admin}")
    manager.add_line(f"  Underscore admin: {user.mreg_status.underscore_admin}")

    manager.add_line("Groups:")
    for group in user.groups:
        manager.add_line(f"  {group}")

    output_user_permissions(user.permissions)


def output_user_permissions(permissions: Iterable[UserPermission]) -> None:
    """Output user permissions.

    :param permissions: List of UserPermission objects to output.
    """
    # NOTE: this is more or less identical to `output_permissions()`
    # with the addition of printing labels.
    manager = OutputManager()
    manager.add_line("Permissions:")

    permissions_list = list(permissions)
    if not permissions_list:
        manager.add_line("  None")
        return

    OutputManager().add_formatted_table(
        ("IP range", "Group", "Reg.exp.", "Labels"),
        ("range", "group", "regex", "labels_str"),
        permissions_list,
        indent=2,
    )


def output_server_version(version: ServerVersion) -> None:
    """Output server version.

    :param version: ServerVersion to output.
    """
    manager = OutputManager()
    manager.add_line(f"mreg-server: {version.version}")


def output_server_libraries(libraries: ServerLibraries, indent: int = 4) -> None:
    """Output server libraries.

    :param libraries: ServerLibraries to output.
    :param indent: Number of spaces for indentation.
    """
    manager = OutputManager()
    if not libraries.libraries:
        return

    manager.add_line("Libraries:")
    for lib in libraries.libraries:
        manager.add_line(f"{' ' * indent}{lib.name}: {lib.version}")


def output_health_info(health: HealthInfo) -> None:
    """Output health information.

    :param health: HealthInfo to output.
    """
    manager = OutputManager()
    manager.add_line("Health Information:")
    manager.add_line(f"  Uptime: {health.heartbeat.as_str()}")
    manager.add_line(f"  LDAP: {health.ldap.status}")
