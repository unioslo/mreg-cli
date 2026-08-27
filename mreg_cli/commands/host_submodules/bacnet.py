"""Backnet subcommands for the host command.

Commands implemented:

    - bacnetid_add
    - bacnetid_remove
    - bacnetid_list
"""

from __future__ import annotations

import argparse

from mreg_api.models import BacnetID

from mreg_cli.client import get_client
from mreg_cli.commands.host import registry as command_registry
from mreg_cli.exceptions import (
    CreateError,
    EntityAlreadyExists,
    EntityNotFound,
    EntityOwnershipMismatch,
    InputFailure,
)
from mreg_cli.output import output_bacnetids
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag
from mreg_cli.utilities.resolution import resolve_host
from mreg_cli.utilities.shared import string_to_int


@command_registry.register_command(
    prog="bacnetid_add",
    description="Assign a BACnet ID to the host.",
    short_desc="Add BACnet ID",
    flags=[
        Flag("name", description="Name of host.", metavar="NAME"),
        Flag(
            "-id",
            description=f"ID value (0-{BacnetID.MAX_ID()})",
            flag_type=int,
            required=True,
            metavar="ID",
        ),
    ],
)
def bacnetid_add(args: argparse.Namespace) -> None:
    """Assign a BACnet ID to the host.

    :param args: argparse.Namespace (name, id)
    """
    name: str = args.name
    id_: int = args.id

    client = get_client()
    host = resolve_host(client, name)
    host_bacnet = client.bacnetid.get_by_host(host)
    if host_bacnet is not None:
        raise EntityAlreadyExists(f"{host.name} already has BACnet ID {host_bacnet.id}.")

    existing = client.bacnetid.first(id=id_)
    if existing:
        raise EntityOwnershipMismatch(
            f"BACnet ID {existing.id} is already in use by {existing.hostname}."
        )

    bacnetid = client.bacnetid.create(host=host, id=id_)
    if bacnetid and bacnetid.hostname == str(host.name):
        OutputManager().add_ok(f"Assigned BACnet ID {bacnetid.id} to {bacnetid.hostname}.")
    else:
        raise CreateError(f"Failed to assign BACnet ID {id_} to {host.name}.")


@command_registry.register_command(
    prog="bacnetid_remove",
    description="Unassign the BACnet ID from the host.",
    short_desc="Remove BACnet ID",
    flags=[
        Flag("name", description="Name of host.", metavar="NAME"),
    ],
)
def bacnetid_remove(args: argparse.Namespace) -> None:
    """Unassign the BACnet ID from the host.

    :param args: argparse.Namespace (name)
    """
    name: str = args.name

    client = get_client()
    host = resolve_host(client, name)
    host_bacnet = client.bacnetid.get_by_host(host)
    if host_bacnet is None:
        raise EntityNotFound(f"{host.name} does not have a BACnet ID assigned.")

    client.bacnetid.delete(host_bacnet)
    OutputManager().add_ok(f"Unassigned BACnet ID {host_bacnet.id} from {host.name}.")


@command_registry.register_command(
    prog="bacnetid_list",
    description="Find/list BACnet IDs and hostnames by ID.",
    short_desc="List used BACnet IDs",
    flags=[
        Flag(
            "-min",
            description=f"Minimum ID value (0-{BacnetID.MAX_ID()})",
            flag_type=int,
            metavar="MIN",
            default=0,
        ),
        Flag(
            "-max",
            description=f"Maximum ID value (0-{BacnetID.MAX_ID()})",
            flag_type=int,
            metavar="MAX",
            default=BacnetID.MAX_ID(),
        ),
    ],
)
def bacnetid_list(args: argparse.Namespace) -> None:
    """Find/list BACnet IDs and hostnames by ID.

    :param args: argparse.Namespace (min, max)
    """
    client = get_client()

    min_id = string_to_int(args.min, "Minimum ID")
    max_id = string_to_int(args.max, "Maximum ID")

    if min_id < 0:
        raise InputFailure("Minimum ID value cannot be less than 0.")

    if min_id > max_id:
        raise InputFailure("Minimum ID value cannot be greater than maximum ID value.")

    if max_id > BacnetID.MAX_ID():
        raise InputFailure(f"The maximum ID value is {BacnetID.MAX_ID()}.")

    bacnetids = client.bacnetid.list_in_range(min_id, max_id)
    if not bacnetids:
        raise EntityNotFound("No BACnet IDs found in the specified range.")

    output_bacnetids(bacnetids)
