"""Backnet subcommands for the host command.

Commands implemented:

    - bacnetid_add
    - bacnetid_remove
    - bacnetid_list
"""

from __future__ import annotations

import argparse

from mreg_cli.api.models import BacnetID, Host
from mreg_cli.commands.host import registry as command_registry
from mreg_cli.exceptions import (
    CreateError,
    DeleteError,
    EntityAlreadyExists,
    EntityNotFound,
    EntityOwnershipMismatch,
    InputFailure,
)
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag


@command_registry.register_command(
    prog="bacnetid_add",
    description="Assign a BACnet ID to the host.",
    short_desc="Add BACnet ID",
    flags=[
        Flag("name", description="Name of host.", metavar="NAME"),
        Flag("-id", description=f"ID value (0-{BacnetID.MAX_ID()})", metavar="ID"),
    ],
)
def bacnetid_add(args: argparse.Namespace) -> None:
    """Assign a BACnet ID to the host.

    :param args: argparse.Namespace (name, id)
    """
    host = Host.get_by_any_means_or_raise(args.name)
    host_bacnet = host.bacnet()
    if host_bacnet is not None:
        raise EntityAlreadyExists(f"{host.name} already has BACnet ID {host_bacnet.id}.")

    existing = BacnetID.get(args.id)
    if existing:
        raise EntityOwnershipMismatch(
            f"BACnet ID {existing.id} is already in use by {existing.hostname}."
        )

    BacnetID.create(params={"hostname": host.name, "id": args.id})

    validator = BacnetID.get(args.id)
    if validator and validator.hostname == host.name:
        OutputManager().add_ok(f"Assigned BACnet ID {validator.id} to {validator.hostname}.")
    else:
        raise CreateError(f"Failed to assign BACnet ID {args.id} to {host.name}.")


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
    host = Host.get_by_any_means_or_raise(args.name)
    host_bacnet = host.bacnet()
    if host_bacnet is None:
        raise EntityNotFound(f"{host.name} does not have a BACnet ID assigned.")

    if host_bacnet.delete():
        OutputManager().add_ok(f"Unassigned BACnet ID {host_bacnet.id} from {host.name}.")
    else:
        raise DeleteError(f"Failed to unassign BACnet ID {host_bacnet.id} from {host.name}.")


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
        ),
        Flag(
            "-max",
            description=f"Maximum ID value (0-{BacnetID.MAX_ID()})",
            flag_type=int,
            metavar="MAX",
        ),
    ],
)
def bacnetid_list(args: argparse.Namespace) -> None:
    """Find/list BACnet IDs and hostnames by ID.

    :param args: argparse.Namespace (min, max)
    """
    min_id = args.min if args.min is not None else 0
    max_id = args.max if args.max is not None else BacnetID.MAX_ID()

    if min_id < 0:
        raise InputFailure("Minimum ID value cannot be less than 0.")

    if min_id is not None and max_id is not None and min_id > max_id:
        raise InputFailure("Minimum ID value cannot be greater than maximum ID value.")

    if max_id is not None and max_id > BacnetID.MAX_ID():
        raise InputFailure(f"The maximum ID value is {BacnetID.MAX_ID()}.")

    bacnetids = BacnetID.get_in_range(min_id, max_id)
    if not bacnetids:
        raise EntityNotFound("No BACnet IDs found in the specified range.")

    BacnetID.output_multiple(bacnetids)
