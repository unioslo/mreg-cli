"""Sub module for the 'host' command handling CNAME records."""

from __future__ import annotations

import argparse

from mreg_cli.client import get_client
from mreg_cli.commands.host import registry as command_registry
from mreg_cli.exceptions import (
    EntityAlreadyExists,
    EntityNotFound,
    EntityOwnershipMismatch,
    InputFailure,
    PatchError,
)
from mreg_cli.output.host import output_cnames
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag


@command_registry.register_command(
    prog="cname_add",
    description=(
        "Add a CNAME record to host. If NAME is an alias "
        "the cname host is used as target for ALIAS."
    ),
    short_desc="Add CNAME.",
    flags=[
        Flag("name", description="Name of target host.", metavar="NAME"),
        Flag("alias", description="Name of CNAME host.", metavar="ALIAS"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def cname_add(args: argparse.Namespace) -> None:
    """Add a CNAME record to host.

    :param args: argparse.Namespace (name, alias, force)
    """
    client = get_client()
    name: str = args.name
    alias: str = args.alias

    # Get host info or raise exception
    host = client.resolve_host(name)
    alias = client.fqdn(alias)

    alias_in_use = client.resolve_host(alias, required=False)
    if alias_in_use:
        if alias_in_use.id == host.id:
            raise EntityAlreadyExists(f"The alias {alias} is already active for {host}.")

        if alias_in_use.name != alias:
            raise EntityOwnershipMismatch(
                f"The alias {alias} is already in use as a CNAME for {alias_in_use.name}."
            )

        # Catchall for any other case, should not be possible.
        raise EntityOwnershipMismatch(
            "The alias name is in use by an existing host. Find a new alias."
        )

    zone = client.zone.get_from_host(alias)
    if not zone:
        raise EntityNotFound(f"Could not find a zone for the alias {alias}.")

    cname = client.cname.create(host=host, name=alias)
    OutputManager().add_ok(f"Added CNAME {cname.name} for {host.name}.")


@command_registry.register_command(
    prog="cname_remove",
    description="Remove CNAME record.",
    short_desc="Remove CNAME.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
        Flag("alias", description="Name of CNAME to remove.", metavar="CNAME"),
    ],
)
def cname_remove(args: argparse.Namespace) -> None:
    """Remove CNAME record.

    :param args: argparse.Namespace (name, alias)
    """
    client = get_client()
    name: str = args.name
    alias: str = args.alias

    host = client.resolve_host(name)
    alias = client.fqdn(alias)

    alias_as_host = client.host.get_by_name(alias, required=False)
    if alias_as_host:
        raise InputFailure(f"The alias {alias} is a host, did you mix up the arguments?")

    cname = client.cname.get_by_name(alias, required=False)
    if not cname:
        raise EntityNotFound(f"No CNAME record found for {alias}.")

    # Handle situation where the CNAME is not associated with the host we are removing it from.
    if cname.host != host.id:
        cname_host = client.host.get_by_id(cname.host, required=False)
        if not cname_host:
            raise EntityNotFound(f"Could not find the host for the CNAME {alias}.")
        actual = cname_host.name
        desired = host.name
        raise EntityOwnershipMismatch(
            f"The CNAME {cname.name} is associated with {actual}, NOT {desired}."
        )

    client.cname.delete(cname)
    OutputManager().add_line(f"Removed CNAME {cname.name} for {host.name}.")


@command_registry.register_command(
    prog="cname_replace",
    description="Move a CNAME record from one host to another.",
    short_desc="Replace a CNAME record.",
    flags=[
        Flag("cname", description="The CNAME to modify.", metavar="CNAME"),
        Flag("host", description="The new host for the CNAME.", metavar="HOST"),
    ],
)
def cname_replace(args: argparse.Namespace) -> None:
    """Move a CNAME entry from one host to another.

    :param args: argparse.Namespace (cname, host)
    """
    client = get_client()
    cname: str = args.cname
    host_arg: str = args.host

    cname = client.fqdn(cname)
    host = client.resolve_host(host_arg)

    cname_obj = client.cname.get_by_name(cname, required=False)
    if not cname_obj:
        raise EntityNotFound(f"No CNAME record found for {cname}.")

    old_host = client.host.get_by_id(cname_obj.host, required=False)
    if not old_host:
        raise EntityNotFound(f"Could not find the host for the CNAME {cname}.")

    client.cname.update(cname_obj, host=host)
    OutputManager().add_ok(f"Moved CNAME alias {cname}: {old_host.name} -> {host.name}.")


@command_registry.register_command(
    prog="cname_show",
    description=(
        "Show CNAME records for host. If NAME is an alias the cname hosts' aliases are shown."
    ),
    short_desc="Show CNAME records.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
    ],
)
def cname_show(args: argparse.Namespace) -> None:
    """Show CNAME records for host.

    If <name> is an alias the cname hosts aliases are shown.

    :param args: argparse.Namespace (name)
    """
    client = get_client()
    host = client.resolve_host(args.name)
    output_cnames(host.cnames, host=host)
