"""Sub module for the 'host' command handling CNAME records."""

from __future__ import annotations

import argparse

from mreg_cli.api.models import CNAME, Host, HostT, Zone
from mreg_cli.commands.host import registry as command_registry
from mreg_cli.log import cli_error, cli_info, cli_warning
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
    # Get host info or raise exception
    host = Host.get_by_any_means_or_raise(args.name)
    alias = HostT(hostname=args.alias)

    alias_in_use = Host.get_by_any_means(alias, inform_as_cname=False)
    if alias_in_use:
        if alias_in_use.id == host.id:
            cli_error(f"The alias {alias} is already active for {host}.")

        if alias_in_use.name.hostname != alias.hostname:
            cli_error(
                f"The alias {alias} is already in use as a CNAME for {alias_in_use.name.hostname}."
            )

        # Catchall for any other case, should not be possible.
        cli_error("The alias name is in use by an existing host. Find a new alias.")

    zone = Zone.get_from_hostname(alias)
    if not zone:
        cli_error(f"Could not find a zone for the alias {alias}.")

    CNAME.create(params={"host": str(host.id), "name": alias.hostname})
    cname = CNAME.get_by_host_and_name(host.name, alias)

    if cname:
        cli_info(f"Added CNAME {cname.name} for {host.name.hostname}.", print_msg=True)
    else:
        cli_error(f"Failed to add CNAME {alias} for {host.name.hostname}.")


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
    host = Host.get_by_any_means_or_raise(args.name)
    alias = HostT(hostname=args.alias)

    alias_as_host = Host.get_by_field("name", alias.hostname)
    if alias_as_host:
        cli_warning(f"The alias {alias} is a host, did you mix up the arguments?")

    cname = CNAME.get_by_field("name", alias.hostname)
    if not cname:
        cli_warning(f"No CNAME record found for {alias}.")

    # Handle situation where the CNAME is not associated with the host we are removing it from.
    if cname.host != host.id:
        cname_host = Host.get_by_id(cname.host)
        if not cname_host:
            cli_error(f"Could not find the host for the CNAME {alias}.")
        actual = cname_host.name.hostname
        desired = host.name.hostname
        cli_warning(f"The CNAME {cname.name} is associated with {actual}, NOT {desired}.")

    if cname.delete():
        cli_info(f"Removed CNAME {cname.name} for {host.name}.", print_msg=True)
    else:
        cli_error(f"Failed to remove CNAME {cname.name} for {host.name}.")


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
    cname = HostT(hostname=args.cname)
    host = Host.get_by_any_means_or_raise(args.host)

    cname_obj = CNAME.get_by_name(cname)

    if not cname_obj:
        cli_error(f"No CNAME record found for {cname}.")

    old_host = Host.get_by_id(cname_obj.host)
    if not old_host:
        cli_error(f"Could not find the host for the CNAME {cname}.")

    updated_cname = cname_obj.patch({"host": host.id})
    if updated_cname:
        cli_info(
            f"Moved CNAME alias {cname}: {old_host.name.hostname} -> {host.name}.", print_msg=True
        )
    else:
        cli_error(f"Failed to move CNAME alias {cname}.")


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
    Host.get_by_any_means_or_raise(args.name).output_cnames()
