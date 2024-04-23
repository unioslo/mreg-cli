"""Sub module for the 'host' command handling CNAME records."""

import argparse

from mreg_cli.commands.host import registry as command_registry
from mreg_cli.exceptions import HostNotFoundWarning
from mreg_cli.log import cli_error, cli_info, cli_warning
from mreg_cli.types import Flag
from mreg_cli.utilities.api import delete, patch, post
from mreg_cli.utilities.host import clean_hostname, cname_exists, host_info_by_name
from mreg_cli.utilities.output import output_cname
from mreg_cli.utilities.zone import zone_check_for_hostname


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
    info = host_info_by_name(args.name)
    alias = clean_hostname(args.alias)

    # If alias name already exist as host, abort.
    try:
        host_info_by_name(alias)
        cli_error("The alias name is in use by an existing host. Find a new alias.")
    except HostNotFoundWarning:
        pass

    # Check if cname already in use
    if cname_exists(alias):
        cli_warning("The alias is already in use.")

    # Check if the cname is in a zone controlled by mreg
    zone_check_for_hostname(alias, args.force)

    data = {"host": info["id"], "name": alias}
    # Create CNAME record
    path = "/api/v1/cnames/"
    post(path, **data)
    cli_info("Added cname alias {} for {}".format(alias, info["name"]), print_msg=True)


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
    info = host_info_by_name(args.name)
    hostname = info["name"]
    alias = clean_hostname(args.alias)

    if not info["cnames"]:
        cli_warning(f'"{hostname}" doesn\'t have any CNAME records.')

    for cname in info["cnames"]:
        if cname["name"] == alias:
            break
    else:
        cli_warning(f'"{alias}" is not an alias for "{hostname}"')

    # Delete CNAME host
    path = f"/api/v1/cnames/{alias}"
    delete(path)
    cli_info(f"Removed cname alias {alias} for {hostname}", print_msg=True)


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
    cname = clean_hostname(args.cname)
    host = clean_hostname(args.host)

    cname_info = host_info_by_name(cname)
    host_info = host_info_by_name(host)

    if cname_info["id"] == host_info["id"]:
        cli_error(f"The CNAME {cname} already points to {host}.")

    # Update CNAME record.
    data = {"host": host_info["id"], "name": cname}
    path = f"/api/v1/cnames/{cname}"
    patch(path, **data)
    cli_info(f"Moved CNAME alias {cname}: {cname_info['name']} -> {host}", print_msg=True)


@command_registry.register_command(
    prog="cname_show",
    description=(
        "Show CNAME records for host. If NAME is an alias the cname " "hosts aliases are shown."
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
    try:
        info = host_info_by_name(args.name)
        for cname in info["cnames"]:
            output_cname(cname["name"], info["name"])
        cli_info("showed cname aliases for {}".format(info["name"]))
        return
    except HostNotFoundWarning:
        cli_warning(f"No cname found for {args.name}")
