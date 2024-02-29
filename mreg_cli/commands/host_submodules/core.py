"""Core commands for the host sub-module.

Commands implemented:

    - add
    - remove
    - rename
    - info
    - find
    - set_comment
    - set_contact
"""

import argparse
from typing import Dict, List, Optional, Union

from mreg_cli.commands.host import registry as command_registry
from mreg_cli.exceptions import HostNotFoundWarning
from mreg_cli.log import cli_info, cli_warning
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag
from mreg_cli.utilities.api import delete, get, get_list, patch, post
from mreg_cli.utilities.history import format_history_items, get_history_items
from mreg_cli.utilities.host import (
    assoc_mac_to_ip,
    clean_hostname,
    cname_exists,
    get_host_by_name,
    get_requested_ip,
    host_info_by_name,
    host_info_by_name_or_ip,
)
from mreg_cli.utilities.network import get_network_by_ip, ips_are_in_same_vlan
from mreg_cli.utilities.output import output_host_info, output_ip_info
from mreg_cli.utilities.shared import convert_wildcard_to_regex, format_mac
from mreg_cli.utilities.validators import is_valid_email, is_valid_ip, is_valid_mac
from mreg_cli.utilities.zone import zone_check_for_hostname

#########################################
#  Implementation of sub command 'add'  #
#########################################


@command_registry.register_command(
    prog="add",
    description=(
        "Add a new host with the given name, ip or network and contact. comment is optional."
    ),
    short_desc="Add a new host",
    flags=[
        Flag(
            "name",
            short_desc="Name of new host (req)",
            description="Name of new host (req)",
        ),
        Flag(
            "-ip",
            short_desc="An ip or net",
            description=(
                "The hosts ip or a network. If it's a network the first free IP is "
                "selected from the network"
            ),
            metavar="IP/NET",
        ),
        Flag(
            "-contact",
            short_desc="Contact mail for the host",
            description="Contact mail for the host",
        ),
        Flag("-comment", short_desc="A comment.", description="A comment."),
        Flag("-macaddress", description="Mac address", metavar="MACADDRESS"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def add(args: argparse.Namespace) -> None:
    """Add a new host with the given name.

    :param args: argparse.Namespace (name, ip, contact, comment, force, macaddress)
    """
    # Fail if given host exists

    ip = None
    name = clean_hostname(args.name)
    try:
        name = get_host_by_name(name)
    except HostNotFoundWarning:
        pass
    else:
        cli_warning("host {} already exists".format(name))

    if "*" in name and not args.force:
        cli_warning("Wildcards must be forced.")

    zone_check_for_hostname(name, args.force)

    if cname_exists(name):
        cli_warning("the name is already in use by a cname")

    if args.macaddress is not None and not is_valid_mac(args.macaddress):
        cli_warning("invalid MAC address: {}".format(args.macaddress))

    if args.ip:
        ip = get_requested_ip(args.ip, args.force)

    # Contact sanity check
    if args.contact and not is_valid_email(args.contact):
        cli_warning(
            "invalid mail address ({}) when trying to add {}".format(args.contact, args.name)
        )

    # Create the new host with an ip address
    path = "/api/v1/hosts/"
    data = {
        "name": name,
        "contact": args.contact or None,
        "comment": args.comment or None,
    }
    if args.ip and ip:
        data["ipaddress"] = ip

    post(path, params=None, **data)
    if args.macaddress is not None:
        # It can only be one, as it was just created.
        ipdata = get(f"{path}{name}").json()["ipaddresses"][0]
        assoc_mac_to_ip(args.macaddress, ipdata, force=args.force)
    msg = f"created host {name}"
    if args.ip:
        msg += f" with IP {ip}"
    cli_info(msg, print_msg=True)


@command_registry.register_command(
    prog="remove",
    description="Remove the given host.",
    short_desc="Remove a host",
    flags=[
        Flag(
            "name",
            short_desc="Name or ip.",
            description="Name of host or an ip belonging to the host.",
            metavar="NAME/IP",
        ),
        Flag("-force", action="store_true", description="Enable force."),
        Flag(
            "-override",
            short_desc="Comma separated override list, requires -force.",
            description=(
                "Comma separated overrides for forced removal. Requires -force."
                "Accepted overrides: 'cname', 'ipadress', 'mx', 'srv', 'ptr', 'naptr'."
                "Example usage: '-override cname,ipaddress,mx'"
            ),
            metavar="OVERRIDE",
        ),
    ],
)
def remove(args: argparse.Namespace) -> None:
    """Remove host.

    :param args: argparse.Namespace (name, force, override)
    """
    # Get host info or raise exception
    info = host_info_by_name_or_ip(args.name)
    overrides: List[str] = args.override.split(",") if args.override else []

    accepted_overrides = ["cname", "ipaddress", "mx", "srv", "ptr", "naptr"]
    for override in overrides:
        if override not in accepted_overrides:
            cli_warning(f"Invalid override: {override}. Accepted overrides: {accepted_overrides}")

    def forced(override_required: Optional[str] = None) -> bool:
        # If we require an override, check if it's in the list of provided overrides.
        if override_required:
            return override_required in overrides

        # We didn't require an override, so we only need to check for force.
        if args.force:
            return True

        # And the fallback is "no".
        return False

    warnings: List[str] = []
    # Require force if host has any cnames.
    if info["cnames"] and not args.force:
        warnings.append(f"  {len(info['cnames'])} cnames, override with 'cname'")
        for cname in info["cnames"]:
            warnings.append(f"    - {cname['name']}")

    # Require force if host has multiple A/AAAA records and they are not in the same VLAN.
    if len(info["ipaddresses"]) > 1:
        same_vlan = ips_are_in_same_vlan([ip["ipaddress"] for ip in info["ipaddresses"]])

        if same_vlan and not forced():
            warnings.append("  multiple ipaddresses on the same VLAN. Must use 'force'.")
        elif not same_vlan and not forced("ipaddresses"):
            warnings.append(
                "  {} ipaddresses on distinct VLANs, override with 'ipadress'".format(
                    len(info["ipaddresses"])
                )
            )
            for ip in info["ipaddresses"]:
                vlan = get_network_by_ip(ip["ipaddress"]).get("vlan")
                warnings.append(f"   - {ip['ipaddress']} (vlan: {vlan})")

    if info["mxs"] and not forced("mx"):
        warnings.append(f"  {len(info['mxs'])} MX records, override with 'mx'")
        for mx in info["mxs"]:
            warnings.append(f"    - {mx['mx']} (priority: {mx['priority']})")

    # Require force if host has any NAPTR records. Delete the NAPTR records if
    # force
    path = "/api/v1/naptrs/"
    naptrs = get_list(path, params={"host": info["id"]})
    if len(naptrs) > 0:
        if not forced("naptr"):
            warnings.append("  {} NAPTR records, override with 'naptr'".format(len(naptrs)))
            for naptr in naptrs:
                warnings.append(f"    - {naptr['replacement']}")
        else:
            for naptr in naptrs:
                cli_info(
                    "deleted NAPTR record {} when removing {}".format(
                        naptr["replacement"],
                        info["name"],
                    )
                )

    # Require force if host has any SRV records. Delete the SRV records if force
    path = "/api/v1/srvs/"
    srvs = get_list(path, params={"host__name": info["name"]})
    if len(srvs) > 0:
        if not forced("srv"):
            warnings.append(f"  {len(srvs)} SRV records, override with 'srv'")
            for srv in srvs:
                warnings.append(f"    - {srv['name']}")
        else:
            for srv in srvs:
                cli_info(
                    "deleted SRV record {} when removing {}".format(
                        srv["name"],
                        info["name"],
                    )
                )

    # Require force if host has any PTR records. Delete the PTR records if force
    if len(info["ptr_overrides"]) > 0:
        if not forced("ptr"):
            warnings.append(f"  {len(info['ptr_overrides'])} PTR records, override with 'ptr'")
            for ptr in info["ptr_overrides"]:
                warnings.append(f"    - {ptr['ipaddress']}")
        else:
            for ptr in info["ptr_overrides"]:
                cli_info(
                    "deleted PTR record {} when removing {}".format(
                        ptr["ipaddress"],
                        info["name"],
                    )
                )

    # To be able to undo the delete the ipaddress field of the 'old_data' has to
    # be an ipaddress string
    if len(info["ipaddresses"]) > 0:
        info["ipaddress"] = info["ipaddresses"][0]["ipaddress"]

    # Warn user and raise exception if any force requirements was found
    if warnings:
        warn_msg = "\n".join(warnings)
        cli_warning(
            "{} requires force and override for deletion:\n{}".format(info["name"], warn_msg)
        )

    # Delete host
    path = f"/api/v1/hosts/{info['name']}"
    delete(path)
    cli_info("removed {}".format(info["name"]), print_msg=True)


@command_registry.register_command(
    prog="info_pydantic",
    description="Print info about one or more hosts.",
    short_desc="Print info about one or more hosts.",
    flags=[
        Flag(
            "hosts",
            description="One or more hosts given by their name, ip or mac.",
            short_desc="One or more names, ips or macs.",
            nargs="+",
            metavar="NAME/IP/MAC",
        )
    ],
)
def host_info_pydantic(args: argparse.Namespace) -> None:
    """Print information about host."""
    import mreg_cli.api as api

    host = api.get_host(args.hosts[0])
    host.output_host_info()


@command_registry.register_command(
    prog="info",
    description="Print info about one or more hosts.",
    short_desc="Print info about one or more hosts.",
    flags=[
        Flag(
            "hosts",
            description="One or more hosts given by their name, ip or mac.",
            short_desc="One or more names, ips or macs.",
            nargs="+",
            metavar="NAME/IP/MAC",
        )
    ],
)
def host_info(args: argparse.Namespace) -> None:
    """Print information about host.

    If <name> is an alias the cname hosts info is shown.

    :param args: argparse.Namespace (hosts)
    """
    for name_or_ip in args.hosts:
        # Get host info or raise exception
        if is_valid_ip(name_or_ip):
            output_ip_info(name_or_ip)
        elif is_valid_mac(name_or_ip):
            mac = format_mac(name_or_ip)
            ret = get_list("api/v1/hosts/", params={"ipaddresses__macaddress": mac})
            if ret:
                output_host_info(ret[0])
            else:
                cli_warning(f"Found no host with macaddress: {mac}")
        else:
            info = host_info_by_name(name_or_ip)
            name = clean_hostname(name_or_ip)
            if any(cname["name"] == name for cname in info["cnames"]):
                OutputManager().add_line(f'{name} is a CNAME for {info["name"]}')
            output_host_info(info)


@command_registry.register_command(
    prog="find",
    description="Lists hosts matching search criteria",
    short_desc="Lists hosts matching search criteria",
    flags=[
        Flag(
            "-name",
            description="Name or part of name",
            short_desc="Name or part of name",
            metavar="NAME",
        ),
        Flag(
            "-comment",
            description="Comment or part of comment",
            short_desc="Comment or part of comment",
            metavar="COMMENT",
        ),
        Flag(
            "-contact",
            description="Contact or part of contact",
            short_desc="Contact or part of contact",
            metavar="CONTACT",
        ),
    ],
)
def find(args: argparse.Namespace) -> None:
    """List hosts maching search criteria.

    :param args: argparse.Namespace (name, comment, contact)
    """

    def _add_param(param: str, value: str) -> None:
        param, value = convert_wildcard_to_regex(param, value, True)
        params[param] = value

    if not any([args.name, args.comment, args.contact]):
        cli_warning("Need at least one search critera")

    params: Dict[str, Union[str, int]] = {
        "ordering": "name",
        "page_size": 1,
    }

    for param in ("contact", "comment", "name"):
        value = getattr(args, param)
        if value:
            _add_param(param, value)

    path = "/api/v1/hosts/"
    ret = get(path, params=params).json()

    if ret["count"] == 0:
        cli_warning("No hosts found.")
    elif ret["count"] > 500:
        cli_warning(f'Too many hits, {ret["count"]}, more than limit of 500. Refine search.')

    del params["page_size"]
    ret = get_list(path, params=params)
    max_name = max_contact = 20
    for i in ret:
        max_name = max(max_name, len(i["name"]))
        max_contact = max(max_contact, len(i["contact"]))

    def _print(name: str, contact: str, comment: str) -> None:
        OutputManager().add_line(
            "{0:<{1}} {2:<{3}} {4}".format(name, max_name, contact, max_contact, comment)
        )

    _print("Name", "Contact", "Comment")
    for i in ret:
        _print(i["name"], i["contact"], i["comment"])


@command_registry.register_command(
    prog="find_pydantic",
    description="Lists hosts matching search criteria",
    short_desc="Lists hosts matching search criteria",
    flags=[
        Flag(
            "-name",
            description="Name or part of name",
            short_desc="Name or part of name",
            metavar="NAME",
        ),
        Flag(
            "-comment",
            description="Comment or part of comment",
            short_desc="Comment or part of comment",
            metavar="CONTACT",
        ),
        Flag(
            "-contact",
            description="Contact or part of contact",
            short_desc="Contact or part of contact",
            metavar="CONTACT",
        ),
    ],
)
def find_pydantic(args: argparse.Namespace) -> None:
    """List hosts maching search criteria.

    :param args: argparse.Namespace (name, comment, contact)
    """
    import mreg_cli.api as api

    def _add_param(param: str, value: str) -> None:
        param, value = convert_wildcard_to_regex(param, value, True)
        params[param] = value

    if not any([args.name, args.comment, args.contact]):
        cli_warning("Need at least one search critera")

    params: Dict[str, Union[str, int]] = {
        "ordering": "name",
    }

    for param in ("contact", "comment", "name"):
        value = getattr(args, param)
        if value:
            _add_param(param, value)

    hostlist = api.get_hosts(params)
    hostlist.output_host_list()


@command_registry.register_command(
    prog="rename",
    description="Rename host. If the old name is an alias then the alias is renamed.",
    short_desc="Rename a host",
    flags=[
        Flag(
            "old_name",
            description=(
                "Host name of the host to rename. May be an alias. "
                "If it is an alias then the alias is renamed."
            ),
            short_desc="Existing host name.",
            metavar="OLD",
        ),
        Flag(
            "new_name",
            description="New name for the host, or alias.",
            short_desc="New name",
            metavar="NEW",
        ),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def rename(args: argparse.Namespace) -> None:
    """Rename host. If <old-name> is an alias then the alias is renamed.

    :param args: argparse.Namespace (old_name, new_name, force)
    """
    # Find old host
    old_name = get_host_by_name(args.old_name)

    # Make sure new hostname does not exist.
    new_name = clean_hostname(args.new_name)
    try:
        new_name = get_host_by_name(new_name)
    except HostNotFoundWarning:
        pass
    else:
        if not args.force:
            cli_warning("host {} already exists".format(new_name))

    if cname_exists(new_name):
        cli_warning("the name is already in use by a cname")

    # Require force if FQDN not in MREG zone
    zone_check_for_hostname(new_name, args.force)

    if "*" in new_name and not args.force:
        cli_warning("Wildcards must be forced.")

    # Rename host
    path = f"/api/v1/hosts/{old_name}"
    # Cannot redo/undo now since it changes name
    patch(path, name=new_name)

    cli_info("renamed {} to {}".format(old_name, new_name), print_msg=True)


# Add 'set_comment' as a sub command to the 'host' command
@command_registry.register_command(
    prog="set_comment",
    description="Set comment for host. If NAME is an alias the cname host is updated.",
    short_desc="Set comment.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
        Flag(
            "comment",
            description=(
                "The new comment. If it contains spaces then it must be enclosed in quotes."
            ),
            metavar="COMMENT",
        ),
    ],
)
def set_comment(args: argparse.Namespace) -> None:
    """Set comment for host. If <name> is an alias the cname host is updated.

    :param args: argparse.Namespace (name, comment)
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)
    # Update comment
    path = f"/api/v1/hosts/{info['name']}"
    patch(path, comment=args.comment)
    cli_info(
        'Updated comment of {} to "{}"'.format(info["name"], args.comment),
        print_msg=True,
    )


@command_registry.register_command(
    prog="set_contact",
    description="Set contact for host. If <name> is an alias the cname host is updated.",
    short_desc="Set contact.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
        Flag("contact", description="Mail address of the contact.", metavar="CONTACT"),
    ],
)
def set_contact(args: argparse.Namespace) -> None:
    """Set contact for host. If <name> is an alias the cname host is updated.

    :param args: argparse.Namespace (name, contact)
    """
    # Contact sanity check
    if not is_valid_email(args.contact):
        cli_warning("invalid mail address {} (target host: {})".format(args.contact, args.name))

    # Get host info or raise exception
    info = host_info_by_name(args.name)

    # Update contact information
    path = f"/api/v1/hosts/{info['name']}"
    patch(path, contact=args.contact)
    cli_info("Updated contact of {} to {}".format(info["name"], args.contact), print_msg=True)


@command_registry.register_command(
    prog="history",
    description="Show history for host.",
    short_desc="Show history.",
    flags=[
        Flag("name", description="Host name", metavar="NAME"),
    ],
)
def history(args: argparse.Namespace) -> None:
    """Show host history for name.

    :param args: argparse.Namespace (name)
    """
    hostname = clean_hostname(args.name)
    items = get_history_items(hostname, "host", data_relation="hosts")
    format_history_items(hostname, items)
