"""DHCP commands for mreg_cli."""
import argparse

from .cli import Flag, cli
from .exceptions import CliWarning
from .history import history
from .log import cli_info, cli_warning
from .util import format_mac, get_list, host_info_by_name, is_valid_ip, is_valid_mac, patch

#################################
#  Add the main command 'dhcp'  #
#################################

dhcp = cli.add_command(
    prog="dhcp",
    description="Manage DHCP associations.",
    short_desc="Manage DHCP",
)


def _dhcp_get_ip_by_arg(arg: str) -> str:
    """Get A/AAAA record by either ip address or host name.

    :param arg: ip address or host name (as a string)
    """
    if is_valid_ip(arg):
        path = "/api/v1/ipaddresses/"
        params = {
            "ipaddress": arg,
        }
        history.record_get(path)
        ip = get_list(path, params=params)
        if not len(ip):
            cli_warning(f"ip {arg} doesn't exist.")
        elif len(ip) > 1:
            cli_warning("ip {} is in use by {} hosts".format(arg, len(ip)))
        ip = ip[0]
    else:
        info = host_info_by_name(arg)
        if len(info["ipaddresses"]) > 1:
            cli_warning(
                "{} has {} ip addresses, please enter one of the addresses instead.".format(
                    info["name"],
                    len(info["ipaddresses"]),
                )
            )
        if len(info["ipaddresses"]) == 0:
            cli_warning(
                "{} doesn't have any ip addresses.".format(arg),
                raise_exception=True,
                exception=CliWarning,
            )
        ip = info["ipaddresses"][0]
    return ip


def assoc_mac_to_ip(mac: str, ip: str, force: bool = False) -> str:
    """Associate MAC address with IP address."""
    # MAC addr sanity check
    if is_valid_mac(mac):
        new_mac = format_mac(mac)
        path = "/api/v1/ipaddresses/"
        params = {
            "macaddress": new_mac,
            "ordering": "ipaddress",
        }
        history.record_get(path)
        macs = get_list(path, params=params)
        ips = ", ".join([i["ipaddress"] for i in macs])
        if len(macs) and not force:
            cli_warning(
                "mac {} already in use by: {}. Use force to add {} -> {} as well.".format(
                    mac, ips, ip["ipaddress"], mac
                )
            )
    else:
        cli_warning("invalid MAC address: {}".format(mac))

    old_mac = ip.get("macaddress")
    if old_mac == new_mac:
        cli_info("new and old mac are identical. Ignoring.", print_msg=True)
        return
    elif old_mac and not force:
        cli_warning(
            "ip {} has existing mac {}. Use force to replace.".format(ip["ipaddress"], old_mac)
        )

    # Update Ipaddress with a mac
    path = f"/api/v1/ipaddresses/{ip['id']}"
    history.record_patch(path, new_data={"macaddress": new_mac}, old_data=ip)
    patch(path, macaddress=new_mac)
    return new_mac


#########################################
# Implementation of sub command 'assoc' #
#########################################


def assoc(args: argparse.Namespace) -> None:
    """Associate MAC address with host.

    If host has multiple A/AAAA records an IP must be given instead of name.

    :param args: argparse.Namespace (name, mac, force)
    """
    ip = _dhcp_get_ip_by_arg(args.name)
    new_mac = assoc_mac_to_ip(args.mac, ip, force=args.force)

    if new_mac is not None:
        cli_info(
            "associated mac address {} with ip {}".format(new_mac, ip["ipaddress"]),
            print_msg=True,
        )


dhcp.add_command(
    prog="assoc",
    description=(
        "Associate MAC address with host. If host got multiple A/AAAA "
        "records an IP must be given instead of name."
    ),
    short_desc="Add MAC address to host.",
    callback=assoc,
    flags=[
        Flag("name", description="Name or IP of target host.", metavar="NAME/IP"),
        Flag("mac", description="Mac address.", metavar="MACADDRESS"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)


############################################
# Implementation of sub command 'disassoc' #
############################################


def disassoc(args: argparse.Namespace) -> None:
    """Disassociate MAC address with host/ip.

    If host has multiple A/AAAA records an IP must be given instead of name.

    :param args: argparse.Namespace (name)
    """
    ip = _dhcp_get_ip_by_arg(args.name)

    if ip.get("macaddress"):
        # Update ipaddress
        path = f"/api/v1/ipaddresses/{ip['id']}"
        history.record_patch(path, new_data={"macaddress": ""}, old_data=ip)
        patch(path, macaddress="")
        cli_info(
            "disassociated mac address {} from ip {}".format(ip["macaddress"], ip["ipaddress"]),
            print_msg=True,
        )
    else:
        cli_info(
            "ipaddress {} has no associated mac address".format(ip["ipaddress"]),
            print_msg=True,
        )


dhcp.add_command(
    prog="disassoc",
    description=(
        "Disassociate MAC address with host/ip. If host got multiple "
        "A/AAAA records an IP must be given instead of name."
    ),
    short_desc="Disassociate MAC address.",
    callback=disassoc,
    flags=[
        Flag("name", description="Name or IP of host.", metavar="NAME/IP"),
    ],
)
