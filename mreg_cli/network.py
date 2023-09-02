import ipaddress
import urllib.parse
from argparse import Namespace
from typing import Any, Dict, Union

from .cli import Flag, cli
from .history import history
from .log import cli_error, cli_info, cli_warning
from .util import (
    convert_wildcard_to_regex,
    delete,
    get,
    get_list,
    get_network,
    get_network_reserved_ips,
    get_network_unused_count,
    get_network_unused_list,
    get_network_used_count,
    get_network_used_list,
    ipsort,
    is_valid_category_tag,
    is_valid_ip,
    is_valid_location_tag,
    is_valid_network,
    patch,
    post,
    string_to_int,
)

###################################
#  Add the main command 'network'  #
###################################

network = cli.add_command(
    prog="network",
    description="Manage networks.",
    short_desc="Manage networks",
)


def get_network_range_from_input(net: str) -> str:
    if net.endswith("/"):
        net = net[:-1]
    if is_valid_ip(net):
        network = get_network(net)
        return network["network"]
    elif is_valid_network(net):
        return net
    else:
        cli_warning("Not a valid ip or network")


# helper methods
def print_network_unused(count: int, padding: int = 25) -> None:
    "Pretty print amount of unused addresses."
    assert isinstance(count, int)
    print(
        "{1:<{0}}{2}{3}".format(
            padding, "Unused addresses:", count, " (excluding reserved adr.)"
        )
    )


def print_network_excluded_ranges(info: dict, padding: int = 25) -> None:
    if not info:
        return
    count = 0
    for i in info:
        start_ip = ipaddress.ip_address(i["start_ip"])
        end_ip = ipaddress.ip_address(i["end_ip"])
        count += int(end_ip) - int(start_ip)
        if end_ip == start_ip:
            count += 1
    print("{1:<{0}}{2} ipaddresses".format(padding, "Excluded ranges:", count))
    for i in info:
        print("{1:<{0}}{2} -> {3}".format(padding, "", i["start_ip"], i["end_ip"]))


def print_network_reserved(ip_range: str, reserved: int, padding: int = 25) -> None:
    "Pretty print ip range and reserved addresses list."
    assert isinstance(ip_range, str)
    assert isinstance(reserved, int)
    network = ipaddress.ip_network(ip_range)
    print(
        "{1:<{0}}{2} - {3}".format(
            padding, "IP-range:", network.network_address, network.broadcast_address
        )
    )
    print("{1:<{0}}{2}".format(padding, "Reserved host addresses:", reserved))
    print("{1:<{0}}{2}{3}".format(padding, "", network.network_address, " (net)"))
    res = get_network_reserved_ips(ip_range)
    res.remove(str(network.network_address))
    broadcast = False
    if str(network.broadcast_address) in res:
        res.remove(str(network.broadcast_address))
        broadcast = True
    for host in res:
        print("{1:<{0}}{2}".format(padding, "", host))
    if broadcast:
        print(
            "{1:<{0}}{2}{3}".format(
                padding, "", network.broadcast_address, " (broadcast)"
            )
        )


def print_network(info: int, text: str, padding: int = 25) -> None:
    print("{1:<{0}}{2}".format(padding, text, info))


##########################################
# Implementation of sub command 'create' #
##########################################


def create(args):
    """Create a new network."""
    frozen = True if args.frozen else False
    if args.vlan:
        string_to_int(args.vlan, "VLAN")
    if args.category and not is_valid_category_tag(args.category):
        cli_warning("Not a valid category tag")
    if args.location and not is_valid_location_tag(args.location):
        cli_warning("Not a valid location tag")

    networks_existing = get_list("/api/v1/networks/")
    for network in networks_existing:
        network_object = ipaddress.ip_network(network["network"])
        if network_object.overlaps(ipaddress.ip_network(args.network)):
            cli_warning(
                "Overlap found between new network {} and existing "
                "network {}".format(
                    ipaddress.ip_network(args.network), network["network"]
                )
            )

    post(
        "/api/v1/networks/",
        network=args.network,
        description=args.desc,
        vlan=args.vlan,
        category=args.category,
        location=args.location,
        frozen=frozen,
    )
    cli_info("created network {}".format(args.network), True)


network.add_command(
    prog="create",
    description="Create a new network",
    short_desc="Create a new network",
    callback=create,
    flags=[
        Flag("-network", description="Network.", required=True, metavar="NETWORK"),
        Flag(
            "-desc",
            description="Network description.",
            required=True,
            metavar="DESCRIPTION",
        ),
        Flag("-vlan", description="VLAN.", default=None, metavar="VLAN"),
        Flag("-category", description="Category.", default=None, metavar="Category"),
        Flag("-location", description="Location.", default=None, metavar="LOCATION"),
        Flag("-frozen", description="Set frozen network.", action="store_true"),
    ],
)


########################################
# Implementation of sub command 'info' #
########################################


def info(args):
    """Display network info."""
    for net in args.networks:
        print_network_info(net)


network.add_command(
    prog="info",
    description="Display network info for one or more networks.",
    short_desc="Display network info.",
    callback=info,
    flags=[
        Flag(
            "networks",
            description="One or more networks.",
            nargs="+",
            metavar="NETWORK",
        ),
    ],
)


def print_network_info(network_info: Union[str, Dict[str, Any]]) -> None:
    """Prints info about a network given a network address string (CIDR notation),
    or from a network info dict fetched by `get_network()`.

    If a network address string is passed in, `get_network()` is called to fetch
    information about the network with the given address.
    """
    if isinstance(network_info, str):
        addr = network_info
        ip_range = get_network_range_from_input(addr)
        network_info = get_network(ip_range)
    elif isinstance(network_info, dict):
        ip_range = network_info["network"]
    else:
        # TODO:improve error message. Possibly raise a built-in exception to signal
        # that this is not a user error?
        t = urllib.parse.quote(str(type(network_info)))  # quote to safely HTML print
        cli_warning(f"Unable to display network information about a {t} object")

    used = get_network_used_count(ip_range)
    unused = get_network_unused_count(ip_range)
    ip_network = ipaddress.ip_network(ip_range)

    # Pretty print all network info
    print_network(network_info["network"], "Network:")
    print_network(ip_network.netmask.exploded, "Netmask:")
    print_network(network_info["description"], "Description:")
    print_network(network_info["category"], "Category:")
    print_network(network_info["location"], "Location:")
    print_network(network_info["vlan"], "VLAN")
    print_network(
        network_info["dns_delegated"] if network_info["dns_delegated"] else False,
        "DNS delegated:",
    )
    print_network(network_info["frozen"] if network_info["frozen"] else False, "Frozen")
    print_network_reserved(network_info["network"], network_info["reserved"])
    print_network_excluded_ranges(network_info["excluded_ranges"])
    print_network(used, "Used addresses:")
    print_network_unused(unused)
    cli_info(f"printed network info for {ip_range}")


########################################
# Implementation of sub command 'find' #
########################################


def find(args: Namespace):
    """List networks matching search criteria."""
    args_dict = vars(args)

    ip_arg = args_dict.get("ip")

    if ip_arg:
        ip_range = get_network_range_from_input(ip_arg)
        network_info = get_network(ip_range)
        networks = [network_info]
    else:
        params = {}
        param_names = [
            "network",
            "description",
            "vlan",
            "dns_delegated",
            "category",
            "location",
            "frozen",
            "reserved",
        ]
        for name in param_names:
            value = args_dict.get(name)
            if value is None:
                continue
            param, val = convert_wildcard_to_regex(name, value)
            params[param] = val

        if not params:
            cli_warning("Need at least one search criteria")

        path = "/api/v1/networks/"
        networks = get_list(path, params)

    if not networks:
        cli_warning("No networks matching the query were found.")

    n_networks = len(networks)
    for i, nwork in enumerate(networks):
        if args.limit and i >= args.limit:
            omitted = n_networks - i
            if not args.silent:
                s = "s" if omitted > 1 else ""
                print(f"Reached limit ({args.limit}). Omitted {omitted} network{s}.")
            break
        if args.addr_only:
            print(nwork["network"])
        else:
            print_network_info(nwork)
            print()  # Blank line between networks

    if not args.silent:
        s = "s" if n_networks > 1 else ""
        print(f"Found {n_networks} network{s} matching the search criteria.")


network.add_command(
    prog="find",
    description="Search for networks based on a range of search parameters",
    short_desc="Search for networks",
    callback=find,
    flags=[
        Flag(
            "-ip",
            description="Exact IP address",
            metavar="IP",
        ),
        Flag(
            "-network",
            description="Network address",
            metavar="NETWORK",
        ),
        Flag(
            "-description",
            description="Description. Supports * as a wildcard",
            metavar="DESCRIPTION",
        ),
        Flag(
            "-vlan",
            description="VLAN",
            metavar="VLAN",
        ),
        Flag(
            "-dns_delegated",
            description="DNS delegation status (0 or 1)",
            metavar="DNS-DELEGATED",
        ),
        Flag(
            "-category",
            description="Category",
            metavar="CATEGORY",
        ),
        Flag(
            "-location",
            description="Location",
            metavar="LOCATION",
        ),
        Flag(
            "-frozen",
            description="Frozen status (0 or 1)",
            metavar="FROZEN",
        ),
        Flag(
            "-reserved",
            description="Exact number of reserved network addresses",
            metavar="RESERVED",
        ),
        Flag(
            "-addr-only",
            description="Only print network address of matching networks",
            action="store_true",
        ),
        Flag(
            "-limit",
            description="Maximum number of networks to print",
            metavar="LIMIT",
            type=int,
        ),
        Flag(
            "-silent",
            description="Do not print meta info (number of networks found, limit reached, etc.)",
            action="store_true",
        ),
    ],
)


#########################################################
# Implementation of sub command 'list_unused_addresses' #
#########################################################


def list_unused_addresses(args):
    """Lists all the unused addresses for a network."""
    ip_range = get_network_range_from_input(args.network)
    unused = get_network_unused_list(ip_range)
    if not unused:
        cli_warning(f"No free addresses remaining on network {ip_range}")

    for address in unused:
        print("{1:<{0}}".format(25, address))


network.add_command(
    prog="list_unused_addresses",
    description="Lists all the unused addresses for a network",
    short_desc="Lists unused addresses",
    callback=list_unused_addresses,
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
    ],
)


#######################################################
# Implementation of sub command 'list_used_addresses' #
#######################################################


def list_used_addresses(args):
    """Lists all the used addresses for a network."""
    ip_range = get_network_range_from_input(args.network)
    urlencoded_ip_range = urllib.parse.quote(ip_range)

    path = f"/api/v1/networks/{urlencoded_ip_range}/used_host_list"
    history.record_get(path)
    ip2host = get(path).json()
    path = f"/api/v1/networks/{urlencoded_ip_range}/ptroverride_host_list"
    history.record_get(path)
    ptr2host = get(path).json()

    ips = ipsort(set(list(ip2host.keys()) + list(ptr2host.keys())))
    if not ips:
        print(f"No used addresses on {ip_range}")
        return

    for ip in ips:
        if ip in ptr2host:
            print("{1:<{0}}{2} (ptr override)".format(25, ip, ptr2host[ip]))
        elif ip in ip2host:
            if len(ip2host[ip]) > 1:
                hosts = ",".join(ip2host[ip])
                host = f"{hosts} (NO ptr override!!)"
            else:
                host = ip2host[ip][0]
            print("{1:<{0}}{2}".format(25, ip, host))


network.add_command(
    prog="list_used_addresses",
    description="Lists all the used addresses for a network",
    short_desc="Lists all the used addresses for a network",
    callback=list_used_addresses,
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
    ],
)


##########################################
# Implementation of sub command 'remove' #
##########################################


def remove(args):
    """Remove network."""
    ipaddress.ip_network(args.network)
    host_list = get_network_used_list(args.network)
    if host_list:
        cli_warning(
            "Network contains addresses that are in use. Remove hosts "
            "before deletion"
        )

    if not args.force:
        cli_warning("Must force.")

    delete(f"/api/v1/networks/{urllib.parse.quote(args.network)}")
    cli_info("removed network {}".format(args.network), True)


network.add_command(
    prog="remove",
    description="Remove network",
    short_desc="Remove network",
    callback=remove,
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)


######################################################
# Implementation of sub command 'add_excluded_range' #
######################################################


def add_excluded_range(args):
    """Add an excluded range to a network."""
    info = get_network(args.network)
    network = info["network"]
    if not is_valid_ip(args.start_ip):
        cli_error(f"Start ipaddress {args.start_ip} not valid")
    if not is_valid_ip(args.end_ip):
        cli_error(f"End ipaddress {args.end_ip} not valid")

    path = f"/api/v1/networks/{urllib.parse.quote(network)}/excluded_ranges/"
    data = {"network": info["id"], "start_ip": args.start_ip, "end_ip": args.end_ip}
    post(path, **data)
    cli_info(f"Added exclude range to {network}", True)


network.add_command(
    prog="add_excluded_range",
    description="Add an excluded range to a network",
    short_desc="Add an excluded range to a network",
    callback=add_excluded_range,
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
        Flag("start_ip", description="Start ipaddress", metavar="STARTIP"),
        Flag("end_ip", description="End ipaddress", metavar="ENDIP"),
    ],
)


#########################################################
# Implementation of sub command 'remove_excluded_range' #
#########################################################


def remove_excluded_range(args):
    """Remove an excluded range to a network."""
    info = get_network(args.network)
    network = info["network"]

    if not is_valid_ip(args.start_ip):
        cli_error(f"Start ipaddress {args.start_ip} not valid")
    if not is_valid_ip(args.end_ip):
        cli_error(f"End ipaddress {args.end_ip} not valid")

    if not info["excluded_ranges"]:
        cli_error(f"Network {network} has no excluded ranges")

    for i in info["excluded_ranges"]:
        if i["start_ip"] == args.start_ip and i["end_ip"] == args.end_ip:
            path = f"/api/v1/networks/{urllib.parse.quote(network)}/excluded_ranges/{i['id']}"
            break
    else:
        cli_error("Found no matching exclude range.")
    delete(path)
    cli_info(f"Removed exclude range from {network}", True)


network.add_command(
    prog="remove_excluded_range",
    description="Remove an excluded range to a network",
    short_desc="Remove an excluded range to a network",
    callback=remove_excluded_range,
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
        Flag("start_ip", description="Start ipaddress", metavar="STARTIP"),
        Flag("end_ip", description="End ipaddress", metavar="ENDIP"),
    ],
)


################################################
# Implementation of sub command 'set_category' #
################################################


def set_category(args):
    """Set category tag for network."""
    network = get_network(args.network)
    if not is_valid_category_tag(args.category):
        cli_warning("Not a valid category tag")

    path = f"/api/v1/networks/{urllib.parse.quote(network['network'])}"
    patch(path, category=args.category)
    cli_info(
        "updated category tag to '{}' for {}".format(args.category, network["network"]),
        True,
    )


network.add_command(
    prog="set_category",
    description="Set category tag for network",
    short_desc="Set category tag for network",
    callback=set_category,
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
        Flag("category", description="Category tag.", metavar="CATEGORY-TAG"),
    ],
)


###################################################
# Implementation of sub command 'set_description' #
###################################################


def set_description(args):
    """Set description for network."""
    network = get_network(args.network)
    path = f"/api/v1/networks/{urllib.parse.quote(network['network'])}"
    patch(path, description=args.description)
    cli_info(
        "updated description to '{}' for {}".format(
            args.description, network["network"]
        ),
        True,
    )


network.add_command(
    prog="set_description",  # <network> <description>
    description="Set description for network",
    short_desc="Set description for network",
    callback=set_description,
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
        Flag("description", description="Network description.", metavar="DESC"),
    ],
)


#####################################################
# Implementation of sub command 'set_dns_delegated' #
#####################################################


def set_dns_delegated(args):
    """Set that DNS-administration is being handled elsewhere."""
    ip_range = get_network_range_from_input(args.network)
    get_network(ip_range)
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}"
    patch(path, dns_delegated=True)
    cli_info(f"updated dns_delegated to 'True' for {ip_range}", print_msg=True)


network.add_command(
    prog="set_dns_delegated",
    description="Set that DNS-administration is being handled elsewhere.",
    short_desc="Set that DNS-administration is being handled elsewhere.",
    callback=set_dns_delegated,
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
    ],
)


##############################################
# Implementation of sub command 'set_frozen' #
##############################################


def set_frozen(args):
    """Freeze a network."""
    ip_range = get_network_range_from_input(args.network)
    get_network(ip_range)
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}"
    patch(path, frozen=True)
    cli_info(f"updated frozen to 'True' for {ip_range}", print_msg=True)


network.add_command(
    prog="set_frozen",
    description="Freeze a network.",
    short_desc="Freeze a network.",
    callback=set_frozen,
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
    ],
)


################################################
# Implementation of sub command 'set_location' #
################################################


def set_location(args):
    """Set location tag for network."""
    ip_range = get_network_range_from_input(args.network)
    get_network(ip_range)
    if not is_valid_location_tag(args.location):
        cli_warning("Not a valid location tag")

    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}"
    patch(path, location=args.location)
    cli_info(
        "updated location tag to '{}' for {}".format(args.location, ip_range), True
    )


network.add_command(
    prog="set_location",
    description="Set location tag for network",
    short_desc="Set location tag for network",
    callback=set_location,
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
        Flag("location", description="Location tag.", metavar="LOCATION-TAG"),
    ],
)


################################################
# Implementation of sub command 'set_reserved' #
################################################


def set_reserved(args):
    """Set number of reserved hosts."""
    ip_range = get_network_range_from_input(args.network)
    get_network(ip_range)
    reserved = args.number
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}"
    patch(path, reserved=reserved)
    cli_info(f"updated reserved to '{reserved}' for {ip_range}", print_msg=True)


network.add_command(
    prog="set_reserved",
    description="Set number of reserved hosts.",
    short_desc="Set number of reserved hosts.",
    callback=set_reserved,
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
        Flag(
            "number", description="Number of reserved hosts.", type=int, metavar="NUM"
        ),
    ],
)


############################################
# Implementation of sub command 'set_vlan' #
############################################


def set_vlan(args):
    """Set VLAN for network."""
    ip_range = get_network_range_from_input(args.network)
    get_network(ip_range)
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}"
    patch(path, vlan=args.vlan)
    cli_info(f"updated vlan to {args.vlan} for {ip_range}", print_msg=True)


network.add_command(
    prog="set_vlan",  # <network> <vlan>
    description="Set VLAN for network",
    short_desc="Set VLAN for network",
    callback=set_vlan,
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
        Flag("vlan", description="VLAN.", type=int, metavar="VLAN"),
    ],
)


#######################################################
# Implementation of sub command 'unset_dns_delegated' #
#######################################################


def unset_dns_delegated(args):
    """Set that DNS-administration is not being handled elsewhere."""
    ip_range = get_network_range_from_input(args.network)
    get_network(ip_range)
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}"
    patch(path, dns_delegated=False)
    cli_info(f"updated dns_delegated to 'False' for {ip_range}", print_msg=True)


network.add_command(
    prog="unset_dns_delegated",
    description="Set that DNS-administration is not being handled elsewhere.",
    short_desc="Set that DNS-administration is not being handled elsewhere.",
    callback=unset_dns_delegated,
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
    ],
)


################################################
# Implementation of sub command 'unset_frozen' #
################################################


def unset_frozen(args):
    """Unfreeze a network."""
    ip_range = get_network_range_from_input(args.network)
    get_network(ip_range)
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}"
    patch(path, frozen=False)
    cli_info(f"updated frozen to 'False' for {ip_range}", print_msg=True)


network.add_command(
    prog="unset_frozen",
    description="Unfreeze a network.",
    short_desc="Unfreeze a network.",
    callback=unset_frozen,
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
    ],
)
