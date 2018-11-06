import re
import json
import sys
import getpass
import ipaddress
import operator
from socket import inet_aton
import struct
import traceback
import typing
import types
import inspect
import requests

from config import cli_config
from exceptions import *
from history import history
from log import *

try:
    conf = cli_config(required_fields=(
        "server_ip",
        "server_port",
        "tag_file",
        "129_240_file",
        "158_36_file",
        "172_16_file",
        "193_157_file",
    ))
except Exception as e:
    print("util.py: cli_config:", e)
    traceback.print_exc()
    sys.exit(1)

location_tags = []
category_tags = []

with open(conf['tag_file'], 'r') as file:
    line_number = 1
    for line in file:
        match = re.match(r"(?P<location>[a-zA-Z0-9]+)\s+:\s+Plassering:.*", line)
        if match:
            location_tags.append(match.group('location'))
            line_number += 1
        else:
            match = re.match(r"(?P<category>[a-zA-Z0-9]+)\s+.*", line)
            if not match:
                print('ERROR in %s, wrong format on line: %d - %s\n', conf['tag_file'], line_number,
                      line)
                sys.exit(-1)
            category_tags.append(match.group('category'))
            line_number += 1


def host_exists(name: str) -> bool:
    """Checks if a host with the given name exists"""
    url = "http://{}:{}/hosts/?name={}".format(
        conf["server_ip"],
        conf["server_port"],
        name
    )
    history.record_get(url)
    hosts = get(url).json()

    # Response data sanity checks
    if len(hosts) > 1:
        cli_error("host exist check received more than one exact match for \"{}\"".format(name))
    if len(hosts) == 0:
        return False
    if hosts[0]["name"] != name:
        cli_error("host exist check received from API \"{}\" when searched for \"{}\"".format(
            hosts[0]["name"],
            name,
        ))
    return True


def host_info_by_name_or_ip(name_or_ip: str) -> dict:
    """
    Return a dict with host information about the given host, or the host owning the given ip.

    :param name_or_ip: Either a host name on short or long form or an ipv4/ipv6 address.
    :return: A dict of the JSON object received with the host information
    """
    if is_valid_ip(name_or_ip):
        name = resolve_ip(name_or_ip)
    else:
        name = name_or_ip
    return host_info_by_name(name)


def host_info_by_name(name: str, follow_cnames: bool = True) -> dict:
    """
    Return a dict with host information about the given host.

    :param name: A host name on either short or long form.
    :param follow_cnames: Indicate whether or not to follow cname relations. If True (default)
    then it will return the host with the canonical name instead of the given alias.
    :return: A dict of the JSON object received with the host information
    """
    # Get longform of name, raise exception if host doesn't exist
    name = resolve_input_name(name)

    # All host info data is returned from the API
    url = "http://{}:{}/hosts/{}".format(conf["server_ip"], conf["server_port"], name)
    history.record_get(url)
    host = get(url).json()

    # Follow CNAMEs
    if host["cname"] and follow_cnames:
        if len(host["cname"]) > 1:
            cli_error("{} has multiple CNAME records".format(name))
        return host_info_by_name(host["cname"][0]["cname"])
    else:
        return host


def available_ips_from_subnet(subnet: dict) -> list:
    """
    Returns unsed ips from the given subnet.
    Assumes subnet exists.
    :param subnet: dict with subnet info.
    :return: List of Ip address strings
    """

    unused = get_subnet_unused_list(subnet['range'])
    if not unused:
        cli_warning("No free addresses remaining on subnet {}".format(subnet['range']))
    return unused

def first_unused_ip_from_subnet(subnet: dict) -> str:
    """
    Returns the first unused ip from a given subnet.
    Assumes subnet exists.
    :param subnet: dict with subnet info.
    :return: Ip address string
    """

    unused = get_subnet_first_unused(subnet['range'])
    if not unused:
        cli_warning("No free addresses remaining on subnet {}".format(subnet['range']))
    return unused

def zone_mreg_controlled(zone: str) -> bool:
    """Return true of the zone is controlled by MREG"""
    assert isinstance(zone, str)
    url = "http://{}:{}/zones/?name={}".format(
        conf["server_ip"],
        conf["server_port"],
        zone,
    )
    history.record_get(url)
    zone = get(url).json()
    if not len(zone):
        return False
    return True


def host_in_mreg_zone(host: str) -> bool:
    """Return true if host is in a MREG controlled zone"""
    assert isinstance(host, str)
    splitted = host.split(".")
    if not len(splitted):
        return False

    url = "http://{}:{}/zones/".format(
        conf["server_ip"],
        conf["server_port"],
    )
    history.record_get(url)
    zones = get(url).json()

    s = ""
    splitted.reverse()
    for sub in splitted:
        s = "{}.{}".format(sub, s) if len(s) else sub
        for zone in zones:
            if zone["name"] == s:
                return True

    return False


def ip_in_mreg_net(ip: str) -> bool:
    """Return true if the ip is in a MREG controlled subnet"""
    assert isinstance(ip, str)
    ipaddr = ipaddress.ip_address(ip)

    url = "http://{}:{}/subnets/".format(
        conf["server_ip"],
        conf["server_port"],
    )
    history.record_get(url)
    nets = get(url).json()

    for net in nets:
        n = ipaddress.ip_network(net["range"])
        if ipaddr in n:
            return True

    return False


################################################################################
#                                                                              #
#   HTTP requests wrappers with error checking                                 #
#                                                                              #
################################################################################


def post(url: str, **kwargs) -> requests.Response:
    """Uses requests to make a post request. Assumes that all kwargs are data fields"""
    p = requests.post(url, data=kwargs)
    if not p.ok:
        message = "POST \"{}\": {}: {}".format(url, p.status_code, p.reason)
        try:
            body = p.json()
        except ValueError:
            pass
        else:
            message += "\n{}".format(json.dumps(body, indent=2))
        cli_error(message)
    return p


def patch(url: str, **kwargs) -> requests.Response:
    """Uses requests to make a patch request. Assumes that all kwargs are data fields"""
    p = requests.patch(url, data=kwargs)
    if not p.ok:
        message = "PATCH \"{}\": {}: {}".format(url, p.status_code, p.reason)
        try:
            body = p.json()
        except ValueError:
            pass
        else:
            message += "\n{}".format(json.dumps(body, indent=2))
        cli_error(message)
    return p


def delete(url: str) -> requests.Response:
    """Uses requests to make a delete request"""
    d = requests.delete(url)
    if not d.ok:
        message = "DELETE \"{}\": {}: {}".format(url, d.status_code, d.reason)
        try:
            body = d.json()
        except ValueError:
            pass
        else:
            message += "\n{}".format(json.dumps(body, indent=2))
        cli_error(message)
    return d


def get(url: str) -> requests.Response:
    """Uses requests to make a get request"""
    g = requests.get(url)
    if not g.ok:
        message = "GET \"{}\": {}: {}".format(url, g.status_code, g.reason)
        try:
            body = g.json()
        except ValueError:
            pass
        else:
            message += "\n{}".format(json.dumps(body, indent=2))
        cli_error(message)
    return g


################################################################################
#                                                                              #
#   Cname utilities                                                            #
#                                                                              #
################################################################################

def aliases_of_host(name: str) -> typing.List[str]:
    """Finds all aliases for the host"""
    url = "http://{}:{}/hosts/?cname__cname={}".format(
        conf["server_ip"],
        conf["server_port"],
        name
    )
    history.record_get(url)
    hosts = get(url).json()
    aliases = []
    for host in hosts:
        aliases.append(host["name"])
    return aliases


################################################################################
#                                                                              #
#   Host resolving utilities                                                   #
#                                                                              #
################################################################################


def resolve_name_or_ip(name_or_ip: str) -> str:
    """Tries to find a host from the given name/ip. Raises an exception if not."""
    if is_valid_ip(name_or_ip):
        return resolve_ip(name_or_ip)
    else:
        return resolve_input_name(name_or_ip)


def resolve_ip(ip: str) -> str:
    """Returns host name associated with ip"""
    url = "http://{}:{}/hosts/?ipaddress__ipaddress={}".format(
        conf["server_ip"],
        conf["server_port"],
        ip
    )
    history.record_get(url)
    hosts = get(url).json()

    # Response data sanity check
    if len(hosts) > 1:
        cli_error("resolve ip got multiple matches for ip \"{}\"".format(ip))

    if len(hosts) == 0:
        cli_warning("{} doesnt belong to any host".format(ip), exception=HostNotFoundWarning)
    return hosts[0]["name"]


def resolve_input_name(name: str) -> str:
    """Tries to find the named host. Raises an exception if not."""
    if "." in name:
        hostname = name
    else:
        hostname = clean_hostname(name)

    url = "http://{}:{}/hosts/?name={}".format(
        conf["server_ip"],
        conf["server_port"],
        hostname
    )
    history.record_get(url)
    hosts = get(url).json()

    if len(hosts) == 1:
        assert hosts[0]["name"] == hostname
        return hostname
    cli_warning("host not found: {}".format(name), exception=HostNotFoundWarning)


################################################################################
#                                                                              #
#   Host name longform utilities                                               #
#                                                                              #
################################################################################

def clean_hostname(name: typing.AnyStr) -> str:
    """ Converts from short to long hostname, if no domain found. """
    ### bytes?
    if not isinstance(name, (str, bytes)):
        cli_warning("Invalid input for hostname: {}".format(name))

    name = name.lower()
    # Assume user is happy with domain, but strip the punctation mark.
    if name.endswith("."):
        return name[:-1]

    # If no domain in conf, not much more can be done
    if 'domain' in conf and not name.endswith(conf['domain']):
            return "{}.{}".format(name, conf['domain'])
    return name

################################################################################
#                                                                              #
#   Hinfo utility                                                              #
#                                                                              #
################################################################################

HinfoTuple = typing.Tuple[str, str]
HinfoDict = typing.Dict[int, HinfoTuple]

def hinfo_sanify(hid: str, hinfo: HinfoDict):
    """Check if the requested hinfo is a valid one."""
    try:
        int(hid)
    except ValueError:
        cli_warning("hinfo {} is not a number".format(hid))
    if len(hinfo) == 0:
        cli_warning("Can not set hinfo, as no hinfo presets defined")
    if not hid in hinfo:
        cli_warning("Unknown hinfo preset {}".format(hid))

def hinfo_dict() -> HinfoDict:
    """
    Return a dict with descriptions of available hinfo presets. The keys
    are the hinfo ids.
    """
    url = "http://{}:{}/hinfopresets/".format(conf["server_ip"], conf["server_port"])
    history.record_get(url)
    hinfo_get = get(url)
    hl = dict()
    for hinfo in hinfo_get.json():
        assert isinstance(hinfo, dict)
        hl[str(hinfo["hinfoid"])] = (hinfo["cpu"], hinfo["os"])
    return hl


################################################################################
#                                                                              #
#   Subnet utility                                                             #
#                                                                              #
################################################################################

def get_subnet(ip: str) -> dict:
    "Returns subnet associated with given range or IP"
    if is_valid_subnet(ip):
        url = "http://{}:{}/subnets/{}".format(
            conf["server_ip"],
            conf["server_port"],
            ip
        )
        history.record_get(url)
        return get(url).json()
    elif is_valid_ip(ip):
        url = "http://{}:{}/subnets/".format(
            conf["server_ip"],
            conf["server_port"]
        )
        ip_object = ipaddress.ip_address(ip)
        #resolve_ip(ip)
        subnet = None
        history.record_get(url)
        subnet_list = get(url).json()
        subnet_ranges = [ip_range['range'] for ip_range in subnet_list]
        for ip_range in subnet_ranges:
            ip_network = ipaddress.ip_network(ip_range)
            if ip_object in ip_network:
                subnet = ip_range
                break

        if subnet:
            url = "http://{}:{}/subnets/{}".format(
                conf["server_ip"],
                conf["server_port"],
                subnet
            )
            history.record_get(url)
            return get(url).json()
        cli_warning("ip address exists but is not an address in any existing subnet")
    else:
        cli_warning("Not a valid ip range or ip address")


def get_subnet_used_count(ip_range: str):
    "Return a count of the addresses in use on a given subnet"
    url = "http://{}:{}/subnets/{}{}".format(
        conf["server_ip"],
        conf["server_port"],
        ip_range,
        "?used_count"
    )
    history.record_get(url)
    return get(url).json()

def get_subnet_used_list(ip_range: str):
    "Return a list of the addresses in use on a given subnet"
    url = "http://{}:{}/subnets/{}{}".format(
        conf["server_ip"],
        conf["server_port"],
        ip_range,
        "?used_list"
    )
    history.record_get(url)
    return get(url).json()


def get_subnet_unused_count(ip_range: str):
    "Return a count of the unused addresses on a given subnet"
    url = "http://{}:{}/subnets/{}{}".format(
        conf["server_ip"],
        conf["server_port"],
        ip_range,
        "?unused_count"
    )
    history.record_get(url)
    return get(url).json()

def get_subnet_unused_list(ip_range: str):
    "Return a list of the unused addresses on a given subnet"
    url = "http://{}:{}/subnets/{}{}".format(
        conf["server_ip"],
        conf["server_port"],
        ip_range,
        "?unused_list"
    )
    history.record_get(url)
    return get(url).json()

def get_subnet_first_unused(ip_range: str):
    "Returns the first unused address on a subnet, if any"
    url = "http://{}:{}/subnets/{}{}".format(
        conf["server_ip"],
        conf["server_port"],
        ip_range,
        "?first_unused"
    )
    history.record_get(url)
    return get(url).json()

def get_subnet_reserved_ips(ip_range: str):
    "Returns the first unused address on a subnet, if any"
    url = "http://{}:{}/subnets/{}{}".format(
        conf["server_ip"],
        conf["server_port"],
        ip_range,
        "?reserved_list"
    )
    history.record_get(url)
    return get(url).json()

def get_vlan_mapping():
    """"Get VLAN mapping: subnet - vlan"""
    vlans = {}
    get_vlans_from_file(conf['129_240_file'], vlans)
    get_vlans_from_file(conf['158_36_file'], vlans)
    get_vlans_from_file(conf['172_16_file'], vlans)
    get_vlans_from_file(conf['193_157_file'], vlans)
    return vlans


def get_vlans_from_file(file: str, vlans: dict):
    "Read VLAN mapping from a file"
    with open(file, 'r') as file:
        for line in file:
            if re.match(r"#.*", line):
                pass
            else:
                match = re.match(
                    r"(?P<range>\d+.\d+.\d+.\d+\/\d+)\s+.*?[vlan|VLAN|Vlan]\s*?(?P<vlan>\d+).*",
                    line)
                if match:
                    vlans[match.group('vlan')] = match.group('range')

def string_to_int(value, error_tag):
    try:
        return int(value)
    except ValueError:
        cli_warning("%s: Not a valid integer" % error_tag)


################################################################################
#                                                                              #
#   Pretty printing                                                            #
#                                                                              #
################################################################################


def print_host_name(name: str, padding: int = 14) -> None:
    """Pretty print given name."""
    if name is None:
        return
    assert isinstance(name, str)
    print("{1:<{0}}{2}".format(padding, "Name:", name))


def print_contact(contact: str, padding: int = 14) -> None:
    """Pretty print given contact."""
    if contact is None:
        return
    assert isinstance(contact, str)
    print("{1:<{0}}{2}".format(padding, "Contact:", contact))


def print_comment(comment: str, padding: int = 14) -> None:
    """Pretty print given comment."""
    if comment is None:
        return
    assert isinstance(comment, str)
    print("{1:<{0}}{2}".format(padding, "Comment:", comment))


def print_ipaddresses(ipaddresses: typing.Iterable[dict], padding: int = 14) -> None:
    """Pretty print given ip addresses"""
    if ipaddresses is None:
        return
    a_records = []
    aaaa_records = []
    len_ip = 0
    for record in ipaddresses:
        if is_valid_ipv4(record["ipaddress"]):
            a_records.append(record)
            if len(record["ipaddress"]) > len_ip:
                len_ip = len(record["ipaddress"])
        elif is_valid_ipv6(record["ipaddress"]):
            aaaa_records.append(record)
            if len(record["ipaddress"]) > len_ip:
                len_ip = len(record["ipaddress"])
    len_ip += 2
    if a_records:
        print("{1:<{0}}{2:<{3}}{4}".format(padding, "A_Records:", "IP", len_ip, "MAC"))
        for record in a_records:
            ip = record["ipaddress"]
            mac = record["macaddress"]
            print("{1:<{0}}{2:<{3}}{4}".format(
                padding, "", ip if ip else "<not set>", len_ip,
                mac if mac else "<not set>"))

    # print aaaa records
    if aaaa_records:
        print("{1:<{0}}{2:<{3}}{4}".format(padding, "AAAA_Records:", "IP", len_ip, "MAC"))
        for record in aaaa_records:
            ip = record["ipaddress"]
            mac = record["macaddress"]
            print("{1:<{0}}{2:<{3}}{4}".format(
                padding, "", ip if ip else "<not set>", len_ip,
                mac if mac else "<not set>"))


def print_ttl(ttl: int, padding: int = 14) -> None:
    """Pretty print given ttl"""
    assert isinstance(ttl, int) or ttl is None
    print("{1:<{0}}{2}".format(padding, "TTL:", ttl or "(Default)"))


def print_hinfo(hid: str, padding: int = 14) -> None:
    """Pretty given hinfo id"""
    hinfos = hinfo_dict()
    hid = str(hid)
    hinfo = hinfos[hid]
    print("{1:<{0}}cpu={2} os={3}".format(padding, "Hinfo:", hinfo[0], hinfo[1]))


def print_hinfo_list(hinfos: HinfoDict, padding: int = 14) -> None:
    """Pretty print a dict of host infos"""
    if len(hinfos) == 0:
        print("No hinfo presets.")
        return
    max_len = max([len(x[0]) for x in hinfos.values()])
    print("{1:<{0}}    {2:<{3}} {4}".format(padding, "Id", "CPU", max_len, "OS"))
    for hid in sorted(hinfos.keys()):
        hinfo = hinfos[hid]
        print(
            "{1:<{0}} -> {2:<{3}} {4}".format(padding, hid, hinfo[0], max_len, hinfo[1]))


def print_srv(srv: dict, padding: int = 14) -> None:
    """Pretty print given srv"""
    print("{1:<{0}} SRV {2:^6} {3:^6} {4:^6} {5}".format(
        padding,
        srv["service"],
        srv["priority"],
        srv["weight"],
        srv["port"],
        srv["target"],
    ))


def print_loc(loc: str, padding: int = 14) -> None:
    """Pretty print given loc"""
    if loc is None:
        return
    assert isinstance(loc, str)
    print("{1:<{0}}{2}".format(padding, "Loc:", loc))


def print_cname(cname: str, host: str, padding: int = 14) -> None:
    """Pretty print given cname"""
    print("{1:<{0}}{2} -> {3}".format(padding, "Cname:", cname, host))


def print_txt(txt: str, padding: int = 14) -> None:
    """Pretty print given txt"""
    if txt is None:
        return
    assert isinstance(txt, str)
    print("{1:<{0}}{2}".format(padding, "TXT:", txt))


def print_naptr(naptr: dict, host_name: str, padding: int = 14) -> None:
    """Pretty print given txt"""
    assert isinstance(naptr, dict)
    assert isinstance(host_name, str)
    print("{1:<{0}} NAPTR {2} {3} \"{4}\" \"{5}\" \"{6}\" {7}".format(
        padding,
        host_name,
        naptr["preference"],
        naptr["orderv"],
        naptr["flag"],
        naptr["service"],
        naptr["regex"] or "",
        naptr["replacement"],
    ))


def print_ptr(ip: str, host_name: str, padding: int = 14) -> None:
    """Pretty print given txt"""
    assert isinstance(ip, str)
    assert isinstance(host_name, str)
    print("{1:<{0}} PTR {2}".format(padding, ip, host_name))


def print_subnet_unused(count: int, padding: int = 25) -> None:
    "Pretty print amount of unused addresses"
    assert isinstance(count, int)
    print(
        "{1:<{0}}{2}{3}".format(padding, "Unused addresses:", count, " (excluding reserved adr.)"))


def print_subnet_reserved(ip_range: str, reserved: int, padding: int = 25) -> None:
    "Pretty print ip range and reserved addresses list"
    assert isinstance(ip_range, str)
    assert isinstance(reserved, int)
    subnet = ipaddress.ip_network(ip_range)
    print("{1:<{0}}{2} - {3}".format(padding, "IP-range:", subnet.network_address,
                                     subnet.broadcast_address))
    print("{1:<{0}}{2}".format(padding, "Reserved host addresses:", reserved))
    print("{1:<{0}}{2}{3}".format(padding, "", subnet.network_address, " (net)"))
    res = get_subnet_reserved_ips(ip_range)
    res.remove(str(subnet.network_address))
    broadcast = False
    if str(subnet.broadcast_address) in res:
        res.remove(str(subnet.broadcast_address))
        broadcast = True
    for host in res:
        print("{1:<{0}}{2}".format(padding, "", host))
    if broadcast:
        print("{1:<{0}}{2}{3}".format(padding, "", subnet.broadcast_address, " (broadcast)"))


def print_subnet(info: int, text: str, padding: int = 25) -> None:
    print("{1:<{0}}{2}".format(padding, text, info))


################################################################################
#                                                                              #
#   Validation functions                                                       #
#                                                                              #
################################################################################


def is_valid_ip(ip: str) -> bool:
    """Check if ip is valid ipv4 og ipv6."""
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)


def is_valid_ipv4(ip: str) -> bool:
    """Check if ip is valid ipv4"""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    else:
        return True


def is_valid_ipv6(ip: str) -> bool:
    """Check if ip is valid ipv6"""
    try:
        ipaddress.IPv6Address(ip)
    except ValueError:
        return False
    else:
        return True


def is_valid_subnet(net: str) -> bool:
    """Check if net is a valid subnet"""
    if is_valid_ip(net):
        return False
    try:
        ipaddress.ip_network(net)
        return True
    except ValueError:
        return False


def is_valid_ttl(ttl: typing.Union[int, str, bytes]) -> bool:  # int?
    """Check application specific ttl restrictions."""
    if ttl == "default":
        return True
    if not isinstance(ttl, int):
        try:
            ttl = int(ttl)
        except ValueError:
            return False
    return 300 <= ttl <= 68400


def is_valid_email(email: typing.AnyStr) -> bool:
    """Check if email looks like a valid email"""
    if not isinstance(email, str):
        try:
            email = str(email)
        except ValueError:
            return False
    return True if re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email) else False


def is_valid_loc(loc: str) -> bool:
    # TODO LOC: implement validate loc
    return True


def is_valid_location_tag(loc: str) -> bool:
    """Check if valid location tag"""
    return loc in location_tags


def is_valid_category_tag(cat: str) -> bool:
    """Check if valid location tag"""
    return cat in category_tags


def is_valid_mac_addr(addr: str) -> bool:
    """Check if address is a valid MAC address"""
    return re.match("^[a-fA-F0-9]{2}([a-fA-F0-9]{10}|(:[a-fA-F0-9]{2}){5})$", addr)
