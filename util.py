import re
import sys
import ipaddress
import typing
import inspect
import requests

from configurations import *
from exceptions import *

try:
    conf = cli_config(required_fields=("server_ip", "server_port"))
except Exception as e:
    print(e)
    sys.exit(1)

IpAddress = typing.Union[str, bytes, int]


def resolve_name_or_ip(name_or_ip: typing.Union[typing.AnyStr, IpAddress]) -> str:
    """Tries to find a host from the given name/ip. Raises an exception if not."""
    if is_valid_ip(name_or_ip):
        url = "http://{}:{}/hosts/{}/"
        host_get = requests.get(url.format(conf["server_ip"], conf["server_port"], name_or_ip))
        if host_get.ok:
            return host_get.json()["name"]
    return resolve_input_name(name_or_ip)


def resolve_input_name(name: typing.AnyStr) -> str:
    """Tries to find the named host. Raises an exception if not."""
    if not isinstance(name, str):
        name = str(name)

    url = "http://{}:{}/hosts/{}/"
    if is_longform(name):
        host_get = requests.get(url.format(conf["server_ip"], conf["server_port"], name))
        if host_get.ok:
            return name
    else:
        short_get = requests.get(url.format(conf["server_ip"], conf["server_port"], name))
        if short_get.ok:
            return name
        long_name = to_longform(name)
        long_get = requests.get(url.format(conf["server_ip"], conf["server_port"], long_name))
        if long_get.ok:
            return long_name
    raise HostNotFoundError


def to_longform(name: typing.AnyStr) -> str:
    """Return long form of host name, i.e. append uio.no"""
    if not isinstance(name, str):
        name = str(name)
    s = ".uio.no" if name[len(name) - 1] != "." else "uio.no"
    return name + s


################################################################################
#                                                                              #
#   Pretty printing                                                            #
#                                                                              #
################################################################################

def cli_error(msg: typing.Any):
    """Print an error message with the name of the caller"""
    print("ERROR: {}: {}".format(inspect.stack()[1][3], msg))


def cli_warning(msg):
    """Print a warning message with the name of the caller"""
    print("Warning: {}: {}".format(inspect.stack()[1][3], msg))


def cli_info(msg):
    """Print an info message with the name of the caller"""
    print("{}: {}".format(inspect.stack()[1][3], msg))


################################################################################
#                                                                              #
#   Validation functions                                                       #
#                                                                              #
################################################################################


def is_valid_ip(ip: IpAddress) -> bool:
    """Check if ip is valid ipv4 og ipv6."""
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)


def is_valid_ipv4(ip: IpAddress) -> bool:
    """Check if ip is valid ipv4"""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    else:
        return True


def is_valid_ipv6(ip: IpAddress) -> bool:
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
    except ValueError:
        return False
    else:
        return True


def is_valid_ttl(ttl: typing.Union[int, str, bytes]) -> bool:  # int?
    """Check application specific ttl restrictions."""
    if not isinstance(ttl, int):
        try:
            ttl = int(ttl)
        except ValueError:
            return False
    return ttl >= 300


def is_valid_email(email: typing.AnyStr) -> bool:
    """Check if email looks like a valid email"""
    if not isinstance(email, str):
        try:
            email = str(email)
        except ValueError:
            return False
    return True if re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email) else False


def is_longform(name: typing.AnyStr) -> bool:
    """Check if name ends with uio.no"""
    if not isinstance(name, (str, bytes)):
        return False
    return True if re.match("^.*\.uio\.no\.?$", name) else False
