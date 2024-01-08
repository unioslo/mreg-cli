"""Utility functions for mreg_cli.

Due to circular dependencies, this module is not allowed to import anything from mreg_cli.
And this rule is promptly broken by importing from mreg_cli.outputmanager...
"""

import ipaddress
import json
import logging
import os
import re
import sys
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Iterable,
    List,
    NoReturn,
    Optional,
    Tuple,
    Union,
    cast,
    overload,
)

from .outputmanager import OutputManager

if TYPE_CHECKING:
    from typing_extensions import Literal

    from .types import ResponseLike

import urllib.parse

import requests
from prompt_toolkit import prompt

from .exceptions import CliError, HostNotFoundWarning
from .history import history
from .log import cli_error, cli_warning

location_tags: List[str] = []
category_tags: List[str] = []

session = requests.Session()
session.headers.update({"User-Agent": "mreg-cli"})

mreg_auth_token_file = os.path.join(str(os.getenv("HOME")), ".mreg-cli_auth_token")

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 20

config = {}  # initialized by set_config


def error(msg: str, code: int = os.EX_UNAVAILABLE) -> NoReturn:
    """Print an error message and exits with the given code."""
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def set_config(cfg: Dict[str, Any]) -> None:
    """Set the config dict."""
    global config
    config = cfg


def host_exists(name: str) -> bool:
    """Check if a host with the given name exists."""
    path = "/api/v1/hosts/"
    params = {
        "name": name,
    }
    history.record_get(path)
    hosts = get_list(path, params=params)

    # Response data sanity checks
    if len(hosts) > 1:
        cli_error('host exist check received more than one exact match for "{}"'.format(name))
    if len(hosts) == 0:
        return False
    if hosts[0]["name"] != name:
        cli_error(
            'host exist check received from API "{}" when searched for "{}"'.format(
                hosts[0]["name"],
                name,
            )
        )
    return True


def host_info_by_name_or_ip(name_or_ip: str) -> Dict[str, Any]:
    """Return a dict with host information about the given host, or the host owning the given ip.

    :param name_or_ip: Either a host name on short or long form or an ipv4/ipv6 address.
    :return: A dict of the JSON object received with the host information
    """
    if is_valid_ip(name_or_ip):
        name = resolve_ip(name_or_ip)
    else:
        name = name_or_ip
    return host_info_by_name(name)


def _host_info_by_name(name: str, follow_cname: bool = True) -> Optional[Dict[str, Any]]:
    hostinfo = get(f"/api/v1/hosts/{urllib.parse.quote(name)}", ok404=True)

    if hostinfo:
        return hostinfo.json()
    elif follow_cname:
        # All host info data is returned from the API
        path = "/api/v1/hosts/"
        params = {"cnames__name": name}
        history.record_get(path)
        hosts = get_list(path, params=params)
        if len(hosts) == 1:
            return hosts[0]
    return None


def host_info_by_name(name: str, follow_cname: bool = True) -> Dict[str, Any]:
    """Return a dict with host information about the given host.

    :param name: A host name on either short or long form.
    :param follow_cname: Indicate whether or not to check if name is a cname. If True (default)
    if will attempt to get the host via the cname.
    :return: A dict of the JSON object received with the host information
    """
    # Get longform of name
    name = clean_hostname(name)
    hostinfo = _host_info_by_name(name, follow_cname=follow_cname)
    if hostinfo is None:
        cli_warning(f"host not found: {name!r}", exception=HostNotFoundWarning)

    return hostinfo


def _cname_info_by_name(name: str) -> Optional[Dict[str, Any]]:
    """Return a dict with information about the given cname."""
    path = "/api/v1/cnames/"
    params = {
        "name": name,
    }
    info = get_list(path, params=params)
    if len(info) == 1:
        return info[0]
    return None


def _srv_info_by_name(name: str) -> Optional[Dict[str, Any]]:
    """Return a dict with information about the given srv."""
    path = "/api/v1/srvs/"
    params = {
        "name": name,
    }
    info = get_list(path, params=params)
    if len(info) == 1:
        return info[0]
    return None


def get_info_by_name(name: str) -> Tuple[str, Dict[str, Any]]:
    """Get host, cname or srv by name."""
    name = clean_hostname(name)
    info = _host_info_by_name(name, follow_cname=False)
    if info is not None:
        return "host", info
    info = _cname_info_by_name(name)
    if info is not None:
        return "cname", info
    info = _srv_info_by_name(name)
    if info is not None:
        return "srv", info
    cli_warning(f"not found: {name!r}", exception=HostNotFoundWarning)


def first_unused_ip_from_network(network: Dict[str, Any]) -> str:
    """Return the first unused ip from a given network.

    Assumes network exists.
    :param network: dict with network info (key: "network").
    :return: Ip address string.
    """
    unused = get_network_first_unused(network["network"])
    if not unused:
        cli_warning("No free addresses remaining on network {}".format(network["network"]))
    return unused


def ip_in_mreg_net(ip: str) -> bool:
    """Return true if the ip is in a MREG controlled network."""
    net = get_network_by_ip(ip)
    return bool(net)


################################################################################
#                                                                              #
#   HTTP requests wrappers with error checking                                 #
#                                                                              #
################################################################################


def set_file_permissions(f: str, mode: int) -> None:
    """Set file permissions on a file."""
    try:
        os.chmod(f, mode)
    except PermissionError:
        print("Failed to set permissions on " + f, file=sys.stderr)
    except FileNotFoundError:
        pass


def login1(user: str, url: str) -> None:
    """Login to MREG."""
    global mregurl, username
    mregurl = url
    username = user

    if os.path.isfile(mreg_auth_token_file):
        try:
            with open(mreg_auth_token_file, encoding="utf-8") as tokenfile:
                tokenuser, token = tokenfile.readline().split("¤")
                if tokenuser == user:
                    session.headers.update({"Authorization": f"Token {token}"})
        except PermissionError:
            pass

    # Unconditionally set file permissions to 0600.  This is done here
    # in order to migrate existing installations and can be removed when
    # 0.9.11+ is reasonably widespread.  --Marius, 2021-04-22
    # Consider inlining set_file_permissions afterwards!
    set_file_permissions(mreg_auth_token_file, 0o600)

    # Find a better URL.. but so far so good
    try:
        ret = session.get(
            requests.compat.urljoin(mregurl, "/api/v1/hosts/"),
            params={"page_size": 1},
            timeout=5,
        )
    except requests.exceptions.ConnectionError:
        error(f"Could not connect to {url}")

    if ret.status_code == 401:
        login(user, url)


def login(user: str, url: str) -> None:
    """Login to MREG."""
    print(f"Connecting to {url}")

    # get url
    password = prompt(f"Password for {username}: ", is_password=True)
    try:
        _update_token(username, password)
    except CliError as e:
        error(e)


def logout() -> None:
    """Logout from MREG."""
    path = requests.compat.urljoin(mregurl, "/api/token-logout/")
    # Try to logout, and ignore errors
    try:
        session.post(path)
    except requests.exceptions.ConnectionError:
        pass


def update_token() -> None:
    """Update the token."""
    password = prompt("You need to re-autenticate\nEnter password: ", is_password=True)
    try:
        _update_token(username, password)
    except CliError as e:
        error(e)


def _update_token(username: str, password: str) -> None:
    """Perform the actual token update."""
    tokenurl = requests.compat.urljoin(mregurl, "/api/token-auth/")
    try:
        result = requests.post(tokenurl, {"username": username, "password": password})
    except requests.exceptions.ConnectionError as err:
        error(err)
    except requests.exceptions.SSLError as e:
        error(e)
    if not result.ok:
        try:
            res = result.json()
        except json.JSONDecodeError:
            res = result.text
        if result.status_code == 400:
            if "non_field_errors" in res:
                cli_error("Invalid username/password")
        else:
            cli_error(res)
    token = result.json()["token"]
    session.headers.update({"Authorization": f"Token {token}"})
    try:
        with open(mreg_auth_token_file, "w", encoding="utf-8") as tokenfile:
            tokenfile.write(f"{username}¤{token}")
    except FileNotFoundError:
        pass
    except PermissionError:
        pass
    set_file_permissions(mreg_auth_token_file, 0o600)


def result_check(result: "ResponseLike", operation_type: str, url: str) -> None:
    """Check the result of a request."""
    if not result.ok:
        message = f'{operation_type} "{url}": {result.status_code}: {result.reason}'
        try:
            body = result.json()
        except ValueError:
            pass
        else:
            message += "\n{}".format(json.dumps(body, indent=2))
        cli_warning(message)


def _request_wrapper(
    operation_type: str,
    path: str,
    params: Dict[str, str] = None,
    ok404: bool = False,
    first: bool = True,
    use_json: bool = False,
    **data: Any,
) -> Optional["ResponseLike"]:
    """Wrap request calls to MREG for logging and token management."""
    if params is None:
        params = {}
    url = requests.compat.urljoin(mregurl, path)

    if use_json:
        result = getattr(session, operation_type)(url, json=params, timeout=HTTP_TIMEOUT)
    else:
        result = getattr(session, operation_type)(
            url, params=params, data=data, timeout=HTTP_TIMEOUT
        )
    result = cast(requests.Response, result)  # convince mypy that result is a Response

    OutputManager().recording_request(operation_type, url, params, data, result)

    if first and result.status_code == 401:
        update_token()
        return _request_wrapper(operation_type, path, first=False, **data)
    elif result.status_code == 404 and ok404:
        return None

    result_check(result, operation_type.upper(), url)
    return result


@overload
def get(path: str, params: Dict[str, str], ok404: "Literal[True]") -> Optional["ResponseLike"]:
    ...


@overload
def get(path: str, params: Dict[str, str], ok404: "Literal[False]") -> "ResponseLike":
    ...


@overload
def get(path: str, params: Dict[str, str] = ..., *, ok404: bool) -> Optional["ResponseLike"]:
    ...


@overload
def get(path: str, params: Dict[str, str] = ...) -> "ResponseLike":
    ...


def get(path: str, params: Dict[str, str] = None, ok404: bool = False) -> Optional["ResponseLike"]:
    """Make a standard get request."""
    if params is None:
        params = {}
    return _request_wrapper("get", path, params=params, ok404=ok404)


def get_list(
    path: Optional[str], params: Dict[str, Any] = None, ok404: bool = False
) -> List[Dict[str, Any]]:
    """Make a get request that produces a list.

    Will iterate over paginated results and return result as list.
    """
    if params is None:
        params = {}
    ret: List[Dict[str, Any]] = []
    while path:
        resp = get(path, params=params, ok404=ok404)
        if resp is None:
            return ret
        result = resp.json()

        if "next" in result:
            path = result["next"]
            ret.extend(result["results"])
        else:
            path = None
    return ret


def post(path: str, params: Dict[str, Any] = None, **kwargs: Any) -> Optional["ResponseLike"]:
    """Use requests to make a post request. Assumes that all kwargs are data fields."""
    if params is None:
        params = {}
    return _request_wrapper("post", path, params=params, **kwargs)


def patch(
    path: str, params: Dict[str, Any] = None, use_json: bool = False, **kwargs: Any
) -> Optional["ResponseLike"]:
    """Use requests to make a patch request. Assumes that all kwargs are data fields."""
    if params is None:
        params = {}
    return _request_wrapper("patch", path, params=params, use_json=use_json, **kwargs)


def delete(path: str, params: Dict[str, Any] = None) -> Optional["ResponseLike"]:
    """Use requests to make a delete request."""
    if params is None:
        params = {}
    return _request_wrapper("delete", path, params=params)


################################################################################
#                                                                              #
#   Cname utilities                                                            #
#                                                                              #
################################################################################


def cname_exists(cname: str) -> bool:
    """Check if a cname exists."""
    if len(get_list("/api/v1/cnames/", params={"name": cname})):
        return True
    else:
        return False


################################################################################
#                                                                              #
#   Host resolving utilities                                                   #
#                                                                              #
################################################################################


def resolve_name_or_ip(name_or_ip: str) -> str:
    """Try to find a host from the given name/ip. Raises an exception if not."""
    if is_valid_ip(name_or_ip):
        return resolve_ip(name_or_ip)
    else:
        return resolve_input_name(name_or_ip)


def resolve_ip(ip: str) -> str:
    """Return a host name associated with ip."""
    path = "/api/v1/hosts/"
    params = {
        "ipaddresses__ipaddress": ip,
    }
    history.record_get(path)
    hosts = get_list(path, params=params)

    # Response data sanity check
    if len(hosts) > 1:
        cli_error('resolve ip got multiple matches for ip "{}"'.format(ip))

    if len(hosts) == 0:
        cli_warning("{} doesnt belong to any host".format(ip), exception=HostNotFoundWarning)
    return hosts[0]["name"]


def resolve_input_name(name: str) -> str:
    """Try to find the named host. Raises an exception if not."""
    hostname = clean_hostname(name)

    path = "/api/v1/hosts/"
    params = {
        "name": hostname,
    }
    history.record_get(path)
    hosts = get_list(path, params=params)

    if len(hosts) == 1:
        assert hosts[0]["name"] == hostname
        return hostname
    cli_warning("host not found: {}".format(name), exception=HostNotFoundWarning)


################################################################################
#                                                                              #
#   Host name longform utilities                                               #
#                                                                              #
################################################################################


def clean_hostname(name: Union[str, bytes]) -> str:
    """Convert from short to long hostname, if no domain found."""
    # bytes?
    if not isinstance(name, (str, bytes)):
        cli_warning("Invalid input for hostname: {}".format(name))

    if isinstance(name, bytes):
        name = name.decode()

    name = name.lower()

    # invalid characters?
    if re.search(r"^(\*\.)?([a-z0-9_][a-z0-9\-]*\.?)+$", name) is None:
        cli_warning("Invalid input for hostname: {}".format(name))

    # Assume user is happy with domain, but strip the dot.
    if name.endswith("."):
        return name[:-1]

    # If a dot in name, assume long name.
    if "." in name:
        return name

    # Append domain name if in config and it does not end with it
    if "domain" in config and not name.endswith(config["domain"]):
        return "{}.{}".format(name, config["domain"])
    return name


################################################################################
#                                                                              #
#   Network utility                                                             #
#                                                                              #
################################################################################


def ipsort(ips: Iterable[Any]) -> List[Any]:
    """Sort a list of ips."""
    return sorted(ips, key=lambda i: ipaddress.ip_address(i))


def get_network_by_ip(ip: str) -> Dict[str, Any]:
    """Return a network associated with given IP."""
    if is_valid_ip(ip):
        path = f"/api/v1/networks/ip/{urllib.parse.quote(ip)}"
        net = get(path, ok404=True)
        if net:
            return net.json()
        else:
            return {}
    else:
        cli_warning("Not a valid ip address")


def get_network(ip: str) -> Dict[str, Any]:
    """Return a network associated with given range or IP."""
    if is_valid_network(ip):
        path = f"/api/v1/networks/{urllib.parse.quote(ip)}"
        history.record_get(path)
        return get(path).json()
    elif is_valid_ip(ip):
        net = get_network_by_ip(ip)
        if net:
            return net
        cli_warning("ip address exists but is not an address in any existing network")
    else:
        cli_warning("Not a valid ip range or ip address")


def get_network_used_count(ip_range: str) -> int:
    """Return a count of the addresses in use on a given network."""
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}/used_count"
    history.record_get(path)
    return get(path).json()


def get_network_used_list(ip_range: str) -> List[str]:
    """Return a list of the addresses in use on a given network."""
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}/used_list"
    history.record_get(path)
    return get(path).json()


def get_network_unused_count(ip_range: str) -> int:
    """Return a count of the unused addresses on a given network."""
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}/unused_count"
    history.record_get(path)
    return get(path).json()


def get_network_unused_list(ip_range: str) -> List[str]:
    """Return a list of the unused addresses on a given network."""
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}/unused_list"
    history.record_get(path)
    return get(path).json()


def get_network_first_unused(ip_range: str) -> str:
    """Return the first unused address on a network, if any."""
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}/first_unused"
    history.record_get(path)
    return get(path).json()


def get_network_reserved_ips(ip_range: str) -> List[str]:
    """Return the first unused address on a network, if any."""
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}/reserved_list"
    history.record_get(path)
    return get(path).json()


def string_to_int(value: Any, error_tag: str) -> int:
    """Convert a string to an integer."""
    try:
        return int(value)
    except ValueError:
        cli_warning("%s: Not a valid integer" % error_tag)


################################################################################
#                                                                              #
#   Validation functions                                                       #
#                                                                              #
################################################################################


def is_valid_ip(ip: str) -> bool:
    """Check if ip is valid ipv4 og ipv6."""
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)


def is_valid_ipv4(ip: str) -> bool:
    """Check if ip is valid ipv4."""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    else:
        return True


def is_valid_ipv6(ip: str) -> bool:
    """Check if ip is valid ipv6."""
    try:
        ipaddress.IPv6Address(ip)
    except ValueError:
        return False
    else:
        return True


def is_valid_network(net: str) -> bool:
    """Check if net is a valid network."""
    if is_valid_ip(net):
        return False
    try:
        ipaddress.ip_network(net)
        return True
    except ValueError:
        return False


def is_valid_mac(mac: str) -> bool:
    """Check if mac is a valid MAC address."""
    return bool(re.match(r"^([a-fA-F0-9]{2}[\.:-]?){5}[a-fA-F0-9]{2}$", mac))


def is_valid_ttl(ttl: Union[int, str, bytes]) -> bool:  # int?
    """Check application specific ttl restrictions."""
    if ttl in ("", "default"):
        return True
    if not isinstance(ttl, int):
        try:
            ttl = int(ttl)
        except ValueError:
            return False
    return 300 <= ttl <= 68400


def is_valid_email(email: Union[str, bytes]) -> bool:
    """Check if email looks like a valid email."""
    if not isinstance(email, str):
        try:
            email = email.decode()
        except ValueError:
            return False
    return True if re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email) else False


def is_valid_location_tag(loc: str) -> bool:
    """Check if valid location tag."""
    return loc in location_tags


def is_valid_category_tag(cat: str) -> bool:
    """Check if valid location tag."""
    return cat in category_tags


def format_mac(mac: str) -> str:
    """Create a strict 'aa:bb:cc:11:22:33' MAC address.

    Replaces any other delimiters with a colon and turns it into all lower case.
    """
    mac = re.sub("[.:-]", "", mac).lower()
    return ":".join(["%s" % (mac[i : i + 2]) for i in range(0, 12, 2)])


def convert_wildcard_to_regex(
    param: str, arg: str, autoWildcards: bool = False
) -> Tuple[str, str]:
    """Convert wildcard filter "foo*bar*" to something DRF will understand.

    E.g. "foo*bar*" -> "?name__regex=$foo.*bar.*"

    :param param: The parameter to filter on
    :param arg: The argument to filter on
    :param autoWildcards: If True, add wildcards to the beginning and end of the argument if
                          they are not already present.
    """
    if "*" not in arg:
        if autoWildcards:
            arg = f"*{arg}*"
        else:
            return (param, arg)

    args = arg.split("*")
    args_len = len(args) - 1
    regex = ""
    for i, piece in enumerate(args):
        if i == 0 and piece:
            regex += f"^{piece}"
        elif i == args_len and piece:
            regex += f"{piece}$"
        elif piece:
            regex += f".*{piece}.*"
    #        if i == 0 and piece:
    #            parts.append(f'{param}__startswith={piece}')
    #        elif i == args_len and piece:
    #            parts.append(f'{param}__endswith={piece}')
    #        elif piece:
    #            parts.append(f'{param}__contains={piece}')

    if arg == "*":
        regex = "."

    return (f"{param}__regex", regex)
