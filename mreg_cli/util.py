import ipaddress
import json
import re
import requests
import sys
import typing

from prompt_toolkit import prompt

from .exceptions import CliError, HostNotFoundWarning
from .history import history
from .log import cli_error, cli_warning

location_tags = []
category_tags = []
session = requests.Session()


def set_config(cfg):
    global config
    config = cfg


def host_exists(name: str) -> bool:
    """Checks if a host with the given name exists"""
    path = f"/hosts/?name={name}"
    history.record_get(path)
    hosts = get(path).json()

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


def host_info_by_name(name: str, follow_cname: bool = True) -> dict:
    """
    Return a dict with host information about the given host.

    :param name: A host name on either short or long form.
    :param follow_cname: Indicate whether or not to check if name is a cname. If True (default)
    if will attempt to get the host via the cname.
    :return: A dict of the JSON object received with the host information
    """

    def _get_host(name):
        path = f"/hosts/{name}"
        history.record_get(path)
        host = get(path).json()
        return host

    # Get longform of name
    name = clean_hostname(name)

    if host_exists(name):
        return _get_host(name)
    elif follow_cname:
        # All host info data is returned from the API
        path = f"/hosts/?cnames__name={name}"
        history.record_get(path)
        host = get(path).json()
        if len(host):
            assert len(host) == 1
            return _get_host(host[0]['name'])

    cli_warning("host not found: {}".format(name), exception=HostNotFoundWarning)


def first_unused_ip_from_network(network: dict) -> str:
    """
    Returns the first unused ip from a given network.
    Assumes network exists.
    :param network: dict with network info.
    :return: Ip address string
    """

    unused = get_network_first_unused(network['range'])
    if not unused:
        cli_warning("No free addresses remaining on network {}".format(network['range']))
    return unused


def zone_mreg_controlled(zone: str) -> bool:
    """Return true of the zone is controlled by MREG"""
    assert isinstance(zone, str)
    path = f"/zones/?name={zone}"
    history.record_get(path)
    zone = get(path).json()
    return bool(len(zone))


def host_in_mreg_zone(host: str) -> bool:
    """Return true if host is in a MREG controlled zone"""
    assert isinstance(host, str)
    if "." not in host:
        return False
    splitted = host.split(".")

    path = "/zones/"
    history.record_get(path)
    zonenames = set([zone['name'] for zone in get(path).json()])

    for i in range(len(splitted)):
        name = ".".join(splitted[i:])
        if name in zonenames:
            return True

    return False


def ip_in_mreg_net(ip: str) -> bool:
    """Return true if the ip is in a MREG controlled network"""
    net = get_network_by_ip(ip)
    return bool(net)


################################################################################
#                                                                              #
#   HTTP requests wrappers with error checking                                 #
#                                                                              #
################################################################################

def login(user, url):
    global mregurl, username
    mregurl = url
    username = user
    print(f"Connecting to {url}")
    # get url
    password = prompt(f"Password for {username}: ", is_password=True)
    try:
        _update_token(username, password)
    except CliError as e:
        print(e)
        sys.exit(1)
    except requests.exceptions.SSLError as e:
        print(e)
        sys.exit(1)


def update_token():
    password = prompt("You need to re-autenticate\nEnter password: ",
                      is_password=True)
    try:
        _update_token(username, password)
    except CliError as e:
        print(e)
        sys.exit(1)


def _update_token(username, password):
    tokenurl = requests.compat.urljoin(mregurl, '/api/token-auth/')
    result = requests.post(tokenurl, {'username': username,
                                      'password': password})
    if not result.ok:
        res = result.json()
        if result.status_code == 400:
            if 'non_field_errors' in res:
                cli_error("Invalid username/password")
        else:
            cli_error(res)
    token = result.json()['token']
    session.headers.update({"Authorization": f"Token {token}"})


def result_check(result, type, url):
    if not result.ok:
        message = f"{type} \"{url}\": {result.status_code}: {result.reason}"
        try:
            body = result.json()
        except ValueError:
            pass
        else:
            message += "\n{}".format(json.dumps(body, indent=2))
        cli_warning(message)


def _request_wrapper(type, path, ok404=False, first=True, **data):
    url = requests.compat.urljoin(mregurl, path)
    result = getattr(session, type)(url, data=data)

    if first and result.status_code == 401:
        update_token()
        return _request_wrapper(type, path, first=False, **data)
    elif result.status_code == 404 and ok404:
        return None

    result_check(result, type.upper(), url)
    return result


def get(path: str, ok404=False) -> requests.Response:
    """Uses requests to make a get request."""
    return _request_wrapper("get", path, ok404=ok404)


def post(path: str, **kwargs) -> requests.Response:
    """Uses requests to make a post request. Assumes that all kwargs are data fields"""
    return _request_wrapper("post", path, **kwargs)


def patch(path: str, **kwargs) -> requests.Response:
    """Uses requests to make a patch request. Assumes that all kwargs are data fields"""
    return _request_wrapper("patch", path, **kwargs)


def delete(path: str) -> requests.Response:
    """Uses requests to make a delete request."""
    return _request_wrapper("delete", path)


################################################################################
#                                                                              #
#   Cname utilities                                                            #
#                                                                              #
################################################################################

def cname_exists(cname: str) -> bool:
    """Check if a cname exists"""
    if len(get(f"/cnames/?name={cname}").json()):
        return True
    else:
        return False


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
    path = f"/hosts/?ipaddresses__ipaddress={ip}"
    history.record_get(path)
    hosts = get(path).json()

    # Response data sanity check
    if len(hosts) > 1:
        cli_error("resolve ip got multiple matches for ip \"{}\"".format(ip))

    if len(hosts) == 0:
        cli_warning("{} doesnt belong to any host".format(ip), exception=HostNotFoundWarning)
    return hosts[0]["name"]


def resolve_input_name(name: str) -> str:
    """Tries to find the named host. Raises an exception if not."""
    name = name.lower()
    if "." in name:
        hostname = name
    else:
        hostname = clean_hostname(name)

    path = f"/hosts/?name={hostname}"
    history.record_get(path)
    hosts = get(path).json()

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

    # Append domain name if in config and it does not end with it
    if 'domain' in config and not name.endswith(config['domain']):
            return "{}.{}".format(name, config['domain'])
    return name


################################################################################
#                                                                              #
#   Network utility                                                             #
#                                                                              #
################################################################################

def get_network_by_ip(ip: str) -> dict:
    if is_valid_ip(ip):
        path = f"/networks/ip/{ip}"
        net = get(path, ok404=True)
        if net:
            return net.json()
        else:
            return {}
    else:
        cli_warning("Not a valid ip address")


def get_network(ip: str) -> dict:
    "Returns network associated with given range or IP"
    if is_valid_network(ip):
        path = f"/networks/{ip}"
        history.record_get(path)
        return get(path).json()
    elif is_valid_ip(ip):
        net = get_network_by_ip(ip)
        if net:
            return net
        cli_warning("ip address exists but is not an address in any existing network")
    else:
        cli_warning("Not a valid ip range or ip address")


def get_network_used_count(ip_range: str):
    "Return a count of the addresses in use on a given network"
    path = f"/networks/{ip_range}/used_count"
    history.record_get(path)
    return get(path).json()


def get_network_used_list(ip_range: str):
    "Return a list of the addresses in use on a given network"
    path = f"/networks/{ip_range}/used_list"
    history.record_get(path)
    return get(path).json()


def get_network_unused_count(ip_range: str):
    "Return a count of the unused addresses on a given network"
    path = f"/networks/{ip_range}/unused_count"
    history.record_get(path)
    return get(path).json()


def get_network_unused_list(ip_range: str):
    "Return a list of the unused addresses on a given network"
    path = f"/networks/{ip_range}/unused_list"
    history.record_get(path)
    return get(path).json()


def get_network_first_unused(ip_range: str):
    "Returns the first unused address on a network, if any"
    path = f"/networks/{ip_range}/first_unused"
    history.record_get(path)
    return get(path).json()


def get_network_reserved_ips(ip_range: str):
    "Returns the first unused address on a network, if any"
    path = f"/networks/{ip_range}/reserved_list"
    history.record_get(path)
    return get(path).json()


def string_to_int(value, error_tag):
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


def is_valid_network(net: str) -> bool:
    """Check if net is a valid network"""
    if is_valid_ip(net):
        return False
    try:
        ipaddress.ip_network(net)
        return True
    except ValueError:
        return False


def is_valid_ttl(ttl: typing.Union[int, str, bytes]) -> bool:  # int?
    """Check application specific ttl restrictions."""
    if ttl in ("", "default"):
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


def is_valid_location_tag(loc: str) -> bool:
    """Check if valid location tag"""
    return loc in location_tags


def is_valid_category_tag(cat: str) -> bool:
    """Check if valid location tag"""
    return cat in category_tags
