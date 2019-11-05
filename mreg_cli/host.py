import dateutil.parser
import ipaddress
import json
import typing


from .cli import Flag, cli
from .exceptions import HostNotFoundWarning
from .history import history
from .log import cli_error, cli_info, cli_warning
from .util import (
    clean_hostname,
    cname_exists,
    convert_wildcard_to_regex,
    delete,
    first_unused_ip_from_network,
    format_mac,
    get,
    get_list,
    get_network,
    get_network_by_ip,
    get_network_reserved_ips,
    host_info_by_name,
    host_info_by_name_or_ip,
    ip_in_mreg_net,
    is_valid_email,
    is_valid_ip,
    is_valid_ipv4,
    is_valid_ipv6,
    is_valid_mac,
    is_valid_network,
    is_valid_ttl,
    patch,
    post,
    resolve_input_name,
)

#################################
#  Add the main command 'host'  #
#################################

host = cli.add_command(
    prog='host',
    description='Manage hosts.',
)


def print_hinfo(hinfo: dict, padding: int = 14) -> None:
    """Pretty given hinfo id"""
    if hinfo is None:
        return
    print("{1:<{0}}cpu={2} os={3}".format(padding, "Hinfo:", hinfo['cpu'], hinfo['os']))


def zoneinfo_for_hostname(host: str) -> dict:
    """Return zoneinfo for a hostname, or None if not found or invalid"""
    if "." not in host:
        return None

    path = f"/api/v1/zones/forward/hostname/{host}"
    history.record_get(path)
    zoneinfo = get(path, ok404=True)
    return None if zoneinfo is None else zoneinfo.json()


def check_zone_for_hostname(name: str, force: bool, require_zone: bool = False):
    # Require force if FQDN not in MREG zone
    zoneinfo = zoneinfo_for_hostname(name)
    if zoneinfo is None:
        if require_zone:
            cli_warning(f"{name} isn't in a zone controlled by MREG.")
        if not force:
            cli_warning(f"{name} isn't in a zone controlled by MREG, must force")
    elif 'delegation' in zoneinfo and not force:
        delegation = zoneinfo['delegation']['name']
        cli_warning(f"{name} is in zone delegation {delegation}, must force")


def _get_ip_from_args(ip, force, ipversion=None):

    # Try to fail fast for valid IP
    if ipversion is not None and is_valid_ip(ip):
        if ipversion == 4:
            # Fail if input isn't ipv4
            if is_valid_ipv6(ip):
                cli_warning("got ipv6 address, want ipv4.")
            if not is_valid_ipv4(ip):
                cli_warning(f"not valid ipv4 address: {ip}")
        elif ipversion == 6:
            # Fail if input isn't ipv6
            if is_valid_ipv4(ip):
                cli_warning("got ipv4 address, want ipv6.")
            if not is_valid_ipv6(ip):
                cli_warning(f"not valid ipv6 address: {ip}")

    # Handle arbitrary ip from network if received a network w/o mask
    if ip.endswith("/"):
        network = get_network(ip[:-1])
        ip = first_unused_ip_from_network(network)
    # Handle arbitrary ip from network if received a network w/mask
    elif is_valid_network(ip):
        network = get_network(ip)
        ip = first_unused_ip_from_network(network)
    elif is_valid_ip(ip):
        path = f"/api/v1/hosts/?ipaddresses__ipaddress={ip}"
        hosts = get_list(path)
        if hosts and not force:
            hostnames = ','.join([i['name'] for i in hosts])
            cli_warning(f'{ip} already in use by: {hostnames}. Must force')
        network = get_network_by_ip(ip)
        if not network:
            if force:
                return ip
            cli_warning(f"{ip} isn't in a network controlled by MREG, must force")
    else:
        cli_warning(f"Could not determine network for {ip}")

    network_object = ipaddress.ip_network(network['network'])
    if ipversion:
        if network_object.version != ipversion:
            if ipversion == 4:
                cli_warning("Attemptet to get an ipv4 address, but input yielded ipv6")
            elif ipversion == 6:
                cli_warning("Attemptet to get an ipv6 address, but input yielded ipv4")

    if network["frozen"] and not force:
        cli_warning("network {} is frozen, must force"
                    .format(network["network"]))
    # Chat the address given isn't reserved
    reserved_addresses = get_network_reserved_ips(network['network'])
    if ip in reserved_addresses and not force:
        cli_warning("Address is reserved. Requires force")
    if network_object.num_addresses > 2:
        if ip == network_object.network_address.exploded:
            cli_warning("Can't overwrite the network address of the network")
        if ip == network_object.broadcast_address.exploded:
            cli_warning("Can't overwrite the broadcast address of the network")

    return ip


def _check_ipversion(ip, ipversion):
    # Ip sanity check
    if ipversion == 4:
        if not is_valid_ipv4(ip):
            cli_warning(f'not a valid ipv4: {ip}')
    elif ipversion == 6:
        if not is_valid_ipv6(ip):
            cli_warning(f'not a valid ipv6: {ip}')
    else:
        cli_warning(f'Unknown ipversion: {ipversion}')


################################################################################
#                                                                              #
#                              Host manipulation                               #
#                                                                              #
################################################################################


#########################################
#  Implementation of sub command 'add'  #
#########################################

def add(args):
    """Add a new host with the given name.
       ip/network, comment and contact are optional.
    """

    # Fail if given host exists
    name = clean_hostname(args.name)
    try:
        name = resolve_input_name(name)
    except HostNotFoundWarning:
        pass
    else:
        cli_warning("host {} already exists".format(name))

    if "*" in name and not args.force:
        cli_warning("Wildcards must be forced.")

    check_zone_for_hostname(name, args.force)

    if cname_exists(name):
        cli_warning("the name is already in use by a cname")

    if args.ip:
        ip = _get_ip_from_args(args.ip, args.force)

    # Contact sanity check
    if args.contact and not is_valid_email(args.contact):
        cli_warning(
            "invalid mail address ({}) when trying to add {}".format(
                args.contact,
                args.name))

    # Create the new host with an ip address
    path = "/api/v1/hosts/"
    data = {
        "name": name,
        "contact": args.contact or None,
        "comment": args.comment or None,
    }
    if args.ip:
        data['ipaddress'] = ip

    history.record_post(path, resource_name=name, new_data=data)
    post(path, **data)
    msg = f"created host {name}"
    if args.ip:
        msg += f" with IP {ip}"
    cli_info(msg, print_msg=True)


# Add 'add' as a sub command to the 'host' command
host.add_command(
    prog='add',
    description='Add a new host with the given name, ip or network and contact. '
                'comment are optional.',
    short_desc='Add a new host',
    callback=add,
    flags=[
        Flag('name',
             short_desc='Name of new host (req)',
             description='Name of new host (req)'),
        Flag('-ip',
             short_desc='An ip or net',
             description="The hosts ip or a network. If it's a network the first free IP is "
                         "selected from the network",
             metavar='IP/NET'),
        Flag('-contact',
             short_desc='Contact mail for the host',
             description='Contact mail for the host'),
        Flag('-comment',
             short_desc='A comment.',
             description='A comment.'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ]
)


############################################
#  Implementation of sub command 'remove'  #
############################################

def remove(args):
    # args.name, args.force
    """Remove host."""

    # Get host info or raise exception
    info = host_info_by_name_or_ip(args.name)

    warn_msg = ""
    # Require force if host has any cnames.
    cnames = info["cnames"]
    if len(cnames):
        if not args.force:
            warn_msg += "{} cnames. ".format(len(cnames))

    # Require force if host has multiple A/AAAA records
    if len(info["ipaddresses"]) > 1 and not args.force:
        warn_msg += "{} ipaddresses. ".format(len(info["ipaddresses"]))

    # Require force if host has any NAPTR records. Delete the NAPTR records if
    # force
    path = f"/api/v1/naptrs/?host={info['id']}"
    history.record_get(path)
    naptrs = get_list(path)
    if len(naptrs) > 0:
        if not args.force:
            warn_msg += "{} NAPTR records. ".format(len(naptrs))
        else:
            for naptr in naptrs:
                cli_info("deleted NAPTR record {} when removing {}".format(
                    naptr["replacement"],
                    info["name"],
                ))

    # Require force if host has any SRV records. Delete the SRV records if force
    path = f"/api/v1/srvs/?host__name={info['name']}"
    history.record_get(path)
    srvs = get_list(path)
    if len(srvs) > 0:
        if not args.force:
            warn_msg += "{} SRV records. ".format(len(srvs))
        else:
            for srv in srvs:
                cli_info("deleted SRV record {} when removing {}".format(
                    srv["name"],
                    info["name"],
                ))

    # Require force if host has any PTR records. Delete the PTR records if force
    if len(info["ptr_overrides"]) > 0:
        if not args.force:
            warn_msg += "{} PTR records. ".format(len(info["ptr_overrides"]))
        else:
            for ptr in info["ptr_overrides"]:
                cli_info("deleted PTR record {} when removing {}".format(
                    ptr["ipaddress"],
                    info["name"],
                ))

    # To be able to undo the delete the ipaddress field of the 'old_data' has to
    # be an ipaddress string
    if len(info["ipaddresses"]) > 0:
        info["ipaddress"] = info["ipaddresses"][0]["ipaddress"]

    # Warn user and raise exception if any force requirements was found
    if warn_msg:
        cli_warning("{} has: {}Must force".format(info["name"], warn_msg))

    # Delete host
    path = f"/api/v1/hosts/{info['name']}"
    history.record_delete(path, old_data=info)
    delete(path)
    cli_info("removed {}".format(info["name"]), print_msg=True)


# Add 'remove' as a sub command to the 'host' command
host.add_command(
    prog='remove',
    description='Remove the given host.',
    callback=remove,
    flags=[
        Flag('name',
             short_desc='Name or ip.',
             description='Name of host or an ip belonging to the host.',
             metavar='NAME/IP'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ]
)


##########################################
#  Implementation of sub command 'info'  #
##########################################

# first some print helpers

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


def print_ipaddresses(ipaddresses: typing.Iterable[dict], names: bool = False,
                      padding: int = 14) -> None:
    """Pretty print given ip addresses"""
    def _find_padding(lst, attr):
        return max(padding, max([len(i[attr]) for i in lst])+1)
    if not ipaddresses:
        return
    a_records = []
    aaaa_records = []
    len_ip = _find_padding(ipaddresses, 'ipaddress')
    for record in ipaddresses:
        if is_valid_ipv4(record["ipaddress"]):
            a_records.append(record)
        elif is_valid_ipv6(record["ipaddress"]):
            aaaa_records.append(record)
    if names:
        len_names = _find_padding(ipaddresses, 'name')
    else:
        len_names = padding
    for records, text in ((a_records, 'A_Records'), (aaaa_records, 'AAAA_Records')):
        if records:
            print("{1:<{0}}{2:<{3}}  {4}".format(len_names, text, "IP", len_ip, "MAC"))
            for record in records:
                ip = record["ipaddress"]
                mac = record["macaddress"]
                if names:
                    name = record["name"]
                else:
                    name = ""
                print("{1:<{0}}{2:<{3}}  {4}".format(
                    len_names, name, ip if ip else "<not set>", len_ip,
                    mac if mac else "<not set>"))


def print_ttl(ttl: int, padding: int = 14) -> None:
    """Pretty print given ttl"""
    assert isinstance(ttl, int) or ttl is None
    print("{1:<{0}}{2}".format(padding, "TTL:", ttl or "(Default)"))



def print_loc(loc: dict, padding: int = 14) -> None:
    """Pretty print given loc"""
    if loc is None:
        return
    assert isinstance(loc, dict)
    print("{1:<{0}}{2}".format(padding, "Loc:", loc['loc']))


def print_cname(cname: str, host: str, padding: int = 14) -> None:
    """Pretty print given cname"""
    print("{1:<{0}}{2} -> {3}".format(padding, "Cname:", cname, host))


def print_mx(mxs: dict, padding: int = 14) -> None:
    """Pretty print all MXs"""
    if not mxs:
        return
    len_pri = len("Priority")
    print("{1:<{0}}{2} {3}".format(padding, "MX:", "Priority", "Server"))
    for mx in sorted(mxs, key=lambda i: i['priority']):
        print("{1:<{0}}{2:>{3}} {4}".format(padding, "", mx['priority'], len_pri, mx['mx']))


def print_naptr(naptr: dict, host_name: str, padding: int = 14) -> None:
    """Pretty print given txt"""
    assert isinstance(naptr, dict)
    assert isinstance(host_name, str)


def print_ptr(ip: str, host_name: str, padding: int = 14) -> None:
    """Pretty print given txt"""
    assert isinstance(ip, str)
    assert isinstance(host_name, str)
    print("{1:<{0}}{2} -> {3}".format(padding, 'PTR override:', ip, host_name))


def print_txt(txt: str, padding: int = 14) -> None:
    """Pretty print given txt"""
    if txt is None:
        return
    assert isinstance(txt, str)
    print("{1:<{0}}{2}".format(padding, "TXT:", txt))


def _print_host_info(info):
    # Pretty print all host info
    print_host_name(info["name"])
    print_contact(info["contact"])
    if info["comment"]:
        print_comment(info["comment"])
    print_ipaddresses(info["ipaddresses"])
    for ptr in info["ptr_overrides"]:
        print_ptr(ptr["ipaddress"], info["name"])
    print_ttl(info["ttl"])
    print_mx(info['mxs'])
    print_hinfo(info['hinfo'])
    if info["loc"]:
        print_loc(info["loc"])
    for cname in info["cnames"]:
        print_cname(cname["name"], info["name"])
    for txt in info["txts"]:
        print_txt(txt["txt"])
    _srv_show(host_id=info['id'])
    _naptr_show(info)
    _sshfp_show(info)
    cli_info("printed host info for {}".format(info["name"]))


def _print_ip_info(ip):
    """Print all hosts which have a given IP. Also print out PTR override, if any."""
    path = f"/api/v1/hosts/?ipaddresses__ipaddress={ip}&ordering=name"
    ip = ip.lower()
    history.record_get(path)
    hosts = get_list(path)
    ipaddresses = []
    ptrhost = None
    for info in hosts:
        for i in info['ipaddresses']:
            if i['ipaddress'] == ip:
                i['name'] = info['name']
                ipaddresses.append(i)
        for i in info['ptr_overrides']:
            if i['ipaddress'] == ip:
                ptrhost = info['name']

    print_ipaddresses(ipaddresses, names=True)
    if len(ipaddresses) > 1 and ptrhost is None:
        cli_warning(f'IP {ip} used by {len(ipaddresses)} hosts, but no PTR override')
    if ptrhost is None:
        path = f"/api/v1/hosts/?ptr_overrides__ipaddress={ip}"
        history.record_get(path)
        hosts = get_list(path)
        if hosts:
            ptrhost = hosts[0]['name']
        elif ipaddresses:
            ptrhost = 'default'
    if not ipaddresses and ptrhost is None:
        cli_warning(f'Found no hosts or ptr override matching IP {ip}')
    print_ptr(ip, ptrhost)


def info_(args):
    """Print information about host. If <name> is an alias the cname hosts info
    is shown.
    """
    for name_or_ip in args.hosts:
        # Get host info or raise exception
        if is_valid_ip(name_or_ip):
            _print_ip_info(name_or_ip)
        elif is_valid_mac(name_or_ip):
            mac = format_mac(name_or_ip)
            ret = get_list(f'api/v1/hosts/?ipaddresses__macaddress={mac}')
            if ret:
                _print_host_info(ret[0])
            else:
                cli_warning(f'Found no host with macaddress: {mac}')
        else:
            info = host_info_by_name(name_or_ip)
            name = clean_hostname(name_or_ip)
            if any(cname['name'] == name for cname in info['cnames']):
                print(f'{name} is a CNAME for {info["name"]}')
            _print_host_info(info)


# Add 'info' as a sub command to the 'host' command
host.add_command(
    prog='info',
    description='Print info about one or more hosts.',
    short_desc='Print info about one or more hosts.',
    callback=info_,
    flags=[
        Flag('hosts',
             description='One or more hosts given by their name, ip or mac.',
             short_desc='One or more names, ips or macs.',
             nargs='+',
             metavar='NAME/IP/MAC')
    ]
)


def find(args):
    """List hosts maching search criteria
    """

    def _add_param(param, value):
        if '*' not in value:
            value = f'*{value}*'

        params.append(convert_wildcard_to_regex(param, value))

    if not any([args.name, args.comment, args.contact]):
        cli_warning('Need at least one search critera')

    params = []

    for param in ('contact', 'comment', 'name'):
        value = getattr(args, param)
        if value:
            _add_param(param, value)

    path = '/api/v1/hosts/?ordering=name&' + '&'.join(params)
    ret = get(path + '&page_size=1').json()

    if ret['count'] == 0:
        cli_warning('No hosts found.')
    elif ret['count'] > 500:
        cli_warning(f'Too many hits, {ret["count"]}, more than limit of 500. Refine search.')

    ret = get_list(path)
    max_name = max_contact = 20
    for i in ret:
        max_name = max(max_name, len(i['name']))
        max_contact = max(max_contact, len(i['contact']))

    def _print(name, contact, comment):
        print("{0:<{1}} {2:<{3}} {4}".format(name, max_name, contact, max_contact, comment))

    _print('Name', 'Contact', 'Comment')
    for i in ret:
        _print(i['name'], i['contact'], i['comment'])

host.add_command(
    prog='find',
    description='Lists hosts matching search criteria',
    short_desc='Lists hosts matching search criteria',
    callback=find,
    flags=[
        Flag('-name',
             description='Name or part of name',
             short_desc='Name or part of name',
             metavar='NAME'),
        Flag('-comment',
             description='Comment or part of comment',
             short_desc='Comment or part of comment',
             metavar='CONTACT'),
        Flag('-contact',
             description='Contact or part of contact',
             short_desc='Contact or part of contact',
             metavar='CONTACT')
    ]
)


############################################
#  Implementation of sub command 'rename'  #
############################################

def rename(args):
    """Rename host. If <old-name> is an alias then the alias is renamed.
    """

    # Find old host
    old_name = resolve_input_name(args.old_name)

    # Make sure new hostname does not exist.
    new_name = clean_hostname(args.new_name)
    try:
        new_name = resolve_input_name(new_name)
    except HostNotFoundWarning:
        pass
    else:
        if not args.force:
            cli_warning("host {} already exists".format(new_name))

    if cname_exists(new_name):
        cli_warning("the name is already in use by a cname")

    # Require force if FQDN not in MREG zone
    check_zone_for_hostname(new_name, args.force)

    if "*" in new_name and not args.force:
        cli_warning("Wildcards must be forced.")

    old_data = {"name": old_name}
    new_data = {"name": new_name}

    # Rename host
    path = f"/api/v1/hosts/{old_name}"
    # Cannot redo/undo now since it changes name
    history.record_patch(path, new_data, old_data, redoable=False,
                         undoable=False)
    patch(path, name=new_name)

    cli_info("renamed {} to {}".format(old_name, new_name), print_msg=True)


# Add 'rename' as a sub command to the 'host' command
host.add_command(
    prog='rename',
    description='Rename host. If the old name is an alias then the alias is '
                'renamed.',
    short_desc='Rename a host',
    callback=rename,
    flags=[
        Flag('old_name',
             description='Host name of the host to rename. May be an alias. '
                         'If it is an alias then the alias is renamed.',
             short_desc='Existing host name.',
             metavar='OLD'),
        Flag('new_name',
             description='New name for the host, or alias.',
             short_desc='New name',
             metavar='NEW'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ],
)


#################################################
#  Implementation of sub command 'set_comment'  #
#################################################

def set_comment(args):
    """Set comment for host. If <name> is an alias the cname host is updated.
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)
    old_data = {"comment": info["comment"] or ""}
    new_data = {"comment": args.comment}

    # Update comment
    path = f"/api/v1/hosts/{info['name']}"
    history.record_patch(path, new_data, old_data)
    patch(path, comment=args.comment)
    cli_info("updated comment of {} to \"{}\""
             .format(info["name"], args.comment), print_msg=True)


# Add 'set_comment' as a sub command to the 'host' command
host.add_command(
    prog='set_comment',
    description='Set comment for host. If NAME is an alias the cname host is '
                'updated.',
    short_desc='Set comment.',
    callback=set_comment,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
        Flag('comment',
             description='The new comment. If it contains spaces then it must '
                         'be enclosed in quotes.',
             metavar='COMMENT')
    ],
)


#################################################
#  Implementation of sub command 'set_contact'  #
#################################################

def set_contact(args):
    """Set contact for host. If <name> is an alias the cname host is updated.
    """
    # Contact sanity check
    if not is_valid_email(args.contact):
        cli_warning("invalid mail address {} (target host: {})".format(
            args.contact, args.name))

    # Get host info or raise exception
    info = host_info_by_name(args.name)
    old_data = {"contact": info["contact"]}
    new_data = {"contact": args.contact}

    # Update contact information
    path = f"/api/v1/hosts/{info['name']}"
    history.record_patch(path, new_data, old_data)
    patch(path, contact=args.contact)
    cli_info("Updated contact of {} to {}".format(info["name"], args.contact),
             print_msg=True)


# Add 'set_contact' as a sub command to the 'host' command
host.add_command(
    prog='set_contact',
    description='Set contact for host. If NAME is an alias the cname host is '
                'updated.',
    short_desc='Set contact.',
    callback=set_contact,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
        Flag('contact',
             description='Mail address of the contact.',
             metavar='CONTACT')
    ],
)


################################################################################
#                                                                              #
#                                  A records                                   #
#                                                                              #
################################################################################

def _ip_add(args, ipversion):
    info = None

    if "*" in args.name and not args.force:
        cli_warning("Wildcards must be forced.")

    ip = _get_ip_from_args(args.ip, args.force, ipversion=ipversion)

    try:
        # Get host info for or raise exception
        info = host_info_by_name(args.name)
    except HostNotFoundWarning:
        pass

    if info is None:
        hostname = clean_hostname(args.name)
        data = {'name': hostname,
                'ipaddress': ip}
        # Create new host with IP
        path = "/api/v1/hosts/"
        history.record_post(path, ip, data)
        post(path, **data)
        cli_info(f"Created host {hostname} with ip {ip}", print_msg=True)
    else:
        # Require force if host has multiple A/AAAA records
        if len(info["ipaddresses"]) and not args.force:
            cli_warning("{} already has A/AAAA record(s), must force"
                        .format(info["name"]))

        if any(args.ip == i["ipaddress"] for i in info["ipaddresses"]):
            cli_warning(f"Host already has IP {args.ip}")

        data = {
            "host": info["id"],
            "ipaddress": ip,
        }

        # Add IP
        path = "/api/v1/ipaddresses/"
        history.record_post(path, ip, data)
        post(path, **data)
        cli_info(f"added ip {ip} to {info['name']}", print_msg=True)


###########################################
#  Implementation of sub command 'a_add'  #
###########################################

def a_add(args):
    """Add an A record to host. If <name> is an alias the cname host is used.
    """
    _ip_add(args, 4)


# Add 'a_add' as a sub command to the 'host' command
host.add_command(
    prog='a_add',
    description='Add an A record to host. If NAME is an alias the cname host '
                'is used.',
    short_desc='Add A record.',
    callback=a_add,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
        Flag('ip',
             description='The IP of new A record. May also be a network, '
                         'in which case a random IP address from that network '
                         'is chosen.',
             metavar='IP/network'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ],
)


##############################################
#  Implementation of sub command 'a_change'  #
##############################################

def _ip_change(args, ipversion):
    if args.old == args.new:
        cli_warning("New and old IP are equal")

    _check_ipversion(args.old, ipversion)

    # Get host info or raise exception
    info = host_info_by_name(args.name)

    for i in info["ipaddresses"]:
        if i["ipaddress"] == args.old:
            ip_id = i["id"]
            break
    else:
        cli_warning("\"{}\" is not owned by {}".format(args.old, info["name"]))

    new_ip = _get_ip_from_args(args.new, args.force, ipversion=ipversion)

    old_data = {"ipaddress": args.old}
    new_data = {"ipaddress": new_ip}

    # Update A/AAAA records ip address
    path = f"/api/v1/ipaddresses/{ip_id}"
    # Cannot redo/undo since recourse name changes
    history.record_patch(path, new_data, old_data, redoable=False,
                         undoable=False)
    patch(path, ipaddress=new_ip)
    cli_info(
        "changed ip {} to {} for {}".format(args.old, new_ip, info["name"]),
        print_msg=True)


def a_change(args):
    """Change A record. If <name> is an alias the cname host is used.
    """

    _ip_change(args, 4)


# Add 'a_change' as a sub command to the 'host' command
host.add_command(
    prog='a_change',
    description='Change an A record for the target host. If NAME is an alias '
                'the cname host is used.',
    short_desc='Change A record.',
    callback=a_change,
    flags=[
        Flag('name',
             description='Name of the target host.',
             short_desc='Host name.',
             metavar='NAME'),
        Flag('-old',
             description='The existing IP that should be changed.',
             short_desc='IP to change.',
             required=True,
             metavar='IP'),
        Flag('-new',
             description='The new IP address. May also be a network, in which '
                         'case a random IP from that network is chosen.',
             short_desc='New IP.',
             required=True,
             metavar='IP/network'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ],
)

############################################
#  Implementation of sub command 'a_move'  #
############################################


def _ip_move(args, ipversion):
    _check_ipversion(args.ip, ipversion)
    frominfo = host_info_by_name(args.fromhost)
    toinfo = host_info_by_name(args.tohost)
    ip_id = None
    for ip in frominfo['ipaddresses']:
        if ip['ipaddress'] == args.ip:
            ip_id = ip['id']
    ptr_id = None
    for ptr in frominfo['ptr_overrides']:
        if ptr['ipaddress'] == args.ip:
            ptr_id = ptr['id']
    if ip_id is None and ptr_id is None:
        cli_warning(f'Host {frominfo["name"]} have no IP or PTR with address {args.ip}')
    msg = ""
    if ip_id:
        path = f'/api/v1/ipaddresses/{ip_id}'
        patch(path, host=toinfo['id'])
        msg = f'Moved ipaddress {args.ip}'
    else:
        msg += f'No ipaddresses matched. '
    if ptr_id:
        path = f'/api/v1/ptroverrides/{ptr_id}'
        patch(path, host=toinfo['id'])
        msg += 'Moved PTR override.'
    cli_info(msg, print_msg=True)


def a_move(args):
    """Move an IP from a host to another host. Will move also move the PTR, if any.
    """

    _ip_move(args, 4)


# Add 'a_move' as a sub command to the 'host' command
host.add_command(
    prog='a_move',
    description='Move A record from a host to another host',
    short_desc='Move A record',
    callback=a_move,
    flags=[
        Flag('-ip',
             description='IP to move',
             required=True,
             metavar='IP'),
        Flag('-fromhost',
             description='Name of source host',
             required=True,
             metavar='NAME'),
        Flag('-tohost',
             description='Name of destination host',
             required=True,
             metavar='NAME'),
    ],
)


##############################################
#  Implementation of sub command 'a_remove'  #
##############################################

def _ip_remove(args, ipversion):
    ip_id = None

    _check_ipversion(args.ip, ipversion)

    # Check that ip belongs to host
    info = host_info_by_name(args.name)
    for rec in info["ipaddresses"]:
        if rec["ipaddress"] == args.ip:
            ip_id = rec["id"]
            break
    else:
        cli_warning("{} is not owned by {}".format(args.ip, info["name"]))

    old_data = {
        "host": info["id"],
        "ipaddress": args.ip,
    }

    # Remove ip
    path = f"/api/v1/ipaddresses/{ip_id}"
    history.record_delete(path, old_data)
    delete(path)
    cli_info("removed ip {} from {}".format(args.ip, info["name"]),
             print_msg=True)


def a_remove(args):
    """Remove A record from host. If <name> is an alias the cname host is used.
    """

    _ip_remove(args, 4)


# Add 'a_remove' as a sub command to the 'host' command
host.add_command(
    prog='a_remove',
    description='Remove an A record from the target host.',
    short_desc='Remove A record.',
    callback=a_remove,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
        Flag('ip',
             description='IP to remove.',
             metavar='IP'),
    ],
)


############################################
#  Implementation of sub command 'a_show'  #
############################################

def a_show(args):
    """Show hosts ipaddresses. If <name> is an alias the cname host is used.
    """
    info = host_info_by_name(args.name)
    print_ipaddresses(info["ipaddresses"])
    cli_info("showed ip addresses for {}".format(info["name"]))


# Add 'a_show' as a sub command to the 'host' command
host.add_command(
    prog='a_show',
    description='Show hosts ipaddresses. If NAME is an alias the cname host '
                'is used.',
    short_desc='Show ipaddresses.',
    callback=a_show,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
    ],
)


################################################################################
#                                                                              #
#                                 AAAA records                                 #
#                                                                              #
################################################################################


##############################################
#  Implementation of sub command 'aaaa_add'  #
##############################################

def aaaa_add(args):
    """Add an AAAA record to host. If <name> is an alias the cname host is used.
    """
    _ip_add(args, 6)


# Add 'aaaa_add' as a sub command to the 'host' command
host.add_command(
    prog='aaaa_add',
    description=' Add an AAAA record to host. If NAME is an alias the cname '
                'host is used.',
    short_desc='Add AAAA record.',
    callback=aaaa_add,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
        Flag('ip',
             description='The IPv6 to add to target host.',
             metavar='IPv6'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ],
)


#################################################
#  Implementation of sub command 'aaaa_change'  #
#################################################

def aaaa_change(args):
    """Change AAAA record. If <name> is an alias the cname host is used.
    """

    _ip_change(args, 6)


# Add 'aaaa_change' as a sub command to the 'host' command
host.add_command(
    prog='aaaa_change',
    description='Change AAAA record. If NAME is an alias the cname host is '
                'used.',
    short_desc='Change AAAA record.',
    callback=aaaa_change,
    flags=[
        Flag('name',
             description='Name of the target host.',
             short_desc='Host name.',
             metavar='NAME'),
        Flag('-old',
             description='The existing IPv6 that should be changed.',
             short_desc='IPv6 to change.',
             required=True,
             metavar='IPv6'),
        Flag('-new',
             description='The new IPv6 address.',
             short_desc='New IPv6.',
             required=True,
             metavar='IPv6'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ],
)

###############################################
#  Implementation of sub command 'aaaa_move'  #
###############################################


def aaaa_move(args):
    """Move an IP from a host to another host. Will move also move the PTR, if any.
    """

    _ip_move(args, 6)


# Add 'aaaa_move' as a sub command to the 'host' command
host.add_command(
    prog='aaaa_move',
    description='Move AAAA record from a host to another host',
    short_desc='Move AAAA record',
    callback=aaaa_move,
    flags=[
        Flag('-ip',
             description='IP to move',
             required=True,
             metavar='IP'),
        Flag('-fromhost',
             description='Name of source host',
             required=True,
             metavar='NAME'),
        Flag('-tohost',
             description='Name of destination host',
             required=True,
             metavar='NAME'),
    ],
)


#################################################
#  Implementation of sub command 'aaaa_remove'  #
#################################################

def aaaa_remove(args):
    """Remove AAAA record from host. If <name> is an alias the cname host is
    used.
    """
    _ip_remove(args, 6)


# Add 'aaaa_remove' as a sub command to the 'host' command
host.add_command(
    prog='aaaa_remove',
    description='Remove AAAA record from host. If NAME is an alias the cname '
                'host is used.',
    short_desc='Remove AAAA record.',
    callback=aaaa_remove,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
        Flag('ip',
             description='IPv6 to remove.',
             metavar='IPv6'),
    ],
)


###############################################
#  Implementation of sub command 'aaaa_show'  #
###############################################

def aaaa_show(args):
    """Show hosts ipaddresses. If <name> is an alias the cname host is used.
    """
    info = host_info_by_name(args.name)
    print_ipaddresses(info["ipaddresses"])
    cli_info("showed aaaa records for {}".format(info["name"]))


# Add 'aaaa_show' as a sub command to the 'host' command
host.add_command(
    prog='aaaa_show',
    description='Show hosts AAAA records. If NAME is an alias the cname host '
                'is used.',
    short_desc='Show AAAA records.',
    callback=aaaa_show,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
    ],
)


################################################################################
#                                                                              #
#                                CNAME records                                 #
#                                                                              #
################################################################################


###############################################
#  Implementation of sub command 'cname_add'  #
###############################################

def cname_add(args):
    """Add a CNAME record to host.
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

    data = {'host': info['id'],
            'name': alias}
    # Create CNAME record
    path = "/api/v1/cnames/"
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info("Added cname alias {} for {}".format(alias, info["name"]),
             print_msg=True)


# Add 'cname_add' as a sub command to the 'host' command
host.add_command(
    prog='cname_add',
    description='Add a CNAME record to host. If NAME is an alias '
                'the cname host is used as target for ALIAS.',
    short_desc='Add CNAME.',
    callback=cname_add,
    flags=[
        Flag('name',
             description='Name of target host.',
             metavar='NAME'),
        Flag('alias',
             description='Name of CNAME host.',
             metavar='ALIAS'),
    ],
)


##################################################
#  Implementation of sub command 'cname_remove'  #
##################################################

def cname_remove(args):
    """Remove CNAME record.
    """
    info = host_info_by_name(args.name)
    hostname = info['name']
    alias = clean_hostname(args.alias)

    if not info['cnames']:
        cli_warning("\"{}\" doesn't have any CNAME records.".format(hostname))

    for cname in info['cnames']:
        if cname['name'] == alias:
            break
    else:
        cli_warning("\"{}\" is not an alias for \"{}\"".format(alias, hostname))

    # Delete CNAME host
    path = f"/api/v1/cnames/{alias}"
    history.record_delete(path, dict(), undoable=False)
    delete(path)
    cli_info("Removed cname alias {} for {}".format(alias, hostname),
             print_msg=True)


# Add 'cname_remove' as a sub command to the 'host' command
host.add_command(
    prog='cname_remove',
    description='Remove CNAME record.',
    callback=cname_remove,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
        Flag('alias',
             description='Name of CNAME to remove.',
             metavar='CNAME'),
    ],
)


################################################
#  Implementation of sub command 'cname_show'  #
################################################

def cname_show(args):
    """Show CNAME records for host. If <name> is an alias the cname hosts
    aliases are shown.
    """
    try:
        info = host_info_by_name(args.name)
        for cname in info["cnames"]:
            print_cname(cname["name"], info["name"])
        cli_info("showed cname aliases for {}".format(info["name"]))
        return
    except HostNotFoundWarning:
        # Try again with the alias
        pass

    name = clean_hostname(args.name)
    path = f"/api/v1/hosts/?cnames__name={name}"
    history.record_get(path)
    hosts = get_list(path)
    if len(hosts):
        print_cname(name, hosts[0]["name"])
    else:
        cli_warning("No cname found for {}".format(name))


# Add 'cname_show' as a sub command to the 'host' command
host.add_command(
    prog='cname_show',
    description='Show CNAME records for host. If NAME is an alias the cname '
                'hosts aliases are shown.',
    short_desc='Show CNAME records.',
    callback=cname_show,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
    ],
)


################################################################################
#                                                                              #
#                                HINFO records                                 #
#                                                                              #
################################################################################

def _hinfo_remove(host_) -> None:
    """
    Helper method to remove hinfo from a host.
    """
    old_data = {"hinfo": host_["hinfo"]}
    new_data = {"hinfo": ""}

    # Set hinfo to null value
    path = f"/api/v1/hosts/{host_['name']}"
    history.record_patch(path, new_data, old_data)
    patch(path, hinfo="")



###############################################
#  Implementation of sub command 'hinfo_add'  #
###############################################

def hinfo_add(args):
    """Add hinfo for host. If <name> is an alias the cname host is updated.
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)

    if info['hinfo']:
        cli_warning(f"{info['name']} already has hinfo set.")

    data = {
        "host": info["id"],
        "cpu": args.cpu,
        "os": args.os
    }
    # Add HINFO record to host
    path = "/api/v1/hinfos/"
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info("Added HINFO record to {}".format(info["name"]), print_msg=True)


host.add_command(
    prog='hinfo_add',
    description='Add HINFO for host. If NAME is an alias the cname host is '
                'updated.',
    short_desc='Set HINFO.',
    callback=hinfo_add,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
        Flag('cpu',
             description='CPU/hardware',
             metavar='CPU'),
        Flag('os',
             description='Operating system',
             metavar='OS'),
    ],
)


##################################################
#  Implementation of sub command 'hinfo_remove'  #
##################################################

def hinfo_remove(args):
    """
    hinfo_remove <name>
        Remove hinfo for host. If <name> is an alias the cname host is updated.
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)

    if not info['hinfo']:
        cli_warning(f"{info['name']} already has no hinfo set.")
    host_id = info['id']
    path = f"/api/v1/hinfos/{host_id}"
    history.record_delete(path, host_id)
    delete(path)
    cli_info("deleted HINFO from {}".format(info['name']), True)


# Add 'hinfo_remove' as a sub command to the 'host' command
host.add_command(
    prog='hinfo_remove',
    description='Remove hinfo for host. If NAME is an alias the cname host is '
                'updated.',
    short_desc='Remove HINFO.',
    callback=hinfo_remove,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
    ],
)



################################################
#  Implementation of sub command 'hinfo_show'  #
################################################

def hinfo_show(args):
    """Show hinfo for host. If <name> is an alias the cname hosts hinfo is
    shown.
    """
    info = host_info_by_name(args.name)
    if info["hinfo"]:
        print_hinfo(info["hinfo"])
    else:
        cli_info("No hinfo for {}".format(args.name), print_msg=True)
    cli_info("showed hinfo for {}".format(info["name"]))


# Add 'hinfo_show' as a sub command to the 'host' command
host.add_command(
    prog='hinfo_show',
    description='Show hinfo for host. If NAME is an alias the cname hosts '
                'hinfo is shown.',
    short_desc='Show HINFO.',
    callback=hinfo_show,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
    ],
)

def _history(args):
    """Show host history for name"""
    hostname = clean_hostname(args.name)

    def _remove_unneded_keys(data):
        for key in ('id', 'created_at', 'updated_at',):
            data.pop(key, None)

    # First check if any model id with the name exists
    base_path = "/api/v1/history/?resource=host"
    ret = get(f"{base_path}&name={hostname}&page_size=1").json()
    if ret["count"] == 0:
        cli_info(f"No history found for {hostname}", True)
        return
    model_id = ret["results"][0]["model_id"]
    ret = get_list(f"{base_path}&model_id={model_id}")
    for i in ret:
        timestamp = dateutil.parser.parse(i['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        msg = ''
        data = json.loads(i['data'])
        action = i['action']
        model = i['model']
        if action == 'create':
            msg = ', '.join(f"{k} = '{v}'" for k,v in data.items())
        elif action == 'update':
            if model in ('Ipaddress', ):
                msg = data['current_data']['ipaddress'] + ', '
            changes = []
            for key, newval in data['update'].items():
                oldval = data["current_data"][key] or 'not set'
                newval = newval or 'not set'
                changes.append(f"{key}: {oldval} -> {newval}")
            msg += ','.join(changes)
        elif action == 'destroy':
            _remove_unneded_keys(data)
            if model == 'Host':
                msg = "deleted " + i["name"]
            else:
                msg = ', '.join(f"{k} = '{v}'" for k,v in data.items())
        else:
            cli_warning(f'Unhandled history entry: {i}')

        print(f"{timestamp} [{i['user']}]: {model} {action}: {msg}")


host.add_command(
    prog='history',
    description='Show history for hostname',
    short_desc='Show history for hostname',
    callback=_history,
    flags=[
        Flag('name',
             description='Hostname',
             metavar='NAME'),
    ],
)



################################################################################
#                                                                              #
#                                 LOC records                                  #
#                                                                              #
################################################################################


################################################
#  Implementation of sub command 'loc_remove'  #
################################################

def loc_remove(args):
    """Remove location from host. If <name> is an alias the cname host is
    updated.
    """

    # Get host info or raise exception
    info = host_info_by_name(args.name)
    if not info['loc']:
        cli_warning(f"{info['name']} already has no loc set.")
    host_id = info['id']
    path = f"/api/v1/locs/{host_id}"
    history.record_delete(path, host_id)
    delete(path)

    cli_info("removed LOC for {}".format(info["name"]), print_msg=True)


# Add 'loc_remove' as a sub command to the 'host' command
host.add_command(
    prog='loc_remove',
    description='Remove location from host. If NAME is an alias the cname host '
                'is updated.',
    short_desc='Remove LOC record.',
    callback=loc_remove,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
    ],
)


#############################################
#  Implementation of sub command 'loc_add'  #
#############################################

def loc_add(args):
    """Set location of host. If <name> is an alias the cname host is updated.
    """

    # Get host info or raise exception
    info = host_info_by_name(args.name)

    if info['loc']:
        cli_warning(f"{info['name']} already has loc set.")

    data = {
        "host": info["id"],
        "loc": args.loc
    }
    path = "/api/v1/locs/"
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info("added LOC '{}' for {}".format(args.loc, info["name"]),
             print_msg=True)


host.add_command(
    prog='loc_add',
    description='Set location of host. If NAME is an alias the cname host is '
                'updated.',
    short_desc='Set LOC record.',
    callback=loc_add,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
        Flag('loc',
             description='New LOC.',
             metavar='LOC'),
    ],
)


##############################################
#  Implementation of sub command 'loc_show'  #
##############################################

def loc_show(args):
    """Show location of host. If <name> is an alias the cname hosts LOC is
    shown.
    """
    info = host_info_by_name(args.name)
    if info["loc"]:
        print_loc(info["loc"])
    else:
        cli_info("No LOC for {}".format(args.name), print_msg=True)
    cli_info("showed LOC for {}".format(info["name"]))


# Add 'loc_show' as a sub command to the 'host' command
host.add_command(
    prog='loc_show',
    description='Show location of host. If NAME is an alias the cname hosts '
                'LOC is shown.',
    short_desc='Show LOC record.',
    callback=loc_show,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
    ],
)


###############################################################################
#                                                                             #
#                                 MX records                                  #
#                                                                             #
###############################################################################

def _mx_in_mxs(mxs, priority, mx):
    for info in mxs:
        if info['priority'] == priority and info['mx'] == mx:
            return info['id']
    return None


#############################################
#  Implementation of sub command 'mx_add'  #
#############################################

def mx_add(args):
    """Add a mx record to host. <text> must be enclosed in double quotes if it
    contains more than one word.
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)
    if _mx_in_mxs(info['mxs'], args.priority, args.mx):
        cli_warning("{} already has that MX defined".format(info['name']))

    data = {
        "host": info["id"],
        "priority": args.priority,
        "mx": args.mx
    }
    # Add MX record to host
    path = "/api/v1/mxs/"
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info("Added MX record to {}".format(info["name"]), print_msg=True)


# Add 'mx_add' as a sub command to the 'host' command
host.add_command(
    prog='mx_add',
    description='Add a MX record to host.',
    short_desc='Add MX record.',
    callback=mx_add,
    flags=[
        Flag('name',
             description='Host target name.',
             metavar='NAME'),
        Flag('priority',
             description='Priority',
             type=int,
             metavar='PRIORITY'),
        Flag('mx',
             description='Mail Server',
             metavar='MX'),
    ],
)


################################################
#  Implementation of sub command 'mx_remove'  #
################################################

def mx_remove(args):
    """Remove MX record for host.
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)

    mx_id = _mx_in_mxs(info['mxs'], args.priority, args.mx)
    if mx_id is None:
        cli_warning("{} has no MX records with priority {} and mail exhange {}".format(
                    info['name'], args.priority, args.mx))
    path = f"/api/v1/mxs/{mx_id}"
    history.record_delete(path, mx_id)
    delete(path)
    cli_info("deleted MX from {}".format(info['name']), True)


# Add 'mx_remove' as a sub command to the 'host' command
host.add_command(
    prog='mx_remove',
    description=' Remove MX record for host.',
    short_desc='Remove MX record.',
    callback=mx_remove,
    flags=[
        Flag('name',
             description='Host target name.',
             metavar='NAME'),
        Flag('priority',
             description='Priority',
             type=int,
             metavar='PRIORITY'),
        Flag('mx',
             description='Mail Server',
             metavar='TEXT'),
    ],
)


##############################################
#  Implementation of sub command 'mx_show'  #
##############################################

def mx_show(args):
    """Show all MX records for host.
    """
    info = host_info_by_name(args.name)
    path = f"/api/v1/mxs/?host={info['id']}"
    history.record_get(path)
    mxs = get_list(path)
    print_mx(mxs, padding=5)
    cli_info("showed MX records for {}".format(info['name']))


# Add 'mx_show' as a sub command to the 'host' command
host.add_command(
    prog='mx_show',
    description='Show all MX records for host.',
    short_desc='Show MX records.',
    callback=mx_show,
    flags=[
        Flag('name',
             description='Host target name.',
             metavar='NAME'),
    ],
)


################################################################################
#                                                                              #
#                                NAPTR records                                 #
#                                                                              #
################################################################################


###############################################
#  Implementation of sub command 'naptr_add'  #
###############################################

def naptr_add(args):
    """Add a NAPTR record to host.
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)

    data = {
        "preference": args.preference,
        "order": args.order,
        "flag": args.flag,
        "service": args.service,
        "regex": args.regex,
        "replacement": args.replacement,
        "host": info["id"],
    }

    # Create NAPTR record
    path = "/api/v1/naptrs/"
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info("created NAPTR record for {}".format(info["name"]), print_msg=True)


# Add 'naptr_add' as a sub command to the 'host' command
host.add_command(
    prog='naptr_add',
    description='Add a NAPTR record to host.',
    short_desc='Add NAPTR record.',
    callback=naptr_add,
    flags=[
        Flag('-name',
             description='Name of the target host.',
             required=True,
             metavar='NAME'),
        Flag('-preference',
             description='NAPTR preference.',
             type=int,
             required=True,
             metavar='PREFERENCE'),
        Flag('-order',
             description='NAPTR order.',
             type=int,
             required=True,
             metavar='ORDER'),
        Flag('-flag',
             description='NAPTR flag.',
             required=True,
             metavar='FLAG'),
        Flag('-service',
             description='NAPTR service.',
             required=True,
             metavar='SERVICE'),
        Flag('-regex',
             description='NAPTR regexp.',
             required=True,
             metavar='REGEXP'),
        Flag('-replacement',
             description='NAPTR replacement.',
             required=True,
             metavar='REPLACEMENT'),
    ],
)


##################################################
#  Implementation of sub command 'naptr_remove'  #
##################################################

def naptr_remove(args):
    """
    naptr_remove <name> <replacement>
        Remove NAPTR record.
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)

    # get the hosts NAPTR records where repl is a substring of the replacement
    # field
    path = f"/api/v1/naptrs/?replacement__contains={args.replacement}&host={info['id']}"
    history.record_get(path)
    naptrs = get_list(path)

    data = None
    attrs = ('preference', 'order', 'flag', 'service', 'regex', 'replacement',)
    for naptr in naptrs:
        if all(naptr[attr] == getattr(args, attr) for attr in attrs):
            data = naptr

    if data is None:
        cli_warning("Did not find any matching NAPTR record.")

    # Delete NAPTR record
    path = f"/api/v1/naptrs/{data['id']}"
    history.record_delete(path, data)
    delete(path)
    cli_info("deleted NAPTR record for {}".format(info["name"]), print_msg=True)


# Add 'naptr_remove' as a sub command to the 'host' command
host.add_command(
    prog='naptr_remove',
    description='Remove NAPTR record.',
    callback=naptr_remove,
    flags=[
        Flag('-name',
             description='Name of the target host.',
             required=True,
             metavar='NAME'),
        Flag('-preference',
             description='NAPTR preference.',
             type=int,
             required=True,
             metavar='PREFERENCE'),
        Flag('-order',
             description='NAPTR order.',
             type=int,
             required=True,
             metavar='ORDER'),
        Flag('-flag',
             description='NAPTR flag.',
             required=True,
             metavar='FLAG'),
        Flag('-service',
             description='NAPTR service.',
             required=True,
             metavar='SERVICE'),
        Flag('-regex',
             description='NAPTR regexp.',
             required=True,
             metavar='REGEXP'),
        Flag('-replacement',
             description='NAPTR replacement.',
             required=True,
             metavar='REPLACEMENT'),
    ],
)


################################################
#  Implementation of sub command 'naptr_show'  #
################################################

def _naptr_show(info):
    path = f"/api/v1/naptrs/?host={info['id']}"
    history.record_get(path)
    naptrs = get_list(path)
    headers = ("NAPTRs:", "Preference", "Order", "Flag", "Service", "Regex", "Replacement")
    row_format = '{:<14}' * len(headers) 
    if naptrs:
        print(row_format.format(*headers))
        for naptr in naptrs:
            print(row_format.format(
                '',
                naptr["preference"],
                naptr["order"],
                naptr["flag"],
                naptr["service"],
                naptr["regex"] or '""',
                naptr["replacement"],
            ))
    return len(naptrs)


def naptr_show(args):
    """Show all NAPTR records for host.
    """
    info = host_info_by_name(args.name)
    num_naptrs = _naptr_show(info)
    if num_naptrs == 0:
        print(f"No naptrs for {info['name']}")
    cli_info("showed {} NAPTR records for {}".format(num_naptrs, info["name"]))


# Add 'naptr_show' as a sub command to the 'host' command
host.add_command(
    prog='naptr_show',
    description='Show all NAPTR records for host.',
    short_desc='Show NAPTR records.',
    callback=naptr_show,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
    ],
)


################################################################################
#                                                                              #
#                                 PTR records                                  #
#                                                                              #
################################################################################


################################################
#  Implementation of sub command 'ptr_change'  #
################################################

def ptr_change(args):
    """Move PTR record from <old-name> to <new-name>.
    """
    # Get host info or raise exception
    old_info = host_info_by_name(args.old)
    new_info = host_info_by_name(args.new)

    # check that new host haven't got a ptr record already
    if len(new_info["ptr_overrides"]):
        cli_warning("{} already got a PTR record".format(new_info["name"]))

    # check that old host has a PTR record with the given ip
    if not len(old_info["ptr_overrides"]):
        cli_warning("no PTR record for {} with ip {}".format(old_info["name"],
                                                             args.ip))
    if old_info["ptr_overrides"][0]["ipaddress"] != args.ip:
        cli_warning("{} PTR record doesn't match {}".format(old_info["name"],
                                                            args.ip))

    # change PTR record
    data = {
        "host": new_info["id"],
    }

    path = "/api/v1/ptroverrides/{}".format(old_info["ptr_overrides"][0]["id"])
    history.record_patch(path, data, old_info["ptr_overrides"][0])
    patch(path, **data)
    cli_info("changed owner of PTR record {} from {} to {}".format(
        args.ip,
        old_info["name"],
        new_info["name"],
    ), print_msg=True)


# Add 'ptr_change' as a sub command to the 'host' command
host.add_command(
    prog='ptr_change',
    description='Move PTR record from OLD to NEW.',
    short_desc='Move PTR record.',
    callback=ptr_change,
    flags=[
        Flag('-ip',
             description='IP of PTR record. May be IPv4 or IPv6.',
             short_desc='IP of PTR record.',
             required=True,
             metavar='IP'),
        Flag('-old',
             description='Name of old host.',
             required=True,
             metavar='NAME'),
        Flag('-new',
             description='Name of new host.',
             required=True,
             metavar='NAME'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ],
)


################################################
#  Implementation of sub command 'ptr_remove'  #
################################################

def ptr_remove(args):
    """Remove PTR record from host.
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)

    for ptr in info['ptr_overrides']:
        if ptr['ipaddress'] == args.ip:
            ptr_id = ptr['id']
            break
    else:
        cli_warning("no PTR record for {} with ip {}".format(info["name"],
                                                             args.ip))

    # Delete record
    path = f"/api/v1/ptroverrides/{ptr_id}"
    history.record_delete(path, ptr_id)
    delete(path)
    cli_info("deleted PTR record {} for {}".format(args.ip, info["name"]),
             print_msg=True)


# Add 'ptr_remove' as a sub command to the 'host' command
host.add_command(
    prog='ptr_remove',
    description='Remove PTR record from host.',
    short_desc='Remove PTR record.',
    callback=ptr_remove,
    flags=[
        Flag('ip',
             description='IP of PTR record. May be IPv4 or IPv6.',
             metavar='IP'),
        Flag('name',
             description='Name of host.',
             metavar='NAME'),
    ],
)


#############################################
#  Implementation of sub command 'ptr_add'  #
#############################################

def ptr_add(args):
    """Create a PTR record for host.
    """
    # Ip sanity check
    if not is_valid_ip(args.ip):
        cli_warning("invalid ip: {}".format(args.ip))
    if not ip_in_mreg_net(args.ip):
        cli_warning("{} isn't in a network controlled by MREG".format(args.ip))

    # Get host info or raise exception
    info = host_info_by_name(args.name)

    # check that a PTR record with the given ip doesn't exist
    path = f"/api/v1/ptroverrides/?ipaddress={args.ip}"
    history.record_get(path)
    ptrs = get_list(path)
    if len(ptrs):
        cli_warning("{} already exist in a PTR record".format(args.ip))
    # check if host is in mreg controlled zone, must force if not
    if info['zone'] is None and not args.force:
        cli_warning("{} isn't in a zone controlled by MREG, must force"
                    .format(info["name"]))

    network = get_network_by_ip(args.ip)
    reserved_addresses = get_network_reserved_ips(network['network'])
    if args.ip in reserved_addresses and not args.force:
        cli_warning("Address is reserved. Requires force")

    # create PTR record
    data = {
        "host": info["id"],
        "ipaddress": args.ip,
    }
    path = "/api/v1/ptroverrides/"
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info("Added PTR record {} to {}".format(args.ip, info["name"]),
             print_msg=True)


# Add 'ptr_add' as a sub command to the 'host' command
host.add_command(
    prog='ptr_add',
    description='Create a PTR record for host.',
    short_desc='Add PTR record.',
    callback=ptr_add,
    flags=[
        Flag('ip',
             description='IP of PTR record. May be IPv4 or IPv6.',
             metavar='IP'),
        Flag('name',
             description='Name of host.',
             metavar='NAME'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ],
)


##############################################
#  Implementation of sub command 'ptr_show'  #
##############################################

def ptr_show(args):
    """Show PTR record matching given ip.
    """

    if not is_valid_ip(args.ip):
        cli_warning(f"{args.ip} is not a valid IP")

    path = f"/api/v1/hosts/?ptr_overrides__ipaddress={args.ip}"
    history.record_get(path)
    host = get_list(path)

    if host:
        host = host[0]
        for ptr in host["ptr_overrides"]:
            if args.ip == ptr["ipaddress"]:
                padding = len(args.ip)
                print_ptr(args.ip, host["name"], padding)
    else:
        print(f"No PTR found for IP '{args.ip}'")


# Add 'ptr_show' as a sub command to the 'host' command
host.add_command(
    prog='ptr_show',
    description='Show PTR record matching given ip (empty input shows all '
                'PTR records).',
    short_desc='Show PTR record.',
    callback=ptr_show,
    flags=[
        Flag('ip',
             description='IP of PTR record. May be IPv4 or IPv6.',
             metavar='IP'),
    ],
)


################################################################################
#                                                                              #
#                                 SRV records                                  #
#                                                                              #
################################################################################


#############################################
#  Implementation of sub command 'srv_add'  #
#############################################

def srv_add(args):
    """Add SRV record.
    """

    sname = clean_hostname(args.name)
    check_zone_for_hostname(sname, False, require_zone=True)

    # Require host target
    info = host_info_by_name(args.host)

    # Require force if target host not in MREG zone
    check_zone_for_hostname(info['name'], args.force)

    data = {
        "name": sname,
        "priority": args.priority,
        "weight": args.weight,
        "port": args.port,
        "host": info['id'],
    }

    # Create new SRV record
    path = "/api/v1/srvs/"
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info("Added SRV record {} with target {}".format(sname, info['name']),
             print_msg=True)


# Add 'srv_add' as a sub command to the 'host' command
host.add_command(
    prog='srv_add',
    description='Add SRV record.',
    callback=srv_add,
    flags=[
        Flag('-name',
             description='SRV service.',
             required=True,
             metavar='SERVICE'),
        Flag('-priority',
             description='SRV priority.',
             required=True,
             metavar='PRIORITY'),
        Flag('-weight',
             description='SRV weight.',
             required=True,
             metavar='WEIGHT'),
        Flag('-port',
             description='SRV port.',
             required=True,
             metavar='PORT'),
        Flag('-host',
             description='Host target name.',
             required=True,
             metavar='NAME'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ],
)


################################################
#  Implementation of sub command 'srv_remove'  #
################################################

def srv_remove(args):
    """Remove SRV record.
    """
    info = host_info_by_name(args.host)
    sname = clean_hostname(args.name)

    # Check if service exist
    path = f"/api/v1/srvs/?name={sname}&host={info['id']}"
    history.record_get(path)
    srvs = get_list(path)
    if len(srvs) == 0:
        cli_warning(f"no service named {sname}")

    data = None
    attrs = ('name', 'priority', 'weight', 'port',)
    for srv in srvs:
        if all(srv[attr] == getattr(args, attr) for attr in attrs):
            data = srv
            break

    if data is None:
        cli_warning("Did not find any matching SRV records.")

    # Delete SRV record
    path = f"/api/v1/srvs/{data['id']}"
    history.record_delete(path, data)
    delete(path)
    cli_info("deleted SRV record for {}".format(info["name"]), print_msg=True)


# Add 'srv_remove' as a sub command to the 'host' command
host.add_command(
    prog='srv_remove',
    description='Remove SRV record.',
    callback=srv_remove,
    flags=[
        Flag('-name',
             description='SRV service.',
             required=True,
             metavar='SERVICE'),
        Flag('-priority',
             description='SRV priority.',
             type=int,
             required=True,
             metavar='PRIORITY'),
        Flag('-weight',
             description='SRV weight.',
             type=int,
             required=True,
             metavar='WEIGHT'),
        Flag('-port',
             description='SRV port.',
             type=int,
             required=True,
             metavar='PORT'),
        Flag('-host',
             description='Host target name.',
             required=True,
             metavar='NAME'),
    ],
)


##############################################
#  Implementation of sub command 'srv_show'  #
##############################################

def _srv_show(srvs=None, host_id=None):
    assert srvs is not None or host_id is not None
    hostid2name = dict()
    host_ids = set()

    def print_srv(srv: dict, hostname: str, padding: int = 14) -> None:
        """Pretty print given srv"""
        print("SRV: {1:<{0}} {2:^6} {3:^6} {4:^6} {5}".format(
            padding,
            srv["name"],
            srv["priority"],
            srv["weight"],
            srv["port"],
            hostname,
        ))

    if srvs is None:
        path = f"/api/v1/srvs/?host={host_id}"
        history.record_get(path)
        srvs = get_list(path)

    if len(srvs) == 0:
        return

    padding = 0

    # Print records
    for srv in srvs:
        if len(srv["name"]) > padding:
            padding = len(srv["name"])
        host_ids.add(str(srv['host']))

    arg = ','.join(host_ids)
    hosts = get_list(f'/api/v1/hosts/?id__in={arg}')
    for host in hosts:
        hostid2name[host['id']] = host['name']

    prev_name = ""
    for srv in srvs:
        if prev_name == srv["name"]:
            srv["name"] = ""
        else:
            prev_name = srv["name"]
        print_srv(srv, hostid2name[srv['host']], padding)


def srv_show(args):
    """Show SRV records for the service.
    """

    sname = clean_hostname(args.service)

    # Get all matching SRV records
    path = f"/api/v1/srvs/?name={sname}"
    history.record_get(path)
    srvs = get_list(path)
    if len(srvs) == 0:
        cli_warning("no service matching {}".format(sname))
    else:
        _srv_show(srvs=srvs)
    cli_info("showed entries for SRV {}".format(sname))


# Add 'srv_show' as a sub command to the 'host' command
host.add_command(
    prog='srv_show',
    description='Show SRV records for the service.',
    short_desc='Show SRV records.',
    callback=srv_show,
    flags=[
        Flag('service',
             description='Host target name.',
             metavar='SERVICE'),
    ],
)


################################################################################
#                                                                              #
#                                 SSHFP records                                #
#                                                                              #
################################################################################


#############################################
# Implementation of sub command 'sshfp_add' #
#############################################

def sshfp_add(args):
    """Add SSHFP record.
    """

    # Get host info or raise exception
    info = host_info_by_name(args.name)

    data = {
        "algorithm": args.algorithm,
        "hash_type": args.hash_type,
        "fingerprint": args.fingerprint,
        "host": info["id"],
    }

    # Create new SSHFP record
    path = "/api/v1/sshfps/"
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info("Added SSHFP record {} for host {}"
             .format(args.fingerprint, info["name"]), print_msg=True)


# Add 'sshfp_add' as a sub command to the 'host' command
host.add_command(
    prog='sshfp_add',
    description='Add SSHFP record.',
    callback=sshfp_add,
    flags=[
        Flag('name',
             description='Host target name.',
             metavar='NAME'),
        Flag('algorithm',
             description='SSH algorithm.',
             metavar='ALGORITHM'),
        Flag('hash_type',
             description='Hash type.',
             metavar='HASH_TYPE'),
        Flag('fingerprint',
             description='Hexadecimal fingerprint.',
             metavar='FINGERPRINT'),
    ],
)


################################################
# Implementation of sub command 'sshfp_remove' #
################################################

def sshfp_remove(args):
    """Remove SSHFP record with a given fingerprint from the host.
       A missing fingerprint removes all SSHFP records for the host.
    """

    def _delete_sshfp_record(sshfp: dict, hname: str):
        path = f"/api/v1/sshfps/{sshfp['id']}"
        history.record_delete(path, sshfp, redoable=False)
        delete(path)
        cli_info("removed SSHFP record with fingerprint {} for {}".format(sshfp["fingerprint"],
                                                                          hname),
                 print_msg=True)

    # Get host info or raise exception
    info = host_info_by_name(args.name)
    hid = info["id"]

    # Get all matching SSHFP records
    path = f"/api/v1/sshfps/?host={hid}"
    history.record_get(path)
    sshfps = get_list(path)
    if len(sshfps) < 1:
        cli_warning("no SSHFP records matching {}".format(info["name"]))

    if args.fingerprint:
        found = False
        for sshfp in sshfps:
            if sshfp["fingerprint"] == args.fingerprint:
                _delete_sshfp_record(sshfp, info["name"])
                found = True
        if not found:
            cli_info("found no SSHFP record with fingerprint {} for {}".format(args.fingerprint,
                                                                               info["name"]),
                     print_msg=True)
    else:
        for sshfp in sshfps:
            _delete_sshfp_record(sshfp, info["name"])


# Add 'sshfp_remove' as a sub command to the 'host' command
host.add_command(
    prog='sshfp_remove',
    description='Remove SSHFP record with a given fingerprint from the host. '
                'A missing fingerprint removes all SSHFP records for the host.',
    callback=sshfp_remove,
    flags=[
        Flag('name',
             description='Host target name.',
             metavar='NAME'),
        Flag('-fingerprint',
             description='Hexadecimal fingerprint.',
             metavar='FINGERPRINT'),
    ],
)


##############################################
# Implementation of sub command 'sshfp_show' #
##############################################

def _sshfp_show(info):
    path = f"/api/v1/sshfps/?host={info['id']}"
    history.record_get(path)
    sshfps = get_list(path)
    headers = ("SSHFPs:", "Algorithm", "Type", "Fingerprint")
    row_format = '{:<14}' * len(headers)
    if sshfps:
        print(row_format.format(*headers))
        for sshfp in sshfps:
            print(row_format.format(
                '',
                sshfp["algorithm"],
                sshfp["hash_type"],
                sshfp["fingerprint"],
            ))
    return len(sshfps)

def sshfp_show(args):
    """Show SSHFP records for the host.
    """

    # Get host info or raise exception
    info = host_info_by_name(args.name)
    num_sshfps = _sshfp_show(info)
    if num_sshfps == 0:
        cli_warning(f"no SSHFP records for {info['name']}")


# Add 'sshfp_show' as a sub command to the 'host' command
host.add_command(
    prog='sshfp_show',
    description='Show SSHFP records for the host.',
    short_desc='Show SSHFP record.',
    callback=sshfp_show,
    flags=[
        Flag('name',
             description='Host target name.',
             metavar='NAME'),
    ],
)


################################################################################
#                                                                              #
#                                 TTL records                                  #
#                                                                              #
################################################################################


################################################
#  Implementation of sub command 'ttl_remove'  #
################################################

def ttl_remove(args):
    """Remove explicit TTL for host. If <name> is an alias the alias host is
    updated.
    """
    info = host_info_by_name(args.name)
    old_data = {"ttl": info["ttl"]}
    new_data = {"ttl": ""}

    # Remove TTL value
    path = f"/api/v1/hosts/{info['name']}"
    history.record_patch(path, new_data, old_data)
    patch(path, ttl="")
    cli_info("removed TTL for {}".format(info["name"]), print_msg=True)


# Add 'ttl_remove' as a sub command to the 'host' command
host.add_command(
    prog='ttl_remove',
    description='Remove explicit TTL for host. If NAME is an alias the alias '
                'host is updated.',
    short_desc='Remove TTL record.',
    callback=ttl_remove,
    flags=[
        Flag('name',
             description='Host target name.',
             metavar='NAME'),
    ],
)


#############################################
#  Implementation of sub command 'ttl_set'  #
#############################################

def ttl_set(args):
    """Set ttl for host. Valid values are 300 <= TTL <= 68400 or "default". If
    <name> is an alias the alias host is updated.
    """

    # Get host info or raise exception
    info = host_info_by_name(args.name)

    # TTL sanity check
    if not is_valid_ttl(args.ttl):
        cli_warning(
            "invalid TTL value: {} (target host {})".format(args.ttl,
                                                            info["name"]))

    old_data = {"ttl": info["ttl"] or ""}
    new_data = {"ttl": args.ttl if args.ttl != "default" else ""}

    # Update TTL
    path = f"/api/v1/hosts/{info['name']}"
    history.record_patch(path, new_data, old_data)
    patch(path, **new_data)
    cli_info("updated TTL to {} for {}".format(args.ttl, info["name"]), print_msg=True)


# Add 'ttl_set' as a sub command to the 'host' command
host.add_command(
    prog='ttl_set',
    description='Set ttl for host. Valid values are 300 <= TTL <= 68400 or '
                '"default". If NAME is an alias the alias host is updated.',
    short_desc='Set TTL record.',
    callback=ttl_set,
    flags=[
        Flag('name',
             description='Host target name.',
             metavar='NAME'),
        Flag('ttl',
             description='New TTL.',
             metavar='TTL'),
    ],
)


##############################################
#  Implementation of sub command 'ttl_show'  #
##############################################

def ttl_show(args):
    """Show ttl for host. If <name> is an alias the alias hosts TTL is shown.
    """
    info = host_info_by_name(args.name)
    print_ttl(info["ttl"])
    cli_info("showed TTL for {}".format(info["name"]))


# Add 'ttl_show' as a sub command to the 'host' command
host.add_command(
    prog='ttl_show',
    description='Show ttl for host. If NAME is an alias the alias hosts TTL is '
                'shown.',
    short_desc='Show TTL.',
    callback=ttl_show,
    flags=[
        Flag('name',
             description='Host target name.',
             metavar='NAME'),
    ],
)


################################################################################
#                                                                              #
#                                 TXT records                                  #
#                                                                              #
################################################################################


#############################################
#  Implementation of sub command 'txt_add'  #
#############################################

def txt_add(args):
    """Add a txt record to host. <text> must be enclosed in double quotes if it
    contains more than one word.
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)
    if any(args.text == i["txt"] for i in info["txts"]):
        cli_warning("The TXT record already exists for {}".format(info["name"]))

    data = {
        "host": info["id"],
        "txt": args.text
    }
    # Add TXT record to host
    path = "/api/v1/txts/"
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info("Added TXT record to {}".format(info["name"]), print_msg=True)


# Add 'txt_add' as a sub command to the 'host' command
host.add_command(
    prog='txt_add',
    description='Add a txt record to host. TEXT must be enclosed in double '
                'quotes if it contains more than one word.',
    short_desc='Add TXT record.',
    callback=txt_add,
    flags=[
        Flag('name',
             description='Host target name.',
             metavar='NAME'),
        Flag('text',
             description='TXT record text. Must be quoted if contains spaces.',
             metavar='TEXT'),
    ],
)


################################################
#  Implementation of sub command 'txt_remove'  #
################################################

def txt_remove(args):
    """Remove TXT record for host with <text>.
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)
    hostname = info["name"]

    # Check for matching TXT records for host
    path = "/api/v1/txts/?host={}&txt={}".format(
        info["id"],
        args.text,
    )
    history.record_get(path)
    txts = get_list(path)
    if len(txts) == 0:
        cli_warning(f"{hostname} has no TXT records equal: {args.text}")

    txt = txts[0]
    path = f"/api/v1/txts/{txt['id']}"
    history.record_delete(path, txt)
    delete(path)
    cli_info(f"deleted TXT records from {hostname}", print_msg=True)


# Add 'txt_remove' as a sub command to the 'host' command
host.add_command(
    prog='txt_remove',
    description=' Remove TXT record for host matching TEXT.',
    short_desc='Remove TXT record.',
    callback=txt_remove,
    flags=[
        Flag('name',
             description='Host target name.',
             metavar='NAME'),
        Flag('text',
             description='TXT record text. Must be quoted if contains spaces.',
             metavar='TEXT'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ],
)


##############################################
#  Implementation of sub command 'txt_show'  #
##############################################

def txt_show(args):
    """Show all TXT records for host.
    """
    info = host_info_by_name(args.name)
    path = f"/api/v1/txts/?host={info['id']}"
    history.record_get(path)
    txts = get_list(path)
    for txt in txts:
        print_txt(txt["txt"], padding=5)
    cli_info("showed TXT records for {}".format(info["name"]))


# Add 'txt_show' as a sub command to the 'host' command
host.add_command(
    prog='txt_show',
    description='Show all TXT records for host.',
    short_desc='Show TXT records.',
    callback=txt_show,
    flags=[
        Flag('name',
             description='Host target name.',
             metavar='NAME'),
    ],
)
