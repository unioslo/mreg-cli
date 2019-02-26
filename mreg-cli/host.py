import ipaddress
import typing

from cli import cli, Flag
from exceptions import HostNotFoundWarning
from history import history
from log import cli_info, cli_warning
from util import delete, get, patch, post, \
                 clean_hostname, cname_exists, first_unused_ip_from_network, \
                 get_network_by_ip, get_network, get_network_reserved_ips, \
                 host_info_by_name, host_info_by_name_or_ip, host_in_mreg_zone, \
                 ip_in_mreg_net, \
                 is_valid_email, is_valid_ip, is_valid_ipv4, is_valid_ipv6, \
                 is_valid_network, is_valid_ttl, resolve_input_name

#################################
#  Add the main command 'host'  #
#################################

host = cli.add_command(
    prog='host',
    description='Manage hosts.',
)

# helper methods
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
    if hid not in hinfo:
        cli_warning("Unknown hinfo preset {}".format(hid))


def hinfo_dict() -> HinfoDict:
    """
    Return a dict with descriptions of available hinfo presets. The keys
    are the hinfo ids.
    """
    path = "/hinfopresets/"
    history.record_get(path)
    hinfo_get = get(path)
    hl = dict()
    for hinfo in hinfo_get.json():
        assert isinstance(hinfo, dict)
        hl[str(hinfo["id"])] = (hinfo["cpu"], hinfo["os"])
    return hl


def print_hinfo(hid: str, padding: int = 14) -> None:
    """Pretty given hinfo id"""
    hinfos = hinfo_dict()
    hid = str(hid)
    hinfo = hinfos[hid]
    print("{1:<{0}}cpu={2} os={3}".format(padding, "Hinfo:", hinfo[0], hinfo[1]))


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
    # Or else check that the address given isn't reserved
    elif is_valid_ip(ip):
        network = get_network_by_ip(ip)
        if not network:
            if force:
                return ip
            else:
                cli_warning(f"{ip} isn't in a network controlled by MREG, must force")
    else:
        cli_warning(f"Could not determine network for {ip}")

    network_object = ipaddress.ip_network(network['range'])
    if ipversion:
        if network_object.version != ipversion:
            if ipversion == 4:
                cli_warning("Attemptet to get an ipv4 address, but input yielded ipv6")
            elif ipversion == 6:
                cli_warning("Attemptet to get an ipv6 address, but input yielded ipv4")

    if network["frozen"] and not force:
        cli_warning("network {} is frozen, must force"
                    .format(network["range"]))
    reserved_addresses = get_network_reserved_ips(network['range'])
    if ip in reserved_addresses and not force:
        cli_warning("Address is reserved. Requires force")
    if network_object.num_addresses > 2:
        if ip == network_object.network_address.exploded:
            cli_warning("Can't overwrite the network address of the network")
        if ip == network_object.broadcast_address.exploded:
            cli_warning("Can't overwrite the broadcast address of the network")

    return ip


################################################################################
#                                                                              #
#                              Host manipulation                               #
#                                                                              #
################################################################################


#########################################
#  Implementation of sub command 'add'  #
#########################################

def add(args):
    """Add a new host with the given name, ip or network and contact. hinfo and
    comment are optional.
    """

    # Fail if given host exits
    name = clean_hostname(args.name)
    try:
        name = resolve_input_name(name)
    except HostNotFoundWarning:
        pass
    else:
        cli_warning("host {} already exists".format(name))

    # TODO: only for superusers
    if "*" in name and not args.force:
        cli_warning("Wildcards must be forced.")

    if cname_exists(name):
        cli_warning("the name is already in use by a cname")

    ip = _get_ip_from_args(args.ip, args.force)

    # Contact sanity check
    if not is_valid_email(args.contact):
        cli_warning(
            "invalid mail address ({}) when trying to add {}".format(
                args.contact,
                args.name))

    # Verify hinfo id
    if args.hinfo:
        hi_dict = hinfo_dict()
        hinfo_sanify(args.hinfo, hi_dict)

    # Require force if FQDN not in MREG zone
    if not host_in_mreg_zone(name) and not args.force:
        cli_warning(
            "{} isn't in a zone controlled by MREG, must force".format(name))

    # Create the new host with an ip address
    path = "/hosts/"
    data = {
        "name": name,
        "ipaddress": ip,
        "contact": args.contact,
        "hinfo": args.hinfo or None,
        "comment": args.comment or None,
    }
    history.record_post(path, resource_name=name, new_data=data)
    post(path, **data)
    cli_info("created host {}".format(name), print_msg=True)


# Add 'add' as a sub command to the 'host' command
host.add_command(
    prog='add',
    description='Add a new host with the given name, ip or network and contact. '
                'hinfo and comment are optional.',
    short_desc='Add a new host',
    callback=add,
    flags=[
        Flag('name',
             short_desc='Name of new host (req)',
             description='Name of new host (req)'),
        Flag('-ip',
             short_desc='An ip or net (req)',
             description='The hosts ip or a net. If it\'s a net a random ip is '
                         'selected from the net (req)',
             required=True,
             metavar='IP/NET'),
        Flag('-contact',
             short_desc='Contact mail for the host (req)',
             description='Contact mail for the host (req)',
             required=True),
        Flag('-hinfo',
             short_desc='Host information.',
             description='Host information.'),
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
    path = f"/naptrs/?host={info['id']}"
    history.record_get(path)
    naptrs = get(path).json()
    if len(naptrs) > 0:
        if not args.force:
            warn_msg += "{} NAPTR records. ".format(len(naptrs))
        else:
            for naptr in naptrs:
                path = f"/naptrs/{naptr['id']}"
                history.record_delete(path, naptr)
                delete(path)
                cli_info("deleted NAPTR record {} when removing {}".format(
                    naptr["replacement"],
                    info["name"],
                ))

    # Require force if host has any SRV records. Delete the SRV records if force
    path = f"/srvs/?target={info['name']}"
    history.record_get(path)
    srvs = get(path).json()
    if len(srvs) > 0:
        if not args.force:
            warn_msg += "{} SRV records. ".format(len(srvs))
        else:
            for srv in srvs:
                path = f"/srvs/{srv['id']}"
                history.record_delete(path, srv)
                delete(path)
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
                path = f"/ptroverrides/{ptr['id']}"
                history.record_delete(path, ptr, redoable=False, undoable=False)
                delete(path)
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
    path = f"/hosts/{info['name']}"
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


def print_srv(srv: dict, padding: int = 14) -> None:
    """Pretty print given srv"""
    print("{1:<{0}} SRV {2:^6} {3:^6} {4:^6} {5}".format(
        padding,
        srv["name"],
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


def print_mx(mxs: dict, padding: int = 14) -> None:
    """Pretty print all MXs"""
    if mxs is None:
        return
    len_pri = len("Priority")
    print("{1:<{0}}{2} {3}".format(padding, "MX:", "Priority", "Server"))
    for mx in sorted(mxs, key=lambda i: i['priority']):
        print("{1:<{0}}{2:>{3}} {4}".format(padding, "", mx['priority'], len_pri, mx['mx']))


def print_naptr(naptr: dict, host_name: str, padding: int = 14) -> None:
    """Pretty print given txt"""
    assert isinstance(naptr, dict)
    assert isinstance(host_name, str)
    print("{1:<{0}} NAPTR {2} {3} \"{4}\" \"{5}\" \"{6}\" {7}".format(
        padding,
        host_name,
        naptr["preference"],
        naptr["order"],
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


def print_txt(txt: str, padding: int = 14) -> None:
    """Pretty print given txt"""
    if txt is None:
        return
    assert isinstance(txt, str)
    print("{1:<{0}}{2}".format(padding, "TXT:", txt))


def info_(args):
    """Print information about host. If <name> is an alias the cname hosts info
    is shown.
    """
    for name_or_ip in args.hosts:
        # Get host info or raise exception
        info = host_info_by_name_or_ip(name_or_ip)

        # Pretty print all host info
        print_host_name(info["name"])
        print_contact(info["contact"])
        if info["comment"]:
            print_comment(info["comment"])
        print_ipaddresses(info["ipaddresses"])
        print_ttl(info["ttl"])
        print_mx(info['mxs'])
        if info["hinfo"]:
            print_hinfo(info["hinfo"])
        if info["loc"]:
            print_loc(info["loc"])
        for cname in info["cnames"]:
            print_cname(cname["name"], info["name"])
        for txt in info["txts"]:
            print_txt(txt["txt"])
        for ptr in info["ptr_overrides"]:
            print_ptr(ptr["ipaddress"], info["name"])
        _naptr_show(info)
        cli_info("printed host info for {}".format(info["name"]))


# Add 'info' as a sub command to the 'host' command
host.add_command(
    prog='info',
    description='Print info about one or more hosts.',
    short_desc='Print info about one or more hosts.',
    callback=info_,
    flags=[
        Flag('hosts',
             description='One or more hosts given by their name or ip.',
             short_desc='One or more names and/or ips.',
             nargs='+',
             metavar='NAME/IP')
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
    if not host_in_mreg_zone(new_name) and not args.force:
        cli_warning("{} isn't in a zone controlled by MREG, must force".format(
            new_name))

    # TODO: only for superusers
    if "*" in new_name and not args.force:
        cli_warning("Wildcards must be forced.")

    old_data = {"name": old_name}
    new_data = {"name": new_name}

    # Rename host
    path = f"/hosts/{old_name}"
    # Cannot redo/undo now since it changes name
    history.record_patch(path, new_data, old_data, redoable=False,
                         undoable=False)
    patch(path, name=new_name)

    # Update all srv records pointing to <old-name>
    path = f"/srvs/?target={old_name}"
    history.record_get(path)
    srvs = get(path).json()
    for srv in srvs:
        path = f"/srvs/{srv['id']}"
        old_data = {"target": old_name}
        new_data = {"target": new_name}
        history.record_patch(path, new_data, old_data)
        patch(path, target=new_name)
    if len(srvs):
        cli_info("updated {} SRV record(s) when renaming {} to {}".format(
            len(srvs),
            old_name,
            new_name,
        ))
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
    path = f"/hosts/{info['name']}"
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
    path = f"/hosts/{info['name']}"
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


###########################################
#  Implementation of sub command 'a_add'  #
###########################################

def a_add(args):
    """Add an A record to host. If <name> is an alias the cname host is used.
    """

    ip = None
    # Get host info for or raise exception
    info = host_info_by_name(args.name)

    # TODO: only for superusers
    if "*" in args.name and not args.force:
        cli_warning("Wildcards must be forced.")

    # Require force if host has multiple A/AAAA records
    if len(info["ipaddresses"]) and not args.force:
        cli_warning("{} already has A/AAAA record(s), must force"
                    .format(info["name"]))

    if any(args.ip == i["ipaddress"] for i in info["ipaddresses"]):
        cli_warning(f"Host already has IP {args.ip}")

    ip = _get_ip_from_args(args.ip, args.force, ipversion=4)

    data = {
        "host": info["id"],
        "ipaddress": ip,
    }

    # Add A record
    path = "/ipaddresses/"
    history.record_post(path, ip, data)
    post(path, **data)
    cli_info("added ip {} to {}".format(ip, info["name"]), print_msg=True)


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

def a_change(args):
    """Change A record. If <name> is an alias the cname host is used.
    """

    if args.old == args.new:
        cli_warning("New and old IP are equal")

    # Get host info or raise exception
    info = host_info_by_name(args.name)

    # Fail if input isn't ipv4
    if not is_valid_ipv6(args.old):
        cli_warning("not a valid ipv4 \"{}\" (target host {})"
                    .format(args.old, info["name"]))

    for i in info["ipaddresses"]:
        if i["ipaddress"] == args.old:
            ip_id = i["id"]
            break
    else:
        cli_warning("\"{}\" is not owned by {}".format(args.old, info["name"]))

    new_ip = _get_ip_from_args(args.new, args.force, ipversion=4)

    old_data = {"ipaddress": args.old}
    new_data = {"ipaddress": new_ip}

    # Update A records ip address
    path = f"/ipaddresses/{ip_id}"
    # Cannot redo/undo since recourse name changes
    history.record_patch(path, new_data, old_data, redoable=False,
                         undoable=False)
    patch(path, ipaddress=new_ip)
    cli_info(
        "changed ip {} to {} for {}".format(args.old, new_ip, info["name"]),
        print_msg=True)


# Add 'a_change' as a sub command to the 'host' command
host.add_command(
    prog='a_change',
    description='Change an A record for the target host. If NAME is an alias '
                'the cname host is used.',
    short_desc='Change A record.',
    callback=a_change,
    flags=[
        Flag('-name',
             description='Name of the target host.',
             short_desc='Host name.',
             required=True,
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


##############################################
#  Implementation of sub command 'a_remove'  #
##############################################

def a_remove(args):
    """Remove A record from host. If <name> is an alias the cname host is used.
    """

    ip_id = None

    # Ip sanity check
    if not is_valid_ipv4(args.ip):
        cli_warning("not a valid ipv4: \"{}\"".format(args.ip))

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
    path = f"/ipaddresses/{ip_id}"
    history.record_delete(path, old_data)
    delete(path)
    cli_info("removed ip {} from {}".format(args.ip, info["name"]),
             print_msg=True)


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

    # Get host info or raise exception
    info = host_info_by_name(args.name)

    # TODO: only for superusers
    if "*" in args.name and not args.force:
        cli_warning("Wildcards must be forced.")

    if len(info["ipaddresses"]) and not args.force:
        cli_warning("{} already has A/AAAA record(s), must force"
                    .format(info["name"]))

    if any(args.ip == i["ipaddress"] for i in info["ipaddresses"]):
        cli_warning(f"Host already has IP {args.ip}")

    ip = _get_ip_from_args(args.ip, args.force, ipversion=6)

    data = {
        "host": info["id"],
        "ipaddress": ip,
    }

    # Create AAAA records
    path = "/ipaddresses/"
    history.record_post(path, ip, data)
    post(path, **data)
    cli_info("added ip {} to {}".format(ip, info["name"]), print_msg=True)


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
    if args.old == args.new:
        cli_warning("New and old IP are equal")

    # Get host info or raise exception
    info = host_info_by_name(args.name)

    # Fail if input isn't ipv6
    if not is_valid_ipv6(args.old):
        cli_warning("not a valid ipv6 \"{}\" (target host {})"
                    .format(args.old, info["name"]))

    for i in info["ipaddresses"]:
        if i["ipaddress"] == args.old:
            ip_id = i["id"]
            break
    else:
        cli_warning("\"{}\" is not owned by {}".format(args.old, info["name"]))

    new_ip = _get_ip_from_args(args.new, args.force, ipversion=6)

    old_data = {"ipaddress": args.old}
    new_data = {"ipaddress": new_ip}

    # Update AAAA records ip address
    path = f"/ipaddresses/{ip_id}"
    # Cannot redo/undo since recourse name changes
    history.record_patch(path, new_data, old_data, redoable=False,
                         undoable=False)
    patch(path, ipaddress=new_ip)
    cli_info(
        "changed ip {} to {} for {}".format(args.old, new_ip, info["name"]),
        print_msg=True)


# Add 'aaaa_change' as a sub command to the 'host' command
host.add_command(
    prog='aaaa_change',
    description='Change AAAA record. If NAME is an alias the cname host is '
                'used.',
    short_desc='Change AAAA record.',
    callback=aaaa_change,
    flags=[
        Flag('-name',
             description='Name of the target host.',
             short_desc='Host name.',
             required=True,
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


#################################################
#  Implementation of sub command 'aaaa_remove'  #
#################################################

def aaaa_remove(args):
    """Remove AAAA record from host. If <name> is an alias the cname host is
    used.
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)

    # Ipv6 sanity check
    if not is_valid_ipv6(args.ip):
        cli_warning("not a valid ipv6 \"{}\" (target host {})"
                    .format(args.ip, info["name"]))

    # Check that ip belongs to host
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

    # Delete AAAA record
    path = f"/ipaddresses/{ip_id}"
    history.record_delete(path, old_data)
    delete(path)
    cli_info("removed {} from {}".format(args.ip, info["name"]), print_msg=True)


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
        cli_warning("The alias name is in use by an existing host. "
                    "Find a new alias.")
    except HostNotFoundWarning:
        pass

    # Check if cname already in use
    if cname_exists(alias):
        cli_warning("The alias is already in use.")

    data = {'host': info['id'],
            'name': alias}
    # Create CNAME record
    path = "/cnames/"
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
    path = f"/cnames/{alias}"
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
    path = f"/hosts/?cnames_name={name}"
    history.record_get(path)
    hosts = get(path).json()
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
    path = f"/hosts/{host_['name']}"
    history.record_patch(path, new_data, old_data)
    patch(path, hinfo="")


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
    _hinfo_remove(info)
    cli_info("removed hinfo for {}".format(info["name"]), print_msg=True)


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


###############################################
#  Implementation of sub command 'hinfo_set'  #
###############################################

def hinfo_set(args):
    """Set hinfo for host. If <name> is an alias the cname host is updated.
    """
    hinfo_sanify(args.hinfo, hinfo_dict())

    # Get host info or raise exception
    info = host_info_by_name(args.name)
    old_data = {"hinfo": info["hinfo"] or ""}
    new_data = {"hinfo": args.hinfo}

    # Update hinfo
    path = f"/hosts/{info['name']}"
    history.record_patch(path, new_data, old_data)
    patch(path, hinfo=args.hinfo)
    cli_info("updated hinfo to {} for {}".format(args.hinfo, info["name"]),
             print_msg=True)


# Add 'hinfo_set' as a sub command to the 'host' command
host.add_command(
    prog='hinfo_set',
    description='Set HINFO for host. If NAME is an alias the cname host is '
                'updated.',
    short_desc='Set HINFO.',
    callback=hinfo_set,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
        Flag('hinfo',
             description='New HINFO.',
             metavar='HINFO'),
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


#######################################################
#  Implementation of sub command 'hinfopresets_list'  #
#######################################################

def hinfopresets_list(args):
    """Show hinfopresets.
    """

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
                "{1:<{0}} -> {2:<{3}} {4}".format(padding, hid, hinfo[0],
                                                  max_len, hinfo[1]))

    hi_dict = hinfo_dict()
    if hi_dict:
        print_hinfo_list(hi_dict)
    else:
        cli_info("No hinfopresets.", print_msg=True)


# Add 'hinfopresets_list' as a sub command to the 'host' command
host.add_command(
    prog='hinfopresets_list',
    description='Show hinfopresets.',
    short_desc='Show hinfopresets.',
    callback=hinfopresets_list,
)


#########################################################
#  Implementation of sub command 'hinfopresets_create'  #
#########################################################

def hinfopresets_create(args):
    """Create a new hinfopreset.
    """
    hi_dict = hinfo_dict()
    for hid, hinfo in hi_dict.items():
        if (args.cpu, args.os) == hinfo:
            cli_warning("cpu {} and os {} already defined as set {}".format(
                args.cpu, args.os, hid))

    data = {
        "cpu": args.cpu,
        "os": args.os
    }
    path = "/hinfopresets/"
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info("Added new hinfopreset with cpu {} and os {}"
             .format(args.cpu, args.os), print_msg=True)


# Add 'hinfopresets_create' as a sub command to the 'host' command
host.add_command(
    prog='hinfopresets_create',
    description='Create a new hinfopreset.',
    short_desc='Create a new hinfopreset.',
    callback=hinfopresets_create,
    flags=[
        Flag('cpu',
             description='CPU of hinfopreset.',
             metavar='CPU'),
        Flag('os',
             description='OS of hinfopreset.',
             metavar='OS'),
    ],
)


#########################################################
#  Implementation of sub command 'hinfopresets_remove'  #
#########################################################

def hinfopresets_remove(args):
    """Remove a hinfopreset.
    """
    hi_dict = hinfo_dict()
    if args.id not in hi_dict.keys():
        cli_info("hinfopreset {} does not exist".format(args.id),
                 print_msg=True)
        return

    # Check for hinfopreset in use
    path = f"/hosts/?hinfo={args.id}"
    history.record_get(path)
    hosts = get(path).json()
    if len(hosts):
        if args.force:
            for host in hosts:
                info = host_info_by_name(host['name'])
                _hinfo_remove(info)
            cli_info("Removed hinfopreset {} from {} hosts"
                     .format(args.id, len(hosts)), print_msg=True)
        else:
            cli_warning("hinfopreset {} in use by {} hosts, must force".format(
                args.id, len(hosts)))

    path = f"/hinfopresets/{args.id}"
    history.record_delete(path, args.id)
    delete(path)
    cli_info("Removed hinfopreset {}".format(args.id), print_msg=True)


# Add 'hinfo_show' as a sub command to the 'host' command
host.add_command(
    prog='hinfopresets_remove',
    description='Remove a hinfopreset.',
    short_desc='Remove a hinfopreset.',
    callback=hinfopresets_remove,
    flags=[
        Flag('id',
             description='Hinfopreset id.',
             metavar='ID'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
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
    # LOC always require force
    if not args.force:
        cli_warning("require force to remove location")

    # Get host info or raise exception
    info = host_info_by_name(args.name)

    old_data = {"loc": info["loc"]}
    new_data = {"loc": ""}

    # Set LOC to null value
    path = f"/hosts/{info['name']}"
    history.record_patch(path, new_data, old_data)
    patch(path, loc="")
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
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ],
)


#############################################
#  Implementation of sub command 'loc_set'  #
#############################################

def loc_set(args):
    """Set location of host. If <name> is an alias the cname host is updated.
    """

    def is_valid_loc(loc: str) -> bool:
        # TODO LOC: implement validate loc
        return True

    # LOC always require force
    if not args.force:
        cli_warning("require force to set location")

    # Get host info or raise exception
    info = host_info_by_name(args.name)

    # LOC sanity check
    if not is_valid_loc(args.loc):
        cli_warning("invalid LOC \"{}\" (target host {})"
                    .format(args.loc, info["name"]))

    old_data = {"loc": info["loc"] or ""}
    new_data = {"loc": args.loc}

    # Update LOC
    path = f"/hosts/{info['name']}"
    history.record_patch(path, new_data, old_data)
    patch(path, loc=args.loc)
    cli_info("updated LOC to {} for {}".format(args.loc, info["name"]),
             print_msg=True)


# Add 'loc_set' as a sub command to the 'host' command
host.add_command(
    prog='loc_set',
    description='Set location of host. If NAME is an alias the cname host is '
                'updated.',
    short_desc='Set LOC record.',
    callback=loc_set,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
        Flag('loc',
             description='New LOC.',
             metavar='LOC'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
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
    print_loc(info["loc"])
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
    path = "/mxs/"
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
             metavar='TEXT'),
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
        "NOT FOUND"
        cli_warning("{} has not MX records with priority {} and mail exhange {}".format(
                    info['name'], args.priority, args.mx))
    path = f"/mxs/{mx_id}"
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
    path = f"/mxs/?host={info['id']}"
    history.record_get(path)
    mxs = get(path).json()
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
        "preference": int(args.preference),
        "order": int(args.order),
        "flag": args.flag,
        "service": args.service,
        "regex": args.regexp,
        "replacement": args.replacement,
        "host": info["id"],
    }

    # Create NAPTR record
    path = "/naptrs/"
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
        Flag('-regexp',
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
    path = f"/naptrs/?replacement__contains={args.replacement}&host={info['id']}"
    history.record_get(path)
    naptrs = get(path).json()
    if not len(naptrs):
        cli_warning("{} hasn't got any NAPTR reocrds matching \"{}\"".format(
            info["name"],
            args.replacement,
        ))
    if len(naptrs) > 1 and not args.force:
        cli_warning(
            "{} got {} NAPTR records matching \"{}\", must force.".format(
                info["name"],
                len(naptrs),
                args.replacement,
            ))

    # Delete NAPTR record(s)
    for naptr in naptrs:
        path = f"/naptrs/{naptr['id']}"
        history.record_delete(path, naptr)
        delete(path)
    cli_info("deleted {} NAPTR record(s) for {}"
             .format(len(naptrs), info["name"]), print_msg=True)


# Add 'naptr_remove' as a sub command to the 'host' command
host.add_command(
    prog='naptr_remove',
    description='Remove NAPTR record.',
    callback=naptr_remove,
    flags=[
        Flag('name',
             description='Name of the target host.',
             metavar='NAME'),
        Flag('replacement',
             description='NAPTR replacement.',
             metavar='REPLACEMENT'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ],
)


################################################
#  Implementation of sub command 'naptr_show'  #
################################################

def _naptr_show(info):
    path = f"/naptrs/?host={info['id']}"
    history.record_get(path)
    naptrs = get(path).json()
    if naptrs:
        print("{1:<{0}} {2} {3} {4} {5} {6} {7}".format(
            14, info["name"], "Preference", "Order", "Flag", "Service",
            "Regex", "Replacement"))
        for ptr in naptrs:
            print_naptr(ptr, info["name"])
    return len(naptrs)

def naptr_show(args):
    """Show all NAPTR records for host.
    """
    info = host_info_by_name(args.name)
    num_naptrs = _naptr_show(info)
    if num_naptrs == 0:
        print(f"No naptrs for info['name']")
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

    path = "/ptroverrides/{}".format(old_info["ptr_overrides"][0]["id"])
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
             metavar='IP'),
        Flag('-old',
             description='Name of old host.',
             metavar='NAME'),
        Flag('-new',
             description='Name of new host.',
             metavar='NAME'),
    ],
)


################################################
#  Implementation of sub command 'ptr_remove'  #
################################################

def ptr_remove(args):
    """Remove PTR record from host.
    """
    # XXX: broken function by
    # Get host info or raise exception
    info = host_info_by_name(args.name)

    # Check that host got PTR record (assuming host got at most one record)
    if len(info["ptr_overrides"]) == 0:
        cli_warning("no PTR record for {} with ip {}".format(info["name"],
                                                             args.ip))

    # Delete record
    path = "/ptroverrides/{}".format(info["ptr_overrides"][0]["id"])
    history.record_delete(path, info["ptr_override"][0])
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
#  Implementation of sub command 'ptr_set'  #
#############################################

def ptr_set(args):
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
    path = f"/ptroverrides/?ipaddress={args.ip}"
    history.record_get(path)
    ptrs = get(path).json()
    if len(ptrs):
        cli_warning("{} already exist in a PTR record".format(args.ip))

    # check if host is in mreg controlled zone, must force if not
    if not host_in_mreg_zone(info["name"]) and not args.force:
        cli_warning("{} isn't in a zone controlled by MREG, must force"
                    .format(info["name"]))

    network = get_network_by_ip(args.ip)
    reserved_addresses = get_network_reserved_ips(network['range'])
    if args.ip in reserved_addresses and not args.force:
        cli_warning("Address is reserved. Requires force")

    # create PTR record
    data = {
        "host": info["id"],
        "ipaddress": args.ip,
    }
    path = "/ptroverrides/"
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info("Added PTR record {} to {}".format(args.ip, info["name"]),
             print_msg=True)


# Add 'ptr_set' as a sub command to the 'host' command
host.add_command(
    prog='ptr_set',
    description='Create a PTR record for host.',
    short_desc='Set PTR record.',
    callback=ptr_set,
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

    path = f"/hosts/?ptr_overrides__ipaddress={args.ip}"
    history.record_get(path)
    host = get(path, ok404=True).json()

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

    # Require force if target host doesn't exist
    host_name = clean_hostname(args.name)
    try:
        host_name = resolve_input_name(args.name)
    except HostNotFoundWarning:
        if not args.force:
            cli_warning("{} doesn't exist. Must force".format(args.name))

    # Require force if target host not in MREG zone
    if not host_in_mreg_zone(host_name) and not args.force:
        cli_warning(
            "{} isn't in a MREG controlled zone, must force".format(host_name))

    sname = clean_hostname(args.service)

    # Check if a SRV record with identical service exists
    path = f"/srvs/?service={sname}"
    history.record_get(path)
    srvs = get(path).json()
    if len(srvs) > 0:
        entry_exists = True
    else:
        entry_exists = False

    data = {
        "name": sname,
        "priority": args.pri,
        "weight": args.weight,
        "port": args.port,
        "target": host_name,
    }

    # Create new SRV record
    path = "/srvs/"
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    if entry_exists:
        cli_info("Added SRV record {} with target {} to existing entry."
                 .format(sname, host_name), print_msg=True)
    else:
        cli_info("Added SRV record {} with target {}".format(sname, host_name),
                 print_msg=True)


# Add 'srv_add' as a sub command to the 'host' command
host.add_command(
    prog='srv_add',
    description='Add SRV record.',
    callback=srv_add,
    flags=[
        Flag('-service',
             description='SRV service.',
             required=True,
             metavar='SERVICE'),
        Flag('-pri',
             description='SRV priority.',
             required=True,
             metavar='PRI'),
        Flag('-weight',
             description='SRV weight.',
             required=True,
             metavar='WEIGHT'),
        Flag('-port',
             description='SRV port.',
             required=True,
             metavar='PORT'),
        Flag('-name',
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
    sname = clean_hostname(args.service)

    # Check if service exist
    path = f"/srvs/?service={sname}"
    history.record_get(path)
    srvs = get(path).json()
    if len(srvs) == 0:
        cli_warning("not service named {}".format(sname))
    elif len(srvs) > 1 and not args.force:
        cli_warning("multiple services named {}, must force".format(sname))

    # Remove all SRV records with that service
    for srv in srvs:
        assert isinstance(srv, dict)
        path = f"/srvs/{srv['id']}"
        history.record_delete(path, srv, redoable=False)
        delete(path)
        cli_info("removed SRV record {} with target {}".format(srv["name"],
                                                               srv["target"]),
                 print_msg=True)


# Add 'srv_remove' as a sub command to the 'host' command
host.add_command(
    prog='srv_remove',
    description='Remove SRV record.',
    callback=srv_remove,
    flags=[
        Flag('service',
             description='Host target name.',
             metavar='SERVICE'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ],
)


##############################################
#  Implementation of sub command 'srv_show'  #
##############################################

def srv_show(args):
    """Show SRV. An empty input shows all existing SRV records
    """

    sname = clean_hostname(args.service)

    # Get all matching SRV records
    path = f"/srvs/?name={sname}"
    history.record_get(path)
    srvs = get(path).json()
    if len(srvs) < 1:
        cli_warning("no service matching {}".format(sname))
    padding = 0

    # Print records
    for srv in srvs:
        if len(srv["name"]) > padding:
            padding = len(srv["name"])
    prev_name = ""
    for srv in sorted(srvs, key=lambda k: k["name"]):
        if prev_name == srv["name"]:
            srv["name"] = ""
        else:
            prev_name = srv["name"]
        print_srv(srv, padding)
    cli_info("showed entries for SRV {}".format(sname))


# Add 'srv_show' as a sub command to the 'host' command
host.add_command(
    prog='srv_show',
    description='Show SRV show. An empty input showes all existing SRV '
                'records.',
    short_desc='Show SRV record.',
    callback=srv_show,
    flags=[
        Flag('service',
             description='Host target name.',
             metavar='SERVICE'),
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
    path = f"/hosts/{info['name']}"
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
    path = f"/hosts/{info['name']}"
    history.record_patch(path, new_data, old_data)
    patch(path, **new_data)
    cli_info("updated TTL for {}".format(info["name"]), print_msg=True)


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
    path = "/txts/"
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
    """Remove TXT record for host matching <text>.
    """
    # Get host info or raise exception
    info = host_info_by_name(args.name)

    # Check for matching TXT records for host
    path = "/txts/?host={}&txt__contains={}".format(
        info["id"],
        args.text,
    )
    history.record_get(path)
    txts = get(path).json()
    if len(txts) == 0:
        cli_warning(
            "{} hasn't got any TXT records matching \"{}\"".format(info["name"],
                                                                   args.text))
    if len(txts) > 1 and not args.force:
        cli_warning("\"{}\" matched {} of {} TXT records. Must force.".format(
            args.text,
            len(args),
            info["name"],
        ))

    # Remove TXT records
    for txt in txts:
        path = f"/txts/{txt['id']}"
        history.record_delete(path, txt)
        delete(path)
    cli_info("deleted {} of {} TXT records matching \"{}\"".format(
        len(txts),
        info["name"],
        args.text
    ))


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
    path = f"/txts/?host={info['id']}"
    history.record_get(path)
    txts = get(path).json()
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
