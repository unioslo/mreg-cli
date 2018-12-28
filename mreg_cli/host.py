import urllib

from util import *
from log import *
# noinspection PyUnresolvedReferences
from cli import cli, Flag
from history import history

try:
    conf = cli_config(required_fields=("server_ip", "server_port"))
except Exception as e:
    print("commands.py: cli_config:", e)
    traceback.print_exc()
    sys.exit(1)

#################################
#  Add the main command 'host'  #
#################################

host = cli.add_command(
    prog='host',
    description='Manage hosts.',
)


################################################################################
#                                                                              #
#                              Host manipulation                               #
#                                                                              #
################################################################################


#########################################
#  Implementation of sub command 'add'  #
#########################################

def add(args):
    """Add a new host with the given name, ip or subnet and contact. hinfo and
    comment are optional.
    """
    # NOTE: an A-record forward-zone not controlled by MREG aren't handled

    ip = None
    hi_dict = hinfo_dict()

    # Verify hinfo id
    if args.hinfo:
        hinfo_sanify(args.hinfo, hi_dict)

    # Handle arbitrary ip from subnet if received a subnet w/o mask
    subnet = dict()
    if re.match(r"^.*/$", args.ip):
        subnet = get_subnet(args.ip[:-1])
        ip = first_unused_ip_from_subnet(subnet)

    # Handle arbitrary ip from subnet if received a subnet w/mask
    elif is_valid_subnet(args.ip):
        subnet = get_subnet(args.ip)
        ip = first_unused_ip_from_subnet(subnet)

    # Require force if given valid ip in subnet not controlled by MREG
    elif is_valid_ip(args.ip) and not ip_in_mreg_net(args.ip):
        if not args.force:
            cli_warning(
                "{} isn't in a subnet controlled by MREG, must force".format(
                    args.ip))
        else:
            ip = args.ip

    # Or else check that the address given isn't reserved
    else:
        subnet = get_subnet(args.ip)
        network_object = ipaddress.ip_network(subnet['range'])
        reserved_addresses = set(
            map(str, get_subnet_reserved_ips(subnet['range'])))
        if args.ip in reserved_addresses and not args.force:
            cli_warning("Address is reserved. Requires force")
        if args.ip == network_object.network_address.exploded:
            cli_warning("Can't overwrite the network address of the subnet")
        if args.ip == network_object.broadcast_address.exploded:
            cli_warning("Can't overwrite the broadcast address of the subnet")
        ip = args.ip

    # Require force if subnet is frozen
    if not args.force and subnet['frozen']:
        cli_warning(
            "Subnet {} is frozen. Requires force".format(subnet['range']))

    # Contact sanity check
    if not is_valid_email(args.contact):
        cli_warning(
            "invalid mail address ({}) when trying to add {}".format(
                args.contact,
                args.name))

    # Fail if given host exits
    name = clean_hostname(args.name)
    try:
        name = resolve_input_name(name)
    except HostNotFoundWarning:
        pass
    else:
        cli_warning("host {} already exists".format(name))

    if cname_exists(name):
        cli_warning("the name is already in use by a cname")

    # Require force if FQDN not in MREG zone
    if not host_in_mreg_zone(name) and not args.force:
        cli_warning(
            "{} isn't in a zone controlled by MREG, must force".format(name))

    # TODO: only for superusers
    if "*" in name and not args.force:
        cli_warning("Wildcards must be forced.")

    # Create the new host with an ip address
    url = "http://{}:{}/hosts/".format(conf["server_ip"], conf["server_port"])
    data = {
        "name": name,
        "ipaddress": ip,
        "contact": args.contact,
        "hinfo": args.hinfo or None,
        "comment": args.comment or None,
    }
    history.record_post(url, resource_name=name, new_data=data)
    post(url, **data)
    cli_info("created host {}".format(name), print_msg=True)


# Add 'add' as a sub command to the 'host' command
host.add_command(
    prog='add',
    description='Add a new host with the given name, ip or subnet and contact. '
                'hinfo and comment are optional.',
    short_desc='Add a new host',
    callback=add,
    flags=[
        Flag('-name',
             short_desc='Name of new host (req)',
             description='Name of new host (req)',
             required=True),
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
             action='count',
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
    url = "http://{}:{}/naptrs/?host={}".format(
        conf["server_ip"],
        conf["server_port"],
        info["id"],
    )
    history.record_get(url)
    naptrs = get(url).json()
    if len(naptrs) > 0:
        if not args.force:
            warn_msg += "{} NAPTR records. ".format(len(naptrs))
        else:
            for ptr in naptrs:
                url = "http://{}:{}/naptrs/{}".format(
                    conf["server_ip"],
                    conf["server_port"],
                    ptr["id"],
                )
                history.record_delete(url, ptr)
                delete(url)
                cli_info("deleted NAPTR record {} when removing {}".format(
                    ptr["replacement"],
                    info["name"],
                ))

    # Require force if host has any SRV records. Delete the SRV records if force
    url = "http://{}:{}/srvs/?target={}".format(
        conf["server_ip"],
        conf["server_port"],
        info["id"],
    )
    history.record_get(url)
    srvs = get(url).json()
    if len(srvs) > 0:
        if not args.force:
            warn_msg += "{} SRV records. ".format(len(srvs))
        else:
            for srv in srvs:
                url = "http://{}:{}/srvs/{}".format(
                    conf["server_ip"],
                    conf["server_port"],
                    srv["id"],
                )
                history.record_delete(url, srv)
                delete(url)
                cli_info("deleted SRV record {} when removing {}".format(
                    srv["service"],
                    info["name"],
                ))

    # Require force if host has any PTR records. Delete the PTR records if force
    if len(info["ptr_overrides"]) > 0:
        if not args.force:
            warn_msg += "{} PTR records. ".format(len(info["ptr_overrides"]))
        else:
            for ptr in info["ptr_overrides"]:
                url = "http://{}:{}/ptroverrides/{}".format(
                    conf["server_ip"],
                    conf["server_port"],
                    ptr["id"],
                )
                history.record_delete(url, ptr, redoable=False, undoable=False)
                delete(url)
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
    url = "http://{}:{}/hosts/{}".format(conf["server_ip"], conf["server_port"],
                                         info["name"])
    history.record_delete(url, old_data=info)
    delete(url)
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
             action='count',
             description='Enable force.'),
    ]
)


##########################################
#  Implementation of sub command 'info'  #
##########################################

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
    url = "http://{}:{}/hosts/{}".format(conf["server_ip"], conf["server_port"],
                                         old_name)
    # Cannot redo/undo now since it changes name
    history.record_patch(url, new_data, old_data, redoable=False,
                         undoable=False)
    patch(url, name=new_name)

    # Update all srv records pointing to <old-name>
    url = "http://{}:{}/srvs/?target={}".format(
        conf["server_ip"],
        conf["server_port"],
        old_name,
    )
    history.record_get(url)
    srvs = get(url).json()
    for srv in srvs:
        url = "http://{}:{}/srvs/{}".format(
            conf["server_ip"],
            conf["server_port"],
            srv["id"],
        )
        old_data = {"target": old_name}
        new_data = {"target": new_name}
        history.record_patch(url, new_data, old_data)
        patch(url, target=new_name)
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
             action='count',
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
    url = "http://{}:{}/hosts/{}".format(conf["server_ip"],
                                         conf["server_port"],
                                         info["name"])
    history.record_patch(url, new_data, old_data)
    patch(url, comment=args.comment)
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
    url = "http://{}:{}/hosts/{}".format(conf["server_ip"], conf["server_port"],
                                         info["name"])
    history.record_patch(url, new_data, old_data)
    patch(url, contact=args.contact)
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

    # Handle arbitrary ip from subnet if received a subnet w/o mask
    if re.match(r"^.*/$", args.ip):
        subnet = get_subnet(args.ip[:-1])
        if subnet["frozen"] and not args.force:
            cli_warning(
                "subnet {} is frozen, must force".format(subnet["range"]))
        ip = first_unused_ip_from_subnet(subnet)

    # Handle arbitrary ip from subnet if received a subnet w/mask
    elif is_valid_subnet(args.ip):
        subnet = get_subnet(args.ip)
        if subnet["frozen"] and not args.force:
            cli_warning(
                "subnet {} is frozen, must force".format(subnet["range"]))
        ip = first_unused_ip_from_subnet(subnet)

    # Require force if given valid ip in subnet not controlled by MREG
    elif is_valid_ip(args.ip) and not ip_in_mreg_net(args.ip):
        if not args.force:
            cli_warning(
                "{} isn't in a subnet controlled by MREG, must force".format(
                    args.ip))
        else:
            ip = args.ip

    # Or else check that the address given isn't reserved
    else:
        subnet = get_subnet(args.ip)
        if subnet["frozen"] and not args.force:
            cli_warning(
                "subnet {} is frozen, must force".format(subnet["range"]))
        network_object = ipaddress.ip_network(subnet['range'])
        reserved_addresses = set(
            map(str, get_subnet_reserved_ips(subnet['range'])))
        if args.ip in reserved_addresses and not args.force:
            cli_warning("Address is reserved. Requires force")
        if args.ip == network_object.network_address.exploded:
            cli_warning("Can't overwrite the network address of the subnet")
        if args.ip == network_object.broadcast_address.exploded:
            cli_warning("Can't overwrite the broadcast address of the subnet")
        ip = args.ip

    # Fail if input isn't ipv4
    if is_valid_ipv6(ip):
        cli_warning("got ipv6 address, want ipv4.")
    if not is_valid_ipv4(ip):
        cli_warning("not valid ipv4 address: {}".format(ip))

    data = {
        "host": info["id"],
        "ipaddress": ip,
    }

    # Add A record
    url = "http://{}:{}/ipaddresses/".format(conf["server_ip"],
                                             conf["server_port"])
    history.record_post(url, ip, data)
    post(url, **data)
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
             description='The IP of new A record. May also be a subnet, '
                         'in which case a random IP address from that subnet '
                         'is chosen.',
             metavar='IP/SUBNET'),
        Flag('-force',
             action='count',
             description='Enable force.'),
    ],
)


##############################################
#  Implementation of sub command 'a_change'  #
##############################################

def a_change(args):
    """Change A record. If <name> is an alias the cname host is used.
    """

    ip, ip_id = None, None

    if args.old == args.new:
        cli_warning("New and old IP are equal")

    # Ip and subnet sanity checks
    if not is_valid_ipv4(args.old):
        cli_warning("invalid ipv4 \"{}\" (target host {})"
                    .format(args.old, args.name))
    elif not is_valid_ipv4(args.new) and not is_valid_subnet(args.new):
        cli_warning("invalid ipv4 nor subnet \"{}\" (target host {})"
                    .format(args.new, args.name))

    # Check that ip belongs to host
    info = host_info_by_name(args.name)
    for rec in info["ipaddresses"]:
        if rec["ipaddress"] == args.old:
            ip_id = rec["id"]
            break
    else:
        cli_warning("{} is not owned by {}".format(args.old, info["name"]))

    # Handle arbitrary ip from subnet if received a subnet w/o mask
    if re.match(r"^.*/$", args.new):
        subnet = get_subnet(args.new[:-1])
        if subnet["frozen"] and not args.force:
            cli_warning("subnet {} is frozen, must force"
                        .format(subnet["range"]))
        ip = first_unused_ip_from_subnet(subnet)

    # Handle arbitrary ip from subnet if received a subnet w/mask
    elif is_valid_subnet(args.new):
        subnet = get_subnet(args.new)
        if subnet["frozen"] and not args.force:
            cli_warning("subnet {} is frozen, must force"
                        .format(subnet["range"]))
        ip = first_unused_ip_from_subnet(subnet)

    # Require force if given valid ip in subnet not controlled by MREG
    elif is_valid_ip(args.new) and not ip_in_mreg_net(args.new):
        if not args.force:
            cli_warning("{} isn't in a subnet controlled by MREG, must force"
                        .format(args.new))
        else:
            ip = args.new

    # Or else check that the address given isn't reserved
    else:
        subnet = get_subnet(args.new)
        if subnet["frozen"] and not args.force:
            cli_warning(
                "subnet {} is frozen, must force".format(subnet["range"]))
        network_object = ipaddress.ip_network(subnet['range'])
        reserved_addresses = \
            set(map(str, get_subnet_reserved_ips(subnet['range'])))
        if args.new in reserved_addresses and not args.force:
            cli_warning("Address is reserved. Requires force")
        if args.new == network_object.network_address.exploded:
            cli_warning("Can't overwrite the network address of the subnet")
        if args.new == network_object.broadcast_address.exploded:
            cli_warning("Can't overwrite the broadcast address of the subnet")
        ip = args.new

    # Fail if input isn't ipv4
    if is_valid_ipv6(ip):
        cli_warning("got ipv6 address, want ipv4.")
    if not is_valid_ipv4(ip):
        cli_warning("not valid ipv4 address: {}".format(ip))

    old_data = {"ipaddress": args.old}
    new_data = {"ipaddress": ip}

    # Update A record ip address
    url = "http://{}:{}/ipaddresses/{}".format(conf["server_ip"],
                                               conf["server_port"], ip_id)
    history.record_patch(url, new_data, old_data, redoable=False,
                         undoable=False)
    patch(url, ipaddress=ip)
    cli_info("updated ip {} to {} for {}".format(args.old, ip, info["name"]),
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
             description='The new IP address. May also be a subnet, in which '
                         'case a random IP from that subnet is chosen.',
             short_desc='New IP.',
             required=True,
             metavar='IP/SUBNET'),
        Flag('-force',
             action='count',
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
    url = "http://{}:{}/ipaddresses/{}".format(conf["server_ip"],
                                               conf["server_port"], ip_id)
    history.record_delete(url, old_data)
    delete(url)
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

    ip = None
    # Get host info or raise exception
    info = host_info_by_name(args.name)

    # TODO: only for superusers
    if "*" in args.name and not args.force:
        cli_warning("Wildcards must be forced.")

    if len(info["ipaddresses"]) and not args.force:
        cli_warning("{} already has A/AAAA record(s), must force"
                    .format(info["name"]))

    # Handle arbitrary ip from subnet if received a subnet w/o mask
    if re.match(r"^.*/$", args.ip):
        subnet = get_subnet(args.ip[:-1])
        if subnet["frozen"] and not args.force:
            cli_warning("subnet {} is frozen, must force"
                        .format(subnet["range"]))
        ip = first_unused_ip_from_subnet(subnet)

    # Handle arbitrary ip from subnet if received a subnet w/mask
    elif is_valid_subnet(args.ip):
        subnet = get_subnet(args.ip)
        if subnet["frozen"] and not args.force:
            cli_warning("subnet {} is frozen, must force"
                        .format(subnet["range"]))
        ip = first_unused_ip_from_subnet(subnet)

    # Require force if given valid ip in subnet not controlled by MREG
    elif is_valid_ip(args.ip) and not ip_in_mreg_net(args.ip):
        if not args.force:
            cli_warning("{} isn't in a subnet controlled by MREG, must force"
                        .format(args.ip))
        else:
            ip = args.ip

    # Or else check that the address given isn't reserved
    else:
        subnet = get_subnet(args.ip)
        if subnet["frozen"] and not args.force:
            cli_warning("subnet {} is frozen, must force"
                        .format(subnet["range"]))
        network_object = ipaddress.ip_network(subnet['range'])
        reserved_addresses = \
            set(map(str, get_subnet_reserved_ips(subnet['range'])))
        if args.ip in reserved_addresses and 'y' not in args:
            cli_warning("Address is reserved. Requires force")
        if args.ip == network_object.network_address.exploded:
            cli_warning("Can't overwrite the network address of the subnet")
        if args.ip == network_object.broadcast_address.exploded:
            cli_warning("Can't overwrite the broadcast address of the subnet")
        ip = args.ip

    # Fail if input isn't ipv6
    if is_valid_ipv4(ip):
        cli_warning("got ipv4 address, want ipv6.")
    if not is_valid_ipv6(ip):
        cli_warning("not valid ipv6 address: {}".format(ip))

    data = {
        "host": info["id"],
        "ipaddress": ip,
    }

    # Create AAAA records
    url = "http://{}:{}/ipaddresses/".format(conf["server_ip"],
                                             conf["server_port"])
    history.record_post(url, ip, data)
    post(url, **data)
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
             action='count',
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

    # Handle arbitrary ip from subnet if received a subnet w/o mask
    if re.match(r"^.*/$", args.new):
        subnet = get_subnet(args.new[:-1])
        if subnet["frozen"] and not args.force:
            cli_warning(
                "subnet {} is frozen, must force".format(subnet["range"]))
        new_ip = first_unused_ip_from_subnet(subnet)

    # Handle arbitrary ip from subnet if received a subnet w/mask
    elif is_valid_subnet(args.new):
        subnet = get_subnet(args.new)
        if subnet["frozen"] and not args.force:
            cli_warning(
                "subnet {} is frozen, must force".format(subnet["range"]))
        new_ip = first_unused_ip_from_subnet(subnet)

    # Require force if given valid ip in subnet not controlled by MREG
    elif is_valid_ip(args.new) and not ip_in_mreg_net(args.new):
        if not args.force:
            cli_warning(
                "{} isn't in a subnet controlled by MREG, must force".format(
                    args.new))
        else:
            new_ip = args.new

    # Or else check that the address given isn't reserved
    else:
        subnet = get_subnet(args.new)
        if subnet["frozen"] and not args.force:
            cli_warning(
                "subnet {} is frozen, must force".format(subnet["range"]))
        network_object = ipaddress.ip_network(subnet['range'])
        reserved_addresses = \
            set(map(str, get_subnet_reserved_ips(subnet['range'])))
        if args.new in reserved_addresses and not args.force:
            cli_warning("Address is reserved. Requires force")
        if args.new == network_object.network_address.exploded:
            cli_warning("Can't overwrite the network address of the subnet")
        if args.new == network_object.broadcast_address.exploded:
            cli_warning("Can't overwrite the broadcast address of the subnet")
        new_ip = args.new

    # Fail if input isn't ipv6
    if not is_valid_ipv6(args.old):
        cli_warning("not a valid ipv6 \"{}\" (target host {})"
                    .format(args.old, info["name"]))
    elif is_valid_ipv4(new_ip):
        cli_warning("got ipv4 address, want ipv6.")
    elif not is_valid_ipv6(new_ip):
        cli_warning("not a valid ipv6 \"{}\" (target host {})"
                    .format(new_ip, info["name"]))

    # Check that ip belongs to host
    for rec in info["ipaddresses"]:
        if rec["ipaddress"] == args.old:
            ip_id = rec["id"]
            break
    else:
        cli_warning("\"{}\" is not owned by {}".format(args.old, info["name"]))

    old_data = {"ipaddress": args.old}
    new_data = {"ipaddress": new_ip}

    # Update AAAA records ip address
    url = "http://{}:{}/ipaddresses/{}".format(conf["server_ip"],
                                               conf["server_port"], ip_id)
    # Cannot redo/undo since recourse name changes
    history.record_patch(url, new_data, old_data, redoable=False,
                         undoable=False)
    patch(url, ipaddress=new_ip)
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
             action='count',
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
    url = "http://{}:{}/ipaddresses/{}".format(conf["server_ip"],
                                               conf["server_port"], ip_id)
    history.record_delete(url, old_data)
    delete(url)
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
    url = "http://{}:{}/cnames/".format(conf["server_ip"], conf["server_port"])
    history.record_post(url, "", data, undoable=False)
    post(url, **data)
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
    url = "http://{}:{}/cnames/{}".format(conf["server_ip"],
                                          conf["server_port"], alias)
    history.record_delete(url, dict(), undoable=False)
    delete(url)
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
    url = "http://{}:{}/hosts/?cnames__name={}".format(conf["server_ip"],
                                                       conf["server_port"],
                                                       name)
    history.record_get(url)
    hosts = get(url).json()
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
    url = "http://{}:{}/hosts/{}".format(conf["server_ip"],
                                         conf["server_port"], host_["name"])
    history.record_patch(url, new_data, old_data)
    patch(url, hinfo="")


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
    # .name .hinfo
    """Set hinfo for host. If <name> is an alias the cname host is updated.
    """
    hinfo_sanify(args.hinfo, hinfo_dict())

    # Get host info or raise exception
    info = host_info_by_name(args.name)
    old_data = {"hinfo": info["hinfo"] or ""}
    new_data = {"hinfo": args.hinfo}

    # Update hinfo
    url = "http://{}:{}/hosts/{}".format(conf["server_ip"],
                                         conf["server_port"], info["name"])
    history.record_patch(url, new_data, old_data)
    patch(url, hinfo=args.hinfo)
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
    url = "http://{}:{}/hinfopresets/".format(conf["server_ip"],
                                              conf["server_port"])
    history.record_post(url, "", data, undoable=False)
    post(url, **data)
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
    url = "http://{}:{}/hosts/?hinfo={}".format(
        conf["server_ip"],
        conf["server_port"],
        args.id,
    )
    history.record_get(url)
    hosts = get(url).json()
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

    url = "http://{}:{}/hinfopresets/{}".format(
        conf["server_ip"],
        conf["server_port"],
        args.id,
    )
    history.record_delete(url, args.id)
    delete(url)
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
             action='count',
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
    print('remove loc:', args.name)


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
#  Implementation of sub command 'loc_set'  #
#############################################

def loc_set(args):
    print('set loc:', args.loc)


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
    ],
)


##############################################
#  Implementation of sub command 'loc_show'  #
##############################################

def loc_show(args):
    print('show LOC:', args.name)


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


################################################################################
#                                                                              #
#                                NAPTR records                                 #
#                                                                              #
################################################################################


###############################################
#  Implementation of sub command 'naptr_add'  #
###############################################

def naptr_add(args):
    print('add NAPTR:', args.name)


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
             required=True,
             metavar='PREFERENCE'),
        Flag('-order',
             description='NAPTR order.',
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
    print('removet NAPTR:', args.name)


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
    ],
)


################################################
#  Implementation of sub command 'naptr_show'  #
################################################

def naptr_show(args):
    print('show NAPTR:', args.name)


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
    print('change PTR:', args.ip)


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
    print('remove PTR:', args.ip)


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
    print('set PTR:', args.ip)


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
    ],
)


##############################################
#  Implementation of sub command 'ptr_show'  #
##############################################

def ptr_show(args):
    print('show PTR:', args.ip)


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
    print('add srv:', args.service)


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
    ],
)


################################################
#  Implementation of sub command 'srv_remove'  #
################################################

def srv_remove(args):
    print('remove srv:', args.name)


# Add 'srv_remove' as a sub command to the 'host' command
host.add_command(
    prog='srv_remove',
    description='Remove SRV record.',
    callback=srv_remove,
    flags=[
        Flag('service',
             description='Host target name.',
             metavar='SERVICE'),
    ],
)


##############################################
#  Implementation of sub command 'srv_show'  #
##############################################

def srv_show(args):
    print('show srv:', args.service)


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
    print('remove ttl:', args.name)


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
    print('set ttl:', args.ttl)


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
    print('show TTL:', args.name)


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
    print('add txt:', args.text)


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
    print('remove txt:', args.text)


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
    ],
)


##############################################
#  Implementation of sub command 'txt_show'  #
##############################################

def txt_show(args):
    print('show txt:', args.name)


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
