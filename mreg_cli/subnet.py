from util import *
from log import *
# noinspection PyUnresolvedReferences
from cli import cli, Flag
from history import history

###################################
#  Add the main command 'subnet'  #
###################################

subnet = cli.add_command(
    prog='subnet',
    description='Manage subnets.',
)


##########################################
# Implementation of sub command 'create' #
##########################################

def create(args):
    """Create a new subnet
    """
    frozen = True if args.frozen else False
    if args.vlan:
        string_to_int(args.vlan, "VLAN")
    if args.category and not is_valid_category_tag(args.category):
        cli_warning("Not a valid category tag")
    if args.location and not is_valid_location_tag(args.location):
        cli_warning("Not a valid location tag")

    url = "http://{}:{}/subnets/".format(conf["server_ip"], conf["server_port"])
    subnets_existing = get(url).json()
    for subnet in subnets_existing:
        subnet_object = ipaddress.ip_network(subnet['range'])
        if subnet_object.overlaps(ipaddress.ip_network(args.subnet)):
            cli_warning("Overlap found between new subnet {} and existing "
                        "subnet {}".format(ipaddress.ip_network(args.subnet),
                                           subnet['range']))

    url = "http://{}:{}/subnets/".format(conf["server_ip"], conf["server_port"])
    post(url, range=args.subnet, description=args.desc, vlan=args.vlan,
         category=args.category, location=args.location, frozen=frozen)
    cli_info("created subnet {}".format(args.subnet), True)


subnet.add_command(
    prog='create',
    description='Create a new subnet',
    short_desc='Create a new subnet',
    callback=create,
    flags=[
        Flag('-subnet',
             description='Subnet.',
             required=True,
             metavar='SUBNET'),
        Flag('-desc',
             description='Subnet description.',
             required=True,
             metavar='DESCRIPTION'),
        Flag('-vlan',
             description='VLAN.',
             default=None,
             metavar='VLAN'),
        Flag('-category',
             description='Category.',
             default=None,
             metavar='Category'),
        Flag('-location',
             description='Location.',
             default=None,
             metavar='LOCATION'),
        Flag('-frozen',
             description='Set frozen subnet.',
             action='count'),
    ]
)


###########################################
# Implementation of sub command 'import_' #
###########################################

def import_(args):
    """Import subnet data from <file>.
    """
    input_file = args.file
    log_file = open('subnets_import.log', 'a')
    vlans = get_vlan_mapping()
    # Flag to check before making requests if something isn't right
    ERROR = False

    log_file.write("------ READ FROM {} START ------\n".format(input_file))

    # Read in new subnet structure from file
    import_data = {}
    with open(input_file, 'r') as file:
        line_number = 0
        for line in file:
            line_number += 1
            match = re.match(r"(?P<range>\d+.\d+.\d+.\d+\/\d+)\s+"
                             r"((:(?P<tags>.*):\|(?P<description_tags>.*))|"
                             r"(?P<description_solo>.*))", line)
            if match:
                info = {'location': None, 'category': ''}
                if match.group('tags'):
                    tags = match.group('tags').split(':')
                    for tag in tags:
                        if is_valid_location_tag(tag):
                            info['location'] = tag
                        elif is_valid_category_tag(tag):
                            info['category'] = ('%s %s' % (
                                info['category'], tag)).strip()
                        else:
                            log_file.write(
                                "{}: Invalid tag {}. Valid tags can be found "
                                "in {}\n".format(line_number, tag,
                                                 conf['tag_file']))
                data = {
                    'range': match.group('range'),
                    'description': match.group(
                        'description_tags').strip() if match.group(
                        'description_tags') else match.group(
                        'description_solo').strip(),
                    'vlan': vlans[match.group('range')] if match.group(
                        'range') in vlans else 0,
                    'category': info['category'] if info['category'] else None,
                    'location': info['location'] if info['location'] else None,
                    'frozen': False
                }
                import_data['%s' % match.group('range')] = data
            else:
                log_file.write(
                    "{}: Could not match string\n".format(line_number))
                ERROR = True

    log_file.write("------ READ FROM {} END ------\n".format(input_file))

    # Fetch existing subnets from server
    res = requests.get(
        'http://{}:{}/subnets'.format(conf["server_ip"],
                                      conf["server_port"])).json()
    current_subnets = {subnet['range']: subnet for subnet in res}

    subnets_delete = current_subnets.keys() - import_data.keys()
    subnets_post = import_data.keys() - current_subnets.keys()
    subnets_patch = set()
    subnets_ignore = import_data.keys() & current_subnets.keys()

    # Check if subnets marked for deletion have any addresses in use
    for subnet in subnets_delete:
        used_list = get_subnet_used_list(subnet)
        if used_list:
            ERROR = True
            log_file.write("WARNING: {} contains addresses that are in use. "
                           "Remove hosts before deletion\n".format(subnet))

    # Check if subnets marked for creation have any overlap with existing
    # subnets.
    for subnet_new in subnets_post:
        subnet_object = ipaddress.ip_network(subnet_new)
        for subnet_existing in subnets_ignore:
            if subnet_object.overlaps(ipaddress.ip_network(subnet_existing)):
                ERROR = True
                log_file.write(
                    "ERROR: Overlap found between new subnet {} and existing "
                    "subnet {}\n".format(subnet_new, subnet_existing)
                )

    # Check which existing subnets need to be patched
    for subnet in subnets_ignore:
        current_data = current_subnets[subnet]
        new_data = import_data[subnet]
        if (new_data['description'] != current_data['description']
                or new_data['vlan'] != current_data['vlan']
                or new_data['category'] != current_data['category']
                or new_data['location'] != current_data['location']):
            subnets_patch.add(subnet)

    if ERROR:
        log_file.close()
        cli_warning(
            "Errors detected during setup. Check subnets_import.log for details")

    if len(subnets_delete) + len(subnets_patch) != 0:
        if ((len(subnets_delete) + len(subnets_patch)) / len(
                current_subnets.keys())) > 2 and not args.force:
            cli_warning("WARNING: The import will change over 20% of the "
                        "subnets. Requires force")

    log_file.write("------ API REQUESTS START ------\n".format(input_file))

    for subnet in subnets_delete:
        url = "http://{}:{}/subnets/{}".format(conf["server_ip"],
                                               conf["server_port"], subnet)
        delete(url)
        log_file.write("DELETE {}\n".format(url))

    for subnet in subnets_post:
        url = "http://{}:{}/subnets/".format(conf["server_ip"],
                                             conf["server_port"])
        data = import_data[subnet]
        post(url, range=data['range'],
             description=data['description'],
             vlan=data['vlan'],
             category=data['category'],
             location=data['location'],
             frozen=data['frozen'])
        log_file.write(
            "POST {} - {} - {}\n".format(url, subnet, data['description']))

    for subnet in subnets_patch:
        url = "http://{}:{}/subnets/{}".format(conf["server_ip"],
                                               conf["server_port"], subnet)
        data = import_data[subnet]
        patch(url, description=data['description'],
              vlan=data['vlan'],
              category=data['category'],
              location=data['location'])
        log_file.write("PATCH {}\n".format(url))

    log_file.write("------ API REQUESTS END ------\n".format(input_file))
    log_file.close()


subnet.add_command(
    prog='import',
    description='Import subnet data from FILE.',
    short_desc='Import subnet data from FILE.',
    callback=import_,
    flags=[
        Flag('file',
             description='File to import from.',
             metavar='FILE'),
        Flag('-force',
             action='count',
             description='Enable force.'),
    ]
)


########################################
# Implementation of sub command 'info' #
########################################

def info(args):
    """Display subnet info
    """
    for ip_range in args.subnets:
        # Get subnet info or raise exception
        subnet_info = get_subnet(ip_range)
        used = get_subnet_used_count(subnet_info['range'])
        unused = get_subnet_unused_count(subnet_info['range'])
        network = ipaddress.ip_network(subnet_info['range'])

        # Pretty print all subnet info
        print_subnet(subnet_info['range'], "Subnet:")
        print_subnet(network.netmask.exploded, "Netmask:")
        print_subnet(subnet_info['description'], "Description:")
        print_subnet(subnet_info['category'], "Category:")
        print_subnet(subnet_info['location'], "Location:")
        print_subnet(subnet_info['vlan'], "VLAN")
        print_subnet(subnet_info['dns_delegated'] if
                     subnet_info['dns_delegated'] else False, "DNS delegated:")
        print_subnet(subnet_info['frozen'] if subnet_info['frozen'] else False,
                     "Frozen")
        print_subnet_reserved(subnet_info['range'], subnet_info['reserved'])
        print_subnet(used, "Used addresses:")
        print_subnet_unused(unused)
        cli_info("printed subnet info for {}".format(subnet_info['range']))


subnet.add_command(
    prog='info',
    description='Display subnet info for one or more subnets.',
    short_desc='Display subnet info.',
    callback=info,
    flags=[
        Flag('subnets',
             description='One or more subnets.',
             nargs='+',
             metavar='SUBNET'),
    ]
)


#########################################################
# Implementation of sub command 'list_unused_addresses' #
#########################################################

def list_unused_addresses(args):
    """Lists all the unused addresses for a subnet
    """
    if is_valid_ip(args.subnet) or is_valid_subnet(args.subnet):
        subnet = get_subnet(args.subnet)
        unused_addresses = available_ips_from_subnet(subnet)
    else:
        cli_warning("Not a valid ip or subnet")

    for address in unused_addresses:
        print("{1:<{0}}".format(25, address))


subnet.add_command(
    prog='list_unused_addresses',
    description='Lists all the unused addresses for a subnet',
    short_desc='Lists unused addresses',
    callback=list_unused_addresses,
    flags=[
        Flag('subnet',
             description='Subnet.',
             metavar='SUBNET'),
    ]
)


#######################################################
# Implementation of sub command 'list_used_addresses' #
#######################################################

def list_used_addresses(args):
    """Lists all the used addresses for a subnet
    """
    if is_valid_ip(args.subnet):
        subnet = get_subnet(args.subnet)
        addresses = get_subnet_used_list(subnet['range'])
    elif is_valid_subnet(args.subnet):
        addresses = get_subnet_used_list(args.subnet)
    else:
        cli_warning("Not a valid ip or subnet")

    for address in addresses:
        host = resolve_ip(address)
        print("{1:<{0}}{2}".format(25, address, host))
    else:
        print("No used addresses.")


subnet.add_command(
    prog='list_used_addresses',
    description='Lists all the used addresses for a subnet',
    short_desc='Lists all the used addresses for a subnet',
    callback=list_used_addresses,
    flags=[
        Flag('subnet',
             description='Subnet.',
             metavar='SUBNET'),
    ]
)


##########################################
# Implementation of sub command 'remove' #
##########################################

def remove(args):
    """Remove subnet
    """
    import urllib

    ipaddress.ip_network(args.subnet)
    host_list = get_subnet_used_list(args.subnet)
    if host_list:
        cli_warning("Subnet contains addresses that are in use. Remove hosts "
                    "before deletion")

    if not args.force:
        cli_warning("Must force.")

    url = "http://{}:{}/subnets/{}".format(
        conf["server_ip"], conf["server_port"],
        urllib.parse.quote(args.subnet, safe='')
    )
    delete(url)
    cli_info("removed subnet {}".format(args.subnet), True)


subnet.add_command(
    prog='remove',
    description='Remove subnet',
    short_desc='Remove subnet',
    callback=remove,
    flags=[
        Flag('subnet',
             description='Subnet.',
             metavar='SUBNET'),
        Flag('-force',
             action='count',
             description='Enable force.'),
    ]
)


################################################
# Implementation of sub command 'set_category' #
################################################

def set_category(args):
    """Set category tag for subnet
    """
    subnet = get_subnet(args.subnet)
    if not is_valid_category_tag(args.category):
        cli_warning("Not a valid category tag")

    url = "http://{}:{}/subnets/{}".format(conf["server_ip"],
                                           conf["server_port"],
                                           subnet['range'])
    patch(url, category=args.category)
    cli_info("updated category tag to '{}' for {}"
             .format(args.category, subnet['range']), True)


subnet.add_command(
    prog='set_category',
    description='Set category tag for subnet',
    short_desc='Set category tag for subnet',
    callback=set_category,
    flags=[
        Flag('subnet',
             description='Subnet.',
             metavar='SUBNET'),
        Flag('category',
             description='Category tag.',
             metavar='CATEGORY-TAG'),
    ]
)


###################################################
# Implementation of sub command 'set_description' #
###################################################

def set_description(args):
    """Set description for subnet
    """
    subnet = get_subnet(args.subnet)
    url = "http://{}:{}/subnets/{}".format(conf["server_ip"],
                                           conf["server_port"],
                                           subnet['range'])
    patch(url, description=args.description)
    cli_info("updated description to '{}' for {}".format(args.description,
                                                         subnet['range']), True)


subnet.add_command(
    prog='set_description',  # <subnet> <description>
    description='Set description for subnet',
    short_desc='Set description for subnet',
    callback=set_description,
    flags=[
        Flag('subnet',
             description='Subnet.',
             metavar='SUBNET'),
        Flag('description',
             description='Subnet description.',
             metavar='DESC'),
    ]
)


#####################################################
# Implementation of sub command 'set_dns_delegated' #
#####################################################

def set_dns_delegated(args):
    """Set that DNS-administration is being handled elsewhere.
    """
    subnet = get_subnet(args.subnet)

    url = "http://{}:{}/subnets/{}".format(conf["server_ip"],
                                           conf["server_port"],
                                           subnet['range'])
    patch(url, dns_delegated=True)
    cli_info("updated dns_delegated to '{}' for {}"
             .format(True, subnet['range']), print_msg=True)


subnet.add_command(
    prog='set_dns_delegated',
    description='Set that DNS-administration is being handled elsewhere.',
    short_desc='Set that DNS-administration is being handled elsewhere.',
    callback=set_dns_delegated,
    flags=[
        Flag('subnet',
             description='Subnet.',
             metavar='SUBNET'),
    ]
)


##############################################
# Implementation of sub command 'set_frozen' #
##############################################

def set_frozen(args):
    """Freeze a subnet.
    """
    subnet = get_subnet(args.subnet)
    url = "http://{}:{}/subnets/{}".format(conf["server_ip"],
                                           conf["server_port"],
                                           subnet['range'])
    patch(url, frozen=True)
    cli_info("updated frozen to '{}' for {}"
             .format(True, subnet['range']), print_msg=True)


subnet.add_command(
    prog='set_frozen',
    description='Freeze a subnet.',
    short_desc='Freeze a subnet.',
    callback=set_frozen,
    flags=[
        Flag('subnet',
             description='Subnet.',
             metavar='SUBNET'),
    ]
)


################################################
# Implementation of sub command 'set_location' #
################################################

def set_location(args):
    """Set location tag for subnet
    """
    subnet = get_subnet(args.subnet)
    if not is_valid_location_tag(args.location):
        cli_warning("Not a valid location tag")

    url = "http://{}:{}/subnets/{}".format(conf["server_ip"],
                                           conf["server_port"],
                                           subnet['range'])
    patch(url, location=args.location)
    cli_info("updated location tag to '{}' for {}"
             .format(args.location, subnet['range']), True)


subnet.add_command(
    prog='set_location',
    description='Set location tag for subnet',
    short_desc='Set location tag for subnet',
    callback=set_location,
    flags=[
        Flag('subnet',
             description='Subnet.',
             metavar='SUBNET'),
        Flag('location',
             description='Location tag.',
             metavar='LOCATION-TAG'),
    ]
)


################################################
# Implementation of sub command 'set_reserved' #
################################################

def set_reserved(args):
    """Set number of reserved hosts.
    """
    subnet = get_subnet(args.subnet)
    reserved = args.number
    url = "http://{}:{}/subnets/{}".format(conf["server_ip"],
                                           conf["server_port"], subnet['range'])
    patch(url, reserved=reserved)
    cli_info("updated reserved to '{}' for {}"
             .format(reserved, subnet['range']), print_msg=True)


subnet.add_command(
    prog='set_reserved',
    description='Set number of reserved hosts.',
    short_desc='Set number of reserved hosts.',
    callback=set_reserved,
    flags=[
        Flag('subnet',
             description='Subnet.',
             metavar='SUBNET'),
        Flag('number',
             description='Number of reserved hosts.',
             type=int,
             metavar='NUM'),
    ]
)


############################################
# Implementation of sub command 'set_vlan' #
############################################

def set_vlan(args):
    """Set VLAN for subnet
    """
    subnet = get_subnet(args.subnet)
    url = "http://{}:{}/subnets/{}".format(conf["server_ip"],
                                           conf["server_port"],
                                           subnet['range'])
    patch(url, vlan=args.vlan)
    cli_info("updated vlan to {} for {}".format(args.vlan, subnet['range']),
             print_msg=True)


subnet.add_command(
    prog='set_vlan',  # <subnet> <vlan>
    description='Set VLAN for subnet',
    short_desc='Set VLAN for subnet',
    callback=set_vlan,
    flags=[
        Flag('subnet',
             description='Subnet.',
             metavar='SUBNET'),
        Flag('vlan',
             description='VLAN.',
             type=int,
             metavar='VLAN'),
    ]
)


#######################################################
# Implementation of sub command 'unset_dns_delegated' #
#######################################################

def unset_dns_delegated(args):
    """Set that DNS-administration is not being handled elsewhere.
    """
    subnet = get_subnet(args.subnet)
    url = "http://{}:{}/subnets/{}".format(conf["server_ip"],
                                           conf["server_port"],
                                           subnet['range'])
    patch(url, dns_delegated=False)
    cli_info("updated dns_delegated to '{}' for {}"
             .format(False, subnet['range']), print_msg=True)


subnet.add_command(
    prog='unset_dns_delegated',
    description='Set that DNS-administration is not being handled elsewhere.',
    short_desc='Set that DNS-administration is not being handled elsewhere.',
    callback=unset_dns_delegated,
    flags=[
        Flag('subnet',
             description='Subnet.',
             metavar='SUBNET'),
    ]
)


################################################
# Implementation of sub command 'unset_frozen' #
################################################

def unset_frozen(args):
    """Unfreeze a subnet.
    """
    subnet = get_subnet(args.subnet)
    url = "http://{}:{}/subnets/{}".format(conf["server_ip"],
                                           conf["server_port"],
                                           subnet['range'])
    patch(url, frozen=False)
    cli_info("updated frozen to '{}' for {}"
             .format(False, subnet['range']), print_msg=True)


subnet.add_command(
    prog='unset_frozen',
    description='Unfreeze a subnet.',
    short_desc='Unfreeze a subnet.',
    callback=unset_frozen,
    flags=[
        Flag('subnet',
             description='Subnet.',
             metavar='SUBNET'),
    ]
)
