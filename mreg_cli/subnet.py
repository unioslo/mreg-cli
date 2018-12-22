from cli import cli, Flag

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
    print('Doing subnet create:', args.subnet)


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
             required=True,
             metavar='VLAN'),
        Flag('-dns',
             description='DNS delegated.',
             required=True,
             metavar='DNS-DELEGATED'),
        Flag('-category',
             description='Category.',
             required=True,
             metavar='Category'),
        Flag('-location',
             description='Location.',
             required=True,
             metavar='LOCATION'),
        Flag('-frozen',
             description='Set frozen subnet.',
             required=True,
             action='count'),
    ]
)


###########################################
# Implementation of sub command 'import_' #
###########################################

def import_(args):
    print('Doing subnet import:', args.file)


subnet.add_command(
    prog='import',
    description='Import subnet data from FILE.',
    short_desc='Import subnet data from FILE.',
    callback=import_,
    flags=[
        Flag('file',
             description='File to import from.',
             metavar='FILE'),
    ]
)


########################################
# Implementation of sub command 'info' #
########################################

def info(args):
    print('Doing subnet info:', args.subnet)


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
    print('Doing subnet list_unused_addresses:', args.subnet)


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
    print('Doing subnet list_used_addresses:', args.subnet)


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
    print('Doing subnet remove:', args.subnet)


subnet.add_command(
    prog='remove',
    description='Remove subnet',
    short_desc='Remove subnet',
    callback=remove,
    flags=[
        Flag('subnet',
             description='Subnet.',
             metavar='SUBNET'),
    ]
)


################################################
# Implementation of sub command 'set_category' #
################################################

def set_category(args):
    print('Doing subnet set_category:', args.subnet)


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
    print('Doing subnet set_description:', args.subnet)


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
    print('Doing subnet set_dns_delegated:', args.subnet)


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
    print('Doing subnet set_frozen:', args.subnet)


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
    print('Doing subnet set_location:', args.subnet)


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
    print('Doing subnet set_reserved:', args.subnet)


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
             metavar='NUM'),
    ]
)


############################################
# Implementation of sub command 'set_vlan' #
############################################

def set_vlan(args):
    print('Doing subnet set_vlan:', args.subnet)


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
             metavar='VLAN'),
    ]
)


#######################################################
# Implementation of sub command 'unset_dns_delegated' #
#######################################################

def unset_dns_delegated(args):
    print('Doing subnet unset_dns_delegated:', args.subnet)


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
    print('Doing subnet unset_frozen:', args.subnet)


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
