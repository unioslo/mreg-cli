from cli import cli, Flag

#################################
#  Add the main command 'dhcp'  #
#################################

dhcp = cli.add_command(
    prog='dhcp',
    description='Manage dhcp.',
)


#########################################
# Implementation of sub command 'assoc' #
#########################################

def assoc(args):
    print('associate:', args.name, args.mac)


dhcp.add_command(
    prog='assoc',
    description='Associate MAC address with host. If host got multiple A/AAAA '
                'records an IP must be given instead of name.',
    short_desc='Add MAC address to host.',
    callback=assoc,
    flags=[
        Flag('name',
             description='Name or IP of target host.',
             metavar='NAME/IP'),
        Flag('mac',
             description='Mac address.',
             metavar='MACADDRESS')
    ]
)


############################################
# Implementation of sub command 'disassoc' #
############################################

def disassoc(args):
    print('disassoc:', args.name)


dhcp.add_command(
    prog='disassoc',
    description='Disassociate MAC address with host/ip. If host got multiple '
                'A/AAAA records an IP must be given instead of name.',
    short_desc='Disassociate MAC address.',
    callback=disassoc,
    flags=[
        Flag('name',
             description='Name or IP of host.',
             metavar='NAME/IP'),
    ]
)
