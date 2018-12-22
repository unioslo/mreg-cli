from cli import cli, Flag

#################################
#  Add the main command 'zone'  #
#################################

zone = cli.add_command(
    prog='zone',
    description='Manage zones.',
)


##########################################
# Implementation of sub command 'create' #
##########################################

def create(args):
    print('create:', args.zone)


zone.add_command(
    prog='create',
    description='Create new zone.',
    short_desc='Create new zone.',
    callback=create,
    flags=[
        Flag('zone',
             description='Zone name.',
             metavar='ZONE'),
        Flag('ns',
             description='Nameservers of the zone.',
             nargs='+',
             metavar='NS'),
    ]
)


##########################################
# Implementation of sub command 'delete' #
##########################################

def delete(args):
    print('delete:', args.zone)


zone.add_command(
    prog='delete',
    description='Delete a zone',
    short_desc='Delete a zone',
    callback=delete,
    flags=[
        Flag('zone',
             description='Zone name.',
             metavar='ZONE'),
    ]
)


##########################################
# Implementation of sub command 'set_ns' #
##########################################

def set_ns(args):
    print('set_ns:', args.zone)


zone.add_command(
    prog='set_ns',
    description='Update nameservers for an existing zone.',
    short_desc='Update nameservers for an existing zone.',
    callback=set_ns,
    flags=[
        Flag('zone',
             description='Zone name.',
             metavar='ZONE'),
        Flag('ns',
             description='Nameservers of the zone.',
             nargs='+',
             metavar='NS'),
    ]
)


###########################################
# Implementation of sub command 'set_soa' #
###########################################

def set_soa(args):
    print('set_soa:', args.zone)


zone.add_command(
    prog='set_soa',
    description='Updated the SOA of a zone.',
    short_desc='Updated the SOA of a zone.',
    callback=set_soa,
    flags=[
        Flag('-zone',
             description='Zone name.',
             required=True,
             metavar='ZONE'),
        Flag('-ns',
             description='Primary nameserver.',
             required=True,
             metavar='PRIMARY-NS'),
        Flag('-email',
             description='Zone contact email.',
             required=True,
             metavar='EMAIL'),
        Flag('-serialno',
             description='Serial number.',
             required=True,
             metavar='SERIALNO'),
        Flag('-retry',
             description='Retry time.',
             metavar='RETRY'),
        Flag('-expire',
             description='Expire time.',
             required=True,
             metavar='EXPIRE'),
        Flag('-ttl',
             description='Time To Live.',
             required=True,
             metavar='TTL'),
    ]
)
