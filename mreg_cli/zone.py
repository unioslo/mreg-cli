from .exceptions import HostNotFoundWarning
from .cli import cli, Flag
from .log import cli_info, cli_warning
from .util import delete, get, host_info_by_name, host_in_mreg_zone, \
                  patch, post


#################################
#  Add the main command 'zone'  #
#################################

zone = cli.add_command(
    prog='zone',
    description='Manage zones.',
)


def _verify_nameservers(nameservers, force):
    if not nameservers:
        cli_warning('At least one nameserver is required')

    errors = []
    for nameserver in nameservers:
        try:
            info = host_info_by_name(nameserver)
        except HostNotFoundWarning:
            if not force:
                errors.append(f"{nameserver} is not in mreg, must force")
        else:
            if host_in_mreg_zone(info['name']):
                if not info['ipaddresses'] and not force:
                    errors.append("{nameserver} has no A-record/glue, must force")
    if errors:
        cli_warning("\n".join(errors))


def print_ns(info: str, hostname: str, ttl: str, padding: int = 20) -> None:
    print("        {1:<{0}}{2:<{3}}{4}".format(padding, info, hostname, 20, ttl))


##########################################
# Implementation of sub command 'create' #
##########################################

def create(args):
    """Create new zone.
    """
    _verify_nameservers(args.ns, args.force)
    post("/zones/", name=args.zone, email=args.email, primary_ns=args.ns)
    cli_info("created zone {}".format(args.zone), True)


zone.add_command(
    prog='create',
    description='Create new zone.',
    short_desc='Create new zone.',
    callback=create,
    flags=[
        Flag('zone',
             description='Zone name.',
             metavar='ZONE'),
        Flag('email',
             description='Contact email.',
             metavar='EMAIL'),
        Flag('ns',
             description='Nameservers of the zone.',
             nargs='+',
             metavar='NS'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ]
)


#####################################################
# Implementation of sub command 'delegation_create' #
#####################################################

def delegation_create(args):
    """Create a new zone delegation. """
    zone = get(f"/zones/{args.zone}", ok404=True)
    if zone is None:
        cli_warning(f"Zone '{args.zone}' does not exist")
    if not args.delegation.endswith(f".{args.zone}"):
        cli_warning(f"Delegation '{args.delegation}' is not in '{args.zone}'")
    _verify_nameservers(args.ns, args.force)
    post(f"/zones/{args.zone}/delegations/",
         name=args.delegation,
         nameservers=args.ns)
    cli_info("created zone delegation {}".format(args.delegation), True)


zone.add_command(
    prog='delegation_create',
    description='Create new zone delegation.',
    short_desc='Create new zone delegation.',
    callback=delegation_create,
    flags=[
        Flag('zone',
             description='Zone name.',
             metavar='ZONE'),
        Flag('delegation',
             description='Delegation',
             metavar='DELEGATION'),
        Flag('ns',
             description='Nameservers for the delegation.',
             nargs='+',
             metavar='NS'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ]
)


##########################################
# Implementation of sub command 'delete' #
##########################################

def zone_delete(args):
    """Delete a zone
    """
    zone = get(f"/zones/{args.zone}").json()

    hosts = get(f"/hosts/?zone={zone['id']}").json()
    zones = get(f"/zones/?name__endswith=.{args.zone}").json()

    # XXX: Not a fool proof check, as e.g. SRVs are not hosts. (yet.. ?)
    if hosts and not args.force:
        cli_warning(
            "Zone has {} registered entries, must force".format(len(hosts)))
    other_zones = [z['name'] for z in zones if z['name'] != args.zone]
    if other_zones:
        cli_warning("Zone has registered subzones '{}', "
                    "can not delete".format(", ".join(sorted(other_zones))))

    delete(f"/zones/{args.zone}")
    cli_info("deleted zone {}".format(zone['name']), True)


zone.add_command(
    prog='delete',
    description='Delete a zone',
    short_desc='Delete a zone',
    callback=zone_delete,
    flags=[
        Flag('zone',
             description='Zone name.',
             metavar='ZONE'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ]
)


#####################################################
# Implementation of sub command 'delegation_delete' #
#####################################################

def delegation_delete(args):
    """Delete a zone delegation. """
    zone = get(f"/zones/{args.zone}", ok404=True)
    if zone is None:
        cli_warning(f"Zone '{args.zone}' does not exist")
    if not args.delegation.endswith(f".{args.zone}"):
        cli_warning(f"Delegation '{args.delegation}' is not in '{args.zone}'")
    delete(f"/zones/{args.zone}/delegations/{args.delegation}")
    cli_info("Removed zone delegation {}".format(args.delegation), True)


zone.add_command(
    prog='delegation_delete',
    description='Delete a zone delegation',
    short_desc='Delete a zone delegation',
    callback=delegation_delete,
    flags=[
        Flag('zone',
             description='Zone name.',
             metavar='ZONE'),
        Flag('delegation',
             description='Delegation',
             metavar='DELEGATION'),
        ]
)


##########################################
# Implementation of sub command 'info' #
##########################################

def info(args):
    """Show SOA info for a existing zone.
    """

    def print_soa(info: str, text: str, padding: int = 20) -> None:
        print("{1:<{0}}{2}".format(padding, info, text))

    if not args.zone:
        cli_warning('Name is required')

    zone = get(f"/zones/{args.zone}").json()
    print_soa("Zone:", zone["name"])
    print_ns("Nameservers:", "hostname", "TTL")
    for ns in zone['nameservers']:
        ttl = ns['ttl'] if ns['ttl'] else "<not set>"
        print_ns("", ns['name'], ttl)
    print_soa("Primary ns:", zone["primary_ns"])
    print_soa("Email:", zone['email'])
    print_soa("Serialnumber:", zone["serialno"])
    print_soa("Refresh:", zone["refresh"])
    print_soa("Retry:", zone["retry"])
    print_soa("Expire:", zone["expire"])
    print_soa("TTL:", zone["ttl"])


zone.add_command(
    prog='info',
    description='Delete a zone',
    short_desc='Delete a zone',
    callback=info,
    flags=[
        Flag('zone',
             description='Zone name.',
             metavar='ZONE'),
    ]
)


##########################################
# Implementation of sub command 'list' #
##########################################

def zone_list(args):
    """List all zones.
    """

    zones = get("/zones/").json()
    if zones:
        print("Zones:")
        for zone in sorted(zones, key=lambda kv: kv['name']):
            print('   {}'.format(zone['name']))
    else:
        print("No zones found.")


zone.add_command(
    prog='list',
    description='List all zones',
    short_desc='List all zones',
    callback=zone_list,
)


##########################################
# Implementation of sub command 'delegation_list' #
##########################################

def zone_delegation_list(args):
    """List a zone's delegations
    """


    zone = get(f"/zones/{args.zone}", ok404=True)
    if zone is None:
        cli_warning(f"Zone '{args.zone}' does not exist")
    delegations = get(f"/zones/{args.zone}/delegations/").json()
    if delegations:
        print("Delegations:")
        for i in sorted(delegations, key=lambda kv: kv['name']):
            print('    {}'.format(i['name']))
            print_ns("Nameservers:", "hostname", "TTL")
            for ns in i['nameservers']:
                ttl = ns['ttl'] if ns['ttl'] else "<not set>"
                print_ns("", ns['name'], ttl)
    else:
        cli_info(f"No delegations for {args.zone}", True)


zone.add_command(
    prog='delegation_list',
    description="List a zone's delegations",
    short_desc="List a zone's delegations",
    callback=zone_delegation_list,
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
    """Update nameservers for an existing zone.
    """
    _verify_nameservers(args.ns, args.force)
    patch(f"/zones/{args.zone}/nameservers", primary_ns=args.ns)
    cli_info("updated nameservers for {}".format(args.zone), True)


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
        Flag('-force',
             action='store_true',
             description='Enable force.'),
    ]
)


###########################################
# Implementation of sub command 'set_soa' #
###########################################

def set_soa(args):
    # .zone .ns .email .serialno .retry .expire .ttl
    """Updated the SOA of a zone.
    """
    # TODO Validation for valid domain names
    get(f"/zones/{args.zone}").json()
    data = {}
    for i in ('email', 'expire', 'refresh', 'retry', 'serialno', 'ttl'):
        value = getattr(args, i, None)
        if value is not None:
            data[i] = value
    if args.ns:
        data['primary_ns'] = args.ns

    if data:
        patch(f"/zones/{args.zone}", **data)
        cli_info("set soa for {}".format(args.zone), True)
    else:
        cli_info("No options set, so unchanged.", True)


zone.add_command(
    prog='set_soa',
    description='Updated the SOA of a zone.',
    short_desc='Updated the SOA of a zone.',
    callback=set_soa,
    flags=[
        Flag('zone',
             description='Zone name.',
             metavar='ZONE'),
        Flag('-ns',
             description='Primary nameserver (SOA MNAME).',
             metavar='PRIMARY-NS'),
        Flag('-email',
             description='Zone contact email.',
             metavar='EMAIL'),
        Flag('-serialno',
             description='Serial number.',
             type=int,
             metavar='SERIALNO'),
        Flag('-refresh',
             description='Refresh time.',
             type=int,
             metavar='REFRESH'),
        Flag('-retry',
             description='Retry time.',
             type=int,
             metavar='RETRY'),
        Flag('-expire',
             description='Expire time.',
             type=int,
             metavar='EXPIRE'),
        Flag('-ttl',
             description='Time To Live.',
             type=int,
             metavar='TTL'),
    ]
)
