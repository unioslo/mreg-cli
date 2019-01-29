from util import *
from log import *
# noinspection PyUnresolvedReferences
from cli import cli, Flag
from history import history

try:
    conf = cli_config(required_fields=("mregurl",))
except Exception as e:
    print("commands.py: cli_config:", e)
    traceback.print_exc()
    sys.exit(1)

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
    """Create new zone.
    """
    if not args.ns:
        cli_warning('At least one nameserver is required')

    for nameserver in args.ns:
        try:
            info = host_info_by_name(nameserver)
        except HostNotFoundWarning:
            if not args.force:
                cli_warning(
                    "{} has no A-record/glue, must force".format(nameserver))
        else:
            if host_in_mreg_zone(info['name']):
                if not info['ipaddresses'] and not args.force:
                    cli_warning("{} has no A-record/glue, must force".format(
                        nameserver))

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


##########################################
# Implementation of sub command 'delete' #
##########################################

def _delete(args):
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
    callback=_delete,
    flags=[
        Flag('zone',
             description='Zone name.',
             metavar='ZONE'),
        Flag('-force',
             action='store_true',
             description='Enable force.'),
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

    def print_ns(info: str, hostname: str, ttl: str, padding: int = 20) -> None:
        print("{1:<{0}}{2:<{3}}{4}".format(padding, info, hostname, 20, ttl))

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

def list_(args):
    """List all zones.
    """

    zones = get("/zones/").json()
    print("Zones:")
    for zone in sorted(zones, key=lambda kv: kv['name']):
        print('   {}'.format(zone['name']))


zone.add_command(
    prog='list',
    description='Delete a zone',
    short_desc='Delete a zone',
    callback=list_,
)


##########################################
# Implementation of sub command 'set_ns' #
##########################################

def set_ns(args):
    """Update nameservers for an existing zone.
    """
    # TODO Validation for valid domain names
    if not args.ns:
        cli_warning('At least one nameserver is required')

    for i in range(len(args.ns)):
        info = host_info_by_name(args.ns[i])
        if host_in_mreg_zone(info['name']):
            if not info['ipaddresses'] and not args.force:
                cli_warning("{} has no A-record/glue, must force".format(
                    args.ns[i]))
        args.ns[i] = info['name']

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
    zone = get(f"/zones/{args.zone}").json()
    nameservers = zone['nameservers']
    if args.ns not in [nameserver['name'] for nameserver in nameservers]:
        cli_warning("{} is not one of {}'s nameservers. Add it with set_ns "
                    "before trying again".format(args.ns, args.zone))

    patch(f"/zones/{args.zone}", primary_ns=args.ns, email=args.email,
            serialno=args.serialno, refresh=args.refresh, retry=args.retry,
            expire=args.expire, ttl=args.ttl)
    cli_info("set soa for {}".format(args.zone), True)


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
        Flag('-refresh',
             description='Refresh time.',
             type=int,
             required=True,
             metavar='REFRESH'),
        Flag('-retry',
             description='Retry time.',
             type=int,
             required=True,
             metavar='RETRY'),
        Flag('-expire',
             description='Expire time.',
             type=int,
             required=True,
             metavar='EXPIRE'),
        Flag('-ttl',
             description='Time To Live.',
             type=int,
             required=True,
             metavar='TTL'),
    ]
)
