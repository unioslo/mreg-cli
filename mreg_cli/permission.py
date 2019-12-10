import ipaddress
from urllib.parse import urlencode

from .cli import Flag, cli
from .history import history
from .log import cli_info, cli_warning
from .util import convert_wildcard_to_regex, delete, get_list, is_valid_network, post

###################################
#  Add the main command 'access'  #
###################################

permission = cli.add_command(
    prog='permission',
    description='Manage permissions.',
)


##########################################
# Implementation of sub command 'list' #
##########################################


def network_list(args):
    """
    Lists permissions for networks
    """

    # Replace with a.supernet_of(b) when python 3.7 is required
    def _supernet_of(a, b):
        return (a.network_address <= b.network_address and
                a.broadcast_address >= b.broadcast_address)

    query = []
    params = ""
    if args.group is not None:
        query.append(convert_wildcard_to_regex("group", args.group))
    if query:
        params = "&" + "&".join(query)
    permissions = get_list(f"/api/v1/permissions/netgroupregex/?ordering=range,group{params}")

    data = []
    if args.range is not None:
        argnetwork = ipaddress.ip_network(args.range)
        for i in permissions:
            permnet = ipaddress.ip_network(i['range'])
            if argnetwork.version == permnet.version and \
               _supernet_of(argnetwork, ipaddress.ip_network(i['range'])):
                data.append(i)
    else:
        data = permissions

    if not data:
        cli_info("No permissions found", True)
        return

    headers = ("Range", "Group", "Regex")
    keys = ('range', 'group', 'regex')
    raw_format = ''
    for key, header in zip(keys, headers):
        longest = len(header)
        for d in data:
            longest = max(longest, len(d[key]))
        raw_format += '{:<%d} ' % longest

    print(raw_format.format(*headers))
    for d in data:
        print(raw_format.format(*[d[key] for key in keys]))

permission.add_command(
    prog='network_list',
    description='List permissions for networks',
    short_desc='List permissions for networks',
    callback=network_list,
    flags=[
        Flag('-group',
             description='Group with access',
             metavar='GROUP'),
        Flag('-range',
             description='Network range',
             metavar='RANGE'),
    ]
)

##########################################
# Implementation of sub command 'add' #
##########################################


def network_add(args):
    """
    Add permission for network
    """

    if not is_valid_network(args.range):
        cli_warning(f'Invalid range: {args.range}')

    data = {
        'range': args.range,
        'group': args.group,
        'regex': args.regex,
    }
    path = "/api/v1/permissions/netgroupregex/"
    history.record_get(path, "", data)
    post(path, **data)
    cli_info(f"Added permission to {args.range}", True)


permission.add_command(
    prog='network_add',
    description='Add permission for network',
    short_desc='Add permission for network',
    callback=network_add,
    flags=[
        Flag('range',
             description='Network range',
             metavar='RANGE'),
        Flag('group',
             description='Group with access',
             metavar='GROUP'),
        Flag('regex',
             description='Regular expression',
             metavar='REGEX'),
    ]
)


##########################################
# Implementation of sub command 'remove' #
##########################################

def network_remove(args):
    """
    Remove permission for networks
    """

    query = {
        'group': args.group,
        'range': args.range,
        'regex': args.regex,
    }
    params = "{}".format(urlencode(query))
    permissions = get_list("/api/v1/permissions/netgroupregex/?{}".format(params))

    if not permissions:
        cli_warning("No matching permission found", True)
        return

    assert len(permissions) == 1, "Should only match one permission"
    id = permissions[0]['id']
    path = f"/api/v1/permissions/netgroupregex/{id}"
    history.record_delete(path, dict(), undoable=False)
    delete(path)
    cli_info(f"Removed permission for {args.range}", True)


permission.add_command(
    prog='network_remove',
    description='Remove permission for network',
    short_desc='Remove permission for network',
    callback=network_remove,
    flags=[
        Flag('range',
             description='Network range',
             metavar='RANGE'),
        Flag('group',
             description='Group with access',
             metavar='GROUP'),
        Flag('regex',
             description='Regular expression',
             metavar='REGEX'),
    ]
)
