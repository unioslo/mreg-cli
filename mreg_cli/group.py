from itertools import chain

from .log import cli_error, cli_info, cli_warning
from .cli import cli, Flag
from .history import history
from .util import delete, get, get_list, host_info_by_name, patch, post


##################################
#  Add the main command 'group'  #
##################################

group = cli.add_command(
    prog='group',
    description='Manage hostgroups',
)

### Utils

def get_hostgroup(name):
    ret = get_list(f'/api/v1/hostgroups/?name={name}')
    if not ret:
        cli_warning(f'Group "{name}" does not exist')
    return ret[0]



##########################################
# Implementation of sub command 'create' #
##########################################

def create(args):
    # .name .description
    """
    Create a new host group
    """

    ret = get_list(f'/api/v1/hostgroups/?name={args.name}')
    if ret:
        cli_error(f'Groupname "{args.name}" already in use')
    
    data = {
        'name': args.name,
        'description': args.description
    }

    path = '/api/v1/hostgroups/'
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info(f"Created new group {args.name}", print_msg=True)


group.add_command(
    prog='create',
    description='Create a new host group',
    short_desc='Create a new host group',
    callback=create,
    flags=[
        Flag('name',
             description='Group name',
             metavar='NAME'),
        Flag('description',
             description='Description',
             metavar='DESCRIPTION'),
    ]
)


########################################
# Implementation of sub command 'info' #
########################################

def info(args):
    """
    Show host group info
    """

    def _print(key, value, padding=14):
        print("{1:<{0}} {2}".format(padding, key, value))

    for name in args.name:
        info = get_hostgroup(name)

        _print('Name:', info['name'])
        _print('Description:', info['description'])
        members = []
        count = len(info['hosts'])
        if count > 0:
            members.append('{} host{}'.format(count, 's' if count > 1 else ''))
        ngroups = len(info['groups'])
        if count > 0:
            members.append('{} group{}'.format(count, 's' if count > 1 else ''))
        _print('Members:', ', '.join(members))
        if len(info['owners']):
            owners = ', '.join([i['name'] for i in info['owners']])
            _print('Owners:', owners)


group.add_command(
    prog='info',
    description='Shows group info with description, member count and owner(s)',
    short_desc='Group info',
    callback=info,
    flags=[
        Flag('name',
             description='Group name',
             nargs='+',
             metavar='NAME'),
    ]
)


########################################
# Implementation of sub command 'list' #
########################################

def _list(args):
    """
    List group members
    """

    def _print(key, value, source='', padding=14):
        print("{1:<{0}} {2:<{0}} {3}".format(padding, key, value, source))
    def _print_hosts(hosts, source=''):
        for host in hosts:
            _print('host', host['name'], source=source)
    def _expand_group(groupname):
        info = get(f'/hostgroups/{groupname}').json()
        _print_hosts(info['hosts'], source=groupname)
        for group in info['groups']:
            _expand_group(group['name'])

    info = get_hostgroup(args.name)
    if args.expand:
        _print('Type', 'Name', 'Source')
        _print_hosts(info['hosts'], source=args.name)
    else:
        _print('Type', 'Name')
        _print_hosts(info['hosts'])

    for group in info['groups']:
        if args.expand:
            _expand_group(group['name'])
        else:
            _print('group', group['name'])

group.add_command(
    prog='list',
    description='List group members',
    short_desc='List group members',
    callback=_list,
    flags=[
        Flag('name',
             description='Group name',
             metavar='NAME'),
        Flag('-expand',
             description='Expand group members',
             action='store_true'),
    ]
)

def _delete(args):
    # .name .force
    """
    Delete a host group
    """

    info = get_hostgroup(args.name)

    if len(info['hosts']) or len(info['groups']) and not args.force:
        cli_error('Group contains %d host(s) and %d group(s), must force'
                  % (len(info['hosts']), len('groups')))
    
    path = f'/api/v1/hostgroups/{args.name}'
    history.record_delete(path, dict())
    delete(path)
    cli_info(f"Deleted group {args.name}", print_msg=True)


group.add_command(
    prog='delete',
    description='Delete host group',
    short_desc='Delete host group',
    callback=_delete,
    flags=[
        Flag('name',
             description='Group name',
             metavar='NAME'),
        Flag('-force',
            action='store_true',
            description='Enable force'),
    ]
)

#############################################
# Implementation of sub command 'group_add' #
#############################################

def group_add(args):
    """
    Add group(s) to group
    """

    for name in chain([args.dstgroup], args.srcgroup):
        get_hostgroup(name)

    for src in args.srcgroup:
        data = {
            'name': src,
        }

        path = f'/api/v1/hostgroups/{args.dstgroup}/groups/'
        history.record_post(path, "", data, undoable=False)
        post(path, **data)
        cli_info(f"Added {src} to {args.dstgroup}", print_msg=True)


group.add_command(
    prog='group_add',
    description='Add source group(s) to destination group',
    short_desc='Add group(s) to group',
    callback=group_add,
    flags=[
        Flag('dstgroup',
             description='destination group',
             metavar='DSTGROUP'),
        Flag('srcgroup',
             description='source group',
             nargs='+',
             metavar='SRCGROUP'),
    ]
)

################################################
# Implementation of sub command 'group_remove' #
################################################

def group_remove(args):
    """
    Remove group(s) from group
    """

    info = get_hostgroup(args.dstgroup)
    group_names = set(i['name'] for i in info['groups'])
    for name in args.srcgroup:
        if name not in group_names:
            cli_warning(f"'{name}' not a group member in {args.dstgroup}")

    for src in args.srcgroup:
        path = f'/api/v1/hostgroups/{args.dstgroup}/groups/{src}'
        history.record_delete(path, dict())
        delete(path)
        cli_info(f"Removed '{src}' from {args.dstgroup}", print_msg=True)


group.add_command(
    prog='group_remove',
    description='Remove source group(s) from destination group',
    short_desc='Remove group(s) from group',
    callback=group_remove,
    flags=[
        Flag('dstgroup',
             description='destination group',
             metavar='DSTGROUP'),
        Flag('srcgroup',
             description='source group',
             nargs='+',
             metavar='SRCGROUP'),
    ]
)

############################################
# Implementation of sub command 'host_add' #
############################################

def host_add(args):
    """
    Add host(s) to group
    """

    get_hostgroup(args.group)
    info = []
    for name in args.hosts:
        info.append(host_info_by_name(name, follow_cname=False))

    for i in info:
        name = i['name']
        data = {
            'name': name,
        }
        path = f'/api/v1/hostgroups/{args.group}/hosts/'
        history.record_post(path, "", data, undoable=False)
        post(path, **data)
        cli_info(f"Added {name} to {args.group}", print_msg=True)


group.add_command(
    prog='host_add',
    description='Add host(s) to group',
    short_desc='Add host(s) to group',
    callback=host_add,
    flags=[
        Flag('group',
             description='group',
             metavar='GROUP'),
        Flag('hosts',
             description='hosts',
             nargs='+',
             metavar='HOST'),
    ]
)

###############################################
# Implementation of sub command 'host_remove' #
###############################################

def host_remove(args):
    """
    Remove host(s) from group
    """

    get_hostgroup(args.group)
    info = []
    for name in args.hosts:
        info.append(host_info_by_name(name, follow_cname=False))

    for i in info:
        name = i['name']
        path = f'/api/v1/hostgroups/{args.group}/hosts/{name}'
        history.record_delete(path, dict())
        delete(path)
        cli_info(f"Removed '{name}' from {args.group}", print_msg=True)


group.add_command(
    prog='host_remove',
    description='Remove host(s) from group',
    short_desc='Remove host(s) from group',
    callback=host_remove,
    flags=[
        Flag('group',
             description='group',
             metavar='GROUP'),
        Flag('hosts',
             description='host',
             nargs='+',
             metavar='HOST'),
    ]
)

################################################
# Implementation of sub command 'owner_remove' #
################################################

def owner_remove(args):
    """
    Remove owner(s) from group
    """

    info = get_hostgroup(args.group)
    names = set(i['name'] for i in info['owners'])
    for i in args.owners:
        if i not in names:
            cli_warning(f"'{i}' not a owner of {args.group}")

    for i in args.owners:
        path = f'/api/v1/hostgroups/{args.group}/owners/{i}'
        history.record_delete(path, dict())
        delete(path)
        cli_info(f"Removed '{i}' from {args.group}", print_msg=True)


group.add_command(
    prog='owner_remove',
    description='Remove owner(s) from group',
    short_desc='Remove owner(s) from group',
    callback=owner_remove,
    flags=[
        Flag('group',
             description='group',
             metavar='GROUP'),
        Flag('owners',
             description='owner',
             nargs='+',
             metavar='OWNER'),
    ]
)

###################################################
# Implementation of sub command 'set_description' #
###################################################

def set_description(args):
    """Set description for group
    """
    group = get_hostgroup(args.name)
    patch(f"/hostgroups/{args.name}", description=args.description)
    cli_info("updated description to '{}' for {}".format(args.description,
                                                         args.name), True)


group.add_command(
    prog='set_description',
    description='Set description for group',
    short_desc='Set description for group',
    callback=set_description,
    flags=[
        Flag('name',
             description='Group',
             metavar='GROUP'),
        Flag('description',
             description='Group description.',
             metavar='DESC'),
    ]
)
