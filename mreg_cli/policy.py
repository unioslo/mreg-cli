from itertools import chain

from .cli import Flag, cli
from .history import history
from .history_log import get_history_items, print_history_items
from .log import cli_error, cli_info, cli_warning
from .util import (convert_wildcard_to_regex, delete, get, get_list, host_info_by_name,
                   patch, post)

##################################
#  Add the main command 'policy'  #
##################################

policy = cli.add_command(
    prog='policy',
    description='Manage hostpolicy',
)

# Utils


def _get_atom(name):
    return get_list(f'/api/v1/hostpolicy/atoms/?name={name}')


def get_atom(name):
    ret = _get_atom(name)
    if not ret:
        cli_warning(f'Atom "{name}" does not exist')
    return ret[0]


def _get_role(name):
    return get_list(f'/api/v1/hostpolicy/roles/?name={name}')


def get_role(name):
    ret = _get_role(name)
    if not ret:
        cli_warning(f'Role "{name}" does not exist')
    return ret[0]

def get_atom_or_role(name):
    atom = _get_atom(name)
    if atom:
        return 'atom', atom[0]
    role = _get_role(name)
    if role:
        return 'role', role[0]
    cli_warning(f'Could not find an atom or a role with name: {name}')


"""
Implementation of sub command 'atom_create'
"""


def atom_create(args):
    # .name .description
    """
    Create a new atom
    """

    ret = _get_atom(args.name)
    if ret:
        cli_error(f'Atom "{args.name}" already in use')

    data = {
        'name': args.name,
        'description': args.description
    }

    if args.created:
        data['create_date'] = args.created

    path = '/api/v1/hostpolicy/atoms/'
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info(f"Created new atom {args.name}", print_msg=True)


policy.add_command(
    prog='atom_create',
    description='Create a new atom',
    short_desc='Create a new atom',
    callback=atom_create,
    flags=[
        Flag('name',
             description='Atom name',
             metavar='NAME'),
        Flag('description',
             description='Description',
             metavar='DESCRIPTION'),
        Flag('-created',
             description='Created date',
             metavar='CREATED'),
    ]
)


def atom_delete(args):
    # .name
    """
    Delete an atom
    """

    get_atom(args.name)

    info = get_list(f'/api/v1/hostpolicy/roles/?atoms__name__exact={args.name}')
    inuse = [i['name'] for i in info]

    if inuse:
        roles = ', '.join(inuse)
        cli_error(f'Atom {args.name} used in roles: {roles}')

    path = f'/api/v1/hostpolicy/atoms/{args.name}'
    history.record_delete(path, dict())
    delete(path)
    cli_info(f"Deleted atom {args.name}", print_msg=True)


policy.add_command(
    prog='atom_delete',
    description='Delete an atom',
    short_desc='Delete an atom',
    callback=atom_delete,
    flags=[
        Flag('name',
             description='Atom name',
             metavar='NAME'),
    ]
)



"""
Implementation of sub command 'role_create'
"""


def role_create(args):
    # .role .description
    """
    Create a new role
    """

    ret = _get_role(args.name)
    if ret:
        cli_error(f'Role "{args.name}" already in use')

    data = {
        'name': args.name,
        'description': args.description
    }

    if args.created:
        data['create_date'] = args.created

    path = '/api/v1/hostpolicy/roles/'
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info(f"Created new role {args.name}", print_msg=True)


policy.add_command(
    prog='role_create',
    description='Create a new role',
    short_desc='Create a new role',
    callback=role_create,
    flags=[
        Flag('name',
             description='Role name',
             metavar='NAME'),
        Flag('description',
             description='Description',
             metavar='DESCRIPTION'),
        Flag('-created',
             description='Created date',
             metavar='CREATED'),
    ]
)


def role_delete(args):
    # .name
    """
    Delete a role
    """

    info = get_role(args.name)
    inuse = [i['name'] for i in info['hosts']]

    if inuse:
        hosts = ', '.join(inuse)
        cli_error(f'Role {args.name} used on hosts: {hosts}')

    path = f'/api/v1/hostpolicy/roles/{args.name}'
    history.record_delete(path, dict())
    delete(path)
    cli_info(f"Deleted role {args.name}", print_msg=True)


policy.add_command(
    prog='role_delete',
    description='Delete a role',
    short_desc='Delete a role',
    callback=role_delete,
    flags=[
        Flag('name',
             description='Role name',
             metavar='NAME'),
    ]
)


def add_atom(args):
    """
    Make an atom member of a role
    """

    info = get_role(args.role)
    for atom in info['atoms']:
        if args.atom == atom['name']:
            cli_info(f"Atom {args.atom} already a member of role {args.role}", print_msg=True)
            return
    get_atom(args.atom)

    data = {'name': args.atom}
    path = f'/api/v1/hostpolicy/roles/{args.role}/atoms/'
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info(f"Added atom {args.atom} to role {args.role}", print_msg=True)


policy.add_command(
    prog='add_atom',
    description='Make an atom member of a role',
    short_desc='Make an atom member of a role',
    callback=add_atom,
    flags=[
        Flag('role',
             description='Role name',
             metavar='ROLE'),
        Flag('atom',
             description='Atom name',
             metavar='ATOM'),
    ]
)


def remove_atom(args):
    """
    Remove an atom member from a role
    """

    info = get_role(args.role)
    for atom in info['atoms']:
        if args.atom == atom['name']:
            break
    else:
        cli_warning(f"Atom {args.atom} not a member of {args.role}")

    path = f'/api/v1/hostpolicy/roles/{args.role}/atoms/{args.atom}'
    history.record_delete(path, dict())
    delete(path)
    cli_info(f"Removed atom {args.atom} from role {args.role}", print_msg=True)


policy.add_command(
    prog='remove_atom',
    description='Remove an atom member from a role',
    short_desc='Remove an atom member from a role',
    callback=remove_atom,
    flags=[
        Flag('role',
             description='Role name',
             metavar='ROLE'),
        Flag('atom',
             description='Atom name',
             metavar='ATOM'),
    ]
)


########################################
# Implementation of sub command 'info' #
########################################

def info(args):
    """
    Show info about an atom or role
    """

    def _print(key, value, padding=14):
        print("{1:<{0}} {2}".format(padding, key, value))

    for name in args.name:
        policy, info = get_atom_or_role(name)
        _print('Name:', info['name'])
        _print('Created:', info['create_date'])
        _print('Description:', info['description'])

        if policy == 'atom':
            print("Roles where this atom is a member:")
            if info['roles']:
                for i in info['roles']:
                    _print('', i['name'])
            else:
                print('None')
        else:
            print("Atom members:")
            if info['atoms']:
                for i in info['atoms']:
                    _print('', i['name'])
            else:
                print('None')


policy.add_command(
    prog='info',
    description='Show info about an atom or role',
    short_desc='atom/role info',
    callback=info,
    flags=[
        Flag('name',
             description='atom/role name',
             nargs='+',
             metavar='NAME'),
    ]
)


def atom_history(args):
    """Show history for name"""
    items = get_history_items(args.name, 'hostpolicy_atom', data_relation='atoms')
    print_history_items(args.name, items)

policy.add_command(
    prog='atom_history',
    description='Show history for atom name',
    short_desc='Show history for atom name',
    callback=atom_history,
    flags=[
        Flag('name',
             description='Host name',
             metavar='NAME'),
    ],
)

def role_history(args):
    """Show history for name"""
    items = get_history_items(args.name, 'hostpolicy_role', data_relation='roles')
    print_history_items(args.name, items)

policy.add_command(
    prog='role_history',
    description='Show history for role name',
    short_desc='Show history for role name',
    callback=role_history,
    flags=[
        Flag('name',
             description='Host name',
             metavar='NAME'),
    ],
)


def list_atoms(args):
    """
    List all atoms by given filters
    """

    def _print(key, value, padding=14):
        print("{1:<{0}} {2}".format(padding, key, value))
    
    filter = convert_wildcard_to_regex('name', args.name)
    info = get_list(f'/api/v1/hostpolicy/atoms/?{filter}')
    if info:
        for i in info:
            _print(i['name'], i['description'])
    else:
        print('No match')


policy.add_command(
    prog='list_atoms',
    description='List all atoms by given filters',
    short_desc='List all atoms by given filters',
    callback=list_atoms,
    flags=[
        Flag('name',
            description='Atom name filter',
             metavar='NAME'),
    ]
)


def list_roles(args):
    """
    List all roles by given filters
    """

    def _print(key, value, padding=14):
        print("{1:<{0}} {2}".format(padding, key, value))
    
    filter = convert_wildcard_to_regex('name', args.name)
    info = get_list(f'/api/v1/hostpolicy/roles/?{filter}')
    if info:
        for i in info:
            _print(i['name'], i['description'])
    else:
        print('No match')


policy.add_command(
    prog='list_roles',
    description='List all roles by given filters',
    short_desc='List all roles by given filters',
    callback=list_roles,
    flags=[
        Flag('name',
            description='Role name filter',
             metavar='NAME'),
    ]
)


def list_hosts(args):
    """
    List hosts which use the given role
    """
    info = get_role(args.name)
    if info['hosts']:
        print('Name:')
        for i in info['hosts']:
            print(" " + i['name'])
    else:
        print('No host uses this role')



policy.add_command(
    prog='list_hosts',
    description='List hosts which use the given role',
    short_desc='List hosts which use the given role',
    callback=list_hosts,
    flags=[
        Flag('name',
            description='Role name',
             metavar='NAME'),
    ]
)

def list_members(args):
    """
    List atom members for a role
    """
    info = get_role(args.name)

    if info['atoms']:
        print('Name:')
        for i in info['atoms']:
            print(" " + i['name'])
    else:
        print('No atom members')

policy.add_command(
    prog='list_members',
    description='List all members of a role',
    short_desc='List role members',
    callback=list_members,
    flags=[
        Flag('name',
            description='Role name',
             metavar='NAME'),
    ]
)


def host_add(args):
    """
    Add host(s) to role
    """

    get_role(args.role)
    info = []
    for name in args.hosts:
        info.append(host_info_by_name(name, follow_cname=False))

    for i in info:
        name = i['name']
        data = {
            'name': name,
        }
        path = f'/api/v1/hostpolicy/roles/{args.role}/hosts/'
        history.record_post(path, "", data, undoable=False)
        post(path, **data)
        cli_info(f"Added {name} to {args.role}", print_msg=True)


policy.add_command(
    prog='host_add',
    description='Add host(s) to role',
    short_desc='Add host(s) to role',
    callback=host_add,
    flags=[
        Flag('role',
             description='role',
             metavar='ROLE'),
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
    Remove host(s) from role
    """

    get_role(args.role)
    info = []
    for name in args.hosts:
        info.append(host_info_by_name(name, follow_cname=False))

    for i in info:
        name = i['name']
        path = f'/api/v1/hostpolicy/roles/{args.role}/hosts/{name}'
        history.record_delete(path, dict())
        delete(path)
        cli_info(f"Removed '{name}' from {args.role}", print_msg=True)


policy.add_command(
    prog='host_remove',
    description='Remove host(s) from role',
    short_desc='Remove host(s) from role',
    callback=host_remove,
    flags=[
        Flag('role',
             description='role',
             metavar='ROLE'),
        Flag('hosts',
             description='host',
             nargs='+',
             metavar='HOST'),
    ]
)

###################################################
# Implementation of sub command 'set_description' #
###################################################


def set_description(args):
    """Set description for atom/role
    """
    if _get_atom(args.name):
        path = f'/api/v1/hostpolicy/atoms/{args.name}'
    elif _get_role(args.name):
        path = f'/api/v1/hostpolicy/roles/{args.name}'
    else:
        cli_warning('Could not find an atom or role with name {args.name}')
    patch(path, description=args.description)
    cli_info("updated description to '{}' for {}".format(args.description,
                                                         args.name), True)


policy.add_command(
    prog='set_description',
    description='Set description for an atom or role',
    short_desc='Set description for an atom or role',
    callback=set_description,
    flags=[
        Flag('name',
             description='Name',
             metavar='NAME'),
        Flag('description',
             description='Description.',
             metavar='DESC'),
    ]
)
