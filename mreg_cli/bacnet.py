from .cli import Flag, cli
from .exceptions import HostNotFoundWarning
from .history import history
from .host import host
from .log import cli_error, cli_info, cli_warning
from .util import (
    host_info_by_name,
    print_table,
    get,
    get_list,
    post,
    delete,
)

def bacnetid_add(args):
    info = host_info_by_name(args.name)
    if 'bacnetid' in info and info['bacnetid'] is not None:
        cli_error("{} already has BACnet ID {}.".format(info['name'],info['bacnetid']['id']))
    postdata = {'hostname': info['name']}
    path = '/api/v1/bacnet/ids/'
    bacnetid = getattr(args, 'id')
    if bacnetid:
        response = get(path+bacnetid, ok404=True)
        if response:
            j = response.json()
            cli_error('BACnet ID {} is already in use by {}'.format(j['id'], j['hostname']))
        postdata['id'] = bacnetid
    history.record_post(path, '', postdata)
    post(path, **postdata)
    info = host_info_by_name(args.name)
    if 'bacnetid' in info and info['bacnetid'] is not None:
        b = info['bacnetid']
        cli_info("Assigned BACnet ID {} to {}".format(b['id'], info['name']), print_msg=True)


host.add_command(
    prog='bacnetid_add',
    description='Assign a BACnet ID to the host.',
    short_desc='Add BACnet ID',
    callback=bacnetid_add,
    flags=[
        Flag('name',
             description='Name of host.',
             metavar='NAME'),
        Flag('-id',
             description='ID value (0-4194302)',
             metavar='ID'),
    ],
)

def bacnetid_remove(args):
    info = host_info_by_name(args.name)
    if 'bacnetid' not in info or info["bacnetid"] is None:
        cli_error("{} does not have a BACnet ID assigned.".format(info['name']))
    path = '/api/v1/bacnet/ids/{}'.format(info['bacnetid']['id'])
    history.record_delete(path, info['bacnetid'])
    delete(path)
    cli_info("Unassigned BACnet ID {} from {}".format(info['bacnetid']['id'], info['name']), print_msg=True)

host.add_command(
    prog='bacnetid_remove',
    description='Unassign the BACnet ID from the host.',
    short_desc='Remove BACnet ID',
    callback=bacnetid_remove,
    flags=[
        Flag('name',
             description='Name of host.',
             metavar='NAME'),
    ],
)


def bacnetid_list(args):
    minval = 0
    if args.min is not None:
        minval = args.min
        if minval < 0:
            cli_error("The minimum ID value is 0.")
    maxval = 4194302
    if args.max is not None:
        maxval = args.max
        if maxval > 4194302:
            cli_error("The maximum ID value is 4194302.")
    r = get_list("/api/v1/bacnet/ids/",{'id__range':'{},{}'.format(minval,maxval)})
    print_table(('ID','Hostname'), ('id','hostname'), r)

host.add_command(
    prog='bacnetid_list',
    description='Find/list BACnet IDs and hostnames',
    short_desc='List used BACnet IDs',
    callback=bacnetid_list,
    flags=[
        Flag('-min',
             description='Minimum ID value (0-4194302)',
             type=int,
             metavar='MIN'),
        Flag('-max',
             description='Maximum ID value (0-4194302)',
             type=int,
             metavar='MAX'),
    ],
)
