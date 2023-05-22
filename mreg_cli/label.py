from .cli import Flag, cli
from .history import history
from .log import cli_info, cli_warning, cli_error
from .util import get, get_list, post, patch, delete, print_table

label = cli.add_command(
    prog='label',
    description='Manage labels.',
)

def label_add(args):
    if ' ' in args.name:
        print("The label name can't contain spaces.")
        return
    data = {
        "name": args.name,
        "description": args.description
    }
    path = "/api/v1/labels/"
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info(f"Added label \"{args.name}\"", True)

label.add_command(
    prog='add',
    description='Add a label',
    short_desc='Add a label',
    callback=label_add,
    flags=[
        Flag('name', short_desc='Label name', description='The name of the new label'),
        Flag('description', description='The purpose of the label')
    ]
)

def label_list(args):
    labels = get_list("/api/v1/labels/", params={"ordering":"name"})
    if not labels:
        cli_info("No labels", True)
        return
    print_table(('Name','Description'), ('name','description'), labels)

label.add_command(
    prog='list',
    description='List labels',
    callback=label_list,
    flags=[]
)

def label_delete(args):
    path = f"/api/v1/labels/name/{args.name}"
    history.record_delete(path, dict(), undoable=False)
    delete(path)
    cli_info(f"Removed label \"{args.name}\"", True)

label.add_command(
    prog='remove',
    description='Remove a label',
    callback=label_delete,
    flags=[
        Flag('name', short_desc='Label name', description='The name of the label to remove')
    ]
)

def label_info(args):
    path = f"/api/v1/labels/name/{args.name}"
    label = get(path).json()
    print("Name:                  ", label["name"])
    print("Description:           ", label["description"])

    rolelist = get_list("/api/v1/hostpolicy/roles/", params={"labels__name":args.name})
    print("Roles with this label: ")
    if rolelist:
        for r in rolelist:
            print("    "+r["name"])
    else:
        print("    None")

    permlist = get_list("/api/v1/permissions/netgroupregex/", params={"labels__name":args.name})
    print("Permissions with this label:")
    if permlist:
        print_table(("IP range", "Group", "Reg.exp."), ("range","group","regex"), permlist, indent=4)
    else:
        print("    None")

label.add_command(
    prog='info',
    description='Show details about a label',
    callback=label_info,
    flags=[
        Flag('name', short_desc='Label name', description='The name of the label')
    ]
)

def label_rename(args):
    path = f"/api/v1/labels/name/{args.oldname}"
    res = get(path, ok404=True)
    if not res:
        cli_warning(f'Label "{args.oldname}" does not exist.')
    data = {
        "name": args.newname
    }
    if args.desc:
        data["description"] = args.desc
    patch(path, **data)
    cli_info("Renamed label \"{}\" to \"{}\"".format(args.oldname, args.newname), True)

label.add_command(
    prog='rename',
    description='Rename a label and/or change the description',
    callback=label_rename,
    flags=[
        Flag('oldname', short_desc='Old name', description='The old (current) name of the label'),
        Flag('newname', short_desc='New name', description='The new name of the label'),
        Flag('-desc', metavar='DESCRIPTION', short_desc='New description', description='The new description of the label')
    ]
)
