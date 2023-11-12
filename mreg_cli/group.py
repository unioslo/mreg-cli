from itertools import chain

from .cli import Flag, cli
from .history import history
from .history_log import format_history_items, get_history_items
from .log import cli_error, cli_info, cli_warning
from .outputmanager import OutputManager
from .util import delete, get_list, host_info_by_name, patch, post

##################################
#  Add the main command 'group'  #
##################################

group = cli.add_command(
    prog="group",
    description="Manage hostgroups.",
    short_desc="Manage hostgroups",
)

# Utils


def get_hostgroup(name):
    ret = get_list("/api/v1/hostgroups/", params={"name": name})
    if not ret:
        cli_warning(f'Group "{name}" does not exist')
    return ret[0]


"""
Implementation of sub command 'create'
"""


def create(args) -> None:
    # .name .description
    """Create a new host group."""
    ret = get_list("/api/v1/hostgroups/", params={"name": args.name})
    if ret:
        cli_error(f'Groupname "{args.name}" already in use')

    data = {"name": args.name, "description": args.description}

    path = "/api/v1/hostgroups/"
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info(f"Created new group {args.name!r}", print_msg=True)


group.add_command(
    prog="create",
    description="Create a new host group",
    short_desc="Create a new host group",
    callback=create,
    flags=[
        Flag("name", description="Group name", metavar="NAME"),
        Flag("description", description="Description", metavar="DESCRIPTION"),
    ],
)


########################################
# Implementation of sub command 'info' #
########################################


def info(args) -> None:
    """Show host group info."""

    manager = OutputManager()

    for name in args.name:
        info = get_hostgroup(name)

        manager.add_formatted_line("Name:", info["name"])
        manager.add_formatted_line("Description:", info["description"])
        members = []
        count = len(info["hosts"])
        if count:
            members.append("{} host{}".format(count, "s" if count > 1 else ""))
        count = len(info["groups"])
        if count:
            members.append("{} group{}".format(count, "s" if count > 1 else ""))
        manager.add_formatted_line("Members:", ", ".join(members))
        if len(info["owners"]):
            owners = ", ".join([i["name"] for i in info["owners"]])
            manager.add_formatted_line("Owners:", owners)

    return manager


group.add_command(
    prog="info",
    description="Shows group info with description, member count and owner(s)",
    short_desc="Group info",
    callback=info,
    flags=[
        Flag("name", description="Group name", nargs="+", metavar="NAME"),
    ],
)


##########################################
# Implementation of sub command 'rename' #
##########################################


def rename(args) -> None:
    """Rename group."""
    get_hostgroup(args.oldname)
    patch(f"/api/v1/hostgroups/{args.oldname}", name=args.newname)
    cli_info(f"Renamed group {args.oldname!r} to {args.newname!r}", True)


group.add_command(
    prog="rename",
    description="Rename a group",
    short_desc="Rename a group",
    callback=rename,
    flags=[
        Flag("oldname", description="Existing name", metavar="OLDNAME"),
        Flag("newname", description="New name", metavar="NEWNAME"),
    ],
)


########################################
# Implementation of sub command 'list' #
########################################


def _list(args) -> None:
    """List group members."""

    manager = OutputManager()

    def _format_hosts(hosts, source=""):
        for host in hosts:
            manager.add_formatted_line_with_source("host", host["name"], source)

    def _expand_group(groupname):
        info = get_hostgroup(groupname)
        _format_hosts(info["hosts"], source=groupname)
        for group in info["groups"]:
            _expand_group(group["name"])

    info = get_hostgroup(args.name)
    if args.expand:
        manager.add_formatted_line_with_source("Type", "Name", "Source")
        _format_hosts(info["hosts"], source=args.name)
    else:
        manager.add_formatted_line("Type", "Name")
        _format_hosts(info["hosts"])

    for group in info["groups"]:
        if args.expand:
            _expand_group(group["name"])
        else:
            manager.add_formatted_line("group", group["name"])


group.add_command(
    prog="list",
    description="List group members",
    short_desc="List group members",
    callback=_list,
    flags=[
        Flag("name", description="Group name", metavar="NAME"),
        Flag("-expand", description="Expand group members", action="store_true"),
    ],
)

##########################################
# Implementation of sub command 'delete' #
##########################################


def _delete(args) -> None:
    # .name .force
    """Delete a host group."""
    info = get_hostgroup(args.name)

    if (len(info["hosts"]) or len(info["groups"])) and not args.force:
        cli_error(
            "Group contains %d host(s) and %d group(s), must force"
            % (len(info["hosts"]), len(info["groups"]))
        )

    path = f"/api/v1/hostgroups/{args.name}"
    history.record_delete(path, dict())
    delete(path)
    cli_info(f"Deleted group {args.name!r}", print_msg=True)


group.add_command(
    prog="delete",
    description="Delete host group",
    short_desc="Delete host group",
    callback=_delete,
    flags=[
        Flag("name", description="Group name", metavar="NAME"),
        Flag("-force", action="store_true", description="Enable force"),
    ],
)

###########################################
# Implementation of sub command 'history' #
###########################################


def _history(args) -> None:
    """Show host history for name."""
    manager = OutputManager()
    items = get_history_items(args.name, "group", data_relation="groups")
    for line in format_history_items(args.name, items):
        manager.add_line(line)

    return manager


group.add_command(
    prog="history",
    description="Show history for group name",
    short_desc="Show history for group name",
    callback=_history,
    flags=[
        Flag("name", description="Group name", metavar="NAME"),
    ],
)


#############################################
# Implementation of sub command 'group_add' #
#############################################


def group_add(args) -> None:
    """Add group(s) to group."""
    for name in chain([args.dstgroup], args.srcgroup):
        get_hostgroup(name)

    for src in args.srcgroup:
        data = {
            "name": src,
        }

        path = f"/api/v1/hostgroups/{args.dstgroup}/groups/"
        history.record_post(path, "", data, undoable=False)
        post(path, **data)
        cli_info(f"Added group {src!r} to {args.dstgroup!r}", print_msg=True)


group.add_command(
    prog="group_add",
    description="Add source group(s) to destination group",
    short_desc="Add group(s) to group",
    callback=group_add,
    flags=[
        Flag("dstgroup", description="destination group", metavar="DSTGROUP"),
        Flag("srcgroup", description="source group", nargs="+", metavar="SRCGROUP"),
    ],
)

################################################
# Implementation of sub command 'group_remove' #
################################################


def group_remove(args) -> None:
    """Remove group(s) from group."""
    info = get_hostgroup(args.dstgroup)
    group_names = set(i["name"] for i in info["groups"])
    for name in args.srcgroup:
        if name not in group_names:
            cli_warning(f"{name!r} not a group member in {args.dstgroup!r}")

    for src in args.srcgroup:
        path = f"/api/v1/hostgroups/{args.dstgroup}/groups/{src}"
        history.record_delete(path, dict())
        delete(path)
        cli_info(f"Removed group {src!r} from {args.dstgroup!r}", print_msg=True)


group.add_command(
    prog="group_remove",
    description="Remove source group(s) from destination group",
    short_desc="Remove group(s) from group",
    callback=group_remove,
    flags=[
        Flag("dstgroup", description="destination group", metavar="DSTGROUP"),
        Flag("srcgroup", description="source group", nargs="+", metavar="SRCGROUP"),
    ],
)

############################################
# Implementation of sub command 'host_add' #
############################################


def host_add(args) -> None:
    """Add host(s) to group."""
    get_hostgroup(args.group)
    info = []
    for name in args.hosts:
        info.append(host_info_by_name(name, follow_cname=False))

    for i in info:
        name = i["name"]
        data = {
            "name": name,
        }
        path = f"/api/v1/hostgroups/{args.group}/hosts/"
        history.record_post(path, "", data, undoable=False)
        post(path, **data)
        cli_info(f"Added host {name!r} to {args.group!r}", print_msg=True)


group.add_command(
    prog="host_add",
    description="Add host(s) to group",
    short_desc="Add host(s) to group",
    callback=host_add,
    flags=[
        Flag("group", description="group", metavar="GROUP"),
        Flag("hosts", description="hosts", nargs="+", metavar="HOST"),
    ],
)

###############################################
# Implementation of sub command 'host_remove' #
###############################################


def host_remove(args) -> None:
    """Remove host(s) from group."""
    get_hostgroup(args.group)
    info = []
    for name in args.hosts:
        info.append(host_info_by_name(name, follow_cname=False))

    for i in info:
        name = i["name"]
        path = f"/api/v1/hostgroups/{args.group}/hosts/{name}"
        history.record_delete(path, dict())
        delete(path)
        cli_info(f"Removed host {name!r} from {args.group!r}", print_msg=True)


group.add_command(
    prog="host_remove",
    description="Remove host(s) from group",
    short_desc="Remove host(s) from group",
    callback=host_remove,
    flags=[
        Flag("group", description="group", metavar="GROUP"),
        Flag("hosts", description="host", nargs="+", metavar="HOST"),
    ],
)

#############################################
# Implementation of sub command 'host_list' #
#############################################


def host_list(args) -> None:
    """List group memberships for host."""
    hostname = host_info_by_name(args.host, follow_cname=False)["name"]
    group_list = get_list("/api/v1/hostgroups/", params={"hosts__name": hostname})
    if len(group_list) == 0:
        cli_info(f"Host {hostname!r} is not a member in any hostgroup", True)
        return

    manager = OutputManager()

    manager.add_line("Groups:")
    for group in group_list:
        manager.add_line("  ", group["name"])

    return manager


group.add_command(
    prog="host_list",
    description="List host's group memberships",
    short_desc="List host's group memberships",
    callback=host_list,
    flags=[
        Flag("host", description="hostname", metavar="HOST"),
    ],
)

#############################################
# Implementation of sub command 'owner_add' #
#############################################


def owner_add(args) -> None:
    """Add owner(s) to group."""
    get_hostgroup(args.group)

    for name in args.owners:
        data = {
            "name": name,
        }
        path = f"/api/v1/hostgroups/{args.group}/owners/"
        history.record_post(path, "", data, undoable=False)
        post(path, **data)
        cli_info(f"Added {name!r} as owner of {args.group!r}", print_msg=True)


group.add_command(
    prog="owner_add",
    description="Add owner(s) to group",
    short_desc="Add owner(s) to group",
    callback=owner_add,
    flags=[
        Flag("group", description="group", metavar="GROUP"),
        Flag("owners", description="owners", nargs="+", metavar="OWNER"),
    ],
)

################################################
# Implementation of sub command 'owner_remove' #
################################################


def owner_remove(args) -> None:
    """Remove owner(s) from group."""
    info = get_hostgroup(args.group)
    names = set(i["name"] for i in info["owners"])
    for i in args.owners:
        if i not in names:
            cli_warning(f"{i!r} not a owner of {args.group}")

    for i in args.owners:
        path = f"/api/v1/hostgroups/{args.group}/owners/{i}"
        history.record_delete(path, dict())
        delete(path)
        cli_info(f"Removed {i!r} as owner of {args.group!r}", print_msg=True)


group.add_command(
    prog="owner_remove",
    description="Remove owner(s) from group",
    short_desc="Remove owner(s) from group",
    callback=owner_remove,
    flags=[
        Flag("group", description="group", metavar="GROUP"),
        Flag("owners", description="owner", nargs="+", metavar="OWNER"),
    ],
)

###################################################
# Implementation of sub command 'set_description' #
###################################################


def set_description(args) -> None:
    """Set description for group."""
    get_hostgroup(args.name)
    patch(f"/api/v1/hostgroups/{args.name}", description=args.description)
    cli_info(f"updated description to {args.description!r} for {args.name!r}", True)


group.add_command(
    prog="set_description",
    description="Set description for group",
    short_desc="Set description for group",
    callback=set_description,
    flags=[
        Flag("name", description="Group", metavar="GROUP"),
        Flag("description", description="Group description.", metavar="DESC"),
    ],
)
