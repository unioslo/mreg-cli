from .cli import Flag, cli
from .history import history
from .history_log import format_history_items, get_history_items
from .log import cli_error, cli_info, cli_warning
from .outputmanager import OutputManager
from .util import convert_wildcard_to_regex, delete, get, get_list, host_info_by_name, patch, post

##################################
#  Add the main command 'policy'  #
##################################

policy = cli.add_command(
    prog="policy",
    description="Manage policies for hosts.",
    short_desc="Manage policies",
)

# Utils


def _get_atom(name):
    return get_list("/api/v1/hostpolicy/atoms/", params={"name": name})


def get_atom(name):
    ret = _get_atom(name)
    if not ret:
        cli_warning(f"Atom {name!r} does not exist")
    return ret[0]


def _get_role(name):
    return get_list("/api/v1/hostpolicy/roles/", params={"name": name})


def get_role(name):
    ret = _get_role(name)
    if not ret:
        cli_warning(f"Role {name!r} does not exist")
    return ret[0]


def get_atom_or_role(name):
    atom = _get_atom(name)
    if atom:
        return "atom", atom[0]
    role = _get_role(name)
    if role:
        return "role", role[0]
    cli_warning(f"Could not find an atom or a role with name: {name!r}")


"""
Implementation of sub command 'atom_create'
"""


def atom_create(args) -> None:
    # .name .description
    """Create a new atom."""
    ret = _get_atom(args.name)
    if ret:
        cli_error(f'Atom "{args.name}" already in use')

    data = {"name": args.name, "description": args.description}

    if args.created:
        data["create_date"] = args.created

    path = "/api/v1/hostpolicy/atoms/"
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info(f"Created new atom {args.name}", print_msg=True)


policy.add_command(
    prog="atom_create",
    description="Create a new atom",
    short_desc="Create a new atom",
    callback=atom_create,
    flags=[
        Flag("name", description="Atom name", metavar="NAME"),
        Flag("description", description="Description", metavar="DESCRIPTION"),
        Flag("-created", description="Created date", metavar="CREATED"),
    ],
)


def atom_delete(args) -> None:
    # .name
    """Delete an atom."""
    get_atom(args.name)

    info = get_list("/api/v1/hostpolicy/roles/", params={"atoms__name__exact": args.name})
    inuse = [i["name"] for i in info]

    if inuse:
        roles = ", ".join(inuse)
        cli_error(f"Atom {args.name} used in roles: {roles}")

    path = f"/api/v1/hostpolicy/atoms/{args.name}"
    history.record_delete(path, dict())
    delete(path)
    cli_info(f"Deleted atom {args.name}", print_msg=True)


policy.add_command(
    prog="atom_delete",
    description="Delete an atom",
    short_desc="Delete an atom",
    callback=atom_delete,
    flags=[
        Flag("name", description="Atom name", metavar="NAME"),
    ],
)


"""
Implementation of sub command 'role_create'
"""


def role_create(args) -> None:
    # .role .description
    """Create a new role."""
    ret = _get_role(args.name)
    if ret:
        cli_error(f"Role name {args.name!r} already in use")

    data = {"name": args.name, "description": args.description}

    if args.created:
        data["create_date"] = args.created

    path = "/api/v1/hostpolicy/roles/"
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info(f"Created new role {args.name!r}", print_msg=True)


policy.add_command(
    prog="role_create",
    description="Create a new role",
    short_desc="Create a new role",
    callback=role_create,
    flags=[
        Flag("name", description="Role name", metavar="NAME"),
        Flag("description", description="Description", metavar="DESCRIPTION"),
        Flag("-created", description="Created date", metavar="CREATED"),
    ],
)


def role_delete(args) -> None:
    # .name
    """Delete a role."""
    info = get_role(args.name)
    inuse = [i["name"] for i in info["hosts"]]

    if inuse:
        hosts = ", ".join(inuse)
        cli_error(f"Role {args.name!r} used on hosts: {hosts}")

    path = f"/api/v1/hostpolicy/roles/{args.name}"
    history.record_delete(path, dict())
    delete(path)
    cli_info(f"Deleted role {args.name!r}", print_msg=True)


policy.add_command(
    prog="role_delete",
    description="Delete a role",
    short_desc="Delete a role",
    callback=role_delete,
    flags=[
        Flag("name", description="Role name", metavar="NAME"),
    ],
)


def add_atom(args) -> None:
    """Make an atom member of a role."""
    info = get_role(args.role)
    for atom in info["atoms"]:
        if args.atom == atom["name"]:
            cli_info(
                f"Atom {args.atom!r} already a member of role {args.role!r}",
                print_msg=True,
            )
            return
    get_atom(args.atom)

    data = {"name": args.atom}
    path = f"/api/v1/hostpolicy/roles/{args.role}/atoms/"
    history.record_post(path, "", data, undoable=False)
    post(path, **data)
    cli_info(f"Added atom {args.atom!r} to role {args.role!r}", print_msg=True)


policy.add_command(
    prog="add_atom",
    description="Make an atom member of a role",
    short_desc="Make an atom member of a role",
    callback=add_atom,
    flags=[
        Flag("role", description="Role name", metavar="ROLE"),
        Flag("atom", description="Atom name", metavar="ATOM"),
    ],
)


def remove_atom(args) -> None:
    """Remove an atom member from a role."""
    info = get_role(args.role)
    for atom in info["atoms"]:
        if args.atom == atom["name"]:
            break
    else:
        cli_warning(f"Atom {args.atom!r} not a member of {args.role!r}")

    path = f"/api/v1/hostpolicy/roles/{args.role}/atoms/{args.atom}"
    history.record_delete(path, dict())
    delete(path)
    cli_info(f"Removed atom {args.atom!r} from role {args.role!r}", print_msg=True)


policy.add_command(
    prog="remove_atom",
    description="Remove an atom member from a role",
    short_desc="Remove an atom member from a role",
    callback=remove_atom,
    flags=[
        Flag("role", description="Role name", metavar="ROLE"),
        Flag("atom", description="Atom name", metavar="ATOM"),
    ],
)


########################################
# Implementation of sub command 'info' #
########################################


def info(args) -> None:
    """Show info about an atom or role."""

    manager = OutputManager()

    def _format(key, value, padding=14):
        manager.add_formatted_line(key, value, padding)

    for name in args.name:
        policy, info = get_atom_or_role(name)
        _format("Name:", info["name"])
        _format("Created:", info["create_date"])
        _format("Description:", info["description"])

        if policy == "atom":
            manager.add_line("Roles where this atom is a member:")
            if info["roles"]:
                for i in info["roles"]:
                    _format("", i["name"])
            else:
                manager.add_line("None")
        else:
            manager.add_line("Atom members:")
            if info["atoms"]:
                for i in info["atoms"]:
                    _format("", i["name"])
            else:
                _format("", "None")

            manager.add_line("Labels:")
            for i in info["labels"]:
                lb = get(f"/api/v1/labels/{i}").json()
                _format("", lb["name"])
            if not info["labels"]:
                _format("", "None")


policy.add_command(
    prog="info",
    description="Show info about an atom or role",
    short_desc="atom/role info",
    callback=info,
    flags=[
        Flag("name", description="atom/role name", nargs="+", metavar="NAME"),
    ],
)


def atom_history(args) -> None:
    """Show history for name."""
    items = get_history_items(args.name, "hostpolicy_atom", data_relation="atoms")
    format_history_items(args.name, items)


policy.add_command(
    prog="atom_history",
    description="Show history for atom name",
    short_desc="Show history for atom name",
    callback=atom_history,
    flags=[
        Flag("name", description="Host name", metavar="NAME"),
    ],
)


def role_history(args) -> None:
    """Show history for name."""
    items = get_history_items(args.name, "hostpolicy_role", data_relation="roles")
    format_history_items(args.name, items)


policy.add_command(
    prog="role_history",
    description="Show history for role name",
    short_desc="Show history for role name",
    callback=role_history,
    flags=[
        Flag("name", description="Host name", metavar="NAME"),
    ],
)


def list_atoms(args) -> None:
    """List all atoms by given filters."""

    manager = OutputManager()

    def _format(key, value, padding=20):
        manager.add_formatted_line(key, value, padding)

    params = {}
    param, value = convert_wildcard_to_regex("name", args.name, True)
    params[param] = value
    info = get_list("/api/v1/hostpolicy/atoms/", params=params)
    if info:
        for i in info:
            _format(i["name"], repr(i["description"]))
    else:
        manager.add_line("No match")


policy.add_command(
    prog="list_atoms",
    description="List all atoms by given filters",
    short_desc="List all atoms by given filters",
    callback=list_atoms,
    flags=[
        Flag(
            "name",
            description="Atom name, or part of name. You can use * as a wildcard.",
            metavar="FILTER",
        ),
    ],
)


def list_roles(args) -> None:
    """List all roles by given filters."""

    manager = OutputManager()

    params = {}
    param, value = convert_wildcard_to_regex("name", args.name, True)
    params[param] = value
    info = get_list("/api/v1/hostpolicy/roles/", params=params)
    if not info:
        manager.add_line("No match")
        return

    labelnames = {}
    labellist = get_list("/api/v1/labels/")
    if labellist:
        for i in labellist:
            labelnames[i["id"]] = i["name"]

    rows = []
    for i in info:
        # show label names instead of id numbers
        labels = []
        for j in i["labels"]:
            labels.append(labelnames[j])
        i["labels"] = ", ".join(labels)
        rows.append(i)
    manager.add_formatted_table(
        ("Role", "Description", "Labels"), ("name", "description", "labels"), rows
    )


policy.add_command(
    prog="list_roles",
    description="List all roles by given filters",
    short_desc="List all roles by given filters",
    callback=list_roles,
    flags=[
        Flag(
            "name",
            description="Role name, or part of name. You can use * as a wildcard.",
            metavar="FILTER",
        ),
    ],
)


def list_hosts(args) -> None:
    """List hosts which use the given role."""
    manager = OutputManager()
    info = get_role(args.name)
    if info["hosts"]:
        manager.add_line("Name:")
        for i in info["hosts"]:
            manager.add_line(f" {i['name']}")
    else:
        manager.add_line("No host uses this role")


policy.add_command(
    prog="list_hosts",
    description="List hosts which use the given role",
    short_desc="List hosts which use the given role",
    callback=list_hosts,
    flags=[
        Flag("name", description="Role name", metavar="NAME"),
    ],
)


def list_members(args) -> None:
    """List atom members for a role."""
    info = get_role(args.name)
    manager = OutputManager()
    if info["atoms"]:
        manager.add_line("Name:")
        for i in info["atoms"]:
            manager.add_line(f" {i['name']}")
    else:
        manager.add_line("No atom members")


policy.add_command(
    prog="list_members",
    description="List all members of a role",
    short_desc="List role members",
    callback=list_members,
    flags=[
        Flag("name", description="Role name", metavar="NAME"),
    ],
)


def host_add(args) -> None:
    """Add host(s) to role."""
    get_role(args.role)
    info = []
    for name in args.hosts:
        info.append(host_info_by_name(name, follow_cname=False))

    for i in info:
        name = i["name"]
        data = {
            "name": name,
        }
        path = f"/api/v1/hostpolicy/roles/{args.role}/hosts/"
        history.record_post(path, "", data, undoable=False)
        post(path, **data)
        cli_info(f"Added host '{name}' to role '{args.role}'", print_msg=True)


policy.add_command(
    prog="host_add",
    description="Add host(s) to role",
    short_desc="Add host(s) to role",
    callback=host_add,
    flags=[
        Flag("role", description="role", metavar="ROLE"),
        Flag("hosts", description="hosts", nargs="+", metavar="HOST"),
    ],
)


def host_list(args) -> None:
    """List host roles."""

    manager = OutputManager()

    def _format(hostname, roleinfo):
        if not roleinfo:
            cli_info(f"Host {hostname!r} has no roles.", print_msg=True)
        else:
            manager.add_line(f"Roles for {hostname!r}:")
            for role in roleinfo:
                manager.add_line(f"  {role['name']}")

    info = []
    for name in args.hosts:
        info.append(host_info_by_name(name))

    for i in info:
        name = i["name"]
        path = "/api/v1/hostpolicy/roles/"
        params = {
            "hosts__name": name,
        }
        _format(name, get_list(path, params=params))


policy.add_command(
    prog="host_list",
    description="List roles for host(s)",
    short_desc="List roles for host(s)",
    callback=host_list,
    flags=[
        Flag("hosts", description="hosts", nargs="+", metavar="HOST"),
    ],
)


def host_remove(args) -> None:
    """Remove host(s) from role."""
    get_role(args.role)
    info = []
    for name in args.hosts:
        info.append(host_info_by_name(name, follow_cname=False))

    for i in info:
        name = i["name"]
        path = f"/api/v1/hostpolicy/roles/{args.role}/hosts/{name}"
        history.record_delete(path, dict())
        delete(path)
        cli_info(f"Removed host '{name}' from role '{args.role}'", print_msg=True)


policy.add_command(
    prog="host_remove",
    description="Remove host(s) from role",
    short_desc="Remove host(s) from role",
    callback=host_remove,
    flags=[
        Flag("role", description="role", metavar="ROLE"),
        Flag("hosts", description="host", nargs="+", metavar="HOST"),
    ],
)


def rename(args) -> None:
    """Rename an atom/role."""
    if _get_atom(args.oldname):
        path = f"/api/v1/hostpolicy/atoms/{args.oldname}"
    elif _get_role(args.oldname):
        path = f"/api/v1/hostpolicy/roles/{args.oldname}"
    else:
        cli_warning("Could not find an atom or role with name {args.name!r}")
    patch(path, name=args.newname)
    cli_info(f"Renamed {args.oldname!r} to {args.newname!r}", True)


policy.add_command(
    prog="rename",
    description="Rename an atom or role",
    short_desc="Rename an atom or role",
    callback=rename,
    flags=[
        Flag("oldname", description="Existing name", metavar="OLDNAME"),
        Flag("newname", description="New name", metavar="NEWNAME"),
    ],
)

###################################################
# Implementation of sub command 'set_description' #
###################################################


def set_description(args) -> None:
    """Set description for atom/role."""
    if _get_atom(args.name):
        path = f"/api/v1/hostpolicy/atoms/{args.name}"
    elif _get_role(args.name):
        path = f"/api/v1/hostpolicy/roles/{args.name}"
    else:
        cli_warning("Could not find an atom or role with name {args.name!r}")
    patch(path, description=args.description)
    cli_info(f"updated description to {args.description!r} for {args.name!r}", print_msg=True)


policy.add_command(
    prog="set_description",
    description="Set description for an atom or role",
    short_desc="Set description for an atom or role",
    callback=set_description,
    flags=[
        Flag("name", description="Name", metavar="NAME"),
        Flag("description", description="Description.", metavar="DESC"),
    ],
)


#################################################################
# Implementation of sub commands 'label_add' and 'label_remove'
#################################################################


def add_label_to_role(args) -> None:
    """Add a label to a role."""
    # find the role
    path = f"/api/v1/hostpolicy/roles/{args.role}"
    res = get(path, ok404=True)
    if not res:
        cli_warning(f"Could not find a role with name {args.role!r}")
    role = res.json()
    # find the label
    labelpath = f"/api/v1/labels/name/{args.label}"
    res = get(labelpath, ok404=True)
    if not res:
        cli_warning(f"Could not find a label with name {args.label!r}")
    label = res.json()
    # check if the role already has the label
    if label["id"] in role["labels"]:
        cli_warning(f"The role {args.role!r} already has the label {args.label!r}")
    # patch the role
    ar = role["labels"]
    ar.append(label["id"])
    patch(path, labels=ar)
    cli_info(f"Added the label {args.label!r} to the role {args.role!r}.", print_msg=True)


policy.add_command(
    prog="label_add",
    description="Add a label to a role",
    callback=add_label_to_role,
    flags=[Flag("label"), Flag("role")],
)


def remove_label_from_role(args) -> None:
    """Remove a label from a role."""
    # find the role
    path = f"/api/v1/hostpolicy/roles/{args.role}"
    res = get(path, ok404=True)
    if not res:
        cli_warning(f"Could not find a role with name {args.role!r}")
    role = res.json()
    # find the label
    labelpath = f"/api/v1/labels/name/{args.label}"
    res = get(labelpath, ok404=True)
    if not res:
        cli_warning(f"Could not find a label with name {args.label!r}")
    label = res.json()
    # check if the role has the label
    if label["id"] not in role["labels"]:
        cli_warning(f"The role {args.role!r} doesn't have the label {args.label!r}")
    # patch the role
    ar = role["labels"]
    ar.remove(label["id"])
    patch(path, use_json=True, params={"labels": ar})
    cli_info(f"Removed the label {args.label!r} from the role {args.role!r}.", print_msg=True)


policy.add_command(
    prog="label_remove",
    description="Remove a label from a role",
    callback=remove_label_from_role,
    flags=[Flag("label"), Flag("role")],
)
