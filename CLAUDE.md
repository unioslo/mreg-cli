# mreg-cli Architecture

## Overview

This CLI uses `mreg_api` for data models and API operations, with presentation logic handled by standalone output functions in `mreg_cli.output`.

### Module Structure

```text
mreg_cli/
├── output/               # Presentation logic
│   ├── __init__.py       # Re-exports all output functions
│   ├── base.py           # Shared utilities (timestamps, TTL)
│   ├── zone.py           # Zone, delegation, nameserver output
│   ├── host.py           # Host, IP, CNAME, TXT, MX, SRV, etc.
│   ├── network.py        # Network, community, policy output
│   ├── policy.py         # Role, atom, label, permission output
│   ├── group.py          # HostGroup output
│   └── meta.py           # UserInfo, ServerVersion, HealthInfo
│
├── commands/             # Command handlers (use mreg_api.models + mreg_cli.output)
│   └── ...
│
├── exceptions.py         # CLI exception classes and handling functions
└── outputmanager.py      # Low-level output formatting
```

## Usage Examples

Commands use `mreg_api.models` for data operations and `mreg_cli.output` for presentation:

```python
# mreg_cli/commands/zone.py
from mreg_api.models import Zone
from mreg_cli.output import output_zone

def zone_info(args):
    zone = Zone.get_zone_or_raise(args.name)
    output_zone(zone)  # Standalone function
```

<details>
<summary><strong>Output Function Reference</strong></summary>

### Zone (`mreg_cli.output.zone`)

- `output_zone(zone, padding=20)` - Single zone
- `output_zones(zones)` - List of zones
- `output_nameservers(nameservers, padding=20)` - Zone nameservers
- `output_delegations(zone, padding=20)` - Zone delegations

### Host (`mreg_cli.output.host`)

- `output_host(host, names=False, traverse_hostgroups=False)` - Single host
- `output_hosts(hosts, names=False, traverse_hostgroups=False)` - Multiple hosts
- `output_hostlist(hostlist)` - HostList result
- `output_ipaddresses(ips, padding=14, names=False)` - IP addresses
- `output_cnames(cnames, host=None, padding=14)` - CNAME records
- `output_mxs(mxs, padding=14)` - MX records
- `output_txts(txts, padding=14)` - TXT records
- `output_srvs(srvs, padding=14)` - SRV records
- `output_naptrs(naptrs, padding=14)` - NAPTR records
- `output_sshfps(sshfps, padding=14)` - SSHFP records
- `output_ptr_overrides(ptrs, padding=14)` - PTR overrides
- `output_hinfo(hinfo, padding=14)` - HINFO record
- `output_location(loc, padding=14)` - LOC record
- `output_bacnetids(bacnetids)` - BACnet IDs

### Network (`mreg_cli.output.network`)

- `output_network(network, padding=25)` - Single network
- `output_networks(networks, padding=25)` - Multiple networks
- `output_unused_addresses(network, padding=25)` - Unused IPs
- `output_used_addresses(network, padding=46)` - Used IPs with hosts
- `output_excluded_ranges(excluded_ranges, padding=32)` - Excluded ranges
- `output_community(community, padding=14, show_hosts=True)` - Single community
- `output_communities(communities, padding=14, show_hosts=True, sort=NAME)` - Multiple communities
- `output_network_policy(policy)` - Network policy
- `output_network_policy_attributes(attributes, padding=20)` - Policy attributes

### Policy (`mreg_cli.output.policy`)

- `output_role(role, padding=14)` - Single role
- `output_roles(roles, padding=14)` - Multiple roles (single line)
- `output_roles_table(roles, padding=14)` - Roles as table
- `output_role_hosts(role, padding=14, exclude_roles=None)` - Role's hosts
- `output_role_atoms(role, padding=14)` - Role's atoms
- `output_atom(atom, padding=14)` - Single atom
- `output_atoms(atoms, padding=14)` - Multiple atoms (single line)
- `output_atoms_lines(atoms, padding=20)` - Atoms (one per line)
- `output_label(label, padding=14)` - Label with roles/permissions
- `output_permissions(permissions, indent=4)` - Permissions table

### Group (`mreg_cli.output.group`)

- `output_hostgroup(hostgroup, padding=14)` - Single hostgroup
- `output_hostgroups(hostgroups, padding=14, multiline=False)` - Multiple hostgroups
- `output_hostgroup_members(hostgroup, expand=False)` - Group members

### Meta (`mreg_cli.output.meta`)

- `output_user_info(user, django=False)` - User information
- `output_user_permissions(permissions)` - User permissions
- `output_server_version(version)` - Server version
- `output_server_libraries(libraries, indent=4)` - Server libraries
- `output_health_info(health)` - Health information

### Base (`mreg_cli.output.base`)

- `output_timestamps(obj, padding=14)` - Created/updated timestamps
- `output_ttl(obj, label="TTL", field="ttl", padding=14)` - TTL value

</details>

## Known Issues

1. **Circular imports**: Some functions use local imports to avoid circular dependencies between output modules.

2. **Type protocol mismatches**: `Role` and `Atom` have `created_at` as computed properties rather than direct fields, causing protocol mismatches with `HasTimestamps`.

## Exception Handling

Exception handling uses standalone functions in `mreg_cli.exceptions`.
This allows uniform handling of exceptions from both `mreg_cli` and `mreg_api`.

### Exception Classes

Exception classes in `mreg_cli.exceptions` are pure data containers with no output methods:

```text
CliException (base)
├── CliError (non-recoverable errors, displayed in red)
│   ├── CreateError, PatchError, DeleteError, GetError
│   ├── InternalError, FileError, ValidationError, LoginFailedError
└── CliWarning (recoverable, displayed in italics)
    ├── APIError (has response attribute), UnexpectedDataError
    ├── EntityNotFound, EntityAlreadyExists, MultipleEntitiesFound
    ├── TooManyResults, NoHistoryFound, ForceMissing
    └── IPNetworkWarning and subclasses
```

### Exception Handling Locations

- `mreg_cli/cli.py` - Main command parsing catches and handles exceptions
- `mreg_cli/main.py` - Entry point handles login and REPL exceptions
- `mreg_cli/utilities/api.py` - Authentication-related exception handling

## Future Work

### Caching

The cache code was copied to `mreg_api` but has not been implemented in that module. Implementing caching should be the **last priority** once the final API design of both packages is clear.
