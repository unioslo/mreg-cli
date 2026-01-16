# Refactoring: Separating Presentation from Data Models

## Background

The API code from this project was extracted and moved to a separate package called `mreg_api`. To minimize code changes, classes in `mreg_cli` were modified to inherit from corresponding `mreg_api` classes. This inheritance-based approach has several problems:

1. **Return type confusion**: Class methods like `Zone.get_zone()` return `mreg_api` instances, but `mreg_cli` needs instances with output methods.

2. **Field override burden**: Composed fields (e.g., `Zone.nameservers`) must be redefined in every subclass to use `mreg_cli` types instead of `mreg_api` types.

3. **Mixin antipatterns**: `TimestampMixin` is defined as a `BaseModel` with duplicate datetime fields just to satisfy type checking.

4. **Type ambiguity**: It's unclear whether code returns `mreg_api` or `mreg_cli` instances without careful inspection.

## Solution: Standalone Output Functions

The chosen solution separates presentation logic from data models entirely:

- **Data/API operations**: Use `mreg_api.models` directly
- **Presentation/Output**: Use standalone functions in `mreg_cli.output`

This eliminates the need for `mreg_cli` model subclasses in most cases.

## Target Module Structure

After the refactoring is complete, `mreg_cli/api/` should be removed entirely. Commands will use `mreg_api.models` directly for data operations.

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
└── outputmanager.py      # Low-level output formatting
```

## Migration Status

### Completed

- [x] Created `mreg_cli/output/` package with all output functions
- [x] Functions typed to accept `mreg_api.models` types
- [x] Extracted output logic from model classes to standalone functions

### Pending

- [ ] Update command handlers to use `mreg_cli.output` functions
- [ ] Update command handlers to use `mreg_api.models` directly
- [ ] Remove `mreg_cli/api/` module entirely

## Usage Examples

### Before (inheritance-based)

```python
# mreg_cli/commands/zone.py
from mreg_cli.api.models import Zone

def zone_info(args):
    zone = Zone.get_zone_or_raise(args.name)
    zone.output()  # Method on model
```

### After (standalone functions)

```python
# mreg_cli/commands/zone.py
from mreg_api.models import Zone
from mreg_cli.output import output_zone

def zone_info(args):
    zone = Zone.get_zone_or_raise(args.name)
    output_zone(zone)  # Standalone function
```

## Output Function Reference

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

## Known Issues

1. **Circular imports**: Some functions use local imports to avoid circular dependencies between output modules.

2. **Type protocol mismatches**: `Role` and `Atom` have `created_at` as computed properties rather than direct fields, causing protocol mismatches with `HasTimestamps`.

3. **Temporary model imports**: Some functions still import from `mreg_cli.api.models` for model validation during the transition period.
