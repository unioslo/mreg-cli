"""Output utilities for mreg_cli models.

This module provides standalone functions for formatting and outputting
mreg_api model instances to the console. This separates presentation logic
from data models.

Usage:
    from mreg_cli.output import output_host, output_zone
    import mreg_api.models

    host = mreg_api.models.Host.get_by_name("myhost.example.com")
    output_host(host)
"""

from __future__ import annotations

from mreg_cli.output.base import (
    output_timestamps,
    output_ttl,
)
from mreg_cli.output.group import (
    output_hostgroup,
    output_hostgroup_members,
    output_hostgroups,
)
from mreg_cli.output.host import (
    output_bacnetids,
    output_cname,
    output_cnames,
    output_hinfo,
    output_host,
    output_host_cnames,
    output_host_ipaddresses,
    output_host_networks,
    output_host_roles,
    output_hostlist,
    output_hosts,
    output_ipaddress,
    output_ipaddresses,
    output_location,
    output_mx,
    output_mxs,
    output_naptr,
    output_naptrs,
    output_ptr_override,
    output_ptr_overrides,
    output_srv,
    output_srvs,
    output_sshfp,
    output_sshfps,
    output_txt,
    output_txts,
)
from mreg_cli.output.meta import (
    output_health_info,
    output_server_libraries,
    output_server_version,
    output_user_info,
    output_user_permissions,
)
from mreg_cli.output.network import (
    output_communities,
    output_community,
    output_network,
    output_network_excluded_ranges,
    output_network_policies,
    output_network_policy,
    output_network_policy_attribute,
    output_network_policy_attributes,
    output_network_unused_addresses,
    output_network_used_addresses,
    output_networks,
)
from mreg_cli.output.policy import (
    output_atom,
    output_atoms,
    output_atoms_lines,
    output_label,
    output_permission,
    output_permissions,
    output_role,
    output_role_atoms,
    output_role_hosts,
    output_roles,
    output_roles_table,
)
from mreg_cli.output.zone import (
    output_delegations,
    output_nameservers,
    output_zone,
    output_zones,
)

__all__ = [
    # Base
    "output_timestamps",
    "output_ttl",
    # Zone
    "output_zone",
    "output_zones",
    "output_nameservers",
    "output_delegations",
    # Host
    "output_host",
    "output_hosts",
    "output_hostlist",
    "output_ipaddress",
    "output_ipaddresses",
    "output_host_networks",
    "output_host_ipaddresses",
    "output_host_cnames",
    "output_host_roles",
    "output_cname",
    "output_cnames",
    "output_hinfo",
    "output_location",
    "output_txt",
    "output_txts",
    "output_mx",
    "output_mxs",
    "output_naptr",
    "output_naptrs",
    "output_srv",
    "output_srvs",
    "output_ptr_override",
    "output_ptr_overrides",
    "output_sshfp",
    "output_sshfps",
    "output_bacnetids",
    # Network
    "output_network",
    "output_networks",
    "output_network_unused_addresses",
    "output_network_used_addresses",
    "output_network_excluded_ranges",
    "output_community",
    "output_communities",
    "output_network_policy",
    "output_network_policies",
    "output_network_policy_attribute",
    "output_network_policy_attributes",
    # Policy
    "output_role",
    "output_roles",
    "output_roles_table",
    "output_role_hosts",
    "output_role_atoms",
    "output_atom",
    "output_atoms",
    "output_atoms_lines",
    "output_label",
    "output_permission",
    "output_permissions",
    # Group
    "output_hostgroup",
    "output_hostgroups",
    "output_hostgroup_members",
    # Meta
    "output_user_info",
    "output_user_permissions",
    "output_server_version",
    "output_server_libraries",
    "output_health_info",
]
