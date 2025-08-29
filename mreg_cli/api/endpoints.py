"""API endpoints for mreg."""

from __future__ import annotations

from enum import Enum
from typing import Literal
from urllib.parse import quote, urljoin


class Endpoint(str, Enum):
    """API endpoints."""

    Hosts = "/api/v1/hosts/"
    Ipaddresses = "/api/v1/ipaddresses/"
    Naptrs = "/api/v1/naptrs/"
    Srvs = "/api/v1/srvs/"
    Hinfos = "/api/v1/hinfos/"
    Cnames = "/api/v1/cnames/"
    Sshfps = "/api/v1/sshfps/"
    Zones = "/api/v1/zones/"
    History = "/api/v1/history/"
    Txts = "/api/v1/txts/"
    PTR_overrides = "/api/v1/ptroverrides/"
    Locs = "/api/v1/locs/"
    Mxs = "/api/v1/mxs/"
    NAPTRs = "/api/v1/naptrs/"
    Nameservers = "/api/v1/nameservers/"

    HostGroups = "/api/v1/hostgroups/"
    HostGroupsAddHostGroups = "/api/v1/hostgroups/{}/groups/"
    HostGroupsRemoveHostGroups = "/api/v1/hostgroups/{}/groups/{}"
    HostGroupsAddHosts = "/api/v1/hostgroups/{}/hosts/"
    HostGroupsRemoveHosts = "/api/v1/hostgroups/{}/hosts/{}"
    HostGroupsAddOwner = "/api/v1/hostgroups/{}/owners/"
    HostGroupsRemoveOwner = "/api/v1/hostgroups/{}/owners/{}"

    BacnetID = "/api/v1/bacnet/ids/"

    Labels = "/api/v1/labels/"
    LabelsByName = "/api/v1/labels/name/"

    Networks = "/api/v1/networks/"
    NetworksByIP = "/api/v1/networks/ip/"
    NetworksUsedCount = "/api/v1/networks/{}/used_count"
    NetworksUsedList = "/api/v1/networks/{}/used_list"
    NetworksUnusedCount = "/api/v1/networks/{}/unused_count"
    NetworksUnusedList = "/api/v1/networks/{}/unused_list"
    NetworksFirstUnused = "/api/v1/networks/{}/first_unused"
    NetworksReservedList = "/api/v1/networks/{}/reserved_list"
    NetworksUsedHostList = "/api/v1/networks/{}/used_host_list"
    NetworksPTROverrideHostList = "/api/v1/networks/{}/ptroverride_host_list"
    NetworksAddExcludedRanges = "/api/v1/networks/{}/excluded_ranges/"
    NetworksRemoveExcludedRanges = "/api/v1/networks/{}/excluded_ranges/{}"

    # Network policies, attributes, and communities
    NetworkCommunities = "/api/v1/networks/{}/communities/"
    NetworkCommunity = "/api/v1/networks/{}/communities/{}"
    NetworkCommunityHosts = "/api/v1/networks/{}/communities/{}/hosts/"
    NetworkCommunityHost = "/api/v1/networks/{}/communities/{}/hosts/{}"
    NetworkPolicies = "/api/v1/networkpolicies/"
    NetworkPolicyAttributes = "/api/v1/networkpolicyattributes/"

    HostPolicyRoles = "/api/v1/hostpolicy/roles/"
    HostPolicyRolesAddAtom = "/api/v1/hostpolicy/roles/{}/atoms/"
    HostPolicyRolesRemoveAtom = "/api/v1/hostpolicy/roles/{}/atoms/{}"
    HostPolicyRolesAddHost = "/api/v1/hostpolicy/roles/{}/hosts/"
    HostPolicyRolesRemoveHost = "/api/v1/hostpolicy/roles/{}/hosts/{}"
    HostPolicyAtoms = "/api/v1/hostpolicy/atoms/"

    PermissionNetgroupRegex = "/api/v1/permissions/netgroupregex/"

    ForwardZones = f"{Zones}forward/"
    ReverseZones = f"{Zones}reverse/"

    # NOTE: Delegations endpoints MUST have a trailing slash
    ForwardZonesDelegations = f"{ForwardZones}{{}}/delegations/"
    ReverseZonesDelegations = f"{ReverseZones}{{}}/delegations/"

    ForwardZonesDelegationsZone = f"{ForwardZones}{{}}/delegations/{{}}"
    ReverseZonesDelegationsZone = f"{ReverseZones}{{}}/delegations/{{}}"

    # NOTE: Nameservers endpoints must NOT have a trailing slash
    ForwardZonesNameservers = f"{ForwardZones}{{}}/nameservers"
    ReverseZonesNameservers = f"{ReverseZones}{{}}/nameservers"

    ForwardZoneForHost = f"{ForwardZones}hostname/"

    TokenIsValid = "/api/token-is-valid/"

    MetaUser = "/api/meta/user"
    MetaVersion = "/api/meta/version"
    MetaLibraries = "/api/meta/libraries"

    HealthHeartbeat = "/api/meta/health/heartbeat"
    HealthLDAP = "/api/meta/health/ldap"

    def __str__(self):
        """Prevent direct usage without parameters where needed."""
        if "{}" in self.value:
            raise ValueError(f"Endpoint {self.name} requires parameters. Use `with_params`.")
        return self.value

    def requires_search_for_id(self) -> bool:
        """Return True if this endpoint requires a search for an ID."""
        return self.external_id_field() != "id"

    def external_id_field(self) -> Literal["id", "name", "network", "host"]:
        """Return the name of the field that holds the external ID."""
        if self in (
            Endpoint.Hosts,
            Endpoint.HostGroups,
            Endpoint.Cnames,
            Endpoint.ForwardZones,
            Endpoint.ReverseZones,
            Endpoint.ForwardZonesDelegations,
            Endpoint.ReverseZonesDelegations,
            Endpoint.HostPolicyRoles,
            Endpoint.HostPolicyAtoms,
            Endpoint.Nameservers,
        ):
            return "name"
        if self in (Endpoint.Networks,):
            return "network"
        if self in (Endpoint.Hinfos, Endpoint.Locs):
            return "host"
        return "id"

    def with_id(self, identity: str | int) -> str:
        """Return the endpoint with an ID."""
        id_field = quote(str(identity))
        return urljoin(self.value, id_field)

    def with_params(self, *params: str | int) -> str:
        """Construct and return an endpoint URL by inserting parameters.

        :param params: A sequence of parameters to be inserted into the URL.
        :raises ValueError: If the number of provided parameters does not match the
                            number of placeholders.
        :returns: A fully constructed endpoint URL with parameters.
        """
        placeholders_count = self.value.count("{}")
        if placeholders_count != len(params):
            raise ValueError(
                f"{self.name} endpoint expects {placeholders_count} parameters, got {len(params)}."
            )
        encoded_params = (quote(str(param)) for param in params)
        return self.value.format(*encoded_params)
