"""Host output functions."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal, Sequence

from mreg_cli.api.endpoints import Endpoint
from mreg_cli.exceptions import EntityNotFound
from mreg_cli.output.base import output_timestamps, output_ttl
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import IP_Version
from mreg_cli.utilities.api import get_list_in

if TYPE_CHECKING:
    import mreg_api.models


# -----------------------------------------------------------------------------
# Host output functions
# -----------------------------------------------------------------------------


def output_host(
    host: mreg_api.models.Host,
    names: bool = False,
    traverse_hostgroups: bool = False,
) -> None:
    """Output host information to the console.

    :param host: Host to output.
    :param names: If True, output the host names only.
    :param traverse_hostgroups: If True, traverse hostgroups and include them.
    """
    # Import here to avoid circular imports
    from mreg_cli.output.group import output_hostgroups
    from mreg_cli.output.policy import output_roles

    padding = 14

    manager = OutputManager()
    manager.add_line(f"{'Name:':<{padding}}{host.name}")
    manager.add_line(f"{'Contact:':<{padding}}{host.contact}")

    if host.comment:
        manager.add_line(f"{'Comment:':<{padding}}{host.comment}")

    output_host_networks(host)
    output_ptr_overrides(host.ptr_overrides, padding=padding)

    output_ttl(host, padding=padding)

    output_mxs(host.mxs, padding=padding)

    if host.hinfo:
        output_hinfo(host.hinfo, padding=padding)

    if host.loc:
        output_location(host.loc, padding=padding)

    output_host_cnames(host, padding=padding)

    output_txts(host.txts, padding=padding)
    output_srvs(host.srvs, padding=padding)
    output_naptrs(host.naptrs, padding=padding)
    output_sshfps(host.sshfps, padding=padding)

    if host.bacnetid is not None:  # This may be zero.
        manager.add_line(f"{'Bacnet ID:':<{padding}}{host.bacnetid}")

    output_roles(host.roles, padding=padding)

    if traverse_hostgroups:
        hostgroups = host.get_hostgroups(traverse=True)
    else:
        hostgroups = host.hostgroups
    output_hostgroups(hostgroups, padding=padding)

    output_timestamps(host)


def output_hosts(
    hosts: Sequence[mreg_api.models.Host],
    names: bool = False,
    traverse_hostgroups: bool = False,
) -> None:
    """Output multiple hosts to the console.

    :param hosts: List of Host objects to output.
    :param names: If True, output the host names only.
    :param traverse_hostgroups: If True, traverse hostgroups and include them.
    """
    for i, host in enumerate(hosts, start=1):
        output_host(host, names=names, traverse_hostgroups=traverse_hostgroups)
        if i != len(hosts):
            OutputManager().add_line("")


def output_hostlist(hostlist: mreg_api.models.HostList) -> None:
    """Output a list of hosts to the console.

    :param hostlist: HostList object containing hosts to output.
    :raises EntityNotFound: If no hosts are found.
    """
    if not hostlist.results:
        raise EntityNotFound("No hosts found.")

    max_name = max_contact = 20
    for i in hostlist.results:
        max_name = max(max_name, len(str(i.name)))
        max_contact = max(max_contact, max((len(c) for c in i.contact_emails), default=0))

    def _format(name: str, contact: str, comment: str) -> None:
        OutputManager().add_line(
            "{0:<{1}} {2:<{3}} {4}".format(name, max_name, contact, max_contact, comment)
        )

    _format("Name", "Contact", "Comment")
    for i in hostlist.results:
        _format(str(i.name), ", ".join(i.contact_emails), i.comment)


def output_host_networks(
    host: mreg_api.models.Host,
    padding: int = 14,
    only: Literal[4, 6] | None = None,
) -> None:
    """Output all A(AAA) records along with MAC address and network policy.

    :param host: Host whose networks to output.
    :param padding: Number of spaces for left-padding the output.
    :param only: If 4, only output IPv4; if 6, only output IPv6.
    """
    # Import here to avoid circular imports
    from mreg_cli.api.models import Community, IPAddress, Network

    networks = host.networks()
    if not networks:
        return

    manager = OutputManager()

    v4: list[tuple[mreg_api.models.Network, mreg_api.models.IPAddress]] = []
    v6: list[tuple[mreg_api.models.Network, mreg_api.models.IPAddress]] = []

    for network, ips in networks.items():
        network = Network.model_validate(network, from_attributes=True)
        for ip in ips:
            ip = IPAddress.model_validate(ip, from_attributes=True)
            if network.ip_network.version == 4:
                v4.append((network, ip))
            elif network.ip_network.version == 6:
                v6.append((network, ip))

    def output_a_records(
        nets: list[tuple[mreg_api.models.Network, mreg_api.models.IPAddress]],
        version: int,
    ) -> None:
        if not nets:
            return
        record_type = "A" if version == 4 else "AAAA"
        manager.add_line(f"{record_type}_Records:")
        data: list[dict[str, str]] = []

        headers: tuple[str, ...] = ("IP", "MAC")
        keys: tuple[str, ...] = ("ip", "mac")

        ip_to_community: dict[mreg_api.models.IPAddress, mreg_api.models.Community] = {}
        if host.communities:
            for com in host.communities:
                ip = host.get_ip_by_id(com.ipaddress)
                ip = IPAddress.model_validate(ip, from_attributes=True)

                if ip:
                    ip_to_community[ip] = Community.model_validate(
                        com.community, from_attributes=True
                    )

        if ip_to_community:
            for net, ip in nets:
                policy = ""
                if net.policy:
                    policy = net.policy.name
                d: dict[str, str] = {
                    "ip": str(ip.ipaddress),
                    "mac": ip.macaddress or "<not set>",
                    "policy": policy,
                    "community": "",
                }
                if ip in ip_to_community:
                    d["community"] = ip_to_community[ip].name
                    if ip_to_community[ip].global_name:
                        d["community"] += f" ({ip_to_community[ip].global_name})"

                data.append(d)

            headers = ("IP", "MAC", "Policy", "Community")
            keys = ("ip", "mac", "policy", "community")

        else:
            for _, ip in nets:
                d = {
                    "ip": str(ip.ipaddress),
                    "mac": ip.macaddress or "<not set>",
                }
                data.append(d)

        manager.add_formatted_table(
            headers=headers,
            keys=keys,
            data=data,
            indent=padding,
        )

    if only is None or only == 4:
        output_a_records(v4, 4)
    if only is None or only == 6:
        output_a_records(v6, 6)


def output_host_ipaddresses(
    host: mreg_api.models.Host,
    padding: int = 14,
    names: bool = False,
    only: IP_Version | None = None,
) -> None:
    """Output the IP addresses for a host.

    :param host: Host whose IP addresses to output.
    :param padding: Number of spaces for left-padding the output.
    :param names: If True, include host names.
    :param only: If 4 or 6, only output that IP version.
    """
    if not host.ipaddresses:
        return

    if only and only == 4:
        ips = [ip for ip in host.ipaddresses if ip.is_ipv4()]
        output_ipaddresses(ips, padding=padding, names=names)
    elif only and only == 6:
        ips = [ip for ip in host.ipaddresses if ip.is_ipv6()]
        output_ipaddresses(ips, padding=padding, names=names)
    else:
        output_ipaddresses(host.ipaddresses, padding=padding, names=names)


def output_host_cnames(host: mreg_api.models.Host, padding: int = 14) -> None:
    """Output the CNAME records for a host.

    :param host: Host whose CNAMEs to output.
    :param padding: Number of spaces for left-padding the output.
    """
    if not host.cnames:
        return
    output_cnames(host.cnames, host=host, padding=padding)


def output_host_roles(host: mreg_api.models.Host, padding: int = 14) -> None:
    """Output the roles for a host.

    :param host: Host whose roles to output.
    :param padding: Number of spaces for left-padding the output.
    """
    roles = host.roles
    manager = OutputManager()
    if not roles:
        manager.add_line(f"Host {host.name} has no roles")
    else:
        manager.add_line(f"Roles for {host.name}:")
        for role in roles:
            manager.add_line(f"  {role}")


# -----------------------------------------------------------------------------
# IP Address output functions
# -----------------------------------------------------------------------------


def output_ipaddress(
    ip: mreg_api.models.IPAddress,
    len_ip: int,
    len_names: int,
    names: bool = False,
) -> None:
    """Output a single IP address.

    :param ip: IPAddress to output.
    :param len_ip: Width for the IP address column.
    :param len_names: Width for the names column.
    :param names: If True, resolve and display host names.
    """
    # Import here to avoid circular imports
    import mreg_api.models

    ip_str = str(ip.ipaddress)
    mac = ip.macaddress if ip.macaddress else "<not set>"

    name = ""
    if names:
        host = mreg_api.models.Host.get_by_id(ip.host)
        name = host.name if host else "<Not found>"

    OutputManager().add_line(f"{name:<{len_names}}{ip_str:<{len_ip}}{mac}")


def output_ipaddresses(
    ips: Sequence[mreg_api.models.IPAddress],
    padding: int = 14,
    names: bool = False,
) -> None:
    """Output multiple IP addresses.

    :param ips: List of IPAddress objects to output.
    :param padding: Minimum width for columns.
    :param names: If True, resolve and display host names.
    """
    if not ips:
        return

    manager = OutputManager()
    len_ip = max(padding, max([len(str(ip.ipaddress)) for ip in ips], default=0) + 2)

    # This seems completely broken, we need to look up all the hosts and get their names.
    # This again requires a fetch_hosts() call that takes a series of identifiers using
    # id__in.
    len_names = (
        padding
        if not names
        else max(padding, max([len(str(ip.host)) for ip in ips], default=0) + 2)
    )

    # Separate and output A and AAAA records
    for record_type, records in (
        ("A_Records", [ip for ip in ips if ip.is_ipv4()]),
        ("AAAA_Records", [ip for ip in ips if ip.is_ipv6()]),
    ):
        if records:
            manager.add_line(f"{record_type:<{len_names}}IP{' ' * (len_ip - 2)}MAC")
            for record in records:
                output_ipaddress(record, len_ip=len_ip, len_names=len_names, names=names)


# -----------------------------------------------------------------------------
# HInfo output function
# -----------------------------------------------------------------------------


def output_hinfo(hinfo: mreg_api.models.HInfo, padding: int = 14) -> None:
    """Output a HINFO record.

    :param hinfo: HInfo to output.
    :param padding: Number of spaces for left-padding the output.
    """
    OutputManager().add_line(f"{'Hinfo:':<{padding}}cpu={hinfo.cpu} os={hinfo.os}")


# -----------------------------------------------------------------------------
# CNAME output functions
# -----------------------------------------------------------------------------


def output_cname(
    cname: mreg_api.models.CNAME,
    host: mreg_api.models.Host | None = None,
    padding: int = 14,
) -> None:
    """Output a CNAME record.

    :param cname: CNAME to output.
    :param host: Host the CNAME points to. Attempts to resolve if not provided.
    :param padding: Number of spaces for left-padding the output.
    """
    if host:
        hostname = host.name
    elif actual_host := cname.resolve_host():
        hostname = actual_host.name
    else:
        hostname = "<Not found>"
    OutputManager().add_line(f"{'Cname:':<{padding}}{cname.name} -> {hostname}")


def output_cnames(
    cnames: Sequence[mreg_api.models.CNAME],
    host: mreg_api.models.Host | None = None,
    padding: int = 14,
) -> None:
    """Output multiple CNAME records.

    :param cnames: List of CNAMEs to output.
    :param host: Host the CNAMEs point to. Attempts to resolve if not provided.
    :param padding: Number of spaces for left-padding the output.
    """
    for cname in cnames:
        output_cname(cname, host=host, padding=padding)


# -----------------------------------------------------------------------------
# TXT output functions
# -----------------------------------------------------------------------------


def output_txt(txt: mreg_api.models.TXT, padding: int = 14) -> None:
    """Output a TXT record.

    :param txt: TXT record to output.
    :param padding: Number of spaces for left-padding the output.
    """
    OutputManager().add_line(f"{'TXT:':<{padding}}{txt.txt}")


def output_txts(txts: Sequence[mreg_api.models.TXT], padding: int = 14) -> None:
    """Output multiple TXT records.

    :param txts: List of TXT records to output.
    :param padding: Number of spaces for left-padding the output.
    """
    for txt in txts:
        output_txt(txt, padding=padding)


# -----------------------------------------------------------------------------
# MX output functions
# -----------------------------------------------------------------------------


def output_mx(mx: mreg_api.models.MX, padding: int = 14) -> None:
    """Output an MX record.

    :param mx: MX record to output.
    :param padding: Number of spaces for left-padding the output.
    """
    len_pri = len("Priority")
    OutputManager().add_line(f"{'':<{padding}}{mx.priority:>{len_pri}} {mx.mx}")


def output_mxs(mxs: Sequence[mreg_api.models.MX], padding: int = 14) -> None:
    """Output multiple MX records.

    :param mxs: List of MX records to output.
    :param padding: Number of spaces for left-padding the output.
    """
    if not mxs:
        return

    OutputManager().add_line(f"{'MX:':<{padding}}Priority Server")
    for mx in sorted(mxs, key=lambda i: i.priority):
        output_mx(mx, padding=padding)


# -----------------------------------------------------------------------------
# NAPTR output functions
# -----------------------------------------------------------------------------


def naptr_headers() -> list[str]:
    """Return the headers for NAPTR records."""
    return [
        "NAPTRs:",
        "Preference",
        "Order",
        "Flag",
        "Service",
        "Regex",
        "Replacement",
    ]


def output_naptr(naptr: mreg_api.models.NAPTR, padding: int = 14) -> None:
    """Output a NAPTR record.

    :param naptr: NAPTR record to output.
    :param padding: Number of spaces for left-padding the output.
    """
    row_format = f"{{:<{padding}}}" * len(naptr_headers())
    OutputManager().add_line(
        row_format.format(
            "",
            naptr.preference,
            naptr.order,
            naptr.flag,
            naptr.service,
            naptr.regex or '""',
            naptr.replacement,
        )
    )


def output_naptrs(naptrs: Sequence[mreg_api.models.NAPTR], padding: int = 14) -> None:
    """Output multiple NAPTR records.

    :param naptrs: List of NAPTR records to output.
    :param padding: Number of spaces for left-padding the output.
    """
    if not naptrs:
        return

    headers = naptr_headers()
    row_format = f"{{:<{padding}}}" * len(headers)
    manager = OutputManager()
    manager.add_line(row_format.format(*headers))
    for naptr in naptrs:
        output_naptr(naptr, padding=padding)


# -----------------------------------------------------------------------------
# SRV output functions
# -----------------------------------------------------------------------------


def output_srv(
    srv: mreg_api.models.Srv,
    padding: int = 14,
    host_id_name_map: dict[int, str] | None = None,
) -> None:
    """Output a SRV record.

    :param srv: SRV record to output.
    :param padding: Number of spaces for left-padding the output.
    :param host_id_name_map: Optional mapping of host IDs to names.
    """
    host_name = "<Not found>"
    if host_id_name_map and srv.host in host_id_name_map:
        host_name = host_id_name_map[srv.host]
    elif not host_id_name_map or srv.host not in host_id_name_map:
        host = srv.resolve_host()
        if host:
            host_name = host.name

    # Format the output string to include padding and center alignment
    # for priority, weight, and port.
    format_str = "SRV: {:<{padding}} {:^6} {:^6} {:^6} {}"
    OutputManager().add_line(
        format_str.format(
            srv.name,
            str(srv.priority),
            str(srv.weight),
            str(srv.port),
            host_name,
            padding=padding,
        )
    )


def output_srvs(srvs: Sequence[mreg_api.models.Srv], padding: int = 14) -> None:
    """Output multiple SRV records.

    :param srvs: List of SRV records to output.
    :param padding: Minimum number of spaces for left-padding the output.
    """
    if not srvs:
        return

    # Import here to avoid circular imports
    from mreg_cli.api.models import Host

    host_ids = {srv.host for srv in srvs}

    # FIXME: refactor to not require Endpoint! API library should handle this
    host_data = get_list_in(Endpoint.Hosts, "id", list(host_ids))
    hosts = [Host.model_validate(host) for host in host_data]

    host_id_name_map = {host.id: str(host.name) for host in hosts}

    host_id_name_map.update(
        {host_id: host_id_name_map.get(host_id, "<Not found>") for host_id in host_ids}
    )

    padding = max((len(srv.name) for srv in srvs), default=padding)

    # Output each SRV record with the optimized host name lookup
    for srv in srvs:
        output_srv(srv, padding=padding, host_id_name_map=host_id_name_map)


# -----------------------------------------------------------------------------
# PTR override output functions
# -----------------------------------------------------------------------------


def output_ptr_override(ptr: mreg_api.models.PTR_override, padding: int = 14) -> None:
    """Output a PTR override record.

    :param ptr: PTR override to output.
    :param padding: Number of spaces for left-padding the output.
    """
    host = ptr.resolve_host()
    hostname = host.name if host else "<Not found>"
    OutputManager().add_line(f"{'PTR override:':<{padding}}{ptr.ipaddress} -> {hostname}")


def output_ptr_overrides(
    ptrs: Sequence[mreg_api.models.PTR_override],
    padding: int = 14,
) -> None:
    """Output multiple PTR override records.

    :param ptrs: List of PTR overrides to output.
    :param padding: Number of spaces for left-padding the output.
    """
    if not ptrs:
        return

    for ptr in ptrs:
        output_ptr_override(ptr, padding=padding)


# -----------------------------------------------------------------------------
# SSHFP output functions
# -----------------------------------------------------------------------------


def sshfp_headers() -> list[str]:
    """Return the headers for SSHFP records."""
    return ["SSHFPs:", "Algorithm", "Hash Type", "Fingerprint"]


def output_sshfp(sshfp: mreg_api.models.SSHFP, padding: int = 14) -> None:
    """Output an SSHFP record.

    :param sshfp: SSHFP record to output.
    :param padding: Number of spaces for left-padding the output.
    """
    row_format = f"{{:<{padding}}}" * len(sshfp_headers())
    OutputManager().add_line(
        row_format.format("", sshfp.algorithm, sshfp.hash_type, sshfp.fingerprint)
    )


def output_sshfps(sshfps: Sequence[mreg_api.models.SSHFP], padding: int = 14) -> None:
    """Output multiple SSHFP records.

    :param sshfps: List of SSHFP records to output.
    :param padding: Number of spaces for left-padding the output.
    """
    if not sshfps:
        return

    headers = sshfp_headers()
    row_format = f"{{:<{padding}}}" * len(headers)
    manager = OutputManager()
    manager.add_line(row_format.format(*headers))
    for sshfp in sshfps:
        output_sshfp(sshfp, padding=padding)


# -----------------------------------------------------------------------------
# BacnetID output function
# -----------------------------------------------------------------------------


def output_bacnetids(bacnetids: Sequence[mreg_api.models.BacnetID]) -> None:
    """Output multiple Bacnet ID records.

    :param bacnetids: List of Bacnet IDs to output.
    """
    if not bacnetids:
        return

    OutputManager().add_formatted_table(("ID", "Hostname"), ("id", "hostname"), bacnetids)


# -----------------------------------------------------------------------------
# Location output function
# -----------------------------------------------------------------------------


def output_location(loc: mreg_api.models.Location, padding: int = 14) -> None:
    """Output a LOC record.

    :param loc: Location to output.
    :param padding: Number of spaces for left-padding the output.
    """
    OutputManager().add_line(f"{'LOC:':<{padding}}{loc.loc}")
