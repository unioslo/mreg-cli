"""Field formatting functions for the CLI.

These are typically utilities for formatting fields in a consistent way. The functions
shall queue the output directly to the OutputManager, and will not return anything.

Note that these functions *may* themselves require API calls to get additional data
related to the field or dataset being formatted.
"""

from typing import Any, Dict, Iterable, List, Optional, Union

from mreg_cli.log import cli_info, cli_warning
from mreg_cli.outputmanager import OutputManager
from mreg_cli.utilities.api import get_list
from mreg_cli.utilities.validators import is_valid_ipv4, is_valid_ipv6


def output_hinfo(hinfo: Union[Dict[str, Any], None], padding: int = 14) -> None:
    """Pretty given hinfo id."""
    if hinfo is None:
        return
    OutputManager().add_line(
        "{1:<{0}}cpu={2} os={3}".format(padding, "Hinfo:", hinfo["cpu"], hinfo["os"])
    )


def output_host_name(name: Union[str, None], padding: int = 14) -> None:
    """Pretty print given name."""
    if name is None:
        return
    OutputManager().add_line("{1:<{0}}{2}".format(padding, "Name:", name))


def output_contact(contact: Union[str, None], padding: int = 14) -> None:
    """Pretty print given contact."""
    if contact is None:
        return
    OutputManager().add_line("{1:<{0}}{2}".format(padding, "Contact:", contact))


def output_comment(comment: Union[str, None], padding: int = 14) -> None:
    """Pretty print given comment."""
    if comment is None:
        return
    OutputManager().add_line("{1:<{0}}{2}".format(padding, "Comment:", comment))


def output_ipaddresses(
    ipaddresses: Iterable[Dict[str, Any]], names: bool = False, padding: int = 14
) -> None:
    """Pretty print given ip addresses."""

    def _find_padding(lst: Iterable[Dict[str, Any]], attr: str):
        return max(padding, max([len(i[attr]) for i in lst]) + 1)

    manager = OutputManager()

    if not ipaddresses:
        return
    a_records = []
    aaaa_records = []
    len_ip = _find_padding(ipaddresses, "ipaddress")
    for record in ipaddresses:
        if is_valid_ipv4(record["ipaddress"]):
            a_records.append(record)
        elif is_valid_ipv6(record["ipaddress"]):
            aaaa_records.append(record)
    if names:
        len_names = _find_padding(ipaddresses, "name")
    else:
        len_names = padding
    for records, text in ((a_records, "A_Records"), (aaaa_records, "AAAA_Records")):
        if records:
            manager.add_line("{1:<{0}}{2:<{3}}  {4}".format(len_names, text, "IP", len_ip, "MAC"))
            for record in records:
                ip = record["ipaddress"]
                mac = record["macaddress"]
                if names:
                    name = record["name"]
                else:
                    name = ""
                manager.add_line(
                    "{1:<{0}}{2:<{3}}  {4}".format(
                        len_names,
                        name,
                        ip if ip else "<not set>",
                        len_ip,
                        mac if mac else "<not set>",
                    )
                )


def output_ttl(ttl: int, padding: int = 14) -> None:
    """Pretty print given ttl."""
    OutputManager().add_line("{1:<{0}}{2}".format(padding, "TTL:", ttl or "(Default)"))


def output_loc(loc: Union[Dict[str, Any], None], padding: int = 14) -> None:
    """Pretty print given loc."""
    if loc is None:
        return
    OutputManager().add_line("{1:<{0}}{2}".format(padding, "Loc:", loc["loc"]))


def output_cname(cname: str, host: str, padding: int = 14) -> None:
    """Pretty print given cname."""
    OutputManager().add_line("{1:<{0}}{2} -> {3}".format(padding, "Cname:", cname, host))


def output_mx(mxs: List[Dict[str, Any]], padding: int = 14) -> None:
    """Pretty print all MXs."""
    if not mxs:
        return
    len_pri = len("Priority")
    manager = OutputManager()
    manager.add_line("{1:<{0}}{2} {3}".format(padding, "MX:", "Priority", "Server"))
    for mx in sorted(mxs, key=lambda i: i["priority"]):
        manager.add_line(
            "{1:<{0}}{2:>{3}} {4}".format(padding, "", mx["priority"], len_pri, mx["mx"])
        )


def output_ptr(ip: str, host_name: str, padding: int = 14) -> None:
    """Pretty print given txt."""
    OutputManager().add_line("{1:<{0}}{2} -> {3}".format(padding, "PTR override:", ip, host_name))


def output_txt(txt: Union[str, None], padding: int = 14) -> None:
    """Pretty print given txt."""
    if txt is None:
        return
    OutputManager().add_line("{1:<{0}}{2}".format(padding, "TXT:", txt))


def output_bacnetid(bacnetid: Union[Dict[str, Any], None], padding: int = 14) -> None:
    """Pretty print given txt."""
    if bacnetid is None:
        return
    OutputManager().add_line("{1:<{0}}{2}".format(padding, "BACnet ID:", bacnetid["id"]))


def output_policies(policies: List[str], padding: int = 14) -> None:
    """Pretty print given policies.

    This follows the output policy of printing nothing if there are no policies.
    """
    if not policies:
        return
    OutputManager().add_line("{1:<{0}}{2}".format(padding, "Policies:", ", ".join(policies)))


def output_srv(srvs: Optional[List[Dict[str, Any]]] = None, host_id: Optional[str] = None) -> None:
    """Pretty print given srv."""
    assert srvs is not None or host_id is not None
    hostid2name = dict()
    host_ids = set()

    def print_srv(srv: Dict[str, Any], hostname: str, padding: int = 14) -> None:
        """Pretty print given srv."""
        OutputManager().add_line(
            "SRV: {1:<{0}} {2:^6} {3:^6} {4:^6} {5}".format(
                padding,
                srv["name"],
                srv["priority"],
                srv["weight"],
                srv["port"],
                hostname,
            )
        )

    if srvs is None:
        path = "/api/v1/srvs/"
        params = {
            "host": host_id,
        }
        srvs = get_list(path, params=params)

    if len(srvs) == 0:
        return

    padding = 0

    # The assert at the start of the method doesn't catch the None case,
    # so to make linters happy, we need to check for it explicitly here.
    if srvs is not None:
        for srv in srvs:
            if len(srv["name"]) > padding:
                padding = len(srv["name"])
            host_ids.add(str(srv["host"]))

    arg = ",".join(host_ids)
    hosts = get_list("/api/v1/hosts/", params={"id__in": arg})
    for host in hosts:
        hostid2name[host["id"]] = host["name"]

    prev_name = ""
    if srvs is not None:
        for srv in srvs:
            if prev_name == srv["name"]:
                srv["name"] = ""
            else:
                prev_name = srv["name"]
            print_srv(srv, hostid2name[srv["host"]], padding)


def output_naptr(info: Dict[str, str]) -> int:
    """Pretty print given naptr."""
    path = "/api/v1/naptrs/"
    params = {
        "host": info["id"],
    }
    naptrs = get_list(path, params=params)
    headers = (
        "NAPTRs:",
        "Preference",
        "Order",
        "Flag",
        "Service",
        "Regex",
        "Replacement",
    )
    row_format = "{:<14}" * len(headers)
    manager = OutputManager()
    if naptrs:
        manager.add_line(row_format.format(*headers))
        for naptr in naptrs:
            manager.add_line(
                row_format.format(
                    "",
                    naptr["preference"],
                    naptr["order"],
                    naptr["flag"],
                    naptr["service"],
                    naptr["regex"] or '""',
                    naptr["replacement"],
                )
            )
    return len(naptrs)


def output_sshfp(info: Dict[str, str]) -> int:
    """Show SSHFP records for the host."""
    path = "/api/v1/sshfps/"
    params = {
        "host": info["id"],
    }
    sshfps = get_list(path, params=params)
    headers = ("SSHFPs:", "Algorithm", "Type", "Fingerprint")
    row_format = "{:<14}" * len(headers)
    manager = OutputManager()
    if sshfps:
        manager.add_line(row_format.format(*headers))
        for sshfp in sshfps:
            manager.add_line(
                row_format.format(
                    "",
                    sshfp["algorithm"],
                    sshfp["hash_type"],
                    sshfp["fingerprint"],
                )
            )
    return len(sshfps)


def output_host_info(info: Dict[str, Any]) -> None:
    """Print all host info.

    :param info: Host info dict from API.
    """
    output_host_name(info["name"])
    output_contact(info["contact"])
    if info["comment"]:
        output_comment(info["comment"])
    output_ipaddresses(info["ipaddresses"])
    for ptr in info["ptr_overrides"]:
        output_ptr(ptr["ipaddress"], info["name"])
    output_ttl(info["ttl"])
    output_mx(info["mxs"])
    output_hinfo(info["hinfo"])
    if info["loc"]:
        output_loc(info["loc"])
    for cname in info["cnames"]:
        output_cname(cname["name"], info["name"])
    for txt in info["txts"]:
        output_txt(txt["txt"])
    output_srv(host_id=info["id"])
    output_naptr(info)
    output_sshfp(info)
    if "bacnetid" in info:
        output_bacnetid(info.get("bacnetid"))

    policies = get_list("/api/v1/hostpolicy/roles/", params={"hosts__name": info["name"]})
    output_policies([p["name"] for p in policies])

    cli_info("printed host info for {}".format(info["name"]))


def output_ip_info(ip: str) -> None:
    """Print all hosts which have a given IP. Also print out PTR override, if any.

    :param ip: IP address to search for.
    """
    path = "/api/v1/hosts/"
    params = {
        "ipaddresses__ipaddress": ip,
        "ordering": "name",
    }
    ip = ip.lower()
    hosts = get_list(path, params=params)
    ipaddresses = []
    ptrhost = None
    for info in hosts:
        for i in info["ipaddresses"]:
            if i["ipaddress"] == ip:
                i["name"] = info["name"]
                ipaddresses.append(i)
        for i in info["ptr_overrides"]:
            if i["ipaddress"] == ip:
                ptrhost = info["name"]

    output_ipaddresses(ipaddresses, names=True)
    if len(ipaddresses) > 1 and ptrhost is None:
        cli_warning(f"IP {ip} used by {len(ipaddresses)} hosts, but no PTR override")
    if ptrhost is None:
        path = "/api/v1/hosts/"
        params = {
            "ptr_overrides__ipaddress": ip,
        }
        hosts = get_list(path, params=params)
        if hosts:
            ptrhost = hosts[0]["name"]
        elif ipaddresses:
            ptrhost = "default"
    if not ipaddresses and ptrhost is None:
        cli_warning(f"Found no hosts or ptr override matching IP {ip}")
    output_ptr(ip, str(ptrhost))
