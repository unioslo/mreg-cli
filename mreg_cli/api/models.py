"""Pydantic models for the mreg_cli package."""

import ipaddress
import re
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, root_validator, validator
from pydantic.types import StringConstraints

from mreg_cli.api.endpoints import Endpoint
from mreg_cli.log import cli_warning
from mreg_cli.outputmanager import OutputManager
from mreg_cli.utilities.api import delete, get, get_item_by_key_value, get_list, get_list_in, patch

IPAddressT = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# Sigh... Python 3.7 and earlier doesn't have Annotated, so we, well, cry.
if sys.version_info >= (3, 8):
    from typing import Annotated

    HostT = Annotated[str, StringConstraints(min_length=1, max_length=255)]
else:
    HostT = str

_mac_regex = re.compile(r"^([0-9A-Fa-f]{2}[.:-]){5}([0-9A-Fa-f]{2})$")


class FrozenModel(BaseModel):
    """Model for an immutable object."""

    def __setattr__(self, name: str, value: Any):
        """Raise an exception when trying to set an attribute."""
        raise AttributeError("Cannot set attribute on a frozen object")

    def __delattr__(self, name: str):
        """Raise an exception when trying to delete an attribute."""
        raise AttributeError("Cannot delete attribute on a frozen object")

    class Config:
        """Pydantic configuration.

        Set the class to frozen to make it immutable and thus hashable.
        """

        frozen = True


class FrozenModelWithTimestamps(FrozenModel):
    """Model with created_at and updated_at fields."""

    created_at: datetime
    updated_at: datetime

    def output_timestamps(self, padding: int = 14) -> None:
        """Output the created and updated timestamps to the console."""
        output_manager = OutputManager()
        output_manager.add_line(f"{'Created:':<{padding}}{self.created_at:%c}")
        output_manager.add_line(f"{'Updated:':<{padding}}{self.updated_at:%c}")


class WithHost(BaseModel):
    """Model for an object that has a host element."""

    host: int

    def resolve_host(self) -> Union["Host", None]:
        """Resolve the host ID to a Host object.

        Notes
        -----
            - This method will call the API to resolve the host ID to a Host object.
            - This assumes that there is a host attribute in the object.

        """
        data = get_item_by_key_value(Endpoint.Hosts, "id", str(self.host))

        if not data:
            return None

        return Host(**data)


class NameServer(FrozenModelWithTimestamps):
    """Model for representing a nameserver within a DNS zone."""

    id: int  # noqa: A003
    name: str
    ttl: Optional[int] = None


class Zone(FrozenModelWithTimestamps):
    """Model representing a DNS zone with various attributes and related nameservers."""

    id: int  # noqa: A003
    nameservers: List[NameServer]
    updated: bool
    primary_ns: str
    email: str
    serialno: int
    serialno_updated_at: datetime
    refresh: int
    retry: int
    expire: int
    soa_ttl: int
    default_ttl: int
    name: str


class Network(FrozenModelWithTimestamps):
    """Model for a network."""

    id: int  # noqa: A003
    excluded_ranges: List[str]
    network: str  # for now
    description: str
    vlan: Optional[int]
    dns_delegated: bool
    category: str
    location: str
    frozen: bool
    reserved: int

    def __hash__(self):
        """Return a hash of the network."""
        return hash((self.id, self.network))


class MACAddressField(FrozenModel):
    """Represents a MAC address."""

    address: str

    @validator("address", pre=True)
    def validate_and_format_mac(cls, v: str) -> str:
        """Validate and normalize MAC address to 'aa:bb:cc:dd:ee:ff' format.

        :param v: The input MAC address string.
        :raises ValueError: If the input does not match the expected MAC address pattern.
        :returns: The normalized MAC address.
        """
        # Validate input format
        if not _mac_regex.match(v):
            raise ValueError("Invalid MAC address format")

        # Normalize MAC address
        v = re.sub(r"[.:-]", "", v).lower()
        return ":".join(v[i : i + 2] for i in range(0, 12, 2))

    def __str__(self) -> str:
        """Return the MAC address as a string."""
        return self.address


class IPAddressField(FrozenModel):
    """Represents an IP address, automatically determines if it's IPv4 or IPv6."""

    address: IPAddressT

    @validator("address", pre=True)
    def parse_ip_address(cls, value: str) -> IPAddressT:
        """Parse and validate the IP address."""
        try:
            return ipaddress.ip_address(value)
        except ValueError as e:
            raise ValueError(f"Invalid IP address '{value}'.") from e

    def is_ipv4(self) -> bool:
        """Check if the IP address is IPv4."""
        return isinstance(self.address, ipaddress.IPv4Address)

    def is_ipv6(self) -> bool:
        """Check if the IP address is IPv6."""
        return isinstance(self.address, ipaddress.IPv6Address)

    def __str__(self) -> str:
        """Return the IP address as a string."""
        return str(self.address)

    def __hash__(self):
        """Return a hash of the IP address."""
        return hash(self.address)


class IPAddress(FrozenModelWithTimestamps, WithHost):
    """Represents an IP address with associated details."""

    id: int  # noqa: A003
    macaddress: Optional[MACAddressField] = None
    ipaddress: IPAddressField

    @validator("macaddress", pre=True, allow_reuse=True)
    def create_valid_macadress_or_none(cls, v: str):
        """Create macaddress or convert empty strings to None."""
        if v:
            return MACAddressField(address=v)

        return None

    @root_validator(pre=True)
    def convert_ip_address(cls, values: Any):
        """Convert ipaddress string to IPAddressField if necessary."""
        ip_address = values.get("ipaddress")
        if isinstance(ip_address, str):
            values["ipaddress"] = {"address": ip_address}
        return values

    def __str__(self):
        """Return the IP address as a string."""
        return self.ipaddress.__str__()

    def is_ipv4(self) -> bool:
        """Return True if the IP address is IPv4."""
        return self.ipaddress.is_ipv4()

    def is_ipv6(self) -> bool:
        """Return True if the IP address is IPv6."""
        return self.ipaddress.is_ipv6()

    def network(self) -> Network:
        """Return the network of the IP address."""
        data = get(Endpoint.NetworksByIP.with_id(str(self.ip())))
        return Network(**data.json())

    def vlan(self) -> Optional[int]:
        """Return the VLAN of the IP address."""
        return self.network().vlan

    def ip(self) -> IPAddressT:
        """Return the IP address."""
        return self.ipaddress.address

    def associate_mac(self, mac: Union[MACAddressField, str], force: bool = False) -> "IPAddress":
        """Associate a MAC address with the IP address.

        :param mac: The MAC address to associate.
        :param force: If True, force the association even if the IP address already has
                      a MAC address.

        :returns: A new IPAddress object with the updated MAC address.
        """
        if isinstance(mac, str):
            mac = MACAddressField(address=mac)

        if self.macaddress and not force:
            cli_warning(f"IP address {self.ipaddress} already has MAC address {self.macaddress}.")

        patch(Endpoint.Ipaddresses.with_id(self.id), macaddress=mac.address)
        return self.model_copy(update={"macaddress": mac})

    def output(self, len_ip: int, len_names: int, names: bool = False):
        """Output the IP address to the console."""
        ip = self.ipaddress.__str__()
        mac = self.macaddress if self.macaddress else "<not set>"
        name = str(self.host) if names else ""
        OutputManager().add_line(f"{name:<{len_names}}{ip:<{len_ip}}{mac}")

    @classmethod
    def output_multiple(cls, ips: List["IPAddress"], padding: int = 14, names: bool = False):
        """Output IP addresses to the console."""
        output_manager = OutputManager()
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
                output_manager.add_line(f"{record_type:<{len_names}}IP{' ' * (len_ip - 2)}MAC")
                for record in records:
                    record.output(len_ip=len_ip, len_names=len_names, names=names)

    def __hash__(self):
        """Return a hash of the IP address."""
        return hash((self.id, self.ipaddress.address, self.macaddress))


class HInfo(FrozenModelWithTimestamps, WithHost):
    """Represents a HINFO record."""

    cpu: str
    os: str

    def output(self, padding: int = 14):
        """Output the HINFO record to the console."""
        OutputManager().add_line(
            "{1:<{0}}cpu={2} os={3}".format(padding, "Hinfo:", self.cpu, self.os)
        )


class CNAME(FrozenModelWithTimestamps, WithHost):
    """Represents a CNAME record."""

    name: HostT
    ttl: Optional[int] = None
    zone: int

    def output(self, padding: int = 14) -> None:
        """Output the CNAME record to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        actual_host = self.resolve_host()
        host = actual_host.name if actual_host else "<Not found>"

        OutputManager().add_line(f"{'Cname:':<{padding}}{self.name} -> {host}")

    @classmethod
    def output_multiple(cls, cnames: List["CNAME"], padding: int = 14) -> None:
        """Output multiple CNAME records to the console.

        :param cnames: List of CNAME records to output.
        :param padding: Number of spaces for left-padding the output.
        """
        if not cnames:
            return

        for cname in cnames:
            cname.output(padding=padding)


class TXT(FrozenModelWithTimestamps):
    """Represents a TXT record."""

    txt: str
    host: int

    def output(self, padding: int = 14) -> None:
        """Output the TXT record to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        OutputManager().add_line(f"{'TXT:':<{padding}}{self.txt}")

    @classmethod
    def output_multiple(cls, txts: List["TXT"], padding: int = 14) -> None:
        """Output multiple TXT records to the console.

        :param txts: List of TXT records to output.
        :param padding: Number of spaces for left-padding the output.
        """
        if not txts:
            return

        for txt in txts:
            txt.output(padding=padding)


class MX(FrozenModelWithTimestamps, WithHost):
    """Represents a MX record."""

    mx: str
    priority: int
    host: int

    def output(self, padding: int = 14) -> None:
        """Output the MX record to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        len_pri = len("Priority")
        OutputManager().add_line(
            "{1:<{0}}{2:>{3}} {4}".format(padding, "", self.priority, len_pri, self.mx)
        )

    @classmethod
    def output_multiple(cls, mxs: List["MX"], padding: int = 14) -> None:
        """Output MX records to the console."""
        if not mxs:
            return

        OutputManager().add_line("{1:<{0}}{2} {3}".format(padding, "MX:", "Priority", "Server"))
        for mx in sorted(mxs, key=lambda i: i.priority):
            mx.output(padding=padding)


class NAPTR(FrozenModelWithTimestamps, WithHost):
    """Represents a NAPTR record."""

    id: int  # noqa: A003
    preference: int
    order: int
    flag: Optional[str]
    service: Optional[str]
    regex: Optional[str]
    replacement: str

    def output(self, padding: int = 14) -> None:
        """Output the NAPTR record to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        row_format = f"{{:<{padding}}}" * len(NAPTR.headers())
        OutputManager().add_line(
            row_format.format(
                "",
                self.preference,
                self.order,
                self.flag,
                self.service,
                self.regex or '""',
                self.replacement,
            )
        )

    @classmethod
    def headers(cls) -> List[str]:
        """Return the headers for the NAPTR record."""
        return [
            "NAPTRs:",
            "Preference",
            "Order",
            "Flag",
            "Service",
            "Regex",
            "Replacement",
        ]

    @classmethod
    def output_multiple(cls, naptrs: List["NAPTR"], padding: int = 14) -> None:
        """Output multiple NAPTR records to the console."""
        headers = cls.headers()
        row_format = f"{{:<{padding}}}" * len(headers)
        manager = OutputManager()
        if naptrs:
            manager.add_line(row_format.format(*headers))
            for naptr in naptrs:
                naptr.output(padding=padding)


class Srv(FrozenModelWithTimestamps, WithHost):
    """Represents a SRV record."""

    id: int  # noqa: A003
    name: str
    priority: int
    weight: int
    port: int
    ttl: Optional[int]
    zone: int

    def output(self, padding: int = 14, host_id_name_map: Optional[Dict[int, str]] = None) -> None:
        """Output the SRV record to the console.

        The output will include the record name, priority, weight, port,
        and the associated host name. Optionally uses a mapping of host IDs
        to host names to avoid repeated lookups.

        :param padding: Number of spaces for left-padding the output.
        :param host_names: Optional dictionary mapping host IDs to host names.
        """
        host_name = "<Not found>"
        if host_id_name_map and self.host in host_id_name_map:
            host_name = host_id_name_map[self.host]
        elif not host_id_name_map or self.host not in host_id_name_map:
            host = self.resolve_host()
            if host:
                host_name = host.name

        # Format the output string to include padding and center alignment
        # for priority, weight, and port.
        output_manager = OutputManager()
        format_str = "SRV: {:<{padding}} {:^6} {:^6} {:^6} {}"
        output_manager.add_line(
            format_str.format(
                self.name,
                str(self.priority),
                str(self.weight),
                str(self.port),
                host_name,
                padding=padding,
            )
        )

    @classmethod
    def output_multiple(cls, srvs: List["Srv"], padding: int = 14) -> None:
        """Output multiple SRV records.

        This method adjusts the padding dynamically based on the longest record name.

        :param srvs: List of Srv records to output.
        :param padding: Minimum number of spaces for left-padding the output.
        """
        if not srvs:
            return

        host_ids = {srv.host for srv in srvs}

        host_data = get_list_in(Endpoint.Hosts, "id", list(host_ids))
        hosts = [Host(**host) for host in host_data]

        host_id_name_map = {host.id: host.name for host in hosts}

        host_id_name_map.update(
            {host_id: host_id_name_map.get(host_id, "<Not found>") for host_id in host_ids}
        )

        padding = max((len(srv.name) for srv in srvs), default=padding)

        # Output each SRV record with the optimized host name lookup
        for srv in srvs:
            srv.output(padding=padding, host_id_name_map=host_id_name_map)


class PTR_override(FrozenModelWithTimestamps, WithHost):
    """Represents a PTR override record."""

    id: int  # noqa: A003
    host: int
    ipaddress: str  # For now, should be an IP address

    def output(self, padding: int = 14):
        """Output the PTR override record to the console.

        :param padding: Number of spaces for left-padding the output.
        """
        host = self.resolve_host()
        hostname = host.name if host else "<Not found>"

        OutputManager().add_line(f"{'PTR override:':<{padding}}{self.ipaddress} -> {hostname}")

    @classmethod
    def output_multiple(cls, ptrs: List["PTR_override"], padding: int = 14):
        """Output multiple PTR override records to the console.

        :param ptrs: List of PTR override records to output.
        :param padding: Number of spaces for left-padding the output.
        """
        if not ptrs:
            return

        for ptr in ptrs:
            ptr.output(padding=padding)


class Host(FrozenModelWithTimestamps):
    """Model for an individual host.

    This is the endpoint at /api/v1/hosts/<id>.
    """

    id: int  # noqa: A003
    name: HostT
    ipaddresses: List[IPAddress]
    cnames: List[CNAME] = []
    mxs: List[MX] = []
    txts: List[TXT] = []
    ptr_overrides: List[PTR_override] = []
    hinfo: Optional[HInfo] = None
    loc: Optional[str] = None
    bacnetid: Optional[str] = None
    contact: str
    ttl: Optional[int] = None
    comment: Optional[str] = None
    zone: Optional[int] = None

    @validator("comment", pre=True, allow_reuse=True)
    def empty_string_to_none(cls, v: str):
        """Convert empty strings to None."""
        return v or None

    def delete(self) -> bool:
        """Delete the host.

        :raises CliWarning: If the operation to delete the host fails.

        :returns: True if the host was deleted successfully, False otherwise.
        """
        # Note, we can't use .id as the identifier here, as the host name is used
        # in the endpoint URL...
        op = delete(Endpoint.Hosts.with_id(self.name))
        if not op:
            cli_warning(f"Failed to delete host {self.name}, operation failed.")

        return op.status_code >= 200 and op.status_code < 300

    def ipv4_addresses(self):
        """Return a list of IPv4 addresses."""
        return [ip for ip in self.ipaddresses if ip.is_ipv4()]

    def ipv6_addresses(self):
        """Return a list of IPv6 addresses."""
        return [ip for ip in self.ipaddresses if ip.is_ipv6()]

    def associate_mac_to_ip(
        self, mac: Union[MACAddressField, str], ip: Union[IPAddressField, str], force: bool = False
    ) -> "Host":
        """Associate a MAC address to an IP address.

        :param mac: The MAC address to associate.
        :param ip: The IP address to associate.

        :returns: A new Host object with the updated IP address.
        """
        if isinstance(mac, str):
            mac = MACAddressField(address=mac)

        if isinstance(ip, str):
            ip = IPAddressField(address=ipaddress.ip_address(ip))

        params = {
            "macaddress": mac.address,
            "ordering": "ipaddress",
        }

        data = get_list(Endpoint.Ipaddresses, params=params)
        ipadresses = [IPAddress(**ip) for ip in data]

        if ip in [ip.ipaddress for ip in ipadresses]:
            cli_warning(f"IP address {ip} already has MAC address {mac} associated.")

        if len(ipadresses) and not force:
            cli_warning(
                "mac {} already in use by: {}. Use force to add {} -> {} as well.".format(
                    mac, ipadresses, ip.address, mac
                )
            )

        ip_found_in_host = False
        new_ips: List[IPAddress] = []
        for myip in self.ipaddresses:
            current_ip = myip.model_copy()

            if myip.ipaddress.address == ip.address:
                current_ip = myip.associate_mac(mac, force=force)
                ip_found_in_host = True

            new_ips.append(current_ip)

        if not ip_found_in_host:
            cli_warning(f"IP address {ip} not found in host {self.name}.")

        return self.model_copy(update={"ipaddresses": new_ips})

    def networks(self) -> Dict[Network, List[IPAddress]]:
        """Return a dict of unique networks and a list of associated IP addresses for the host.

        :returns: A dictionary of networks and the associated IP addresses.
        """
        ret_dict: Dict[Network, List[IPAddress]] = {}

        for ip in self.ipaddresses:
            network = ip.network()
            if network not in ret_dict:
                ret_dict[network] = []

            ret_dict[network].append(ip)

        return ret_dict

    def vlans(self) -> Dict[int, List[IPAddress]]:
        """Return a dict of unique VLANs ID and a list of associated IP addresses for the host.

        IP addresses without a VLAN are assigned to VLAN 0.

        Note that this method will call self.networks() to determine the networks associated with
        the IP addresses. If you wish to report more details about what networks the IP addresses
        (ie, beyond simply the VLAN ID), use self.networks() and parse the VLAN from the network
        manually.

        :returns: A dictionary of VLAN ID and the associated IP addresses.
        """
        ret_dict: Dict[int, List[IPAddress]] = {}

        for network, ips in self.networks().items():
            vlan = network.vlan or 0
            if vlan not in ret_dict:
                ret_dict[vlan] = []

            ret_dict[vlan].extend(ips)

        return ret_dict

    # This would be greatly improved by having a proper error returned to avoid the need for
    # manually calling networks() or vlans() to determine the issue. One option is to use
    # a custom exception, or to return a tuple of (bool, str) where the str is the error message.
    def all_ips_on_same_vlan(self) -> bool:
        """Return True if all IP addresses are on the same VLAN.

        - If there are no IP addresses, return True.
        - If there is only one IP address, return True.
        - If there are multiple IP addresses and they are all on the same VLAN, return True.

        Note that this method will call self.vlans() to determine if all IP addresses are on the
        same VLAN, which in turn calls self.networks() to determine the networks associated with
        the IP addresses.

        If you wish to report more details about what VLANs the IP addresses are on, use
        self.vlans() or self.networks().

        :returns: True if all IP addresses are on the same VLAN, False otherwise.
        """
        vlans = self.vlans()
        if not vlans:
            return True

        if len(vlans) == 1:
            return True

        return False

    def naptrs(self) -> List[NAPTR]:
        """Return a list of NAPTR records."""
        naptrs = get_list(Endpoint.Naptrs, params={"host": self.id})
        return [NAPTR(**naptr) for naptr in naptrs]

    def srvs(self) -> List[Srv]:
        """Return a list of SRV records."""
        srvs = get_list(Endpoint.Srvs, params={"host": self.id})
        return [Srv(**srv) for srv in srvs]

    def output_host_info(self, names: bool = False):
        """Output host information to the console with padding."""
        padding = 14

        output_manager = OutputManager()
        output_manager.add_line(f"{'Name:':<{padding}}{self.name}")
        output_manager.add_line(f"{'Contact:':<{padding}}{self.contact}")

        if self.comment:
            output_manager.add_line(f"{'Comment:':<{padding}}{self.comment}")

        IPAddress.output_multiple(self.ipaddresses, padding=padding, names=names)
        PTR_override.output_multiple(self.ptr_overrides, padding=padding)

        output_manager.add_line("{1:<{0}}{2}".format(padding, "TTL:", self.ttl or "(Default)"))

        MX.output_multiple(self.mxs, padding=padding)

        if self.hinfo:
            self.hinfo.output(padding=padding)

        if self.loc:
            output_manager.add_line(f"{'Loc:':<{padding}}{self.loc}")

        CNAME.output_multiple(self.cnames, padding=padding)
        TXT.output_multiple(self.txts, padding=padding)
        Srv.output_multiple(self.srvs(), padding=padding)
        NAPTR.output_multiple(self.naptrs(), padding=padding)

        # output_hinfo(info["hinfo"])

        # if info["loc"]:
        #     output_loc(info["loc"])
        # for cname in info["cnames"]:
        #     output_cname(cname["name"], info["name"])
        # for txt in info["txts"]:
        #     output_txt(txt["txt"])
        # output_srv(host_id=info["id"])
        # output_naptr(info)
        # output_sshfp(info)
        # if "bacnetid" in info:
        #     output_bacnetid(info.get("bacnetid"))

        # policies = get_list("/api/v1/hostpolicy/roles/", params={"hosts__name": info["name"]})
        # output_policies([p["name"] for p in policies])

        # cli_info("printed host info for {}".format(info["name"]))

        self.output_timestamps()

    def __hash__(self):
        """Return a hash of the host."""
        return hash((self.id, self.name))


class HostList(FrozenModel):
    """Model for a list of hosts.

    This is the endpoint at /api/v1/hosts/.
    """

    results: List[Host]

    @validator("results", pre=True)
    def check_results(cls, v: List[Dict[str, str]]):
        """Check that the results are valid."""
        return v

    def __len__(self):
        """Return the number of results."""
        return len(self.results)

    def __getitem__(self, key: int) -> Host:
        """Get a result by index."""
        return self.results[key]

    def __str__(self):
        """Return a string representation of the results."""
        return str(self.results)

    def __repr__(self):
        """Return a string representation of the results."""
        return repr(self.results)

    def count(self):
        """Return the number of results."""
        return len(self.results)

    def output_host_list(self):
        """Output a list of hosts to the console."""
        if not self.results:
            cli_warning("No hosts found.")

        max_name = max_contact = 20
        for i in self.results:
            max_name = max(max_name, len(i.name))
            max_contact = max(max_contact, len(i.contact))

        def _format(name: str, contact: str, comment: str) -> None:
            OutputManager().add_line(
                "{0:<{1}} {2:<{3}} {4}".format(name, max_name, contact, max_contact, comment)
            )

        _format("Name", "Contact", "Comment")
        for i in self.results:
            _format(i.name, i.contact, i.comment or "")
