"""Pydantic models for the mreg_cli package."""

import ipaddress
import re
import sys
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, root_validator, validator
from pydantic.types import StringConstraints

from mreg_cli.api.endpoints import Endpoint
from mreg_cli.log import cli_warning
from mreg_cli.outputmanager import OutputManager
from mreg_cli.utilities.api import delete, get, get_list, patch

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


class Network(FrozenModel):
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


class IPAddress(FrozenModel):
    """Represents an IP address with associated details."""

    id: int  # noqa: A003
    macaddress: Optional[MACAddressField] = None
    ipaddress: IPAddressField
    host: int

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

    def __hash__(self):
        """Return a hash of the IP address."""
        return hash((self.id, self.ipaddress.address, self.macaddress))


class CNAME(FrozenModel):
    """Represents a CNAME record."""

    name: HostT
    ttl: Optional[int] = None
    zone: int
    host: int


class TXT(FrozenModel):
    """Represents a TXT record."""

    txt: str
    host: int


class MX(FrozenModel):
    """Represents a MX record."""

    mx: str
    priority: int
    host: int


class NAPTR(FrozenModel):
    """Represents a NAPTR record."""

    id: int  # noqa: A003
    host: int
    preference: int
    order: int
    flag: Optional[str]
    service: Optional[str]
    regex: Optional[str]
    replacement: str


class Srv(FrozenModel):
    """Represents a SRV record."""

    id: int  # noqa: A003
    name: str
    priority: int
    weight: int
    port: int
    ttl: Optional[int]
    zone: int
    host: int


class PTR_override(FrozenModel):
    """Represents a PTR override record."""

    id: int  # noqa: A003
    host: int
    ipaddress: str  # For now, should be an IP address


class Host(FrozenModel):
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
    hinfo: Optional[str] = None
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

    # This wouold be greatly improved by having a proper error returned to avoid the need for
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
        # We should access by ID, but the current tests use host__name, so to reduce
        # the number of changes, we'll use name for now.
        # srvs = get_list(Endpoint.Srvs, params={"host": self.id})
        srvs = get_list(Endpoint.Srvs, params={"host__name": self.name})
        return [Srv(**srv) for srv in srvs]

    def output_host_info(self, names: bool = False):
        """Output host information to the console with padding."""
        output_manager = OutputManager()
        output_manager.add_line(f"Name:         {self.name}")
        output_manager.add_line(f"Contact:      {self.contact}")

        # Calculate padding
        len_ip = max(
            14, max([len(ip.ipaddress.__str__()) for ip in self.ipaddresses], default=0) + 1
        )
        len_names = (
            14
            if not names
            else max(14, max([len(str(ip.host)) for ip in self.ipaddresses], default=0) + 1)
        )

        # Separate and output A and AAAA records
        for record_type, records in (
            ("A_Records", self.ipv4_addresses()),
            ("AAAA_Records", self.ipv6_addresses()),
        ):
            if records:
                output_manager.add_line(f"{record_type:<{len_names}}IP{' ' * (len_ip - 2)}MAC")
                for record in records:
                    ip = record.ipaddress.__str__()
                    mac = record.macaddress if record.macaddress else "<not set>"
                    name = str(record.host) if names else ""
                    output_manager.add_line(f"{name:<{len_names}}{ip:<{len_ip}}{mac}")

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
