"""Pydantic models for the mreg_cli package."""


import ipaddress
from typing import Annotated, Any, Dict, List, Optional, Union

from pydantic import BaseModel, EmailStr, root_validator, validator
from pydantic.types import StringConstraints

from mreg_cli.log import cli_warning
from mreg_cli.outputmanager import OutputManager

MACAddressT = Annotated[
    str, StringConstraints(pattern=r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
]

HostT = Annotated[str, StringConstraints(min_length=1, max_length=255)]


class IPAddressField(BaseModel):
    """Represents an IP address, automatically determines if it's IPv4 or IPv6."""

    address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

    @validator("address", pre=True)
    def parse_ip_address(cls, value: str) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
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


class IPAddress(BaseModel):
    """Represents an IP address with associated details."""

    macaddress: Optional[MACAddressT] = None
    ipaddress: IPAddressField
    host: int

    @validator("macaddress", pre=True, allow_reuse=True)
    def empty_string_to_none(cls, v: str):
        """Convert empty strings to None."""
        return v or None

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


class CNAME(BaseModel):
    """Represents a CNAME record."""

    name: HostT
    ttl: Optional[int] = None
    zone: int
    host: int


class TXT(BaseModel):
    """Represents a TXT record."""

    txt: str
    host: int


class HostModel(BaseModel):
    """Model for an individual host.

    This is the endpoint at /api/v1/hosts/<id>.
    """

    name: HostT
    ipaddresses: List[IPAddress]
    cnames: List[CNAME] = []
    mxs: List[str] = []
    txts: List[TXT] = []
    ptr_overrides: List[str] = []
    hinfo: Optional[str] = None
    loc: Optional[str] = None
    bacnetid: Optional[str] = None
    contact: EmailStr
    ttl: Optional[int] = None
    comment: Optional[str] = None
    zone: int

    @validator("comment", pre=True, allow_reuse=True)
    def empty_string_to_none(cls, v: str):
        """Convert empty strings to None."""
        return v or None

    def ipv4_addresses(self):
        """Return a list of IPv4 addresses."""
        return [ip for ip in self.ipaddresses if ip.is_ipv4()]

    def ipv6_addresses(self):
        """Return a list of IPv6 addresses."""
        return [ip for ip in self.ipaddresses if ip.is_ipv6()]

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


class HostList(BaseModel):
    """Model for a list of hosts.

    This is the endpoint at /api/v1/hosts/.
    """

    results: List[HostModel]

    @validator("results", pre=True)
    def check_results(cls, v: List[Dict[str, str]]):
        """Check that the results are valid."""
        return v

    def __len__(self):
        """Return the number of results."""
        return len(self.results)

    def __getitem__(self, key: int) -> HostModel:
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
