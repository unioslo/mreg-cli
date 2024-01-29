"""Pydantic models for the mreg_cli package."""

from typing import Annotated, List, Optional

from pydantic import BaseModel, EmailStr, validator
from pydantic.types import StringConstraints

from mreg_cli.outputmanager import OutputManager
from mreg_cli.utilities.validators import is_valid_ipv4, is_valid_ipv6

MACAddressT = Annotated[
    str, StringConstraints(pattern=r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
]

HostT = Annotated[str, StringConstraints(min_length=1, max_length=255)]


class IPAddress(BaseModel):
    """Represents an IP address with associated details."""

    macaddress: Optional[MACAddressT] = None
    ipaddress: str
    host: int

    @validator("macaddress", pre=True, allow_reuse=True)
    def empty_string_to_none(cls, v: str):
        """Convert empty strings to None."""
        return v or None

    @validator("ipaddress")
    def validate_ipaddress(cls, v: str):
        """Validate the IP address format."""
        if is_valid_ipv4(v):
            return v
        elif is_valid_ipv6(v):
            return v
        raise ValueError("Invalid IP address format")

    def __str__(self):
        """Return the IP address as a string."""
        return self.ipaddress

    def is_ipv4(self):
        """Return True if the IP address is IPv4."""
        return is_valid_ipv4(self.ipaddress)

    def is_ipv6(self):
        """Return True if the IP address is IPv6."""
        return is_valid_ipv6(self.ipaddress)


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
        len_ip = max(14, max([len(ip.ipaddress) for ip in self.ipaddresses], default=0) + 1)
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
                    ip = record.ipaddress
                    mac = record.macaddress if record.macaddress else "<not set>"
                    name = str(record.host) if names else ""
                    output_manager.add_line(f"{name:<{len_names}}{ip:<{len_ip}}{mac}")
