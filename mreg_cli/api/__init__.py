"""API glue code for the mreg_cli package.

Originally the API code took whatever JSON data it received and returned it as a dictionary.
This led to horrible code that was hard to maintain and debug. This module is an attempt to
fix that by using pydantic models to validate incoming data so the client code has
guarantees about the data it is working with.
"""

from __future__ import annotations

import re
from ipaddress import ip_address

from mreg_cli.api.endpoints import Endpoint
from mreg_cli.api.models import Host, HostList, MACAddressField
from mreg_cli.config import MregCliConfig
from mreg_cli.log import cli_warning
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import IP_AddressT
from mreg_cli.utilities.api import get, get_item_by_key_value


def get_host(identifier: str, ok404: bool = False, inform_as_cname: bool = False) -> None | Host:
    """Get a host by the given identifier.

    - If the identifier is numeric, it will be treated as an ID.
    - If the identifier is an IP address, it will be treated as an IP address (v4 or v6).
    - If the identifier is a MAC address, it will be treated as a MAC address.
    - Otherwise, it will be treated as a hostname. If the hostname is a CNAME,
      the host it points to will be returned.

    To check if a returned host is a cname, one can do the following:

    ```python
    hostname = "host.example.com"
    host = get_host(hostname, ok404=True)
    if host is None:
        print("Host not found.")
    elif host.name != hostname:
        print(f"{hostname} is a CNAME pointing to {host.name}")
    else:
        print(f"{host.name} is a host.")
    ```

    Note that get_host will perform a case-insensitive search for a fully qualified version
    of the hostname, so the comparison above may fail.

    :param identifier: The identifier to search for.
    :param ok404: If True, don't raise a CliWarning if the host is not found.
    :param inform_as_cname: If True, inform the user if the host is a CNAME.

    :raises CliWarning: If we don't find the host and `ok404` is False.

    :returns: A Host object if the host was found, otherwise None.
    """
    data = None
    if identifier.isdigit():
        data = get_item_by_key_value(Endpoint.Hosts, "id", identifier, ok404=ok404)
    else:
        try:
            ip_address(identifier)
            data = get_item_by_key_value(Endpoint.Hosts, "ipaddress", identifier, ok404=ok404)
        except ValueError:
            pass

        try:
            mac = MACAddressField(address=identifier)
            data = get_item_by_key_value(Endpoint.Hosts, "macaddress", mac.address, ok404=ok404)
        except ValueError:
            pass

        hostname = clean_hostname(identifier)

        data = get(Endpoint.Hosts.with_id(hostname), ok404=True)

        if data:
            data = data.json()
        else:
            data = get_item_by_key_value(Endpoint.Cnames, "name", hostname, ok404=ok404)
            # If we found a CNAME, get the host it points to. We're not interested in the CNAME
            # itself. Also, no point in pydantic-ifying the CNAME data since we're not using it.
            if data is not None:
                data = get_item_by_key_value(Endpoint.Hosts, "id", data["host"], ok404=ok404)

            if data and inform_as_cname:
                OutputManager().add_line(f"{hostname} is a CNAME for {data['name']}")

    if data is None:
        if not ok404:
            cli_warning(f"Host {identifier} not found.")

        return None

    return Host(**data)


def delete_host(identifier: str) -> bool:
    """Delete a host by the given identifier."""
    host = get_host(identifier)
    if host is None:
        cli_warning(f"Host {identifier} not found.")

    return host.delete()


def get_hosts(params: dict[str, str | int]) -> HostList:
    """Get a list of hosts."""
    return HostList.get(params=params)


def add_host(data: dict[str, str | None]) -> Host | None:
    """Add a host."""
    return Host.create(kwargs=data)


def get_network_by_ip(ip: IP_AddressT) -> None | dict[str, str | int]:
    """Return a network associated with given IP."""
    return get(Endpoint.NetworksByIP.with_id(str(ip))).json()


def clean_hostname(name: str | bytes) -> str:
    """Ensure hostname is fully qualified, lowercase, and has valid characters.

    :param name: The hostname to clean.

    :raises CliWarning: If the hostname is invalid.

    :returns: The cleaned hostname.
    """
    # bytes?
    if not isinstance(name, (str, bytes)):
        cli_warning(f"Invalid input for hostname: {name}")

    if isinstance(name, bytes):
        name = name.decode()

    name = name.lower()

    # invalid characters?
    if re.search(r"^(\*\.)?([a-z0-9_][a-z0-9\-]*\.?)+$", name) is None:
        cli_warning(f"Invalid input for hostname: {name}")

    # Assume user is happy with domain, but strip the dot.
    if name.endswith("."):
        return name[:-1]

    # If a dot in name, assume long name.
    if "." in name:
        return name

    config = MregCliConfig()
    default_domain = config.get("domain")
    # Append domain name if in config and it does not end with it
    if default_domain and not name.endswith(default_domain):
        return f"{name}.{default_domain}"
    return name
