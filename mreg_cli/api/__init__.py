"""API glue code for the mreg_cli package.

Originally the API code took whatever JSON data it received and returned it as a dictionary.
This led to horrible code that was hard to maintain and debug. This module is an attempt to
fix that by using pydantic models to validate incoming data so the client code has
guarantees about the data it is working with.
"""

from ipaddress import ip_address
from typing import Dict, Union

from mreg_cli.api.endpoints import Endpoint
from mreg_cli.api.models import HostList, HostModel, MACAddressField
from mreg_cli.log import cli_warning
from mreg_cli.utilities.api import get, get_item_by_key_value, get_list, post
from mreg_cli.utilities.host import clean_hostname


def get_host(identifier: str, ok404: bool = False) -> Union[None, HostModel]:
    """Get a host by the given identifier.

    - If the identifier is numeric, it will be treated as an ID.
    - If the identifier is an IP address, it will be treated as an IP address (v4 or v6).
    - If the identifier is a MAC address, it will be treated as a MAC address.
    - Otherwise, it will be treated as a hostname. If the hostname is a CNAME,
      the host it points to will be returned.

    To check if a returned host is a cname, one can do the following:

    ```python
    hostname = "example.com"
    host = get_host(hostname, ok404=True)
    if host is None:
        print("Host not found.")
    elif host.name != hostname:
        print(f"{hostname} is a CNAME pointing to {host.name}")
    else:
        print(f"{host.name} is a host.")
    ```

    :param identifier: The identifier to search for.

    :raises CliWarning: If we don't find the host and `ok404` is False.

    :returns: A HostModel object if the host was found, otherwise None.
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

        data = get(Endpoint.Hosts.with_id(hostname), ok404=ok404)

        if data is None:
            data = get_item_by_key_value(Endpoint.Cnames, "name", hostname, ok404=ok404)
            # If we found a CNAME, get the host it points to. We're not interested in the CNAME
            # itself. Also, no point in pydantic-ifying the CNAME data since we're not using it.
            if data is not None:
                data = get_item_by_key_value(Endpoint.Hosts, "id", data["host"], ok404=ok404)
        else:
            data = data.json()

    if data is None:
        return None

    return HostModel(**data)


def delete_host(identifier: str) -> bool:
    """Delete a host by the given identifier."""
    host = get_host(identifier)
    if host is None:
        cli_warning(f"Host {identifier} not found.")

    return host.delete()


def get_hosts(params: Dict[str, Union[str, int]]) -> HostList:
    """Get a list of hosts."""
    data = get_list(Endpoint.Hosts, params=params)
    return HostList(results=[HostModel(**host_data) for host_data in data])


def add_host(data: Dict[str, Union[str, None]]) -> bool:
    """Add a host."""
    response = post(Endpoint.Hosts, params=None, **data)

    if response and response.ok:
        return True

    return False
