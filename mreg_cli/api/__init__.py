"""API glue code for the mreg_cli package.

Originally the API code took whatever JSON data it received and returned it as a dictionary.
This led to horrible code that was hard to maintain and debug. This module is an attempt to
fix that by using pydantic models to validate incoming data so the client code has
guarantees about the data it is working with.
"""

from typing import Dict, Union

from mreg_cli.api.models import HostList, HostModel
from mreg_cli.utilities.api import get, get_list
from mreg_cli.utilities.host import clean_hostname


def get_host(name: str) -> HostModel:
    """Get a host by name."""
    hostname = clean_hostname(name)
    data = get(f"/api/v1/hosts/{hostname}")
    return HostModel(**data.json())


def get_hosts(params: Dict[str, Union[str, int]]) -> HostList:
    """Get a list of hosts."""
    endpoint = "/api/v1/hosts/"
    data = get_list(endpoint, params=params)
    return HostList(results=[HostModel(**host_data) for host_data in data])
