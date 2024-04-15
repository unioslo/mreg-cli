"""API endpoints for mreg."""

from enum import Enum
from typing import Union
from urllib.parse import quote


class Endpoint(str, Enum):
    """API endpoints."""

    Hosts = "/api/v1/hosts/"
    Ipaddresses = "/api/v1/ipaddresses/"
    Networks = "/api/v1/networks/"
    NetworksByIP = "/api/v1/networks/ip/"
    Naptrs = "/api/v1/naptrs/"
    Srvs = "/api/v1/srvs/"
    Cnames = "/api/v1/cnames/"

    def with_id(self, identity: Union[str, int]) -> str:
        """Return the endpoint with an ID."""
        id_field = quote(str(identity))

        return f"{self.value}{id_field}"
