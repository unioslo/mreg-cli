"""API endpoints for mreg."""

from enum import Enum
from typing import Union


class Endpoint(str, Enum):
    """API endpoints."""

    Hosts = "/api/v1/hosts/"
    Ipaddresses = "/api/v1/ipaddresses/"

    def with_id(self, identity: Union[str, int]) -> str:
        """Return the endpoint with an ID."""
        return f"{self.value}{identity}"
