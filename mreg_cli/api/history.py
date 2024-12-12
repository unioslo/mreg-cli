"""History abstractions for mreg-cli."""

from __future__ import annotations

import datetime
import json
from enum import Enum
from typing import Any, Self

from pydantic import BaseModel, Field, field_validator

from mreg_cli.api.endpoints import Endpoint
from mreg_cli.exceptions import EntityNotFound, InternalError
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import QueryParams
from mreg_cli.utilities.api import get_typed


class HistoryResource(str, Enum):
    """History resources for the API.

    Names represent resource names.
    Values represent resource relations.

    Access resource names and relation with the `resource()` and `relation()` methods.
    """

    Host = "hosts"
    Permissions = "permissions"
    Group = "groups"
    HostPolicy_Role = "roles"
    HostPolicy_Atom = "atoms"

    @classmethod
    def _missing_(cls, value: Any) -> HistoryResource:
        v = str(value).lower()
        for resource in cls:
            if resource.value == v:
                return resource
            elif resource.name.lower() == v:
                return resource
        raise ValueError(f"Unknown resource {value}")

    def relation(self) -> str:
        """Get the resource relation."""
        return self.value

    def resource(self) -> str:
        """Get the resource name."""
        return self.name.lower()


class HistoryItem(BaseModel):
    """Represents a history item."""

    id: int  # noqa: A003
    timestamp: datetime.datetime
    user: str
    resource: HistoryResource
    name: str
    mid: int = Field(alias="model_id")  # model_ is an internal pydantic namespace.
    model: str
    action: str
    data: dict[str, Any]

    @field_validator("data", mode="before")
    def parse_json_data(cls, v: Any) -> Any:
        """Ensure that non-dict values are treated as JSON."""
        if isinstance(v, dict):
            return v  # pyright: ignore[reportUnknownVariableType]
        try:
            return json.loads(v)
        except json.JSONDecodeError as e:
            raise ValueError("Failed to parse history data as JSON") from e

    def clean_timestamp(self) -> str:
        """Clean up the timestamp for output."""
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")

    def msg(self, _basename: str) -> str:
        """Attempt to make a history item human readable."""
        msg = ""
        action = self.action
        model = self.model
        if action in ("add", "remove"):
            if action == "add":
                direction = "to"
            elif action == "remove":
                direction = "from"
            else:
                raise InternalError(f"Unhandled history entry: {action}")
            rel = self.data["relation"][:-1]
            cls = str(self.resource)
            if "." in cls:
                cls = cls[cls.rindex(".") + 1 :]
            cls = cls.replace("HostPolicy_", "")
            cls = cls.lower()
            msg = f"{rel} {self.data['name']} {direction} {cls} {self.name}"
        elif action == "create":
            msg = ", ".join(f"{k} = '{v}'" for k, v in self.data.items())
        elif action == "update":
            if model in ("Ipaddress",):
                msg = self.data["current_data"]["ipaddress"] + ", "
            changes: list[str] = []
            for key, newval in self.data["update"].items():
                oldval = self.data["current_data"][key] or "not set"
                newval = newval or "not set"
                changes.append(f"{key}: {oldval} -> {newval}")
            msg += ",".join(changes)
        elif action == "destroy":
            if model == "Host":
                msg = "deleted " + self.name
            else:
                msg = ", ".join(f"{k} = '{v}'" for k, v in self.data.items())
        else:
            raise InternalError(f"Unhandled history entry: {action}")

        return msg

    def output(self, basename: str) -> None:
        """Output the history item."""
        ts = self.clean_timestamp()
        msg = self.msg(basename)
        OutputManager().add_line(f"{ts} [{self.user}]: {self.model} {self.action}: {msg}")

    @classmethod
    def output_multiple(cls, basename: str, items: list[HistoryItem]) -> None:
        """Output multiple history items."""
        for item in sorted(items, key=lambda i: i.timestamp):
            item.output(basename)

    @classmethod
    def get(cls, name: str, resource: HistoryResource) -> list[Self]:
        """Get history items for a resource."""
        params: QueryParams = {"resource": resource.resource(), "name": name}
        ret = get_typed(Endpoint.History, list[cls], params=params)
        if len(ret) == 0:
            raise EntityNotFound(f"No history found for {name}")

        model_ids = ",".join({str(i.mid) for i in ret})
        params = {
            "resource": resource.resource(),
            "model_id__in": model_ids,
        }
        ret = get_typed(Endpoint.History, list[cls], params=params)

        params = {
            "data__relation": resource.relation(),
            "data__id__in": model_ids,
        }
        ret.extend(get_typed(Endpoint.History, list[cls], params=params))

        return ret
