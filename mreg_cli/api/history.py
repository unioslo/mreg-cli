"""History abstractions for mreg-cli."""

from __future__ import annotations

import datetime
import json
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from mreg_cli.api.endpoints import Endpoint
from mreg_cli.log import cli_warning
from mreg_cli.outputmanager import OutputManager
from mreg_cli.utilities.api import get_list


class HistoryResource(str, Enum):
    """History resources."""

    Host = "host"
    Group = "group"
    HostPolicy_Role = "hostpolicy_role"
    HostPolicy_Atom = "hostpolicy_atom"

    def relation(self) -> str:
        """Provide the relation of the resource."""
        if self == HistoryResource.Host:
            return "hosts"
        if self == HistoryResource.Group:
            return "groups"
        if self == HistoryResource.HostPolicy_Role:
            return "roles"
        if self == HistoryResource.HostPolicy_Atom:
            return "atoms"

        raise ValueError(f"Unknown resource {self}")


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
    def parse_json_data(cls, v: Any) -> dict[str, Any]:
        """Ensure that data is always treated as a dictionary."""
        if isinstance(v, dict):
            return v  # type: ignore
        else:
            return json.loads(v)

    def clean_timestamp(self) -> str:
        """Clean up the timestamp for output."""
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")

    def msg(self, basename: str) -> str:
        """Attempt to make a history item human readable."""
        msg = ""
        action = self.action
        model = self.model
        if action in ("add", "remove"):
            if self.name == basename:
                msg = self.name
            else:
                msg = self.resource + " " + self.name
                if action == "add":
                    action = "add to"
                elif action == "remove":
                    action = "remove from"
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
            cli_warning(f"Unhandled history entry: {action}")

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
    def get(cls, name: str, resource: HistoryResource) -> list[HistoryItem]:
        """Get history items for a resource."""
        resource_value = resource.value

        params: dict[str, str | int] = {"resource": resource_value, "name": name}

        ret = get_list(Endpoint.History, params=params)

        if len(ret) == 0:
            cli_warning(f"No history found for {name}")

        model_ids = ",".join({str(i["model_id"]) for i in ret})

        params = {
            "resource": resource_value,
            "model_id__in": model_ids,
        }

        ret = get_list(Endpoint.History, params=params)

        data_relation = resource.relation()

        params = {
            "data__relation": data_relation,
            "data__id__in": model_ids,
        }
        ret.extend(get_list(Endpoint.History, params=params))

        return [cls(**i) for i in ret]
