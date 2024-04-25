"""Abstract models for the API."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Generic, TypeVar, cast

from pydantic import AliasChoices, BaseModel
from pydantic.fields import FieldInfo

from mreg_cli.api.endpoints import Endpoint
from mreg_cli.api.history import HistoryItem, HistoryResource
from mreg_cli.log import cli_warning
from mreg_cli.outputmanager import OutputManager
from mreg_cli.utilities.api import delete, get, get_item_by_key_value, get_list, patch, post

BMT = TypeVar("BMT", bound="BaseModel")


def get_field_aliases(field_info: FieldInfo) -> set[str]:
    """Get all aliases for a Pydantic field."""
    aliases: set[str] = set()

    if field_info.alias:
        aliases.add(field_info.alias)

    if field_info.validation_alias:
        if isinstance(field_info.validation_alias, str):
            aliases.add(field_info.validation_alias)
        elif isinstance(field_info.validation_alias, AliasChoices):
            for choice in field_info.validation_alias.choices:
                if isinstance(choice, str):
                    aliases.add(choice)
    return aliases


def get_model_aliases(model: BaseModel) -> dict[str, str]:
    """Get a mapping of aliases to field names for a Pydantic model.

    Includes field names, alias, and validation alias(es).
    """
    fields: dict[str, str] = {}

    for field_name, field_info in model.model_fields.items():
        aliases = get_field_aliases(field_info)
        if model.model_config.get("populate_by_name"):
            aliases.add(field_name)
        # Assign aliases to field name in mapping
        for alias in aliases:
            fields[alias] = field_name

    return fields


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


class FrozenModelWithTimestamps(FrozenModel):
    """Model with created_at and updated_at fields."""

    created_at: datetime
    updated_at: datetime

    def output_timestamps(self, padding: int = 14) -> None:
        """Output the created and updated timestamps to the console."""
        output_manager = OutputManager()
        output_manager.add_line(f"{'Created:':<{padding}}{self.created_at:%c}")
        output_manager.add_line(f"{'Updated:':<{padding}}{self.updated_at:%c}")


class APIMixin(Generic[BMT], ABC):
    """A mixin for API-related methods."""

    id: int  # noqa: A003

    def id_for_endpoint(self) -> int | str:
        """Return the appropriate id for the object for its endpoint.

        :returns: The correct identifier for the endpoint.
        """
        field = self.endpoint().external_id_field()
        return getattr(self, field)

    @classmethod
    def field_for_endpoint(cls) -> str:
        """Return the appropriate field for the object for its endpoint.

        :param field: The field to return.
        :returns: The correct field for the endpoint.
        """
        return cls.endpoint().external_id_field()

    @classmethod
    @abstractmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the method."""
        raise NotImplementedError("You must define an endpoint.")

    @classmethod
    def get(cls, _id: int) -> BMT | None:
        """Get an object.

        This function is at its base a wrapper around the get_by_id function,
        but it can be overridden to provide more specific functionality.

        :param _id: The ID of the object.
        :returns: The object if found, None otherwise.
        """
        return cls.get_by_id(_id)

    @classmethod
    def get_by_id(cls, _id: int) -> BMT | None:
        """Get an object by its ID.

        Note that for Hosts, the ID is the name of the host.

        :param _id: The ID of the object.
        :returns: The object if found, None otherwise.
        """
        endpoint = cls.endpoint()

        # Some endpoints do not use the ID field as the endpoint identifier,
        # and in these cases we need to search for the ID... Lovely.
        if endpoint.requires_search_for_id():
            data = get_item_by_key_value(cls.endpoint(), "id", str(_id))
        else:
            data = get(cls.endpoint().with_id(_id), ok404=True)
            if not data:
                return None
            data = data.json()

        if not data:
            return None

        return cast(BMT, cls(**data))

    @classmethod
    def get_by_field(cls, field: str, value: str) -> BMT | None:
        """Get an object by a field.

        Note that some endpoints do not use the ID field for lookups. We do some
        magic mapping via endpoint introspection to perform the following mapping for
        classes and their endpoint "id" fields:

          - Hosts -> name
          - Networks -> network

        This implies that doing a get_by_field("name", value) on Hosts will *not*
        result in a search, but a direct lookup at ../endpoint/name which is what
        the mreg server expects for Hosts (and similar for Network).

        :param field: The field to search by.
        :param value: The value to search for.

        :returns: The object if found, None otherwise.
        """
        endpoint = cls.endpoint()

        if endpoint.requires_search_for_id() and field == endpoint.external_id_field():
            data = get(endpoint.with_id(value), ok404=True)
            if not data:
                return None
            data = data.json()
        else:
            data = get_item_by_key_value(cls.endpoint(), field, value, ok404=True)

        if not data:
            return None

        return cast(BMT, cls(**data))

    @classmethod
    def get_list_by_field(
        cls, field: str, value: str | int, ordering: str | None = None
    ) -> list[BMT]:
        """Get a list of objects by a field.

        :param field: The field to search by.
        :param value: The value to search for.
        :param ordering: The ordering to use when fetching the list.

        :returns: A list of objects if found, an empty list otherwise.
        """
        params = {field: value}
        if ordering:
            params["ordering"] = ordering

        data = get_list(cls.endpoint(), params=params)
        return [cast(BMT, cls(**item)) for item in data]

    def refetch(self) -> BMT:
        """Fetch an updated version of the object.

        Note that the caller (self) of this method will remain unchanged and can contain
        outdated information. The returned object will be the updated version.

        :returns: The fetched object.
        """
        obj = self.__class__.get_by_id(self.id)
        if not obj:
            cli_warning(f"Could not refresh {self.__class__.__name__} with ID {self.id}.")

        return obj

    def patch(self, fields: dict[str, Any]) -> BMT:
        """Patch the object with the given values.

        :param kwargs: The values to patch.
        :returns: The object refetched from the server.
        """
        patch(self.endpoint().with_id(self.id_for_endpoint()), **fields)

        new_object = self.refetch()

        aliases = get_model_aliases(new_object)
        for key, value in fields.items():
            field_name = key
            if key in aliases:
                field_name = aliases[key]
            try:
                nval = getattr(new_object, field_name)
            except AttributeError:
                cli_warning(f"Could not get value for {field_name} in patched object.")
            if str(nval) != str(value):
                cli_warning(
                    # Should this reference `field_name` instead of `key`?
                    f"Patch failure! Tried to set {key} to {value}, but server returned {nval}."
                )

        return new_object

    def delete(self) -> bool:
        """Delete the object.

        :returns: True if the object was deleted, False otherwise.
        """
        response = delete(self.endpoint().with_id(self.id_for_endpoint()))

        if response and response.ok:
            return True

        return False

    @classmethod
    def create(cls, kwargs: dict[str, str | None]) -> None | BMT:
        """Create the object.

        :returns: The object if created, None otherwise.
        """
        response = post(cls.endpoint(), params=None, **kwargs)

        if response and response.ok:
            location = response.headers.get("Location")
            if location:
                obj = None
                if cls.endpoint().external_id_field() == "name":
                    obj = cls.get_by_field("name", location.split("/")[-1])
                else:
                    obj = cls.get_by_id(int(location.split("/")[-1]))

                if obj:
                    return obj

                cli_warning(f"Could not fetch object from location {location}.")

            else:
                cli_warning("No location header in response.")

        return None

    def history(self, resource: HistoryResource) -> list[HistoryItem]:
        """Get the history of the object.

        :param resource: The resource type to get the history for.

        :returns: The history of the object.
        """
        name = self.id_for_endpoint()
        return HistoryItem.get(str(name), resource)

    def output_history(self, resource: HistoryResource) -> None:
        """Output the history of the object.

        :param resource: The resource type to get the history for.
        """
        items = self.history(resource)
        HistoryItem.output_multiple(str(self.id_for_endpoint()), items)
