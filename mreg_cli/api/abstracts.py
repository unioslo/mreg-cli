"""Abstract models for the API."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Callable, Self, cast

from pydantic import AliasChoices, BaseModel, ConfigDict
from pydantic.fields import FieldInfo

from mreg_cli.api.endpoints import Endpoint
from mreg_cli.exceptions import (
    CreateError,
    EntityAlreadyExists,
    EntityNotFound,
    GetError,
    InternalError,
    PatchError,
)
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import JsonMapping, QueryParams
from mreg_cli.utilities.api import (
    delete,
    get,
    get_item_by_key_value,
    get_list_unique,
    get_typed,
    patch,
    post,
)


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


def validate_patched_model(model: BaseModel, fields: dict[str, Any]) -> None:
    """Validate that model fields were patched correctly."""
    aliases = get_model_aliases(model)

    validators: dict[type, Callable[[Any, Any], bool]] = {
        list: _validate_lists,
        dict: _validate_dicts,
    }
    for key, value in fields.items():
        field_name = key
        if key in aliases:
            field_name = aliases[key]

        try:
            nval = getattr(model, field_name)
        except AttributeError as e:
            raise PatchError(f"Could not get value for {field_name} in patched object.") from e

        # Ensure patched value is the one we tried to set
        validator = validators.get(
            type(nval),  # type: ignore # dict.get call with unknown type (Any) is fine
            _validate_default,
        )
        if not validator(nval, value):
            raise PatchError(
                f"Patch failure! Tried to set {key} to {value!r}, but server returned {nval!r}."
            )


def _validate_lists(new: list[Any], old: list[Any]) -> bool:
    """Validate that two lists are equal."""
    if len(new) != len(old):
        return False
    return all(x in old for x in new)


def _validate_dicts(new: dict[str, Any], old: dict[str, Any]) -> bool:
    """Validate that two dictionaries are equal."""
    if len(new) != len(old):
        return False
    return all(old.get(k) == v for k, v in new.items())


def _validate_default(new: Any, old: Any) -> bool:
    """Validate that two values are equal."""
    return str(new) == str(old)


class FrozenModel(BaseModel):
    """Model for an immutable object."""

    def __setattr__(self, name: str, value: Any):
        """Raise an exception when trying to set an attribute."""
        raise AttributeError("Cannot set attribute on a frozen object")

    def __delattr__(self, name: str):
        """Raise an exception when trying to delete an attribute."""
        raise AttributeError("Cannot delete attribute on a frozen object")

    model_config = ConfigDict(
        # Freeze model to make it immutable and thus hashable.
        frozen=True,
    )


class FrozenModelWithTimestamps(FrozenModel):
    """Model with created_at and updated_at fields."""

    created_at: datetime
    updated_at: datetime

    def output_timestamps(self, padding: int = 14) -> None:
        """Output the created and updated timestamps to the console."""
        output_manager = OutputManager()
        output_manager.add_line(f"{'Created:':<{padding}}{self.created_at:%c}")
        output_manager.add_line(f"{'Updated:':<{padding}}{self.updated_at:%c}")


class APIMixin(ABC):
    """A mixin for API-related methods."""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Ensure that the subclass inherits from BaseModel."""
        super().__init_subclass__(**kwargs)
        if BaseModel not in cls.__mro__:
            raise TypeError(
                f"{cls.__name__} must be applied on classes inheriting from BaseModel."
            )

    def id_for_endpoint(self) -> int | str:
        """Return the appropriate id for the object for its endpoint.

        :returns: The correct identifier for the endpoint.
        """
        field = self.endpoint().external_id_field()
        return getattr(self, field)

    @classmethod
    @abstractmethod
    def endpoint(cls) -> Endpoint:
        """Return the endpoint for the method."""
        raise NotImplementedError("You must define an endpoint.")

    @classmethod
    def get(cls, _id: int) -> Self | None:
        """Get an object.

        This function is at its base a wrapper around the get_by_id function,
        but it can be overridden to provide more specific functionality.

        :param _id: The ID of the object.
        :returns: The object if found, None otherwise.
        """
        return cls.get_by_id(_id)

    @classmethod
    def get_list_by_id(cls, _id: int) -> list[Self]:
        """Get a list of objects by their ID.

        :param _id: The ID of the object.
        :returns: A list of objects if found, an empty list otherwise.
        """
        endpoint = cls.endpoint()
        if endpoint.requires_search_for_id():
            return cls.get_list_by_field("id", _id)

        data = get(endpoint.with_id(_id), ok404=True)
        if not data:
            return []

        return [cls(**item) for item in data.json()]

    @classmethod
    def get_by_id(cls, _id: int) -> Self | None:
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

        return cls(**data)

    @classmethod
    def get_by_field(cls, field: str, value: str | int) -> Self | None:
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

        return cls(**data)

    @classmethod
    def get_by_field_or_raise(
        cls,
        field: str,
        value: str,
        exc_type: type[Exception] = EntityNotFound,
        exc_message: str | None = None,
    ) -> Self:
        """Get an object by a field and raise if not found.

        Used for cases where the object must exist for the operation to continue.

        :param field: The field to search by.
        :param value: The value to search for.
        :param exc_type: The exception type to raise.
        :param exc_message: The exception message. Overrides the default message.

        :returns: The object if found.
        """
        obj = cls.get_by_field(field, value)
        if not obj:
            if not exc_message:
                exc_message = f"{cls.__name__} with {field} {value!r} not found."
            raise exc_type(exc_message)
        return obj

    @classmethod
    def get_by_field_and_raise(
        cls,
        field: str,
        value: str,
        exc_type: type[Exception] = EntityAlreadyExists,
        exc_message: str | None = None,
    ) -> None:
        """Get an object by a field and raise if found.

        Used for cases where the object must NOT exist for the operation to continue.

        :param field: The field to search by.
        :param value: The value to search for.
        :param exc_type: The exception type to raise.
        :param exc_message: The exception message. Overrides the default message.

        :raises Exception: If the object is found.
        """
        obj = cls.get_by_field(field, value)
        if obj:
            if not exc_message:
                exc_message = f"{cls.__name__} with {field} {value!r} already exists."
            raise exc_type(exc_message)
        return None

    @classmethod
    def get_list(cls, params: QueryParams | None = None, limit: int | None = None) -> list[Self]:
        """Get a list of all objects.

        Optionally filtered by query parameters and limited by limit.

        :param params: The query parameters to filter by.
        :param limit: The maximum number of hits to allow (default 500)

        :returns: A list of objects if found, an empty list otherwise.
        """
        return get_typed(cls.endpoint(), list[cls], params=params, limit=limit)

    @classmethod
    def get_by_query(
        cls, query: QueryParams, ordering: str | None = None, limit: int | None = 500
    ) -> list[Self]:
        """Get a list of objects by a query.

        :param query: The query to search by.
        :param ordering: The ordering to use when fetching the list.
        :param limit: The maximum number of hits to allow (default 500)

        :returns: A list of objects if found, an empty list otherwise.
        """
        if ordering:
            query["ordering"] = ordering
        return cls.get_list(params=query, limit=limit)

    @classmethod
    def get_list_by_field(
        cls, field: str, value: str | int, ordering: str | None = None, limit: int = 500
    ) -> list[Self]:
        """Get a list of objects by a field.

        :param field: The field to search by.
        :param value: The value to search for.
        :param ordering: The ordering to use when fetching the list.
        :param limit: The maximum number of hits to allow (default 500)

        :returns: A list of objects if found, an empty list otherwise.
        """
        query: QueryParams = {field: value}
        return cls.get_by_query(query=query, ordering=ordering, limit=limit)

    @classmethod
    def get_by_query_unique_or_raise(
        cls,
        query: QueryParams,
        exc_type: type[Exception] = EntityNotFound,
        exc_message: str | None = None,
    ) -> Self:
        """Get an object by a query and raise if not found.

        Used for cases where the object must exist for the operation to continue.

        :param query: The query to search by.
        :param exc_type: The exception type to raise.
        :param exc_message: The exception message. Overrides the default message.

        :returns: The object if found.
        """
        obj = cls.get_by_query_unique(query)
        if not obj:
            if not exc_message:
                exc_message = f"{cls.__name__} with query {query} not found."
            raise exc_type(exc_message)
        return obj

    @classmethod
    def get_by_query_unique_and_raise(
        cls,
        query: QueryParams,
        exc_type: type[Exception] = EntityAlreadyExists,
        exc_message: str | None = None,
    ) -> None:
        """Get an object by a query and raise if found.

        Used for cases where the object must NOT exist for the operation to continue.

        :param query: The query to search by.
        :param exc_type: The exception type to raise.
        :param exc_message: The exception message. Overrides the default message.

        :raises Exception: If the object is found.
        """
        obj = cls.get_by_query_unique(query)
        if obj:
            if not exc_message:
                exc_message = f"{cls.__name__} with query {query} already exists."
            raise exc_type(exc_message)
        return None

    @classmethod
    def get_by_query_unique(cls, data: QueryParams) -> Self | None:
        """Get an object with the given data.

        :param data: The data to search for.
        :returns: The object if found, None otherwise.
        """
        obj_dict = get_list_unique(cls.endpoint(), params=data)
        if not obj_dict:
            return None
        return cls(**obj_dict)

    def refetch(self) -> Self:
        """Fetch an updated version of the object.

        Note that the caller (self) of this method will remain unchanged and can contain
        outdated information. The returned object will be the updated version.

        :returns: The fetched object.
        """
        id_field = self.endpoint().external_id_field()
        identifier = getattr(self, id_field, None)
        if not identifier:
            raise InternalError(
                f"Could not get identifier for {self.__class__.__name__} via {id_field}."
            )

        lookup = None
        # If we have and ID field, a refetch based on that is cleaner as a rename
        # will change the name or whatever other insane field that are used for lookups...
        # Let this be a lesson to you all, don't use mutable fields as identifiers. :)
        if hasattr(self, "id"):
            lookup = getattr(self, "id", None)
            if not lookup:
                raise InternalError(f"Could not get ID for {self.__class__.__name__} via 'id'.")
        else:
            lookup = getattr(self, identifier)

        obj = self.__class__.get_by_id(lookup)
        if not obj:
            raise GetError(f"Could not refresh {self.__class__.__name__} with ID {identifier}.")

        return obj

    def patch(self, fields: dict[str, Any], validate: bool = True) -> Self:
        """Patch the object with the given values.

        Notes
        -----
          1. Depending on the endpoint, the server may not return the patched object.
          2. Patching with None may not clear the field if it isn't nullable (which few fields
             are). Odds are you want to pass an empty string instead.

        :param fields: The values to patch.
        :param validate: Whether to validate the patched object.
        :returns: The object refetched from the server.

        """
        patch(self.endpoint().with_id(self.id_for_endpoint()), **fields)
        new_object = self.refetch()

        if validate:
            # __init_subclass__ guarantees we inherit from BaseModel
            # but we can't signal this to the type checker, so we cast here.
            validate_patched_model(cast(BaseModel, new_object), fields)

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
    def create(cls, params: JsonMapping, fetch_after_create: bool = True) -> Self | None:
        """Create the object.

        Note that several endpoints do not support location headers for created objects,
        so we can't fetch the object after creation. In these cases, we return None even
        if the object was created successfully...

        :param params: The parameters to create the object with.
        :raises CreateError: If the object could not be created.
        :raises GetError: If the object could not be fetched after creation.
        :returns: The object if created and its fetchable, None otherwise.
        """
        response = post(cls.endpoint(), params=None, **params)

        if response and response.ok:
            location = response.headers.get("Location")
            if location and fetch_after_create:
                return get_typed(location, cls)
            # else:
            # Lots of endpoints don't give locations on creation,
            # so we can't fetch the object, but it's not an error...
            # Per se.
            # raise APIError("No location header in response.")

        else:
            raise CreateError(f"Failed to create {cls} with {params} @ {cls.endpoint()}.")

        return None
