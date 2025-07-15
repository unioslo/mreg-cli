from __future__ import annotations

import logging
from collections.abc import MutableSequence
from enum import Enum
from typing import Any, Sequence, TypeVar, cast, Generic

import rich.box
from pydantic import BaseModel, ConfigDict, Field, RootModel, model_serializer
from pydantic.fields import ComputedFieldInfo, FieldInfo
from rich.console import Console, RenderableType
from rich.errors import MarkupError
from rich.table import Table
from rich.text import Text


logger = logging.getLogger(__name__)


class MetaKey(str, Enum):
    """Keys used in `json_schema_extra` of a field to customize rendering."""

    JOIN_CHAR = "join_char"
    HEADER = "header"


def fmt_field_name(field_name: str) -> str:
    """Format a field name for display in a table."""
    return field_name.capitalize().replace("_", " ")


ColsType = list[str]
"""A list of column headers."""

RowContent = MutableSequence["RenderableType"]
"""A list of renderables representing the content of a row."""

RowsType = MutableSequence[RowContent]
"""A list of rows, where each row is a list of strings."""

ColsRowsType = tuple[ColsType, RowsType]
"""A tuple containing a list of columns and a list of rows, where each row is a list of strings."""


T = TypeVar("T")


def get_text(text: str, *, log: bool = True) -> Text:
    """Interpret text as markup-styled text, or plain text if it fails."""
    try:
        return Text.from_markup(text)
    except MarkupError as e:
        # Log this so that we can more easily debug incorrect rendering
        # In most cases, this will be due to some Zabbix item key that looks
        # like a markup tag, e.g. `system.cpu.load[percpu,avg]`
        # but we need to log it nonetheless for other cases
        # However, we don't want to log when we're removing markup
        # from log records, so we have a `log` parameter to control this.
        if log:
            logger.debug("Markup error when rendering text: '%s': %s", text, e)
        return Text(text)


def get_safe_renderable(renderable: RenderableType) -> RenderableType:
    """Ensure that the renderable can be rendered without raising an exception."""
    if isinstance(renderable, str):
        return get_text(renderable)
    return renderable


def get_table(
    cols: ColsType,
    rows: RowsType,
    title: str | None = None,
    *,
    show_lines: bool = True,
    box: rich.box.Box = rich.box.ROUNDED,
) -> Table:
    """Get a Rich table given a list of columns and rows."""
    table = Table(title=title, box=box, show_lines=show_lines)
    for col in cols:
        table.add_column(col, overflow="fold")
    for row in rows:
        # We might have subtables in the rows.
        # If they have no rows, we don't want to render them.
        row = [cell if not isinstance(cell, Table) or cell.rows else "" for cell in row]
        table.add_row(*row)
    return table


class TableRenderableBase(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        validate_assignment=True,
        extra="allow",
    )

    __title__: str | None = None
    __show_lines__: bool = True
    __box__: rich.box.Box = rich.box.ROUNDED

    def __cols_rows__(self) -> ColsRowsType:
        """Get the columns and rows for the table representation of the object.

        Example:
            >>> class User(TableRenderable):
            ...     userid: str = Field(json_schema_extra={"header" : "User ID"})
            ...     username: str = ""
            ...
            >>> User(userid="1", username="admin").__cols_rows__()
            (["UserID", "Username"], [["1", "admin"]])

        """
        return [], []

    def as_table(self) -> Table:
        """Get a Rich table given the rows and cols generated for the object."""
        cols, rows = self.__cols_rows__()
        for row in rows:
            for i, cell in enumerate(row):
                row[i] = get_safe_renderable(cell)

        return get_table(
            cols=cols,
            rows=rows,
            title=self.__title__,
            show_lines=self.__show_lines__,
            box=self.__box__,
        )


class TableRenderable(TableRenderableBase):
    """Base class for objects that can be rendered as a table."""

    def _get_extra(self, field: str, key: MetaKey, default: T) -> T:
        f = self.model_fields.get(field, None)
        if not f:
            raise ValueError(f"Field {field!r} does not exist.")
        if not f.json_schema_extra or not isinstance(f.json_schema_extra, dict):
            return default
        # NOTE: this cast isn't super type safe, but we are expected to call this
        # method with the extra key constants defined above.
        #
        # If need be, we can add some sort of model validator that ensures
        # all JSON schema extra keys have the correct type.
        # But that will only happen once we actually encounter such a bug.
        return cast(T, f.json_schema_extra.get(key, default))

    def __all_fields__(self) -> dict[str, FieldInfo | ComputedFieldInfo]:
        """Get all fields for the model.

        Includes computed fields while ensuring excluded fields are not included.
        """
        all_fields: dict[str, FieldInfo | ComputedFieldInfo] = {
            **self.model_fields,
            **self.model_computed_fields,
        }
        return {n: f for n, f in all_fields.items() if not getattr(f, "exclude", False)}

    def __cols__(self) -> ColsType:
        """Get the columns for the table representation of the object.

        Only override if you want to customize the column headers without
        overriding the rows. Otherwise, override `__cols_rows__`.

        By default, uses the name of the fields as the column headers,
        with the first letter capitalized.
        This can be overriden with `header` in `json_schema_extra`:

        >>> class User(TableRenderable):
        ...     userid: str = Field(json_schema_extra={"header" : "User ID"})
        ...     username: str = ""
        ...
        >>> User().__cols__()
        ["User ID", "Username"]
        """
        cols: list[str] = []

        for field_name, field in self.__all_fields__().items():
            if (
                field.json_schema_extra
                and isinstance(field.json_schema_extra, dict)
                and field.json_schema_extra.get(MetaKey.HEADER, None)
            ):
                cols.append(str(field.json_schema_extra[MetaKey.HEADER]))
            else:
                cols.append(fmt_field_name(field_name))
        return cols

    def __rows__(self) -> RowsType:
        r"""Get the rows for the table representation of the object.

        Only override if you want to customize the rows without
        overriding the columns. Otherwise, override `__cols_rows__`.

        Render types in the following way:
            - TableRenderable: render as a table
            - BaseModel: render as JSON string
            - list: render as newline delimited string
        Everything else is rendered as a string.

        Example
        -------
        >>> class User(TableRenderable):
        ...     userid: str
        ...     username: str
        ...     groups: List[str] = []
        ...
        >>> User(userid="1", username="admin", groups=["foo", "bar", "baz"]).__rows__()
        [["1", "admin", "foo\nbar\nbaz"]]

        """  # noqa: D416
        fields: dict[str, Any | str] = {
            field_name: getattr(self, field_name, "") for field_name in self.__all_fields__()
        }
        for field_name, value in fields.items():
            if isinstance(value, TableRenderable):
                fields[field_name] = value.as_table()
            elif isinstance(value, BaseModel):
                # Fall back to rendering as JSON string
                logger.warning(
                    "Cannot render %s as a table.",
                    value.__class__.__name__,
                    stack_info=True,  # we want to know how we got here
                )
                fields[field_name] = value.model_dump_json(indent=2)
            elif isinstance(value, list):
                value = cast(list[Any], value)
                # A list either contains TableRenderable objects or stringable objects
                if value and all(isinstance(v, TableRenderable) for v in value):
                    # TableRenderables are wrapped in an AggregateResult to render them
                    # as a single table instead of a table per item.
                    # NOTE: we assume list contains items of the same type
                    # Rendering an aggregate result with mixed types is not supported
                    # and will probably break.
                    value = cast(list[TableRenderable], value)
                    fields[field_name] = AggregateResult(root=value).as_table()
                else:
                    # Other lists are rendered as newline delimited strings.
                    # The delimiter can be modified with the `JOIN_CHAR` meta-key in
                    # the field's `json_schema_extra`.
                    join_char = self._get_extra(field_name, MetaKey.JOIN_CHAR, "\n")
                    fields[field_name] = join_char.join(str(v) for v in value)
            else:
                fields[field_name] = str(value)
        return [list(fields.values())]  # must be a list of lists

    def __cols_rows__(self) -> ColsRowsType:
        """Get the columns and rows for the table representation of the object.

        Example:
            >>> class User(TableRenderable):
            ...     userid: str = Field(json_schema_extra={"header" : "User ID"})
            ...     username: str = ""
            ...
            >>> User(userid="1", username="admin").__cols_rows__()
            (["UserID", "Username"], [["1", "admin"]])

        """
        return self.__cols__(), self.__rows__()


TableRenderableT = TypeVar("TableRenderableT", bound="TableRenderable")


class AggregateResult(TableRenderableBase, Generic[TableRenderableT]):
    """Resut wrapping multiple table renderables.

    Used for compatibility with the legacy JSON format,
    as well as implementing table rendering for multiple
    results.
    """

    root: Sequence[TableRenderableT] = Field(default_factory=list)

    @model_serializer(when_used="json")
    def serialize_root(self) -> list[dict[str, Any]]:
        """Serialize the root field to a list of dictionaries."""
        return [result.model_dump() for result in self.root]

    def __cols_rows__(self) -> ColsRowsType:
        cols: ColsType = []
        rows: RowsType = []

        for result in self.root:
            c, r = result.__cols_rows__()
            if not cols:
                cols = c
            if r:
                rows.append(r[0])  # NOTE: why not add all rows?
        return cols, rows
