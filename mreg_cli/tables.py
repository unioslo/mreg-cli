from pydantic import BaseModel, ConfigDict


class TableRow(BaseModel):
    """Base class for table rows used by `OutputManager.print_formatted_table`.

    The Header for each column is determined by the name of each field.
    However, names can be overridden by specifying an attribute docstring
    for the field _or_ using `Field(..., description="<header>")`.

    Example:
    -------
    ```
    class MyRow(TableRow):
        foo: str # header: "Foo"
        bar: str # header: "Bar Users"
        \"\"\"Bar Users\"\"\"
        baz: str = Field(..., description="Baz Users") # header: "Baz Users"
    ```

    """  # noqa: D301 # escaping double quotes

    model_config = ConfigDict(use_attribute_docstrings=True)

    # NOTE: ideally we guarantee identical order between `keys` and `headers` somehow
    @classmethod
    def keys(cls) -> list[str]:
        """Return the keys of the model as a list."""
        return list(cls.model_fields.keys())

    @classmethod
    def headers(cls) -> list[str]:
        """Return the headers of the model as a list."""
        headers: list[str] = []
        for name, field in cls.model_fields.items():
            headers.append(field.description or name.capitalize())
        return headers
