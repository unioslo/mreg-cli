"""Configuration management for the application.

Provides a singleton configuration class that reads settings from
multiple sources, including environment variables, command line arguments,
and an INI configuration file.
"""

from __future__ import annotations

import argparse
import configparser
import logging
import os
from pathlib import Path
from typing import Annotated, Any, ClassVar, Self, TypedDict

from pydantic import AfterValidator, AliasChoices, Field, field_validator
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    EnvSettingsSource,
    InitSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)
from pydantic_settings.sources import ConfigFileSourceMixin
from pydantic_settings.sources.types import PathType
from typing_extensions import override

from mreg_cli.dirs import DEFAULT_CONFIG_PATH, LOG_FILE_DEFAULT
from mreg_cli.types import LogLevel
from mreg_cli.utilities.fs import get_writable_file_or_tempfile, to_path

logger = logging.getLogger(__name__)


# Defaults
DEFAULT_PROMPT = "{user}@{host}"

UNSET_STR = "-"
"""String used to represent unset values in the config table."""


class ConfigSourceMap(TypedDict):
    """Mapping of config sources to their values + active config."""

    cli: dict[str, Any]
    env: dict[str, Any]
    file: dict[str, Any]
    active: dict[str, Any]


class CliSettingsSource(PydanticBaseSettingsSource):
    """HACK: Mock source for storing command line arguments.

    Does not actually parse anything, just stores the args
    and acts as a settings source for introspection purposes.
    """

    def __init__(self, settings_cls: type[BaseSettings]):
        """Initialize the CLI settings source."""
        # NOTE: Declare variables _before_ any method is executed
        self.cli_data: dict[str, Any] = {}
        """Dictionary of command line arguments."""

        super().__init__(settings_cls)

    @override
    def __call__(self) -> dict[str, Any]:
        """Return all active CLI args that differ from field defaults."""
        active: dict[str, Any] = {}
        for k, v in self.cli_data.items():
            if v is None:
                continue
            if k in self.settings_cls.model_fields:
                field = self.settings_cls.model_fields[k]
                # Only include if different from default value
                if field.default is not None and v == field.default:
                    continue
                elif field.default_factory is not None and v == field.default_factory():
                    continue
                active[k] = v
        return active

    @override
    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        # Nothing to do here. Only implement the return statement to make mypy happy
        return None, "", False

    def set_cli_args(self, args: argparse.Namespace | dict[str, Any]) -> None:
        """Set the command line arguments to be used as a source.

        :param args: Command line arguments as an argparse.Namespace or dictionary.
        """
        if isinstance(args, argparse.Namespace):
            args = vars(args)
        self.cli_data = {k: v for k, v in args.items() if v is not None}

    @override
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"


class IniConfigSettingsSource(InitSettingsSource, ConfigFileSourceMixin):
    """Pydantic settings source that loads variables from an INI file."""

    def __init__(self, settings_cls: type[BaseSettings]):
        """Initialize the INI config settings source."""
        # NOTE: Declare variables _before_ any method is executed
        self.paths: list[Path] = []
        """List of successfully read config file paths in chronological order."""

        # Read INI files to populate initial configuration data.
        # DEFAULT_CONFIG_PATH is ordered by precedence, but we need to read files
        # in reverse order since each file read overwrites existing values
        # in the dictionary in the order they are read. This ensures the highest
        # precedence file is processed last and takes priority.
        self.ini_data = self._read_files(DEFAULT_CONFIG_PATH[::-1])  # reverse order
        super().__init__(settings_cls, self.ini_data)

    # Modified version of ConfigFileSourceMixin._read_files() with extra
    # protection against Path.expanduser() failures
    @override
    def _read_files(self, files: PathType | None) -> dict[str, Any]:
        if files is None:
            return {}
        if isinstance(files, (str, os.PathLike)):
            files = [files]
        vars: dict[str, Any] = {}  # noqa: A001
        for file in files:
            try:
                file_path = to_path(file)  # handles failed Path.expanduser()
            except Exception as e:
                logger.warning("Skipping invalid config file path %s: %s", file, e)
                continue
            if file_path.is_file():
                vars.update(self._read_file(file_path))
        return vars

    @override
    def _read_file(self, path: Path) -> dict[str, Any]:
        """Read from an INI file and return a dictionary of settings."""
        try:
            config = configparser.ConfigParser()
            config.read(path)
            vals = {k: v for k, v in config["mreg"].items()}
            # no error here, assume we loaded from the file
            self.paths.append(path)  # no duplicate checking here
            logger.info("Loaded config file %s", path)
            return vals
        except Exception as e:
            logger.error("Failed to read config file %s: %s", path, e)
            return {}

    @override
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"


def to_path_optional(value: Any) -> Path | None:
    """Convert a value to a Path object with expanded user and resolved symlinks, or None."""
    if value is None:
        return None
    return to_path(value)


ResolvedPath = Annotated[Path, AfterValidator(to_path_optional)]
"""Path type that is user expanded (~) and resolved (absolute+symlinks) after validation."""


class MregCliConfig(BaseSettings):
    """Configuration singleton class for the mreg-cli."""

    user: str = ""
    url: str = "https://mreg.uio.no"
    domain: str = "uio.no"
    timeout: int = 20
    prompt: str = "{user}@{host}"
    category_tags: list[str] = []
    location_tags: list[str] = []
    cache: bool = True
    cache_ttl: int = Field(default=300, ge=0)
    http_timeout: int = Field(default=20, ge=0)
    record_traffic: ResolvedPath | None = None
    record_traffic_without_timestamps: bool = False
    token_only: bool = False
    source: ResolvedPath | None = None
    verbose: bool = False
    log_file: ResolvedPath | None = Field(
        LOG_FILE_DEFAULT,
        # New and old names both valid
        validation_alias=AliasChoices("logfile", "log_file"),
    )
    log_level: LogLevel = LogLevel.INFO

    model_config = SettingsConfigDict(
        env_prefix="MREG_CLI_",
        # IMPORTANT: Validate assignment so we can override fields with CLI args
        validate_assignment=True,
        extra="ignore",
    )

    # Class vars required for singleton behavior
    _instance: ClassVar[Self | None] = None

    _init: ClassVar[bool] = False
    """Flag to indicate if sources should be loaded on next instantiation."""

    _sources: ClassVar[tuple[PydanticBaseSettingsSource, ...]] = tuple()
    """Settings sources that have been loaded."""

    def __new__(cls, **kwargs: Any) -> Self:
        """Create a new instance of the config or return the existing one."""
        if cls._instance is None:
            cls._reset_instance()  # clears state, triggers source loading
            cls._instance = super().__new__(cls, **kwargs)
        return cls._instance

    def __init__(self, **kwargs: Any) -> None:
        """Initialize the configuration instance.

        Loads from sources on first instantiation only.
        """
        # Calling __init__ again causes Pydantic to reevaluate sources,
        # thereby overwriting the values in the current instance.
        if self._init:
            return
        super().__init__(**kwargs)
        self.__class__._init = True

    @classmethod
    def _reset_instance(cls) -> None:
        cls._instance = None
        cls._init = False
        cls._sources = tuple()

    @field_validator("user")
    def _user_or_getpass_getuser(cls, v: str | None) -> str:
        """Fall back on `getpass.getuser()` if user arg is empty string."""
        if not v:
            import getpass  # noqa: PLC0415 # only import if we need it

            return getpass.getuser()
        return v

    @field_validator("category_tags", "location_tags", mode="before")
    def _ensure_tags_are_lists(cls, v: Any) -> list[str]:
        # NOTE: does NOT work for env vars, since the Pydantic source
        # parses those values inside the settings source itself.
        if isinstance(v, str):
            return [tag.strip() for tag in v.split(",") if tag.strip()]
        if isinstance(v, list):
            return [str(i) for i in v if i is not None]
        return []

    @field_validator("log_file", mode="after")
    def _ensure_log_file_writable(cls, v: Path) -> Path | None:
        """Ensure we have a writable log file."""
        try:
            return get_writable_file_or_tempfile(v)
        except OSError as e:
            logger.error(str(e))
            return None

    @override
    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,  # noqa: ARG003 # unused
        file_secret_settings: PydanticBaseSettingsSource,  # noqa: ARG003 # unused
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Parse settings from usual sources + INI file _iff_ not already initialized."""
        # Store sources so we can introspect later
        cls._sources = (
            env_settings,
            init_settings,
            IniConfigSettingsSource(settings_cls),
        )
        return cls._sources

    @classmethod
    def get_default_config(cls) -> Self:
        """Create a Config object with default values.

        Does not read from any sources.
        """
        cls._reset_instance()
        return cls.model_construct()

    def parse_cli_args(self, args: argparse.Namespace | dict[str, Any]) -> None:
        """Parse command line arguments and update the configuration."""
        source = CliSettingsSource(MregCliConfig)
        source.set_cli_args(args)
        for key, value in source.cli_data.items():
            if value is None:
                continue  # Optional values are None by default - don't overwrite
            if key in self.model_fields:
                try:
                    setattr(self, key, value)
                except Exception as e:
                    # TODO: show error in console as well
                    logger.error("Failed to set config '%s': %s", key, e)
        # HACK: add/replace CLI source so we can introspect later
        self.__class__._sources = tuple(
            s for s in self.__class__._sources if not isinstance(s, CliSettingsSource)
        ) + (source,)

    def _calculate_column_width(self, data: dict[str, Any], min_width: int = 8) -> int:
        """Calculate the maximum column width, ensuring a minimum width.

        :param data: Dictionary of data for the column.
        :param min_width: Minimum width of the column.
        :returns: Calculated column width.
        """
        max_length = max((len(str(value)) for value in data.values()), default=0)
        return max(max_length, min_width) + 2  # Adding 2 for padding

    def _fmt_config_value(self, value: Any) -> str:
        """Format a configuration value for display."""
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, list):
            return ", ".join(str(v) for v in value)
        if value is None:
            return UNSET_STR
        return str(value)

    def print_config_table(self) -> None:
        """Pretty print the configuration options in a dynamic table format."""
        all_keys = set(self.model_fields)
        key_width = max(max(len(key) for key in all_keys), 8) + 2

        # Collect values from each settings source
        states: ConfigSourceMap = {
            "active": self.model_dump(),
            "cli": {},
            "env": {},
            "file": {},
        }
        for source in self._sources:
            if isinstance(source, IniConfigSettingsSource):
                states["file"] = source()
            elif isinstance(source, EnvSettingsSource):
                states["env"] = source()
            elif isinstance(source, CliSettingsSource):
                states["cli"] = source()

        # Calculate column widths depending on content
        active_width = self._calculate_column_width(states["active"])
        cli_width = self._calculate_column_width(states["cli"])
        env_width = self._calculate_column_width(states["env"])
        file_width = self._calculate_column_width(states["file"])

        # Print the table header
        print("Configuration Options:")
        header_format = f"{{:<{key_width}}} {{:<{active_width}}} {{:<{cli_width}}} {{:<{env_width}}} {{:<{file_width}}}"  # noqa: E501
        print(header_format.format("Key", "Active", "CLI", "Env", "File"))
        print("-" * (key_width + active_width + cli_width + env_width + file_width))

        # Print each row
        row_format = f"{{:<{key_width}}} {{:<{active_width}}} {{:<{cli_width}}} {{:<{env_width}}} {{:<{file_width}}}"  # noqa: E501
        for key in sorted(all_keys):
            # Use formatted values for active config
            active_line_val = self._fmt_config_value(states["active"].get(key, UNSET_STR))
            # Use "raw" values from sources
            cli_var_val = str(states["cli"].get(key, UNSET_STR))
            env_var_val = str(states["env"].get(key, UNSET_STR))
            config_file_val = str(states["file"].get(key, UNSET_STR))
            print(
                row_format.format(key, active_line_val, cli_var_val, env_var_val, config_file_val)
            )
