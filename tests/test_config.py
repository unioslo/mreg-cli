from __future__ import annotations

import os
import unittest.mock
from pathlib import Path

import pytest
from inline_snapshot import snapshot
from pydantic import BaseModel, ValidationError

from mreg_cli.config import IniConfigSettingsSource, MregCliConfig, ResolvedPath


def test_get_default_config() -> None:
    """Test that the default config does not change."""
    conf = MregCliConfig.get_default_config()
    assert len(conf._sources) == 0

    # Dump as JSON to avoid PosixPath vs WindowsPath issues
    # as well as testing serialization.
    conf_dict = conf.model_dump(mode="json")

    # Mock log file location
    conf_dict["log_file"] = "/mock/log/file.log"

    assert conf_dict == snapshot(
        {
            "url": "https://mreg.uio.no",
            "user": "",
            "domain": "uio.no",
            "timeout": 20,
            "prompt": "{user}@{host}",
            "category_tags": [],
            "location_tags": [],
            "cache": True,
            "cache_ttl": 300,
            "http_timeout": 20,
            "record_traffic": None,
            "record_traffic_without_timestamps": False,
            "token_only": False,
            "source": None,
            "verbose": False,
            "log_file": "/mock/log/file.log",
            "log_level": "INFO",
        }
    )


def test_config_loaded_only_once() -> None:
    # reset the singleton to force reload
    MregCliConfig._reset_instance()
    assert len(MregCliConfig._sources) == 0

    # We have loaded from sources
    conf = MregCliConfig()
    assert len(MregCliConfig._sources) > 0
    assert len(conf._sources) == len(MregCliConfig._sources)

    # Compare sources when called multiple times
    sources_before = conf._sources
    conf2 = MregCliConfig()
    sources_after = conf2._sources
    assert sources_before is sources_after
    assert conf is conf2


def test_config_singleton() -> None:
    """Test that the Config class is a singleton."""
    config1 = MregCliConfig()
    config2 = MregCliConfig()
    assert config1 is config2


def test_default_config_is_not_singleton() -> None:
    """Test that the default config is not a singleton."""
    default1 = MregCliConfig.get_default_config()
    default2 = MregCliConfig.get_default_config()
    assert default1 is not default2


def test_get_default_config_sources() -> None:
    """Test that the default config has no sources."""
    conf = MregCliConfig.get_default_config()
    assert len(conf._sources) == 0


def test_modified_config_persists() -> None:
    """Test that modifications to the config persist across instances."""
    config1 = MregCliConfig()
    config1.url = "https://example.com"
    config2 = MregCliConfig()
    assert config1.url == config2.url == "https://example.com"

    # Reset the singleton and check that a new config is not the same config object
    # we used earlier.
    # TODO: do not attempt to load INI file here!
    # When we reset the config, it may source config values from a config file.
    MregCliConfig._reset_instance()
    config3 = MregCliConfig()
    assert config3 is not config1
    assert config3 is not config2
    assert config1 is config2


def test_config_in_tests_no_fs() -> None:
    """Test that the config does not read from the filesystem in tests by default."""
    config = MregCliConfig()
    assert len(config._sources) == 0


def test_config_read_from_fs(tmp_path: Path) -> None:
    conf_str = """\
[mreg]
url=http://127.0.0.1:8080
user=testuser
domain=test.org
timeout=30
prompt={user}@{host}
# logfile=cli.log
category_tags=cat1,cat2,cat3
location_tags=loc1,loc2,loc3
cache=false
cache_ttl=250
"""
    conf_path = tmp_path / "mreg-cli.conf"
    conf_path.write_text(conf_str)

    MregCliConfig._reset_instance()  # trigger reload
    # Patch the default search paths to only include our temporary config file
    with unittest.mock.patch(
        "mreg_cli.config.DEFAULT_CONFIG_PATH",
        (conf_path,),
    ):
        config = MregCliConfig()
        assert len(config._sources) > 0
        # Check that we actually read from the config file
        p = next(src for src in config._sources if isinstance(src, IniConfigSettingsSource))
        assert conf_path in p.paths

        assert config.url == snapshot("http://127.0.0.1:8080")
        assert config.user == snapshot("testuser")
        assert config.domain == snapshot("test.org")
        assert config.timeout == snapshot(30)
        assert config.prompt == snapshot("{user}@{host}")
        assert config.category_tags == snapshot(["cat1", "cat2", "cat3"])
        assert config.location_tags == snapshot(["loc1", "loc2", "loc3"])
        assert config.cache == snapshot(False)
        assert config.cache_ttl == snapshot(250)


def test_config_read_from_env() -> None:
    os.environ["MREG_CLI_URL"] = "http://127.0.0.1:8080"
    os.environ["MREG_CLI_USER"] = "testuser"
    os.environ["MREG_CLI_DOMAIN"] = "test.org"
    os.environ["MREG_CLI_TIMEOUT"] = "30"
    os.environ["MREG_CLI_PROMPT"] = "{user}@{host}"
    os.environ["MREG_CLI_CATEGORY_TAGS"] = '["cat1","cat2","cat3"]'
    os.environ["MREG_CLI_LOCATION_TAGS"] = '["loc1","loc2","loc3"]'
    os.environ["MREG_CLI_CACHE"] = "false"
    os.environ["MREG_CLI_CACHE_TTL"] = "250"

    MregCliConfig._reset_instance()  # trigger reload
    # Patch the config paths to avoid reading from fs
    with unittest.mock.patch(
        "mreg_cli.config.DEFAULT_CONFIG_PATH",
        tuple(),
    ):
        config = MregCliConfig()
        assert config.url == snapshot("http://127.0.0.1:8080")
        assert config.user == snapshot("testuser")
        assert config.domain == snapshot("test.org")
        assert config.timeout == snapshot(30)
        assert config.prompt == snapshot("{user}@{host}")
        assert config.category_tags == snapshot(["cat1", "cat2", "cat3"])
        assert config.location_tags == snapshot(["loc1", "loc2", "loc3"])
        assert config.cache == snapshot(False)
        assert config.cache_ttl == snapshot(250)


def test_resolvedpath_type() -> None:
    """Test that the ResolvedPath type works as expected."""
    os.environ["HOME"] = "/path/to/home/testuser"

    assert ResolvedPath.__origin__ == Path  # pyright: ignore[reportAttributeAccessIssue, reportUnknownMemberType]

    # Handles str input the same
    inp = "~/some/path"
    p = Path(inp)
    rp = ResolvedPath(inp)  # pyright: ignore[reportCallIssue]
    assert p == rp

    # Handles Path input the same
    inp_path = Path("~/some/other/path")
    rp2 = ResolvedPath(inp_path)  # pyright: ignore[reportCallIssue]
    assert inp_path == rp2

    # Model with required ResolvedPath field
    class TestModelRequired(BaseModel):
        filename: ResolvedPath

    m = TestModelRequired(filename="~/some/file")
    assert isinstance(m.filename, Path)
    assert m.filename == Path("/path/to/home/testuser/some/file")

    # Model with optional ResolvedPath field
    class TestModelOptional(BaseModel):
        filename: ResolvedPath | None = None

    m = TestModelOptional()
    assert m.filename is None
    m2 = TestModelOptional(filename="~/some/file")
    assert isinstance(m2.filename, Path)
    assert m2.filename == Path("/path/to/home/testuser/some/file")


@pytest.mark.parametrize(
    "optional",
    [
        pytest.param(True, id="optional (ResolvedPath | None)"),
        pytest.param(False, id="required (ResolvedPath)"),
    ],
)
def test_resolvedpath_invalid(optional: bool) -> None:
    if optional:

        class TestModel(BaseModel):
            filename: ResolvedPath | None = None
    else:

        class TestModel(BaseModel):
            filename: ResolvedPath

    for invalid in [123, 45.6, True, False, [], {}, ()]:
        with pytest.raises(ValidationError) as excinfo:
            # Ensure we raise a pydantic ValidationError on invalid input
            TestModel(filename=invalid)  # pyright: ignore[reportArgumentType]
            assert "Invalid path" in str(excinfo.value)
