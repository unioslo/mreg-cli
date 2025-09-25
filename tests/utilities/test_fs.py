from __future__ import annotations

import os
from pathlib import Path

import pytest

from mreg_cli.utilities.fs import get_writable_file_or_tempfile, to_path


def test_get_writable_file_or_tempfile_ok(tmp_path: Path) -> None:
    """Test passing a writable file path to get_writable_file_or_tempfile."""
    file_path = tmp_path / "testfile.txt"
    result_path = get_writable_file_or_tempfile(file_path)
    assert result_path == file_path
    assert result_path.exists()
    assert result_path.is_file()


@pytest.mark.parametrize(
    "content",
    [
        pytest.param("Some content", id="simple text"),
        pytest.param("", id="empty string"),
        pytest.param("特殊字符", id="unicode characters"),
        pytest.param("Line1\nLine2\nLine3", id="multiple lines"),
    ],
)
def test_get_writable_file_or_tempfile_ok_nonempty(tmp_path: Path, content: str) -> None:
    """Test get_writable_file_or_tempfile with an existing non-empty file."""
    file_path = tmp_path / "testfile.txt"
    file_path.write_text(content)
    pre = file_path.read_text()
    result_path = get_writable_file_or_tempfile(file_path)
    post = file_path.read_text()
    assert pre == post  # Ensure content is unchanged
    assert result_path == file_path
    assert result_path.exists()
    assert result_path.is_file()


def test_get_writable_file_or_tempfile_dir_fail(tmp_path: Path) -> None:
    """Test passing a directory path to get_writable_file_or_tempfile."""
    dir_path = tmp_path / "somedir"
    dir_path.mkdir()
    result_path = get_writable_file_or_tempfile(dir_path)
    assert result_path != dir_path
    assert result_path.exists()
    assert result_path.is_file()


def test_get_writable_file_or_tempfile_non_writable_root() -> None:
    """Test get_writable_file_or_tempfile with a non-writable path."""
    # Test with a non-writable path (simulate by using root directory on Unix)
    if os.name != "nt":  # Skip this test on Windows
        non_writable_path = Path("/testfile.txt")
        try:
            with pytest.raises(OSError):
                non_writable_path.touch()  # Ensure we can't create it
            result_path = get_writable_file_or_tempfile(non_writable_path)
            assert result_path != non_writable_path
            assert result_path.exists()
            assert result_path.is_file()
        finally:
            # ensure we don't leave a file behind in case the test is run with
            # elevated privileges (and thus fails to raise OSError above)
            if non_writable_path.exists():
                non_writable_path.unlink()


@pytest.mark.parametrize(
    "as_path",
    [
        pytest.param(True, id="as Path"),
        pytest.param(False, id="as str"),
    ],
)
def test_to_path_relative(as_path: bool) -> None:
    """Test to_path with a relative path."""
    inp = "some/relative/path.txt"
    if as_path:
        result = to_path(Path(inp))
    else:
        result = to_path(inp)
    assert result == (Path.cwd() / inp).resolve()


@pytest.mark.parametrize(
    "as_path",
    [
        pytest.param(True, id="as Path"),
        pytest.param(False, id="as str"),
    ],
)
def test_to_path_user_home_expansion(as_path: bool) -> None:
    """Test to_path with a path containing ~ for home directory.

    NOTE: ~user is not tested as it is system dependent and
    is more effort to mock than it is worth.
    """
    os.environ["HOME"] = str("/some/path/to/foo")
    inp = "~/file.txt"
    if as_path:
        result = to_path(Path(inp))
    else:
        result = to_path(inp)
    assert result == Path("/some/path/to/foo/file.txt")


@pytest.mark.parametrize(
    "as_path",
    [
        pytest.param(True, id="as Path"),
        pytest.param(False, id="as str"),
    ],
)
@pytest.mark.parametrize(
    "no_home_dir",
    [
        pytest.param(True, id="no homedir"),
        pytest.param(False, id="with homedir"),
    ],
)
def test_to_path_absolute(as_path: bool, no_home_dir: bool) -> None:
    """Test to_path with absolute paths."""
    if no_home_dir:
        # Simulate no home directory by removing HOME env var
        del os.environ["HOME"]
    else:
        # Ensure HOME is set
        if not os.environ.get("HOME"):
            os.environ["HOME"] = "/path/to/home"

    # Absolute path should be unaffected by home dir presence
    inp = "/absolute/path/to/file.txt"
    if as_path:
        result = to_path(Path(inp))
    else:
        result = to_path(inp)
    assert result == Path("/absolute/path/to/file.txt")
