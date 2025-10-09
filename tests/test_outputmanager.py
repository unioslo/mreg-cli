from __future__ import annotations

from copy import deepcopy

import pytest

from mreg_cli.outputmanager import remove_dict_key_recursive
from mreg_cli.types import Json


@pytest.mark.parametrize(
    "inp,key,expected",
    [
        pytest.param(
            {"a": 1, "b": 2},
            "a",
            {"b": 2},
            id="simple_single_key_dict",
        ),
        pytest.param(
            {"a": {"b": 2, "c": 3}, "d": 4},
            "b",
            {"a": {"c": 3}, "d": 4},
            id="nested_dict_removal",
        ),
        pytest.param(
            [{"a": 1}, {"a": 2}, {"b": 3}],
            "a",
            [{}, {}, {"b": 3}],
            id="list_of_dicts",
        ),
        pytest.param(
            {"a": [{"b": 1, "c": 2}, {"b": 3, "d": 4}], "e": {"b": 5, "f": {"b": 6}}},
            "b",
            {"a": [{"c": 2}, {"d": 4}], "e": {"f": {}}},
            id="complex_nested_structure",
        ),
        pytest.param(
            {"a": 1, "b": 2},
            "c",
            {"a": 1, "b": 2},
            id="key_not_present",
        ),
        pytest.param(
            {},
            "a",
            {},
            id="empty_dict",
        ),
        pytest.param(
            [],
            "a",
            [],
            id="empty_list",
        ),
        pytest.param(
            {"a": 1, "b": "string", "c": True, "d": None, "e": 1.5, "f": {"a": 2}},
            "a",
            {"b": "string", "c": True, "d": None, "e": 1.5, "f": {}},
            id="mixed_types_with_nested_removal",
        ),
        pytest.param(
            [[[{"a": 1}]], [[{"a": 2}]]],
            "a",
            [[[{}]], [[{}]]],
            id="deeply_nested_lists",
        ),
    ],  # type: ignore
)
def test_remove_dict_key_recursive(inp: Json, key: str, expected: Json) -> None:
    """Test remove_dict_key_recursive with a variety of inputs."""
    remove_dict_key_recursive(inp, key)
    assert inp == expected


def test_none_value_handling() -> None:
    """Test that the function handles None values appropriately."""
    obj: Json = None
    remove_dict_key_recursive(obj, "any_key")  # Should not raise any exception
    assert obj is None


@pytest.mark.parametrize(
    "inp",
    [
        "string",
        123,
        1.5,
        True,
        False,
        None,
    ],
)
def test_primitive_value_handling(inp: Json) -> None:
    """Test that the function handles primitive values appropriately."""
    original = deepcopy(inp)
    remove_dict_key_recursive(inp, "any_key")  # Should not raise any exception
    assert inp == original  # Should not modify primitive values
