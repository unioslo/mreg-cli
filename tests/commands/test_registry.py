"""Tests for nested command registries and hidden aliases."""

from __future__ import annotations

import argparse
from typing import Any

import pytest
from inline_snapshot import snapshot

from mreg_cli.cli import Command, cli
from mreg_cli.commands.base import BaseCommand, register_commands
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import InternalError
from mreg_cli.types import Flag


def callback(_: argparse.Namespace) -> None:
    """No-op command callback."""


def build_cli(registry: CommandRegistry, name: str) -> Command:
    """Register `registry` as top-level command `name` under a fresh root CLI.

    The command vocabulary (names, aliases, flags) lives in the registry the
    caller built; this helper only wires up the root CLI.
    """

    class Commands(BaseCommand):
        def __init__(self, cli: Any) -> None:
            super().__init__(cli, registry, name, f"{name} commands.", name)

    root = Command(argparse.ArgumentParser(prog="test"), [], "")
    register_commands(root, [Commands])
    return root


class TestHiddenAliases:
    """A tree with nested groups and hidden aliases.

    Registers one command, `x policy attribute list <name>`, with two hidden
    aliases: `x policy_attribute_list` (beside the groups) and
    `x legacy attribute_list` (through an ad-hoc group).
    """

    ALIAS = "x policy_attribute_list"
    AD_HOC_ALIAS = "x legacy attribute_list"

    PATHS = [
        pytest.param(["x", "policy", "attribute", "list", "foo"], id="nested groups"),
        pytest.param(ALIAS.split() + ["foo"], id="alias"),
        pytest.param(AD_HOC_ALIAS.split() + ["foo"], id="ad-hoc group"),
    ]

    def setup_method(self) -> None:
        """Build the tree described in the class docstring."""
        registry = CommandRegistry()
        attribute = registry.group("policy", "Manage policies.").group(
            "attribute", "Manage attributes."
        )
        attribute.register_command(
            prog="list",
            description="List attributes",
            aliases=[self.ALIAS, self.AD_HOC_ALIAS],
            flags=[Flag("name", description="Name")],
        )(callback)
        self.root = build_cli(registry, "x")

    @pytest.mark.parametrize("argv", PATHS)
    def test_invocation_paths_resolve(self, argv: list[str]) -> None:
        """Every invocation path dispatches to the command with its arguments."""
        ns = self.root.parser.parse_args(argv)
        assert ns.func is callback
        assert ns.name == "foo"

    def test_help_shows_only_visible_commands(self) -> None:
        """Hidden aliases and ad-hoc groups are omitted from help output."""
        x = self.root.children["x"]
        help_text = x.parser.format_help()
        assert "policy" in help_text
        assert "policy_attribute_list" not in help_text
        assert "legacy" not in help_text

    def test_completion_suggests_only_visible_commands(self) -> None:
        """Hidden aliases and ad-hoc groups are omitted from completions."""
        assert [c.text for c in self.root.complete("pol", ["x", "pol"])] == ["policy"]
        assert [c.text for c in self.root.complete("", ["x"])] == ["policy"]


class TestAliasRegistration:
    """Registering aliases: missing segments are created ad-hoc, empty aliases rejected."""

    @staticmethod
    def build(alias: str) -> Command:
        """Build a tree whose single command carries `alias`."""
        registry = CommandRegistry()
        registry.group("policy", "Manage policies.").register_command(
            prog="list", description="List policies", aliases=[alias]
        )(callback)
        return build_cli(registry, "x")

    def test_unknown_toplevel_creates_hidden_group(self) -> None:
        """An alias with an unknown top-level segment creates a hidden ad-hoc group."""
        root = self.build("no_such_toplevel policy_attribute_list")
        toplevel = root.children["no_such_toplevel"]
        assert toplevel.hidden
        assert toplevel.children["policy_attribute_list"].hidden
        ns = root.parser.parse_args(["no_such_toplevel", "policy_attribute_list"])
        assert ns.func is callback

    def test_single_segment_creates_hidden_command(self) -> None:
        """A single-segment alias creates a hidden ad-hoc top-level command."""
        root = self.build("policy_attribute_list")
        assert root.children["policy_attribute_list"].hidden
        ns = root.parser.parse_args(["policy_attribute_list"])
        assert ns.func is callback

    def test_empty_alias_is_rejected(self) -> None:
        """An empty alias raises an error."""
        with pytest.raises(InternalError) as exc_info:
            self.build("")
        assert exc_info.exconly() == snapshot(
            "mreg_cli.exceptions.InternalError: Empty alias for command 'list'"
        )

    def test_whitespace_alias_is_rejected(self) -> None:
        """An alias with only whitespace raises an error."""
        with pytest.raises(InternalError) as exc_info:
            self.build("  ")
        assert exc_info.exconly() == snapshot(
            "mreg_cli.exceptions.InternalError: Empty alias for command 'list'"
        )


# Deprecated network command names kept as hidden aliases, from the changelog.
DEPRECATED_NETWORK_ALIASES = [
    ("network policy_add", "network policy add"),
    ("network policy_create", "network policy create"),
    ("network policy_delete", "network policy delete"),
    ("network policy_info", "network policy info"),
    ("network policy_list", "network policy list"),
    ("network policy_rename", "network policy rename"),
    ("network policy_remove", "network policy remove"),
    ("network policy_set_description", "network policy set_description"),
    ("network policy_set_pattern", "network policy set_pattern"),
    ("network policy_unset_pattern", "network policy unset_pattern"),
    ("network policy_attribute_add", "network policy attribute add"),
    ("network policy_attribute_create", "network policy attribute create"),
    ("network policy_attribute_delete", "network policy attribute delete"),
    ("network policy_attribute_info", "network policy attribute info"),
    ("network policy_attribute_list", "network policy attribute list"),
    ("network policy_attribute_remove", "network policy attribute remove"),
    ("network policy_attribute_set_description", "network policy attribute set_description"),
    ("network community_create", "network community create"),
    ("network community_delete", "network community delete"),
    ("network community_info", "network community info"),
    ("network community_list", "network community list"),
    ("network community_rename", "network community rename"),
    ("network community_set_description", "network community set_description"),
    ("network community_host_add", "network community host add"),
    ("network community_host_remove", "network community host remove"),
]


def resolve(path: str) -> Command:
    """Return the command at `path` in the root CLI command tree."""
    command: Command = cli
    for segment in path.split():
        command = command.children[segment]
    return command


@pytest.mark.parametrize("deprecated,current", DEPRECATED_NETWORK_ALIASES)
def test_deprecated_alias_resolves_to_current_command(deprecated: str, current: str) -> None:
    """Test that a deprecated network alias resolves to its current command."""
    deprecated_func = resolve(deprecated).parser.get_default("func")
    assert deprecated_func is resolve(current).parser.get_default("func")
