"""Host, network, and policy resolution helpers for mreg-cli.

These replace the old get_by_any_means* class methods that lived on the mreg_api models.
The CLI is responsible for composing the heuristic lookup chain.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Literal, overload

from mreg_api import MregClient
from mreg_api.models import Atom, Host, Network, Role

from mreg_cli.exceptions import EntityNotFound as CliEntityNotFound

if TYPE_CHECKING:
    pass


@overload
def resolve_host(
    client: MregClient,
    identifier: str | int,
    *,
    required: Literal[False],
    inform_if_cname: bool = ...,
) -> Host | None: ...


@overload
def resolve_host(
    client: MregClient,
    identifier: str | int,
    *,
    required: Literal[True] = ...,
    inform_if_cname: bool = ...,
) -> Host: ...


@overload
def resolve_host(
    client: MregClient,
    identifier: str | int,
    *,
    required: bool = ...,
    inform_if_cname: bool = ...,
) -> Host | None: ...


def resolve_host(
    client: MregClient,
    identifier: str | int,
    *,
    required: bool = True,
    inform_if_cname: bool = False,
) -> Host | None:
    """Resolve a host by id, IP, MAC, name, or CNAME target.

    Replaces Host.get_by_any_means() / get_by_any_means_or_raise().

    Resolution order: numeric id → IP → MAC → name → CNAME target.
    """
    from mreg_cli.outputmanager import OutputManager

    # We got passed an integer, assume host ID
    if isinstance(identifier, int):
        return client.host.get_by_id(identifier, required=required)

    getters: list[Callable[[str], Host | None]] = []
    ident_str = str(identifier)

    # Try by ID first if the identifier is a decimal number
    if ident_str.isdecimal():
        getters.append(lambda s: client.host.get_by_id(int(s), required=False))

    # Try by IP → MAC → name
    getters.extend(
        [
            lambda s: client.host.get_by_ip(s, required=False),
            lambda s: client.host.get_by_mac(s, required=False),
            lambda s: client.host.get_by_name(s, required=False),
        ]
    )

    for getter in getters:
        try:
            host = getter(ident_str)
            if host is not None:
                return host
        except Exception:
            pass

    # Fall back to CNAME
    cname = client.cname.get_by_name(ident_str, required=False)
    if cname is not None:
        host = client.host.get_by_id(cname.host, required=False)
        # NOTE: should it be an error if CNAME has host ID that doesn't exist? Probably.
        # At the very least produce a warning if CNAME host ID cannot be resolved.
        if host is not None:
            if inform_if_cname:
                OutputManager().add_line(f"{ident_str!r} is a CNAME for {host.name!r}")
            return host

    if required:
        raise CliEntityNotFound(f"Host {identifier!r} not found.")

    return None


@overload
def resolve_network(
    client: MregClient,
    identifier: str,
    *,
    required: Literal[False],
) -> Network | None: ...


@overload
def resolve_network(
    client: MregClient,
    identifier: str,
    *,
    required: Literal[True] = ...,
) -> Network: ...


@overload
def resolve_network(
    client: MregClient,
    identifier: str,
    *,
    required: bool = ...,
) -> Network | None: ...


def resolve_network(
    client: MregClient,
    identifier: str,
    *,
    required: bool = True,
) -> Network | None:
    """Resolve a network by IP address, CIDR notation, or numeric id.

    Replaces Network.get_by_any_means() / get_by_any_means_or_raise().
    """
    from mreg_cli.exceptions import EntityNotFound as CliEntityNotFound

    network: Network | None = None
    try:
        # Try as IP first
        network = client.network.get_by_ip(identifier, required=False)
    except Exception:
        pass

    if network is None:
        try:
            # Try as CIDR / network address
            network = client.network.get(identifier, required=False)
        except Exception:
            pass

    if network is None and identifier.isdigit():
        try:
            network = client.network.first(id=int(identifier), required=False)
            # network = client.network.get(int(identifier), required=False)
        except Exception:
            pass

    if network is None and required:
        raise CliEntityNotFound(f"Network {identifier!r} not found.")
    return network


@overload
def resolve_policy(
    client: MregClient,
    name: str,
    *,
    required: Literal[False],
) -> Atom | Role | None: ...


@overload
def resolve_policy(
    client: MregClient,
    name: str,
    *,
    required: Literal[True] = ...,
) -> Atom | Role: ...


@overload
def resolve_policy(
    client: MregClient,
    name: str,
    *,
    required: bool = ...,
) -> Atom | Role | None: ...


def resolve_policy(
    client: MregClient,
    name: str,
    *,
    required: bool = True,
) -> Atom | Role | None:
    """Resolve a host policy name to an Atom or Role.

    Replaces HostPolicy.get_role_or_atom_or_raise().
    Atom is checked first (old order).
    """
    atom = client.atom.get_by_name(name, required=False)
    if atom is not None:
        return atom
    role = client.role.get_by_name(name, required=False)
    if role is not None:
        return role
    if required:
        raise CliEntityNotFound(f"No atom or role named {name!r}.")
    return None
