"""Global MregClient accessor for mreg-cli.

The client is constructed once in main() and stored here via set_client().
All other modules retrieve it via get_client() instead of instantiating MregClient directly.
"""

from __future__ import annotations

from collections.abc import Callable, Generator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Literal, overload

from mreg_api import MregClient
from mreg_api.cache import CacheConfig
from mreg_api.events import Event, EventKind, EventLevel
from mreg_api.models import Atom, Host, Network, Role

from mreg_cli.__about__ import __version__
from mreg_cli.exceptions import EntityNotFound as CliEntityNotFound
from mreg_cli.exceptions import TooManyResults

if TYPE_CHECKING:
    from mreg_cli.config import MregCliConfig

_client: MregCliClient | None = None


def _fail_on_truncate(event: Event) -> None:
    """Event hook that raises TooManyResults if the event is a truncation event."""
    if event.kind == EventKind.TRUNCATION:
        raise TooManyResults(f"{event.message} Refine your search.")


def _record_events(event: Event) -> None:
    """Event hook for MregClient to record events in the OutputManager."""
    from mreg_cli.outputmanager import OutputManager  # noqa: PLC0415

    om = OutputManager()
    if om.is_suppressing_events():
        return

    if event.level >= EventLevel.WARNING:
        om.add_warning(event.message)
    elif event.kind == EventKind.MUTATION:
        om.add_ok(event.message)
    else:
        om.add_line(event.message)


class MregCliClient(MregClient):
    """Subclass of MregClient that adds CLI-specific functionality."""

    def _add_listeners(self) -> None:
        """Add event listeners for CLI-specific behavior."""
        self.events.subscribe(_fail_on_truncate)  # fail fast - don't double print
        self.events.subscribe(_record_events)

    @overload
    def resolve_policy(
        self,
        name: str,
        *,
        required: Literal[False],
    ) -> Atom | Role | None: ...

    @overload
    def resolve_policy(
        self,
        name: str,
        *,
        required: Literal[True] = ...,
    ) -> Atom | Role: ...

    @overload
    def resolve_policy(
        self,
        name: str,
        *,
        required: bool = ...,
    ) -> Atom | Role | None: ...

    def resolve_policy(
        self,
        name: str,
        *,
        required: bool = True,
    ) -> Atom | Role | None:
        """Resolve a host policy name to an Atom or Role.

        Resolution order: Atom name → Role name.
        """
        atom = self.atom.get_by_name(name, required=False)
        if atom is not None:
            return atom
        role = self.role.get_by_name(name, required=False)
        if role is not None:
            return role
        if required:
            raise CliEntityNotFound(f"No atom or role named {name!r}.")
        return None

    @overload
    def resolve_host(
        self,
        identifier: str | int,
        *,
        required: Literal[False],
        inform_if_cname: bool = ...,
    ) -> Host | None: ...

    @overload
    def resolve_host(
        self,
        identifier: str | int,
        *,
        required: Literal[True] = ...,
        inform_if_cname: bool = ...,
    ) -> Host: ...

    @overload
    def resolve_host(
        self,
        identifier: str | int,
        *,
        required: bool = ...,
        inform_if_cname: bool = ...,
    ) -> Host | None: ...

    def resolve_host(
        self,
        identifier: str | int,
        *,
        required: bool = True,
        inform_if_cname: bool = False,
    ) -> Host | None:
        """Resolve a host by id, IP, MAC, name, or CNAME target.

        Resolution order: numeric id → IP → MAC → name → CNAME target.
        """
        from mreg_cli.outputmanager import OutputManager  # noqa: PLC0415

        # We got passed an integer, assume host ID
        if isinstance(identifier, int):
            return self.host.get_by_id(identifier, required=required)

        getters: list[Callable[[str], Host | None]] = []
        ident_str = str(identifier)

        # Try by ID first if the identifier is a decimal number
        if ident_str.isdecimal():
            getters.append(lambda s: self.host.get_by_id(int(s), required=False))

        # Try by IP → MAC → name
        getters.extend(
            [
                lambda s: self.host.get_by_ip(s, required=False),
                lambda s: self.host.get_by_mac(s, required=False),
                lambda s: self.host.get_by_name(s, required=False),
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
        cname = self.cname.get_by_name(ident_str, required=False)
        if cname is not None:
            host = self.host.get_by_id(cname.host, required=False)
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
        self,
        identifier: str,
        *,
        required: Literal[False],
    ) -> Network | None: ...

    @overload
    def resolve_network(
        self,
        identifier: str,
        *,
        required: Literal[True] = ...,
    ) -> Network: ...

    @overload
    def resolve_network(
        self,
        identifier: str,
        *,
        required: bool = ...,
    ) -> Network | None: ...

    def resolve_network(
        self,
        identifier: str,
        *,
        required: bool = True,
    ) -> Network | None:
        """Resolve a network by IP address, CIDR notation, or numeric id.

        Resolution order: IP address → CIDR / network address → numeric id.
        """
        network: Network | None = None
        try:
            # Try as IP first
            network = self.network.get_by_ip(identifier, required=False)
        except Exception:
            pass

        if network is None:
            try:
                # Try as CIDR / network address
                network = self.network.get(identifier, required=False)
            except Exception:
                pass

        if network is None and identifier.isdecimal():
            try:
                network = self.network.first(id=int(identifier), required=False)
                # network = self.network.get(int(identifier), required=False)
            except Exception:
                pass

        if network is None and required:
            raise CliEntityNotFound(f"Network {identifier!r} not found.")
        return network


def init_client(config: MregCliConfig) -> MregCliClient:
    """Initialize the global client instance given the config.

    Idempotent: calling this multiple times will return the same client instance.
    """
    global _client
    if _client is None:
        _client = MregCliClient(
            url=config.url,
            domain=config.domain,
            timeout=config.http_timeout,
            user_agent=f"mreg-cli/{__version__}",
            cache=CacheConfig(
                enable=config.cache,
                ttl=config.cache_ttl,
                # other cache settings from config should go here
            ),
        )
        _client._add_listeners()  # pyright: ignore[reportPrivateUsage]
    return _client


# NOTE: maybe add some protection here to prevent calling this in the main loop
# some sort of global state that only allows this to be called in tests?
# That begs the question why we even have this function.
def _reset_client() -> None:  # pyright: ignore[reportUnusedFunction] # in tests
    """Reset the global client instance (for testing)."""
    global _client
    _client = None


def get_client() -> MregCliClient:
    """Return the global client instance.

    :raises RuntimeError: If init_client() has not been called yet.
    """
    if _client is None:
        raise RuntimeError("MregCliClient not initialized — call init_client() first.")
    return _client
