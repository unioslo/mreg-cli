from __future__ import annotations

import logging
from typing import Any, Callable, Literal, ParamSpec, Protocol, Self, TypeVar, runtime_checkable

from diskcache import Cache
from pydantic import BaseModel, ByteSize, field_serializer

from mreg_cli.config import MregCliConfig

logger = logging.getLogger(__name__)


P = ParamSpec("P")
T = TypeVar("T")

_CACHE: CacheLike | None = None
"""The global cache object. Instantiated by `configure()`."""


_ORIGINAL_API_DO_GET: Callable[..., Any] | None = None
"""Holds the original `mreg_cli.utilities.api._do_get` function before it is memoized."""


@runtime_checkable
class CacheLike(Protocol):
    """Interface for `diskcache.Cache`-like objects."""

    def __len__(self) -> Any: ...
    def clear(self, retry: bool = False) -> int: ...
    def delete(self, key: str, retry: bool = False) -> bool: ...
    @property
    def directory(self) -> str: ...
    @property
    def disk(self) -> Any: ...
    def get(self, key: str, default: str | None = None) -> Any: ...
    def evict(self, tag: str, retry: bool = False) -> int: ...
    def memoize(
        self,
        name: str | None = None,
        typed: bool = False,
        expire: int | float | None = None,
        tag: str | None = None,
        ignore: tuple[str, ...] = (),
    ) -> Any: ...
    def set(
        self,
        key: str,
        value: Any,
        expire: int | float | None = None,
        read: bool = False,
        tag: str | None = None,
        retry: bool = False,
    ) -> Literal[True]: ...
    def stats(self, enable: bool = True, reset: bool = False) -> tuple[Any, Any]: ...
    def touch(self, key: str, expire: int | float | None = None) -> bool: ...
    def volume(self) -> int: ...


class NullCache:
    """A no-op cache implementation that conforms to the CacheLike protocol.

    Exposes most of the same methods as `diskcache.Cache`.
    """

    def __len__(self) -> int:
        return 0

    def memoize(
        self,
        name: str | None = None,
        typed: bool = False,
        expire: int | float | None = None,
        tag: str | None = None,
        ignore: tuple[str, ...] = (),
    ) -> Callable[[Callable[P, T]], Callable[P, T]]:
        """Returns a decorator that does nothing"""

        def decorator(func: Callable[P, T]) -> Callable[P, T]:
            return func  # Just return the original function unchanged

        return decorator

    def clear(self, retry: bool = False) -> int:
        return 0

    @property
    def directory(self) -> str:
        return ""

    @property
    def disk(self) -> Any:
        return self

    def delete(self, key: str, retry: bool = False) -> bool:
        return True

    def evict(self, tag: str, retry: bool = False) -> int:
        return 0

    def get(self, key: str, default: str | None = None) -> str | None:
        return default

    def set(
        self,
        key: str,
        value: Any,
        expire: int | float | None = None,
        read: bool = False,
        tag: str | None = None,
        retry: bool = False,
    ) -> Literal[True]:
        return True

    def stats(self, enable: bool = True, reset: bool = False) -> tuple[int, int]:
        return (0, 0)

    def touch(self, key: str, expire: int | float | None = None) -> bool:
        return True

    def volume(self) -> int:
        return 0


class CacheInfo(BaseModel):
    """Information about the cache."""

    items: int
    size: ByteSize
    hits: int
    misses: int
    ttl: int
    directory: str

    @field_serializer("size")
    def serialize_size(self, value: ByteSize) -> str:
        return value.human_readable()

    def as_table_args(self) -> tuple[list[str], list[str], list[Self]]:
        """Get a tuple of string arguments for table display."""
        return (
            ["Items", "Hits", "Misses", "Size", "TTL", "Directory"],
            ["items", "hits", "misses", "size", "ttl", "directory"],
            [self],
        )


def get_cache_info(cache: CacheLike | None = None) -> CacheInfo:
    """Get information about the cache.

    Defaults to using the global `cache` object if no argument is provided.
    """
    if cache is None:
        cache = get_cache()

    hits, misses = cache.stats()
    conf = MregCliConfig()

    return CacheInfo(
        size=cache.volume(),  # pyright: ignore[reportArgumentType] # validator converts type
        hits=hits,
        misses=misses,
        items=len(cache),
        directory=cache.directory,
        ttl=conf.get_cache_ttl(),
    )


def _create_cache(config: MregCliConfig) -> CacheLike:
    """Create the global mreg-cli cache.

    Falls back to a no-op cache object if the diskcache cache cannot be created.
    """
    if not config.get_cache_enabled():
        logger.debug("Cache is disabled in configuration, using NullCache.")
        return NullCache()

    try:
        return Cache()
    except Exception as e:
        logger.exception("Failed to create cache: %s", e)
        return NullCache()


def configure(config: MregCliConfig) -> None:
    """Configure the cache."""
    global _CACHE
    if _CACHE is not None:
        return

    _CACHE = _create_cache(config)  # pyright: ignore[reportConstantRedefinition]

    if not config.get_cache_enabled():
        logger.debug("Cache is disabled in configuration, not configuring cache.")
        return
    cache_api_get(_CACHE, config)


def cache_api_get(cache: CacheLike, config: MregCliConfig) -> None:
    """Memoize the mreg_cli.utilities.api._do_get function."""
    import mreg_cli.utilities.api

    global _ORIGINAL_API_DO_GET

    _ORIGINAL_API_DO_GET = mreg_cli.utilities.api._do_get  # pyright: ignore[reportConstantRedefinition]

    # Patch the mreg_cli.utilities.api._do_get function
    mreg_cli.utilities.api._do_get = cache.memoize(expire=config.get_cache_ttl(), tag="api")(
        _ORIGINAL_API_DO_GET
    )


def get_cache() -> CacheLike:
    """Get the global mreg-cli cache."""
    # return a temp cache if cache is not yet configured
    if _CACHE is None:
        logger.debug("Cache not yet configured, returning temporary NullCache.")
        return NullCache()
    return _CACHE
