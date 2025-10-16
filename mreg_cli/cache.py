from __future__ import annotations

import functools
import logging
from dataclasses import dataclass
from types import ModuleType
from typing import Any, Callable, Literal, ParamSpec, Protocol, Self, TypeVar, runtime_checkable

from diskcache import Cache
from pydantic import BaseModel, ByteSize, field_serializer

from mreg_cli.config import MregCliConfig

logger = logging.getLogger(__name__)


P = ParamSpec("P")
T = TypeVar("T")

_CACHE: MregCliCache | None = None
"""The global cache object. Instantiated by `configure()`."""


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
        """Returns a decorator that does nothing."""

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


def _create_cache(config: MregCliConfig) -> CacheLike:
    """Create the global mreg-cli cache.

    Falls back to a no-op cache object if the diskcache cache cannot be created.
    """
    if not config.cache:
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

    cache = _create_cache(config)
    _CACHE = MregCliCache(cache)  # pyright: ignore[reportConstantRedefinition]

    if not config.cache:
        logger.debug("Cache is disabled in configuration, not configuring cache.")
        return

    # Enable cache and patch functions
    _CACHE.enable()


def get_cache() -> MregCliCache:
    """Get the global mreg-cli cache."""
    # return a temp cache if cache is not yet configured
    if _CACHE is None:
        logger.debug("Cache not yet configured, returning temporary NullCache.")
        return MregCliCache(NullCache())
    return _CACHE


@dataclass
class MemoizedFunction:
    """A function to be memoized."""

    func: str  # full module path (i.e. `mreg_cli.foo.bar.do_expensive_thing`)
    tag: str  # the tag to give the cached result


@dataclass
class StoredFunction:
    """A function that has been stored in the cache."""

    module: ModuleType
    func: Callable[..., Any]


TO_MEMOIZE = [
    MemoizedFunction(func="mreg_cli.utilities.api._do_get", tag="api"),
]
"""List functions to memoize with a caching decorator (if enabled)."""


class MregCliCache:
    """Wrapper around the mreg-cli cache."""

    def __init__(self, cache: CacheLike):
        self.cache = cache

        self._original: dict[str, StoredFunction] = {}
        """Original functions, before they were patched. Keys are the full module paths + symbol names."""

    def get_info(self) -> CacheInfo:
        """Get information about the cache."""
        hits, misses = self.cache.stats()
        conf = MregCliConfig()

        return CacheInfo(
            size=self.cache.volume(),  # pyright: ignore[reportArgumentType] # validator converts type
            hits=hits,
            misses=misses,
            items=len(self.cache),
            directory=self.cache.directory,
            ttl=conf.cache_ttl,
        )

    def _patch_functions(self) -> None:
        for func in TO_MEMOIZE:
            self.memoize_function(func)

    def _unpatch_functions(self) -> None:
        for mod_path in self._original.keys():
            self.restore_original_function(mod_path)

    def enable(self) -> None:
        """Enable caching by patching functions with memoized versions."""
        self._patch_functions()
        logger.info("Cache enabled")

    def disable(self, *, clear: bool = True) -> None:
        """Disable caching by restoring patched functions and clearing the cache."""
        self._unpatch_functions()
        if clear:
            self.clear()
        logger.info("Cache disabled")

    def clear(self) -> None:
        """Clear the cache and reset statistics."""
        self.cache.clear()
        self.cache.stats(reset=True)

    def load_module_and_function(
        self, func: MemoizedFunction
    ) -> tuple[ModuleType, Callable[..., Any]]:
        """Load the module and function from a MemoizedFunction."""
        try:
            module, func_name = func.func.rsplit(".", 1)
            mod = __import__(module, fromlist=[func_name])
            return mod, getattr(mod, func_name)
        except Exception as e:
            logger.exception("Failed to load module and function: %s", e)
            raise e

    def save_original_function(
        self, module_path: str, module: ModuleType, func: Callable[..., Any]
    ) -> None:
        """Save the original function before it is patched."""
        self._original[module_path] = StoredFunction(module=module, func=func)

    def load_original_function(self, module_path: str) -> StoredFunction | None:
        """Load the original function from its pre-patch state."""
        return self._original.get(module_path)

    def restore_original_function(self, module_path: str) -> None:
        """Restore an function to its pre-patch state."""
        if original := self.load_original_function(module_path):
            # Set the function back to its original state
            try:
                self._do_patch(original.module, original.func)
            except Exception as e:
                logger.exception("Failed to restore original function: %s", e)

    def patch_function(self, module: ModuleType, func: Callable[..., Any]) -> None:
        """Patch a function in a module."""
        try:
            self._do_patch(module, func)
        except Exception as e:
            logger.exception("Failed to patch function: %s", e)

    def _do_patch(self, module: ModuleType, func: Callable[..., Any]) -> None:
        """Patch a function in a module."""
        setattr(module, func.__name__, func)

    def memoize_function(self, memfunc: MemoizedFunction) -> None:
        """Memoize a given function."""
        config = MregCliConfig()

        mod_path = memfunc.func
        mod, func = self.load_module_and_function(memfunc)

        original = self.load_original_function(mod_path)
        if original is not None:
            # Restore function to its original state before patching
            self.restore_original_function(mod_path)

        # Store a copy of the original function before patching
        self.save_original_function(mod_path, mod, func)

        self.patch_function(
            mod, self.cache.memoize(expire=config.cache_ttl, tag=memfunc.tag)(func)
        )


def disable_cache(func: Callable[P, T]) -> Callable[P, T]:
    """Disable cache for the duration of the decorated function."""

    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        cache = get_cache()
        try:
            cache.disable(clear=False)
            return func(*args, **kwargs)
        finally:
            cache.enable()

    return wrapper
