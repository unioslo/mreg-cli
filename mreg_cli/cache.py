import logging
from typing import Any, Callable, Literal, ParamSpec, Protocol, TypeVar, runtime_checkable

from diskcache import Cache

logger = logging.getLogger(__name__)


P = ParamSpec("P")
T = TypeVar("T")


@runtime_checkable
class CacheLike(Protocol):
    """Interface for `diskcache.Cache`-like objects."""

    def clear(self, retry: bool = False) -> int: ...
    def delete(self, key: str, retry: bool = False) -> bool: ...
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
    def touch(self, key: str, expire: int | float | None = None) -> bool: ...
    def volume(self) -> int: ...


class NullCache:
    """A no-op cache implementation that conforms to the CacheLike protocol.

    Exposes most of the same methods as `diskcache.Cache`.
    """

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

    def evict(self, tag: str, retry: bool = False) -> int:
        return 0

    def clear(self, retry: bool = False) -> int:
        return 0

    def delete(self, key: str, retry: bool = False) -> bool:
        return True

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

    def touch(self, key: str, expire: int | float | None = None) -> bool:
        return True

    def volume(self) -> int:
        return 0


def create_cache() -> CacheLike:
    """Create the global mreg-cli cache.

    Falls back to a no-op cache object if the diskcache cache cannot be created.
    """
    try:
        return Cache()
    except Exception as e:
        logger.exception("Failed to create cache: %s", e)
        return NullCache()


cache = create_cache()
