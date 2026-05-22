"""Cache output functions."""

from __future__ import annotations

from mreg_api.cache import CacheInfo

from mreg_cli.outputmanager import OutputManager


def output_cache_info(cache_info: CacheInfo) -> None:
    """Output cache information to the console."""
    output_manager = OutputManager()
    output_manager.add_formatted_table(
        headers=["Items", "Hits", "Misses", "Size", "TTL", "Directory"],
        keys=["items", "hits", "misses", "size", "ttl", "directory"],
        data=[cache_info],
    )
