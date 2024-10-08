"""Utility functions for mreg_cli.

Due to circular dependencies, be very aware of what you import here.

"""

from __future__ import annotations

from mreg_cli.config import MregCliConfig


def is_valid_location_tag(loc: str) -> bool:
    """Check if valid location tag."""
    return loc in MregCliConfig().get_location_tags()


def is_valid_category_tag(cat: str) -> bool:
    """Check if valid location tag."""
    return cat in MregCliConfig().get_category_tags()
