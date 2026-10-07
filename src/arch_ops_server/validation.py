# SPDX-License-Identifier: GPL-3.0-only OR MIT
"""Package-name validation for anything that reaches a pacman/AUR-helper argv."""

import re
from typing import List, Union

# Arch package naming rules: no leading '-' or '.', so a name can't be a flag.
PKG_RE = re.compile(r"^[a-z0-9@_+][a-z0-9@._+-]*$")


def validate_package_names(names: Union[str, List[str]]) -> List[str]:
    """Return names as a list; raise ValueError naming the first bad entry."""
    lst = [names] if isinstance(names, str) else list(names or [])
    if not lst:
        raise ValueError("no package names given")
    for n in lst:
        if not isinstance(n, str) or not PKG_RE.match(n):
            raise ValueError(f"invalid package name: {n!r}")
    return lst
