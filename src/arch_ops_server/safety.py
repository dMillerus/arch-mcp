# SPDX-License-Identifier: GPL-3.0-only OR MIT
"""Read-only gate for the MCP server.

The server is read-only unless ARCH_OPS_READONLY=0 is set. The env var is read at
call time so tests and operators can flip it without reloading modules.
"""

import os
from typing import Any

WRITE_TOOLS = frozenset({"install_package_secure", "remove_packages"})

# tool -> actions allowed in read-only mode
MIXED_TOOLS = {
    "manage_orphans": frozenset({"list"}),
    "manage_install_reason": frozenset({"list"}),
}

READ_TOOLS = frozenset({
    "search_archwiki",
    "search_aur",
    "get_official_package_info",
    "check_updates_dry_run",
    "audit_package_security",
    "query_file_ownership",
    "verify_package_integrity",
    "manage_groups",
    "get_system_info",
    "analyze_storage",
    "diagnose_system",
    "fetch_news",
    "query_package_history",
    "optimize_mirrors",
    "analyze_pacman_conf",
    "analyze_makepkg_conf",
    "check_database_freshness",
    "run_system_health_check",
})


def readonly_enabled() -> bool:
    """True unless ARCH_OPS_READONLY is explicitly set to "0"."""
    return os.getenv("ARCH_OPS_READONLY", "1") != "0"


def check_allowed(name: str, arguments: dict[str, Any] | None) -> str | None:
    """Return a refusal message if the call is blocked, else None.

    Fails closed: a tool not classified in READ_TOOLS, MIXED_TOOLS or WRITE_TOOLS
    is refused in every mode until it is classified here.
    """
    readonly = readonly_enabled()
    hint = "This server is read-only. Set ARCH_OPS_READONLY=0 in the server environment to enable write operations."
    if name in READ_TOOLS:
        return None
    if name in WRITE_TOOLS:
        return f"Tool '{name}' is disabled: {hint}" if readonly else None
    if name in MIXED_TOOLS:
        if not readonly:
            return None
        args = arguments or {}
        if args.get("action") not in MIXED_TOOLS[name]:
            return f"Action {args.get('action')!r} of '{name}' is disabled: {hint}"
        if name == "manage_orphans" and args.get("dry_run") is False:
            return f"'{name}' with dry_run=false is disabled: {hint}"
        return None
    return f"Tool '{name}' is not classified in the safety allowlist and is refused (fail closed)."
