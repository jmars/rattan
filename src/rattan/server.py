"""FastMCP facade for rattan.

Registers the MCP tool surface (``env_status`` in M0) and gates server startup
on the required host capabilities. The ``--probe`` path reuses the stdlib-only
``capabilities`` probe so it runs without the MCP stack when invoked via the
module entry point.
"""

from __future__ import annotations

import sys

from mcp.server.fastmcp import FastMCP

from rattan import capabilities, config


def _gate_or_raise(table):
    """Raise RuntimeError if any required capability is missing."""
    missing = table.missing_required()
    if not missing:
        return
    lines = ["Refusing to start rattan: missing required capabilities:"]
    for c in missing:
        rem = f" {c.remediation}" if c.remediation else ""
        lines.append(f"  - {c.name}: {c.detail}{rem}")
    raise RuntimeError("\n".join(lines))


def _build_tool(fastmcp):
    @fastmcp.tool(
        description=(
            "Report the sandbox environment status: session info placeholder, "
            "the host capability probe summary, and the network policy "
            "placeholder."
        )
    )
    def env_status() -> dict:
        table = capabilities.get_capabilities()
        return {
            "session": {
                "id": None,
                "note": "M0 placeholder - session lifecycle arrives in M3",
            },
            "capabilities": table.to_dict(),
            "network_policy": {
                "agent": "unshare-net (no network) - M3",
                "provisioning": "share-net - M4",
            },
        }


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if "--probe" in args:
        return capabilities.cli_main(args)

    table = capabilities.get_capabilities()
    _gate_or_raise(table)

    # Gate on base rootfs integrity: refuse to start if the immutable base has
    # drifted (or was never bootstrapped).
    config.validate_base_manifest()

    fastmcp = FastMCP("rattan")
    _build_tool(fastmcp)
    fastmcp.run()
    return 0
