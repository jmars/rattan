"""Entry point for ``python3 -m rattan``.

The ``--probe`` path runs entirely through ``capabilities`` (stdlib-only) so the
host capability probe works even where the MCP stack is not installed. Any other
invocation delegates to ``server.main``, which starts the FastMCP server.
"""

import sys


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if "--probe" in args:
        from palisade import capabilities

        return capabilities.cli_main(args)
    from rattan.server import main as server_main

    return server_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
