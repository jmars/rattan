"""Rattan — an MCP server providing a shell sandbox.

Layered on seccomp (pledge-style) + user namespaces + bubblewrap + Landlock +
overlayfs, with an Arch Linux rootfs and a working pacman.
"""

__version__ = "0.1.0"
