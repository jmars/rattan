# Rattan

A greenfield MCP server providing a shell sandbox: an Arch Linux rootfs with a
working `pacman`, layered on **seccomp (pledge-style) + user namespaces +
bubblewrap + Landlock + overlayfs**. Agent changes to the container are **lost
by default** unless an explicit `env_commit` is requested.

## Docs

- **[`docs/architecture.md`](docs/architecture.md)** — the full architecture:
  layering, process/lifecycle model, pacman provisioning split, COW/commit
  semantics, MCP tool surface, module layout, security invariants.
- **[`docs/implementation-plan.md`](docs/implementation-plan.md)** — the
  concrete build plan: milestones (M0–M5), code-level tickets, dependency
  graph, risk register, definition of done.

## Status

Planning stage. No code yet. See the implementation plan for the build
sequence; M1 (spike + `stage3` inner binary) de-risks the load-bearing unknowns
before any production code.
