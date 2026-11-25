---
name: Bug report
about: Report a defect in rungv, pkg/gvx, a platform backend, or documentation
title: ""
labels: bug
---

## Summary

State the expected behavior and the observed behavior in two or three sentences.

## Environment

- Output of `rungv version`:
- Host OS and version (for example, macOS 15.4, Windows 11 24H2, Ubuntu 24.04):
- Host CPU architecture (`amd64` or `arm64`):
- Execution backend (`hvf`, `whpx`, or `systrap`):

## Minimal Reproduction

Provide the smallest command, OCI image reference, or Go snippet that reproduces the failure.

```sh
# Paste command here
```

## Diagnostics

Attach the terminal output. If a guest fails without a clear message, re-run with `GVX_DEBUG_LOG=1` (or `GVX_SYSTRAP_TRACE=1` on Windows `systrap`) and attach the relevant stderr lines.

> For security vulnerabilities, do not open a public issue. Follow [`SECURITY.md`](../../SECURITY.md) to submit a private GitHub Security Advisory.
