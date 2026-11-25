## Summary

<!-- State the one behavior or documentation improvement introduced by this pull request. -->

## Related Issue

<!-- Link the issue addressed, for example: Closes #123 -->

## Verification

<!-- List the commands run locally or the CI run IDs. For bug fixes, record the observed failure before the change and the passing result after it. -->

## First-Time Contributor Steps

If this is your first pull request to `gvx`, consult [`CONTRIBUTING.md`](../CONTRIBUTING.md) before requesting review:

- [ ] Formatted Go code (`go fmt ./...`) or verified Markdown prose (no em-dashes and all relative links resolve).
- [ ] Confirmed the change targets the owning package documented in [`docs/architecture.md`](../docs/architecture.md).

## Maintainer Checklist (`AGENTS.md` Section 6)

Complete every item applicable to this change (mark non-applicable items with N/A):

- [ ] A Tier 3 change covers one behavior and stays below roughly 400 changed lines excluding tests and generated files.
- [ ] A person or reviewer agent other than the author reviewed Tier 3, platform, signal, memory, or locking changes, with the result recorded in a comment.
- [ ] Tests checking cross-boundary data obtain inputs from the real producer (platform, kernel, or guest probe).
- [ ] Shared binary or memory formats have one canonical definition with named constants.
- [ ] Concurrency fixes name the restored invariant and audit all callers of modified helpers.
- [ ] Changes to accounting, limits, or IDs include a test running two sandboxes concurrently in one process.
