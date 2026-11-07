## Behavior

<!-- State the one behavior that this PR changes. -->

## Evidence

<!-- Show the failure before the fix and the result after it, with run IDs or commands. -->

## Checklist (AGENTS.md section 6)

- [ ] A Tier 3 change covers one behavior and stays below about 400 changed lines without tests.
- [ ] A person or a reviewer agent that did not write the change reviewed it. The result is in a comment.
- [ ] Tests that check data crossing a boundary get the data from the real producer.
- [ ] A shared format has one definition with named constants.
- [ ] A race fix names its invariant and the callers of each changed helper.
- [ ] A change to accounting, limits, or IDs has a test with two sandboxes in one process.
