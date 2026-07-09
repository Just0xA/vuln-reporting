## Fix PR

> **Issue-first gate:** This PR is **blocked** if the linked issue does not carry the `confirmed-bug` label. See `CONTRIBUTING.md`.

**Fixes #** <!-- issue number -->

## What was broken

<!-- One paragraph describing the defect. Mirror the linked bug report's "What happened?" field. -->

## What the fix does

<!-- One paragraph describing the fix in operator-visible terms (what behavior changes for the user). -->

## Root cause

<!-- The actual underlying cause, not just the symptom. If the fix is a workaround rather than addressing root cause, say so and explain why. -->

## Verification method

<!-- How did you confirm the fix works AND doesn't regress adjacent behavior?
- Did you reproduce the bug first?
- Which tests now pass that didn't before?
- Any manual run against real Tenable? -->

## Regression test

<!-- Required: either link the new test that locks in the fix, OR explicitly justify why a regression test is not feasible (e.g., depends on a specific live-Tenable response shape). -->

## Platforms tested

- [ ] Windows
- [ ] Linux
- [ ] macOS

## Python versions tested

- [ ] 3.10
- [ ] 3.12
- [ ] 3.13+

## Scope confirmation

- [ ] This PR fixes exactly one bug (no bundled features / enhancements).
- [ ] No unrelated formatting / refactor changes are present in the diff.
- [ ] `CHANGELOG.md` updated (or N/A explained below).
- [ ] No real customer / vulnerability / asset data appears in commits, tests, fixtures, or screenshots.

## Breaking changes

<!-- Required. State "None" if accurate. Fixes occasionally are breaking when they correct an outright-wrong behavior — call that out explicitly with a migration note. -->
