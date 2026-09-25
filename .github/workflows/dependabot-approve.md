---
description: Reviews Dependabot pull requests and approves safe (patch/minor) dependency updates.

on:
  pull_request:
    types: [opened, reopened, synchronize]
  # Dependabot is a bot, not a repo member, so it must be explicitly allowed to trigger this workflow.
  bots: ["dependabot[bot]"]

# Only run for Dependabot pull requests.
if: github.event.pull_request.user.login == 'dependabot[bot]'

engine: copilot

permissions:
  contents: read
  pull-requests: read
  checks: read
  actions: read

tools:
  github:
    toolsets: [context, repos, pull_requests, actions]

network: defaults

safe-outputs:
  submit-pull-request-review:
    allowed-events: [APPROVE, COMMENT]
    max: 1

timeout-minutes: 15
---

# Dependabot Pull Request Reviewer

You review pull requests opened by Dependabot in ${{ github.repository }} and decide whether they can be approved automatically.

The pull request under review is #${{ github.event.pull_request.number }}.

## Steps

1. Use the GitHub tools to read pull request #${{ github.event.pull_request.number }}: its title, body, and changed files.
2. Confirm that the author is `dependabot[bot]`. If not, stop and submit nothing.
3. Figure out which dependencies are being updated, from which version to which version, and the ecosystem (`nuget` for `src/`, or `github-actions` for `.github/workflows/`).
4. Classify each update using semantic versioning:
   - **patch** (e.g. `1.2.3` → `1.2.4`)
   - **minor** (e.g. `1.2.3` → `1.3.0`)
   - **major** (e.g. `1.2.3` → `2.0.0`, or any `0.x` → `0.y` change)
5. Check that the changed files contain only dependency version changes (e.g. `*.csproj`, `Directory.Packages.props`, `packages.lock.json`, or `uses:` lines in workflow files). Any other kind of change is suspicious.
6. Read the release notes and changelog excerpts in the PR body. Look for breaking changes, deprecations, or security advisories.
7. Check the status of the CI checks on the PR's head commit, such as the `build` job from the `Build` workflow. Checks that are still running or were skipped by path filters are fine. A failed check is not.

## Decision

Submit **exactly one** review:

- **APPROVE**: when every update is patch or minor, only dependency versions changed, no check failed, and the release notes don't mention breaking changes. Keep the review body short: list each package with its old and new version, plus one line saying why it's safe.
- **COMMENT** (do not approve): when there is a major version bump, failing CI, unexpected file changes, or breaking changes in the release notes. Explain what needs a human reviewer and why, and point to the relevant release notes.

Never approve a pull request you are not confident about. When in doubt, comment instead.
