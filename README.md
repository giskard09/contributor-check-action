# contributor-check-action

Reusable GitHub composite action: screens the author of a new issue/PR for
account-shape anomalies (age, followers, repo-creation burst/velocity) and
fabricated credential citations (DOI/CVE/repo claims) before a maintainer
reads it by hand.

Architecture follows the pattern proven in `microsoft/agent-governance-toolkit`'s
contributor-check bot (verified against a real case: their bot correctly
flagged HIGH on issue microsoft/agent-governance-toolkit#3301, and this
action reproduces the same HIGH verdict independently on the same account).

## Scope

**In v1:**
- Profile check — account age, followers, fork ratio, day-zero repo burst, sustained repo-creation velocity.
- Credential check — DOI (via Crossref), CVE (via NVD), and cited-repo claims (existence + age relative to the citing comment).

**Explicitly out of scope:** cross-repo cluster/coordination detection. That
pattern (same actor or affiliated actors showing up across multiple repos
with a similar framing) requires our own historical context — GUARDIA_ALTA /
SEGUIMIENTO_ACTIVO — not something derivable from a single profile snapshot.
This action is a first-pass filter, not a replacement for maintainer judgment.

## Usage

```yaml
name: Contributor Check

on:
  pull_request_target:
    types: [opened]
  issues:
    types: [opened]

permissions:
  contents: read

jobs:
  gate:
    runs-on: ubuntu-latest
    outputs:
      run_check: ${{ steps.decide.outputs.run_check }}
    steps:
      - id: decide
        uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1
        with:
          script: |
            try {
              const { data: perm } = await github.rest.repos.getCollaboratorPermissionLevel({
                owner: context.repo.owner,
                repo: context.repo.repo,
                username: context.actor,
              });
              const isMaintainer = perm.role_name === 'admin' || perm.role_name === 'maintain';
              core.setOutput('run_check', isMaintainer ? 'false' : 'true');
            } catch (e) {
              core.setOutput('run_check', 'true');
            }

  check:
    needs: gate
    if: needs.gate.outputs.run_check == 'true'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
      pull-requests: write
    steps:
      - uses: giskard09/contributor-check-action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Security note

`pull_request_target` runs with base-branch permissions against PRs from
unknown forks. This action never checks out the PR's code — only issue/PR
metadata via the GitHub API — and passes the attacker-controlled username
and body through `env:` blocks rather than direct `${{ }}` shell
interpolation, to prevent script injection via a crafted username.

## Local testing

```bash
python scripts/contributor_check.py --username <handle> --body "<issue text>" --json
```
