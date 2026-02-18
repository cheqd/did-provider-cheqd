Combine all open dependabot PRs into a single PR for the current repo.

Follow these steps:

1. List all open dependabot PRs:
   `gh pr list --repo cheqd/did-provider-cheqd --author "dependabot[bot]" --state open`

2. Create a local branch from develop branch:
   `gh pr checkout develop --repo cheqd/did-provider-cheqd --branch dependabot-combined`

3. Apply commits from each remaining PR:
   `gh pr diff <pr-number> --repo cheqd/did-provider-cheqd --patch | git am`

4. Push the branch:
   `git push origin dependabot-combined -u`

5. Create a PR that references all original dependabot PRs. The PR description should only contain a "## Related PRs" section listing each original PR number. Do not include any mention of Claude in the PR description. Do not close the original PRs.