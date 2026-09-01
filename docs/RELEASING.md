# Releasing

Publishing is automated but deliberately not automatic: `.github/workflows/release.yml` runs when a GitHub Release is **published**, builds the distributions, and uploads them to PyPI through Trusted Publishing.

## One-time PyPI setup

CodeSnake publishes with **Trusted Publishing (OIDC)** rather than an API token. There is no secret stored in this repository — PyPI verifies a short-lived token minted by GitHub for this specific workflow. A stolen repository secret cannot publish, because there isn't one.

Before the first release, add a pending publisher at
<https://pypi.org/manage/account/publishing/> with exactly these values:

| Field | Value |
|---|---|
| PyPI project name | `codesnake` |
| Owner | `bitWarrior` |
| Repository name | `codesnake` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

All five must match or PyPI rejects the token exchange. The environment name is the one that gets forgotten.

Consider claiming the name with a release to [TestPyPI](https://test.pypi.org) first, using the same flow with `repository-url: https://test.pypi.org/legacy/` on the publish step.

## Cutting a release

1. Bump `__version__` in `src/codesnake/_version.py`. That is the only place the version lives; `pyproject.toml` reads it via `tool.setuptools.dynamic`.
2. Open a PR with the bump and merge it once CI is green.
3. Tag the merge commit and push the tag:
   ```bash
   git tag -a v1.3.0 -m "CodeSnake 1.3.0"
   git push origin v1.3.0
   ```
4. Publish a GitHub Release on that tag with notes. Publishing is what starts the workflow.
5. Approve the `pypi` deployment when GitHub asks.

If the release event does not start a run, or a publish failed and you want to retry
without recreating the Release, dispatch it manually with the same tag:

```bash
gh workflow run release.yml -f tag=v1.3.0
```

Both paths run the identical build, the identical tag/version guard, and the same
environment approval.

The build job refuses to publish when the release tag and `_version.py` disagree, so a `v1.3.0` tag cannot ship a `1.2.0` artifact.

## What protects the release path

- **Trusted Publishing** — no long-lived credential exists to steal.
- **The `pypi` environment** — deployments are restricted to `v*` tags, and the publish job is the only thing granted `id-token: write`.
- **Split jobs** — the build job has `contents: read` and no OIDC; the publish job has OIDC and never checks out the repository. Code from the repo and the ability to publish never sit in the same job.
- **Pinned actions** — every action is pinned to a commit SHA, not a mutable tag.

### Still to enable

**Required reviewers on the `pypi` environment.** This is what makes publishing need a human, and it is the single most valuable control here. Environment protection rules are unavailable on private repositories on a free plan; add the rule as soon as the repository is public:

```bash
gh api -X PUT repos/bitWarrior/codesnake/environments/pypi \
  -f 'reviewers[][type]=User' -F 'reviewers[][id]=164793'
```

Until then, publishing a GitHub Release ships to PyPI without a second gate.
