# Integrating CodeSnake

Recipes for running CodeSnake automatically. They assume an install (`pip install -e .` from a checkout, or `pip install -e ".[tools]"` for Bandit support) so `codesnake` is on `PATH`; `python -m codesnake` works everywhere `codesnake` does.

Two facts shape every recipe:

- The **exit code is 1 only for error-severity findings** (plus I/O, syntax, config, and git failures). Warnings and info never fail a run. There is no `--fail-on warning` flag yet; if you need that, parse `--format json` and look at `summary.warnings`.
- **Paths depend on the format.** `--format github` and `--format sarif` emit paths relative to the working directory, so run them from the repository root and the locations will match the checkout. The `text` and `json` formats print paths as you passed them for explicit file arguments, but resolved *absolute* paths when you pass a directory — parse with that in mind.

## Git pre-commit hook

`--staged` asks git for the staged `*.py` files itself and works from any directory inside the repository. With nothing staged it exits 0.

It reads those files **from the working tree**, not from the staged blobs, so with a partial `git add -p` — or an edit made after staging — the hook judges code that is not being committed. The pre-commit framework below avoids this by stashing unstaged changes.

`.git/hooks/pre-commit`:

```sh
#!/bin/sh
exec codesnake check --staged --no-color
```

```bash
chmod +x .git/hooks/pre-commit
```

Add `--severity error` to print only what will block the commit.

### With the pre-commit framework

`.pre-commit-config.yaml`, using the `codesnake` already installed in your environment:

```yaml
repos:
  - repo: local
    hooks:
      - id: codesnake
        name: codesnake
        entry: codesnake check --no-color
        language: system
        types: [python]
```

To have pre-commit manage the install instead, use `language: python` with
`additional_dependencies: ["git+https://github.com/bitWarrior/codesnake@v1.3.0"]`.

## GitHub Actions

`.gitignore` is applied only to files git does not track, matching git's own rule that an ignore pattern has no effect on a committed file. A file added with `git add -f`, or a tracked file inside an ignored directory, is analyzed by a plain `codesnake check src/` — no flag required. This is what stops a pull request from hiding code from the gate by ignoring it and force-adding it.

Two variations are still useful:

```bash
# Also cover UNTRACKED ignored files, e.g. generated code you want linted anyway
codesnake check --no-ignore --severity error --no-color src/

# Exactly what git tracks, and nothing else
codesnake check --no-color --severity error $(git ls-files '*.py')
```

Run the `git ls-files` form from the repository root. If it expands to nothing, CodeSnake exits 2 (`no files to check`); the directory form does not have that empty-tree edge.

### Inline annotations

`--format github` prints workflow commands; GitHub turns them into annotations on the PR diff. This repository's own `.github/workflows/ci.yml` does exactly this.

```yaml
name: codesnake
on: [push, pull_request]

jobs:
  codesnake:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v7
        with:
          python-version: "3.12"
      - run: pip install "git+https://github.com/bitWarrior/codesnake@v1.3.0"
      - run: codesnake check --format github --no-color src/
```

### Code scanning (SARIF)

Upload SARIF so findings appear under **Security → Code scanning**. The `|| true` keeps the upload step running when errors are found; the job then fails on the following line.

```yaml
    permissions:
      contents: read
      security-events: write
    steps:
      # ... checkout / setup-python / install as above
      - run: codesnake check --format sarif --no-color src/ > codesnake.sarif || true
      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: codesnake.sarif
      - run: codesnake check --severity error --no-color --no-ignore src/
```

### Only fail on new findings

Commit a baseline once, then check against it:

```bash
codesnake check --update-baseline .codesnake-baseline.json src/
git add .codesnake-baseline.json
```

Baselines store paths relative to the working directory, so write and read them from the **same** directory — the repository root, to match CI. A baseline recorded at the root suppresses nothing when the check is later run from inside `src/`. (This is why `--baseline` does not belong in the `--staged` hook above without pinning the directory first.)

```yaml
      - run: codesnake check --baseline .codesnake-baseline.json --format github --no-color --no-ignore src/
```

A fingerprint is the file path, the rule code, the message with digits normalized away, and an occurrence index. Line numbers and numeric counts therefore do not matter — edits above a finding, or a complexity score drifting from 15 to 16, will not re-fail CI. Anything else does: moving code to another file, or a rename that changes an identifier quoted in the message (`Unused import 'os'`), mints a new fingerprint even though the finding is unchanged. A genuinely *new* violation (including a second identical one in the same file) fails too. Refresh the baseline with `--update-baseline` as you pay down the backlog.

## Other CI systems

Any runner can consume the JSON report:

```bash
codesnake check --format json --no-color src/ > codesnake.json
```

Per-file issues live under `files[].issues[]`; totals under `summary`. Set `NO_COLOR=1` in the job environment instead of `--no-color` if you prefer.

## VS Code

`.vscode/tasks.json` — a task whose problem matcher reads the `github` format, so findings land in the Problems panel and are clickable. VS Code's matcher understands only `error`/`warning`/`info` severities, so pass `--severity warning` to drop `notice` lines. `"fileLocation": "autoDetect"` resolves both the relative paths the `github` format emits under `cwd` and any absolute path that comes back from outside it.

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "CodeSnake: check src",
      "type": "shell",
      "command": "codesnake",
      "args": ["check", "--format", "github", "--no-color", "--severity", "warning", "src"],
      "options": { "cwd": "${workspaceFolder}" },
      "problemMatcher": {
        "owner": "codesnake",
        "fileLocation": "autoDetect",
        "pattern": {
          "regexp": "^::(error|warning) file=([^,]+),line=(\\d+),col=(\\d+).*::(.*)$",
          "severity": 1,
          "file": 2,
          "line": 3,
          "column": 4,
          "message": 5
        }
      },
      "group": { "kind": "test", "isDefault": true }
    }
  ]
}
```

Run it with **Terminal → Run Task**, or bind it in `keybindings.json`:

```json
[
  { "key": "ctrl+shift+s", "command": "workbench.action.tasks.runTask", "args": "CodeSnake: check src" }
]
```

## Makefile

```makefile
.PHONY: lint lint-errors lint-baseline lint-json

lint:            ## everything, human-readable
	codesnake check src/ test/

lint-errors:     ## only what would fail CI
	codesnake check --severity error --no-ignore src/

lint-baseline:   ## only findings not in the committed baseline
	codesnake check --baseline .codesnake-baseline.json src/

lint-json:
	codesnake check --format json --no-color src/ > codesnake.json
```

## Adopting CodeSnake on an existing codebase

1. **Snapshot** the current state: `codesnake check --update-baseline .codesnake-baseline.json src/` and commit the file. CI now fails only on new findings.
2. **Tune** thresholds in `.codesnake.json` (or `[tool.codesnake]` in `pyproject.toml`) rather than living with noise — `report_info: false` and a higher `max_complexity` are common first moves. Turn whole categories off with `check_style`, `check_complexity`, and friends.
3. **Suppress deliberately** with `# noqa: CODE` on the line (or `# codesnake: ignore=CODE`), never a bare `# noqa` unless every finding on that line is intentional.
4. **Shrink the baseline** as you fix things; re-run `--update-baseline` after each cleanup.
5. **Tighten** once the backlog is gone: lower thresholds, enable info, drop the baseline.

## Alongside other tools

`pip install -e ".[tools]"` installs Bandit, flake8, pylint, mypy, and isort. `codesnake check --bandit` merges Bandit's findings into the same report (marked `source: bandit`, honoring the same `# noqa` lines). Overlap to expect:

| Tool | Overlaps with |
|---|---|
| flake8 / pyflakes | IMP002 (F401), VAR001 (F841), IMP001 (F403), EXC001 (E722) |
| Bandit | SEC001–SEC004, with broader coverage of libraries |
| radon / mccabe | COMP002 (cyclomatic complexity) |
| pylint | most complexity and unused-name rules, at higher cost |

CodeSnake's differentiators are the taint tracking behind SEC001/SEC003 severities, the cross-file IMP003 check, and having no dependencies.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Too many findings | Baseline first, then tune thresholds and `check_*` flags; `# noqa: CODE` for the rest |
| Slow on a large tree | `--jobs N` (auto-parallel from 8 files); point at specific directories; untracked generated code under `.gitignore`d directories is skipped unless you pass `--no-ignore` |
| CI missed a committed file | Tracked files are never hidden by `.gitignore`. If one was missed it is untracked — commit it, or pass `--no-ignore` |
| `No staged Python files.` | Nothing staged, or the files are not `*.py`; a real git failure prints an `Error:` instead |
| Escape codes in CI logs | `--no-color` or `NO_COLOR=1` |
| Warnings don't fail the build | By design; see the exit-code note at the top |
| `[tool.codesnake]` ignored | Reading TOML needs Python 3.11+; on 3.10 a warning is printed and discovery continues upward — the nearest `.codesnake.json` wins, or the built-in defaults if there is none |
