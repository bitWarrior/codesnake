# Contributing to CodeSnake

Bug reports, false-positive and false-negative reports, and pull requests are all welcome.

## Reporting

For a **false positive or false negative**, the most useful report is the smallest file that reproduces it, the rule code, and what you expected. These are the reports that make a linter better — a rule that fires on idiomatic code costs users more than a rule that misses an edge case.

For a **security issue**, see [SECURITY.md](SECURITY.md) — please do not open a public issue.

## Getting set up

CodeSnake has no runtime dependencies, so a checkout is enough:

```bash
git clone https://github.com/bitWarrior/codesnake
cd codesnake
python -m unittest discover -s test -p 'test_*.py'
```

The test suite puts `src/` on `sys.path` itself, so no install is needed to run it. To get the `codesnake` command, or the optional tools:

```bash
pip install -e .              # console script
pip install -e ".[tools]"     # plus bandit, flake8, pylint, mypy, isort
```

`PYTHONPATH=src python -m codesnake` works from a bare checkout without installing anything.

## Ground rules

**No runtime dependencies.** `dependencies = []` in `pyproject.toml` is a feature, not an oversight — it is why CodeSnake is safe to drop into a CI job, and it is part of the [threat model](SECURITY.md#threat-model). Standard library only. Test-only and optional-extra dependencies are fine.

**Never import or execute analyzed code.** All analysis runs on the AST from `ast.parse`. A change that imports, `exec`s, or otherwise runs a file being checked will not be merged.

**Python 3.10+.** Guard anything newer at the point of use, the way `tomllib` and `ast.TryStar` already are.

**Match the surrounding code.** Comments explain *why*, not *what*. Follow the naming and structure already in `checker.py`.

## Changing or adding a rule

A rule change usually touches four places:

1. **The check** in `src/codesnake/checker.py` — a `visit_*` method or a helper it calls.
2. **`ISSUE_SUGGESTIONS`** near the top of `checker.py`, if the code is new. This is the "Suggestion:" line users see.
3. **The rule table** in `README.md` under *What it checks*, if behavior or severity changed.
4. **Tests** in `test/test_codesnake.py`.

Severity means something specific here: `error` fails the run (exit 1), `warning` and `info` do not. Promote a rule to `error` only when a true positive is nearly always a real defect.

## Tests

The house rule, and the one thing most worth internalizing:

> **Verify every new test against the unfixed source.** A regression test that passes before your change is not testing your change.

The mechanical version:

```bash
git stash push src/codesnake/checker.py
python -m unittest discover -s test -p 'test_*.py'   # your new test must FAIL
git stash pop
python -m unittest discover -s test -p 'test_*.py'   # and now PASS
```

This has caught real mistakes — tests written with absolute paths that never exercised the relative-path bug they were meant to pin.

Pair a widened rule with a test that pins what must *stay* quiet. Broadening a check without a guard against over-correction is how a linter becomes noisy: `test_narrow_except_still_quiet` and `test_distinct_tuple_keys_are_not_duplicates` exist for exactly that reason.

Run CodeSnake on itself before opening a PR — CI does, and errors fail the build:

```bash
PYTHONPATH=src python -m codesnake check --severity error src/
```

## Pull requests

Keep a PR to one logical change. Explain in the description what was wrong and how you know it is fixed, not just what you changed.

CI runs the suite on Python 3.10 through 3.13 and self-checks the source; all of it must be green. Workflow-file changes get extra scrutiny, so please raise them separately from code changes.

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
