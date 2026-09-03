# Changelog

All notable changes to CodeSnake are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.1] - 2026-09-03

An information-disclosure fix. Upgrade if you run CodeSnake over trees you do not
fully control — a pull request, a submitted plugin, a checkout of someone else's code.

### Security

- **A directory walk no longer follows a `.py` symlink out of the scan root.**
  `os.walk` does not follow directory symlinks, but a *file* symlink was yielded and
  read through, so `src/x.py -> ~/.ssh/id_rsa` was opened when scanning `src/`. Worse
  than the read itself: a parse failure becomes `SYN001` and the text report prints the
  offending source line, so a line of the target file reached the output — and on a
  public repository, the CI log. Since the attacker picks the target, they pick which
  line fails to parse. Symlinks resolving inside the root are still followed, and an
  explicit file argument is still read as given.

- **The release workflow refuses a tag that is not reachable from `main`.** Branch
  protection governs `main`, not tags, so anyone able to push a tag and publish a
  GitHub Release could previously ship a commit that never passed review — the existing
  guard compared the tag to `_version.py` and said nothing about history. Paired with a
  repository ruleset that blocks deleting or force-updating `v*` tags, and
  `can_admins_bypass` turned off on the `pypi` environment so the approval applies to
  the owner as well. This hardens how CodeSnake is released; it does not change the
  package itself.

## [1.3.0] - 2026-09-03

A security fix for anyone using CodeSnake as a CI gate. Upgrade if you run it against
pull requests you do not control.

### Fixed

- **`.gitignore` no longer hides committed files from a directory walk.** git's own
  rule is that an ignore pattern has no effect on a tracked file; CodeSnake applied
  it regardless, so a pull request could add a file, ignore it, `git add -f` it, and
  `codesnake check src/` would never see it — exiting 0 with the file in the tree.
  Tracked files are now exempt from ignore filtering, and an ignored directory
  holding a tracked file is walked rather than pruned. Untracked ignored files, such
  as generated output, are still skipped. No flag is needed, and CI gates written
  before this release are covered on upgrade.

### Added

- **`--no-ignore`** disables `.gitignore` handling entirely, covering *untracked*
  ignored files as well — useful for linting generated code or scanning a tree that
  is not a git repository. Venvs, caches, and `.git` stay skipped. Explicit file
  arguments were never gitignore-filtered.

## [1.2.1] - 2026-09-01

First release published to PyPI. The package itself is byte-identical to 1.2.0 —
`src/` and `pyproject.toml` are unchanged — so there is nothing to upgrade for if you
are already running 1.2.0 from source.

### Changed

- The release workflow gained a `workflow_dispatch` trigger, so a publish can be
  retried without recreating the GitHub Release. Both entry points share the same
  tag/version guard.
- Checkout in the release build is pinned to the tag being released rather than
  defaulting to the branch.

## [1.2.0] - 2026-09-01

A correctness release. Three defects made the tool quietly under-deliver, and six rules
missed legitimate spellings of patterns they already detected. 212 tests, up from 190.

### Fixed

- **`--format github` emits workspace-relative paths.** A directory argument produced
  absolute paths in the `file=` property, and GitHub silently drops annotations whose
  path does not match the workspace — so no annotation from `codesnake check --format
  github src/` ever attached to a pull request diff.
- **`.gitignore` patterns holding a separator are anchored to their own directory,**
  matching git. `sub/drop.py` no longer also ignores `other/sub/drop.py`, which git
  keeps. Real source files were being skipped with nothing to indicate a short scan.
- **`codesnake config` refuses to overwrite an existing file** without `--force`,
  instead of replacing tuned thresholds with defaults and reporting success.
- **A file that cannot be analyzed no longer sinks the run.** Analysis recurses per AST
  node, so a long chained expression could exhaust the stack; the `RecursionError`
  escaped as a traceback and no file in the run was reported. It is now contained per
  file as a single `IO001`.
- **Overlapping targets are analyzed once.** `codesnake check pkg/a.py pkg/` analyzed
  the same file twice and doubled every finding and count.
- **The banner honors `--no-color` and `NO_COLOR`,** so escape codes no longer leak
  into CI logs and pre-commit output.
- **`max_*` thresholds must be 1 or greater.** `max_complexity: -1` was accepted and
  flagged every function in the tree; it is now a config error naming the key.

### Added

- **Taint reaches sinks through keyword arguments.** `subprocess.run(args=input(),
  shell=True)` is now the `error` the positional form always was. Shell sinks read
  their command by name as well as by position.
- **EXC002** matches `builtins.Exception` and tuple clauses such as
  `except (ValueError, Exception)`.
- **EXC005** covers a `raise` in the `else` of a `try` nested inside a handler.
- **`__all__` re-export forms** — `+=`, `.extend()`, and `.append()` now count as uses,
  so a package `__init__.py` no longer reports every re-exported import as unused.
- **BUG002** detects duplicate tuple keys.

### Changed

- Documentation corrections across `docs/INTEGRATIONS.md` and
  `docs/BASH_SCRIPTS_GUIDE.md`: per-format path behavior, `--staged` reading the working
  tree rather than staged blobs, baselines being written and read from the same
  directory, what fingerprints normalize (digits only), the VS Code `problemMatcher`
  `fileLocation`, Python 3.10 config discovery, and which launcher scripts fall back to
  `python`.
- CI actions moved past the Node.js 20 deprecation and are pinned to commit SHAs.
- The text report splits each file's source once instead of once per issue.

### Security

- `SECURITY.md` documents the threat model and a private reporting path.
- Workflow permissions are deny-by-default; the release workflow publishes to PyPI via
  Trusted Publishing (OIDC) with no stored credential.

## [1.1.0] - 2026-09-01

A correctness, precision, and packaging release. 189 tests, up from 91.

### Added

- **Configuration discovery** — `.codesnake.json` or a `pyproject.toml`
  `[tool.codesnake]` table, found by walking up to the repository root.
- **Parallel analysis** — `-j/--jobs N`, automatic once 8 or more files are checked.
- **Stable baselines** with fingerprints that survive line-number drift.
- `SEC003` coverage for `os.system`, `os.popen`, and `subprocess.check_output`,
  `check_call`, and `getoutput`; `SEC002` coverage for `dill`, `cloudpickle`,
  `jsonpickle`, `marshal`, `shelve`, `pickle.Unpickler(...).load()`, and `yaml.load`
  without a safe `Loader`.
- `check_reliability` category covering `REL002` and `ASY001`.

### Fixed

- Closures no longer produce false "unused variable" warnings; function bodies are
  analyzed after their enclosing scope is fully bound.
- Constants are invalidated on reassignment.
- `x is 0` no longer triggers `STYLE001`; only real booleans do.
- `--staged` works from any subdirectory of the repository.
- Columns are character offsets rather than UTF-8 byte offsets, 1-based in `text`,
  `github`, and `sarif` output.
- `except*` handlers and `match` bodies are checked.

### Changed

- Restructured into a `src/codesnake/` package with a single CLI; `codesnake FILES...`
  is shorthand for `codesnake check FILES...`.
- Version single-sourced from `codesnake/_version.py`.
- MIT `LICENSE` added, with PEP 639 metadata; CI on Python 3.10 through 3.13.

[Unreleased]: https://github.com/bitWarrior/codesnake/compare/v1.3.1...HEAD
[1.3.1]: https://github.com/bitWarrior/codesnake/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/bitWarrior/codesnake/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/bitWarrior/codesnake/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/bitWarrior/codesnake/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/bitWarrior/codesnake/releases/tag/v1.1.0
