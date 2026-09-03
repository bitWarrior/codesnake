# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report privately through GitHub's [private vulnerability reporting](https://github.com/bitWarrior/codesnake/security/advisories/new) (Security → Report a vulnerability), or by email to `contact.bitWarrior@proton.me`.

Please include the CodeSnake version (`codesnake --version`), your Python version and OS, and the smallest input that reproduces the problem. If the report involves a crafted Python file, attach it rather than pasting it, so nothing is mangled in transit.

You should get an acknowledgement within 7 days. If a fix is warranted, the intent is to release it and publish an advisory within 30 days of confirming the report. You are welcome to be credited in the advisory, under whatever name you prefer, or to stay anonymous.

## Supported versions

Fixes land on the latest minor release. There are no long-term support branches.

| Version | Supported |
|---|---|
| 1.2.x | Yes |
| < 1.2 | No — upgrade |

## Threat model

CodeSnake is a static analyzer that runs in developer environments and CI, over code that may be untrusted. Two properties define what it will and will not do:

**It never imports or executes the code it analyzes.** Analysis is performed on the AST produced by `ast.parse`. There is no `import`, no `exec`, no `eval`, and no `importlib` on any analyzed path. Pointing CodeSnake at hostile Python is not supposed to be able to run that Python.

**It has no runtime dependencies.** `pyproject.toml` declares `dependencies = []`; the checker uses only the standard library. There is no third-party package in the default install that could be compromised upstream.

Two places reach outside the process, both only when you ask:

- `--bandit` runs the separate `bandit` executable, if it is installed and on `PATH`, over the files you named. That is a different project with its own dependencies and its own threat model.
- `--staged` runs `git rev-parse` and `git diff --cached` to list staged files.

Directory walks skip `.gitignore` matches, but **only for files git does not track** — matching git's own rule that an ignore pattern has no effect on a committed file. A file added with `git add -f` is therefore still analyzed, and so is a tracked file inside an ignored directory. `--no-ignore` disables ignore handling entirely, for scanning a working tree that is not a git repository or whose ignored output you want covered. Venvs, caches, and `.git` are skipped in every mode.

A directory walk does not follow a `.py` symlink out of the tree being scanned. `src/x.py -> ~/.ssh/id_rsa` is skipped rather than read, because a parse failure prints the offending source line into the report. Symlinks that resolve inside the scan root are followed normally. An explicit file argument is still read as given — naming a file is a deliberate act.

### In scope

- Anything that makes CodeSnake execute code from a file it is analyzing
- Reading or writing files outside the analyzed paths, the config, and the baseline
- A crafted input file that hangs the process indefinitely or exhausts memory
- Code execution or privilege escalation through config, baseline, or CLI handling
- Anything that compromises the release path or the published artifacts

### Out of scope

- **A missed finding is not a vulnerability.** CodeSnake is a linter, not a security boundary. False negatives — including in the `SEC*` rules — are bugs; please file them as ordinary issues. Do not treat a clean CodeSnake report as evidence that code is safe.
- False positives.
- A crash on a malformed file that only affects that run. A `SyntaxError` becomes `SYN001` and an unanalyzable file becomes `IO001`, both contained to the file. Report a crash that escapes as an ordinary bug.
- Vulnerabilities in `bandit` or other optional `[tools]` extras — report those to their projects.

## Verifying a release

Releases are published from tagged commits in this repository. Check what you installed with `codesnake --version`, and prefer installing from a tag rather than a branch.
