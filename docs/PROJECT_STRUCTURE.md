# CodeSnake Project Structure 📁

Complete overview of the CodeSnake project organization.

## 📂 Directory Tree

```
codesnake/
│
├── 📁 src/                             Source code directory
│   ├── __init__.py                     Package initialization
│   ├── README.md                       Source code documentation
│   ├── codesnake.py                    Main semantic checker
│   ├── codesnake_enhanced.py           Enhanced version with config
│   ├── codesnake_banner.py             ASCII art and branding
│   ├── codesnake_cli.py                Unified CLI interface
│   └── demo_banner.py                  Banner demonstration
│
├── 📁 test/                            Test directory
│   ├── __init__.py                     Package marker
│   ├── README.md                       Test documentation
│   ├── test_codesnake.py               Test suite (17 tests)
│   └── example_bad_code.py             Example with issues
│
├── 📁 docs/                            Documentation directory
│   ├── INDEX.md                        Documentation index
│   ├── README.md                       Main documentation
│   ├── QUICKSTART.md                   Quick start guide
│   ├── BASH_SCRIPTS_GUIDE.md           Bash scripts guide
│   ├── BANNER_GUIDE.md                 Banner customization
│   ├── QUICK_REFERENCE.md              One-page cheat sheet
│   ├── PROJECT_STRUCTURE.md            This file
│   └── MIGRATION_GUIDE.md              Update guide
│
├── 🔧 Configuration & Scripts
│   ├── .codesnake.json                 Default configuration
│   ├── setup.sh                        Initial setup wizard
│   ├── codesnake.sh                    Simple launcher
│   └── codesnake-launcher.sh           Advanced launcher
│
├── 📄 Root Files
│   └── README.md                       Root README (points to docs/)
│
└── 🔐 Virtual Environment (created by setup)
    └── codesnake-venv/                 Python virtual environment
```

## 📋 File Descriptions

### Core Python Files

| File | Purpose | Lines | Key Features |
|------|---------|-------|--------------|
| `codesnake.py` | Main checker | ~475 | 17+ code quality checks, AST-based analysis |
| `codesnake_enhanced.py` | Advanced version | ~350 | Config files, multiple output formats |
| `codesnake_banner.py` | Branding | ~65 | Colorful ASCII art, version info |
| `codesnake_cli.py` | CLI tool | ~100 | Unified command interface |
| `demo_banner.py` | Demo | ~50 | Shows all banners |

### Test Files

| File | Purpose | Count |
|------|---------|-------|
| `test/test_codesnake.py` | Test suite | 17 tests |
| `test/example_bad_code.py` | Example code | 17 issues |
| `test/README.md` | Test docs | - |

### Bash Scripts

| Script | Purpose | Features |
|--------|---------|----------|
| `setup.sh` | Initial setup | Creates venv, installs deps, configures |
| `codesnake.sh` | Simple launcher | Auto-activates venv, runs checker |
| `codesnake-launcher.sh` | Advanced launcher | Full options, config support |

### Documentation

| Document | Audience | Content |
|----------|----------|---------|
| `README.md` | All users | Complete features, architecture, usage |
| `QUICKSTART.md` | New users | Get started in 5 minutes |
| `BASH_SCRIPTS_GUIDE.md` | Script users | Launcher details, examples |
| `BANNER_GUIDE.md` | Customizers | Banner info, colors |
| `QUICK_REFERENCE.md` | Daily users | One-page cheat sheet |
| `PROJECT_STRUCTURE.md` | Contributors | This overview |

## 🎯 File Counts by Type

```
Source Files:     6 (in src/)
Test Files:       2 (in test/)
Documentation:    8 (in docs/)
Config Files:     1
Bash Scripts:     3
Root README:      1
Total Files:      21
```

## 📦 Installation Footprint

### Before Setup
```
~60 KB    Source + docs + tests
```

### After Setup
```
~60 KB     Project files
~15 MB     Virtual environment (without optional tools)
~65 MB     Virtual environment (with optional tools)
```

## 🔄 Data Flow

```
User Input
    ↓
Bash Launcher (codesnake.sh / codesnake-launcher.sh)
    ↓
Activate Virtual Environment (codesnake-venv)
    ↓
Python Script (codesnake.py / codesnake_enhanced.py)
    ↓
AST Parser (Python's ast module)
    ↓
Visitor Pattern Analysis (SemanticChecker)
    ↓
Issue Collection & Formatting
    ↓
Output (text / json / github / sarif)
```

## 🧩 Module Dependencies

### Core Dependencies
- **Python 3.7+** (required)
- **ast** module (built-in)
- **sys, pathlib** (built-in)

### Optional Tools
- **pylint** - Advanced linting
- **flake8** - Style checking
- **mypy** - Type checking
- **bandit** - Security scanning

### No External Runtime Dependencies!
CodeSnake works out-of-the-box with just Python 3.7+

## 📍 Key Directories

### `/` (Root)
- Main entry points (launchers)
- Configuration files
- Root README (directs to docs/)

### `/src`
- All Python source code
- Core modules and utilities
- See `src/README.md` for details

### `/test`
- All test-related code
- Example files for testing
- Test documentation

### `/docs`
- All documentation files
- User guides and references
- API documentation

### `/codesnake-venv` (Created by setup)
- Isolated Python environment
- Optional tool installations
- Not committed to version control

## 🚀 Entry Points

### For End Users
1. `./setup.sh` - First time setup
2. `./codesnake.sh <file>` - Quick checks
3. `./codesnake-launcher.sh [options]` - Advanced usage

### For Developers
1. `python src/codesnake.py <file>` - Direct execution
2. `python test/test_codesnake.py` - Run tests
3. `python -m src.codesnake` - Module execution

### For CI/CD
1. `./codesnake-launcher.sh --format json` - JSON output
2. `./codesnake-launcher.sh --format github` - GitHub annotations
3. `./codesnake-launcher.sh --format sarif` - Security format

## 🔍 Finding Files

### Want to...

**Check code?**
→ Use `./codesnake.sh` or `python src/codesnake.py`

**Configure behavior?**
→ Edit `.codesnake.json`

**Run tests?**
→ Use `python test/test_codesnake.py`

**Read documentation?**
→ Check `docs/` directory

**Learn usage?**
→ Read `docs/QUICKSTART.md`

**Customize banner?**
→ Read `docs/BANNER_GUIDE.md`

**Set up first time?**
→ Run `./setup.sh`

**See examples?**
→ Check `test/example_bad_code.py`

**Integration help?**
→ Read `docs/BASH_SCRIPTS_GUIDE.md`

**API reference?**
→ Read `docs/README.md` + `src/README.md`

## 🎨 Color Coding (in terminal)

```
🐍 Green   = CodeSnake branding
🔴 Red     = Errors
🟡 Yellow  = Warnings
🔵 Blue    = Info
🟢 Cyan    = Headers/banners
```

## 📈 Growth Over Time

### v1.0.0 (Current)
- Core checker: ✅
- Enhanced version: ✅
- Bash launchers: ✅
- Test suite: ✅
- Documentation: ✅
- Virtual env setup: ✅

### Future Additions
- Plugin system
- VSCode extension
- Web interface
- GitHub Action
- Docker image
- PyPI package

## 🤝 Contributing

When adding new files:

1. **Source code** → `src/` directory
2. **Tests** → `test/` directory
3. **Documentation** → `docs/` directory
4. **Scripts** → Root directory (.sh files)
5. **Config** → Root directory (dotfiles)

## 📝 Maintenance

### Files to Update Together

**When adding a new check:**
- `src/codesnake.py` - Add visitor method
- `test/test_codesnake.py` - Add test case
- `test/example_bad_code.py` - Add example (optional)
- `docs/README.md` - Update feature list

**When changing structure:**
- `docs/PROJECT_STRUCTURE.md` - This file
- `docs/README.md` - Directory section
- `docs/BASH_SCRIPTS_GUIDE.md` - Structure section
- Root `README.md` - Quick overview

**When updating version:**
- `src/codesnake_banner.py` - VERSION constant
- `src/__init__.py` - __version__
- `docs/README.md` - Version badges
- `setup.sh` - Version in output

---

**Last Updated:** v1.0.0

**Maintained by:** CodeSnake Contributors 🐍
