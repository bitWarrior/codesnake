# CodeSnake Source Code

This directory contains all the Python source code for CodeSnake.

## Files

### Core Modules

**codesnake.py** - Main semantic checker
- Entry point for basic usage
- Contains `SemanticChecker` class
- AST-based code analysis
- ~475 lines

**codesnake_enhanced.py** - Enhanced checker
- Configuration file support
- Multiple output formats (JSON, SARIF, GitHub)
- Command-line argument parsing
- ~350 lines

**codesnake_banner.py** - Branding and UI
- Colorful ASCII art banner
- Version information
- Multiple banner styles
- ~65 lines

**codesnake_cli.py** - Unified CLI interface
- Command dispatcher
- Integrates all components
- ~100 lines

**demo_banner.py** - Banner demonstration
- Shows all available banners
- Visual showcase
- ~50 lines

**__init__.py** - Package initialization
- Exports main classes
- Version information
- Package metadata

## Usage

### Direct Python Execution

```bash
# From project root
python src/codesnake.py file.py
python src/codesnake_enhanced.py --format json file.py
```

### As a Module

```python
import sys
sys.path.insert(0, 'src')

from codesnake import SemanticChecker

checker = SemanticChecker(source_code)
issues = checker.analyze()
```

### Via Launchers (Recommended)

```bash
# Use the bash launchers in project root
./codesnake.sh file.py
./codesnake-launcher.sh -e file.py
```

## Architecture

### Main Classes

**SemanticChecker** (codesnake.py)
- Extends `ast.NodeVisitor`
- Traverses Python AST
- Collects code issues
- Main analysis engine

**EnhancedSemanticChecker** (codesnake_enhanced.py)
- Extends `SemanticChecker`
- Adds configuration support
- Implements output formatters

**CheckerConfig** (codesnake_enhanced.py)
- Configuration data class
- JSON serialization
- Default settings

**Issue** (codesnake.py)
- Data class for code issues
- Severity levels
- Source location info

### Data Flow

```
Source Code
    ↓
ast.parse()
    ↓
SemanticChecker.visit()
    ↓
[visitor methods for each AST node type]
    ↓
SemanticChecker.add_issue()
    ↓
List[Issue]
    ↓
Output Formatter
```

## Adding New Checks

1. **Identify the AST node type:**
```python
import ast
print(ast.dump(ast.parse("x = 5")))
```

2. **Add a visitor method in SemanticChecker:**
```python
def visit_Assign(self, node):
    """Check assignment statements."""
    # Your logic here
    if something_wrong:
        self.add_issue('warning', 'category', 'message', node, 'CODE001')
    self.generic_visit(node)
```

3. **Add test case in test/test_codesnake.py**

4. **Update documentation**

## Dependencies

### Built-in (No Installation Required)
- `ast` - Abstract Syntax Tree parser
- `sys` - System utilities
- `pathlib` - File path handling
- `argparse` - Command-line parsing
- `json` - JSON handling
- `dataclasses` - Data classes

### Optional (For Enhanced Features)
- `pylint` - Additional linting
- `flake8` - Style checking
- `mypy` - Type checking
- `bandit` - Security scanning

## Code Style

- PEP 8 compliant
- Type hints where beneficial
- Docstrings for all public functions
- Comments for complex logic
- Maximum line length: 100 characters

## Testing

Tests are in the `test/` directory:

```bash
# Run from project root
python test/test_codesnake.py
```

## Performance

- Single-pass AST traversal: O(n)
- Memory usage: O(n) for AST
- Typical file (~500 lines): <50ms
- Large file (~5000 lines): <500ms

## Future Enhancements

- [ ] Cross-file analysis
- [ ] Type hint validation
- [ ] Dead code detection
- [ ] Auto-fix capabilities
- [ ] Plugin system
- [ ] Performance profiling integration

---

**For complete documentation, see [../docs/README.md](../docs/README.md)**
