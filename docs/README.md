# CodeSnake 🐍

**Semantic Code Checker for Python 3**

CodeSnake strikes at code problems before they bite! A comprehensive static analysis tool that detects security vulnerabilities, code smells, anti-patterns, and potential bugs through semantic analysis of Python code.

```
    /^\/^\
   /  o o  \     CodeSnake is watching your code...
  (  =  ^  =  )
   )         (
  (           )
 ( (  )   (  ) )
(__(__)___(__)__)
```

## 🚀 Quick Start

```bash
# Basic usage
python codesnake.py your_code.py

# With configuration
python codesnake_enhanced.py --config .codesnake.json your_code.py

# Try the demo
python codesnake.py test/example_bad_code.py
```

## ✨ Features

### Security Checks (SEC) 🔒
- **SEC001**: Dangerous use of `eval()` or `exec()` - can execute arbitrary code
- **SEC002**: Use of `pickle.loads()` - can execute arbitrary code
- **SEC003**: subprocess with `shell=True` - shell injection vulnerability

### Bug Detection (BUG) 🐛
- **BUG001**: Mutable default arguments (lists, dicts, sets)

### Exception Handling (EXC) ⚠️
- **EXC001**: Bare `except:` clauses that catch all exceptions
- **EXC002**: Overly broad exception catching (`except Exception`)
- **EXC003**: Empty except blocks that silently ignore errors
- **EXC004**: Raising exceptions without descriptive messages

### Complexity Analysis (COMP) 📊
- **COMP001**: Functions with too many parameters (>7)
- **COMP002**: High cyclomatic complexity (>10)
- **COMP003**: Functions that are too long (>50 lines)
- **COMP004**: Classes with too many methods (>20)
- **COMP005**: Classes with too many instance variables (>10)

### Performance & Style (PERF/STYLE) ⚡
- **PERF001**: Using `range(len())` instead of `enumerate()`
- **STYLE001**: Comparing with `is True` or `is False`

### Import Quality (IMP) 📦
- **IMP001**: Wildcard imports that pollute namespace

### Reliability (REL) 🛡️
- **REL001**: Using `assert` for data validation (disabled with -O flag)
- **REL002**: General assert usage warnings

## 📋 Installation

```bash
# No dependencies required for basic functionality
chmod +x codesnake.py

# For enhanced features (optional):
pip install pylint flake8 mypy bandit
```

## 🎯 Usage

### Basic Mode

```bash
# Check a single file
python codesnake.py your_code.py

# Check multiple files
python codesnake.py file1.py file2.py file3.py
```

### Enhanced Mode

```bash
# With custom configuration
python codesnake_enhanced.py --config .codesnake.json src/*.py

# JSON output
python codesnake_enhanced.py --format json src/*.py

# Only show errors
python codesnake_enhanced.py --severity error src/*.py

# GitHub Actions format
python codesnake_enhanced.py --format github src/*.py
```

## 📖 Example Output

```
Analysis of example_bad_code.py:
============================================================

ERROR [SEC001] security: Dangerous use of 'eval()' - can execute arbitrary code
  Line 16, Column 13
  result = eval(user_input)  # DANGEROUS!
               ^

WARNING [COMP001] complexity: Function has 9 parameters (max recommended: 7)
  Line 71, Column 0
  def too_many_parameters(a, b, c, d, e, f, g, h, i):
  ^

INFO [PERF001] performance: Use 'enumerate()' instead of 'range(len())'
  Line 163, Column 4
  for i in range(len(items)):
      ^

Summary: 4 errors, 8 warnings, 5 info
```

## ⚙️ Configuration

Create a `.codesnake.json` file:

```json
{
  "max_function_length": 50,
  "max_function_params": 7,
  "max_complexity": 10,
  "max_class_methods": 20,
  "max_instance_vars": 10,
  "check_security": true,
  "check_bugs": true,
  "check_exceptions": true,
  "check_complexity": true,
  "check_performance": true,
  "check_imports": true,
  "check_style": true,
  "report_errors": true,
  "report_warnings": true,
  "report_info": true
}
```

## 🏗️ Architecture

CodeSnake works by:

1. **Parsing**: Converts Python source code into an Abstract Syntax Tree (AST)
2. **Visiting**: Traverses the AST using the Visitor pattern
3. **Analysis**: Each node type is analyzed for specific issues
4. **Reporting**: Issues are collected and formatted for display

```python
class SemanticChecker(ast.NodeVisitor):
    """Main checker that analyzes Python AST"""
    
    def visit_Call(self, node):
        # Check function calls for security issues
        
    def visit_FunctionDef(self, node):
        # Analyze function definitions
        
    def visit_Try(self, node):
        # Check exception handling
```

## 🔧 Extending CodeSnake

### Adding a New Check

1. **Identify the AST Node Type**
   ```python
   import ast
   code = "x = 5"
   tree = ast.parse(code)
   print(ast.dump(tree))
   ```

2. **Create a Visitor Method**
   ```python
   def visit_Assign(self, node):
       """Check assignment statements."""
       if self._is_problematic(node):
           self.add_issue(
               severity='warning',
               category='style',
               message="Your message here",
               node=node,
               code='STYLE002'
           )
       self.generic_visit(node)
   ```

### Example: Custom Project Rules

```python
from codesnake import SemanticChecker

class ProjectChecker(SemanticChecker):
    """Custom checker with project-specific rules."""
    
    def visit_Import(self, node):
        for alias in node.names:
            if alias.name in ('optparse', 'imp'):
                self.add_issue(
                    'warning',
                    'deprecated',
                    f"Module '{alias.name}' is deprecated",
                    node,
                    'PROJ001'
                )
        super().visit_Import(node)
```

## 🔗 Integration

### Pre-commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.py$')

if [ -n "$FILES" ]; then
    echo "🐍 CodeSnake is checking your code..."
    python codesnake.py $FILES
    
    if [ $? -ne 0 ]; then
        echo "❌ Code quality checks failed!"
        exit 1
    fi
    echo "✅ CodeSnake approves!"
fi
```

### GitHub Actions

```yaml
name: CodeSnake Quality Check

on: [push, pull_request]

jobs:
  codesnake:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      - name: Run CodeSnake
        run: python codesnake.py **/*.py
```

### VS Code Task

Create `.vscode/tasks.json`:

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "CodeSnake Check",
            "type": "shell",
            "command": "python",
            "args": ["codesnake.py", "${file}"],
            "problemMatcher": []
        }
    ]
}
```

## 🧪 Testing

```bash
# Run the test suite
python test/test_codesnake.py

# Or using the launcher
./codesnake-launcher.sh --test

# Expected output:
# Tests run: 17
# Failures: 0
# Errors: 0
# Success rate: 100%
```

## 📊 Comparison with Other Tools

| Feature | CodeSnake | Pylint | Flake8 | Bandit |
|---------|-----------|--------|--------|--------|
| Security checks | ✅ | ❌ | ❌ | ✅ |
| Complexity analysis | ✅ | ✅ | Limited | ❌ |
| Custom rules | ✅ Easy | ✅ Complex | ✅ Plugins | ❌ |
| Zero dependencies | ✅ | ❌ | ❌ | ❌ |
| Semantic analysis | ✅ | ✅ | Limited | ✅ |
| Configuration | ✅ JSON | ✅ RC file | ✅ INI | ✅ YAML |

**Use CodeSnake when you want:**
- Zero-dependency static analysis
- Easy customization for project rules
- Combined security + quality checks
- Educational tool to learn AST analysis

**Combine with other tools for best results!**

## 🛠️ Common Workflows

### Quick Check Before Commit
```bash
git diff --cached --name-only | grep '\.py$' | xargs python codesnake.py
```

### Check Entire Project
```bash
find . -name "*.py" -not -path "./venv/*" | xargs python codesnake.py
```

### Generate JSON Report
```bash
python codesnake_enhanced.py --format json src/ > report.json
```

### Focus on Critical Issues
```bash
python codesnake_enhanced.py --severity error src/
```

## 📚 Resources

- **Python AST**: https://docs.python.org/3/library/ast.html
- **Green Tree Snakes**: https://greentreesnakes.readthedocs.io/
- **PEP 8**: https://pep8.org/
- **Security Best Practices**: https://bandit.readthedocs.io/

## 🤝 Contributing

Contributions welcome! To add new checks:

1. Study the AST structure of the pattern you want to detect
2. Add a visitor method to `SemanticChecker`
3. Create test cases in `test_codesnake.py`
4. Update documentation

## 📜 License

MIT License - feel free to use and modify as needed.

## 🎯 Future Enhancements

- [ ] Plugin system for custom checks
- [ ] HTML report generation
- [ ] IDE integration (PyCharm, VS Code extensions)
- [ ] Auto-fix capabilities
- [ ] Cross-file analysis
- [ ] Dead code detection
- [ ] Type hint validation
- [ ] Performance profiling

## 💡 Why "CodeSnake"?

Because like a vigilant snake, CodeSnake:
- 🔍 **Watches** your code carefully
- ⚡ **Strikes** fast at problems
- 🛡️ **Guards** against bugs
- 🐍 **Pythonic** by nature!

---

**Remember**: CodeSnake is here to help, not to criticize. Every issue it finds is an opportunity to write better Python! 🐍✨

*Made with ❤️ for the Python community*
