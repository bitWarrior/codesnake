#!/usr/bin/env python3
"""
CodeSnake - Semantic Code Checker for Python 3
A comprehensive tool to detect coding issues, anti-patterns, and potential bugs.

🐍 CodeSnake strikes at code problems before they bite!
"""

import ast
import sys
from typing import List, Dict, Any, Set
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Issue:
    """Represents a code issue found during analysis."""
    severity: str  # 'error', 'warning', 'info'
    category: str
    message: str
    line: int
    col: int
    code: str  # Issue code like 'SEC001', 'PERF001', etc.


class SemanticChecker(ast.NodeVisitor):
    """Main semantic checker that analyzes Python AST for issues."""
    
    def __init__(self, source_code: str, filename: str = '<string>'):
        self.source_code = source_code
        self.filename = filename
        self.issues: List[Issue] = []
        self.source_lines = source_code.split('\n')
        
        # Track context
        self.current_function = None
        self.current_class = None
        self.imported_names: Set[str] = set()
        self.defined_names: Set[str] = set()
        self.used_names: Set[str] = set()
        self.function_complexity: Dict[str, int] = {}
        
    def add_issue(self, severity: str, category: str, message: str, 
                  node: ast.AST, code: str):
        """Add an issue to the issues list."""
        self.issues.append(Issue(
            severity=severity,
            category=category,
            message=message,
            line=node.lineno,
            col=node.col_offset,
            code=code
        ))
    
    # Security Checks
    
    def visit_Call(self, node: ast.Call):
        """Check for security issues in function calls."""
        # Check for eval/exec usage
        if isinstance(node.func, ast.Name):
            if node.func.id in ('eval', 'exec'):
                self.add_issue(
                    'error',
                    'security',
                    f"Dangerous use of '{node.func.id}()' - can execute arbitrary code",
                    node,
                    'SEC001'
                )
            
            # Check for pickle usage
            if node.func.id == 'loads' and hasattr(node.func, 'attr'):
                self.add_issue(
                    'warning',
                    'security',
                    "pickle.loads() can execute arbitrary code - use with caution",
                    node,
                    'SEC002'
                )
            
            # Track name usage
            self.used_names.add(node.func.id)
        
        # Check for shell=True in subprocess
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ('call', 'run', 'Popen'):
                for keyword in node.keywords:
                    if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                        if keyword.value.value is True:
                            self.add_issue(
                                'warning',
                                'security',
                                "subprocess with shell=True is a security risk - use shell=False",
                                node,
                                'SEC003'
                            )
        
        # Check for assert usage (can be optimized away with -O)
        if isinstance(node.func, ast.Name) and node.func.id == 'assert':
            self.add_issue(
                'warning',
                'reliability',
                "Don't use assert for data validation - it can be disabled with -O flag",
                node,
                'REL001'
            )
        
        self.generic_visit(node)
    
    def visit_Assert(self, node: ast.Assert):
        """Check assert statements."""
        self.add_issue(
            'info',
            'reliability',
            "Assert statements are removed when optimization is enabled (-O flag)",
            node,
            'REL002'
        )
        self.generic_visit(node)
    
    # Code Quality Checks
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Check function definitions for issues."""
        old_function = self.current_function
        self.current_function = node.name
        self.defined_names.add(node.name)
        
        # Check for too many arguments
        total_args = len(node.args.args) + len(node.args.kwonlyargs)
        if total_args > 7:
            self.add_issue(
                'warning',
                'complexity',
                f"Function has {total_args} parameters (max recommended: 7)",
                node,
                'COMP001'
            )
        
        # Check for mutable default arguments
        for default in node.args.defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self.add_issue(
                    'error',
                    'bugs',
                    "Mutable default argument - use None and initialize in function body",
                    default,
                    'BUG001'
                )
        
        # Calculate cyclomatic complexity
        complexity = self._calculate_complexity(node)
        self.function_complexity[node.name] = complexity
        if complexity > 10:
            self.add_issue(
                'warning',
                'complexity',
                f"Function has cyclomatic complexity of {complexity} (max recommended: 10)",
                node,
                'COMP002'
            )
        
        # Check function length
        func_length = node.end_lineno - node.lineno
        if func_length > 50:
            self.add_issue(
                'warning',
                'complexity',
                f"Function is {func_length} lines long (max recommended: 50)",
                node,
                'COMP003'
            )
        
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_ClassDef(self, node: ast.ClassDef):
        """Check class definitions."""
        old_class = self.current_class
        self.current_class = node.name
        self.defined_names.add(node.name)
        
        # Check for too many methods
        methods = [n for n in node.body if isinstance(n, ast.FunctionDef)]
        if len(methods) > 20:
            self.add_issue(
                'warning',
                'complexity',
                f"Class has {len(methods)} methods (max recommended: 20)",
                node,
                'COMP004'
            )
        
        # Check for too many instance variables
        init_method = next((m for m in methods if m.name == '__init__'), None)
        if init_method:
            instance_vars = set()
            for stmt in ast.walk(init_method):
                if isinstance(stmt, ast.Attribute):
                    if isinstance(stmt.value, ast.Name) and stmt.value.id == 'self':
                        instance_vars.add(stmt.attr)
            
            if len(instance_vars) > 10:
                self.add_issue(
                    'warning',
                    'complexity',
                    f"Class has {len(instance_vars)} instance variables (max recommended: 10)",
                    node,
                    'COMP005'
                )
        
        self.generic_visit(node)
        self.current_class = old_class
    
    # Exception Handling Checks
    
    def visit_Try(self, node: ast.Try):
        """Check exception handling."""
        for handler in node.handlers:
            # Bare except clause
            if handler.type is None:
                self.add_issue(
                    'warning',
                    'exceptions',
                    "Bare 'except:' catches all exceptions including SystemExit and KeyboardInterrupt",
                    handler,
                    'EXC001'
                )
            
            # Catching Exception (too broad)
            elif isinstance(handler.type, ast.Name) and handler.type.id == 'Exception':
                self.add_issue(
                    'info',
                    'exceptions',
                    "Catching 'Exception' is very broad - consider catching specific exceptions",
                    handler,
                    'EXC002'
                )
            
            # Empty except block
            if len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass):
                self.add_issue(
                    'warning',
                    'exceptions',
                    "Empty except block silently ignores errors",
                    handler,
                    'EXC003'
                )
        
        self.generic_visit(node)
    
    def visit_Raise(self, node: ast.Raise):
        """Check raise statements."""
        # Raising bare Exception
        if node.exc and isinstance(node.exc, ast.Call):
            if isinstance(node.exc.func, ast.Name) and node.exc.func.id == 'Exception':
                if not node.exc.args:
                    self.add_issue(
                        'warning',
                        'exceptions',
                        "Raising Exception without a message - provide descriptive error message",
                        node,
                        'EXC004'
                    )
        
        self.generic_visit(node)
    
    # Performance Checks
    
    def visit_For(self, node: ast.For):
        """Check for loops for performance issues."""
        # Check for range(len(x)) pattern
        if isinstance(node.iter, ast.Call):
            if isinstance(node.iter.func, ast.Name) and node.iter.func.id == 'range':
                if node.iter.args and isinstance(node.iter.args[0], ast.Call):
                    if isinstance(node.iter.args[0].func, ast.Name):
                        if node.iter.args[0].func.id == 'len':
                            self.add_issue(
                                'info',
                                'performance',
                                "Use 'enumerate()' instead of 'range(len())' for better readability",
                                node,
                                'PERF001'
                            )
        
        self.generic_visit(node)
    
    def visit_Compare(self, node: ast.Compare):
        """Check comparison operations."""
        # Check for 'is True' or 'is False'
        if isinstance(node.ops[0], (ast.Is, ast.IsNot)):
            if node.comparators and isinstance(node.comparators[0], ast.Constant):
                if node.comparators[0].value in (True, False):
                    self.add_issue(
                        'info',
                        'style',
                        "Don't use 'is True/False' - use the boolean value directly",
                        node,
                        'STYLE001'
                    )
        
        self.generic_visit(node)
    
    # Import Checks
    
    def visit_Import(self, node: ast.Import):
        """Check import statements."""
        for alias in node.names:
            self.imported_names.add(alias.asname if alias.asname else alias.name)
            
            # Check for wildcard imports (handled in ImportFrom)
            
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Check from...import statements."""
        for alias in node.names:
            if alias.name == '*':
                self.add_issue(
                    'warning',
                    'imports',
                    f"Wildcard import from '{node.module}' pollutes namespace",
                    node,
                    'IMP001'
                )
            else:
                self.imported_names.add(alias.asname if alias.asname else alias.name)
        
        self.generic_visit(node)
    
    # Variable Usage Checks
    
    def visit_Name(self, node: ast.Name):
        """Track variable usage."""
        if isinstance(node.ctx, ast.Load):
            self.used_names.add(node.id)
        elif isinstance(node.ctx, ast.Store):
            self.defined_names.add(node.id)
        
        self.generic_visit(node)
    
    # String Checks
    
    def visit_JoinedStr(self, node: ast.JoinedStr):
        """Check f-strings for issues."""
        # f-strings are generally good, just track them
        self.generic_visit(node)
    
    def visit_BinOp(self, node: ast.BinOp):
        """Check binary operations."""
        # Check for string concatenation in loops (would need more context)
        if isinstance(node.op, ast.Add):
            if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                # This is just string concatenation, context matters
                pass
        
        self.generic_visit(node)
    
    # Helper Methods
    
    def _calculate_complexity(self, node: ast.AST) -> int:
        """Calculate cyclomatic complexity of a function."""
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity
    
    def check_unused_imports(self):
        """Check for imported but unused names."""
        unused = self.imported_names - self.used_names
        # Note: This is a simplified check, actual unused import detection is complex
        # because of namespace considerations
        for name in unused:
            # Don't report on common false positives
            if name not in ('__future__', 'typing'):
                # We'd need line numbers for imports which we'd need to track separately
                pass
    
    def analyze(self) -> List[Issue]:
        """Perform the complete analysis."""
        try:
            tree = ast.parse(self.source_code, filename=self.filename)
            self.visit(tree)
            self.check_unused_imports()
            return sorted(self.issues, key=lambda x: (x.line, x.col))
        except SyntaxError as e:
            return [Issue(
                severity='error',
                category='syntax',
                message=f"Syntax error: {e.msg}",
                line=e.lineno or 0,
                col=e.offset or 0,
                code='SYN001'
            )]


def format_issue(issue: Issue, source_line: str = '') -> str:
    """Format an issue for display."""
    severity_colors = {
        'error': '\033[91m',  # Red
        'warning': '\033[93m',  # Yellow
        'info': '\033[94m',  # Blue
    }
    reset = '\033[0m'
    
    color = severity_colors.get(issue.severity, '')
    severity_str = issue.severity.upper()
    
    output = f"{color}{severity_str}{reset} [{issue.code}] {issue.category}: {issue.message}\n"
    output += f"  Line {issue.line}, Column {issue.col}\n"
    
    if source_line:
        output += f"  {source_line.strip()}\n"
        output += f"  {' ' * issue.col}^\n"
    
    return output


def check_file(filepath: str) -> List[Issue]:
    """Check a Python file for semantic issues."""
    path = Path(filepath)
    
    if not path.exists():
        print(f"Error: File '{filepath}' not found")
        return []
    
    with open(path, 'r', encoding='utf-8') as f:
        source_code = f.read()
    
    checker = SemanticChecker(source_code, str(path))
    return checker.analyze()


def main():
    """Main entry point."""
    # Print the colorful banner
    try:
        from codesnake_banner import print_snake_banner
        print_snake_banner()
    except ImportError:
        # Fallback if banner module not available
        print("🐍 CodeSnake - Semantic Code Checker\n")
    
    if len(sys.argv) < 2:
        print("Usage: python codesnake.py <python_file>")
        print("\nExample:")
        print("  python codesnake.py mycode.py")
        sys.exit(1)
    
    filepath = sys.argv[1]
    issues = check_file(filepath)
    
    if not issues:
        print(f"✓ No issues found in {filepath}")
        return 0
    
    # Group by severity
    errors = [i for i in issues if i.severity == 'error']
    warnings = [i for i in issues if i.severity == 'warning']
    infos = [i for i in issues if i.severity == 'info']
    
    print(f"\nAnalysis of {filepath}:")
    print(f"{'=' * 60}\n")
    
    # Load source for context
    with open(filepath, 'r') as f:
        source_lines = f.readlines()
    
    for issue in issues:
        source_line = source_lines[issue.line - 1] if issue.line <= len(source_lines) else ''
        print(format_issue(issue, source_line))
    
    print(f"\nSummary: {len(errors)} errors, {len(warnings)} warnings, {len(infos)} info")
    
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
