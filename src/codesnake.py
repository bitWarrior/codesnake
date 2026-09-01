#!/usr/bin/env python3
"""
CodeSnake - Semantic Code Checker for Python 3
A comprehensive tool to detect coding issues, anti-patterns, and potential bugs.

🐍 CodeSnake strikes at code problems before they bite!
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, TextIO, Tuple


SEVERITY_RANK = {'error': 3, 'warning': 2, 'info': 1}

CATEGORY_FLAGS = {
    'security': 'check_security',
    'bugs': 'check_bugs',
    'exceptions': 'check_exceptions',
    'complexity': 'check_complexity',
    'performance': 'check_performance',
    'imports': 'check_imports',
    'style': 'check_style',
}

# Always surface these even when report_errors is false (fail closed).
ALWAYS_SHOW_CODES = frozenset({'IO001', 'SYN001'})

EVAL_EXEC_NAMES = frozenset({
    'eval',
    'exec',
    'builtins.eval',
    'builtins.exec',
    '__builtins__.eval',
    '__builtins__.exec',
})

PICKLE_LOAD_NAMES = frozenset({
    'pickle.loads',
    'pickle.load',
    '_pickle.loads',
    '_pickle.load',
})

SUBPROCESS_SHELL_NAMES = frozenset({
    'subprocess.call',
    'subprocess.run',
    'subprocess.Popen',
})

MUTABLE_CTOR_NAMES = frozenset({
    'list',
    'dict',
    'set',
    'builtins.list',
    'builtins.dict',
    'builtins.set',
})

NESTED_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


class ConfigError(Exception):
    """Raised when a configuration file cannot be loaded."""


@dataclass
class Issue:
    """Represents a code issue found during analysis."""
    severity: str  # 'error', 'warning', 'info'
    category: str
    message: str
    line: int
    col: int
    code: str  # Issue code like 'SEC001', 'PERF001', etc.
    filename: str = ''


@dataclass
class CheckerConfig:
    """Analysis thresholds and category toggles. JSON is the source of truth."""
    max_function_length: int = 50
    max_function_params: int = 7
    max_complexity: int = 10
    max_class_methods: int = 20
    max_instance_vars: int = 10
    check_security: bool = True
    check_bugs: bool = True
    check_exceptions: bool = True
    check_complexity: bool = True
    check_performance: bool = True
    check_imports: bool = True
    check_style: bool = True
    report_errors: bool = True
    report_warnings: bool = True
    report_info: bool = True

    @classmethod
    def from_file(cls, path: str) -> 'CheckerConfig':
        config_path = Path(path)
        try:
            raw = config_path.read_text(encoding='utf-8')
        except FileNotFoundError:
            raise ConfigError(f"Config file '{path}' not found") from None
        except OSError as exc:
            raise ConfigError(f"Could not read config file '{path}': {exc}") from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"Invalid JSON in '{path}': {exc}") from exc

        if not isinstance(data, dict):
            raise ConfigError(f"Config file '{path}' must contain a JSON object")

        known = {item.name for item in fields(cls)}
        kwargs = {key: value for key, value in data.items() if key in known}
        try:
            return cls(**kwargs)
        except TypeError as exc:
            raise ConfigError(f"Invalid config values in '{path}': {exc}") from exc

    def to_file(self, path: str) -> None:
        output = Path(path)
        output.write_text(json.dumps(asdict(self), indent=2) + '\n', encoding='utf-8')

    def allows_severity(self, severity: str) -> bool:
        if severity == 'error':
            return self.report_errors
        if severity == 'warning':
            return self.report_warnings
        if severity == 'info':
            return self.report_info
        return True

    def allows_category(self, category: str) -> bool:
        flag = CATEGORY_FLAGS.get(category)
        if flag is None:
            return True
        return bool(getattr(self, flag))


def load_config(path: Optional[str] = None) -> CheckerConfig:
    """Load config from an explicit path, else .codesnake.json in cwd, else defaults."""
    if path:
        return CheckerConfig.from_file(path)
    default_path = Path('.codesnake.json')
    if default_path.is_file():
        return CheckerConfig.from_file(str(default_path))
    return CheckerConfig()


class SemanticChecker(ast.NodeVisitor):
    """Main semantic checker that analyzes Python AST for issues."""

    def __init__(
        self,
        source_code: str,
        filename: str = '<string>',
        config: Optional[CheckerConfig] = None,
    ):
        self.source_code = source_code
        self.filename = filename
        self.config = config or CheckerConfig()
        self.issues: List[Issue] = []
        self.source_lines = source_code.split('\n')

        self.current_function = None
        self.current_class = None
        self.imported_names: Set[str] = set()
        self.defined_names: Set[str] = set()
        self.used_names: Set[str] = set()
        self.function_complexity: Dict[str, int] = {}
        self.aliases: Dict[str, str] = {}

    def add_issue(
        self,
        severity: str,
        category: str,
        message: str,
        node: ast.AST,
        code: str,
    ):
        """Add an issue to the issues list if the category is enabled."""
        if not self.config.allows_category(category):
            return
        self.issues.append(Issue(
            severity=severity,
            category=category,
            message=message,
            line=getattr(node, 'lineno', 0) or 0,
            col=getattr(node, 'col_offset', 0) or 0,
            code=code,
            filename=self.filename,
        ))

    def _collect_imports(self, tree: ast.AST) -> None:
        """Build a name -> qualified-name map from import statements."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self.aliases[alias.asname] = alias.name
                    else:
                        root = alias.name.split('.')[0]
                        self.aliases[root] = root
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ''
                for alias in node.names:
                    if alias.name == '*':
                        continue
                    local = alias.asname or alias.name
                    if module:
                        self.aliases[local] = f'{module}.{alias.name}'
                    else:
                        self.aliases[local] = alias.name

    def _resolve_name(self, node: Optional[ast.AST]) -> Optional[str]:
        """Return a dotted name for a Call target, using the import map."""
        if node is None:
            return None
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self._resolve_name(node.value)
            if base:
                return f'{base}.{node.attr}'
            return node.attr
        return None

    def _keyword_true(self, node: ast.Call, name: str) -> bool:
        for keyword in node.keywords:
            if keyword.arg == name and isinstance(keyword.value, ast.Constant):
                return keyword.value.value is True
        return False

    # Security Checks

    def visit_Call(self, node: ast.Call):
        """Check for security issues in function calls."""
        resolved = self._resolve_name(node.func)

        if resolved in EVAL_EXEC_NAMES:
            called = resolved.rsplit('.', 1)[-1]
            self.add_issue(
                'error',
                'security',
                f"Dangerous use of '{called}()' - can execute arbitrary code",
                node,
                'SEC001',
            )

        if resolved in PICKLE_LOAD_NAMES:
            self.add_issue(
                'warning',
                'security',
                f"{resolved}() can execute arbitrary code - use with caution",
                node,
                'SEC002',
            )

        if resolved in SUBPROCESS_SHELL_NAMES and self._keyword_true(node, 'shell'):
            self.add_issue(
                'warning',
                'security',
                "subprocess with shell=True is a security risk - use shell=False",
                node,
                'SEC003',
            )

        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert):
        """Check assert statements."""
        self.add_issue(
            'info',
            'reliability',
            "Assert statements are removed when optimization is enabled (-O flag)",
            node,
            'REL002',
        )
        self.generic_visit(node)

    # Function / lambda analysis (shared)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._check_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._check_function(node)

    def visit_Lambda(self, node: ast.Lambda):
        self._check_function(node, is_lambda=True)

    def _count_params(self, args: ast.arguments) -> int:
        return (
            len(args.posonlyargs)
            + len(args.args)
            + len(args.kwonlyargs)
            + (1 if args.vararg else 0)
            + (1 if args.kwarg else 0)
        )

    def _is_mutable_default(self, node: ast.AST) -> bool:
        if isinstance(node, (ast.List, ast.Dict, ast.Set)):
            return True
        if isinstance(node, (ast.ListComp, ast.DictComp, ast.SetComp)):
            return True
        if isinstance(node, ast.Call):
            resolved = self._resolve_name(node.func)
            return resolved in MUTABLE_CTOR_NAMES
        return False

    def _check_mutable_defaults(self, args: ast.arguments) -> None:
        for default in args.defaults:
            if default is not None and self._is_mutable_default(default):
                self.add_issue(
                    'error',
                    'bugs',
                    "Mutable default argument - use None and initialize in function body",
                    default,
                    'BUG001',
                )
        for default in args.kw_defaults:
            if default is not None and self._is_mutable_default(default):
                self.add_issue(
                    'error',
                    'bugs',
                    "Mutable default argument - use None and initialize in function body",
                    default,
                    'BUG001',
                )

    def _check_function(self, node: ast.AST, is_lambda: bool = False) -> None:
        name = getattr(node, 'name', '<lambda>')
        old_function = self.current_function
        self.current_function = name
        if not is_lambda:
            self.defined_names.add(name)

        args = node.args  # type: ignore[attr-defined]
        total_args = self._count_params(args)
        if total_args > self.config.max_function_params:
            self.add_issue(
                'warning',
                'complexity',
                f"Function has {total_args} parameters "
                f"(max recommended: {self.config.max_function_params})",
                node,
                'COMP001',
            )

        self._check_mutable_defaults(args)

        if not is_lambda:
            complexity = self._calculate_complexity(node)
            self.function_complexity[name] = complexity
            if complexity > self.config.max_complexity:
                self.add_issue(
                    'warning',
                    'complexity',
                    f"Function has cyclomatic complexity of {complexity} "
                    f"(max recommended: {self.config.max_complexity})",
                    node,
                    'COMP002',
                )

            end_lineno = getattr(node, 'end_lineno', None)
            if end_lineno is not None:
                func_length = end_lineno - node.lineno + 1
                if func_length > self.config.max_function_length:
                    self.add_issue(
                        'warning',
                        'complexity',
                        f"Function is {func_length} lines long "
                        f"(max recommended: {self.config.max_function_length})",
                        node,
                        'COMP003',
                    )

        self.generic_visit(node)
        self.current_function = old_function

    def visit_ClassDef(self, node: ast.ClassDef):
        """Check class definitions."""
        old_class = self.current_class
        self.current_class = node.name
        self.defined_names.add(node.name)

        methods = [
            n for n in node.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        if len(methods) > self.config.max_class_methods:
            self.add_issue(
                'warning',
                'complexity',
                f"Class has {len(methods)} methods "
                f"(max recommended: {self.config.max_class_methods})",
                node,
                'COMP004',
            )

        init_method = next((m for m in methods if m.name == '__init__'), None)
        if init_method:
            instance_vars = set()
            for stmt in ast.walk(init_method):
                if isinstance(stmt, ast.Attribute):
                    if isinstance(stmt.value, ast.Name) and stmt.value.id == 'self':
                        instance_vars.add(stmt.attr)

            if len(instance_vars) > self.config.max_instance_vars:
                self.add_issue(
                    'warning',
                    'complexity',
                    f"Class has {len(instance_vars)} instance variables "
                    f"(max recommended: {self.config.max_instance_vars})",
                    node,
                    'COMP005',
                )

        self.generic_visit(node)
        self.current_class = old_class

    # Exception Handling Checks

    def visit_Try(self, node: ast.Try):
        """Check exception handling."""
        for handler in node.handlers:
            if handler.type is None:
                self.add_issue(
                    'warning',
                    'exceptions',
                    "Bare 'except:' catches all exceptions including SystemExit and KeyboardInterrupt",
                    handler,
                    'EXC001',
                )
            elif isinstance(handler.type, ast.Name) and handler.type.id == 'Exception':
                self.add_issue(
                    'info',
                    'exceptions',
                    "Catching 'Exception' is very broad - consider catching specific exceptions",
                    handler,
                    'EXC002',
                )

            if len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass):
                self.add_issue(
                    'warning',
                    'exceptions',
                    "Empty except block silently ignores errors",
                    handler,
                    'EXC003',
                )

        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise):
        """Check raise statements."""
        if node.exc and isinstance(node.exc, ast.Call):
            if isinstance(node.exc.func, ast.Name) and node.exc.func.id == 'Exception':
                if not node.exc.args:
                    self.add_issue(
                        'warning',
                        'exceptions',
                        "Raising Exception without a message - provide descriptive error message",
                        node,
                        'EXC004',
                    )

        self.generic_visit(node)

    # Performance Checks

    def visit_For(self, node: ast.For):
        """Check for loops for performance issues."""
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
                                'PERF001',
                            )

        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare):
        """Check comparison operations."""
        if isinstance(node.ops[0], (ast.Is, ast.IsNot)):
            if node.comparators and isinstance(node.comparators[0], ast.Constant):
                if node.comparators[0].value in (True, False):
                    self.add_issue(
                        'info',
                        'style',
                        "Don't use 'is True/False' - use the boolean value directly",
                        node,
                        'STYLE001',
                    )

        self.generic_visit(node)

    # Import Checks

    def visit_Import(self, node: ast.Import):
        """Check import statements."""
        for alias in node.names:
            self.imported_names.add(alias.asname if alias.asname else alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Check from...import statements."""
        for alias in node.names:
            if alias.name == '*':
                module = node.module if node.module is not None else '.'
                self.add_issue(
                    'warning',
                    'imports',
                    f"Wildcard import from '{module}' pollutes namespace",
                    node,
                    'IMP001',
                )
            else:
                self.imported_names.add(alias.asname if alias.asname else alias.name)

        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        """Track variable usage."""
        if isinstance(node.ctx, ast.Load):
            self.used_names.add(node.id)
        elif isinstance(node.ctx, ast.Store):
            self.defined_names.add(node.id)

        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr):
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        self.generic_visit(node)

    def _complexity_contrib(self, node: ast.AST) -> int:
        """Contribution of this node and its descendants, skipping nested scopes."""
        if isinstance(node, NESTED_SCOPE_NODES):
            return 0

        contrib = 0
        if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.ExceptHandler)):
            contrib = 1
        elif isinstance(node, ast.IfExp):
            contrib = 1
        elif isinstance(node, ast.BoolOp):
            contrib = max(len(node.values) - 1, 0)
        elif hasattr(ast, 'Match') and isinstance(node, ast.Match):
            contrib = len(node.cases)

        for child in ast.iter_child_nodes(node):
            contrib += self._complexity_contrib(child)
        return contrib

    def _calculate_complexity(self, node: ast.AST) -> int:
        """Cyclomatic complexity of a function, excluding nested functions/classes."""
        complexity = 1
        for child in ast.iter_child_nodes(node):
            complexity += self._complexity_contrib(child)
        return complexity

    def check_unused_imports(self):
        """Placeholder: unused-import detection needs per-import line tracking."""
        unused = self.imported_names - self.used_names
        for name in unused:
            if name not in ('__future__', 'typing'):
                pass

    def analyze(self) -> List[Issue]:
        """Perform the complete analysis."""
        try:
            tree = ast.parse(self.source_code, filename=self.filename)
            self._collect_imports(tree)
            self.visit(tree)
            self.check_unused_imports()
            return sorted(self.issues, key=lambda x: (x.line, x.col, x.code))
        except SyntaxError as exc:
            return [Issue(
                severity='error',
                category='syntax',
                message=f"Syntax error: {exc.msg}",
                line=exc.lineno or 0,
                col=exc.offset or 0,
                code='SYN001',
                filename=self.filename,
            )]


class EnhancedSemanticChecker(SemanticChecker):
    """Backward-compatible alias; configuration lives on SemanticChecker."""


def _io_issue(filepath: str, message: str) -> Issue:
    return Issue(
        severity='error',
        category='io',
        message=message,
        line=0,
        col=0,
        code='IO001',
        filename=filepath,
    )


def check_file(filepath: str, config: Optional[CheckerConfig] = None) -> List[Issue]:
    """Check a Python file for semantic issues. I/O failures become IO001 errors."""
    path = Path(filepath)
    if not path.exists():
        return [_io_issue(filepath, f"File '{filepath}' not found")]
    if not path.is_file():
        return [_io_issue(filepath, f"'{filepath}' is not a file")]

    try:
        source_code = path.read_text(encoding='utf-8')
    except UnicodeDecodeError as exc:
        return [_io_issue(filepath, f"Could not decode '{filepath}' as UTF-8: {exc}")]
    except OSError as exc:
        return [_io_issue(filepath, f"Could not read '{filepath}': {exc}")]

    checker = SemanticChecker(source_code, str(path), config=config)
    return checker.analyze()


def _read_source_line(source: Optional[str], line: int) -> str:
    if not source or line <= 0:
        return ''
    lines = source.splitlines()
    if line > len(lines):
        return ''
    return lines[line - 1]


def format_issue(issue: Issue, source_line: str = '', use_color: bool = True) -> str:
    """Format an issue for display."""
    severity_colors = {
        'error': '\033[91m',
        'warning': '\033[93m',
        'info': '\033[94m',
    }
    reset = '\033[0m'
    color = severity_colors.get(issue.severity, '') if use_color else ''
    color_reset = reset if use_color else ''
    severity_str = issue.severity.upper()

    output = (
        f"{color}{severity_str}{color_reset} [{issue.code}] "
        f"{issue.category}: {issue.message}\n"
    )
    location = f"Line {issue.line}, Column {issue.col}"
    if issue.filename:
        output += f"  {issue.filename}: {location}\n"
    else:
        output += f"  {location}\n"

    if source_line:
        display = source_line.rstrip('\n')
        output += f"  {display}\n"
        if issue.col >= 0:
            output += f"  {' ' * issue.col}^\n"

    return output


def filter_issues(
    issues: Sequence[Issue],
    config: CheckerConfig,
    min_severity: Optional[str] = None,
) -> List[Issue]:
    """Apply config report_* flags and optional --severity minimum."""
    min_rank = SEVERITY_RANK.get(min_severity or 'info', 1)
    filtered: List[Issue] = []
    for issue in issues:
        if issue.code in ALWAYS_SHOW_CODES:
            filtered.append(issue)
            continue
        if SEVERITY_RANK.get(issue.severity, 0) < min_rank:
            continue
        if not config.allows_severity(issue.severity):
            continue
        filtered.append(issue)
    return filtered


def _count_by_severity(issues: Iterable[Issue]) -> Tuple[int, int, int]:
    errors = warnings = infos = 0
    for issue in issues:
        if issue.severity == 'error':
            errors += 1
        elif issue.severity == 'warning':
            warnings += 1
        elif issue.severity == 'info':
            infos += 1
    return errors, warnings, infos


def _issue_to_dict(issue: Issue) -> dict:
    return {
        'severity': issue.severity,
        'category': issue.category,
        'code': issue.code,
        'message': issue.message,
        'line': issue.line,
        'col': issue.col,
        'filename': issue.filename,
    }


def format_json_report(
    file_issues: Sequence[Tuple[str, List[Issue]]],
) -> str:
    files_out = []
    all_issues: List[Issue] = []
    for path, issues in file_issues:
        all_issues.extend(issues)
        files_out.append({
            'path': path,
            'issues': [_issue_to_dict(issue) for issue in issues],
        })
    errors, warnings, infos = _count_by_severity(all_issues)
    payload = {
        'files': files_out,
        'summary': {
            'files': len(file_issues),
            'errors': errors,
            'warnings': warnings,
            'info': infos,
        },
    }
    return json.dumps(payload, indent=2) + '\n'


def format_github_report(issues: Sequence[Issue]) -> str:
    lines = []
    level_map = {'error': 'error', 'warning': 'warning', 'info': 'notice'}
    for issue in issues:
        level = level_map.get(issue.severity, 'warning')
        file_part = issue.filename or ''
        lines.append(
            f"::{level} file={file_part},line={issue.line},col={issue.col}"
            f"::[{issue.code}] {issue.message}"
        )
    return '\n'.join(lines) + ('\n' if lines else '')


def format_sarif_report(issues: Sequence[Issue], tool_version: str) -> str:
    rules = []
    seen_codes = set()
    for issue in issues:
        if issue.code in seen_codes:
            continue
        seen_codes.add(issue.code)
        rules.append({
            'id': issue.code,
            'name': issue.code,
            'shortDescription': {'text': issue.category},
        })

    level_map = {'error': 'error', 'warning': 'warning', 'info': 'note'}
    results = []
    for issue in issues:
        start_line = issue.line if issue.line > 0 else 1
        start_col = issue.col if issue.col > 0 else 1
        results.append({
            'ruleId': issue.code,
            'level': level_map.get(issue.severity, 'warning'),
            'message': {'text': issue.message},
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {'uri': issue.filename or ''},
                    'region': {
                        'startLine': start_line,
                        'startColumn': start_col,
                    },
                },
            }],
        })

    payload = {
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'CodeSnake',
                    'version': tool_version,
                    'rules': rules,
                },
            },
            'results': results,
        }],
    }
    return json.dumps(payload, indent=2) + '\n'


def _should_use_color(color: Optional[bool], stream: TextIO) -> bool:
    if color is False:
        return False
    if color is True:
        return True
    if os.environ.get('NO_COLOR'):
        return False
    return hasattr(stream, 'isatty') and stream.isatty()


def _print_banner() -> None:
    try:
        from codesnake_banner import print_snake_banner
        print_snake_banner()
    except ImportError:
        try:
            from .codesnake_banner import print_snake_banner
            print_snake_banner()
        except ImportError:
            print("🐍 CodeSnake - Semantic Code Checker\n")


def _print_version() -> None:
    try:
        from codesnake_banner import print_version
        print_version()
    except ImportError:
        try:
            from .codesnake_banner import print_version
            print_version()
        except ImportError:
            print("CodeSnake v1.0.0")


def _tool_version() -> str:
    try:
        from codesnake_banner import VERSION
        return VERSION
    except ImportError:
        try:
            from .codesnake_banner import VERSION
            return VERSION
        except ImportError:
            return '1.0.0'


def run_check(
    files: Sequence[str],
    *,
    config: Optional[CheckerConfig] = None,
    config_path: Optional[str] = None,
    output_format: str = 'text',
    min_severity: Optional[str] = None,
    show_banner: bool = False,
    color: Optional[bool] = None,
    stream: Optional[TextIO] = None,
) -> int:
    """Analyze one or more files. Returns 1 if any error-severity issue exists."""
    out = stream if stream is not None else sys.stdout

    try:
        if config is None:
            config = load_config(config_path)
    except ConfigError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if not files:
        print("Error: no files to check", file=sys.stderr)
        return 1

    if show_banner and output_format == 'text':
        _print_banner()

    file_reports: List[Tuple[str, List[Issue], Optional[str]]] = []
    for filepath in files:
        path = Path(filepath)
        source: Optional[str] = None
        if path.is_file():
            try:
                source = path.read_text(encoding='utf-8')
            except (OSError, UnicodeDecodeError):
                source = None
        issues = check_file(filepath, config=config)
        issues = filter_issues(issues, config, min_severity=min_severity)
        file_reports.append((filepath, issues, source))

    displayed: List[Tuple[str, List[Issue]]] = [
        (path, issues) for path, issues, _ in file_reports
    ]
    all_displayed = [issue for _, issues in displayed for issue in issues]
    errors, warnings, infos = _count_by_severity(all_displayed)
    use_color = _should_use_color(color, out) and output_format == 'text'

    if output_format == 'json':
        out.write(format_json_report(displayed))
    elif output_format == 'github':
        out.write(format_github_report(all_displayed))
    elif output_format == 'sarif':
        out.write(format_sarif_report(all_displayed, _tool_version()))
    else:
        any_issues = False
        for filepath, issues, source in file_reports:
            if not issues:
                out.write(f"✓ No issues found in {filepath}\n")
                continue
            any_issues = True
            out.write(f"\nAnalysis of {filepath}:\n")
            out.write(f"{'=' * 60}\n\n")
            for issue in issues:
                source_line = _read_source_line(source, issue.line)
                rendered = format_issue(issue, source_line, use_color=use_color)
                out.write(rendered)
                if not rendered.endswith('\n'):
                    out.write('\n')
                out.write('\n')
        if any_issues or len(files) > 1:
            out.write(
                f"\nSummary: {errors} errors, {warnings} warnings, {infos} info\n"
            )

    return 1 if errors else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='codesnake',
        description='CodeSnake - Semantic Code Checker for Python 3',
    )
    parser.add_argument('files', nargs='*', help='Python files to check')
    parser.add_argument('--config', help='Path to .codesnake.json')
    parser.add_argument(
        '--format',
        choices=['text', 'json', 'github', 'sarif'],
        default='text',
        help='Output format',
    )
    parser.add_argument(
        '--severity',
        choices=['error', 'warning', 'info'],
        help='Minimum severity to report',
    )
    parser.add_argument('--no-color', action='store_true', help='Disable ANSI colors')
    parser.add_argument('--version', action='store_true', help='Show version and exit')
    parser.add_argument('--banner', action='store_true', help='Show banner and exit')
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.banner:
        _print_banner()
        return 0

    if args.version:
        _print_version()
        return 0

    if not args.files:
        parser.print_help()
        return 1

    return run_check(
        args.files,
        config_path=args.config,
        output_format=args.format,
        min_severity=args.severity,
        show_banner=(args.format == 'text'),
        color=False if args.no_color else None,
    )


if __name__ == '__main__':
    sys.exit(main())
