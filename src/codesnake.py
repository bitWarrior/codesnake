#!/usr/bin/env python3
"""
CodeSnake - Semantic Code Checker for Python 3
A comprehensive tool to detect coding issues, anti-patterns, and potential bugs.

🐍 CodeSnake strikes at code problems before they bite!
"""

from __future__ import annotations

import argparse
import ast
import builtins
import json
import os
import re
import shutil
import subprocess as _subprocess
import sys
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Pattern, Sequence, Set, TextIO, Tuple


SEVERITY_RANK = {'error': 3, 'warning': 2, 'info': 1}

CATEGORY_FLAGS = {
    'security': 'check_security',
    'bugs': 'check_bugs',
    'exceptions': 'check_exceptions',
    'complexity': 'check_complexity',
    'performance': 'check_performance',
    'imports': 'check_imports',
    'style': 'check_style',
    'unused': 'check_unused',
    'reliability': 'check_reliability',
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
    'subprocess.check_call',
    'subprocess.check_output',
})

# These always run their argument through a shell.
ALWAYS_SHELL_NAMES = frozenset({
    'os.system',
    'os.popen',
    'subprocess.getoutput',
    'subprocess.getstatusoutput',
})

MUTABLE_CTOR_NAMES = frozenset({
    'list',
    'dict',
    'set',
    'builtins.list',
    'builtins.dict',
    'builtins.set',
})

OPEN_NAMES = frozenset({'open', 'builtins.open', 'io.open'})

TAINT_CALL_NAMES = frozenset({
    'input',
    'builtins.input',
    'os.getenv',
    'os.environ.get',
})

TAINT_ATTR_NAMES = frozenset({
    'sys.argv',
    'os.environ',
    'sys.stdin',
})

REQUEST_TAINT_ATTRS = frozenset({
    'args', 'GET', 'POST', 'json', 'data', 'form', 'cookies', 'headers',
    'values', 'query_params', 'query', 'params', 'body', 'files',
})

# REQUEST_TAINT_ATTRS only count when read from something that looks like an
# HTTP request object (``request.args``, ``req.json``, ``self.request.GET``).
REQUEST_RECEIVER_NAMES = frozenset({'request', 'req', 'flask_request', 'http_request'})

# Calls that neutralize their input for the sinks we check (shell / eval).
SANITIZER_NAMES = frozenset({
    'int', 'float', 'bool', 'len',
    'builtins.int', 'builtins.float', 'builtins.bool', 'builtins.len',
    'shlex.quote', 'shlex.join',
    're.escape', 'html.escape',
    'urllib.parse.quote', 'urllib.parse.quote_plus',
})

# Wrappers that take ownership of a file handle's lifetime.
HANDLE_OWNER_NAMES = frozenset({'contextlib.closing'})
HANDLE_OWNER_METHODS = frozenset({'enter_context', 'enter_async_context'})

_TEST_FILE_DIRS = frozenset({'test', 'tests', 'testing'})

ABSTRACT_DECORATORS = frozenset({
    'abstractmethod',
    'abc.abstractmethod',
    'overload',
    'typing.overload',
})

ISSUE_SUGGESTIONS = {
    'SEC001': 'Do not evaluate untrusted strings; use ast.literal_eval or a real parser.',
    'SEC002': 'Avoid pickle for untrusted data; use json or a dedicated serializer.',
    'SEC003': 'Pass a sequence of arguments with shell=False.',
    'SEC004': 'Pass a fixed executable and argument list, not a user-built command string.',
    'BUG001': 'Use None as the default and create the mutable object inside the function.',
    'BUG002': 'Remove or rename the duplicate key.',
    'EXC001': "Catch specific exceptions, or use 'except Exception:' if you must.",
    'EXC003': 'Log, re-raise, or handle the error; do not use a bare pass.',
    'EXC005': "Use 'raise NewError(...) from exc' to chain the original exception.",
    'IMP001': 'Import only the names you need.',
    'IMP002': 'Remove the unused import.',
    'IMP003': 'Import a name that the sibling module actually defines, or add that name.',
    'RES001': "Use 'with open(...) as handle:'.",
    'ASY001': 'Await a coroutine, or make the function synchronous.',
    'VAR001': 'Remove the unused name, or prefix it with _ if it is intentional.',
    'VAR002': 'Remove the unused argument, or prefix it with _ if it is required by an API.',
    'PERF001': 'Use enumerate() to get both index and value.',
    'STYLE001': "Write 'if flag:' or 'if not flag:'.",
}

NESTED_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
_TRY_NODES: Tuple[type, ...] = tuple(
    node_type for node_type in (ast.Try, getattr(ast, 'TryStar', None)) if node_type is not None
)

SKIP_UNUSED_NAMES = frozenset({'self', 'cls', 'mcs', 'mcls'})
_BUILTIN_NAMES = frozenset(name for name in dir(builtins) if not name.startswith('_'))

SKIP_DIR_NAMES = frozenset({
    '.git', '.hg', '.svn', '.tox', '.nox',
    '.mypy_cache', '.pytest_cache', '.ruff_cache', '.coverage',
    '__pycache__', 'site-packages', 'dist', 'build', 'htmlcov',
    'node_modules', '.venv', 'venv', 'codesnake-venv', 'env', '.env',
})

_NOQA_RE = re.compile(
    r'#\s*(?:noqa|codesnake:\s*ignore)\b(?:\s*[:=]\s*([^\n#]+))?',
    re.IGNORECASE,
)
_CODING_COOKIE_RE = re.compile(
    br'^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)',
    re.IGNORECASE,
)
_TYPE_CHECKING_NAMES = frozenset({'TYPE_CHECKING', 'typing.TYPE_CHECKING'})


# Binding kinds that participate in VAR003 shadow detection.
_SHADOW_CHECKED_KINDS = frozenset({
    'assign', 'arg', 'vararg', 'function', 'decorated_function',
    'loop', 'unpack', 'annotation',
})
# Binding kinds reported as unused locals (VAR001). Loop targets, tuple
# unpacking, bare annotations, and decorated nested functions are exempt.
_REPORTED_LOCAL_KINDS = frozenset({'assign', 'function', 'class'})


class ConfigError(Exception):
    """Raised when a configuration file cannot be loaded."""


@dataclass
class _Binding:
    name: str
    line: int
    col: int
    kind: str  # import, arg, assign, function, class


class _Scope:
    __slots__ = ('kind', 'name', 'bindings', 'used', 'global_names',
                 'nonlocal_names', 'constants', 'tainted')

    def __init__(self, kind: str, name: str = ''):
        self.kind = kind
        self.name = name
        self.bindings: Dict[str, _Binding] = {}
        self.used: Set[str] = set()
        self.global_names: Set[str] = set()
        self.nonlocal_names: Set[str] = set()
        self.constants: Dict[str, Any] = {}
        self.tainted: Set[str] = set()


@dataclass
class _GitIgnorePattern:
    negated: bool
    dir_only: bool
    regex: Pattern[str]

    def matches(self, rel: str, is_dir: bool) -> bool:
        if self.dir_only and not is_dir:
            return False
        return self.regex.search(rel) is not None


def _gitignore_glob_to_regex(pattern: str, anchored: bool) -> Pattern[str]:
    parts: List[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith('**/', i):
            parts.append('(?:.*/)?')
            i += 3
        elif pattern.startswith('**', i):
            parts.append('.*')
            i += 2
        elif pattern[i] == '*':
            parts.append('[^/]*')
            i += 1
        elif pattern[i] == '?':
            parts.append('[^/]')
            i += 1
        else:
            parts.append(re.escape(pattern[i]))
            i += 1
    body = ''.join(parts)
    if anchored:
        regex = '^' + body + '(?:/.*)?$'
    else:
        regex = r'(?:^|/)' + body + r'(?:/.*)?$'
    return re.compile(regex)


def _parse_gitignore_text(text: str) -> List[_GitIgnorePattern]:
    parsed: List[_GitIgnorePattern] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith('#'):
            continue
        negated = line.startswith('!')
        if negated:
            line = line[1:]
        dir_only = line.endswith('/')
        if dir_only:
            line = line[:-1]
        anchored = line.startswith('/')
        if anchored:
            line = line[1:]
        if not line:
            continue
        parsed.append(_GitIgnorePattern(
            negated=negated,
            dir_only=dir_only,
            regex=_gitignore_glob_to_regex(line, anchored),
        ))
    return parsed


class _IgnoreStack:
    def __init__(self) -> None:
        self._entries: List[Tuple[Path, List[_GitIgnorePattern]]] = []

    def add_gitignore(self, gi_path: Path) -> None:
        try:
            text = gi_path.read_text(encoding='utf-8')
        except OSError:
            return
        self._entries.append((gi_path.parent.resolve(), _parse_gitignore_text(text)))

    def ignored(self, path: Path, is_dir: bool) -> bool:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        ignored = False
        for base, patterns in self._entries:
            try:
                rel = resolved.relative_to(base).as_posix()
            except ValueError:
                continue
            for pattern in patterns:
                if pattern.matches(rel, is_dir):
                    ignored = not pattern.negated
        return ignored


def detect_source_encoding(data: bytes) -> str:
    """PEP 263 encoding cookie, else UTF-8 (with BOM)."""
    if data.startswith(b'\xef\xbb\xbf'):
        return 'utf-8-sig'
    chunks = data.split(b'\n', 2)[:2]
    for raw_line in chunks:
        match = _CODING_COOKIE_RE.match(raw_line.replace(b'\r', b''))
        if match:
            encoding = match.group(1).decode('ascii', errors='replace')
            if encoding.lower() in ('utf-8', 'utf8'):
                return 'utf-8'
            return encoding
    return 'utf-8'


def read_python_source(path: Path) -> str:
    data = path.read_bytes()
    encoding = detect_source_encoding(data)
    return data.decode(encoding)


def ignored_codes_on_line(line: str) -> Optional[Set[str]]:
    """None = no pragma; empty set = ignore all codes; otherwise specific codes."""
    match = _NOQA_RE.search(line)
    if not match:
        return None
    spec = match.group(1)
    if not spec:
        return set()
    return {part.strip().upper() for part in spec.replace(',', ' ').split() if part.strip()}


def iter_python_files(root: Path) -> Iterable[Path]:
    """Yield .py files under root, skipping venvs, caches, and .gitignore matches."""
    try:
        root_resolved = root.resolve()
    except OSError:
        root_resolved = root
    ignore = _IgnoreStack()
    root_gi = root_resolved / '.gitignore'
    if root_gi.is_file():
        ignore.add_gitignore(root_gi)

    for dirpath, dirnames, filenames in os.walk(root_resolved):
        current = Path(dirpath)
        nested_gi = current / '.gitignore'
        if nested_gi.is_file() and nested_gi != root_gi:
            ignore.add_gitignore(nested_gi)

        kept: List[str] = []
        for name in dirnames:
            if name in SKIP_DIR_NAMES or name.endswith('.egg-info'):
                continue
            sub = current / name
            if ignore.ignored(sub, is_dir=True):
                continue
            kept.append(name)
        dirnames[:] = kept

        for name in filenames:
            if not name.endswith('.py'):
                continue
            filepath = current / name
            if ignore.ignored(filepath, is_dir=False):
                continue
            yield filepath


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
    source: str = 'codesnake'
    end_line: int = 0
    end_col: int = 0
    suggestion: str = ''


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
    check_unused: bool = True
    check_reliability: bool = True
    use_bandit: bool = False
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

        known = {item.name: item for item in fields(cls)}
        unknown = sorted(key for key in data if key not in known)
        if unknown:
            print(
                f"Warning: unknown config key(s) in '{path}': {', '.join(unknown)}",
                file=sys.stderr,
            )

        kwargs: Dict[str, Any] = {}
        problems: List[str] = []
        for key, value in data.items():
            field = known.get(key)
            if field is None:
                continue
            expected = type(field.default)
            if expected is bool:
                valid = isinstance(value, bool)
            else:
                valid = isinstance(value, int) and not isinstance(value, bool)
            if not valid:
                problems.append(
                    f"'{key}' must be {expected.__name__}, got {type(value).__name__}"
                )
                continue
            kwargs[key] = value
        if problems:
            raise ConfigError(f"Invalid config values in '{path}': " + '; '.join(problems))
        return cls(**kwargs)

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
        known_exports: Optional[Dict[str, Set[str]]] = None,
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
        self.scopes: List[_Scope] = []
        self._in_type_checking = False
        self._with_expr_ids: Set[int] = set()
        # id(Name node) -> binding kind for stores that are not plain assignments
        # (loop targets, tuple unpacking, bare annotations).
        self._store_kinds: Dict[int, str] = {}
        # Function bodies are analyzed after the enclosing scope is fully bound,
        # so closures may reference names assigned later in that scope.
        self._deferred: List[Tuple[ast.AST, List[_Scope], bool]] = []
        self.known_exports = known_exports or {}

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
        self._record_issue(
            severity,
            category,
            message,
            getattr(node, 'lineno', 0) or 0,
            getattr(node, 'col_offset', 0) or 0,
            code,
            end_line=getattr(node, 'end_lineno', None) or getattr(node, 'lineno', 0) or 0,
            end_col=getattr(node, 'end_col_offset', None) or getattr(node, 'col_offset', 0) or 0,
        )

    def _record_issue(
        self,
        severity: str,
        category: str,
        message: str,
        line: int,
        col: int,
        code: str,
        source: str = 'codesnake',
        end_line: int = 0,
        end_col: int = 0,
        suggestion: str = '',
    ) -> None:
        if not self.config.allows_category(category):
            return
        end_line = end_line or line
        col = self._char_col(line, col)
        end_col = self._char_col(end_line, end_col) if end_col else col
        self.issues.append(Issue(
            severity=severity,
            category=category,
            message=message,
            line=line,
            col=col,
            code=code,
            filename=self.filename,
            source=source,
            end_line=end_line,
            end_col=end_col,
            suggestion=suggestion or ISSUE_SUGGESTIONS.get(code, ''),
        ))

    def _char_col(self, line: int, col: int) -> int:
        """Convert an AST UTF-8 byte offset into a 0-based character offset."""
        if col <= 0 or line <= 0 or line > len(self.source_lines):
            return max(col, 0)
        text = self.source_lines[line - 1]
        if text.isascii():
            return col
        return len(text.encode('utf-8')[:col].decode('utf-8', errors='ignore'))

    def _current_scope(self) -> Optional[_Scope]:
        return self.scopes[-1] if self.scopes else None

    def _push_scope(self, kind: str, name: str = '') -> _Scope:
        scope = _Scope(kind, name)
        self.scopes.append(scope)
        return scope

    def _pop_scope(self) -> Optional[_Scope]:
        if not self.scopes:
            return None
        scope = self.scopes.pop()
        if scope.kind == 'function':
            self._report_unused_locals(scope)
        elif scope.kind == 'module':
            self._report_unused_imports(scope)
        return scope

    def _bind(self, name: str, node: ast.AST, kind: str) -> None:
        scope = self._current_scope()
        if scope is None:
            return
        if name in scope.global_names:
            if len(self.scopes) > 1:
                self.scopes[0].bindings.setdefault(name, _Binding(
                    name,
                    getattr(node, 'lineno', 0) or 0,
                    getattr(node, 'col_offset', 0) or 0,
                    kind,
                ))
            return
        if name in scope.nonlocal_names:
            return
        if name not in scope.bindings:
            if kind in _SHADOW_CHECKED_KINDS and scope.kind == 'function':
                self._maybe_shadow(name, node)
            scope.bindings[name] = _Binding(
                name,
                getattr(node, 'lineno', 0) or 0,
                getattr(node, 'col_offset', 0) or 0,
                kind,
            )

    def _maybe_shadow(self, name: str, node: ast.AST) -> None:
        if name.startswith('_') or name in SKIP_UNUSED_NAMES or name in _BUILTIN_NAMES:
            return
        for scope in reversed(self.scopes[:-1]):
            if scope.kind == 'class' or scope.kind == 'comprehension':
                continue
            if scope.kind == 'module':
                return
            if name in scope.bindings:
                self.add_issue(
                    'info',
                    'unused',
                    f"Name '{name}' shadows a name from an enclosing function",
                    node,
                    'VAR003',
                )
                return

    def _mark_used(self, name: str) -> None:
        for scope in reversed(self.scopes):
            if name in scope.nonlocal_names:
                continue
            if name in scope.bindings or name in scope.global_names:
                scope.used.add(name)
                if name in scope.global_names and self.scopes:
                    self.scopes[0].used.add(name)
                return
        if self.scopes and name in self.scopes[0].bindings:
            self.scopes[0].used.add(name)

    def _lookup_const(self, name: str) -> Any:
        for scope in reversed(self.scopes):
            if name in scope.constants:
                return scope.constants[name]
        return None

    def _set_const(self, name: str, value: Any) -> None:
        scope = self._current_scope()
        if scope is not None:
            scope.constants[name] = value

    def _mark_name_tainted(self, name: str) -> None:
        for scope in reversed(self.scopes):
            if name in scope.global_names:
                self.scopes[0].tainted.add(name)
                return
            if name in scope.bindings:
                scope.tainted.add(name)
                return
        if self.scopes:
            self.scopes[-1].tainted.add(name)

    def _name_is_tainted(self, name: str) -> bool:
        for scope in reversed(self.scopes):
            if name in scope.tainted:
                return True
            if name in scope.bindings:
                return False
        return False

    def _mark_tainted_target(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self._mark_name_tainted(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._mark_tainted_target(elt)
        elif isinstance(target, ast.Starred):
            self._mark_tainted_target(target.value)

    def _is_tainted_expr(self, node: Optional[ast.AST]) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.Name):
            return self._name_is_tainted(node.id)
        if isinstance(node, ast.JoinedStr):
            return any(self._is_tainted_expr(value) for value in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._is_tainted_expr(node.value)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self._is_tainted_expr(node.left) or self._is_tainted_expr(node.right)
        if isinstance(node, ast.Call):
            resolved = self._resolve_name(node.func)
            if resolved in TAINT_CALL_NAMES:
                return True
            if resolved in SANITIZER_NAMES:
                return False
            if isinstance(node.func, ast.Attribute) and node.func.attr in ('get', 'format'):
                if self._is_tainted_expr(node.func.value):
                    return True
                if any(self._is_tainted_expr(arg) for arg in node.args):
                    return True
            return any(self._is_tainted_expr(arg) for arg in node.args)
        if isinstance(node, ast.Attribute):
            resolved = self._resolve_name(node)
            if resolved in TAINT_ATTR_NAMES:
                return True
            if node.attr in REQUEST_TAINT_ATTRS and self._is_request_like(node.value):
                return True
            return self._is_tainted_expr(node.value)
        if isinstance(node, ast.Subscript):
            return self._is_tainted_expr(node.value)
        if isinstance(node, ast.Starred):
            return self._is_tainted_expr(node.value)
        if isinstance(node, (ast.List, ast.Tuple)):
            return any(self._is_tainted_expr(elt) for elt in node.elts)
        return False

    @staticmethod
    def _is_request_like(node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in REQUEST_RECEIVER_NAMES
        if isinstance(node, ast.Attribute):
            return node.attr in REQUEST_RECEIVER_NAMES
        return False

    def _is_literal_expr(self, node: Optional[ast.AST]) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Name):
            if self._name_is_tainted(node.id):
                return False
            for scope in reversed(self.scopes):
                if node.id in scope.constants:
                    return True
            return False
        if isinstance(node, ast.JoinedStr):
            return all(
                isinstance(value, ast.Constant) or (
                    isinstance(value, ast.FormattedValue)
                    and self._is_literal_expr(value.value)
                )
                for value in node.values
            )
        return False

    def _report_unused_imports(self, scope: _Scope) -> None:
        for name, binding in scope.bindings.items():
            if binding.kind != 'import':
                continue
            if name in scope.used:
                continue
            self._record_issue(
                'warning',
                'imports',
                f"Imported name '{name}' is unused",
                binding.line,
                binding.col,
                'IMP002',
            )

    def _report_unused_locals(self, scope: _Scope) -> None:
        for name, binding in scope.bindings.items():
            if name in scope.used:
                continue
            if name in SKIP_UNUSED_NAMES or name.startswith('_'):
                continue
            if binding.kind == 'import':
                self._record_issue(
                    'warning',
                    'imports',
                    f"Imported name '{name}' is unused",
                    binding.line,
                    binding.col,
                    'IMP002',
                )
            elif binding.kind == 'arg':
                self._record_issue(
                    'warning',
                    'unused',
                    f"Unused argument '{name}'",
                    binding.line,
                    binding.col,
                    'VAR002',
                )
            elif binding.kind in _REPORTED_LOCAL_KINDS:
                label = 'nested function' if binding.kind == 'function' else (
                    'nested class' if binding.kind == 'class' else 'local variable'
                )
                self._record_issue(
                    'warning',
                    'unused',
                    f"Unused {label} '{name}'",
                    binding.line,
                    binding.col,
                    'VAR001',
                )

    def _mark_store_kind(self, target: ast.AST, kind: str) -> None:
        """Tag every Name inside ``target`` so visit_Name binds it as ``kind``."""
        if isinstance(target, ast.Name):
            self._store_kinds[id(target)] = kind
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._mark_store_kind(elt, kind)
        elif isinstance(target, ast.Starred):
            self._mark_store_kind(target.value, kind)

    def _is_test_file(self) -> bool:
        path = Path(self.filename)
        name = path.name
        if name.startswith('test_') or name.endswith('_test.py') or name == 'conftest.py':
            return True
        return any(part in _TEST_FILE_DIRS for part in path.parts[:-1])

    def _is_ignored(self, issue: Issue) -> bool:
        if issue.line <= 0 or issue.line > len(self.source_lines):
            return False
        codes = ignored_codes_on_line(self.source_lines[issue.line - 1])
        if codes is None:
            return False
        if not codes:
            return True
        return issue.code.upper() in codes

    def _is_type_checking_test(self, test: ast.AST) -> bool:
        resolved = self._resolve_name(test)
        return resolved in _TYPE_CHECKING_NAMES

    def _record_dunder_all(self, node: ast.Assign) -> None:
        if not self.scopes or self.scopes[-1].kind != 'module':
            return
        names: List[str] = []
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == '__all__':
                value = node.value
                elts: Sequence[ast.AST] = []
                if isinstance(value, (ast.List, ast.Tuple)):
                    elts = value.elts
                for elt in elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        names.append(elt.value)
        for name in names:
            self.scopes[0].used.add(name)

    def _record_constant_assign(self, targets: Sequence[ast.AST], value: ast.AST) -> None:
        if not isinstance(value, ast.Constant):
            return
        for target in targets:
            if isinstance(target, ast.Name):
                self._set_const(target.id, value.value)

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

    def _is_abstract(self, node: ast.AST) -> bool:
        for decorator in getattr(node, 'decorator_list', []):
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            resolved = self._resolve_name(target) or ''
            if resolved.rsplit('.', 1)[-1] in {'abstractmethod', 'overload'}:
                return True
            if resolved in ABSTRACT_DECORATORS:
                return True
        return False

    def _is_stub_body(self, node: ast.AST) -> bool:
        body = list(getattr(node, 'body', []))
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body = body[1:]
        if not body:
            return True
        if len(body) == 1 and isinstance(body[0], ast.Pass):
            return True
        if (
            len(body) == 1
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and body[0].value.value is ...
        ):
            return True
        return False

    def _async_body_has_await(self, node: ast.AST) -> bool:
        for child in ast.iter_child_nodes(node):
            if self._subtree_has_await(child):
                return True
        return False

    def _subtree_has_await(self, node: ast.AST) -> bool:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            return False
        if isinstance(node, (ast.Await, ast.AsyncFor, ast.AsyncWith)):
            return True
        return any(self._subtree_has_await(child) for child in ast.iter_child_nodes(node))

    def _iter_raises(self, stmts: Sequence[ast.AST]) -> Iterable[ast.Raise]:
        for stmt in stmts:
            if isinstance(stmt, ast.Raise):
                yield stmt
            elif isinstance(stmt, ast.If):
                yield from self._iter_raises(stmt.body)
                yield from self._iter_raises(stmt.orelse)
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
                yield from self._iter_raises(stmt.body)
                yield from self._iter_raises(getattr(stmt, 'orelse', []))
            elif isinstance(stmt, _TRY_NODES):
                yield from self._iter_raises(stmt.body)
                yield from self._iter_raises(stmt.finalbody)
            elif isinstance(stmt, ast.Match):
                for case in stmt.cases:
                    yield from self._iter_raises(case.body)

    def _check_lossy_raises(self, handler: ast.ExceptHandler) -> None:
        for raise_node in self._iter_raises(handler.body):
            if raise_node.exc is None:
                continue
            if raise_node.cause is not None:
                continue
            if (
                isinstance(raise_node.exc, ast.Name)
                and handler.name
                and raise_node.exc.id == handler.name
            ):
                continue
            if isinstance(raise_node.exc, (ast.Call, ast.Name)):
                self.add_issue(
                    'warning',
                    'exceptions',
                    "Raising a new exception in 'except' hides the original - use 'raise ... from'",
                    raise_node,
                    'EXC005',
                )

    def _keyword_true(self, node: ast.Call, name: str) -> bool:
        for keyword in node.keywords:
            if keyword.arg != name:
                continue
            value = keyword.value
            # Identity on purpose: 1 == True but ``shell=1`` is not what we match.
            if isinstance(value, ast.Constant) and value.value is True:  # noqa: STYLE001
                return True
            if isinstance(value, ast.Name) and self._lookup_const(value.id) is True:  # noqa: STYLE001
                return True
        return False

    # Security Checks

    def visit_Call(self, node: ast.Call):
        """Check for security issues in function calls."""
        resolved = self._resolve_name(node.func)

        if resolved in EVAL_EXEC_NAMES:
            called = resolved.rsplit('.', 1)[-1]
            arg0 = node.args[0] if node.args else None
            if arg0 is not None and self._is_tainted_expr(arg0):
                self.add_issue(
                    'error',
                    'security',
                    f"Dangerous use of '{called}()' on untrusted input",
                    node,
                    'SEC001',
                )
            elif arg0 is not None and self._is_literal_expr(arg0):
                self.add_issue(
                    'info',
                    'security',
                    f"Use of '{called}()' on a constant - avoid eval/exec",
                    node,
                    'SEC001',
                )
            else:
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

        if resolved in SUBPROCESS_SHELL_NAMES:
            cmd = node.args[0] if node.args else None
            tainted_cmd = cmd is not None and self._is_tainted_expr(cmd)
            if self._keyword_true(node, 'shell'):
                if tainted_cmd:
                    self.add_issue(
                        'error',
                        'security',
                        "subprocess with shell=True and untrusted input is command injection",
                        node,
                        'SEC003',
                    )
                else:
                    self.add_issue(
                        'warning',
                        'security',
                        "subprocess with shell=True is a security risk - use shell=False",
                        node,
                        'SEC003',
                    )
            elif tainted_cmd:
                self.add_issue(
                    'warning',
                    'security',
                    "subprocess command built from untrusted input",
                    node,
                    'SEC004',
                )

        if resolved in ALWAYS_SHELL_NAMES:
            cmd = node.args[0] if node.args else None
            if cmd is not None and self._is_tainted_expr(cmd):
                self.add_issue(
                    'error',
                    'security',
                    f"{resolved}() with untrusted input is command injection",
                    node,
                    'SEC003',
                )
            else:
                self.add_issue(
                    'warning',
                    'security',
                    f"{resolved}() runs its argument through a shell - "
                    "use subprocess with shell=False and an argument list",
                    node,
                    'SEC003',
                )

        if resolved in HANDLE_OWNER_NAMES or (
            isinstance(node.func, ast.Attribute) and node.func.attr in HANDLE_OWNER_METHODS
        ):
            for arg in node.args:
                self._with_expr_ids.add(id(arg))

        if resolved in OPEN_NAMES and id(node) not in self._with_expr_ids:
            self.add_issue(
                'warning',
                'bugs',
                "open() should be used as a context manager (with open(...) as ...)",
                node,
                'RES001',
            )

        self.generic_visit(node)

    def _enter_with(self, node: ast.AST) -> None:
        for item in node.items:  # type: ignore[attr-defined]
            # Any open() anywhere in the context expression (including inside
            # closing(...) or a helper) is owned by the with statement.
            for sub in ast.walk(item.context_expr):
                if isinstance(sub, ast.Call):
                    self._with_expr_ids.add(id(sub))
            if item.optional_vars is not None:
                self._mark_store_kind(item.optional_vars, 'unpack')
        self.generic_visit(node)

    def visit_With(self, node: ast.With):
        self._enter_with(node)

    def visit_AsyncWith(self, node: ast.AsyncWith):
        self._enter_with(node)

    def visit_Dict(self, node: ast.Dict):
        seen: Dict[Any, ast.AST] = {}
        for key in node.keys:
            if key is None or not isinstance(key, ast.Constant):
                continue
            value = key.value
            if isinstance(value, float) and value != value:
                continue
            if isinstance(value, (str, int, float, bool, bytes, type(None))):
                if value in seen:
                    self.add_issue(
                        'warning',
                        'bugs',
                        f"Duplicate dictionary key {value!r}",
                        key,
                        'BUG002',
                    )
                else:
                    seen[value] = key
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert):
        """Check assert statements (skipped in test files, where assert is the API)."""
        if self._is_test_file():
            self.generic_visit(node)
            return
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
        self._bind(node.name, node, self._function_kind(node))
        self._check_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._bind(node.name, node, self._function_kind(node))
        if not self._is_abstract(node) and not self._is_stub_body(node):
            if not self._async_body_has_await(node):
                self.add_issue(
                    'warning',
                    'reliability',
                    f"Async function '{node.name}' never awaits - it will not yield to the event loop",
                    node,
                    'ASY001',
                )
        self._check_function(node)

    @staticmethod
    def _function_kind(node: ast.AST) -> str:
        # A decorator (route registration, signal hook, ...) is a use.
        return 'decorated_function' if getattr(node, 'decorator_list', None) else 'function'

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

        # Decorators, defaults, annotations, and type parameters are evaluated in
        # the enclosing scope when the def statement runs, so visit them now.
        for field_name in ('decorator_list', 'type_params'):
            for child in getattr(node, field_name, None) or []:
                self.visit(child)
        returns = getattr(node, 'returns', None)
        if returns is not None:
            self.visit(returns)
        self.visit(args)

        # The body runs later; defer it so names bound after this def are visible.
        self._deferred.append((node, list(self.scopes), self._in_type_checking))
        self.current_function = old_function

    def _visit_function_body(self, node: ast.AST) -> None:
        name = getattr(node, 'name', '<lambda>')
        old_function = self.current_function
        self.current_function = name
        args = node.args  # type: ignore[attr-defined]

        scope = self._push_scope('function', name)
        for arg in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs):
            self._bind(arg.arg, arg, 'arg')
        # *args / **kwargs usually exist for signature compatibility.
        if args.vararg is not None:
            self._bind(args.vararg.arg, args.vararg, 'vararg')
        if args.kwarg is not None:
            self._bind(args.kwarg.arg, args.kwarg, 'vararg')

        is_lambda = isinstance(node, ast.Lambda)
        if (
            is_lambda  # arity is dictated by the caller
            or (name.startswith('__') and name.endswith('__'))  # protocol methods
            or self._is_abstract(node)
            or (not is_lambda and self._is_stub_body(node))
        ):
            scope.used.update(scope.bindings)

        body = node.body  # type: ignore[attr-defined]
        queued = len(self._deferred)
        if isinstance(body, list):
            for stmt in body:
                self.visit(stmt)
        else:
            self.visit(body)
        # Nested functions queued by this body must run before this scope is
        # popped, so their uses of our locals count and we report accurately.
        self._run_deferred(queued)
        self._pop_scope()
        self.current_function = old_function

    def _run_deferred(self, start: int) -> None:
        """Analyze function bodies deferred since ``start`` (they may defer more)."""
        saved_scopes = self.scopes
        saved_flag = self._in_type_checking
        while len(self._deferred) > start:
            node, scopes, in_type_checking = self._deferred.pop()
            self.scopes = scopes
            self._in_type_checking = in_type_checking
            self._visit_function_body(node)
        self.scopes = saved_scopes
        self._in_type_checking = saved_flag

    def visit_ClassDef(self, node: ast.ClassDef):
        """Check class definitions."""
        self._bind(node.name, node, 'class')
        old_class = self.current_class
        self.current_class = node.name
        self.defined_names.add(node.name)
        self._push_scope('class', node.name)

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
                if isinstance(stmt, ast.Attribute) and isinstance(stmt.ctx, ast.Store):
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
        self._pop_scope()
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

            self._check_lossy_raises(handler)

        self.generic_visit(node)

    visit_TryStar = visit_Try

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

    def visit_AsyncFor(self, node: ast.AsyncFor):
        self._mark_store_kind(node.target, 'loop')
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        """Check for loops for performance issues."""
        self._mark_store_kind(node.target, 'loop')
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
                if isinstance(node.comparators[0].value, bool):
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
            bound = alias.asname if alias.asname else alias.name.split('.')[0]
            self.imported_names.add(bound)
            self._bind(bound, node, 'import')
            if self._in_type_checking:
                scope = self._current_scope()
                if scope is not None:
                    scope.used.add(bound)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Check from...import statements."""
        if node.module == '__future__':
            self.generic_visit(node)
            return
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
                bound = alias.asname if alias.asname else alias.name
                self.imported_names.add(bound)
                self._bind(bound, node, 'import')
                if self._in_type_checking:
                    scope = self._current_scope()
                    if scope is not None:
                        scope.used.add(bound)

        if node.level and node.level >= 1 and self.known_exports:
            self._check_relative_import(node)

        self.generic_visit(node)

    def _check_relative_import(self, node: ast.ImportFrom) -> None:
        target = resolve_relative_module(self.filename, node.level, node.module)
        if target is None:
            return
        defined = self.known_exports.get(str(target))
        if defined is None:
            return
        module_label = node.module or '.'
        for alias in node.names:
            if alias.name == '*':
                continue
            if alias.name not in defined:
                self.add_issue(
                    'error',
                    'imports',
                    f"Imported name '{alias.name}' is not defined in relative module '{module_label}'",
                    node,
                    'IMP003',
                )

    def visit_Name(self, node: ast.Name):
        """Track variable usage."""
        if isinstance(node.ctx, ast.Load):
            self.used_names.add(node.id)
            self._mark_used(node.id)
        elif isinstance(node.ctx, ast.Store):
            self.defined_names.add(node.id)
            scope = self._current_scope()
            if scope is not None:
                # Any rebinding invalidates a previously recorded constant.
                scope.constants.pop(node.id, None)
            self._bind(node.id, node, self._store_kinds.pop(id(node), 'assign'))
        elif isinstance(node.ctx, ast.Del):
            self._mark_used(node.id)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        self._record_dunder_all(node)
        for target in node.targets:
            if isinstance(target, (ast.Tuple, ast.List)):
                self._mark_store_kind(target, 'unpack')
        self.generic_visit(node)
        # Record after visiting targets, which clears any stale constant.
        self._record_constant_assign(node.targets, node.value)
        if self._is_tainted_expr(node.value):
            for target in node.targets:
                self._mark_tainted_target(target)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if node.value is None:
            self._mark_store_kind(node.target, 'annotation')
        self.generic_visit(node)
        if node.value is not None:
            self._record_constant_assign([node.target], node.value)
            if self._is_tainted_expr(node.value):
                self._mark_tainted_target(node.target)

    def visit_AugAssign(self, node: ast.AugAssign):
        self.generic_visit(node)
        if isinstance(node.target, ast.Name):
            self._mark_used(node.target.id)  # ``x += 1`` reads x
        if self._is_tainted_expr(node.value):
            self._mark_tainted_target(node.target)

    def visit_If(self, node: ast.If):
        type_checking = self._is_type_checking_test(node.test)
        self.visit(node.test)
        previous = self._in_type_checking
        if type_checking:
            self._in_type_checking = True
        for stmt in node.body:
            self.visit(stmt)
        self._in_type_checking = previous
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_Global(self, node: ast.Global):
        scope = self._current_scope()
        if scope is not None:
            for name in node.names:
                scope.global_names.add(name)
        self.generic_visit(node)

    def visit_Nonlocal(self, node: ast.Nonlocal):
        scope = self._current_scope()
        if scope is not None:
            for name in node.names:
                scope.nonlocal_names.add(name)
                self._mark_used(name)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.name:
            scope = self._current_scope()
            if scope is not None:
                scope.used.add(node.name)
        self.generic_visit(node)

    def _visit_comprehension(self, node: ast.AST) -> None:
        self._push_scope('comprehension')
        self.generic_visit(node)
        self._pop_scope()

    def visit_ListComp(self, node: ast.ListComp):
        self._visit_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp):
        self._visit_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp):
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp):
        self._visit_comprehension(node)

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
        self.issues = []
        self.aliases = {}
        self._deferred = []
        try:
            tree = ast.parse(self.source_code, filename=self.filename)
            self._collect_imports(tree)
            self.scopes = []
            self._in_type_checking = False
            self._with_expr_ids = set()
            self._store_kinds = {}
            self._push_scope('module')
            self.visit(tree)
            self._run_deferred(0)
            self._pop_scope()
            self.issues = [issue for issue in self.issues if not self._is_ignored(issue)]
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


def collect_module_exports(source: str) -> Set[str]:
    """Module-level names defined or re-exported in a file."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    names: Set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name != '*':
                    names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split('.')[0])
    return names


def resolve_relative_module(
    importer: str,
    level: int,
    module: Optional[str],
) -> Optional[Path]:
    """Resolve a relative import to a .py file or package __init__.py."""
    if level < 1 or not importer or importer == '<string>':
        return None
    try:
        base = Path(importer).resolve().parent
    except OSError:
        return None
    for _ in range(level - 1):
        parent = base.parent
        if parent == base:
            return None
        base = parent
    candidate = base.joinpath(*module.split('.')) if module else base
    pyfile = Path(str(candidate) + '.py')
    init = candidate / '__init__.py'
    if pyfile.is_file():
        return pyfile.resolve()
    if init.is_file():
        return init.resolve()
    return None


def _normalize_issue_path(filename: str) -> str:
    if not filename:
        return ''
    path = Path(filename)
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def issue_fingerprint(issue: Issue) -> str:
    return f"{_normalize_issue_path(issue.filename)}|{issue.code}|{issue.message}"


def load_baseline(path: str) -> Set[str]:
    baseline_path = Path(path)
    try:
        raw = baseline_path.read_text(encoding='utf-8')
        data = json.loads(raw)
    except FileNotFoundError:
        raise ConfigError(f"Baseline file '{path}' not found") from None
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Could not read baseline '{path}': {exc}") from exc
    fingerprints: Set[str] = set()
    for item in data.get('issues') or []:
        if not isinstance(item, dict):
            continue
        stored = item.get('fingerprint')
        if stored:
            fingerprints.add(str(stored))
            continue
        fingerprints.add(
            f"{_normalize_issue_path(str(item.get('filename') or ''))}"
            f"|{item.get('code') or ''}|{item.get('message') or ''}"
        )
    return fingerprints


def write_baseline(issues: Sequence[Issue], path: str) -> None:
    payload = {
        'version': 1,
        'issues': [
            {
                'filename': _normalize_issue_path(issue.filename),
                'code': issue.code,
                'message': issue.message,
                'line': issue.line,
                'fingerprint': issue_fingerprint(issue),
            }
            for issue in issues
        ],
    }
    Path(path).write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')


def _display_path(path: Path) -> str:
    """Path relative to cwd when it is underneath it, else absolute."""
    try:
        rel = os.path.relpath(path, Path.cwd())
    except ValueError:
        return str(path)
    if rel.startswith('..'):
        return str(path)
    return rel


def git_staged_python_files() -> Tuple[List[str], Optional[str]]:
    """Return staged *.py paths (relative to cwd), or an error message.

    ``git diff --name-only`` prints paths relative to the repository root, not
    the current directory, so the root is resolved first.
    """
    try:
        toplevel = _subprocess.run(
            ['git', 'rev-parse', '--show-toplevel'],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if toplevel.returncode != 0:
            detail = (toplevel.stderr or toplevel.stdout or 'not a git repository').strip()
            return [], detail
        completed = _subprocess.run(
            ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACMR'],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, _subprocess.TimeoutExpired) as exc:
        return [], f"Could not run git: {exc}"
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or 'git diff failed').strip()
        return [], detail
    root = Path(toplevel.stdout.strip() or '.')
    files: List[str] = []
    for line in completed.stdout.splitlines():
        name = line.strip()
        if not name.endswith('.py'):
            continue
        full = root / name
        if full.is_file():
            files.append(_display_path(full))
    return files, None


def expand_python_targets(paths: Sequence[str]) -> Tuple[List[str], List[Issue]]:
    """Expand directories to .py files. Explicit files are kept as given."""
    targets: List[str] = []
    extras: List[Issue] = []
    seen: Set[str] = set()

    def _add(item: str) -> None:
        if item not in seen:
            seen.add(item)
            targets.append(item)

    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            found = [str(candidate) for candidate in iter_python_files(path)]
            if not found:
                extras.append(_io_issue(raw, f"No Python files found in '{raw}'"))
                continue
            for filepath in found:
                _add(filepath)
        else:
            _add(raw)
    return targets, extras


def check_file(
    filepath: str,
    config: Optional[CheckerConfig] = None,
    known_exports: Optional[Dict[str, Set[str]]] = None,
) -> List[Issue]:
    """Check a Python file for semantic issues. I/O failures become IO001 errors."""
    path = Path(filepath)
    if not path.exists():
        return [_io_issue(filepath, f"File '{filepath}' not found")]
    if not path.is_file():
        return [_io_issue(filepath, f"'{filepath}' is not a file")]

    try:
        source_code = read_python_source(path)
    except LookupError as exc:
        return [_io_issue(filepath, f"Unknown encoding in '{filepath}': {exc}")]
    except UnicodeDecodeError as exc:
        return [_io_issue(filepath, f"Could not decode '{filepath}': {exc}")]
    except OSError as exc:
        return [_io_issue(filepath, f"Could not read '{filepath}': {exc}")]

    checker = SemanticChecker(
        source_code,
        str(path),
        config=config,
        known_exports=known_exports,
    )
    return checker.analyze()


_BANDIT_SEVERITY = {
    'HIGH': 'error',
    'MEDIUM': 'warning',
    'LOW': 'info',
}


def collect_bandit_issues(filepaths: Sequence[str]) -> List[Issue]:
    """Run bandit if installed and convert findings to Issue objects."""
    bandit_bin = shutil.which('bandit')
    if not bandit_bin or not filepaths:
        return []
    try:
        completed = _subprocess.run(
            [bandit_bin, '-f', 'json', *filepaths],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, _subprocess.TimeoutExpired):
        return []
    payload = completed.stdout.strip()
    if not payload:
        return []
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return []
    issues: List[Issue] = []
    for result in data.get('results') or []:
        severity = _BANDIT_SEVERITY.get(
            str(result.get('issue_severity', '')).upper(),
            'warning',
        )
        test_id = str(result.get('test_id') or 'BANDIT')
        issues.append(Issue(
            severity=severity,
            category='security',
            message=str(result.get('issue_text') or test_id),
            line=int(result.get('line_number') or 0),
            col=int(result.get('col_offset') or 0),
            code=test_id,
            filename=str(result.get('filename') or ''),
            source='bandit',
        ))
    return issues


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

    origin = f" ({issue.source})" if issue.source and issue.source != 'codesnake' else ''
    output = (
        f"{color}{severity_str}{color_reset} [{issue.code}] "
        f"{issue.category}{origin}: {issue.message}\n"
    )
    # Issue.col is a 0-based character offset; humans expect 1-based columns.
    location = f"Line {issue.line}, Column {issue.col + 1}" if issue.line > 0 else ''
    if issue.filename and location:
        output += f"  {issue.filename}: {location}\n"
    elif issue.filename:
        output += f"  {issue.filename}\n"
    elif location:
        output += f"  {location}\n"

    if source_line:
        display = source_line.rstrip('\n')
        output += f"  {display}\n"
        if issue.col >= 0:
            output += f"  {' ' * issue.col}^\n"
    if issue.suggestion:
        output += f"  Suggestion: {issue.suggestion}\n"

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
        'source': issue.source,
        'end_line': issue.end_line,
        'end_col': issue.end_col,
        'suggestion': issue.suggestion,
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
        end = f",endLine={issue.end_line}" if issue.end_line and issue.end_line != issue.line else ''
        suggestion = f" {issue.suggestion}" if issue.suggestion else ''
        col = issue.col + 1 if issue.col >= 0 else 1
        lines.append(
            f"::{level} file={file_part},line={issue.line},col={col}{end}"
            f"::[{issue.code}] {issue.message}{suggestion}"
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
        # SARIF columns are 1-based; Issue.col/end_col are 0-based offsets.
        start_line = issue.line if issue.line > 0 else 1
        start_col = issue.col + 1 if issue.col >= 0 else 1
        end_line = issue.end_line if issue.end_line > 0 else start_line
        end_col = issue.end_col + 1 if issue.end_col > 0 else start_col
        message_text = issue.message
        if issue.suggestion:
            message_text = f"{issue.message} Suggestion: {issue.suggestion}"
        results.append({
            'ruleId': issue.code,
            'level': level_map.get(issue.severity, 'warning'),
            'message': {'text': message_text},
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {'uri': issue.filename or ''},
                    'region': {
                        'startLine': start_line,
                        'startColumn': start_col,
                        'endLine': end_line,
                        'endColumn': max(end_col, 1),
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
    if color is False:  # noqa: STYLE001 - tri-state Optional[bool]
        return False
    if color is True:  # noqa: STYLE001
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
    use_bandit: Optional[bool] = None,
    staged: bool = False,
    baseline_path: Optional[str] = None,
    update_baseline: Optional[str] = None,
) -> int:
    """Analyze one or more files. Returns 1 if any error-severity issue exists."""
    out = stream if stream is not None else sys.stdout

    try:
        if config is None:
            config = load_config(config_path)
    except ConfigError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    file_list = list(files)
    if staged:
        staged_files, git_error = git_staged_python_files()
        if git_error:
            print(f"Error: {git_error}", file=sys.stderr)
            return 1
        if not staged_files:
            print("No staged Python files.", file=sys.stderr)
            return 0
        file_list = staged_files

    if not file_list:
        print("Error: no files to check", file=sys.stderr)
        return 1

    if show_banner and output_format == 'text':
        _print_banner()

    targets, extra_issues = expand_python_targets(file_list)

    file_reports: List[Tuple[str, List[Issue], Optional[str]]] = []
    for extra in extra_issues:
        filtered = filter_issues([extra], config, min_severity=min_severity)
        file_reports.append((extra.filename or '', filtered, None))

    sources_by_file: Dict[str, str] = {}
    known_exports: Dict[str, Set[str]] = {}
    for filepath in targets:
        path = Path(filepath)
        if not path.is_file():
            continue
        try:
            source = read_python_source(path)
        except (OSError, UnicodeDecodeError, LookupError):
            continue
        sources_by_file[filepath] = source
        try:
            known_exports[str(path.resolve())] = collect_module_exports(source)
        except OSError:
            known_exports[filepath] = collect_module_exports(source)

    for filepath in targets:
        source = sources_by_file.get(filepath)
        issues = check_file(filepath, config=config, known_exports=known_exports)
        issues = filter_issues(issues, config, min_severity=min_severity)
        file_reports.append((filepath, issues, source))

    run_bandit = config.use_bandit if use_bandit is None else use_bandit
    if run_bandit and targets:
        if shutil.which('bandit') is None:
            print(
                "Warning: --bandit requested but the 'bandit' executable was not found",
                file=sys.stderr,
            )
        else:
            bandit_issues = collect_bandit_issues(targets)
            by_file: Dict[str, List[Issue]] = {}
            for issue in bandit_issues:
                by_file.setdefault(os.path.abspath(issue.filename), []).append(issue)
            for index, (filepath, issues, source) in enumerate(file_reports):
                extra = by_file.get(os.path.abspath(filepath), [])
                if source:
                    lines = source.split('\n')
                    kept = []
                    for issue in extra:
                        if issue.line <= 0 or issue.line > len(lines):
                            kept.append(issue)
                            continue
                        codes = ignored_codes_on_line(lines[issue.line - 1])
                        if codes is None:
                            kept.append(issue)
                        elif codes and issue.code.upper() not in codes:
                            kept.append(issue)
                    extra = kept
                extra = filter_issues(extra, config, min_severity=min_severity)
                if extra:
                    file_reports[index] = (filepath, issues + extra, source)

    if update_baseline:
        snapshot = [issue for _, issues, _ in file_reports for issue in issues]
        try:
            write_baseline(snapshot, update_baseline)
        except OSError as exc:
            print(f"Error: could not write baseline '{update_baseline}': {exc}", file=sys.stderr)
            return 1

    if baseline_path:
        try:
            fingerprints = load_baseline(baseline_path)
        except ConfigError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        file_reports = [
            (
                filepath,
                [issue for issue in issues if issue_fingerprint(issue) not in fingerprints],
                source,
            )
            for filepath, issues, source in file_reports
        ]

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
        if any_issues or len(file_reports) > 1:
            out.write(
                f"\nSummary: {errors} errors, {warnings} warnings, {infos} info\n"
            )

    return 1 if errors else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='codesnake',
        description='CodeSnake - Semantic Code Checker for Python 3',
    )
    parser.add_argument('files', nargs='*', help='Python files or directories to check')
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
    parser.add_argument(
        '--bandit',
        action='store_true',
        help='Merge findings from the bandit security scanner if it is installed',
    )
    parser.add_argument(
        '--staged',
        action='store_true',
        help='Check only Python files staged in git',
    )
    parser.add_argument('--baseline', help='Ignore issues listed in this baseline JSON file')
    parser.add_argument(
        '--update-baseline',
        metavar='FILE',
        help='Write current findings to a baseline JSON file',
    )
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

    if not args.files and not args.staged:
        parser.print_help()
        return 1

    return run_check(
        args.files,
        config_path=args.config,
        output_format=args.format,
        min_severity=args.severity,
        show_banner=(args.format == 'text'),
        color=False if args.no_color else None,
        use_bandit=True if args.bandit else None,
        staged=args.staged,
        baseline_path=args.baseline,
        update_baseline=args.update_baseline,
    )


if __name__ == '__main__':
    sys.exit(main())
