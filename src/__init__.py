"""
CodeSnake - Semantic Code Checker for Python 3

A comprehensive static analysis tool that detects security vulnerabilities,
code smells, anti-patterns, and potential bugs through semantic analysis.

🐍 Strikes at code problems before they bite!
"""

__version__ = "1.0.0"
__author__ = "CodeSnake Contributors"
__license__ = "MIT"

from .codesnake import (
    CheckerConfig,
    ConfigError,
    EnhancedSemanticChecker,
    Issue,
    SemanticChecker,
    check_file,
    collect_module_exports,
    expand_python_targets,
    git_staged_python_files,
    issue_fingerprint,
    load_baseline,
    load_config,
    read_python_source,
    run_check,
    write_baseline,
)

__all__ = [
    'CheckerConfig',
    'ConfigError',
    'EnhancedSemanticChecker',
    'Issue',
    'SemanticChecker',
    'check_file',
    'collect_module_exports',
    'expand_python_targets',
    'git_staged_python_files',
    'issue_fingerprint',
    'load_baseline',
    'load_config',
    'read_python_source',
    'run_check',
    'write_baseline',
]
