"""
CodeSnake - Semantic Code Checker for Python 3

A static analysis tool that detects security vulnerabilities, code smells,
anti-patterns, and potential bugs through AST-based semantic analysis.

🐍 Strikes at code problems before they bite!
"""

from ._version import __version__
from .checker import (
    CheckerConfig,
    ConfigError,
    analyze_files,
    discover_config_file,
    find_repo_root,
    issue_fingerprints,
    normalize_issue_message,
    resolve_jobs,
    EnhancedSemanticChecker,
    Issue,
    SemanticChecker,
    check_file,
    collect_bandit_issues,
    collect_module_exports,
    expand_python_targets,
    filter_issues,
    format_github_report,
    format_issue,
    format_json_report,
    format_sarif_report,
    git_staged_python_files,
    issue_fingerprint,
    issue_ignored_by_pragma,
    load_baseline,
    load_config,
    read_python_source,
    run_check,
    write_baseline,
)
from .cli import main

__author__ = "CodeSnake Contributors"
__license__ = "MIT"

__all__ = [
    '__version__',
    'CheckerConfig',
    'ConfigError',
    'analyze_files',
    'discover_config_file',
    'find_repo_root',
    'issue_fingerprints',
    'normalize_issue_message',
    'resolve_jobs',
    'EnhancedSemanticChecker',
    'Issue',
    'SemanticChecker',
    'check_file',
    'collect_bandit_issues',
    'collect_module_exports',
    'expand_python_targets',
    'filter_issues',
    'format_github_report',
    'format_issue',
    'format_json_report',
    'format_sarif_report',
    'git_staged_python_files',
    'issue_fingerprint',
    'issue_ignored_by_pragma',
    'load_baseline',
    'load_config',
    'main',
    'read_python_source',
    'run_check',
    'write_baseline',
]
