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
    load_config,
    run_check,
)

__all__ = [
    'CheckerConfig',
    'ConfigError',
    'EnhancedSemanticChecker',
    'Issue',
    'SemanticChecker',
    'check_file',
    'load_config',
    'run_check',
]
