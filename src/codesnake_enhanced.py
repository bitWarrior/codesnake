#!/usr/bin/env python3
"""
Compatibility entry point for the enhanced CodeSnake CLI.

Configuration, multi-file checking, and output formats live in codesnake.py.
This module keeps documented `codesnake_enhanced.py` invocations working.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from codesnake import (  # noqa: E402
    CheckerConfig,
    ConfigError,
    EnhancedSemanticChecker,
    Issue,
    SemanticChecker,
    check_file,
    load_config,
    main,
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
    'main',
    'run_check',
]


if __name__ == '__main__':
    sys.exit(main())
