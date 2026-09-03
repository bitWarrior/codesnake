#!/bin/bash
#
# CodeSnake Enhanced Launcher
# Supports multiple modes and virtual environment management
#

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
VENV_NAME="codesnake-venv"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VENV_PATH="${SCRIPT_DIR}/${VENV_NAME}"

if command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
elif command -v python >/dev/null 2>&1; then
    PYTHON=python
else
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    exit 1
fi

# Help message
show_help() {
    cat << EOF
${CYAN}CodeSnake Enhanced Launcher${NC}

Usage: $0 [OPTIONS] [files...]

Options:
    -h, --help              Show this help message
    -v, --version           Show CodeSnake version
    -e, --enhanced          (deprecated, no-op: all features live in the main CLI)
    -c, --config FILE       Use configuration file
    -f, --format FORMAT     Output format (text|json|github|sarif)
    -s, --severity LEVEL    Minimum severity (error|warning|info)
    --create-venv           Create/recreate virtual environment
    --no-venv               Run without activating virtual environment
    --test                  Run test suite
    --banner                Show CodeSnake banner

Any other argument (files, directories, --bandit, --staged, --no-ignore,
--baseline FILE, --no-color, ...) is passed straight through to CodeSnake.

Examples:
    $0 mycode.py                           # Check a file
    $0 --config .codesnake.json *.py       # Check with a config file
    $0 --test                               # Run tests
    $0 --create-venv                        # Setup virtual environment

EOF
}

# Create virtual environment
create_venv() {
    echo -e "${YELLOW}Creating virtual environment: ${VENV_NAME}${NC}"
    
    # Remove existing venv if present
    if [ -d "${VENV_PATH}" ]; then
        echo -e "${YELLOW}Removing existing virtual environment...${NC}"
        rm -rf "${VENV_PATH}"
    fi
    
    "$PYTHON" -m venv "${VENV_PATH}"
    source "${VENV_PATH}/bin/activate"
    
    echo -e "${GREEN}Upgrading pip...${NC}"
    pip install --upgrade pip --quiet
    
    # Ask about optional dependencies
    echo -e "\n${CYAN}Optional Tools:${NC}"
    echo "  - pylint: Advanced Python linter"
    echo "  - flake8: Style guide enforcement"
    echo "  - mypy: Static type checker"
    echo "  - bandit: Security issue scanner"
    echo
    
    read -p "Install optional tools? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}Installing CodeSnake with optional tools...${NC}"
        pip install -e "${SCRIPT_DIR}[tools]" --quiet
        echo -e "${GREEN}✓ CodeSnake and optional tools installed${NC}"
    else
        pip install -e "${SCRIPT_DIR}" --quiet
        echo -e "${GREEN}✓ CodeSnake installed${NC}"
    fi
    
    echo -e "\n${GREEN}✓ Virtual environment created successfully!${NC}"
    echo -e "${CYAN}Location: ${VENV_PATH}${NC}\n"
}

# Activate virtual environment
activate_venv() {
    if [ -f "${VENV_PATH}/bin/activate" ]; then
        source "${VENV_PATH}/bin/activate"
        echo -e "${GREEN}🐍 Virtual environment activated${NC}"
    else
        echo -e "${YELLOW}Virtual environment not found. Creating...${NC}"
        create_venv
        source "${VENV_PATH}/bin/activate"
    fi
}

# Parse arguments
USE_VENV=true
MODE="check"
PASSTHRU=()   # flags and files forwarded verbatim to CodeSnake

# Read the value for an option that requires one; fail clearly if missing.
need_value() {
    if [ -z "${2:-}" ]; then
        echo -e "${RED}Error: option '$1' requires a value${NC}" >&2
        exit 2
    fi
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--version)
            MODE="version"
            shift
            ;;
        -e|--enhanced)
            # Deprecated: the enhanced checker was merged into the main CLI.
            shift
            ;;
        -c|--config)
            need_value "$1" "${2:-}"
            PASSTHRU+=(--config "$2")
            shift 2
            ;;
        -f|--format)
            need_value "$1" "${2:-}"
            PASSTHRU+=(--format "$2")
            shift 2
            ;;
        -s|--severity)
            need_value "$1" "${2:-}"
            PASSTHRU+=(--severity "$2")
            shift 2
            ;;
        --create-venv)
            create_venv
            exit 0
            ;;
        --no-venv)
            USE_VENV=false
            shift
            ;;
        --test)
            MODE="test"
            shift
            ;;
        --banner)
            MODE="banner"
            shift
            ;;
        --)
            shift
            PASSTHRU+=("$@")
            break
            ;;
        *)
            # Files, directories, and any other CodeSnake flag
            # (--bandit, --staged, --baseline FILE, --no-color, ...).
            PASSTHRU+=("$1")
            shift
            ;;
    esac
done

# Activate virtual environment unless --no-venv specified
if [ "$USE_VENV" = true ]; then
    activate_venv
fi

# Make the package importable even without an editable install.
export PYTHONPATH="${SCRIPT_DIR}/src${PYTHONPATH:+:$PYTHONPATH}"

case "$MODE" in
    test)
        if [ -f "${SCRIPT_DIR}/test/test_codesnake.py" ]; then
            exec "$PYTHON" "${SCRIPT_DIR}/test/test_codesnake.py"
        fi
        echo -e "${RED}Error: test/test_codesnake.py not found${NC}" >&2
        exit 1
        ;;
    banner)
        exec "$PYTHON" -m codesnake --banner
        ;;
    version)
        exec "$PYTHON" -m codesnake --version
        ;;
    *)
        # Arguments are passed as an array: paths with spaces or shell
        # metacharacters are never re-parsed by the shell.
        exec "$PYTHON" -m codesnake check "${PASSTHRU[@]}"
        ;;
esac
