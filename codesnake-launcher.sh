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

# Help message
show_help() {
    cat << EOF
${CYAN}CodeSnake Enhanced Launcher${NC}

Usage: $0 [OPTIONS] [files...]

Options:
    -h, --help              Show this help message
    -v, --version           Show CodeSnake version
    -e, --enhanced          Use enhanced version (codesnake_enhanced.py)
    -c, --config FILE       Use configuration file
    -f, --format FORMAT     Output format (text|json|github|sarif)
    -s, --severity LEVEL    Minimum severity (error|warning|info)
    --create-venv           Create/recreate virtual environment
    --no-venv               Run without activating virtual environment
    --test                  Run test suite
    --banner                Show CodeSnake banner

Examples:
    $0 mycode.py                           # Check a file
    $0 -e --config .codesnake.json *.py    # Enhanced mode with config
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
    
    python3 -m venv "${VENV_PATH}"
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
        echo -e "${GREEN}Installing optional tools...${NC}"
        pip install pylint flake8 mypy bandit --quiet
        echo -e "${GREEN}✓ Optional tools installed${NC}"
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
USE_ENHANCED=false
USE_VENV=true
CONFIG_FILE=""
FORMAT=""
SEVERITY=""
MODE="check"
FILES=()

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
            USE_ENHANCED=true
            shift
            ;;
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -f|--format)
            FORMAT="$2"
            shift 2
            ;;
        -s|--severity)
            SEVERITY="$2"
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
        *)
            FILES+=("$1")
            shift
            ;;
    esac
done

# Activate virtual environment unless --no-venv specified
if [ "$USE_VENV" = true ]; then
    activate_venv
fi

# Build command based on mode
if [ "$MODE" = "test" ]; then
    # Run tests
    if [ -f "${SCRIPT_DIR}/test/test_codesnake.py" ]; then
        python "${SCRIPT_DIR}/test/test_codesnake.py"
    else
        echo -e "${RED}Error: test/test_codesnake.py not found${NC}"
        exit 1
    fi
    
elif [ "$MODE" = "banner" ]; then
    # Show banner
    if [ -f "${SCRIPT_DIR}/src/demo_banner.py" ]; then
        python "${SCRIPT_DIR}/src/demo_banner.py"
    else
        python -c "import sys; sys.path.insert(0, '${SCRIPT_DIR}/src'); from codesnake_banner import print_snake_banner; print_snake_banner()"
    fi
    
elif [ "$MODE" = "version" ]; then
    # Show version
    python -c "import sys; sys.path.insert(0, '${SCRIPT_DIR}/src'); from codesnake_banner import print_version; print_version()"
    
else
    # Check files
    if [ "$USE_ENHANCED" = true ]; then
        CMD="python ${SCRIPT_DIR}/src/codesnake_enhanced.py"
    else
        CMD="python ${SCRIPT_DIR}/src/codesnake.py"
    fi
    
    # Add optional arguments
    if [ -n "$CONFIG_FILE" ]; then
        CMD="$CMD --config $CONFIG_FILE"
    fi
    
    if [ -n "$FORMAT" ]; then
        CMD="$CMD --format $FORMAT"
    fi
    
    if [ -n "$SEVERITY" ]; then
        CMD="$CMD --severity $SEVERITY"
    fi
    
    # Add files
    if [ ${#FILES[@]} -eq 0 ]; then
        # No files specified - show help
        eval "$CMD"
    else
        # Check specified files
        eval "$CMD ${FILES[@]}"
    fi
fi
