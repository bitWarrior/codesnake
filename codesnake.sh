#!/bin/bash
#
# CodeSnake Launcher Script
# Activates the virtual environment and runs CodeSnake
#

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Default virtual environment name
VENV_NAME="codesnake-venv"

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
elif command -v python >/dev/null 2>&1; then
    PYTHON=python
else
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    exit 1
fi

# Virtual environment path
VENV_PATH="${SCRIPT_DIR}/${VENV_NAME}"

# Function to create virtual environment if it doesn't exist
create_venv() {
    echo -e "${YELLOW}Creating virtual environment: ${VENV_NAME}${NC}"
    "$PYTHON" -m venv "${VENV_PATH}"
    
    # Activate and upgrade pip
    source "${VENV_PATH}/bin/activate"
    pip install --upgrade pip
    
    # Install this project from pyproject.toml
    read -p "Install optional tools (pylint, flake8, mypy, bandit, isort)? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}Installing CodeSnake with optional tools...${NC}"
        pip install -e "${SCRIPT_DIR}[tools]"
    else
        pip install -e "${SCRIPT_DIR}"
    fi
    
    echo -e "${GREEN}✓ Virtual environment created successfully!${NC}"
}

# Function to activate virtual environment
activate_venv() {
    if [ -f "${VENV_PATH}/bin/activate" ]; then
        source "${VENV_PATH}/bin/activate"
        echo -e "${GREEN}🐍 Activated virtual environment: ${VENV_NAME}${NC}"
    else
        echo -e "${RED}Error: Virtual environment not found at ${VENV_PATH}${NC}"
        echo -e "${YELLOW}Creating virtual environment...${NC}"
        create_venv
        source "${VENV_PATH}/bin/activate"
    fi
}

# Main script
main() {
    # Activate virtual environment
    activate_venv
    
    # Make the package importable even without an editable install.
    export PYTHONPATH="${SCRIPT_DIR}/src${PYTHONPATH:+:$PYTHONPATH}"

    if [ ! -f "${SCRIPT_DIR}/src/codesnake/checker.py" ]; then
        echo -e "${RED}Error: src/codesnake/checker.py not found in ${SCRIPT_DIR}${NC}"
        exit 1
    fi

    # Run CodeSnake with all passed arguments (no arguments shows help)
    exec "$PYTHON" -m codesnake "$@"
}

# Run main function with all script arguments
main "$@"
