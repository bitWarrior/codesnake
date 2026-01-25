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

# Virtual environment path
VENV_PATH="${SCRIPT_DIR}/${VENV_NAME}"

# Function to create virtual environment if it doesn't exist
create_venv() {
    echo -e "${YELLOW}Creating virtual environment: ${VENV_NAME}${NC}"
    python3 -m venv "${VENV_PATH}"
    
    # Activate and upgrade pip
    source "${VENV_PATH}/bin/activate"
    pip install --upgrade pip
    
    # Install optional dependencies if user wants them
    read -p "Install optional tools (pylint, flake8, mypy, bandit)? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}Installing optional tools...${NC}"
        pip install pylint flake8 mypy bandit
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
    
    # Check if codesnake.py exists
    if [ ! -f "${SCRIPT_DIR}/src/codesnake.py" ]; then
        echo -e "${RED}Error: src/codesnake.py not found in ${SCRIPT_DIR}${NC}"
        exit 1
    fi
    
    # Run CodeSnake with all passed arguments
    if [ $# -eq 0 ]; then
        # No arguments - show help
        python "${SCRIPT_DIR}/src/codesnake.py"
    else
        # Pass all arguments to CodeSnake
        python "${SCRIPT_DIR}/src/codesnake.py" "$@"
    fi
}

# Run main function with all script arguments
main "$@"
