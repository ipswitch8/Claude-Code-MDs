# Bash Scripting Claude Code Guidelines

*Last Updated: 2025-01-16 | Version: 1.0*

## 🏗️ Bash Script Project Structure

### **Script Organization**
```
bash-project/
├── scripts/
│   ├── lib/
│   │   ├── common.sh       # Common functions
│   │   ├── logging.sh      # Logging utilities
│   │   └── validation.sh   # Input validation
│   ├── config/
│   │   ├── settings.conf   # Configuration files
│   │   └── env.conf        # Environment variables
│   ├── main.sh            # Main script entry point
│   ├── install.sh         # Installation script
│   └── utils/
│       ├── backup.sh
│       ├── deploy.sh
│       └── maintenance.sh
├── tests/
│   ├── test_main.sh
│   └── test_utils.sh
├── docs/
│   └── README.md
├── logs/
└── .gitignore
```

### **Single Script Template**
```bash
#!/bin/bash

# Script: example.sh
# Description: Brief description of what this script does
# Author: Your Name
# Version: 1.0
# Last Modified: 2025-01-16

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Script directory
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_NAME="$(basename "$0")"

# Configuration
readonly CONFIG_FILE="${SCRIPT_DIR}/config/settings.conf"
readonly LOG_FILE="${SCRIPT_DIR}/logs/${SCRIPT_NAME%.*}.log"

# Default values
DEBUG=${DEBUG:-false}
VERBOSE=${VERBOSE:-false}
DRY_RUN=${DRY_RUN:-false}

# Source common functions
source "${SCRIPT_DIR}/lib/common.sh" 2>/dev/null || {
    echo "Error: Cannot source common.sh" >&2
    exit 1
}

# Main script logic here
main() {
    log_info "Starting ${SCRIPT_NAME}"

    # Your script logic

    log_info "Completed ${SCRIPT_NAME}"
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
```

## 🔧 Development Best Practices

### **Script Safety and Error Handling**
```bash
#!/bin/bash

# Strict error handling
set -euo pipefail

# Trap errors and cleanup
trap 'error_handler $? $LINENO' ERR
trap 'cleanup' EXIT INT TERM

error_handler() {
    local exit_code=$1
    local line_number=$2
    echo "Error: Script failed with exit code $exit_code at line $line_number" >&2
    echo "Command that failed: ${BASH_COMMAND}" >&2
    cleanup
    exit "$exit_code"
}

cleanup() {
    # Clean up temporary files, processes, etc.
    [[ -n "${TEMP_DIR:-}" ]] && rm -rf "$TEMP_DIR"
    [[ -n "${PID_FILE:-}" ]] && rm -f "$PID_FILE"
}

# Create temporary directory safely
create_temp_dir() {
    TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}.XXXXXX")
    echo "$TEMP_DIR"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Require specific commands
require_commands() {
    local missing_commands=()

    for cmd in "$@"; do
        if ! command_exists "$cmd"; then
            missing_commands+=("$cmd")
        fi
    done

    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        log_error "Missing required commands: ${missing_commands[*]}"
        exit 1
    fi
}
```

### **Logging Framework**
```bash
#!/bin/bash
# lib/logging.sh

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Log levels
readonly LOG_LEVEL_ERROR=0
readonly LOG_LEVEL_WARN=1
readonly LOG_LEVEL_INFO=2
readonly LOG_LEVEL_DEBUG=3

# Current log level (can be overridden)
LOG_LEVEL=${LOG_LEVEL:-$LOG_LEVEL_INFO}

# Log function
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local color=""
    local level_name=""

    case $level in
        $LOG_LEVEL_ERROR)
            level_name="ERROR"
            color=$RED
            ;;
        $LOG_LEVEL_WARN)
            level_name="WARN "
            color=$YELLOW
            ;;
        $LOG_LEVEL_INFO)
            level_name="INFO "
            color=$GREEN
            ;;
        $LOG_LEVEL_DEBUG)
            level_name="DEBUG"
            color=$CYAN
            ;;
    esac

    if [[ $level -le $LOG_LEVEL ]]; then
        if [[ -t 1 ]]; then  # Check if stdout is a terminal
            echo -e "${color}[$timestamp] $level_name: $message${NC}"
        else
            echo "[$timestamp] $level_name: $message"
        fi

        # Also log to file if LOG_FILE is set
        if [[ -n "${LOG_FILE:-}" ]]; then
            echo "[$timestamp] $level_name: $message" >> "$LOG_FILE"
        fi
    fi
}

log_error() { log $LOG_LEVEL_ERROR "$1"; }
log_warn()  { log $LOG_LEVEL_WARN "$1"; }
log_info()  { log $LOG_LEVEL_INFO "$1"; }
log_debug() { log $LOG_LEVEL_DEBUG "$1"; }

# Progress indicator
show_progress() {
    local current=$1
    local total=$2
    local message=${3:-"Processing"}
    local width=50
    local percentage=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))

    printf "\r%s [" "$message"
    printf "%${filled}s" | tr ' ' '='
    printf "%${empty}s" | tr ' ' '-'
    printf "] %d%%" "$percentage"

    if [[ $current -eq $total ]]; then
        echo
    fi
}
```

### **Input Validation and User Interaction**
```bash
#!/bin/bash
# lib/validation.sh

# Validate email address
validate_email() {
    local email=$1
    local regex='^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if [[ $email =~ $regex ]]; then
        return 0
    else
        return 1
    fi
}

# Validate IP address
validate_ip() {
    local ip=$1
    local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'

    if [[ $ip =~ $regex ]]; then
        # Check each octet is 0-255
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [[ $octet -gt 255 ]] || [[ $octet -lt 0 ]]; then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Validate file exists and is readable
validate_file() {
    local file=$1

    if [[ ! -f "$file" ]]; then
        log_error "File does not exist: $file"
        return 1
    fi

    if [[ ! -r "$file" ]]; then
        log_error "File is not readable: $file"
        return 1
    fi

    return 0
}

# Validate directory exists and is writable
validate_directory() {
    local dir=$1

    if [[ ! -d "$dir" ]]; then
        log_error "Directory does not exist: $dir"
        return 1
    fi

    if [[ ! -w "$dir" ]]; then
        log_error "Directory is not writable: $dir"
        return 1
    fi

    return 0
}

# Prompt for user confirmation
confirm() {
    local message=${1:-"Are you sure?"}
    local default=${2:-"n"}
    local response

    if [[ "$default" == "y" || "$default" == "Y" ]]; then
        read -p "$message [Y/n]: " response
        response=${response:-y}
    else
        read -p "$message [y/N]: " response
        response=${response:-n}
    fi

    case "$response" in
        [yY]|[yY][eE][sS])
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Prompt for input with validation
prompt_input() {
    local prompt=$1
    local validator=${2:-}
    local default=${3:-}
    local value

    while true; do
        if [[ -n "$default" ]]; then
            read -p "$prompt [$default]: " value
            value=${value:-$default}
        else
            read -p "$prompt: " value
        fi

        if [[ -z "$validator" ]] || $validator "$value"; then
            echo "$value"
            return 0
        else
            log_error "Invalid input. Please try again."
        fi
    done
}

# Secure password input
prompt_password() {
    local prompt=${1:-"Password"}
    local password
    local confirm

    while true; do
        read -s -p "$prompt: " password
        echo
        read -s -p "Confirm password: " confirm
        echo

        if [[ "$password" == "$confirm" ]]; then
            if [[ ${#password} -ge 8 ]]; then
                echo "$password"
                return 0
            else
                log_error "Password must be at least 8 characters long."
            fi
        else
            log_error "Passwords do not match."
        fi
    done
}
```

## 🚨 Bash Testing Protocol

### **When Script Testing is Required**
- Any changes to shell scripts
- Changes to configuration files
- Updates to environment variables
- Modifications to file permissions or paths
- Changes to external command dependencies

### **Testing Protocol for Bash Scripts**
After the universal 7-step protocol, add these framework-specific steps:

8. **[ ] Syntax validation** - Run `bash -n script.sh` to check syntax
9. **[ ] Shellcheck analysis** - Run `shellcheck script.sh` for best practices
10. **[ ] Test with different inputs** - Validate edge cases and error conditions
11. **[ ] Check file permissions** - Ensure scripts are executable
12. **[ ] Verify external dependencies** - Confirm all required commands are available

### **Script Testing Framework**
```bash
#!/bin/bash
# tests/test_framework.sh

# Simple testing framework for bash scripts
TEST_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0

# Test assertion functions
assert_equals() {
    local expected=$1
    local actual=$2
    local message=${3:-"Assertion failed"}

    TEST_COUNT=$((TEST_COUNT + 1))

    if [[ "$expected" == "$actual" ]]; then
        log_info "✓ PASS: $message"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        log_error "✗ FAIL: $message"
        log_error "  Expected: '$expected'"
        log_error "  Actual:   '$actual'"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

assert_true() {
    local condition=$1
    local message=${2:-"Assertion failed"}

    if $condition; then
        assert_equals "true" "true" "$message"
    else
        assert_equals "true" "false" "$message"
    fi
}

assert_file_exists() {
    local file=$1
    local message=${2:-"File should exist: $file"}

    if [[ -f "$file" ]]; then
        assert_equals "true" "true" "$message"
    else
        assert_equals "true" "false" "$message"
    fi
}

# Test runner
run_tests() {
    log_info "Running tests..."

    # Run all test functions
    for func in $(declare -F | grep "test_" | awk '{print $3}'); do
        log_info "Running $func"
        $func
    done

    # Print summary
    log_info ""
    log_info "Test Summary:"
    log_info "  Total:  $TEST_COUNT"
    log_info "  Passed: $PASS_COUNT"
    log_info "  Failed: $FAIL_COUNT"

    if [[ $FAIL_COUNT -eq 0 ]]; then
        log_info "All tests passed!"
        return 0
    else
        log_error "$FAIL_COUNT test(s) failed!"
        return 1
    fi
}

# Example test function
test_email_validation() {
    source "${SCRIPT_DIR}/lib/validation.sh"

    # Test valid emails
    assert_true "validate_email 'user@example.com'" "Valid email should pass"
    assert_true "validate_email 'user.name+tag@example.com'" "Email with dot and plus should pass"

    # Test invalid emails
    assert_true "! validate_email 'invalid-email'" "Invalid email should fail"
    assert_true "! validate_email 'user@'" "Incomplete email should fail"
}
```

## 🔧 Configuration Management

### **Configuration File Handling**
```bash
#!/bin/bash
# lib/config.sh

# Default configuration
declare -A CONFIG
CONFIG[app_name]="MyApp"
CONFIG[version]="1.0.0"
CONFIG[debug]="false"
CONFIG[log_level]="info"

# Load configuration from file
load_config() {
    local config_file=${1:-"$CONFIG_FILE"}

    if [[ ! -f "$config_file" ]]; then
        log_warn "Configuration file not found: $config_file"
        return 1
    fi

    log_debug "Loading configuration from: $config_file"

    # Read configuration file
    while IFS='=' read -r key value; do
        # Skip comments and empty lines
        [[ $key =~ ^[[:space:]]*# ]] && continue
        [[ -z $key ]] && continue

        # Remove leading/trailing whitespace
        key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        # Remove quotes if present
        value="${value%\"}"
        value="${value#\"}"
        value="${value%\'}"
        value="${value#\'}"

        CONFIG[$key]="$value"
        log_debug "Config: $key = $value"
    done < "$config_file"
}

# Get configuration value
get_config() {
    local key=$1
    local default=${2:-}

    echo "${CONFIG[$key]:-$default}"
}

# Set configuration value
set_config() {
    local key=$1
    local value=$2

    CONFIG[$key]="$value"
}

# Save configuration to file
save_config() {
    local config_file=${1:-"$CONFIG_FILE"}

    log_info "Saving configuration to: $config_file"

    # Create directory if it doesn't exist
    mkdir -p "$(dirname "$config_file")"

    # Write configuration
    {
        echo "# Configuration file generated on $(date)"
        echo "# Do not edit this file manually"
        echo ""

        for key in "${!CONFIG[@]}"; do
            echo "$key=${CONFIG[$key]}"
        done
    } > "$config_file"
}
```

### **Environment Variable Management**
```bash
#!/bin/bash
# lib/env.sh

# Load environment variables from .env file
load_env() {
    local env_file=${1:-".env"}

    if [[ -f "$env_file" ]]; then
        log_debug "Loading environment from: $env_file"

        # Export variables from .env file
        set -a  # Automatically export all variables
        source "$env_file"
        set +a  # Turn off automatic export
    fi
}

# Check required environment variables
require_env() {
    local missing_vars=()

    for var in "$@"; do
        if [[ -z "${!var:-}" ]]; then
            missing_vars+=("$var")
        fi
    done

    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        log_error "Missing required environment variables: ${missing_vars[*]}"
        return 1
    fi
}

# Set default values for environment variables
set_env_defaults() {
    export APP_ENV="${APP_ENV:-development}"
    export LOG_LEVEL="${LOG_LEVEL:-info}"
    export DEBUG="${DEBUG:-false}"
    export TEMP_DIR="${TEMP_DIR:-/tmp}"
}
```

## 🔄 Process Management

### **Service Management Scripts**
```bash
#!/bin/bash
# Service management script

SERVICE_NAME="${SERVICE_NAME:-myservice}"
PID_FILE="${PID_FILE:-/var/run/${SERVICE_NAME}.pid}"
LOG_FILE="${LOG_FILE:-/var/log/${SERVICE_NAME}.log}"
DAEMON_USER="${DAEMON_USER:-${SERVICE_NAME}}"

# Check if service is running
is_running() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        else
            rm -f "$PID_FILE"
            return 1
        fi
    fi
    return 1
}

# Start service
start_service() {
    if is_running; then
        log_warn "Service is already running"
        return 1
    fi

    log_info "Starting $SERVICE_NAME..."

    # Start the service (example)
    nohup sudo -u "$DAEMON_USER" /path/to/service \
        > "$LOG_FILE" 2>&1 &

    local pid=$!
    echo "$pid" > "$PID_FILE"

    # Wait a moment and check if it's still running
    sleep 2
    if is_running; then
        log_info "Service started successfully (PID: $pid)"
        return 0
    else
        log_error "Service failed to start"
        rm -f "$PID_FILE"
        return 1
    fi
}

# Stop service
stop_service() {
    if ! is_running; then
        log_warn "Service is not running"
        return 1
    fi

    local pid=$(cat "$PID_FILE")
    log_info "Stopping $SERVICE_NAME (PID: $pid)..."

    # Send TERM signal
    if kill "$pid" 2>/dev/null; then
        # Wait for graceful shutdown
        local count=0
        while kill -0 "$pid" 2>/dev/null && [[ $count -lt 30 ]]; do
            sleep 1
            count=$((count + 1))
        done

        # Force kill if still running
        if kill -0 "$pid" 2>/dev/null; then
            log_warn "Service didn't stop gracefully, forcing..."
            kill -9 "$pid" 2>/dev/null
        fi

        rm -f "$PID_FILE"
        log_info "Service stopped"
        return 0
    else
        log_error "Failed to stop service"
        return 1
    fi
}

# Restart service
restart_service() {
    stop_service
    sleep 2
    start_service
}

# Get service status
status_service() {
    if is_running; then
        local pid=$(cat "$PID_FILE")
        log_info "Service is running (PID: $pid)"
        return 0
    else
        log_info "Service is not running"
        return 1
    fi
}

# Main service management function
case "${1:-}" in
    start)
        start_service
        ;;
    stop)
        stop_service
        ;;
    restart)
        restart_service
        ;;
    status)
        status_service
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
```

## 🔒 Security Practices

### **Secure Script Practices**
```bash
#!/bin/bash

# Security best practices for bash scripts

# 1. Use secure temporary files
create_secure_temp() {
    local template=${1:-"script.XXXXXX"}
    local temp_file

    temp_file=$(mktemp "/tmp/$template")
    chmod 600 "$temp_file"  # Only owner can read/write
    echo "$temp_file"
}

# 2. Sanitize user input
sanitize_input() {
    local input=$1

    # Remove potentially dangerous characters
    input=$(echo "$input" | tr -d '`$(){}[];&|<>')

    # Limit length
    if [[ ${#input} -gt 256 ]]; then
        log_error "Input too long"
        return 1
    fi

    echo "$input"
}

# 3. Validate file paths
validate_path() {
    local path=$1
    local base_dir=${2:-}

    # Resolve to absolute path
    path=$(readlink -f "$path")

    # Check if path is within allowed directory
    if [[ -n "$base_dir" ]]; then
        base_dir=$(readlink -f "$base_dir")
        if [[ "$path" != "$base_dir"* ]]; then
            log_error "Path outside allowed directory: $path"
            return 1
        fi
    fi

    # Check for suspicious patterns
    if [[ "$path" =~ \.\. ]] || [[ "$path" =~ ^/ ]] && [[ -z "$base_dir" ]]; then
        log_error "Suspicious path: $path"
        return 1
    fi

    echo "$path"
}

# 4. Execute commands safely
execute_safe() {
    local cmd=("$@")

    log_debug "Executing: ${cmd[*]}"

    # Use arrays to prevent word splitting issues
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would execute: ${cmd[*]}"
        return 0
    fi

    "${cmd[@]}"
}

# 5. Handle secrets securely
handle_secret() {
    local secret=$1
    local temp_file

    # Never log secrets
    log_debug "Processing secret (content hidden)"

    # Use process substitution to avoid files
    process_secret() {
        local secret_data
        read -r secret_data
        # Process the secret
        echo "Processed: ${#secret_data} characters"
    }

    echo "$secret" | process_secret
}
```

## 📦 Packaging and Distribution

### **Installation Script**
```bash
#!/bin/bash
# install.sh

readonly INSTALL_DIR="${INSTALL_DIR:-/opt/myapp}"
readonly SERVICE_USER="${SERVICE_USER:-myapp}"
readonly SERVICE_GROUP="${SERVICE_GROUP:-myapp}"

# Installation functions
create_user() {
    if ! id "$SERVICE_USER" &>/dev/null; then
        log_info "Creating user: $SERVICE_USER"
        sudo useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
    fi
}

install_files() {
    log_info "Installing files to: $INSTALL_DIR"

    sudo mkdir -p "$INSTALL_DIR"
    sudo cp -r scripts/* "$INSTALL_DIR/"
    sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
    sudo chmod +x "$INSTALL_DIR"/*.sh
}

install_systemd_service() {
    local service_file="/etc/systemd/system/${SERVICE_USER}.service"

    log_info "Installing systemd service"

    sudo tee "$service_file" > /dev/null <<EOF
[Unit]
Description=My Application Service
After=network.target

[Service]
Type=forking
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/service.sh start
ExecStop=$INSTALL_DIR/service.sh stop
PIDFile=/var/run/${SERVICE_USER}.pid
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable "$SERVICE_USER"
}

# Main installation
main() {
    log_info "Installing application..."

    require_commands sudo systemctl

    create_user
    install_files
    install_systemd_service

    log_info "Installation completed successfully"
    log_info "Start the service with: sudo systemctl start $SERVICE_USER"
}

main "$@"
```

---

*This document covers Bash scripting best practices and should be used alongside universal patterns. For consolidated security guidance including environment variables and secrets management, see security-guidelines.md.*