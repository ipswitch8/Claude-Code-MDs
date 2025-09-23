#!/bin/bash

# Claude Security Defaults - Quick Setup Script
# Installs comprehensive security configuration for any project

set -e  # Exit on any error

# NOTE: Update this URL to point to your actual repository
# For private repositories, you'll need to use a different method or make it public
REPO_URL="https://raw.githubusercontent.com/ipswitch8/claude-security-defaults/main"
PROJECT_DIR="$PWD"
PROJECT_NAME="${PWD##*/}"

echo "🔒 CLAUDE SECURITY SETUP STARTING"
echo "Project: $PROJECT_NAME"
echo "Directory: $PROJECT_DIR"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function to print status
print_status() {
    local status="$1"
    local message="$2"
    case "$status" in
        "success") echo -e "${GREEN}✅ $message${NC}" ;;
        "warning") echo -e "${YELLOW}⚠️  $message${NC}" ;;
        "error") echo -e "${RED}❌ $message${NC}" ;;
        "info") echo -e "${BLUE}ℹ️  $message${NC}" ;;
    esac
}

# Function to download file with fallback
download_file() {
    local file="$1"
    local url="$REPO_URL/$file"
    
    if command -v curl >/dev/null 2>&1; then
        if curl -sSL "$url" > "$file" 2>/dev/null; then
            return 0
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -q -O "$file" "$url" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

# Check if we have internet access
check_internet() {
    if command -v curl >/dev/null 2>&1; then
        curl -s --connect-timeout 5 https://github.com >/dev/null 2>&1
    elif command -v wget >/dev/null 2>&1; then
        wget -q --spider --timeout=5 https://github.com 2>/dev/null
    else
        print_status "error" "Neither curl nor wget available for downloading files"
        return 1
    fi
}

# Create basic security files if download fails
create_basic_files() {
    print_status "warning" "Creating basic security files (offline mode)"
    
    # Basic security audit script
    cat > security-audit.sh << 'EOF'
#!/bin/bash
echo "🔒 Basic Security Check"
[ -d ".git" ] && chmod -R 700 .git && echo "✅ Secured .git directory"
find . -maxdepth 2 -name "*.swp" -o -name "*.tmp" -o -name "*~" -delete 2>/dev/null && echo "✅ Cleaned temp files"
if command -v grep >/dev/null; then
    secrets=$(grep -ri "password.*=" . | grep -v ".git" | head -3)
    [ -n "$secrets" ] && echo "⚠️ Potential secrets found" || echo "✅ No obvious secrets detected"
fi
echo "✅ Basic security check complete"
EOF
    chmod +x security-audit.sh
    
    # Basic security config
    cat > .claude-security.json << 'EOF'
{
  "project_name": "project",
  "security_config": {
    "auto_fix_enabled": true,
    "alert_on_critical": true
  },
  "sensitive_file_patterns": ["*.key", "*.pem", ".env*", "*.sql"]
}
EOF

    # Basic CLAUDE.md
    cat > CLAUDE.md << 'EOF'
# Security Requirements

## Mandatory Checks
- Run `./security-audit.sh` before any work
- Secure .git directory: `chmod -R 700 .git`
- Remove temp files: `find . -name "*.swp" -delete`
- Check for secrets: `grep -ri "password\|key\|secret" .`

## Critical Issues Block Development
Never proceed with CRITICAL security issues unresolved.
EOF
}

# Main setup process
main() {
    print_status "info" "Starting security setup..."
    
    # Check for existing files
    if [ -f "security-audit.sh" ] || [ -f ".claude-security.json" ] || [ -f "CLAUDE.md" ]; then
        echo ""
        read -p "Security files already exist. Overwrite? (y/N): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "info" "Setup cancelled by user"
            exit 0
        fi
    fi
    
    echo ""
    print_status "info" "Downloading security template files..."
    
    # Try to download files
    if check_internet; then
        # Download security-audit.sh
        if download_file "security-audit.sh"; then
            chmod +x security-audit.sh
            print_status "success" "Downloaded security-audit.sh"
        else
            print_status "error" "Failed to download security-audit.sh"
            create_basic_files
            return
        fi
        
        # Download .claude-security.json
        if download_file ".claude-security.json"; then
            print_status "success" "Downloaded .claude-security.json"
        else
            print_status "warning" "Failed to download .claude-security.json"
        fi
        
        # Download CLAUDE.md
        if download_file "CLAUDE.md"; then
            print_status "success" "Downloaded CLAUDE.md"
        else
            print_status "warning" "Failed to download CLAUDE.md"
        fi
        
    else
        print_status "warning" "No internet access - creating basic files"
        create_basic_files
        return
    fi
    
    # Update project name in config files
    if [ -f ".claude-security.json" ]; then
        if command -v sed >/dev/null 2>&1; then
            sed -i.bak "s/template_project/$PROJECT_NAME/g" .claude-security.json 2>/dev/null || true
            rm -f .claude-security.json.bak 2>/dev/null || true
        fi
    fi
    
    # Initialize git if not already a repo
    if [ ! -d ".git" ]; then
        echo ""
        read -p "Initialize git repository? (Y/n): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            git init >/dev/null 2>&1 && print_status "success" "Git repository initialized"
            chmod -R 700 .git 2>/dev/null && print_status "success" "Git permissions secured"
        fi
    else
        # Secure existing git directory
        chmod -R 700 .git 2>/dev/null && print_status "success" "Existing git permissions secured"
    fi
    
    # Create .gitignore if it doesn't exist
    if [ ! -f ".gitignore" ]; then
        cat > .gitignore << 'EOF'
# Security
*.key
*.pem
*.p12
*.pfx
.env*
credentials*
secrets*

# Temporary files
*.swp
*.tmp
*~
.DS_Store

# Logs
*.log
security-audit.log

# Dependencies
node_modules/
.venv/
__pycache__/
EOF
        print_status "success" "Created .gitignore with security patterns"
    fi
    
    echo ""
    print_status "info" "Running initial security audit..."
    
    # Run security audit
    if [ -x "./security-audit.sh" ]; then
        if ./security-audit.sh; then
            print_status "success" "Initial security audit passed!"
        else
            audit_exit_code=$?
            if [ $audit_exit_code -eq 1 ]; then
                print_status "error" "CRITICAL security issues found!"
                echo "Review the output above and fix issues before proceeding."
            elif [ $audit_exit_code -eq 2 ]; then
                print_status "warning" "Security issues found - review recommended"
            fi
        fi
    fi
    
    echo ""
    print_status "success" "Security setup complete!"
    echo ""
    echo "Files created:"
    echo "  - security-audit.sh (comprehensive security scanner)"
    echo "  - .claude-security.json (project security configuration)"
    echo "  - CLAUDE.md (security documentation)"
    echo "  - .gitignore (security-aware patterns)"
    echo ""
    echo "Next steps:"
    echo "  1. Review CLAUDE.md for security requirements"
    echo "  2. Run ./security-audit.sh before any development"
    echo "  3. Fix any security issues reported"
    echo "  4. Add security checks to your CI/CD pipeline"
    echo ""
    print_status "info" "Security is now mandatory for this project!"
}

# Handle script interruption
trap 'print_status "error" "Setup interrupted"; exit 1' INT TERM

# Run main function
main "$@"