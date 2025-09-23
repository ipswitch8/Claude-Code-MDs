#!/bin/bash

# Security Setup Script for Claude Code Projects
# Deploys comprehensive security suite to any project

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="$PWD"
PROJECT_NAME="${PWD##*/}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔒 CLAUDE CODE SECURITY SETUP${NC}"
echo "================================"
echo "Target Project: $PROJECT_NAME"
echo "Project Directory: $TARGET_DIR"
echo ""

# Check if we're in the template directory
if [[ "$TARGET_DIR" == *"Claude_Code_Foundation"* ]]; then
    echo -e "${YELLOW}⚠️  Warning: Running in template directory${NC}"
    echo "This will set up security files in the template itself."
    read -p "Continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Setup cancelled."
        exit 0
    fi
fi

echo -e "${BLUE}📋 Copying security files...${NC}"

# Copy security scripts
if [ -f "$SCRIPT_DIR/security-audit.sh" ]; then
    cp "$SCRIPT_DIR/security-audit.sh" "$TARGET_DIR/"
    chmod +x "$TARGET_DIR/security-audit.sh"
    echo -e "${GREEN}✅ Copied security-audit.sh${NC}"
else
    echo -e "${RED}❌ security-audit.sh not found in template${NC}"
    exit 1
fi

if [ -f "$SCRIPT_DIR/global-security.sh" ]; then
    cp "$SCRIPT_DIR/global-security.sh" "$TARGET_DIR/"
    chmod +x "$TARGET_DIR/global-security.sh"
    echo -e "${GREEN}✅ Copied global-security.sh${NC}"
else
    echo -e "${RED}❌ global-security.sh not found in template${NC}"
    exit 1
fi

# Copy security configuration
if [ -f "$SCRIPT_DIR/.claude-security.json" ]; then
    cp "$SCRIPT_DIR/.claude-security.json" "$TARGET_DIR/"
    echo -e "${GREEN}✅ Copied .claude-security.json${NC}"
else
    echo -e "${RED}❌ .claude-security.json not found in template${NC}"
    exit 1
fi

# Copy security documentation
if [ -f "$SCRIPT_DIR/mandatory-security-protocols.md" ]; then
    cp "$SCRIPT_DIR/mandatory-security-protocols.md" "$TARGET_DIR/"
    echo -e "${GREEN}✅ Copied mandatory-security-protocols.md${NC}"
fi

# Update project name in security config
if [ -f "$TARGET_DIR/.claude-security.json" ]; then
    sed -i.bak "s/template_project/$PROJECT_NAME/g" "$TARGET_DIR/.claude-security.json" 2>/dev/null || \
    sed -i "s/template_project/$PROJECT_NAME/g" "$TARGET_DIR/.claude-security.json"
    rm -f "$TARGET_DIR/.claude-security.json.bak"
    echo -e "${GREEN}✅ Updated project name in security config${NC}"
fi

echo -e "\n${BLUE}🔧 Setting up .gitignore security patterns...${NC}"

# Create or update .gitignore with security patterns
GITIGNORE_PATTERNS=(
    "# Security files"
    "*.key"
    "*.pem"
    "*.p12"
    "*.pfx"
    "*.crt"
    "*.cer"
    ".env*"
    "!.env.example"
    "credentials*"
    "secrets*"
    "backup*"
    "dump*"
    "*.sql"
    "*.db"
    "*.sqlite*"
    "security-audit.log"
    ""
    "# System files"
    ".DS_Store"
    "Thumbs.db"
    "*.tmp"
    "*.swp"
    "*~"
    "*.orig"
    "*.rej"
)

if [ ! -f "$TARGET_DIR/.gitignore" ]; then
    echo -e "${YELLOW}📝 Creating .gitignore file${NC}"
    touch "$TARGET_DIR/.gitignore"
fi

# Add security patterns if not present
for pattern in "${GITIGNORE_PATTERNS[@]}"; do
    if [ -n "$pattern" ] && ! grep -Fq "$pattern" "$TARGET_DIR/.gitignore" 2>/dev/null; then
        echo "$pattern" >> "$TARGET_DIR/.gitignore"
    fi
done

echo -e "${GREEN}✅ Updated .gitignore with security patterns${NC}"

echo -e "\n${BLUE}🔧 Setting up Git security...${NC}"

# Secure .git directory if it exists
if [ -d "$TARGET_DIR/.git" ]; then
    chmod -R 700 "$TARGET_DIR/.git"
    echo -e "${GREEN}✅ Secured .git directory permissions${NC}"

    # Check for credentials in git config
    if grep -q "https://.*:.*@" "$TARGET_DIR/.git/config" 2>/dev/null; then
        echo -e "${YELLOW}⚠️  Warning: Git config may contain credentials${NC}"
        echo "   Consider using SSH keys or credential helpers"
    fi
else
    echo -e "${BLUE}ℹ️  No .git directory found${NC}"
fi

echo -e "\n${BLUE}🧹 Initial cleanup...${NC}"

# Remove temporary files
temp_files_removed=0
for pattern in "*.swp" "*.tmp" "*~" ".DS_Store" "*.orig" "*.rej"; do
    if find "$TARGET_DIR" -maxdepth 2 -name "$pattern" -delete 2>/dev/null; then
        temp_files_removed=1
    fi
done

if [ $temp_files_removed -eq 1 ]; then
    echo -e "${GREEN}✅ Removed temporary files${NC}"
else
    echo -e "${GREEN}✅ No temporary files to remove${NC}"
fi

echo -e "\n${BLUE}🔍 Running initial security audit...${NC}"

# Run security audit
cd "$TARGET_DIR"
if ./security-audit.sh; then
    echo -e "\n${GREEN}✅ SECURITY SETUP COMPLETE${NC}"
    echo -e "${GREEN}✅ Initial security audit passed${NC}"
else
    audit_exit_code=$?
    if [ $audit_exit_code -eq 1 ]; then
        echo -e "\n${RED}🚨 CRITICAL SECURITY ISSUES DETECTED${NC}"
        echo -e "${RED}Review and fix issues before proceeding${NC}"
    elif [ $audit_exit_code -eq 2 ]; then
        echo -e "\n${YELLOW}⚠️  Security issues detected - review recommended${NC}"
        echo -e "${GREEN}✅ SECURITY SETUP COMPLETE${NC}"
    fi
fi

echo -e "\n${BLUE}📋 Next Steps:${NC}"
echo "1. Review security-audit.log for any issues"
echo "2. Add security checks to your CI/CD pipeline"
echo "3. Set up Git pre-commit hooks (optional)"
echo "4. Run ./security-audit.sh before each development session"
echo ""
echo -e "${BLUE}Security Files Added:${NC}"
echo "• security-audit.sh - Comprehensive security scanner"
echo "• global-security.sh - Universal fallback scanner"
echo "• .claude-security.json - Security configuration"
echo "• mandatory-security-protocols.md - Security documentation"
echo "• Updated .gitignore - Security file patterns"
echo ""
echo -e "${GREEN}🛡️  Your project is now secured with comprehensive security protocols!${NC}"