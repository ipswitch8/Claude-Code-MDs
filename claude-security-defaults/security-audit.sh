#!/bin/bash

# Claude Code Security Audit Script
# Universal security scanner for all projects
# Auto-fixes critical issues and reports all findings

WORKING_DIR="$PWD"
PROJECT_NAME="${PWD##*/}"
LOG_FILE="$WORKING_DIR/security-audit.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
ISSUES_FOUND=0
CRITICAL_ISSUES=0

echo "🔒 SECURITY AUDIT STARTED: $PROJECT_NAME"
echo "[$TIMESTAMP] Security audit started in: $WORKING_DIR" >> "$LOG_FILE"

# Color codes for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to report security issues
report_security_issue() {
    local severity="$1"
    local issue="$2"
    local details="$3"
    
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
    
    case "$severity" in
        "CRITICAL")
            CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
            echo -e "${RED}🚨 CRITICAL: $issue${NC}"
            ;;
        "HIGH")
            echo -e "${YELLOW}⚠️  HIGH: $issue${NC}"
            ;;
        "MEDIUM")
            echo -e "${BLUE}ℹ️  MEDIUM: $issue${NC}"
            ;;
        "FIXED")
            echo -e "${GREEN}✅ FIXED: $issue${NC}"
            ;;
    esac
    
    echo "[$TIMESTAMP] $severity: $issue - $details" >> "$LOG_FILE"
    
    if [ -n "$details" ]; then
        echo "   Details: $details"
    fi
}

# 1. CRITICAL FILE PERMISSION CHECKS
echo -e "\n🔍 ${BLUE}CHECKING FILE PERMISSIONS...${NC}"

# Check for world-writable files
world_writable=$(find "$WORKING_DIR" -type f -perm -002 2>/dev/null)
if [ -n "$world_writable" ]; then
    report_security_issue "CRITICAL" "World-writable files detected" "$world_writable"
fi

# Check for exposed .git directories
exposed_git=$(find "$WORKING_DIR" -name ".git" -type d -not -perm 700 2>/dev/null)
if [ -n "$exposed_git" ]; then
    report_security_issue "CRITICAL" "Exposed .git directory with unsafe permissions" "$exposed_git"
    # Auto-fix
    for git_dir in $exposed_git; do
        chmod -R 700 "$git_dir" 2>/dev/null && \
        report_security_issue "FIXED" "Auto-secured .git directory" "$git_dir"
    done
fi

# Check for sensitive swap/temp files
temp_files=$(find "$WORKING_DIR" -name "*.swp" -o -name "*.tmp" -o -name "*~" -o -name ".DS_Store" 2>/dev/null)
if [ -n "$temp_files" ]; then
    report_security_issue "HIGH" "Temporary/swap files detected" "$temp_files"
    # Auto-remove
    find "$WORKING_DIR" \( -name "*.swp" -o -name "*.tmp" -o -name "*~" -o -name ".DS_Store" \) -delete 2>/dev/null && \
    report_security_issue "FIXED" "Removed temporary files" ""
fi

# 2. SENSITIVE FILE DETECTION
echo -e "\n🔍 ${BLUE}SCANNING FOR SENSITIVE FILES...${NC}"

# Define sensitive file patterns (exclude our own security log)
sensitive_files=$(find "$WORKING_DIR" \( \
    -name "*.key" -o \
    -name "*.pem" -o \
    -name "*.p12" -o \
    -name "*.pfx" -o \
    -name ".env*" -o \
    -name "config.php" -o \
    -name "*.sql" -o \
    -name "*.db" -o \
    -name "*.sqlite*" -o \
    -name "backup*" -o \
    -name "credentials*" -o \
    -name "secrets*" \
\) -type f -not -name "security-audit.log" 2>/dev/null)

if [ -n "$sensitive_files" ]; then
    report_security_issue "CRITICAL" "Sensitive files detected in project" "$sensitive_files"
fi

# 3. CODE SECURITY ANALYSIS
echo -e "\n🔍 ${BLUE}ANALYZING CODE FOR SECURITY VULNERABILITIES...${NC}"

# Check for hardcoded secrets using ripgrep if available
if command -v rg >/dev/null 2>&1; then
    secrets=$(rg -i "(api[_-]?key|secret|password|token|private[_-]?key)\s*[=:]\s*['\"][^'\"]{8,}" "$WORKING_DIR" 2>/dev/null)
    if [ -n "$secrets" ]; then
        report_security_issue "CRITICAL" "Potential hardcoded secrets detected" "$secrets"
    fi
    
    # Check for dangerous JavaScript patterns
    dangerous_js=$(rg "(eval\s*\(|innerHTML\s*=|document\.write\(|setTimeout\s*\([^)]*['\"]|setInterval\s*\([^)]*['\"])" "$WORKING_DIR" --type html --type js 2>/dev/null)
    if [ -n "$dangerous_js" ]; then
        report_security_issue "HIGH" "Potentially dangerous JavaScript patterns" "$dangerous_js"
    fi
    
    # Check for external script sources
    external_scripts=$(rg "src\s*=\s*['\"]https?://" "$WORKING_DIR" --type html 2>/dev/null)
    if [ -n "$external_scripts" ]; then
        report_security_issue "MEDIUM" "External script sources detected" "$external_scripts"
    fi
else
    # Fallback to grep if ripgrep not available
    if grep -r -i "password\s*=\s*['\"]" "$WORKING_DIR" 2>/dev/null | grep -q .; then
        report_security_issue "HIGH" "Potential hardcoded credentials (grep fallback)" ""
    fi
    
    if grep -r "eval\s*(" "$WORKING_DIR" 2>/dev/null | grep -q .; then
        report_security_issue "HIGH" "Dangerous eval() usage detected" ""
    fi
fi

# 4. WEB-SPECIFIC SECURITY CHECKS
echo -e "\n🔍 ${BLUE}WEB SECURITY ANALYSIS...${NC}"

# Check for missing CSP headers (if HTML files exist)
html_files=$(find "$WORKING_DIR" -name "*.html" -type f 2>/dev/null)
if [ -n "$html_files" ]; then
    for html_file in $html_files; do
        if ! grep -q "Content-Security-Policy" "$html_file"; then
            report_security_issue "MEDIUM" "Missing Content Security Policy" "$html_file"
        fi
    done
fi

# Check for file upload validation in JavaScript/HTML
if [ -n "$html_files" ]; then
    for html_file in $html_files; do
        if grep -q "type=['\"]file['\"]" "$html_file"; then
            if ! grep -q "accept=" "$html_file"; then
                report_security_issue "HIGH" "File upload without type restrictions" "$html_file"
            fi
        fi
    done
fi

# 5. GIT SECURITY ANALYSIS
echo -e "\n🔍 ${BLUE}GIT REPOSITORY SECURITY...${NC}"

if [ -d ".git" ]; then
    # Check git config for sensitive URLs
    if grep -q "https://.*:.*@" .git/config 2>/dev/null; then
        report_security_issue "CRITICAL" "Git config contains credentials in URLs" ".git/config"
    fi
    
    # Check for large files that might be sensitive
    large_files=$(find "$WORKING_DIR" -type f -size +10M 2>/dev/null | grep -v ".git")
    if [ -n "$large_files" ]; then
        report_security_issue "MEDIUM" "Large files detected (potential data exposure)" "$large_files"
    fi
    
    # Check for files that should be in .gitignore
    if [ ! -f ".gitignore" ]; then
        report_security_issue "MEDIUM" "Missing .gitignore file" ""
    else
        # Check if common sensitive patterns are ignored
        ignored_patterns="*.key *.pem *.env .DS_Store *.log"
        for pattern in $ignored_patterns; do
            if ! grep -q "$pattern" .gitignore; then
                report_security_issue "MEDIUM" "Sensitive pattern not in .gitignore: $pattern" ""
            fi
        done
    fi
fi

# 6. DEPENDENCY SECURITY (if package files exist)
echo -e "\n🔍 ${BLUE}DEPENDENCY SECURITY...${NC}"

# Check for package.json vulnerabilities
if [ -f "package.json" ] && command -v npm >/dev/null 2>&1; then
    if npm audit --audit-level high 2>/dev/null | grep -q "vulnerabilities"; then
        report_security_issue "HIGH" "NPM dependencies have vulnerabilities" "Run: npm audit fix"
    fi
fi

# Check for requirements.txt vulnerabilities
if [ -f "requirements.txt" ] && command -v pip >/dev/null 2>&1; then
    if command -v safety >/dev/null 2>&1; then
        if ! safety check 2>/dev/null; then
            report_security_issue "HIGH" "Python dependencies have vulnerabilities" "Run: pip install safety && safety check"
        fi
    fi
fi

# 7. FINAL SECURITY REPORT
echo -e "\n📊 ${BLUE}SECURITY AUDIT SUMMARY${NC}"
echo "=========================="
echo "Project: $PROJECT_NAME"
echo "Issues Found: $ISSUES_FOUND"
echo "Critical Issues: $CRITICAL_ISSUES"
echo "Audit Log: $LOG_FILE"
echo "Timestamp: $TIMESTAMP"

if [ $CRITICAL_ISSUES -gt 0 ]; then
    echo -e "${RED}⚠️  CRITICAL SECURITY ISSUES REQUIRE IMMEDIATE ATTENTION!${NC}"
    echo -e "${RED}DO NOT DEPLOY OR COMMIT UNTIL ALL CRITICAL ISSUES ARE RESOLVED${NC}"
    exit 1
elif [ $ISSUES_FOUND -gt 0 ]; then
    echo -e "${YELLOW}⚠️  Security issues found - review recommended${NC}"
    exit 2
else
    echo -e "${GREEN}✅ No security issues detected - project is secure${NC}"
    exit 0
fi