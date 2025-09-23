#!/bin/bash

# Global Security Check Script
# Universal security scanner that works on any system
# For use when project-specific security-audit.sh is not available

WORKING_DIR="$PWD"
PROJECT_NAME="${PWD##*/}"

echo "🔒 GLOBAL SECURITY CHECK: $PROJECT_NAME"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ISSUES_FOUND=0
CRITICAL_ISSUES=0

# Report function
report_issue() {
    local severity="$1"
    local message="$2"
    
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
    
    case "$severity" in
        "CRITICAL")
            CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
            echo -e "${RED}🚨 CRITICAL: $message${NC}"
            ;;
        "HIGH")
            echo -e "${YELLOW}⚠️  HIGH: $message${NC}"
            ;;
        "MEDIUM")
            echo -e "${BLUE}ℹ️  MEDIUM: $message${NC}"
            ;;
        "FIXED")
            echo -e "${GREEN}✅ FIXED: $message${NC}"
            ;;
    esac
}

echo -e "\n${BLUE}🔍 CHECKING GIT SECURITY...${NC}"

# 1. Check and fix .git permissions
if [ -d ".git" ]; then
    git_perms=$(ls -ld .git 2>/dev/null | cut -d' ' -f1)
    if [[ "$git_perms" != "drwx------"* ]]; then
        report_issue "CRITICAL" "Unsafe .git directory permissions"
        chmod -R 700 .git 2>/dev/null && report_issue "FIXED" "Secured .git directory permissions"
    else
        echo -e "${GREEN}✅ Git directory permissions secure${NC}"
    fi
    
    # Check for credentials in git config
    if grep -q "https://.*:.*@" .git/config 2>/dev/null; then
        report_issue "CRITICAL" "Git config contains credentials in URLs"
    fi
else
    echo -e "${BLUE}ℹ️  No git repository found${NC}"
fi

echo -e "\n${BLUE}🔍 CLEANING TEMPORARY FILES...${NC}"

# 2. Remove dangerous temporary files
temp_files_found=0
for pattern in "*.swp" "*.tmp" "*~" ".DS_Store" "*.orig" "*.rej"; do
    if find . -maxdepth 3 -name "$pattern" 2>/dev/null | grep -q .; then
        temp_files_found=1
        break
    fi
done

if [ $temp_files_found -eq 1 ]; then
    report_issue "HIGH" "Temporary files detected"
    find . -maxdepth 3 \( -name "*.swp" -o -name "*.tmp" -o -name "*~" -o -name ".DS_Store" -o -name "*.orig" -o -name "*.rej" \) -delete 2>/dev/null
    report_issue "FIXED" "Removed temporary files"
else
    echo -e "${GREEN}✅ No temporary files found${NC}"
fi

echo -e "\n${BLUE}🔍 SCANNING FOR SENSITIVE FILES...${NC}"

# 3. Check for sensitive files
sensitive_found=0
sensitive_patterns="*.key *.pem *.p12 *.pfx .env* *.sql *.db credentials* secrets*"

for pattern in $sensitive_patterns; do
    if find . -maxdepth 2 -name "$pattern" -type f 2>/dev/null | grep -q .; then
        sensitive_found=1
        break
    fi
done

if [ $sensitive_found -eq 1 ]; then
    report_issue "CRITICAL" "Sensitive files detected in project directory"
    echo "   Files found:"
    for pattern in $sensitive_patterns; do
        find . -maxdepth 2 -name "$pattern" -type f 2>/dev/null | head -3 | sed 's/^/     /'
    done
else
    echo -e "${GREEN}✅ No sensitive files detected${NC}"
fi

echo -e "\n${BLUE}🔍 BASIC CODE SECURITY SCAN...${NC}"

# 4. Basic secret scanning
secrets_found=0

# Check for hardcoded passwords/keys
if command -v grep >/dev/null 2>&1; then
    # Look for common secret patterns
    secret_patterns="password\s*[=:]\s*['\"] api[_-]?key\s*[=:]\s*['\"] secret\s*[=:]\s*['\"] token\s*[=:]\s*['\"]"
    
    for pattern in $secret_patterns; do
        if grep -ri "$pattern" . --exclude-dir=".git" --exclude="*.log" 2>/dev/null | head -1 | grep -q .; then
            secrets_found=1
            break
        fi
done

    if [ $secrets_found -eq 1 ]; then
        report_issue "CRITICAL" "Potential hardcoded secrets detected"
        echo "   Review these patterns:"
        for pattern in $secret_patterns; do
            grep -ri "$pattern" . --exclude-dir=".git" --exclude="*.log" 2>/dev/null | head -2 | sed 's/^/     /'
        done
    else
        echo -e "${GREEN}✅ No obvious secrets detected${NC}"
    fi
    
    # Check for dangerous JavaScript patterns
    if find . -name "*.html" -o -name "*.js" 2>/dev/null | grep -q .; then
        dangerous_js=$(grep -r "eval\s*(" . --include="*.html" --include="*.js" 2>/dev/null | head -1)
        if [ -n "$dangerous_js" ]; then
            report_issue "HIGH" "Dangerous JavaScript patterns detected (eval)"
        fi
        
        innerHTML_usage=$(grep -r "innerHTML\s*=" . --include="*.html" --include="*.js" 2>/dev/null | head -1)
        if [ -n "$innerHTML_usage" ]; then
            report_issue "MEDIUM" "Potential XSS risk via innerHTML usage"
        fi
    fi
else
    echo -e "${YELLOW}⚠️  grep not available - skipping code scan${NC}"
fi

echo -e "\n${BLUE}🔍 FILE PERMISSIONS CHECK...${NC}"

# 5. Check for world-writable files
world_writable=$(find . -type f -perm -002 2>/dev/null | head -5)
if [ -n "$world_writable" ]; then
    report_issue "CRITICAL" "World-writable files detected"
    echo "$world_writable" | sed 's/^/     /'
else
    echo -e "${GREEN}✅ No world-writable files found${NC}"
fi

echo -e "\n${BLUE}🔍 DEPENDENCY SECURITY...${NC}"

# 6. Basic dependency checks
if [ -f "package.json" ]; then
    if command -v npm >/dev/null 2>&1; then
        echo -e "${BLUE}ℹ️  Node.js project detected - run 'npm audit' for detailed dependency check${NC}"
    else
        echo -e "${YELLOW}⚠️  Node.js project but npm not available${NC}"
    fi
fi

if [ -f "requirements.txt" ]; then
    echo -e "${BLUE}ℹ️  Python project detected - consider using 'safety check' for dependency scan${NC}"
fi

if [ -f "composer.json" ]; then
    echo -e "${BLUE}ℹ️  PHP project detected - consider using 'composer audit' for security check${NC}"
fi

if [ -f "Gemfile" ]; then
    echo -e "${BLUE}ℹ️  Ruby project detected - consider using 'bundle audit' for security scan${NC}"
fi

echo -e "\n${BLUE}🔍 WEB SECURITY BASICS...${NC}"

# 7. Basic web security checks
if find . -name "*.html" 2>/dev/null | grep -q .; then
    # Check for file upload inputs without restrictions
    upload_inputs=$(grep -r "type=['\"]file['\"]" . --include="*.html" 2>/dev/null)
    if [ -n "$upload_inputs" ]; then
        if ! grep -r "accept=" . --include="*.html" 2>/dev/null | grep -q .; then
            report_issue "HIGH" "File upload inputs without type restrictions"
        fi
    fi
    
    # Check for external scripts
    external_scripts=$(grep -r "src=['\"]https\?://" . --include="*.html" 2>/dev/null | head -3)
    if [ -n "$external_scripts" ]; then
        report_issue "MEDIUM" "External script sources detected"
        echo "$external_scripts" | sed 's/^/     /'
    fi
fi

# 8. .gitignore check
if [ -d ".git" ] && [ ! -f ".gitignore" ]; then
    report_issue "MEDIUM" "Missing .gitignore file for git repository"
fi

echo -e "\n${BLUE}📊 GLOBAL SECURITY SUMMARY${NC}"
echo "=========================="
echo "Project: $PROJECT_NAME"
echo "Issues Found: $ISSUES_FOUND"
echo "Critical Issues: $CRITICAL_ISSUES"

if [ $CRITICAL_ISSUES -gt 0 ]; then
    echo -e "${RED}🚨 CRITICAL SECURITY ISSUES REQUIRE IMMEDIATE ATTENTION!${NC}"
    echo -e "${RED}Install full security suite with: curl -sSL https://raw.githubusercontent.com/ipswitch8/claude-security-defaults/main/setup.sh | bash${NC}"
    exit 1
elif [ $ISSUES_FOUND -gt 0 ]; then
    echo -e "${YELLOW}⚠️  Security issues found - review recommended${NC}"
    exit 2
else
    echo -e "${GREEN}✅ No critical security issues detected${NC}"
    echo -e "${BLUE}ℹ️  For comprehensive security, install full suite with setup.sh${NC}"
    exit 0
fi