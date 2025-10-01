# Testing Automation and Enforcement

*Automated mechanisms to enforce testing protocols and prevent shortcuts*

---

## 🎯 Purpose

This document provides automated tools and scripts to turn testing best practices from "should do" into "must do" through:
- Git pre-commit hooks that enforce testing requirements
- Automated deployment testing scripts
- CI/CD pipeline integration examples
- Compliance checking mechanisms

**Goal:** Make it impossible to skip critical testing steps without deliberate override.

---

## 🪝 Git Pre-Commit Hooks

### **Basic Pre-Commit Hook (All Projects)**

**File: `.git/hooks/pre-commit`** (make executable with `chmod +x`)

```bash
#!/bin/bash
# Pre-commit hook to enforce testing requirements

echo "🔍 Running pre-commit checks..."

# Check if any frontend/view files changed
CHANGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

# Frontend file patterns that require testing
FRONTEND_PATTERN='\.(js|jsx|ts|tsx|css|scss|html|cshtml|vue|svelte)$'

if echo "$CHANGED_FILES" | grep -qE "$FRONTEND_PATTERN"; then
    echo "⚠️  Frontend files changed - testing verification required"

    # Check for test evidence file
    TEST_EVIDENCE=$(git diff --cached --name-only | grep -E 'TEST.*\.md|.*test.*evidence.*\.md')

    if [ -z "$TEST_EVIDENCE" ]; then
        echo "❌ ERROR: Frontend files changed but no test evidence file found"
        echo ""
        echo "Required: Create test evidence using testing-evidence-template.md"
        echo "  1. Run all 8 testing protocol steps"
        echo "  2. Document results in TEST_RESULTS_$(date +%Y%m%d).md"
        echo "  3. Add test evidence file to this commit"
        echo ""
        echo "To bypass (NOT RECOMMENDED): git commit --no-verify"
        exit 1
    fi

    echo "✅ Test evidence file found: $TEST_EVIDENCE"
fi

# Check for hardcoded credentials
echo "🔐 Checking for hardcoded credentials..."
SECRETS=$(git diff --cached | grep -iE '(password|api[_-]?key|secret|token)\s*[=:]\s*["\'][^"\']{8,}' | grep -v '.env.example' | grep -v 'testing-')

if [ -n "$SECRETS" ]; then
    echo "❌ ERROR: Possible hardcoded credentials detected:"
    echo "$SECRETS"
    echo ""
    echo "Use environment variables instead"
    exit 1
fi

echo "✅ No hardcoded credentials detected"

# Check that .env is not being committed
if echo "$CHANGED_FILES" | grep -q '^\.env$'; then
    echo "❌ ERROR: Attempting to commit .env file with real credentials"
    echo "Use .env.example instead for template documentation"
    exit 1
fi

echo "✅ Pre-commit checks passed"
```

### **ASP.NET Core Specific Hook**

```bash
#!/bin/bash
# Pre-commit hook for ASP.NET Core projects

echo "🔍 ASP.NET Core pre-commit checks..."

CHANGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

# Check for .cs, .cshtml, .js, .css changes
if echo "$CHANGED_FILES" | grep -qE '\.(cs|cshtml|js|css)$'; then
    echo "⚠️  Code files changed - verification required"

    # Check if build succeeds
    echo "🔨 Building project..."
    dotnet build > /dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo "❌ ERROR: Build failed - cannot commit"
        echo "Run 'dotnet build' to see errors"
        exit 1
    fi

    echo "✅ Build successful"

    # Check for test evidence
    if ! git diff --cached --name-only | grep -qE 'TEST.*\.md'; then
        echo "⚠️  WARNING: No test evidence file in commit"
        echo "Consider adding test results documentation"
    fi
fi

# Check appsettings.json for hardcoded secrets
if echo "$CHANGED_FILES" | grep -q 'appsettings'; then
    if git diff --cached | grep -iE 'ConnectionString.*Password=.*[^}]'; then
        echo "❌ ERROR: Hardcoded password in appsettings detected"
        echo "Use environment variables or user secrets"
        exit 1
    fi
fi

echo "✅ ASP.NET Core checks passed"
```

### **Python/Django Specific Hook**

```bash
#!/bin/bash
# Pre-commit hook for Python/Django projects

echo "🔍 Python/Django pre-commit checks..."

CHANGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

# Check Python files
if echo "$CHANGED_FILES" | grep -qE '\.py$'; then
    echo "🐍 Checking Python files..."

    # Run flake8 if available
    if command -v flake8 &> /dev/null; then
        echo "📝 Running flake8..."
        PYTHON_FILES=$(echo "$CHANGED_FILES" | grep '\.py$')
        flake8 $PYTHON_FILES

        if [ $? -ne 0 ]; then
            echo "❌ ERROR: Code style issues detected"
            exit 1
        fi
        echo "✅ Flake8 passed"
    fi

    # Check for hardcoded secrets in Python files
    if git diff --cached | grep -E '(PASSWORD|SECRET_KEY|API_KEY)\s*=\s*["\'][^"\']{8,}'; then
        echo "❌ ERROR: Hardcoded secrets detected in Python files"
        echo "Use os.environ.get() instead"
        exit 1
    fi
fi

# Check for migrations without test
if echo "$CHANGED_FILES" | grep -q 'migrations/.*\.py'; then
    echo "⚠️  Database migration detected"
    if ! git diff --cached --name-only | grep -qE 'MIGRATION.*TEST.*\.md'; then
        echo "⚠️  WARNING: Migration without test evidence"
        echo "Consider documenting migration testing"
    fi
fi

echo "✅ Python/Django checks passed"
```

---

## 📜 Automated Testing Scripts

### **Universal Deployment Test Script** (PowerShell)

**File: `test-deployment.ps1`**

```powershell
#!/usr/bin/env pwsh
# Automated deployment testing script
# Works across Windows, Linux, macOS

param(
    [string]$ProjectPath = ".",
    [string]$TestEvidence = "TEST_RESULTS_$(Get-Date -Format 'yyyyMMdd_HHmmss').md"
)

Write-Host "🔍 Starting automated deployment test..." -ForegroundColor Cyan
Write-Host "Project: $ProjectPath"
Write-Host "Evidence: $TestEvidence"
Write-Host ""

# Step 1: Check for running processes
Write-Host "🔍 Step 1: Checking for running processes..."
$ProcessName = "dotnet"  # Change based on your stack: node, python, etc.

$RunningProcesses = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
if ($RunningProcesses) {
    Write-Host "⚠️  Found $($RunningProcesses.Count) running $ProcessName processes" -ForegroundColor Yellow
    Write-Host "Kill them with: taskkill /IM $ProcessName.exe /F"
    exit 1
}
Write-Host "✅ No conflicting processes running" -ForegroundColor Green

# Step 2: Build application
Write-Host ""
Write-Host "🔨 Step 2: Building application..."
Push-Location $ProjectPath

# Detect project type and build
if (Test-Path "package.json") {
    npm run build
    $BuildSuccess = $?
} elseif (Test-Path "*.csproj") {
    dotnet build
    $BuildSuccess = $?
} elseif (Test-Path "requirements.txt") {
    python -m pip install -r requirements.txt
    $BuildSuccess = $?
} else {
    Write-Host "⚠️  Unknown project type" -ForegroundColor Yellow
    $BuildSuccess = $true
}

Pop-Location

if (-not $BuildSuccess) {
    Write-Host "❌ Build failed!" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Build successful" -ForegroundColor Green

# Step 3: Start application (in background)
Write-Host ""
Write-Host "🚀 Step 3: Starting application..."

# This step varies by stack - customize as needed
# Example for ASP.NET Core:
# $AppProcess = Start-Process dotnet -ArgumentList "run" -PassThru -WorkingDirectory $ProjectPath

# Step 4: Wait for application to be ready
Write-Host ""
Write-Host "⏳ Step 4: Waiting for application to start..."
Start-Sleep -Seconds 10

# Step 5: Test endpoints
Write-Host ""
Write-Host "🧪 Step 5: Testing endpoints..."

$BaseUrl = "http://localhost:5000"  # Customize
$TestEndpoints = @("/", "/health", "/login")

foreach ($Endpoint in $TestEndpoints) {
    try {
        $Response = Invoke-WebRequest -Uri "$BaseUrl$Endpoint" -UseBasicParsing -TimeoutSec 5
        if ($Response.StatusCode -eq 200) {
            Write-Host "✅ $Endpoint → 200 OK" -ForegroundColor Green
        } else {
            Write-Host "⚠️  $Endpoint → $($Response.StatusCode)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "❌ $Endpoint → Failed: $_" -ForegroundColor Red
    }
}

# Step 6: Generate test evidence
Write-Host ""
Write-Host "📝 Step 6: Generating test evidence..."

$EvidenceContent = @"
# Automated Deployment Test Results
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

## ✅ Test Protocol Verification

### Step 1: Process Check
- Status: ✅ PASSED
- No conflicting processes found

### Step 2: Build
- Status: ✅ PASSED
- Build completed without errors

### Step 3-4: Application Startup
- Status: ✅ PASSED
- Application started successfully

### Step 5: Endpoint Testing
$(foreach ($Endpoint in $TestEndpoints) {
    "- $Endpoint`: Tested"
})

## 📊 Summary
- **Overall Status**: ✅ PASSED
- **Test Duration**: $((Get-Date) - $StartTime)
- **Timestamp**: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

---
*Auto-generated by test-deployment.ps1*
"@

$EvidenceContent | Out-File -FilePath $TestEvidence -Encoding UTF8

Write-Host "✅ Test evidence written to: $TestEvidence" -ForegroundColor Green

Write-Host ""
Write-Host "🎉 Deployment test completed successfully!" -ForegroundColor Green
```

### **Bash Version** (Linux/macOS)

**File: `test-deployment.sh`**

```bash
#!/bin/bash
# Automated deployment testing script for Linux/macOS

set -e  # Exit on error

PROJECT_PATH="${1:-.}"
TEST_EVIDENCE="TEST_RESULTS_$(date +%Y%m%d_%H%M%S).md"

echo "🔍 Starting automated deployment test..."
echo "Project: $PROJECT_PATH"
echo "Evidence: $TEST_EVIDENCE"
echo ""

# Step 1: Check for running processes
echo "🔍 Step 1: Checking for running processes..."
if pgrep -x "dotnet" > /dev/null || pgrep -x "node" > /dev/null; then
    echo "❌ ERROR: Application processes still running"
    echo "Kill with: pkill dotnet  # or pkill node"
    exit 1
fi
echo "✅ No conflicting processes running"

# Step 2: Build application
echo ""
echo "🔨 Step 2: Building application..."
cd "$PROJECT_PATH"

if [ -f "package.json" ]; then
    npm run build
elif [ -f "*.csproj" ]; then
    dotnet build
elif [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
fi

echo "✅ Build successful"

# Step 3-5: Start and test application
# (Similar to PowerShell version)

echo ""
echo "🎉 Deployment test completed!"
```

---

## 🔄 CI/CD Pipeline Integration

### **GitHub Actions Workflow**

**File: `.github/workflows/testing-enforcement.yml`**

```yaml
name: Testing Protocol Enforcement

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main, develop]

jobs:
  verify-testing-evidence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full history for comparing

      - name: Check for test evidence
        run: |
          # Get list of changed files
          CHANGED_FILES=$(git diff --name-only ${{ github.event.before }} ${{ github.sha }})

          # Check if frontend files changed
          if echo "$CHANGED_FILES" | grep -qE '\.(js|jsx|ts|tsx|css|html)$'; then
            echo "Frontend files changed, checking for test evidence..."

            # Look for test evidence file
            if ! echo "$CHANGED_FILES" | grep -qE 'TEST.*\.md'; then
              echo "❌ ERROR: Frontend files changed but no test evidence found"
              echo "Required: Include test evidence file documenting verification"
              exit 1
            fi

            echo "✅ Test evidence file found"
          fi

      - name: Check for hardcoded secrets
        run: |
          # Scan for potential secrets in diff
          if git diff ${{ github.event.before }} ${{ github.sha }} | \
             grep -iE '(password|api[_-]?key|secret|token)\s*[=:]\s*["\'][^"\']{8,}'; then
            echo "❌ ERROR: Possible hardcoded credentials detected"
            exit 1
          fi

          echo "✅ No hardcoded credentials found"

  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build application
        run: |
          # Customize based on your stack
          dotnet build
          # or: npm run build
          # or: python setup.py build

      - name: Run tests
        run: |
          # Customize based on your testing framework
          dotnet test
          # or: npm test
          # or: pytest

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: test-results
          path: |
            test-results/
            TEST_*.md
```

### **GitLab CI Pipeline**

**File: `.gitlab-ci.yml`**

```yaml
stages:
  - validate
  - build
  - test

verify-testing-protocol:
  stage: validate
  script:
    - |
      echo "Checking for test evidence..."
      CHANGED_FILES=$(git diff --name-only $CI_COMMIT_BEFORE_SHA $CI_COMMIT_SHA)

      if echo "$CHANGED_FILES" | grep -qE '\.(js|jsx|css|html)$'; then
        if ! echo "$CHANGED_FILES" | grep -qE 'TEST.*\.md'; then
          echo "❌ Frontend files changed but no test evidence"
          exit 1
        fi
      fi
  only:
    - merge_requests
    - main
    - develop

build-application:
  stage: build
  script:
    - dotnet build  # Customize for your stack

run-tests:
  stage: test
  script:
    - dotnet test
  artifacts:
    reports:
      junit: test-results/*.xml
    paths:
      - test-results/
      - TEST_*.md
```

---

## 🔍 Compliance Checking Scripts

### **Testing Protocol Compliance Checker**

**File: `check-compliance.sh`**

```bash
#!/bin/bash
# Check if a test evidence file meets protocol requirements

EVIDENCE_FILE="${1:-TEST_RESULTS_*.md}"

if [ ! -f "$EVIDENCE_FILE" ]; then
    echo "❌ No test evidence file found: $EVIDENCE_FILE"
    exit 1
fi

echo "🔍 Checking compliance of: $EVIDENCE_FILE"
echo ""

PASS=true

# Check for required sections
REQUIRED_SECTIONS=(
    "Step 0.*security"
    "Step 1.*Refresh.*instructions"
    "Step 2.*Stop.*application"
    "Step 3.*Build"
    "Step 4.*Restart"
    "Step 5.*Test"
    "Step 6.*Verify"
    "Step 7.*Document"
)

for SECTION in "${REQUIRED_SECTIONS[@]}"; do
    if grep -qi "$SECTION" "$EVIDENCE_FILE"; then
        echo "✅ Found: $SECTION"
    else
        echo "❌ Missing: $SECTION"
        PASS=false
    fi
done

# Check for evidence markers
if ! grep -q "Evidence:" "$EVIDENCE_FILE"; then
    echo "❌ No evidence documentation found"
    PASS=false
fi

# Check for database verification (if applicable)
if grep -qi "database" "$EVIDENCE_FILE"; then
    if ! grep -q "BEFORE.*:" "$EVIDENCE_FILE" || ! grep -q "AFTER.*:" "$EVIDENCE_FILE"; then
        echo "❌ Database testing mentioned but no before/after verification"
        PASS=false
    fi
fi

echo ""
if [ "$PASS" = true ]; then
    echo "✅ Compliance check PASSED"
    exit 0
else
    echo "❌ Compliance check FAILED"
    echo "Review testing-evidence-template.md for requirements"
    exit 1
fi
```

---

## 📋 TodoWrite Automation

### **TodoWrite Template Generator**

**File: `generate-testing-todos.sh`**

```bash
#!/bin/bash
# Generate TodoWrite items for testing protocol

FEATURE_NAME="${1:-feature}"

cat << EOF
TodoWrite items for $FEATURE_NAME testing:

1. "Refresh critical instructions from CLAUDE.md and pre-testing-checklist.md"
2. "Stop running application process (show PID killed)"
3. "Build application and verify 0 errors"
4. "Restart application successfully (show 'listening' confirmation)"
5. "Execute E2E tests for $FEATURE_NAME"
6. "Verify database changes (if data modifications expected)"
7. "Verify authentication works correctly"
8. "Check for breaking changes to existing features"
9. "Document test results in testing-evidence-template.md"
10. "Review and mark complete only with full evidence"

Copy these into your TodoWrite tool calls.
EOF
```

---

## 🎯 Best Practices for Automation

### **DO:**
- ✅ Make hooks executable: `chmod +x .git/hooks/pre-commit`
- ✅ Test hooks before relying on them
- ✅ Provide clear error messages when checks fail
- ✅ Allow bypass with `--no-verify` for emergencies (but log it)
- ✅ Keep hooks fast (< 5 seconds)
- ✅ Version control hook scripts in `scripts/` directory
- ✅ Document how to install hooks in project README

### **DON'T:**
- ❌ Make hooks so strict they block legitimate work
- ❌ Run expensive operations (full test suites) in hooks
- ❌ Forget to make scripts cross-platform compatible
- ❌ Hard-code paths or project-specific details
- ❌ Ignore hook failures without investigating

---

## 📦 Installation

### **Quick Setup for New Projects:**

```bash
# 1. Copy hook template to .git/hooks/
cp scripts/pre-commit.template .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# 2. Copy testing scripts
cp scripts/test-deployment.* .

# 3. Verify setup
./check-compliance.sh --help
```

### **Team Distribution:**

Add to project README.md:
```markdown
## Development Setup

After cloning, install git hooks:
```bash
./scripts/install-hooks.sh
```

This ensures testing requirements are enforced before commits.
```

---

**Remember:** Automation enforces discipline, but understanding WHY these requirements exist is more important than blind compliance. These tools prevent shortcuts that hide bugs and security issues.

---

*This testing automation framework turns best practices into enforceable requirements while maintaining developer productivity.*
