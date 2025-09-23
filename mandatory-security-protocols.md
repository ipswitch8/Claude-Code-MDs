# Mandatory Security Protocols for Claude Code

*🚨 CRITICAL: Every Claude Code session MUST run comprehensive security checks before any code changes.*

## ⚠️ MANDATORY SECURITY REQUIREMENTS

**These protocols apply to ALL systems, ALL projects, ALL sessions - NO EXCEPTIONS.**

### 1. Pre-Session Security Audit
```bash
# MUST be run at the start of EVERY Claude Code session
./security-audit.sh
```

**If `security-audit.sh` is not available, run:**
```bash
./global-security.sh
```

### 2. Critical Security Commands
**Claude Code MUST execute these commands at session start:**

```bash
# 1. Secure .git directory permissions
find . -name ".git" -type d -exec chmod -R 700 {} \;

# 2. Remove dangerous temporary files
find . -name "*.swp" -o -name "*.tmp" -o -name "*~" -o -name ".DS_Store" -delete

# 3. Check for hardcoded secrets
if command -v rg >/dev/null 2>&1; then
    rg -i "(api[_-]?key|secret|password|token)\s*[=:]\s*['\"][^'\"]{8,}" . || echo "No secrets detected"
else
    grep -ri "password\|api.key\|secret\|token" . | head -5 || echo "No secrets detected"
fi

# 4. Verify file permissions
ls -la . && ls -la .git 2>/dev/null || echo "No .git directory"
```

## 🔒 Security Configuration Files

### Required Files for All Projects:
1. **`security-audit.sh`** - Comprehensive security scanner
2. **`global-security.sh`** - Universal fallback security check
3. **`.claude-security.json`** - Security configuration and rules
4. **`mandatory-security-protocols.md`** - This document

### Security Audit Script Features:
- ✅ File permission validation and auto-fix
- ✅ Sensitive file detection
- ✅ Code vulnerability scanning
- ✅ Hardcoded secret detection
- ✅ Web security analysis
- ✅ Git repository security
- ✅ Dependency vulnerability checks
- ✅ Automated critical issue resolution
- ✅ Comprehensive logging and reporting

## 🚨 Security Rules Enforcement

### CRITICAL Issues (MUST be fixed immediately):
- Exposed .git directories with unsafe permissions
- World-writable files
- Hardcoded secrets, passwords, API keys
- Git configurations containing credentials
- Sensitive files in project directories

### HIGH Priority Issues (Fix before deployment):
- Dangerous JavaScript patterns (eval, innerHTML)
- File upload vulnerabilities
- Temporary/swap files
- Dependency vulnerabilities
- Missing input validation

### MEDIUM Priority Issues (Fix within sprint):
- Missing security headers
- External script dependencies
- Large file exposures
- Missing .gitignore patterns

## 🛡️ Automated Security Measures

### Auto-Fix Capabilities:
- **Git Permission Hardening**: Automatically secures .git directories (chmod 700)
- **Temporary File Cleanup**: Removes .swp, .tmp, ~, .DS_Store files
- **Sensitive File Protection**: Secures key files with proper permissions

### Security Monitoring:
- **Real-time Scanning**: Detects security issues during development
- **Compliance Checking**: Validates against OWASP, CWE, PCI-DSS, GDPR
- **Audit Logging**: Comprehensive security event tracking

## 🔍 Custom Security Rules

### Pattern Detection:
- **Hardcoded Passwords**: `password\s*[=:]\s*['\"][^'\"]{1,}['\"]*`
- **API Keys**: `api[_-]?key\s*[=:]\s*['\"][^'\"]{8,}['\"]*`
- **Secret Tokens**: `(secret|token)\s*[=:]\s*['\"][^'\"]{16,}['\"]*`
- **Dangerous Eval**: `eval\s*\(`
- **XSS via innerHTML**: `innerHTML\s*=`
- **SQL Injection**: `SELECT.*\+.*FROM`

### File Security:
- **Sensitive Extensions**: .key, .pem, .p12, .pfx, .env*, .sql, .db
- **Required Permissions**:
  - .git directories: 700
  - Key files: 600
  - Scripts: 755

## 🚀 Integration Requirements

### Git Hooks (Recommended):
```bash
# .git/hooks/pre-commit
#!/bin/bash
./security-audit.sh
if [ $? -eq 1 ]; then
    echo "❌ CRITICAL security issues found - commit blocked"
    exit 1
fi
```

### CI/CD Pipeline Integration:
```yaml
security_audit:
  script:
    - ./security-audit.sh
    - if [ $? -eq 1 ]; then exit 1; fi
  allow_failure: false
```

## 📋 Security Checklist

### Before ANY Code Changes:
- [ ] Run `./security-audit.sh` with 0 critical issues
- [ ] Verify .git directory permissions (700)
- [ ] Confirm no temporary files present
- [ ] Validate no hardcoded secrets
- [ ] Check file permissions compliance

### Before Deployment:
- [ ] Complete security audit passes
- [ ] All dependencies scanned for vulnerabilities
- [ ] Web security headers configured
- [ ] Input validation implemented
- [ ] Authentication/authorization verified
- [ ] HTTPS enforced
- [ ] Error handling secure (no data leaks)

## 🆘 Emergency Security Response

### If CRITICAL Issues Detected:
1. **STOP** all development immediately
2. **RUN** `./security-audit.sh` to identify issues
3. **FIX** all CRITICAL issues before proceeding
4. **VERIFY** clean audit with zero critical issues
5. **DOCUMENT** fixes in security-audit.log
6. **NOTIFY** team if production systems affected

### Security Incident Categories:

**🚨 CRITICAL (Fix Immediately)**
- Exposed credentials or secrets
- Unsafe .git directory permissions
- World-writable sensitive files
- SQL injection vulnerabilities

**⚠️ HIGH (Fix Before Release)**
- Dangerous JavaScript patterns
- File upload security gaps
- Authentication bypasses
- Dependency vulnerabilities

**ℹ️ MEDIUM (Fix Within Sprint)**
- Missing security headers
- Weak configurations
- Missing .gitignore patterns

## 🔗 Security Resources

### Internal Resources:
- **Security Audit Log**: `security-audit.log`
- **Configuration**: `.claude-security.json`
- **Scripts**: `security-audit.sh`, `global-security.sh`

### External Resources:
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Common Weakness Enumeration](https://cwe.mitre.org/)
- [Security Headers Guide](https://securityheaders.com/)

---

## ⚡ Quick Setup

### For New Projects:
```bash
# Copy security files from template
cp /path/to/template/security-audit.sh .
cp /path/to/template/global-security.sh .
cp /path/to/template/.claude-security.json .
chmod +x security-audit.sh global-security.sh

# Run initial security audit
./security-audit.sh
```

### For Existing Projects:
```bash
# Download security suite
curl -sSL https://raw.githubusercontent.com/ipswitch8/claude-security-defaults/main/setup.sh | bash

# Run comprehensive audit
./security-audit.sh
```

---

**🛡️ Security is everyone's responsibility. These protocols ensure comprehensive protection across all development activities.**

*Last Updated: 2025-01-20 | Version: 2.0*