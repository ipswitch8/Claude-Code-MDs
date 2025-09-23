# Claude Code - Project Security Configuration Template

## Mandatory Security Protocols

**🚨 CRITICAL: Every Claude Code session MUST run comprehensive security checks before any code changes.**

### Automatic Security Audit
```bash
# Run before EVERY session - NO EXCEPTIONS
./security-audit.sh
```

### Required Security Commands
Claude Code must execute these commands at the start of EVERY session:

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

## Project-Specific Security Rules

### General Security Requirements
- ✅ .git directory permissions: 700
- ✅ Sensitive files permissions: 600
- ✅ No hardcoded secrets or credentials
- ✅ No dangerous temporary files
- ❌ No world-writable files
- ❌ No credentials in git URLs

### Web Application Security
- ✅ File type validation for uploads
- ✅ Size limits on file uploads
- ✅ Input validation and sanitization
- ✅ Safe DOM manipulation
- ❌ No eval() usage
- ❌ No innerHTML with user data
- ❌ No external script dependencies without integrity checks

### API Security
- ✅ Authentication on all endpoints
- ✅ Rate limiting implementation
- ✅ Input validation and sanitization
- ✅ HTTPS only in production
- ❌ No API keys in client-side code
- ❌ No sensitive data in logs

### Database Security
- ✅ Parameterized queries only
- ✅ Database credentials in environment variables
- ✅ Connection encryption
- ✅ Regular backups with encryption
- ❌ No SQL concatenation
- ❌ No database credentials in code

## Security Configuration Files

### 1. Security Audit Script
`security-audit.sh` - Comprehensive security scanner
- Checks file permissions
- Detects sensitive files
- Analyzes code for vulnerabilities
- Scans dependencies for known issues
- Auto-fixes critical issues
- Generates detailed reports

### 2. Security Rules Configuration
`.claude-security.json` - Project security configuration
- Sensitive file patterns
- Custom security rules
- Permission requirements
- Auto-fix settings
- Compliance framework mappings

### 3. Security Documentation
`CLAUDE.md` - Security protocols and requirements
- Mandatory security checks
- Project-specific rules
- Deployment requirements
- Emergency procedures

## Deployment Security Checklist

Before deploying to ANY environment:

- [ ] Run `./security-audit.sh` with 0 critical issues
- [ ] Verify .git directory is not web-accessible
- [ ] Confirm no sensitive files in web directory
- [ ] Test file upload restrictions (if applicable)
- [ ] Validate all user input handling
- [ ] Check for hardcoded secrets or credentials
- [ ] Verify HTTPS configuration
- [ ] Test authentication and authorization
- [ ] Review error handling (no sensitive data leaks)
- [ ] Confirm logging configuration (no secrets logged)

## Emergency Security Response

If security issues are discovered:

1. **STOP** all development immediately
2. **RUN** `./security-audit.sh` 
3. **FIX** all CRITICAL issues before proceeding
4. **DOCUMENT** fixes in security-audit.log
5. **VERIFY** clean audit before resuming
6. **NOTIFY** team if production systems affected

## Security Incident Categories

### CRITICAL (Fix Immediately)
- Exposed .git directories
- Hardcoded secrets or credentials
- World-writable files
- SQL injection vulnerabilities
- Authentication bypasses

### HIGH (Fix Before Next Release)
- Dangerous JavaScript patterns
- File upload vulnerabilities
- Missing input validation
- Dependency vulnerabilities
- Sensitive data exposure

### MEDIUM (Fix Within Sprint)
- Missing security headers
- Weak permission configurations
- Large file exposures
- Missing .gitignore patterns
- Outdated dependencies

## Integration with Development Workflow

### Git Hooks
Add to `.git/hooks/pre-commit`:
```bash
#!/bin/bash
./security-audit.sh
if [ $? -eq 1 ]; then
    echo "❌ CRITICAL security issues found - commit blocked"
    exit 1
fi
```

### CI/CD Integration
Add to build pipeline:
```yaml
security_audit:
  script:
    - ./security-audit.sh
    - if [ $? -eq 1 ]; then exit 1; fi
  allow_failure: false
```

## Security Contact Information

### For Security Issues
- **Immediate**: Run `./security-audit.sh`
- **Documentation**: Review `security-audit.log`
- **Configuration**: Update `.claude-security.json`
- **Questions**: Refer to this CLAUDE.md file

### Security Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Common Weakness Enumeration](https://cwe.mitre.org/)
- [Security Headers](https://securityheaders.com/)
- [Dependency Check](https://owasp.org/www-project-dependency-check/)

---

## Claude.ai Integration Instructions

### Custom Instructions Template
Copy this to your Claude.ai Custom Instructions:

```
MANDATORY SECURITY PROTOCOL - APPLIES TO ALL CLAUDE CODE SESSIONS:

1. ALWAYS check for CLAUDE.md and follow security requirements
2. ALWAYS run security-audit.sh before any code work
3. NEVER proceed if CRITICAL security issues found
4. ALWAYS secure .git directories (chmod 700)
5. ALWAYS remove temp files (.swp, .tmp, ~, .DS_Store)
6. ALWAYS scan for hardcoded secrets
7. ALWAYS create security files for new projects
8. ALWAYS log security findings

This applies to ALL systems, ALL projects, ALL sessions - NO EXCEPTIONS.
```

### Project Template Setup
For new projects, always include:
1. Copy security-audit.sh from template
2. Copy .claude-security.json from template
3. Copy CLAUDE.md from template
4. Run initial security audit
5. Configure git hooks
6. Add to CI/CD pipeline

---

**⚠️ WARNING: Failure to follow these security protocols may result in:**
- Exposed repositories and credentials
- Data breaches and security incidents
- Compliance violations
- Production security vulnerabilities

**✅ SUCCESS: Following these protocols ensures:**
- Comprehensive security coverage across all projects
- Automatic detection and prevention of common vulnerabilities
- Consistent security standards regardless of team or system
- Proactive security rather than reactive patches
- Compliance with industry security frameworks