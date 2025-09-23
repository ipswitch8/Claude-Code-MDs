# Universal Patterns for Claude Code

*Last Updated: 2025-01-20 | Version: 2.0*

## 🚨🚨🚨 MANDATORY SECURITY PROTOCOLS 🚨🚨🚨

**⚠️ ABSOLUTE REQUIREMENT: RUN SECURITY AUDIT BEFORE ANY CODE CHANGES ⚠️**

**EVERY Claude Code session MUST start with:**

```bash
# 1. Run comprehensive security audit
./security-audit.sh

# If security-audit.sh not available, run:
./global-security.sh

# 2. CRITICAL: Secure .git directory
find . -name ".git" -type d -exec chmod -R 700 {} \;

# 3. Remove temporary files
find . -name "*.swp" -o -name "*.tmp" -o -name "*~" -o -name ".DS_Store" -delete

# 4. Check for secrets
if command -v rg >/dev/null 2>&1; then
    rg -i "(api[_-]?key|secret|password|token)\s*[=:]\s*['\"][^'\"]{8,}" . || echo "No secrets detected"
else
    grep -ri "password\|api.key\|secret\|token" . | head -5 || echo "No secrets detected"
fi
```

**🛑 STOP ALL WORK if CRITICAL security issues are found. Fix immediately before proceeding.**

## 🔥🔥🔥 CRITICAL TESTING RULE 🔥🔥🔥

**⚠️ ABSOLUTE REQUIREMENT: RESTART SERVER BEFORE TESTING/VERIFICATION ⚠️**

**NEVER FORGET:** Before testing ANY changes, you MUST:

1. **COMPLETE all related file changes first**
2. **KILL the running server process**
3. **BUILD and restart the application**
4. **VERIFY the server starts successfully**
5. **ONLY THEN test your changes**

**THIS IS NON-NEGOTIABLE. NO EXCEPTIONS. EVER.**

## 🚨 MANDATORY 8-STEP TESTING PROTOCOL

**For ANY changes to frontend code, views, or configuration:**

0. **[ ] Run security audit** - Execute `./security-audit.sh` with 0 critical issues
1. **[ ] Refresh critical instructions** - Read project CLAUDE.md and relevant documentation
2. **[ ] Stop running application** - Show process kill command and confirmation
3. **[ ] Build application** - Show build output with 0 errors
4. **[ ] Restart application** - Show startup logs with "ready" confirmation
5. **[ ] Test core functionality** - Show actual test commands and results
6. **[ ] Verify assets load correctly** - Show HTTP 200 responses for new files
7. **[ ] Document results** - Create timestamped test report with evidence

**❌ NEVER say "implementation complete" without ALL 8 steps verified with actual evidence.**

## 🔒 Security Best Practices

### **Input Validation**
- **ALWAYS validate user inputs** at both client and server level
- **Use parameterized queries** - NEVER string concatenation for SQL
- **Sanitize all outputs** to prevent XSS attacks
- **Implement proper authentication** and authorization checks

### **Secret Management**
- **NEVER commit secrets** to version control
- **Use environment variables** for configuration
- **Rotate secrets regularly** and use secure storage
- **Log security events** but never log sensitive data

### **Dependencies**
- **Regularly update dependencies** to patch security vulnerabilities
- **Audit dependencies** for known security issues
- **Use dependency scanning tools** in CI/CD pipeline
- **Pin dependency versions** to prevent supply chain attacks

## 📊 Performance Guidelines

### **Monitoring**
- **Profile before optimizing** - measure actual bottlenecks
- **Monitor key metrics**: response time, memory usage, CPU utilization
- **Set up alerts** for performance degradation
- **Test with realistic data volumes** and user loads

### **Optimization Principles**
- **Optimize the critical path** first
- **Cache expensive operations** appropriately
- **Minimize network requests** and payload sizes
- **Use compression** for static assets and API responses

## 🗄️ Database Best Practices

### **Schema Changes**
- **ALWAYS backup before schema changes**
- **Test migrations on development first**
- **Document rollback procedures** for every migration
- **Use additive-only changes** when possible (add columns, don't remove)

### **Query Optimization**
- **Use indexes strategically** on frequently queried columns
- **Avoid N+1 query problems** with proper eager loading
- **Monitor slow queries** and optimize based on actual usage
- **Use connection pooling** and timeout configurations

## 🌿 Git Workflow Standards

### **Branch Strategy**
- **Feature branches**: `feature/description-of-feature`
- **Bug fixes**: `bugfix/issue-description`
- **Hotfixes**: `hotfix/critical-issue`
- **NEVER commit directly to main/master**

### **Commit Messages**
Use conventional commits format:
- `feat: add user authentication system`
- `fix: resolve memory leak in data processor`
- `docs: update API documentation`
- `refactor: simplify database query logic`
- `test: add unit tests for payment processing`

### **Pre-commit Checklist**
- [ ] Code builds without errors
- [ ] All tests pass
- [ ] No sensitive data in commit
- [ ] Meaningful commit message
- [ ] Related files updated (docs, tests, etc.)

## 🐛 Debugging Workflow

### **Systematic Approach**
1. **Reproduce the issue** consistently
2. **Check recent changes** that might have caused it
3. **Review logs** for error messages and stack traces
4. **Use debugging tools** (browser devtools, debugger, profiler)
5. **Isolate the problem** with minimal test cases
6. **Test the fix** thoroughly before deployment

### **Common Debug Points**
- **Client-side**: Browser console, Network tab, Application tab
- **Server-side**: Application logs, database logs, system logs
- **Network**: API responses, CORS issues, SSL/TLS problems
- **Database**: Query execution plans, lock contention, connection issues

## 📝 Documentation Standards

### **Code Documentation**
- **Comment complex logic** and business rules
- **Document API endpoints** with request/response examples
- **Maintain README files** with setup and deployment instructions
- **Keep documentation in sync** with code changes

### **Decision Records**
- **Document architectural decisions** with rationale
- **Record performance optimization choices**
- **Explain security implementation decisions**
- **Track major dependency choices**

## 🚀 Deployment Readiness

### **Pre-deployment Checklist**
- [ ] All tests passing (unit, integration, e2e)
- [ ] No console errors in browser
- [ ] Environment variables configured correctly
- [ ] Database migrations applied and tested
- [ ] Static files optimized and accessible
- [ ] SSL certificates valid and properly configured
- [ ] Monitoring and alerting configured
- [ ] Rollback plan documented and tested

### **Post-deployment Verification**
- [ ] Application starts successfully
- [ ] Critical user flows work correctly
- [ ] Performance metrics within acceptable ranges
- [ ] No new error logs or alerts
- [ ] Database connections and queries working
- [ ] External integrations functioning

## 🔄 Maintenance Practices

### **Regular Tasks**
- **Update dependencies** monthly or as security patches release
- **Review and clean up** unused code and dependencies
- **Optimize database** performance and storage
- **Backup verification** - ensure backups can be restored
- **Security audit** of authentication and authorization

### **Monitoring and Alerts**
- **Set up health checks** for critical services
- **Monitor disk space**, memory usage, and CPU utilization
- **Track application errors** and performance degradation
- **Alert on security events** and unusual activity patterns

---

## 📚 Integration with Project CLAUDE.md

Add this section to your project's CLAUDE.md:

```markdown
# 📚 Documentation References
This project follows Claude Code universal patterns.
For comprehensive guidance, see: universal-patterns.md

# Project-Specific Overrides
[Add any project-specific modifications to universal patterns here]
```

---

*These patterns apply to ALL projects regardless of technology stack.*
*Framework-specific guidance should supplement, not replace, these universal practices.*