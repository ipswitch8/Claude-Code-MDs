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
1. **[ ] Refresh critical instructions** - Read project CLAUDE.md, pre-testing-checklist.md, and relevant documentation
2. **[ ] Stop running application** - Show process kill command and confirmation
3. **[ ] Build application** - Show build output with 0 errors
4. **[ ] Restart application** - Show startup logs with "ready" confirmation
5. **[ ] Test core functionality** - Show actual test commands and results
6. **[ ] Verify assets load correctly** - Show HTTP 200 responses for new files
7. **[ ] Document results** - Create timestamped test report with evidence (use testing-evidence-template.md)

**❌ NEVER say "implementation complete" without ALL 8 steps verified with actual evidence.**

**📋 Supporting Documentation:**
- Use `pre-testing-checklist.md` BEFORE starting step 0 to verify environment readiness
- Use `testing-evidence-template.md` for step 7 to document all test results
- Reference `selenium-e2e-testing.md` for comprehensive E2E testing requirements

## ⚠️ PROHIBITED VS REQUIRED STATEMENTS

### **❌ NEVER SAY (Unacceptable - Indicates Incomplete Work):**
- "Infrastructure tests pass, ready for manual testing"
- "Code looks correct, should work"
- "Authentication failed but system is implemented"
- "Implementation complete" (without evidence)
- "Probably works" or "Should work"
- "Bypassing authentication for testing purposes"
- "Database probably updated correctly"
- "Tests mostly pass"
- "Just needs manual verification"

**⚠️ These statements indicate shortcuts were taken and testing is incomplete.**

### **✅ ALWAYS SAY (Required - Demonstrates Complete Verification):**
- "All 8 protocol steps completed with evidence documented in [filename]"
- "Selenium test completed successfully - clicked [specific UI elements], verified database changed from [X] to [Y]"
- "Authentication verified: logged in as [test user], accessed [protected resource], session persisted"
- "Database verification complete: values changed from [before] to [after] as expected"
- "End-to-end testing confirmed with screenshots at [location]"
- "Tests executed: [X] passed, 0 failed, full evidence in testing-evidence-template.md"
- "Regression testing passed: existing features [list] verified working"

**✅ These statements demonstrate thorough, evidence-based verification.**

### **Completion Criteria:**
Tasks can ONLY be marked complete when statements include:
- ✅ Specific evidence locations (filenames, screenshots, logs)
- ✅ Actual values (database before/after, response codes, etc.)
- ✅ Concrete actions taken (which buttons clicked, which forms filled)
- ✅ Verification of expectations (expected vs actual results)

## 🧪 DATABASE VERIFICATION REQUIREMENTS

**For ANY test that modifies database state:**

### **Mandatory Pattern:**

**BEFORE executing test:**
```sql
-- Document current state
SELECT [relevant_columns]
FROM [relevant_table]
WHERE [test_condition];

-- Example:
SELECT UnitCost, VendorId, LastModified
FROM InvoiceItems
WHERE InvoiceId = 12345 AND PartNumber = 'ABC123';

-- Record results: UnitCost=10.50, VendorId=100, LastModified='2025-01-01'
```

**AFTER executing test:**
```sql
-- Verify changes occurred
SELECT [same_columns]
FROM [same_table]
WHERE [same_condition];

-- Expected results: UnitCost=12.75, VendorId=100, LastModified='2025-01-20'
```

### **Verification Rules:**
- ✅ **PASS**: Values changed as expected → Database update confirmed
- ❌ **FAIL**: Values unchanged → THE FIX DOES NOT WORK
- ❌ **FAIL**: Unexpected changes → Side effects detected, investigate

### **Critical Failures:**
- **Database unchanged when changes expected** = Test failed = Task incomplete (NO EXCEPTIONS)
- **UI shows success but database unchanged** = Test failed = Task incomplete (NO EXCEPTIONS)
- **Cannot query database to verify** = Environment issue, fix before continuing

### **Evidence Requirements:**
Document in testing-evidence-template.md:
- SQL queries used (both before and after)
- Actual results from both queries
- Expected vs actual comparison
- Pass/fail verdict with explanation

## 🔐 AUTHENTICATION TESTING REQUIREMENTS

**⚠️ ABSOLUTE RULE: NEVER BYPASS AUTHENTICATION IN TESTS**

### **❌ PROHIBITED (Authentication Bypass Antipatterns):**
- Creating "infrastructure tests" that skip login
- Testing protected APIs without authenticated sessions
- Claiming "authentication not needed for verification"
- Any form of login workaround or bypass
- Creating separate "focused tests" to avoid auth issues
- Mocking authentication in E2E tests
- Using admin backdoors in test code

### **✅ REQUIRED (Proper Authentication Testing):**
- **MUST successfully complete real user login process**
- **MUST access protected resources as authenticated user**
- **MUST interact with actual UI elements in authenticated context**
- **MUST verify session persistence and cookies**
- **MUST test logout and session expiry**
- If login fails: **FIX THE LOGIN**, don't bypass it
- If authentication broken: **FIX AUTHENTICATION**, don't work around it

### **Authentication Testing Pattern:**
```
1. Navigate to login page
2. Enter credentials from environment variables (never hardcoded)
3. Submit login form
4. Wait for redirect to authenticated page
5. Verify session established (check cookies, session storage)
6. Navigate to protected resource
7. Verify access granted and correct data displayed
8. Perform authenticated actions (CRUD operations)
9. Verify logout works correctly
```

### **Failure Criteria:**
- **Authentication fails** = Test failed = Task incomplete (NO EXCEPTIONS)
- **Session not established** = Test failed = Task incomplete (NO EXCEPTIONS)
- **Protected resources accessible without auth** = Security issue = STOP and fix
- **Any bypass mechanism used** = Test invalid = Task incomplete (NO EXCEPTIONS)

**Remember: Authentication shortcuts hide real problems and create security vulnerabilities.**

## 📝 TodoWrite Enforcement Patterns

**For ANY changes requiring testing, TodoWrite MUST include these items:**

### **Required Todo Items (Frontend/Backend Changes):**
```
TodoWrite must include:
1. "Refresh critical instructions from CLAUDE.md and pre-testing-checklist.md"
2. "Stop running application process (show PID killed)"
3. "Build application and verify 0 errors"
4. "Restart application successfully (show 'listening' confirmation)"
5. "Execute [specific test type] tests"
6. "Verify database changes [if data modifications expected]"
7. "Verify authentication [if auth-related features]"
8. "Check for breaking changes to existing features"
9. "Document test results in testing-evidence-template.md"
10. "Review and mark complete only with full evidence"
```

### **TodoWrite State Management Rules:**
- **Exactly ONE task** must be "in_progress" at any time
- **Mark completed** IMMEDIATELY after finishing, don't batch
- **ONLY mark complete** when evidence exists
- If blocked: create new task describing blocker, keep current task "in_progress"

### **Evidence Requirements Per Todo:**
- **"Stopped process"** → Must show PID and kill confirmation
- **"Built application"** → Must show build output (0 errors)
- **"Restarted application"** → Must show startup logs
- **"Executed tests"** → Must show test output and results
- **"Verified database"** → Must show before/after SQL results
- **"Documented results"** → Must reference completed evidence file

### **Invalid Todo Patterns (Don't Do This):**
❌ Single todo: "Complete feature implementation and test"
❌ Vague: "Test the changes"
❌ No evidence: "Testing complete" (without specifics)
❌ Premature completion: Marking done without evidence
❌ Skipped steps: Missing security audit or instruction refresh

### **Valid Todo Patterns (Do This):**
✅ Specific: "Execute Selenium test for invoice pricing update on invoice #12345"
✅ Evidence-linked: "Document test results in PART_PRICING_TEST_2025-01-20.md"
✅ Measurable: "Verify database: UnitCost changed from 10.50 to 12.75"
✅ Sequential: Each step has clear prerequisites and completion criteria

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