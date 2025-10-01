# Testing Evidence Template

*Use this template to document ALL test results - required for marking tasks complete*

---

## **Test Information**

- **Test Name**: [Feature or functionality being tested]
- **Date/Time**: [YYYY-MM-DD HH:MM:SS]
- **Framework/Platform**: [ASP.NET Core / Django / React / etc.]
- **Test Type**: [Unit / Integration / E2E / Selenium]
- **Purpose**: [What specific functionality is being verified]

---

## **✅ Testing Protocol Verification**

### **Step 0: Instruction Refresh**
- [ ] Read CLAUDE.md or project-specific instructions
- [ ] Read relevant framework documentation (react-nodejs.md, python-django.md, etc.)
- [ ] Read CRITICAL_INSTRUCTION_PRESERVATION.md
- **Evidence**: [Confirmation of files reviewed]

### **Step 1: Environment Preparation**
- [ ] Stopped all running processes (show process IDs killed)
- [ ] Clean environment verified
- **Command**: [Process kill commands used]
- **Evidence**: [Process list before/after]

### **Step 2: Build/Compile**
- [ ] Clean build completed successfully
- **Command**: [Build command used]
- **Result**: [0 errors, X warnings - paste actual output]
- **Evidence**: [Build output with timestamps]

### **Step 3: Server/Application Restart**
- [ ] Application started successfully
- **Command**: [Startup command used]
- **Result**: [Startup confirmation message]
- **Evidence**: [Startup logs, listening ports, etc.]

### **Step 4: Execute Core Tests**
- [ ] Tests executed with actual interactions
- **Actions Performed**: [List specific operations: clicked buttons, filled forms, etc.]
- **Result**: [Success/Failure with details]
- **Evidence**: [Test output, screenshots, console logs]

### **Step 5: Verify Results**
- [ ] Expected outcomes verified
- **URLs/Endpoints Tested**: [List with response codes]
- **UI Elements Verified**: [List elements and states]
- **Evidence**: [Screenshots, HTTP responses, console output]

### **Step 6: Document Findings**
- [ ] This evidence document completed
- **Artifacts Created**: [List files created during testing]
- **Evidence**: [Links to screenshots, logs, recordings]

### **Step 7: Regression Verification**
- [ ] Existing functionality unaffected
- **Features Tested**: [List critical features verified still working]
- **Evidence**: [Test results showing no regressions]

---

## **🗃️ Database Verification** (if applicable)

### **Pre-Test Database State**
```sql
-- Query executed BEFORE test:
[SQL QUERY]

-- Results BEFORE test:
[ACTUAL VALUES BEFORE CHANGES]
```

### **Post-Test Database State**
```sql
-- Query executed AFTER test:
[SAME SQL QUERY]

-- Results AFTER test:
[ACTUAL VALUES AFTER CHANGES]
```

### **Change Verification**
- **Values Changed**: ✅ YES / ❌ NO
- **Expected Changes**: [Describe what should have changed]
- **Actual Changes**: [Describe what actually changed]
- **Verification Status**: ✅ MATCHES EXPECTED / ❌ DOES NOT MATCH

**⚠️ CRITICAL:** If database values are unchanged after a test that should modify data, THE TEST FAILED.

---

## **🔐 Authentication Testing** (if applicable)

### **Login Verification**
- **Login Successful**: ✅ YES / ❌ NO
- **Session Established**: ✅ YES / ❌ NO
- **Credentials Used**: [From environment variables - not hardcoded]
- **Evidence**: [Login page screenshot, session cookies, authenticated page access]

### **Authorization Verification**
- **Permissions Enforced**: ✅ YES / ❌ NO
- **Unauthorized Access Blocked**: ✅ YES / ❌ NO
- **Role-Based Access Working**: ✅ YES / ❌ NO
- **Evidence**: [Access attempts, permission checks, authorization logs]

**⚠️ CRITICAL:** Authentication bypass = Test failure = Task incomplete (NO EXCEPTIONS)

---

## **🎯 Specific Test Results**

### **User Interface Testing**
- **Page Loading**: ✅ SUCCESS / ❌ FAILED - [Details]
- **Element Visibility**: ✅ SUCCESS / ❌ FAILED - [Details]
- **Button Clicks**: ✅ SUCCESS / ❌ FAILED - [Details]
- **Form Submissions**: ✅ SUCCESS / ❌ FAILED - [Details]
- **Validation Messages**: ✅ SUCCESS / ❌ FAILED - [Details]
- **Responsive Design**: ✅ SUCCESS / ❌ FAILED - [Details]

### **API/Backend Testing**
- **Endpoint Accessibility**: ✅ SUCCESS / ❌ FAILED - [Details]
- **Request/Response**: ✅ SUCCESS / ❌ FAILED - [Details]
- **Data Validation**: ✅ SUCCESS / ❌ FAILED - [Details]
- **Error Handling**: ✅ SUCCESS / ❌ FAILED - [Details]

### **Cross-Browser Testing** (if applicable)
- **Chrome**: ✅ PASS / ❌ FAIL - [Version tested]
- **Firefox**: ✅ PASS / ❌ FAIL - [Version tested]
- **Edge**: ✅ PASS / ❌ FAIL - [Version tested]
- **Safari**: ✅ PASS / ❌ FAIL - [Version tested]

---

## **📸 Evidence Artifacts**

### **Screenshots**
- [ ] Initial state: [filename or description]
- [ ] Test execution: [filename or description]
- [ ] Final state: [filename or description]
- [ ] Error states (if any): [filename or description]

### **Log Files**
- [ ] Application logs: [filename or location]
- [ ] Test execution logs: [filename or location]
- [ ] Error logs (if any): [filename or location]
- [ ] Browser console logs: [filename or description]

### **Code/Configuration**
- [ ] Test code: [filename or commit hash]
- [ ] Configuration changes: [filename or commit hash]
- [ ] Environment variables used: [listed in .env.example]

### **Video/Recordings** (if applicable)
- [ ] Test execution recording: [filename or link]
- [ ] Bug reproduction: [filename or link]

---

## **⚠️ Issues Encountered**

### **Blocker Issues** (prevent completion)
- **Issue #1**: [Description]
  - **Impact**: [What doesn't work]
  - **Root Cause**: [Analysis]
  - **Resolution**: [How it was fixed / needs to be fixed]

### **Non-Blocker Issues** (noted for future)
- **Issue #1**: [Description]
  - **Workaround**: [Temporary solution]
  - **Recommendation**: [Suggested fix]

---

## **🎯 Final Verdict**

### **Overall Test Result**: ✅ PASS / ❌ FAIL

### **Pass Criteria Met**:
- [ ] All protocol steps completed with evidence
- [ ] Database changes verified (if applicable)
- [ ] UI interactions successful
- [ ] Authentication working (if applicable)
- [ ] No critical issues blocking functionality
- [ ] Existing features not broken (regression check)
- [ ] All evidence artifacts collected

### **Failure Analysis** (if test failed):
- **Primary Failure Point**: [Where the test failed]
- **Root Cause**: [Why it failed]
- **Impact Assessment**: [What this means for the feature]
- **Remediation Required**: [What needs to be fixed]
- **Estimated Fix Time**: [Time estimate]

### **Task Completion Status**:
- ✅ **COMPLETE** - All criteria met with evidence, ready for deployment
- ⚠️ **COMPLETE WITH NOTES** - Passes but has non-critical issues documented
- ❌ **INCOMPLETE** - Critical failures prevent completion, fixes required

---

## **📋 Prohibited vs Required Statements**

### **❌ NEVER SAY (Unacceptable):**
- "Infrastructure tests pass, ready for manual testing"
- "Code looks correct, should work"
- "Authentication failed but system is implemented"
- "Implementation complete" (without evidence)
- "Probably works" or "Should work"
- "Bypassing authentication for testing purposes"

### **✅ ALWAYS SAY (Required):**
- "Selenium test completed successfully - clicked [specific elements], verified database changed from [X] to [Y]"
- "All 7 protocol steps completed with evidence"
- "End-to-end verification confirmed with screenshots"
- "Database values verified: changed from [before] to [after]"
- "Authentication successful: logged in as [user], accessed [protected resource]"

---

## **📊 Test Metrics** (optional but recommended)

- **Test Execution Time**: [Duration]
- **Number of Test Cases**: [Total / Passed / Failed]
- **Code Coverage**: [Percentage if available]
- **Performance Metrics**: [Load time, response time, etc.]

---

**⚠️ CRITICAL REMINDER:**

Tasks cannot be marked "complete" unless this template shows **PASS** with:
- Full evidence for all applicable sections
- Database verification (if data changes expected)
- Authentication verification (if auth required)
- No blocker issues
- All artifacts collected and referenced

**If authentication fails → Test failed → Task incomplete (NO EXCEPTIONS)**

**If database unchanged when changes expected → Test failed → Task incomplete (NO EXCEPTIONS)**

---

*This template ensures comprehensive, evidence-based testing that prevents false completion claims and shortcuts.*
