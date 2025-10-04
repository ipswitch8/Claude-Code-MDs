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

## **✅ Testing Protocol Verification (10 Steps)**

### **Step 0: Security Audit**
- [ ] Executed ./security-audit.sh with 0 critical issues
- **Evidence**: [Security audit output]

### **Step 1: Instruction Refresh**
- [ ] Read CLAUDE.md or project-specific instructions
- [ ] Read relevant framework documentation (react-nodejs.md, python-django.md, etc.)
- [ ] Read CRITICAL_INSTRUCTION_PRESERVATION.md
- [ ] Read pre-testing-checklist.md
- **Evidence**: [Confirmation of files reviewed]

### **Step 2: Environment Preparation**
- [ ] Stopped all running processes (show process IDs killed)
- [ ] Clean environment verified
- **Command**: [Process kill commands used]
- **Evidence**: [Process list before/after]

### **Step 3: Build/Compile**
- [ ] Clean build completed successfully
- **Command**: [Build command used]
- **Result**: [0 errors, X warnings - paste actual output]
- **Evidence**: [Build output with timestamps]

### **Step 4: Server/Application Restart**
- [ ] Application started successfully
- **Command**: [Startup command used]
- **Result**: [Startup confirmation message]
- **Evidence**: [Startup logs, listening ports, etc.]

### **Step 5: 🚨 MANDATORY SELENIUM UI TESTING 🚨**
- [ ] **ABSOLUTE BLOCKER: Cannot mark complete without browser automation evidence**
- [ ] test_[FEATURE]_selenium.py created with real browser automation code
- [ ] [FEATURE]_selenium_results.txt shows test execution results
- [ ] Chrome screenshots captured (minimum 3)
- [ ] Firefox screenshots captured (minimum 3)
- [ ] console_errors_[FEATURE].txt created with 0 SEVERE errors
- **Test Script**: [File path to test_[FEATURE]_selenium.py]
- **Results File**: [File path to [FEATURE]_selenium_results.txt]
- **Test Count**: [X/Y tests passed]
- **Execution Time**: [Seconds]
- **Evidence**: [List all 6+ evidence files with paths]

**⚠️ NO EVIDENCE = NO COMPLETION - Non-negotiable**

### **Step 6: 🚨 MANDATORY CROSS-BROWSER TESTING 🚨**
- [ ] **ABSOLUTE BLOCKER: Cannot mark complete without multi-browser evidence**
- [ ] Chrome automated testing completed (screenshots + console check)
- [ ] Firefox automated testing completed (screenshots + console check)
- [ ] Mobile viewport (375px) tested with screenshots
- [ ] Tablet viewport (768px) tested with screenshots
- [ ] Desktop viewport (1920px) tested with screenshots
- [ ] Comparative screenshots show consistency across browsers
- [ ] Browser compatibility verification documented
- **Chrome Version**: [Version number]
- **Firefox Version**: [Version number]
- **Chrome Console Errors**: [Number - MUST BE 0]
- **Firefox Console Errors**: [Number - MUST BE 0]
- **Evidence**: [Screenshot files, console error logs]

**⚠️ Console errors > 0 = TEST FAILED = TASK INCOMPLETE**

### **Step 7: Verify Assets Load Correctly**
- [ ] Expected outcomes verified
- **URLs/Endpoints Tested**: [List with response codes]
- **UI Elements Verified**: [List elements and states]
- **Static Assets**: [List assets with HTTP 200 responses]
- **Evidence**: [HTTP responses, network tab screenshots]

### **Step 8: Verify Database Changes**
- [ ] Database verification completed (if data modifications expected)
- **Before State**: [SQL query and results]
- **After State**: [SQL query and results]
- **Values Changed**: ✅ YES / ❌ NO
- **Evidence**: [See Database Verification section below]

### **Step 9: Document Findings**
- [ ] This evidence document completed
- [ ] All 6+ evidence files created and referenced
- **Artifacts Created**: [List ALL files created during testing]
- **Evidence**: [Links to screenshots, logs, recordings, test scripts]

**⚠️ Minimum 6 evidence files required for UI changes**

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

### **🚨 User Interface Testing (SELENIUM MANDATORY)**

**⚠️ ABSOLUTE BLOCKER: UI changes require ALL 6+ evidence files**

#### **Evidence File Checklist (NO EVIDENCE = NO COMPLETION)**
- [ ] **test_[FEATURE]_selenium.py** - [File path or "NOT CREATED"]
  - Lines of code: [Number]
  - Test methods: [Number]
  - Uses BasePage pattern: ✅ YES / ❌ NO
  - Includes authentication: ✅ YES / ❌ NO

- [ ] **[FEATURE]_selenium_results.txt** - [File path or "NOT CREATED"]
  - Tests passed: [X/Y]
  - Execution time: [Seconds]
  - Timestamp: [When tests ran]

- [ ] **screenshots/[FEATURE]_chrome_*.png** - [Number of screenshots]
  - Before state: [Filename]
  - Action state: [Filename]
  - After state: [Filename]

- [ ] **screenshots/[FEATURE]_firefox_*.png** - [Number of screenshots]
  - Before state: [Filename]
  - Action state: [Filename]
  - After state: [Filename]

- [ ] **console_errors_[FEATURE].txt** - [File path or "NOT CREATED"]
  - SEVERE errors: [Number - MUST BE 0]
  - Status: ✅ PASSED (0 errors) / ❌ FAILED (X errors)

- [ ] **[FEATURE]_test_evidence.md** - [This file]

**⚠️ If ANY checkbox is unchecked, task is INCOMPLETE**

#### **Selenium Test Execution Results**
- **Page Loading**: ✅ SUCCESS / ❌ FAILED - [Details]
- **Element Visibility**: ✅ SUCCESS / ❌ FAILED - [Details]
- **Button Clicks**: ✅ SUCCESS / ❌ FAILED - [Specific buttons clicked]
- **Form Submissions**: ✅ SUCCESS / ❌ FAILED - [Forms tested]
- **Validation Messages**: ✅ SUCCESS / ❌ FAILED - [Messages verified]
- **Responsive Design**: ✅ SUCCESS / ❌ FAILED - [Viewports tested: 375px, 768px, 1920px]

#### **Console Error Verification (MANDATORY)**
- **Chrome Console Errors**: [Number - MUST BE 0]
- **Firefox Console Errors**: [Number - MUST BE 0]
- **Evidence File**: console_errors_[FEATURE].txt
- **Status**: ✅ 0 ERRORS / ❌ ERRORS FOUND (BLOCKER)

### **API/Backend Testing**
- **Endpoint Accessibility**: ✅ SUCCESS / ❌ FAILED - [Details]
- **Request/Response**: ✅ SUCCESS / ❌ FAILED - [Details]
- **Data Validation**: ✅ SUCCESS / ❌ FAILED - [Details]
- **Error Handling**: ✅ SUCCESS / ❌ FAILED - [Details]

### **🚨 Cross-Browser Testing (MANDATORY FOR UI CHANGES)**
**⚠️ ABSOLUTE BLOCKER: UI changes require Chrome AND Firefox automated testing**

- **Chrome**: ✅ PASS / ❌ FAIL
  - Version tested: [Version number]
  - Screenshots: [List screenshot filenames]
  - Console errors: [Number - MUST BE 0]
  - Test execution time: [Seconds]

- **Firefox**: ✅ PASS / ❌ FAIL
  - Version tested: [Version number]
  - Screenshots: [List screenshot filenames]
  - Console errors: [Number - MUST BE 0]
  - Test execution time: [Seconds]

- **Edge**: ✅ PASS / ❌ FAIL / ⚠️ OPTIONAL - [Version tested]
- **Safari**: ✅ PASS / ❌ FAIL / ⚠️ OPTIONAL - [Version tested]

#### **Mobile/Responsive Testing (MANDATORY)**
- **Mobile (375px)**: ✅ PASS / ❌ FAIL
  - Screenshots: [Filenames]
  - Elements visible: ✅ YES / ❌ NO
  - Functionality works: ✅ YES / ❌ NO

- **Tablet (768px)**: ✅ PASS / ❌ FAIL
  - Screenshots: [Filenames]
  - Layout correct: ✅ YES / ❌ NO

- **Desktop (1920px)**: ✅ PASS / ❌ FAIL
  - Screenshots: [Filenames]
  - All features accessible: ✅ YES / ❌ NO

**⚠️ If Chrome or Firefox FAILED, task is INCOMPLETE**
**⚠️ If any console errors > 0, task is INCOMPLETE**

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
- [ ] All 10 protocol steps completed with evidence
- [ ] 🚨 Selenium UI testing completed with 6+ evidence files (if UI changes)
- [ ] 🚨 Cross-browser testing completed (Chrome + Firefox) (if UI changes)
- [ ] 🚨 Console errors = 0 across all browsers (if UI changes)
- [ ] Database changes verified (if applicable)
- [ ] UI interactions successful
- [ ] Authentication working (if applicable)
- [ ] No critical issues blocking functionality
- [ ] Existing features not broken (regression check)
- [ ] All evidence artifacts collected

**⚠️ For UI Changes - MUST HAVE:**
- ✅ test_[FEATURE]_selenium.py file created
- ✅ [FEATURE]_selenium_results.txt file created
- ✅ screenshots/[FEATURE]_chrome_*.png files (minimum 3)
- ✅ screenshots/[FEATURE]_firefox_*.png files (minimum 3)
- ✅ console_errors_[FEATURE].txt file (showing 0 errors)
- ✅ This evidence document completed

**Without these 6 files, UI testing is INCOMPLETE**

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
- "UI testing completed" (without Selenium evidence)
- "Visually inspected, looks good"
- "Manual testing passed"
- "Tested in one browser, should work in others"
- "Console errors don't affect functionality"
- "Selenium not needed for this simple change"

### **✅ ALWAYS SAY (Required):**
- "All 10 protocol steps completed with evidence documented in [filename]"
- "Selenium test completed successfully - clicked [specific elements], verified database changed from [X] to [Y]"
- "test_expandable_tickets_selenium.py executed: 8/8 tests passed, screenshots saved to screenshots/, console errors: 0"
- "Multi-browser testing complete: Chrome (v120) and Firefox (v121) both passed, mobile viewport (375px) verified"
- "Evidence files created: test_pricing_selenium.py, pricing_selenium_results.txt, screenshots/pricing_chrome_1.png, screenshots/pricing_firefox_1.png, console_errors_pricing.txt, pricing_test_evidence.md"
- "End-to-end verification confirmed with screenshots"
- "Database values verified: changed from [before] to [after]"
- "Authentication successful: logged in as [user], accessed [protected resource]"
- "Console error log shows 0 errors across all browsers tested"

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
- **🚨 FOR UI CHANGES: All 6+ Selenium evidence files created (NO EXCEPTIONS)**
- **🚨 FOR UI CHANGES: Console errors = 0 (NO EXCEPTIONS)**
- **🚨 FOR UI CHANGES: Chrome AND Firefox testing completed (NO EXCEPTIONS)**
- Database verification (if data changes expected)
- Authentication verification (if auth required)
- No blocker issues
- All artifacts collected and referenced

**If authentication fails → Test failed → Task incomplete (NO EXCEPTIONS)**

**If database unchanged when changes expected → Test failed → Task incomplete (NO EXCEPTIONS)**

**If UI changes without Selenium evidence → Test incomplete → Task incomplete (NO EXCEPTIONS)**

**If console errors > 0 → Test failed → Task incomplete (NO EXCEPTIONS)**

**NO SELENIUM = NO UI COMPLETION = NO FEATURE SIGN-OFF**

---

*This template ensures comprehensive, evidence-based testing that prevents false completion claims and shortcuts.*
