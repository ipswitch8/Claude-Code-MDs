# 🔥🔥🔥 CRITICAL INSTRUCTION PRESERVATION RULES 🔥🔥🔥

## **CONTEXT COMPACTION PREVENTION PROTOCOL**

**⚠️ These instructions MUST be re-read whenever context is compacted or instructions are lost**

---

## **ABSOLUTE RULES (NO EXCEPTIONS):**

### **1. ❌ NEVER MARK TASKS "COMPLETE" WITHOUT:**
- [ ] Full end-to-end Selenium testing with actual UI clicks
- [ ] Database value verification (before/after comparison)
- [ ] Evidence documentation with timestamps
- [ ] Server restart and clean build verification
- [ ] ALL 7 steps of testing protocol completed

### **2. ❌ AUTHENTICATION FAILURE = TEST FAILURE = TASK INCOMPLETE**
- If test users cannot log in → Test failed
- If Selenium times out on login → Test failed
- If any authentication step fails → STOP and fix before proceeding
- No "infrastructure works but login failed" exceptions

### **3. ❌ MANDATORY 8-STEP PROTOCOL:**
```
0. Run security audit - Execute security checks with 0 critical issues
1. Refresh critical instructions - Read CLAUDE.md, pre-testing-checklist.md
2. Stop running application - Show process kill command
3. Build application - Show build output with 0 errors
4. Restart application - Show startup logs with confirmation
5. Test core functionality - Selenium clicks actual UI elements
6. Verify results - HTTP 200 responses + database changes
7. Document evidence - Create timestamped report using testing-evidence-template.md
```

**📋 Use these supporting files:**
- `pre-testing-checklist.md` - Verify environment BEFORE step 0
- `testing-evidence-template.md` - Document results in step 7
- `universal-patterns.md` - Complete protocol details

### **4. ❌ UNACCEPTABLE STATEMENTS:**
- "Infrastructure tests pass, ready for manual testing"
- "Code looks correct, should work"
- "Authentication failed but system is implemented"
- "Implementation complete" (without evidence)

### **5. ✅ REQUIRED STATEMENTS:**
- "Selenium test completed successfully - clicked [specific buttons], verified database changed from [X] to [Y]"
- "All 7 protocol steps completed with evidence"
- "End-to-end verification confirmed"

---

## **DATABASE VERIFICATION REQUIREMENTS:**

### **BEFORE Testing:**
```sql
-- Record current values
SELECT * FROM [relevant_table] WHERE [condition];
```

### **AFTER Testing:**
```sql
-- Verify changes occurred
SELECT * FROM [relevant_table] WHERE [condition];
-- VALUES MUST BE DIFFERENT OR TEST FAILED
```

### **Failure Criteria:**
- If database values are unchanged → THE FIX DOES NOT WORK
- If UI shows success but DB unchanged → THE FIX DOES NOT WORK
- If any verification step fails → THE ENTIRE TEST FAILED

---

## **INSTRUCTION DEGRADATION PREVENTION**

### **What is Instruction Degradation?**
During long sessions or after context compaction, AI systems can "forget" critical rules and requirements, leading to:
- Skipped testing steps
- Shortcuts that bypass important checks
- Missing evidence requirements
- Authentication bypasses
- Incomplete verification

### **Prevention Strategies:**

**1. Proactive Instruction Refresh (Step 0 of all protocols):**
- Always start testing sequences by re-reading critical instructions
- Use `pre-testing-checklist.md` to verify all prerequisites
- Review project-specific CLAUDE.md files
- Check framework-specific documentation

**2. Layered Instruction Architecture:**
```
Layer 1: CRITICAL_INSTRUCTION_PRESERVATION.md (this file) - Critical rules only
Layer 2: universal-patterns.md - Universal testing protocol
Layer 3: Project CLAUDE.md - Project-specific overrides
Layer 4: Framework docs - Framework-specific guidance
```

**3. Warning Sign Monitoring:**
If you notice these thoughts/patterns, instruction degradation is occurring:
- Considering shortcuts or workarounds
- Thinking "probably works" without verification
- Wanting to skip authentication in tests
- Marking tasks complete without evidence
- Rationalizing why a step isn't needed

**4. Mandatory Checkpoints:**
At these points, MUST re-read critical instructions:
- [ ] Start of every testing sequence
- [ ] Before marking any task "complete"
- [ ] After context compaction/conversation continuation
- [ ] When authentication or testing fails
- [ ] When tempted to skip verification steps
- [ ] After extended periods of coding without testing
- [ ] When user questions test completeness

### **Context Loss Detection:**

**Early Warning Signs:**
- ⚠️ Thinking "Infrastructure tests pass, ready for manual testing"
- ⚠️ Saying "Authentication failed but system is implemented"
- ⚠️ Claiming "Code looks correct, should work"
- ⚠️ Stating "Implementation complete" without evidence
- ⚠️ Suggesting to bypass authentication "just for testing"
- ⚠️ Not verifying database changes
- ⚠️ Skipping evidence documentation

**Immediate Actions When Detected:**
1. **STOP** all current work immediately
2. **RE-READ** this file completely
3. **REVIEW** all referenced instruction files
4. **VERIFY** understanding of critical rules
5. **RESTART** work from last verified checkpoint
6. **RE-TEST** with full protocol compliance

---

## **MANDATORY READ SEQUENCE FOR ANY TESTING:**

**BEFORE starting any test:**
1. **pre-testing-checklist.md** - Environment prerequisites
2. **CRITICAL_INSTRUCTION_PRESERVATION.md** (this file) - Core rules
3. **universal-patterns.md** - 8-step testing protocol
4. **Project CLAUDE.md** - Project-specific requirements
5. **Framework documentation** - Framework-specific steps

**DURING testing:**
- Follow 8-step protocol strictly
- Mark each step complete with evidence
- No skipping, no shortcuts

**AFTER testing:**
6. **testing-evidence-template.md** - Document all results
7. **Review checklist** - Verify all criteria met
8. **Mark complete** - Only if ALL evidence collected

---

## **INSTRUCTION PRESERVATION FOR CLAUDE CODE:**

### **Core Principles:**
1. **NEVER generate or guess URLs** unless confident they help with programming
2. **MINIMIZE output tokens** while maintaining helpfulness
3. **Answer concisely** with fewer than 4 lines unless detail requested
4. **NO unnecessary preamble or postamble**
5. **Follow conventions** - check existing code before adding libraries
6. **NEVER ADD COMMENTS** unless asked
7. **USE TodoWrite tool** for complex multi-step tasks

### **Security Requirements:**
- **Assist with defensive security tasks only**
- **Refuse malicious code creation or improvement**
- **Allow security analysis, detection rules, vulnerability explanations**
- **No credential discovery or harvesting assistance**

### **Professional Objectivity:**
- **Prioritize technical accuracy over validation**
- **Focus on facts and problem-solving**
- **Provide direct, objective technical info**
- **Apply rigorous standards to all ideas**
- **Investigate uncertainty rather than confirm beliefs**

### **Tool Usage Policy:**
- **Use Task tool for file searches** to reduce context usage
- **Batch tool calls** when multiple independent pieces needed
- **Run parallel commands** in single message with multiple tool calls
- **WebFetch redirects** require new request with redirect URL

### **Testing Protocol Integration:**
- **ALWAYS restart server before testing frontend changes**
- **Run lint and typecheck** commands after code changes
- **NEVER commit without explicit user request**
- **Verify solutions with tests when possible**

---

## **FILE REFERENCES FOR PRESERVATION:**

### **Core Instruction Files (Always Read):**
- **CRITICAL_INSTRUCTION_PRESERVATION.md** (this file) - Critical rules and degradation prevention
- **universal-patterns.md** - 8-step testing protocol and universal patterns
- **pre-testing-checklist.md** - Environment prerequisites before testing
- **testing-evidence-template.md** - Evidence documentation template

### **Project-Specific Files (Read When Present):**
- **Project CLAUDE.md** - Project-specific requirements and overrides
- **Project-specific testing protocols** - Custom requirements

### **Framework-Specific Files (Read For Your Stack):**
- **react-nodejs.md**, **python-django.md**, **golang.md**, **php.md**, etc.
- **selenium-e2e-testing.md** - E2E testing requirements
- **database-operations.md** - Database migration and testing

### **Security Files (Always Consider):**
- **mandatory-security-protocols.md** - Security requirements
- **security-guidelines.md** - Consolidated security guidance

**READ THESE FILES BEFORE EVERY TEST TO PREVENT INSTRUCTION LOSS**

### **Quick Reference Card:**
```
┌─────────────────────────────────────────────────────┐
│ INSTRUCTION REFRESH PROTOCOL                        │
├─────────────────────────────────────────────────────┤
│ 1. pre-testing-checklist.md → Environment ready?   │
│ 2. This file → Critical rules remembered?          │
│ 3. universal-patterns.md → Protocol steps clear?   │
│ 4. Project CLAUDE.md → Specific requirements?      │
│ 5. Framework docs → Stack-specific needs?          │
├─────────────────────────────────────────────────────┤
│ IF ANY "PROBABLY" OR "SHOULD WORK" → RE-READ ALL  │
└─────────────────────────────────────────────────────┘
```

---

## **EMERGENCY INSTRUCTION RECOVERY:**

If instructions appear lost or degraded:

1. **STOP all current work**
2. **Re-read this entire file**
3. **Review referenced instruction files**
4. **Verify understanding of critical rules**
5. **Resume work only after instruction refresh**

**INSTRUCTION INTEGRITY IS NON-NEGOTIABLE**