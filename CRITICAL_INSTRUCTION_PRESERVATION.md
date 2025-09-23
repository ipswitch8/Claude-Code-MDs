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

### **3. ❌ MANDATORY 7-STEP PROTOCOL:**
```
0. Read CLAUDE.md + TESTING_PROTOCOL.md (instruction refresh)
1. Kill all dotnet processes: taskkill /IM dotnet.exe /F
2. Build: dotnet build (must show 0 errors)
3. Restart: dotnet run (must show "Listening on")
4. Test: Selenium clicks actual UI elements
5. Verify: HTTP 200 responses + database changes
6. Document: Evidence with timestamps
```

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

## **WHEN TO RE-READ THESE INSTRUCTIONS:**

- [ ] **Start of every testing sequence**
- [ ] **Before marking any task "complete"**
- [ ] **After context compaction/conversation continuation**
- [ ] **When authentication or testing fails**
- [ ] **When tempted to skip verification steps**

---

## **WARNING SIGNS OF INSTRUCTION LOSS:**

If you find yourself thinking:
- "Infrastructure tests pass, ready for manual testing"
- "Authentication failed but system is implemented"
- "Code looks correct, should work"
- "Implementation complete" (without evidence)

**IMMEDIATELY RE-READ THESE CRITICAL INSTRUCTIONS**

---

## **MANDATORY READ SEQUENCE FOR ANY TESTING:**

1. **CRITICAL_INSTRUCTIONS.md** (context refresh)
2. **CLAUDE.md lines 63-100** (original protocol)
3. **TESTING_PROTOCOL.md** (detailed steps)
4. **BEFORE_TESTING_CHECKLIST.md** (prerequisites)
5. Execute tests following protocol
6. **TEST_EVIDENCE_TEMPLATE.md** (document results)

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
- **CLAUDE.md** - Lines 63-100 (Testing Protocol)
- **TESTING_PROTOCOL.md** - Complete 7-step requirements
- **BEFORE_TESTING_CHECKLIST.md** - Pre-test verification
- **CRITICAL_INSTRUCTIONS.md** - Context-loss prevention rules

**READ THESE FILES BEFORE EVERY TEST TO PREVENT INSTRUCTION LOSS**

---

## **EMERGENCY INSTRUCTION RECOVERY:**

If instructions appear lost or degraded:

1. **STOP all current work**
2. **Re-read this entire file**
3. **Review referenced instruction files**
4. **Verify understanding of critical rules**
5. **Resume work only after instruction refresh**

**INSTRUCTION INTEGRITY IS NON-NEGOTIABLE**