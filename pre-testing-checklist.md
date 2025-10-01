# Pre-Testing Checklist

*Use this checklist BEFORE executing any tests to ensure proper setup and prevent wasted testing efforts*

---

## **Purpose**

This checklist prevents:
- Testing with incorrect environment setup
- Wasting time on tests that will fail due to prerequisites
- False test failures caused by environment issues
- Incomplete test coverage due to missing configuration

**⚠️ DO NOT PROCEED WITH TESTING IF ANY ITEM IS UNCHECKED**

---

## **📚 Step 0: Instruction Refresh** (MANDATORY)

Before any testing, verify you understand current requirements:

- [ ] **Read project CLAUDE.md** (or equivalent project documentation)
  - Focus on testing protocols
  - Review any framework-specific requirements
  - Note any project-specific testing rules

- [ ] **Read relevant framework documentation**
  - Check react-nodejs.md, python-django.md, golang.md, etc.
  - Review framework-specific testing steps (8-12)
  - Note environment variable requirements

- [ ] **Read CRITICAL_INSTRUCTION_PRESERVATION.md**
  - Review rules that must never be violated
  - Understand prohibited vs required behaviors
  - Refresh context on critical requirements

- [ ] **Read universal-patterns.md testing section**
  - Review 7-step universal testing protocol
  - Understand TodoWrite requirements
  - Check for recent updates to testing standards

**Purpose**: Prevents "instruction degradation" where critical rules are forgotten during long sessions or after context compaction.

---

## **🔧 Environment Verification**

### **Development Environment**
- [ ] **Operating system requirements met**
  - Correct OS version
  - Required system dependencies installed
  - Sufficient disk space and memory

- [ ] **Runtime/SDK installed and correct version**
  - Node.js / .NET / Python / Go / Ruby version verified
  - Package managers available (npm, pip, gem, go mod, etc.)
  - Version matches project requirements

- [ ] **Database accessible**
  - Database server running
  - Connection credentials available (from environment variables)
  - Test database created and migrations applied
  - Database user has correct permissions

- [ ] **Web server/application server configured**
  - Apache / Nginx / IIS configured (if applicable)
  - Virtual hosts / sites configured
  - SSL certificates valid (if testing HTTPS)
  - Ports available and not in use by other processes

### **Process Management**
- [ ] **No conflicting processes running**
  - Application not already running (check process list)
  - No zombie processes from previous sessions
  - Ports not in use by other applications
  - Background workers/services stopped

**Commands to verify**:
```bash
# Check for running processes (examples by platform)
# Linux/macOS:
ps aux | grep [app-name]
lsof -i :[port-number]

# Windows:
tasklist | findstr [app-name]
netstat -ano | findstr :[port-number]

# Kill processes if needed
kill -9 [PID]           # Linux/macOS
taskkill /PID [PID] /F  # Windows
```

---

## **📦 Dependencies and Build**

### **Package Dependencies**
- [ ] **All dependencies installed**
  - package.json → npm install / yarn install
  - requirements.txt → pip install -r requirements.txt
  - Gemfile → bundle install
  - go.mod → go mod download
  - composer.json → composer install
  - *.csproj → dotnet restore

- [ ] **Dependencies up to date** (if required)
  - Security vulnerabilities checked
  - Compatible versions verified
  - Lock files (package-lock.json, Gemfile.lock, etc.) consistent

### **Build System**
- [ ] **Clean build completed successfully**
  - Previous build artifacts cleaned
  - Build command executed with 0 errors
  - Warnings reviewed and acceptable
  - Build output verified

**Build verification commands**:
```bash
# Clean builds (examples)
dotnet clean && dotnet build
npm run build
python setup.py build
go build ./...
mvn clean install
```

---

## **🔐 Credentials and Configuration**

### **Environment Variables**
- [ ] **.env file exists** (for local development)
  - Copy from .env.example if needed
  - All required variables populated with REAL values (not placeholders)
  - Test-specific variables present (TEST_DATABASE_URL, TEST_API_KEY, etc.)

- [ ] **Environment variables loaded correctly**
  - Application can read environment variables
  - No hardcoded credentials in code
  - Sensitive values not logged or displayed

- [ ] **Test credentials available and working**
  - Test user accounts exist in database
  - Test passwords meet security requirements
  - Test API keys valid and not expired
  - Test credentials stored in .env, NOT in code

**Critical check**:
```bash
# Verify .env has real values, not placeholders
grep -i "your_.*_here" .env  # Should return nothing
grep -i "placeholder" .env    # Should return nothing
```

### **Configuration Files**
- [ ] **Framework configuration valid**
  - appsettings.json, settings.py, config.ru, etc. exist
  - Database connection strings reference environment variables
  - API endpoints configured correctly
  - Feature flags set appropriately for testing

- [ ] **Security configuration**
  - SSL/TLS configured (if applicable)
  - CORS settings appropriate for testing
  - Authentication middleware enabled
  - Rate limiting configured (but not too restrictive for testing)

---

## **🧪 Testing Infrastructure**

### **Test Framework Setup**
- [ ] **Test framework installed**
  - Selenium WebDriver / pytest / Jest / RSpec / xUnit installed
  - Browser drivers available (ChromeDriver, GeckoDriver, etc.)
  - Test dependencies installed

- [ ] **Test database prepared**
  - Separate test database created
  - Test data seeded (if required)
  - Test database isolated from development/production
  - Migrations applied to test database

- [ ] **Selenium/E2E testing setup** (if applicable)
  - Selenium Grid running (if using distributed testing)
  - Browser instances available
  - WebDriver executable in PATH
  - Headless mode configured (if needed)

**Selenium verification**:
```bash
# Check Selenium Grid status
curl http://localhost:4444/wd/hub/status

# Verify ChromeDriver
chromedriver --version

# Test browser automation
# (Run simple test to verify browser opens)
```

### **Test Data and Fixtures**
- [ ] **Test data available**
  - Database fixtures/seeds loaded
  - Test files available (if testing file uploads)
  - Mock data generated (if needed)
  - Test accounts created with known credentials

- [ ] **Test data isolated**
  - Test data won't affect production
  - Test data can be cleaned up after tests
  - Tests can run multiple times without conflicts

---

## **🌐 Network and Services**

### **External Services**
- [ ] **External APIs accessible** (if application depends on them)
  - APIs reachable from test environment
  - API keys valid
  - Rate limits not exceeded
  - Mock services running (if using mocks)

- [ ] **Email service configured** (if testing email functionality)
  - SMTP server accessible
  - Test email accounts available
  - Email catching service running (Mailtrap, MailHog, etc.)

- [ ] **Third-party integrations ready** (if applicable)
  - Payment gateways in test mode
  - Authentication providers configured (OAuth, SAML, etc.)
  - CDN/asset servers accessible

### **Network Configuration**
- [ ] **Network connectivity verified**
  - Internet access (if required)
  - Internal services reachable
  - Firewalls not blocking required ports
  - DNS resolution working

---

## **📋 Documentation and Tracking**

### **Test Documentation Prepared**
- [ ] **Test evidence template ready**
  - testing-evidence-template.md available
  - Screenshot tools ready
  - Screen recording ready (if needed)

- [ ] **Test plan documented** (for complex features)
  - Test scenarios defined
  - Expected outcomes documented
  - Pass/fail criteria clear

- [ ] **TodoWrite tasks created** (if using TodoWrite)
  - All testing steps listed as separate todos
  - Each step includes expected evidence
  - Completion criteria defined

### **Version Control**
- [ ] **Git repository status clean** (or changes committed)
  - No uncommitted changes that could be lost
  - Currently on correct branch
  - Latest code pulled from remote (if team project)

- [ ] **Baseline established** (for regression testing)
  - Know what worked before changes
  - Can rollback if tests fail
  - Have reference point for comparison

---

## **🔍 Pre-Test Smoke Checks**

### **Application Startup**
- [ ] **Application starts without errors**
  - Server starts and listens on expected port
  - No fatal errors in startup logs
  - Health check endpoint returns 200 OK
  - Static assets serve correctly

- [ ] **Basic navigation works**
  - Home page loads
  - Login page accessible
  - Basic routes respond
  - No 404 errors on core pages

### **Authentication System**
- [ ] **Authentication functional** (CRITICAL for E2E tests)
  - Login page loads
  - Can log in with test credentials
  - Session persists after login
  - Protected pages accessible when authenticated
  - Logout works

**⚠️ CRITICAL**: If authentication doesn't work, FIX IT before proceeding. Never bypass authentication in tests.

### **Database Connectivity**
- [ ] **Database queries work**
  - Can read from database
  - Can write to database
  - Transactions working
  - No connection pool exhaustion

---

## **⚠️ Warning Signs - DO NOT PROCEED If:**

- [ ] ❌ Authentication is broken or being bypassed
- [ ] ❌ Database connection fails or credentials incorrect
- [ ] ❌ Application won't start or has startup errors
- [ ] ❌ Required environment variables missing or have placeholder values
- [ ] ❌ Test dependencies not installed or wrong versions
- [ ] ❌ Previous test processes still running
- [ ] ❌ Critical instructions not reviewed (Step 0 skipped)
- [ ] ❌ Build fails or has critical errors
- [ ] ❌ Test credentials hardcoded instead of from environment

**Any of these issues will cause test failures or invalid test results. Fix them FIRST.**

---

## **✅ Final Pre-Test Confirmation**

Before proceeding to execute tests, confirm:

- [ ] **All items in this checklist are checked**
- [ ] **Step 0 (Instruction Refresh) completed first**
- [ ] **Application running and accessible**
- [ ] **Test credentials available from environment variables**
- [ ] **Database accessible and migrations current**
- [ ] **Testing framework and tools ready**
- [ ] **Evidence collection tools ready (screenshots, logs)**
- [ ] **Know what "success" looks like for the test**
- [ ] **Know what to verify in database (if data changes expected)**

---

## **🚀 Ready to Test**

Once all items are checked:
1. Proceed with testing according to universal 7-step protocol
2. Document all evidence using testing-evidence-template.md
3. Verify database changes if applicable
4. Mark tasks complete only with full evidence

**Remember**:
- Authentication failure = Test failure = Task incomplete (NO EXCEPTIONS)
- Database unchanged (when changes expected) = Test failed (NO EXCEPTIONS)
- Missing evidence = Cannot mark complete (NO EXCEPTIONS)

---

*This checklist ensures reproducible, valid test results and prevents wasted effort on tests that will fail due to environment issues.*
