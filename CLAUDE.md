# Project Context and Documentation

*This file provides intelligent project detection and loads only relevant documentation for your specific environment.*

---

## 🤖 Auto-Detection Instructions for Claude

**When you start working on this project, follow this detection sequence:**

### **1. Core Documentation (Always Load)**
Always read these files first:
- `mandatory-security-protocols.md` - Security protocols that apply to ALL interactions
- `universal-patterns.md` - Universal development patterns and 7-step testing protocol
- `CRITICAL_INSTRUCTION_PRESERVATION.md` - Critical rules that must never be violated

### **2. Project Environment Detection**

**Run these detection checks to determine which additional files to read:**

```bash
# Check for web server configuration files
ls -la | grep -E "(apache2.conf|httpd.conf|.htaccess|nginx.conf|sites-available|web.config|applicationHost.config)"

# Check for language/framework indicators
ls -la | grep -E "(package.json|composer.json|requirements.txt|Gemfile|go.mod|*.csproj|*.sln)"

# Check for database files
ls -la | grep -E "(migrations|seeds|*.sql|alembic|flyway)"

# Check for testing frameworks
ls -la | grep -E "(pytest.ini|phpunit.xml|jest.config|karma.conf|selenium|cypress)"

# Check for project structure
find . -maxdepth 2 -type d | grep -E "(src|app|controllers|models|views|public|static|templates)"
```

### **3. Conditional File Loading Logic**

**Based on detection results, load appropriate documentation:**

#### **Web Server Detection:**
- **If Apache files found** (`apache2.conf`, `httpd.conf`, `.htaccess`):
  - Read: `apache-administration.md`

- **If Nginx files found** (`nginx.conf`, `sites-available/`, `sites-enabled/`):
  - Read: `nginx-administration.md`

- **If IIS files found** (`web.config`, `applicationHost.config`):
  - Read: `iis-administration.md`

#### **Programming Language/Framework Detection:**

- **If Node.js/React found** (`package.json` with react dependencies):
  - Read: `react-nodejs.md`

- **If Python/Django found** (`requirements.txt` with Django, `manage.py`):
  - Read: `python-django.md`

- **If PHP found** (`composer.json`, `*.php` files):
  - Read: `php.md`

- **If Ruby/Rails found** (`Gemfile`, `config/routes.rb`):
  - Read: `ruby.md`

- **If Go found** (`go.mod`, `*.go` files):
  - Read: `golang.md`

- **If ASP.NET found** (`*.csproj`, `*.sln`, `Program.cs`):
  - Read: `aspnet-core.md`

- **If AutoIt found** (`*.au3` files):
  - Read: `autoit.md`

- **If Bash scripts found** (`*.sh` files, `#!/bin/bash` shebangs):
  - Read: `bash-scripting.md`

#### **Database Detection:**

- **If database files found** (migrations, `*.sql`, database config):
  - Read: `database-operations.md`

- **If PostgreSQL specific** (`postgresql.conf`, `pg_hba.conf`):
  - Also read: `postgresql.md`

#### **Testing Framework Detection:**

- **If Selenium/browser testing found** (`selenium`, `webdriver`, `e2e` directories):
  - Read: `selenium-e2e-testing.md`

#### **Security Context:**

- **Always load for security-sensitive work:**
  - Read: `security-guidelines.md` (consolidated security guidance)

---

## 📋 Detection Example

**Example detection sequence for a Django + PostgreSQL + Nginx project:**

```bash
# Step 1: Load core docs (always)
- mandatory-security-protocols.md
- universal-patterns.md
- CRITICAL_INSTRUCTION_PRESERVATION.md

# Step 2: Detect environment
Found: requirements.txt with Django
Found: nginx.conf
Found: migrations/ directory
Found: pytest.ini

# Step 3: Load conditional docs
- python-django.md (Django detected)
- nginx-administration.md (Nginx detected)
- database-operations.md (migrations detected)
- postgresql.md (PostgreSQL config found)
- security-guidelines.md (security context)

# Result: 8 documentation files loaded (only what's needed)
```

---

## 🎯 Usage Guidelines

**For Claude Code CLI:**

When starting work on this project:
1. Run detection checks above
2. Load only the files relevant to detected environment
3. Apply universal patterns from `universal-patterns.md`
4. Follow security protocols from `mandatory-security-protocols.md`
5. Never violate rules in `CRITICAL_INSTRUCTION_PRESERVATION.md`

**For Multi-Language Projects:**

If multiple languages/frameworks detected:
- Load all relevant framework documentation
- Prioritize the primary framework (most files of that type)
- Cross-reference security guidelines across all frameworks

**For New Projects:**

If no clear framework detected:
- Load only core documentation
- Ask user to clarify project type
- Then load appropriate framework-specific docs

---

## 🔒 Security-First Approach

**Before any code work, always:**
1. Check `mandatory-security-protocols.md` for security requirements
2. Run security audit: `./security-audit.sh` (if exists)
3. Verify `.env` file uses real values (not placeholders)
4. Check `.env.example` for all required environment variables

---

## 📚 Available Documentation Files

### **Core Documentation:**
- `mandatory-security-protocols.md` - Mandatory security rules
- `universal-patterns.md` - Universal development patterns
- `CRITICAL_INSTRUCTION_PRESERVATION.md` - Inviolable rules
- `security-guidelines.md` - Consolidated security guidance

### **Web Servers:**
- `apache-administration.md` - Apache HTTP Server
- `nginx-administration.md` - Nginx
- `iis-administration.md` - Microsoft IIS

### **Programming Languages/Frameworks:**
- `react-nodejs.md` - React + Node.js
- `python-django.md` - Python + Django
- `php.md` - PHP (Laravel, Symfony, vanilla)
- `ruby.md` - Ruby (Rails, Sinatra)
- `golang.md` - Go
- `aspnet-core.md` - ASP.NET Core
- `autoit.md` - AutoIt scripting
- `bash-scripting.md` - Bash shell scripting

### **Databases:**
- `database-operations.md` - Universal database operations
- `postgresql.md` - PostgreSQL specific

### **Testing:**
- `selenium-e2e-testing.md` - Selenium E2E testing

---

## 🚀 Quick Start

**New to this project? Start here:**

1. Read this file (CLAUDE.md) completely
2. Run detection checks to identify project type
3. Load core documentation (mandatory-security-protocols.md, universal-patterns.md)
4. Load framework-specific documentation based on detection
5. Review `.env.example` for required environment variables
6. Run security audit if available
7. Begin development following loaded guidelines

---

## 📝 Notes

- This intelligent loading system prevents information overload
- Only relevant documentation is loaded for your specific project
- Security protocols are always enforced regardless of project type
- Detection logic can be extended for new frameworks/tools

---

*Last Updated: 2025-01-16 | Version: 2.0*
