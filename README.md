# Claude Code Documentation Library

This directory contains standardized documentation templates and best practices for Claude Code across different project types and scenarios.

## 📁 File Structure

### **Core Templates**
- `universal-patterns.md` - Patterns applicable to ALL projects
- `security-guidelines.md` - Security best practices for all frameworks
- `selenium-e2e-testing.md` - Mandatory E2E testing with Selenium
- `mandatory-security-protocols.md` - **CRITICAL: Required security protocols**

### **Security Suite**
- `security-audit.sh` - **MANDATORY: Comprehensive security scanner**
- `global-security.sh` - Universal fallback security check
- `.claude-security.json` - Security configuration and rules
- `setup-security.sh` - Automated security deployment script

### **Framework-Specific**
- `aspnet-core.md` - ASP.NET Core / .NET projects
- `react-nodejs.md` - React and Node.js projects
- `python-django.md` - Python/Django applications
- `vue-nuxt.md` - Vue.js and Nuxt applications
- `angular.md` - Angular applications
- `php.md` - PHP development (Laravel, WordPress, etc.)
- `ruby.md` - Ruby and Ruby on Rails projects
- `golang.md` - Go language projects
- `autoit.md` - Windows automation scripts

### **Specialized Workflows**
- `database-operations.md` - Database management and migrations
- `deployment-readiness.md` - Pre-deployment checklists
- `git-workflows.md` - Git strategies and commit conventions
- `performance-optimization.md` - Performance monitoring and optimization
- `debugging-workflows.md` - Systematic debugging approaches
- `postgresql.md` - PostgreSQL-specific database operations
- `bash-scripting.md` - Shell scripting best practices

### **Server Administration**
- `apache-administration.md` - Apache HTTP Server configuration and security
- `nginx-administration.md` - Nginx web server and reverse proxy management
- `iis-administration.md` - Microsoft IIS configuration and security

## 🎯 How to Use This Library

### **1. For New Projects**
**MANDATORY: Set up security first:**
```bash
# Deploy comprehensive security suite
./setup-security.sh

# Copy relevant framework template
cp aspnet-core.md /path/to/your/project/CLAUDE.md
# OR
cp react-nodejs.md /path/to/your/project/CLAUDE.md
```

**🚨 CRITICAL: Run security audit before ANY development:**
```bash
./security-audit.sh
```

### **2. For Existing Projects**
Add sections from relevant templates to your existing `CLAUDE.md`:
- Always include `universal-patterns.md` content
- Add framework-specific sections as needed
- Include specialized workflows based on project complexity

### **3. Decision Matrix**

| Project Type | Required Files | Optional Files |
|--------------|---------------|----------------|
| **ASP.NET Core** | `universal-patterns.md`, `aspnet-core.md` | `database-operations.md`, `security-guidelines.md`, `iis-administration.md` |
| **React/Node.js** | `universal-patterns.md`, `react-nodejs.md` | `performance-optimization.md`, `deployment-readiness.md`, `nginx-administration.md` |
| **Python/Django** | `universal-patterns.md`, `python-django.md` | `database-operations.md`, `security-guidelines.md`, `nginx-administration.md` |
| **PHP** | `universal-patterns.md`, `php.md` | `database-operations.md`, `security-guidelines.md`, `apache-administration.md` |
| **Ruby/Rails** | `universal-patterns.md`, `ruby.md` | `database-operations.md`, `postgresql.md`, `nginx-administration.md` |
| **Go** | `universal-patterns.md`, `golang.md` | `performance-optimization.md`, `nginx-administration.md` |
| **AutoIT** | `universal-patterns.md`, `autoit.md` | `bash-scripting.md`, `iis-administration.md` |
| **DevOps/Infrastructure** | `universal-patterns.md`, `deployment-readiness.md` | `apache-administration.md`, `nginx-administration.md`, `iis-administration.md` |
| **Enterprise Apps** | All core + framework-specific | All specialized workflows + server administration |
| **Simple Scripts** | `universal-patterns.md` only | `debugging-workflows.md` |

### **4. Integration Instructions**
Add this section to your project's `CLAUDE.md`:

```markdown
# 📚 Additional Documentation
This project follows patterns from Claude Code Documentation Library.
For detailed guidance, reference:
- Universal patterns: universal-patterns.md
- Framework-specific: [framework].md
- Specialized workflows: [workflow].md
```

## 🔄 Template Updates

### **Keeping Your Project Synchronized**
If your project was created from this template, you can sync future template updates using the provided scripts:

**For Unix/Linux/macOS:**
```bash
chmod +x update-template.sh
./update-template.sh https://github.com/your-username/template-repo.git
```

**For Windows:**
```cmd
update-template.bat https://github.com/your-username/template-repo.git
```

**Script Options:**
- `-r, --remote-name NAME` - Name for template remote (default: template)
- `-b, --branch BRANCH` - Template branch to sync from (default: main)
- `-d, --dry-run` - Preview changes without applying them
- `-y, --yes` - Skip interactive prompts

**Manual Update Process:**
```bash
# Add template as remote (first time only)
git remote add template https://github.com/your-username/template-repo.git

# Fetch and merge template changes
git fetch template
git merge template/main --allow-unrelated-histories
```

### **Maintenance**

#### **Updating Templates**
- Templates should be updated based on real project experience
- Each template includes a "Last Updated" date
- Breaking changes should be documented in version headers

#### **Contributing New Patterns**
1. Document the pattern with real examples
2. Test across multiple projects
3. Add to appropriate template file
4. Update this README's decision matrix

## 🚀 Quick Start Examples

### **Minimal CLAUDE.md (Simple Projects)**
```markdown
# Include universal patterns
📚 Reference: universal-patterns.md

# Project-specific notes
[Your custom instructions here]
```

### **Comprehensive CLAUDE.md (Enterprise Projects)**
```markdown
# Multi-reference approach
📚 Core Documentation:
- Universal: universal-patterns.md
- Framework: aspnet-core.md
- Security: security-guidelines.md
- Database: database-operations.md

# Project-specific overrides
[Your custom instructions here]
```

---

*Last Updated: 2025-01-16*
*Version: 1.0*