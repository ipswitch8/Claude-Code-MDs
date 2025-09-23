# Claude Security Defaults - Global Security Configuration

You're absolutely right! Local system configurations don't travel with you. Here's how to make this a **permanent, global feature of your Claude.ai account**:

## **Method 1: Claude.ai Custom Instructions (Recommended)**

### **Set Permanent Security Protocol in Claude.ai:**

1. Go to **claude.ai → Settings → Custom Instructions**
2. Add this to your **custom instructions**:

```
MANDATORY SECURITY PROTOCOL - APPLIES TO ALL CLAUDE CODE SESSIONS:

1. ALWAYS run security checks before any code work:
   - Check .git directory permissions: find . -name ".git" -exec ls -ld {} \;
   - Secure if needed: find . -name ".git" -exec chmod -R 700 {} \;
   - Remove temp files: find . -name "*.swp" -o -name "*.tmp" -o -name "*~" -delete
   - Scan for secrets: grep -ri "password\|api.key\|secret\|token" . | head -5

2. ALWAYS create security files for new projects:
   - security-audit.sh (comprehensive scanner)
   - .claude-security.json (project config)
   - CLAUDE.md (security documentation)

3. NEVER proceed if CRITICAL security issues found
4. ALWAYS log security findings
5. PROACTIVELY notify about security vulnerabilities

This applies to ALL systems, ALL projects, ALL sessions - NO EXCEPTIONS.
```

## **Method 2: Claude.ai Project Templates**

### **Create a "Security Template" Project:**

1. **In Claude.ai, create a new project called "Security-Template"**
2. **Add this as the project's system prompt:**

```
You are a security-first Claude Code assistant. EVERY session must:

1. Run this security check command first:
```bash
# Mandatory security audit
echo "🔒 SECURITY AUDIT STARTING..."

# Check .git permissions
if [ -d ".git" ]; then
  git_perms=$(ls -ld .git | cut -d' ' -f1)
  if [[ "$git_perms" != "drwx------" ]]; then
    echo "🚨 CRITICAL: Fixing .git permissions"
    chmod -R 700 .git
  fi
fi

# Remove dangerous files
find . -maxdepth 2 -name "*.swp" -o -name "*.tmp" -o -name "*~" -delete 2>/dev/null

# Basic secret scan
if command -v grep >/dev/null; then
  secrets=$(grep -ri "password.*=" . | grep -v ".git" | head -3)
  [ -n "$secrets" ] && echo "⚠️ Potential secrets found: $secrets"
fi

echo "✅ Security check complete"
```

2. If security-audit.sh doesn't exist, create it using this template:
[Include the complete security-audit.sh script here]

3. BLOCK all work if CRITICAL issues found
4. Always create .claude-security.json if missing
5. Document all security findings

REMEMBER: This security protocol applies to EVERY system you work on.
```

## **Method 3: Claude.ai Shared Projects**

### **Create Reusable Security Projects:**

1. **Create a project: "Security-Config-Generator"**
2. **Share it across all your workspaces**
3. **Use it to generate security files for any new project**

**Project prompt:**
```
Generate comprehensive security configuration for any project. Always include:
1. security-audit.sh script
2. .claude-security.json config
3. CLAUDE.md documentation
4. Immediate security scan results
Customize based on project type (web, API, mobile, etc.)
```

## **Method 4: Claude.ai Memory/Preferences**

### **Train Claude to Remember Your Security Requirements:**

In **every new conversation**, start with:
```
"Remember: I require mandatory security checks before any code work. Always run security audits, fix .git permissions, remove temp files, scan for secrets. Block on critical issues. This is a permanent requirement for all my projects across all systems."
```

Claude.ai will remember this preference across sessions.

## **Method 5: Automated Security Prompt Template**

### **Create a Standard Project Initialization Prompt:**

Save this prompt and use it for **every new project**:

```
Initialize a new secure project with these requirements:

1. Create comprehensive security-audit.sh script that checks:
   - File permissions (.git must be 700)
   - Sensitive files (keys, configs, secrets)
   - Code vulnerabilities (hardcoded secrets, dangerous patterns)
   - Auto-fixes critical issues

2. Create .claude-security.json with project-specific rules

3. Create CLAUDE.md with security protocols and integration instructions

4. Run immediate security audit and report findings

5. Set up git with secure permissions

This is my standard security baseline for ALL projects on ANY system.
```

## **Method 6: Claude Code Integration via Repository**

### **Create a "Security-Defaults" Repository:**

1. **Create a GitHub repository: `your-username/claude-security-defaults`**
2. **Include all security templates**
3. **Reference it in every project:**

```bash
# At start of any project
curl -sSL https://raw.githubusercontent.com/your-username/claude-security-defaults/main/setup.sh | bash
```

## **Method 7: Browser Bookmarklet**

### **Create a Quick Security Setup Bookmarklet:**

Save this JavaScript bookmarklet in your browser:
```javascript
javascript:(function(){
  const prompt = `Create security configuration files for this project:
  - security-audit.sh (comprehensive scanner)
  - .claude-security.json (project config) 
  - CLAUDE.md (documentation)
  Then run security audit immediately.`;
  
  if(window.location.hostname.includes('claude.ai')) {
    const textarea = document.querySelector('textarea');
    if(textarea) {
      textarea.value = prompt;
      textarea.focus();
    }
  }
})();
```

## **RECOMMENDED APPROACH:**

**Combine Methods 1 + 2 + 4:**

1. **Set Custom Instructions** in Claude.ai (permanent baseline)
2. **Create Security-Template project** (detailed configuration)
3. **Train Claude's memory** by mentioning security requirements in conversations

This ensures your security requirements are **permanently embedded** in your Claude.ai account and apply to **every system, every project, every session** - regardless of where you're working.

**The key is making it part of your Claude.ai profile, not just local system configuration.**

## **Quick Setup Script**

Use this setup script for any new project:

```bash
#!/bin/bash
# Quick security setup for new projects
curl -sSL https://raw.githubusercontent.com/ipswitch8/claude-security-defaults/main/security-audit.sh > security-audit.sh
curl -sSL https://raw.githubusercontent.com/ipswitch8/claude-security-defaults/main/.claude-security.json > .claude-security.json
curl -sSL https://raw.githubusercontent.com/ipswitch8/claude-security-defaults/main/CLAUDE.md > CLAUDE.md
chmod +x security-audit.sh
echo "✅ Security configuration installed"
./security-audit.sh
```

## **Security Files in This Repository**

- `security-audit.sh` - Comprehensive security scanner
- `.claude-security.json` - Project security configuration template
- `CLAUDE.md` - Security documentation and protocols
- `setup.sh` - Quick installation script
- `global-security.sh` - Universal security check script

## **Usage**

1. **For new projects**: Run `curl -sSL https://raw.githubusercontent.com/ipswitch8/claude-security-defaults/main/setup.sh | bash`
2. **For existing projects**: Copy security files and run audit
3. **For Claude.ai**: Use custom instructions and project templates
4. **For emergencies**: Run security audit immediately

**Remember: Security is not optional - it's mandatory for all projects!**