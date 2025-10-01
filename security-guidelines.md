# Security Guidelines for Claude Code

*Last Updated: 2025-01-16 | Version: 1.0*

## 🔒 Security-First Development

### **CRITICAL SECURITY RULES**
1. **NEVER commit secrets, API keys, passwords, or sensitive configuration to version control**
2. **ALL user inputs MUST be validated, sanitized, and escaped before processing**
3. **ALWAYS use parameterized queries - NEVER concatenate user input into SQL**
4. **ENFORCE HTTPS in production - redirect HTTP to HTTPS automatically**
5. **IMPLEMENT proper authentication and authorization on ALL endpoints**
6. **NEVER trust client-side validation - always validate server-side**
7. **USE secure session management and proper logout functionality**
8. **LOG security events for monitoring and incident response**

## 🛡️ Authentication and Authorization

### **Password Security**
```csharp
// GOOD: Use bcrypt or similar for password hashing
using BCrypt.Net;

public string HashPassword(string password)
{
    return BCrypt.HashPassword(password, BCrypt.GenerateSalt(12));
}

public bool VerifyPassword(string password, string hashedPassword)
{
    return BCrypt.Verify(password, hashedPassword);
}

// Password requirements
public bool IsValidPassword(string password)
{
    return password.Length >= 8 &&
           password.Any(char.IsUpper) &&
           password.Any(char.IsLower) &&
           password.Any(char.IsDigit) &&
           password.Any(ch => !char.IsLetterOrDigit(ch));
}
```

### **JWT Token Security**
```csharp
// Secure JWT configuration
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = Configuration["Jwt:Issuer"],
            ValidAudience = Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(Configuration["Jwt:Key"])
            ),
            ClockSkew = TimeSpan.Zero // Remove default 5-minute tolerance
        };
    });

// Generate secure tokens
public string GenerateJwtToken(User user)
{
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.ASCII.GetBytes(_jwtSettings.Key);
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, user.Role)
        }),
        Expires = DateTime.UtcNow.AddHours(1), // Short expiration
        Issuer = _jwtSettings.Issuer,
        Audience = _jwtSettings.Audience,
        SigningCredentials = new SigningCredentials(
            new SymmetricSecurityKey(key),
            SecurityAlgorithms.HmacSha256Signature
        )
    };
    var token = tokenHandler.CreateToken(tokenDescriptor);
    return tokenHandler.WriteToken(token);
}
```

### **Session Management**
```csharp
// Secure session configuration
services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.Name = "__Secure-SessionId";
});

// Session security headers
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
    await next();
});
```

## 🚫 Input Validation and Sanitization

### **SQL Injection Prevention**
```csharp
// GOOD: Parameterized queries
public async Task<User> GetUserByIdAsync(int userId)
{
    const string sql = "SELECT * FROM Users WHERE Id = @UserId";
    using var connection = new SqlConnection(_connectionString);
    return await connection.QueryFirstOrDefaultAsync<User>(sql, new { UserId = userId });
}

// BAD: String concatenation
// string sql = $"SELECT * FROM Users WHERE Id = {userId}"; // NEVER DO THIS
```

### **XSS Prevention**
```csharp
// Server-side HTML encoding
public string SanitizeHtml(string input)
{
    if (string.IsNullOrEmpty(input))
        return string.Empty;

    return HttpUtility.HtmlEncode(input);
}

// Rich text sanitization
using HtmlAgilityPack;

public string SanitizeRichText(string html)
{
    var doc = new HtmlDocument();
    doc.LoadHtml(html);

    var allowedTags = new[] { "p", "br", "strong", "em", "ul", "ol", "li" };
    var allowedAttributes = new[] { "class", "id" };

    var nodesToRemove = doc.DocumentNode.Descendants()
        .Where(n => !allowedTags.Contains(n.Name.ToLower()))
        .ToList();

    foreach (var node in nodesToRemove)
    {
        node.Remove();
    }

    return doc.DocumentNode.InnerHtml;
}
```

### **Input Validation Attributes**
```csharp
public class UserRegistrationModel
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    [StringLength(100, ErrorMessage = "Email cannot exceed 100 characters")]
    public string Email { get; set; }

    [Required(ErrorMessage = "Password is required")]
    [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be 8-100 characters")]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$",
        ErrorMessage = "Password must contain uppercase, lowercase, number, and special character")]
    public string Password { get; set; }

    [Required]
    [StringLength(50, ErrorMessage = "First name cannot exceed 50 characters")]
    [RegularExpression(@"^[a-zA-Z\s]+$", ErrorMessage = "First name can only contain letters and spaces")]
    public string FirstName { get; set; }
}
```

## 🔐 Environment Variable Security (Consolidated Guidance)

### **CRITICAL RULE: Real Values vs Placeholders**

**The `.env.example` vs `.env` Distinction:**

- **`.env.example`** = Documentation template (placeholders are OK here)
  - Purpose: Shows what variables are needed
  - Contains: Placeholder text like `your_api_key_here`
  - Committed to git: YES

- **`.env`** = Runtime configuration (placeholders are NEVER OK)
  - Purpose: Contains actual secrets for the application
  - Contains: Real values ONLY
  - Committed to git: NO (must be in .gitignore)

### **Environment Variable Files**

**`.env.example` (Documentation Template - Commit This):**
```bash
# =======================================================================
# ENVIRONMENT CONFIGURATION TEMPLATE
# =======================================================================
# This file documents required environment variables
# Placeholders shown here are for DOCUMENTATION ONLY
#
# SETUP INSTRUCTIONS:
# 1. Copy this file to .env
# 2. Replace ALL placeholder values with real credentials
# 3. Never use placeholder values in the actual .env file
# =======================================================================

# Database Configuration
DATABASE_URL=postgresql://username:password@host:5432/database_name
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=your_database_name
DATABASE_USER=your_database_user
DATABASE_PASSWORD=your_database_password

# Application Secrets (generate with: openssl rand -base64 32)
JWT_SECRET=your_jwt_secret_here
API_KEY=your_api_key_here
SECRET_KEY=your_secret_key_here
ENCRYPTION_KEY=your_encryption_key_here

# SMTP Configuration
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your_smtp_username
SMTP_PASSWORD=your_smtp_password

# Test Environment Variables (used in test suites)
TEST_DATABASE_URL=postgresql://testuser:testpassword@localhost:5432/test_database
TEST_API_KEY=test_api_key_here
TEST_JWT_SECRET=test_jwt_secret_here

# External API Keys
STRIPE_API_KEY=your_stripe_api_key
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key

# Application Configuration
NODE_ENV=development
ASPNETCORE_ENVIRONMENT=Development
DEBUG=true
LOG_LEVEL=info

# =======================================================================
# SECURITY NOTES:
# - Generate secrets with: openssl rand -base64 32
# - Use different values for dev/test/prod environments
# - Never commit the actual .env file
# - Rotate secrets periodically
# =======================================================================
```

**`.env` (Runtime Configuration - NEVER Commit):**
```bash
# PRODUCTION/DEVELOPMENT - REAL VALUES ONLY
# Generated: 2025-01-16
# Environment: Development

# Database Configuration - REAL credentials
DATABASE_URL=postgresql://myapp_user:Kx9$Lp3!Mn7#Qw2@db-prod.example.com:5432/myapp_production
DATABASE_HOST=db-prod.example.com
DATABASE_PORT=5432
DATABASE_NAME=myapp_production
DATABASE_USER=myapp_user
DATABASE_PASSWORD=Kx9$Lp3!Mn7#Qw2

# Application Secrets - REAL generated values
JWT_SECRET=Zn8#Km3@Pb6!Vc2$Hx9&Ld7%Jt4*Nq5
API_KEY=sk-prod-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
SECRET_KEY=Rt6!Qw3#Mn8@Pb5$Vc2&Hx9%Ld3*Km7
ENCRYPTION_KEY=Lp8!Nq3#Wr5$Bx2&Fv9%Km6*Jt4@Hx7

# SMTP Configuration - REAL credentials
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASSWORD=SG.Kx9Lp3Mn7Qw2Vc5Hx8Ld4Jt6

# Test Environment - REAL generated test values
TEST_DATABASE_URL=postgresql://test_user:Wx5!Yr8#Pb3@localhost:5432/myapp_test
TEST_API_KEY=test-Mx4$Np7!Kq2#Lw9
TEST_JWT_SECRET=test-Bv6!Jx3#Mn8$Qp5

# External APIs - REAL API keys (replace with actual values)
STRIPE_API_KEY=your_stripe_api_key_here
AWS_ACCESS_KEY_ID=your_aws_access_key_here
AWS_SECRET_ACCESS_KEY=your_aws_secret_key_here

# Application Configuration
NODE_ENV=production
ASPNETCORE_ENVIRONMENT=Production
DEBUG=false
LOG_LEVEL=warning
```

### **Generating Secure Values**

```bash
# Generate random secrets for production
echo "JWT_SECRET=$(openssl rand -base64 32)"
echo "API_KEY=$(openssl rand -hex 32)"
echo "SECRET_KEY=$(openssl rand -base64 32)"
echo "ENCRYPTION_KEY=$(openssl rand -base64 44)"

# Generate test database credentials
echo "TEST_DATABASE_URL=postgresql://test_user:$(openssl rand -base64 16)@localhost:5432/test_db"

# Generate all secrets at once
cat > .env.generated << 'EOF'
# Auto-generated secrets - $(date)
JWT_SECRET=$(openssl rand -base64 32)
API_KEY=$(openssl rand -hex 32)
SECRET_KEY=$(openssl rand -base64 32)
ENCRYPTION_KEY=$(openssl rand -base64 44)
TEST_JWT_SECRET=$(openssl rand -base64 32)
TEST_DATABASE_PASSWORD=$(openssl rand -base64 16)
EOF

# Then review and add to your .env file
```

### **Environment Variable Usage in Code**

**Production Code:**
```csharp
// Load from environment - REQUIRED
var connectionString = Environment.GetEnvironmentVariable("DATABASE_CONNECTION")
    ?? throw new InvalidOperationException("DATABASE_CONNECTION not found");

var jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET")
    ?? throw new InvalidOperationException("JWT_SECRET not found");
```

**Test Code - ALSO uses environment variables:**
```csharp
// Test configuration - uses TEST_* environment variables
public class IntegrationTestBase
{
    protected string GetTestDatabaseUrl()
    {
        return Environment.GetEnvironmentVariable("TEST_DATABASE_URL")
            ?? throw new InvalidOperationException("TEST_DATABASE_URL not configured");
    }

    protected string GetTestApiKey()
    {
        return Environment.GetEnvironmentVariable("TEST_API_KEY")
            ?? throw new InvalidOperationException("TEST_API_KEY not configured");
    }
}

// Usage in tests
[Fact]
public async Task TestDatabaseConnection()
{
    var testDbUrl = GetTestDatabaseUrl();
    using var connection = new NpgsqlConnection(testDbUrl);
    await connection.OpenAsync();
    Assert.True(connection.State == ConnectionState.Open);
}
```

### **Azure Key Vault Integration**
```csharp
// Startup.cs
public void ConfigureAppConfiguration(IConfigurationBuilder builder)
{
    if (!env.IsDevelopment())
    {
        var builtConfig = builder.Build();
        var keyVaultUrl = builtConfig["KeyVaultUrl"];

        builder.AddAzureKeyVault(keyVaultUrl, new DefaultAzureCredential());
    }
}
```

## 🌐 HTTPS and Transport Security

### **HTTPS Configuration**
```csharp
// Startup.cs
public void ConfigureServices(IServiceCollection services)
{
    // Enforce HTTPS
    services.AddHttpsRedirection(options =>
    {
        options.RedirectStatusCode = StatusCodes.Status307TemporaryRedirect;
        options.HttpsPort = 443;
    });

    // HSTS (HTTP Strict Transport Security)
    services.AddHsts(options =>
    {
        options.Preload = true;
        options.IncludeSubDomains = true;
        options.MaxAge = TimeSpan.FromDays(365);
    });
}

public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    if (!env.IsDevelopment())
    {
        app.UseHsts();
    }

    app.UseHttpsRedirection();
}
```

### **CORS Configuration**
```csharp
// Secure CORS setup
services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigins", builder =>
    {
        builder
            .WithOrigins("https://yourdomain.com", "https://www.yourdomain.com")
            .WithMethods("GET", "POST", "PUT", "DELETE")
            .WithHeaders("Content-Type", "Authorization")
            .AllowCredentials();
    });
});

app.UseCors("AllowSpecificOrigins");
```

## 🔍 Security Headers

### **Comprehensive Security Headers**
```csharp
public class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Content Security Policy
        context.Response.Headers.Add("Content-Security-Policy",
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' https://trusted-cdn.com; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: https:; " +
            "font-src 'self' https://fonts.gstatic.com; " +
            "connect-src 'self' https://api.yourdomain.com;");

        // Prevent clickjacking
        context.Response.Headers.Add("X-Frame-Options", "DENY");

        // Prevent MIME type sniffing
        context.Response.Headers.Add("X-Content-Type-Options", "nosniff");

        // XSS Protection
        context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");

        // Referrer Policy
        context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");

        // Permissions Policy
        context.Response.Headers.Add("Permissions-Policy",
            "geolocation=(), microphone=(), camera=()");

        await _next(context);
    }
}
```

## 🏗️ Secure Architecture Patterns

### **Rate Limiting**
```csharp
// Using AspNetCoreRateLimit
services.AddMemoryCache();
services.Configure<IpRateLimitOptions>(Configuration.GetSection("IpRateLimiting"));
services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();
services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();

// appsettings.json
{
  "IpRateLimiting": {
    "EnableEndpointRateLimiting": true,
    "StackBlockedRequests": false,
    "RealIpHeader": "X-Real-IP",
    "ClientIdHeader": "X-ClientId",
    "GeneralRules": [
      {
        "Endpoint": "*",
        "Period": "1m",
        "Limit": 60
      },
      {
        "Endpoint": "*/api/auth/*",
        "Period": "1m",
        "Limit": 5
      }
    ]
  }
}
```

### **Request Size Limiting**
```csharp
// Limit request body size
services.Configure<FormOptions>(options =>
{
    options.ValueLengthLimit = 4096; // 4KB
    options.MultipartBodyLengthLimit = 10 * 1024 * 1024; // 10MB
    options.MultipartHeadersLengthLimit = 16384; // 16KB
});

services.Configure<IISServerOptions>(options =>
{
    options.MaxRequestBodySize = 10 * 1024 * 1024; // 10MB
});
```

## 🔐 API Security

### **API Key Management**
```csharp
public class ApiKeyMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IConfiguration _configuration;

    public ApiKeyMiddleware(RequestDelegate next, IConfiguration configuration)
    {
        _next = next;
        _configuration = configuration;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Request.Path.StartsWithSegments("/api"))
        {
            if (!context.Request.Headers.TryGetValue("X-API-Key", out var extractedApiKey))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("API Key missing");
                return;
            }

            var apiKey = _configuration.GetValue<string>("ApiKey");
            if (!apiKey.Equals(extractedApiKey))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Invalid API Key");
                return;
            }
        }

        await _next(context);
    }
}
```

### **Request Logging for Security**
```csharp
public class SecurityLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SecurityLoggingMiddleware> _logger;

    public SecurityLoggingMiddleware(RequestDelegate next, ILogger<SecurityLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Log security-relevant events
        if (context.Request.Path.StartsWithSegments("/api/auth"))
        {
            _logger.LogInformation("Authentication attempt from IP {IpAddress} to {Path}",
                context.Connection.RemoteIpAddress, context.Request.Path);
        }

        // Log failed requests
        await _next(context);

        if (context.Response.StatusCode == 401 || context.Response.StatusCode == 403)
        {
            _logger.LogWarning("Unauthorized access attempt from IP {IpAddress} to {Path}",
                context.Connection.RemoteIpAddress, context.Request.Path);
        }
    }
}
```

## 🚨 Enhanced Security Testing Protocol

### **Pre-Development Security Checklist**
- [ ] **Threat modeling completed** - Identify attack vectors and mitigation strategies
- [ ] **Security requirements defined** - Authentication, authorization, data protection
- [ ] **Secure coding standards established** - Team training on security practices
- [ ] **Development environment secured** - Local dev environments hardened

### **Development Security Checklist**
- [ ] **All user inputs validated and sanitized** - Server-side validation mandatory
- [ ] **Parameterized queries used for database access** - No string concatenation
- [ ] **Authentication and authorization implemented correctly** - Role-based access control
- [ ] **Sensitive data encrypted in transit and at rest** - AES-256 minimum
- [ ] **Security headers configured** - CSP, HSTS, X-Frame-Options, etc.
- [ ] **Rate limiting implemented** - API and authentication endpoints protected
- [ ] **Error messages don't leak sensitive information** - Generic error responses
- [ ] **Secrets not committed to version control** - Environment variables or vault
- [ ] **File upload security implemented** - Validation, scanning, secure storage
- [ ] **CSRF protection enabled** - Anti-forgery tokens for state-changing operations
- [ ] **Account lockout implemented** - Brute force protection enabled
- [ ] **Security logging configured** - Audit trails for all security events

### **Pre-Production Security Checklist**
- [ ] **Dependency vulnerabilities scanned** - All packages up to date
- [ ] **Static security analysis completed** - SAST tools executed
- [ ] **Dynamic security testing performed** - DAST tools executed
- [ ] **Penetration testing completed** - Third-party security assessment
- [ ] **Security configuration reviewed** - Production hardening verified
- [ ] **HTTPS enforced in production** - SSL/TLS properly configured
- [ ] **Security monitoring configured** - SIEM/logging for production
- [ ] **Incident response plan documented** - Security breach procedures
- [ ] **Backup and recovery tested** - Data protection verified
- [ ] **Access controls audited** - Principle of least privilege enforced

### **Ongoing Security Maintenance**
- [ ] **Security patches applied regularly** - Monthly vulnerability updates
- [ ] **Access reviews conducted quarterly** - User permissions audited
- [ ] **Security logs monitored daily** - Anomaly detection active
- [ ] **Backup integrity verified monthly** - Recovery procedures tested
- [ ] **Security training updated annually** - Team education current

### **Vulnerability Scanning**
```bash
# Scan for vulnerable packages
dotnet list package --vulnerable

# Use OWASP Dependency Check
dependency-check --project "MyProject" --scan ./

# Static code analysis
dotnet sonarscanner begin /k:"project-key"
dotnet build
dotnet sonarscanner end
```

## 🔒 File Upload Security

### **Secure File Upload Implementation**
```csharp
public class SecureFileUploadService
{
    private readonly string[] _allowedExtensions = { ".jpg", ".jpeg", ".png", ".pdf", ".docx" };
    private readonly string[] _allowedMimeTypes = { "image/jpeg", "image/png", "application/pdf" };
    private readonly long _maxFileSize = 5 * 1024 * 1024; // 5MB

    public async Task<bool> ValidateFileAsync(IFormFile file)
    {
        // Check file size
        if (file.Length > _maxFileSize || file.Length == 0)
            return false;

        // Check file extension
        var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
        if (!_allowedExtensions.Contains(extension))
            return false;

        // Check MIME type
        if (!_allowedMimeTypes.Contains(file.ContentType.ToLowerInvariant()))
            return false;

        // Scan file content (basic)
        using var stream = file.OpenReadStream();
        var buffer = new byte[512];
        await stream.ReadAsync(buffer, 0, 512);

        // Check for malicious signatures
        if (ContainsMaliciousSignature(buffer))
            return false;

        return true;
    }

    private bool ContainsMaliciousSignature(byte[] buffer)
    {
        // Check for executable signatures
        var maliciousSignatures = new byte[][]
        {
            new byte[] { 0x4D, 0x5A }, // MZ header (executable)
            new byte[] { 0x50, 0x4B }, // ZIP header (potential script archive)
        };

        foreach (var signature in maliciousSignatures)
        {
            if (buffer.Take(signature.Length).SequenceEqual(signature))
                return true;
        }

        return false;
    }

    public string GenerateSecureFileName(string originalFileName)
    {
        // Generate secure filename to prevent path traversal
        var extension = Path.GetExtension(originalFileName);
        var secureFileName = $"{Guid.NewGuid()}{extension}";
        return secureFileName;
    }
}
```

## 🛡️ CSRF Protection

### **Anti-Forgery Token Implementation**
```csharp
// Startup.cs
services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.Name = "__Secure-CSRF-Token";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// Controller action
[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> UpdateProfile(UserProfileModel model)
{
    // Protected action
    return View(model);
}

// For AJAX requests
public class CSRFTokenController : Controller
{
    [HttpGet]
    public IActionResult GetToken()
    {
        var tokens = antiforgery.GetAndStoreTokens(HttpContext);
        return Json(new { token = tokens.RequestToken });
    }
}
```

## 🔐 Data Encryption

### **Encryption at Rest**
```csharp
public class EncryptionService
{
    private readonly string _encryptionKey;

    public EncryptionService(IConfiguration configuration)
    {
        _encryptionKey = configuration["EncryptionKey"]
            ?? throw new InvalidOperationException("Encryption key not configured");
    }

    public string EncryptSensitiveData(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
            return string.Empty;

        using var aes = Aes.Create();
        aes.Key = Convert.FromBase64String(_encryptionKey);
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor();
        using var ms = new MemoryStream();
        using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
        using var writer = new StreamWriter(cs);

        writer.Write(plainText);
        writer.Flush();
        cs.FlushFinalBlock();

        var encrypted = ms.ToArray();
        var result = new byte[aes.IV.Length + encrypted.Length];
        Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
        Array.Copy(encrypted, 0, result, aes.IV.Length, encrypted.Length);

        return Convert.ToBase64String(result);
    }

    public string DecryptSensitiveData(string cipherText)
    {
        if (string.IsNullOrEmpty(cipherText))
            return string.Empty;

        var buffer = Convert.FromBase64String(cipherText);

        using var aes = Aes.Create();
        aes.Key = Convert.FromBase64String(_encryptionKey);

        var iv = new byte[aes.IV.Length];
        var encrypted = new byte[buffer.Length - iv.Length];

        Array.Copy(buffer, 0, iv, 0, iv.Length);
        Array.Copy(buffer, iv.Length, encrypted, 0, encrypted.Length);

        aes.IV = iv;

        using var decryptor = aes.CreateDecryptor();
        using var ms = new MemoryStream(encrypted);
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var reader = new StreamReader(cs);

        return reader.ReadToEnd();
    }
}
```

## 🚫 Content Security Policy (CSP)

### **Comprehensive CSP Implementation**
```csharp
public class ContentSecurityPolicyMiddleware
{
    private readonly RequestDelegate _next;

    public ContentSecurityPolicyMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Generate nonce for inline scripts
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        context.Items["csp-nonce"] = nonce;

        var csp = $@"
            default-src 'self';
            script-src 'self' 'nonce-{nonce}' https://trusted-cdn.com;
            style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
            img-src 'self' data: https: blob:;
            font-src 'self' https://fonts.gstatic.com;
            connect-src 'self' https://api.yourdomain.com;
            media-src 'self';
            object-src 'none';
            child-src 'self';
            frame-ancestors 'none';
            form-action 'self';
            upgrade-insecure-requests;
            block-all-mixed-content;
        ".Replace("\n", "").Replace(" ", " ").Trim();

        context.Response.Headers.Add("Content-Security-Policy", csp);

        await _next(context);
    }
}
```

## 🔍 Security Logging and Monitoring

### **Comprehensive Security Event Logging**
```csharp
public enum SecurityEventType
{
    Login,
    LoginFailed,
    Logout,
    PasswordChange,
    AccountLockout,
    PrivilegeEscalation,
    SuspiciousActivity,
    DataAccess,
    ConfigurationChange,
    SecurityViolation
}

public class SecurityAuditLogger
{
    private readonly ILogger<SecurityAuditLogger> _logger;

    public SecurityAuditLogger(ILogger<SecurityAuditLogger> logger)
    {
        _logger = logger;
    }

    public void LogSecurityEvent(SecurityEventType eventType, string userId, string details, string ipAddress = null)
    {
        var logLevel = GetLogLevel(eventType);
        var eventData = new
        {
            EventType = eventType.ToString(),
            UserId = userId,
            Details = details,
            IpAddress = ipAddress,
            Timestamp = DateTime.UtcNow,
            UserAgent = GetUserAgent()
        };

        _logger.Log(logLevel, "Security Event: {@SecurityEvent}", eventData);

        // Send alerts for critical events
        if (IsCriticalEvent(eventType))
        {
            SendSecurityAlert(eventData);
        }
    }

    private LogLevel GetLogLevel(SecurityEventType eventType)
    {
        return eventType switch
        {
            SecurityEventType.Login => LogLevel.Information,
            SecurityEventType.LoginFailed => LogLevel.Warning,
            SecurityEventType.SuspiciousActivity => LogLevel.Error,
            SecurityEventType.SecurityViolation => LogLevel.Critical,
            _ => LogLevel.Information
        };
    }

    private bool IsCriticalEvent(SecurityEventType eventType)
    {
        return eventType is SecurityEventType.SuspiciousActivity
                         or SecurityEventType.SecurityViolation
                         or SecurityEventType.PrivilegeEscalation;
    }
}
```

## 🛡️ Account Security

### **Account Lockout and Brute Force Protection**
```csharp
public class AccountSecurityService
{
    private readonly IMemoryCache _cache;
    private readonly SecurityAuditLogger _auditLogger;
    private const int MaxFailedAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    public async Task<bool> IsAccountLockedAsync(string identifier)
    {
        var lockoutKey = $"lockout_{identifier}";
        var lockoutTime = _cache.Get<DateTime?>(lockoutKey);

        if (lockoutTime.HasValue && DateTime.UtcNow < lockoutTime.Value)
        {
            return true;
        }

        if (lockoutTime.HasValue && DateTime.UtcNow >= lockoutTime.Value)
        {
            // Clear expired lockout
            _cache.Remove(lockoutKey);
            _cache.Remove($"attempts_{identifier}");
        }

        return false;
    }

    public async Task RecordFailedAttemptAsync(string identifier, string ipAddress)
    {
        var attemptsKey = $"attempts_{identifier}";
        var attempts = _cache.Get<int>(attemptsKey);
        attempts++;

        _cache.Set(attemptsKey, attempts, TimeSpan.FromMinutes(15));

        _auditLogger.LogSecurityEvent(
            SecurityEventType.LoginFailed,
            identifier,
            $"Failed attempt #{attempts}",
            ipAddress);

        if (attempts >= MaxFailedAttempts)
        {
            var lockoutKey = $"lockout_{identifier}";
            var lockoutUntil = DateTime.UtcNow.Add(LockoutDuration);
            _cache.Set(lockoutKey, lockoutUntil, LockoutDuration);

            _auditLogger.LogSecurityEvent(
                SecurityEventType.AccountLockout,
                identifier,
                $"Account locked until {lockoutUntil}",
                ipAddress);
        }
    }

    public void ClearFailedAttempts(string identifier)
    {
        var attemptsKey = $"attempts_{identifier}";
        _cache.Remove(attemptsKey);
    }
}
```

## 🔄 Security Monitoring
```csharp
public class SecurityEventLogger
{
    private readonly ILogger<SecurityEventLogger> _logger;

    public SecurityEventLogger(ILogger<SecurityEventLogger> logger)
    {
        _logger = logger;
    }

    public void LogSuccessfulLogin(string userId, string ipAddress)
    {
        _logger.LogInformation("Successful login for user {UserId} from IP {IpAddress}",
            userId, ipAddress);
    }

    public void LogFailedLogin(string email, string ipAddress)
    {
        _logger.LogWarning("Failed login attempt for email {Email} from IP {IpAddress}",
            email, ipAddress);
    }

    public void LogSuspiciousActivity(string activity, string userId, string ipAddress)
    {
        _logger.LogError("Suspicious activity detected: {Activity} by user {UserId} from IP {IpAddress}",
            activity, userId, ipAddress);
    }
}
```

### **Alerting for Security Events**
```csharp
// Monitor for brute force attacks
public class BruteForceDetectionService
{
    private readonly IMemoryCache _cache;
    private readonly ILogger<BruteForceDetectionService> _logger;

    public bool IsAttackDetected(string ipAddress)
    {
        var key = $"failed_attempts_{ipAddress}";
        var attempts = _cache.Get<int>(key);

        if (attempts >= 5)
        {
            _logger.LogError("Brute force attack detected from IP {IpAddress}", ipAddress);
            return true;
        }

        return false;
    }

    public void RecordFailedAttempt(string ipAddress)
    {
        var key = $"failed_attempts_{ipAddress}";
        var attempts = _cache.Get<int>(key);
        _cache.Set(key, attempts + 1, TimeSpan.FromMinutes(15));
    }
}
```

## 🛡️ Additional Defensive Security Measures

### **Environment Separation and Hardening**
```bash
# Production environment variables (secure configuration)
NODE_ENV=production
ASPNETCORE_ENVIRONMENT=Production
DEBUG=false
DISABLE_DEBUG=true
SECURE_COOKIES=true
TRUST_PROXY=false

# Security-focused startup configuration
FORCE_HTTPS=true
HSTS_MAX_AGE=31536000
CSP_REPORT_ONLY=false
SECURITY_HEADERS_ENABLED=true
```

### **Database Security Hardening**
```sql
-- Database user with minimal privileges
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'SecurePassword123!';
GRANT SELECT, INSERT, UPDATE, DELETE ON app_database.* TO 'app_user'@'localhost';
REVOKE ALL PRIVILEGES ON mysql.* FROM 'app_user'@'localhost';
REVOKE FILE ON *.* FROM 'app_user'@'localhost';

-- Disable dangerous functions
SET sql_mode = 'STRICT_TRANS_TABLES,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION';
```

### **Infrastructure Security**
```yaml
# Docker security configuration
version: '3.8'
services:
  app:
    image: myapp:latest
    user: "1001:1001"  # Non-root user
    read_only: true
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
```

### **Zero Trust Security Model**
```csharp
// Implement zero trust principles
public class ZeroTrustMiddleware
{
    public async Task InvokeAsync(HttpContext context)
    {
        // Verify every request regardless of source
        if (!await VerifyRequestIntegrity(context))
        {
            context.Response.StatusCode = 403;
            return;
        }

        // Log all access attempts
        LogAccessAttempt(context);

        await _next(context);
    }

    private async Task<bool> VerifyRequestIntegrity(HttpContext context)
    {
        // Verify authentication token
        if (!context.User.Identity.IsAuthenticated)
            return false;

        // Check IP allowlist (if applicable)
        if (!IsIpAllowed(context.Connection.RemoteIpAddress))
            return false;

        // Verify device fingerprint (if implemented)
        if (!await VerifyDeviceFingerprint(context))
            return false;

        return true;
    }
}
```

---

**Key Security Enhancements Added:**

✅ **Enhanced CRITICAL SECURITY RULES** - 8 fundamental security principles
✅ **File Upload Security** - Comprehensive validation and malware detection
✅ **CSRF Protection** - Anti-forgery token implementation
✅ **Data Encryption at Rest** - AES encryption service
✅ **Content Security Policy** - Comprehensive CSP with nonce support
✅ **Security Audit Logging** - Structured security event tracking
✅ **Account Security** - Brute force protection and lockout mechanisms
✅ **Enhanced Testing Protocol** - Pre-dev, development, pre-production checklists
✅ **Environment Hardening** - Production security configuration
✅ **Zero Trust Security** - Verify every request approach

*Security is everyone's responsibility. These guidelines should be followed consistently across all projects.*