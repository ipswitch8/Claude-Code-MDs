# ASP.NET Core Claude Code Guidelines

*Last Updated: 2025-01-16 | Version: 1.0*

## 🏗️ Project Structure and Architecture

### **Repository Pattern Implementation**
- **Controllers** (`Controllers/`) - Handle HTTP requests and coordinate between services
- **Services** (`Services/`) - Business logic layer implementing interfaces
- **Repositories** (`Repository/`) - Data access layer implementing interfaces
- **Interfaces** (`Interfaces/`) - Contracts defining repository and service methods
- **DataModels** (`DataModels/`) - Entity Framework Core models including DbContext
- **ViewModels** (`ViewModels/`) - Data transfer objects for views

### **Configuration Management**
```csharp
// Use strongly-typed configuration
public class DatabaseSettings
{
    public string ConnectionString { get; set; }
    public int CommandTimeout { get; set; }
}

// Register in Startup.cs
services.Configure<DatabaseSettings>(Configuration.GetSection("Database"));
```

## 🔧 Development Commands

### **Build and Run**
```bash
# Development build
dotnet build

# Release build
dotnet build -c Release

# Run development server
dotnet run                           # Usually http://localhost:5000 or 8080
dotnet run --launch-profile "IIS Express"  # Usually http://localhost:44XXX

# Watch mode for development
dotnet watch run
```

### **Entity Framework Commands**
```bash
# Add new migration
dotnet ef migrations add MigrationName

# Update database
dotnet ef database update

# Remove last migration (if not applied)
dotnet ef migrations remove

# Generate SQL script
dotnet ef migrations script

# Drop database (development only)
dotnet ef database drop
```

### **Testing**
```bash
# Run all tests
dotnet test

# Run specific test project
dotnet test Tests/ProjectName.Tests.csproj

# Run tests with coverage
dotnet test --collect:"XPlat Code Coverage"

# Run E2E Selenium tests
dotnet test Tests/E2E.Tests/ --filter Category=E2E
```

### **Selenium E2E Testing Setup**
```csharp
// Tests/E2E.Tests/E2E.Tests.csproj
<PackageReference Include="Selenium.WebDriver" Version="4.15.0" />
<PackageReference Include="Selenium.WebDriver.ChromeDriver" Version="118.0.5993.7000" />
<PackageReference Include="Microsoft.AspNetCore.Mvc.Testing" Version="7.0.0" />
<PackageReference Include="FluentAssertions" Version="6.12.0" />
```

```csharp
// Tests/E2E.Tests/BaseE2ETest.cs
using Microsoft.AspNetCore.Mvc.Testing;
using OpenQA.Selenium;
using OpenQA.Selenium.Chrome;
using OpenQA.Selenium.Support.UI;

public class BaseE2ETest : IDisposable
{
    protected readonly WebApplicationFactory<Program> _factory;
    protected readonly IWebDriver _driver;
    protected readonly WebDriverWait _wait;
    protected readonly string _baseUrl;

    public BaseE2ETest()
    {
        _factory = new WebApplicationFactory<Program>();

        var chromeOptions = new ChromeOptions();
        chromeOptions.AddArguments("--headless", "--no-sandbox", "--disable-dev-shm-usage");

        _driver = new ChromeDriver(chromeOptions);
        _wait = new WebDriverWait(_driver, TimeSpan.FromSeconds(10));

        // Start test server
        var client = _factory.CreateClient();
        _baseUrl = client.BaseAddress.ToString();
    }

    protected void NavigateTo(string relativePath)
    {
        _driver.Navigate().GoToUrl(_baseUrl + relativePath.TrimStart('/'));
    }

    protected IWebElement WaitForElement(By locator)
    {
        return _wait.Until(driver => driver.FindElement(locator));
    }

    public void Dispose()
    {
        _driver?.Quit();
        _factory?.Dispose();
    }
}
```

```csharp
// Tests/E2E.Tests/UserWorkflowTests.cs
[Category("E2E")]
public class UserWorkflowTests : BaseE2ETest
{
    [Test]
    public void UserCanLogin_And_AccessDashboard()
    {
        // Navigate to login page
        NavigateTo("/Account/Login");

        // Fill login form
        var emailField = WaitForElement(By.Id("Email"));
        var passwordField = _driver.FindElement(By.Id("Password"));
        var loginButton = _driver.FindElement(By.CssSelector("button[type='submit']"));

        emailField.SendKeys("test@example.com");
        passwordField.SendKeys("TestPassword123!");
        loginButton.Click();

        // Verify dashboard loads
        _wait.Until(driver => driver.Url.Contains("/Dashboard"));
        var welcomeMessage = WaitForElement(By.CssSelector(".welcome-message"));

        welcomeMessage.Text.Should().Contain("Welcome");
    }

    [Test]
    public void UserCanCreateNewRecord()
    {
        // Login first
        NavigateTo("/Account/Login");
        // ... login steps ...

        // Navigate to create form
        NavigateTo("/Users/Create");

        // Fill form
        var nameField = WaitForElement(By.Id("Name"));
        var emailField = _driver.FindElement(By.Id("Email"));

        nameField.SendKeys("John Doe");
        emailField.SendKeys("john.doe@example.com");

        // Submit form
        var submitButton = _driver.FindElement(By.CssSelector("button[type='submit']"));
        submitButton.Click();

        // Verify success
        var successMessage = WaitForElement(By.CssSelector(".alert-success"));
        successMessage.Text.Should().Contain("User created successfully");
    }

    [TestCase("chrome")]
    [TestCase("firefox")]
    [TestCase("edge")]
    public void ResponsiveDesign_WorksAcrossBrowsers(string browserName)
    {
        // Test responsive behavior across different browsers
        NavigateTo("/");

        // Test mobile viewport
        _driver.Manage().Window.Size = new System.Drawing.Size(375, 667);
        var mobileMenu = WaitForElement(By.CssSelector(".mobile-menu-toggle"));
        mobileMenu.Should().NotBeNull();

        // Test desktop viewport
        _driver.Manage().Window.Size = new System.Drawing.Size(1920, 1080);
        var desktopNav = WaitForElement(By.CssSelector(".desktop-navigation"));
        desktopNav.Should().NotBeNull();
    }
}
```

## 🗄️ Database Operations

### **Entity Framework Best Practices**
```csharp
// Use async methods for database operations
public async Task<User> GetUserAsync(int id)
{
    return await _context.Users
        .Include(u => u.Profile)
        .FirstOrDefaultAsync(u => u.Id == id);
}

// Use transactions for multiple operations
using var transaction = await _context.Database.BeginTransactionAsync();
try
{
    await _context.Users.AddAsync(user);
    await _context.SaveChangesAsync();
    await _context.UserProfiles.AddAsync(profile);
    await _context.SaveChangesAsync();
    await transaction.CommitAsync();
}
catch
{
    await transaction.RollbackAsync();
    throw;
}
```

### **Migration Safety**
- **ALWAYS backup production database before migrations**
- **Test migrations on development/staging first**
- **Use additive-only changes when possible**:
  ```csharp
  // Good: Add new column with default value
  migrationBuilder.AddColumn<bool>("IsActive", "Users", defaultValue: true);

  // Risky: Removing columns (do in separate deployment)
  // migrationBuilder.DropColumn("OldColumn", "Users");
  ```

### **Connection String Management**
```json
// appsettings.json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=MyApp;Trusted_Connection=true;",
    "Production": "Server=prod-server;Database=MyApp;User Id=user;Password=***;"
  }
}
```

## 🔐 Authentication and Authorization

### **Cookie Authentication Setup**
```csharp
// Startup.cs
services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.ExpireTimeSpan = TimeSpan.FromHours(24);
        options.SlidingExpiration = true;
    });

services.AddAuthorization(options =>
{
    options.AddPolicy("Admin", policy => policy.RequireRole("Administrator"));
    options.AddPolicy("SalesRep", policy => policy.RequireRole("Sales"));
});
```

### **Secure Controller Actions**
```csharp
[Authorize(Policy = "SalesRep")]
public class InvoiceController : Controller
{
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(InvoiceViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        // Process creation
        return RedirectToAction(nameof(Index));
    }
}
```

## 📝 Logging with Serilog

### **Configuration**
```csharp
// Program.cs
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(configuration)
    .WriteTo.Console()
    .WriteTo.File("logs/app-.log", rollingInterval: RollingInterval.Day)
    .WriteTo.MSSqlServer(connectionString, "Logs")
    .CreateLogger();

// In controllers
private readonly ILogger<InvoiceController> _logger;

public IActionResult Index()
{
    _logger.LogInformation("Loading invoice list for user {UserId}", User.GetUserId());
    // ... rest of method
}
```

### **Structured Logging**
```csharp
// Good: Structured logging
_logger.LogError("Failed to process invoice {InvoiceId} for user {UserId}",
    invoiceId, userId);

// Bad: String concatenation
_logger.LogError($"Failed to process invoice {invoiceId} for user {userId}");
```

## 🌐 API Development

### **REST API Controllers**
```csharp
[ApiController]
[Route("api/[controller]")]
public class InvoicesController : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IEnumerable<InvoiceDto>>> GetInvoices(
        [FromQuery] InvoiceQueryParameters parameters)
    {
        var invoices = await _invoiceService.GetInvoicesAsync(parameters);
        return Ok(invoices);
    }

    [HttpPost]
    public async Task<ActionResult<InvoiceDto>> CreateInvoice(CreateInvoiceDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var invoice = await _invoiceService.CreateAsync(dto);
        return CreatedAtAction(nameof(GetInvoice), new { id = invoice.Id }, invoice);
    }
}
```

### **Model Validation**
```csharp
public class CreateInvoiceDto
{
    [Required(ErrorMessage = "Customer ID is required")]
    public int CustomerId { get; set; }

    [Required]
    [StringLength(100, MinimumLength = 3)]
    public string Description { get; set; }

    [Range(0.01, double.MaxValue, ErrorMessage = "Amount must be greater than 0")]
    public decimal Amount { get; set; }
}
```

## 🎨 Frontend Integration

### **Razor Views Best Practices**
```html
<!-- Use strongly-typed views -->
@model InvoiceEditViewModel

<!-- Include CSRF protection -->
@using (Html.BeginForm("Edit", "Invoice", FormMethod.Post, new { @class = "form" }))
{
    @Html.AntiForgeryToken()

    <!-- Use HTML helpers for form elements -->
    @Html.LabelFor(m => m.CustomerName)
    @Html.EditorFor(m => m.CustomerName, new { htmlAttributes = new { @class = "form-control" } })
    @Html.ValidationMessageFor(m => m.CustomerName)
}
```

### **Static File Handling**
```csharp
// Startup.cs - Configure static files with caching
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx =>
    {
        // Cache static files for 24 hours
        ctx.Context.Response.Headers.Append("Cache-Control", "public,max-age=86400");
    }
});
```

### **JavaScript/CSS Bundling**
```html
<!-- Use environment-specific bundles -->
<environment include="Development">
    <link rel="stylesheet" href="~/css/site.css" />
    <script src="~/js/site.js"></script>
</environment>
<environment exclude="Development">
    <link rel="stylesheet" href="~/css/site.min.css" asp-append-version="true" />
    <script src="~/js/site.min.js" asp-append-version="true"></script>
</environment>
```

## 🚨 ASP.NET Core Testing Protocol

### **Mandatory E2E Testing Requirements**
**ALL web interfaces MUST include Selenium E2E testing:**

1. **[ ] Selenium Grid configured** - Docker containers running for cross-browser testing
2. **[ ] Authentication workflows tested** - Login, logout, role-based access via browser automation
3. **[ ] Form validation E2E** - Both client-side and server-side validation through Selenium
4. **[ ] Cross-browser compatibility** - Chrome, Firefox, Edge tested via Selenium Grid
5. **[ ] Responsive design verified** - Mobile, tablet, desktop viewports tested
6. **[ ] API endpoints tested** - REST endpoints validated through browser interaction

### **Additional Steps for ASP.NET Core**
After the universal 7-step protocol and mandatory E2E testing:

7. **[ ] Verify Entity Framework migrations** - Check if database schema is current
8. **[ ] Test authentication flows** - Verify login/logout works correctly (E2E + unit tests)
9. **[ ] Check static file serving** - Ensure CSS/JS files load with correct MIME types
10. **[ ] Validate API endpoints** - Test REST endpoints return correct HTTP status codes
11. **[ ] Review Serilog output** - Check application logs for errors or warnings
12. **[ ] Run complete E2E test suite** - Full Selenium test coverage completed

### **Performance Testing**
```bash
# Use dotnet-counters for performance monitoring
dotnet-counters monitor --process-id [PID] Microsoft.AspNetCore.Hosting

# Memory usage analysis
dotnet-dump collect -p [PID]
```

## 🔧 Troubleshooting Common Issues

### **Database Connection Problems**
```csharp
// Test connection in Startup.cs
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    // Test database connection on startup
    using (var scope = app.ApplicationServices.CreateScope())
    {
        var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        context.Database.CanConnect();
    }
}
```

### **Static File 404 Issues**
- Verify `UseStaticFiles()` is called before `UseRouting()`
- Check file paths are correct and case-sensitive
- Ensure files are marked as "Content" in project file

### **Authentication Not Working**
- Verify `UseAuthentication()` is called before `UseAuthorization()`
- Check cookie configuration and domain settings
- Validate user claims and roles are set correctly

## 📦 Dependency Management

### **Package Updates**
```bash
# List outdated packages
dotnet list package --outdated

# Update to latest versions
dotnet add package PackageName

# Update all packages in solution
dotnet restore
```

### **Security Considerations**
- Regularly update `Microsoft.AspNetCore.*` packages
- Monitor for security advisories on NuGet packages
- Use `dotnet audit` to check for vulnerable dependencies

---

## 📚 Integration Instructions

Add this to your ASP.NET Core project's CLAUDE.md:

```markdown
# 📚 ASP.NET Core Documentation
This project follows ASP.NET Core best practices.
For detailed guidance, see: aspnet-core.md

# Framework Version
- Target Framework: netcoreapp3.1 (or current version)
- Entity Framework Core: 3.1.x (or current version)

# Additional References
- Universal patterns: universal-patterns.md
- Database operations: database-operations.md
```

---

*This document is specific to ASP.NET Core applications and should be used alongside universal patterns.*