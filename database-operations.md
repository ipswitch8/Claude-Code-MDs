# Database Operations Claude Code Guidelines

*Last Updated: 2025-01-16 | Version: 1.0*

## 🗄️ Database Safety Protocols

### **CRITICAL DATABASE CHANGE GUIDELINES**

**NEVER propose changes to database tables, views, or stored procedures without:**

1. **Search Phase** - Find ALL references in the codebase:
   ```
   - Use Grep to search for view/table names
   - Check both direct references and Entity Framework mappings
   - Look in Controllers, Repositories, Services, and ViewModels
   ```

2. **Analysis Phase** - Understand usage patterns:
   ```
   - How is the data being queried?
   - What columns are being used?
   - Are there JOINs, GROUP BYs, or aggregations?
   - What's the expected row count and structure?
   ```

3. **Impact Assessment** - Document all affected areas:
   ```
   - List every file and method that uses the database object
   - Identify potential breaking changes
   - Note performance implications
   ```

4. **Safe Design Principles**:
   ```
   - ADDITIVE ONLY: Add new columns, never remove/rename existing ones
   - Preserve original structure (JOINs, GROUP BY, WHERE clauses)
   - Use subqueries for new calculated columns to avoid GROUP BY issues
   - Handle NULL values explicitly
   ```

5. **Testing Requirements**:
   ```
   - Include test queries in SQL scripts
   - Verify both old functionality and new features
   - Test with actual production data patterns
   ```

## 📋 Migration Best Practices

### **Schema Migrations**
```sql
-- GOOD: Additive changes
ALTER TABLE Users ADD COLUMN IsEmailVerified BIT DEFAULT 0;
ALTER TABLE Orders ADD COLUMN ShippingTaxAmount DECIMAL(10,2) DEFAULT 0.00;

-- RISKY: Destructive changes (require careful planning)
-- ALTER TABLE Users DROP COLUMN OldField;
-- ALTER TABLE Users RENAME COLUMN OldName TO NewName;

-- SAFE APPROACH: Multi-step deployment
-- Step 1: Add new column
ALTER TABLE Users ADD COLUMN NewField VARCHAR(100);

-- Step 2: Populate new column (separate deployment)
UPDATE Users SET NewField = TRANSFORM(OldField);

-- Step 3: Remove old column (after verifying new column works)
-- ALTER TABLE Users DROP COLUMN OldField;
```

### **Data Migrations**
```sql
-- Use transactions for data migrations
BEGIN TRANSACTION;

-- Create backup table
SELECT * INTO Users_Backup_20250116 FROM Users;

-- Perform migration with error handling
UPDATE Users
SET Status = 'Active'
WHERE Status IS NULL AND LastLoginDate > '2024-01-01';

-- Verify migration
IF @@ROWCOUNT = (SELECT COUNT(*) FROM Users WHERE Status IS NULL AND LastLoginDate > '2024-01-01')
BEGIN
    COMMIT TRANSACTION;
    PRINT 'Migration completed successfully';
END
ELSE
BEGIN
    ROLLBACK TRANSACTION;
    PRINT 'Migration failed - rolled back';
END
```

### **Index Management**
```sql
-- Add indexes with online option (SQL Server)
CREATE NONCLUSTERED INDEX IX_Users_Email
ON Users (Email)
WITH (ONLINE = ON);

-- Check index usage
SELECT
    i.name AS IndexName,
    s.user_seeks,
    s.user_scans,
    s.user_lookups,
    s.user_updates
FROM sys.dm_db_index_usage_stats s
JOIN sys.indexes i ON s.object_id = i.object_id AND s.index_id = i.index_id
WHERE s.database_id = DB_ID()
AND s.object_id = OBJECT_ID('Users');
```

## 🔍 Query Optimization

### **Performance Analysis**
```sql
-- Enable query execution plans
SET STATISTICS IO ON;
SET STATISTICS TIME ON;

-- Analyze slow queries
SELECT TOP 10
    qs.total_elapsed_time / qs.execution_count AS avg_elapsed_time,
    qs.total_logical_reads / qs.execution_count AS avg_logical_reads,
    qs.execution_count,
    qt.text AS query_text
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) qt
ORDER BY avg_elapsed_time DESC;
```

### **Common Optimization Patterns**
```sql
-- GOOD: Use appropriate indexes
SELECT * FROM Orders
WHERE CustomerId = @CustomerId AND OrderDate >= @StartDate;
-- Requires index on (CustomerId, OrderDate)

-- GOOD: Avoid SELECT *
SELECT OrderId, OrderDate, TotalAmount
FROM Orders
WHERE CustomerId = @CustomerId;

-- GOOD: Use EXISTS instead of IN for large datasets
SELECT * FROM Customers c
WHERE EXISTS (SELECT 1 FROM Orders o WHERE o.CustomerId = c.CustomerId);

-- AVOID: Functions in WHERE clauses
-- WHERE YEAR(OrderDate) = 2024  -- Bad
WHERE OrderDate >= '2024-01-01' AND OrderDate < '2025-01-01'  -- Good
```

## 💾 Backup and Recovery

### **Backup Strategies**
```sql
-- Full backup (weekly)
BACKUP DATABASE [MyDatabase]
TO DISK = 'C:\DatabaseBackups\MyDatabase_Full_20250116.bak'
WITH FORMAT, COMPRESSION;

-- Differential backup (daily)
BACKUP DATABASE [MyDatabase]
TO DISK = 'C:\DatabaseBackups\MyDatabase_Diff_20250116.bak'
WITH DIFFERENTIAL, COMPRESSION;

-- Transaction log backup (every 15 minutes)
BACKUP LOG [MyDatabase]
TO DISK = 'C:\DatabaseBackups\MyDatabase_Log_20250116_1530.trn';
```

### **Recovery Testing**
```sql
-- Test restore to verify backup integrity
RESTORE VERIFYONLY
FROM DISK = 'C:\DatabaseBackups\MyDatabase_Full_20250116.bak';

-- Restore to test environment
RESTORE DATABASE [MyDatabase_Test]
FROM DISK = 'C:\DatabaseBackups\MyDatabase_Full_20250116.bak'
WITH MOVE 'MyDatabase' TO 'C:\TestDatabase\MyDatabase_Test.mdf',
     MOVE 'MyDatabase_Log' TO 'C:\TestDatabase\MyDatabase_Test.ldf',
     REPLACE;
```

## 🔐 Security and Access Control

### **User Management**
```sql
-- Create application user with minimal permissions
CREATE LOGIN [AppUser] WITH PASSWORD = 'SecurePassword123!';
CREATE USER [AppUser] FOR LOGIN [AppUser];

-- Grant specific permissions only
GRANT SELECT, INSERT, UPDATE ON dbo.Users TO [AppUser];
GRANT SELECT, INSERT, UPDATE ON dbo.Orders TO [AppUser];
GRANT EXECUTE ON dbo.GetUserOrders TO [AppUser];

-- Deny dangerous permissions
DENY ALTER, DROP ON SCHEMA::dbo TO [AppUser];
```

### **Data Protection**
```sql
-- Encrypt sensitive columns
ALTER TABLE Users
ADD EncryptedSSN varbinary(256);

-- Use parameterized queries (application level)
-- GOOD: Parameters prevent SQL injection
-- command.Parameters.AddWithValue("@UserId", userId);

-- BAD: String concatenation vulnerable to injection
-- string sql = "SELECT * FROM Users WHERE Id = " + userId;
```

## 📊 Monitoring and Maintenance

### **Performance Monitoring**
```sql
-- Monitor blocking sessions
SELECT
    blocking_session_id,
    session_id,
    wait_type,
    wait_time,
    wait_resource
FROM sys.dm_exec_requests
WHERE blocking_session_id > 0;

-- Check database size and growth
SELECT
    name,
    size * 8 / 1024 AS size_mb,
    max_size * 8 / 1024 AS max_size_mb,
    growth,
    is_percent_growth
FROM sys.database_files;
```

### **Maintenance Tasks**
```sql
-- Update statistics (weekly)
UPDATE STATISTICS Users WITH FULLSCAN;

-- Rebuild fragmented indexes (monthly)
SELECT
    OBJECT_NAME(i.object_id) AS TableName,
    i.name AS IndexName,
    ips.avg_fragmentation_in_percent
FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'LIMITED') ips
JOIN sys.indexes i ON ips.object_id = i.object_id AND ips.index_id = i.index_id
WHERE ips.avg_fragmentation_in_percent > 30;

-- Rebuild high fragmentation indexes
ALTER INDEX IX_Users_Email ON Users REBUILD WITH (ONLINE = ON);
```

## 🧪 Database Testing

### **Data Validation**
```sql
-- Test data integrity constraints
-- Check for orphaned records
SELECT o.* FROM Orders o
LEFT JOIN Customers c ON o.CustomerId = c.CustomerId
WHERE c.CustomerId IS NULL;

-- Validate business rules
SELECT * FROM Orders
WHERE TotalAmount < 0 OR OrderDate > GETDATE();

-- Check for duplicate records
SELECT Email, COUNT(*)
FROM Users
GROUP BY Email
HAVING COUNT(*) > 1;
```

### **Performance Testing**
```sql
-- Simulate load testing
DECLARE @i INT = 1;
WHILE @i <= 1000
BEGIN
    INSERT INTO TestOrders (CustomerId, OrderDate, TotalAmount)
    VALUES (RAND() * 1000 + 1, DATEADD(day, -RAND() * 365, GETDATE()), RAND() * 1000);
    SET @i = @i + 1;
END
```

## 🔄 Entity Framework Specific

### **Code First Migrations**
```csharp
// Add migration
public partial class AddUserEmailVerification : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<bool>(
            name: "IsEmailVerified",
            table: "Users",
            type: "bit",
            nullable: false,
            defaultValue: false);

        migrationBuilder.CreateIndex(
            name: "IX_Users_Email",
            table: "Users",
            column: "Email",
            unique: true);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropIndex(
            name: "IX_Users_Email",
            table: "Users");

        migrationBuilder.DropColumn(
            name: "IsEmailVerified",
            table: "Users");
    }
}
```

### **Database Context Configuration**
```csharp
public class AppDbContext : DbContext
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Configure entity relationships
        modelBuilder.Entity<Order>()
            .HasOne(o => o.Customer)
            .WithMany(c => c.Orders)
            .HasForeignKey(o => o.CustomerId)
            .OnDelete(DeleteBehavior.Restrict);

        // Configure indexes
        modelBuilder.Entity<User>()
            .HasIndex(u => u.Email)
            .IsUnique();

        // Configure value conversions
        modelBuilder.Entity<Order>()
            .Property(o => o.Status)
            .HasConversion<string>();
    }
}
```

## 🚨 Database Testing Protocol

### **Pre-Migration Checklist**
- [ ] Full database backup completed
- [ ] Migration tested on development environment
- [ ] All affected queries identified and tested
- [ ] Rollback plan documented and tested
- [ ] Performance impact assessed
- [ ] Monitoring alerts configured

### **Post-Migration Verification**
- [ ] Application starts without errors
- [ ] Critical user flows work correctly
- [ ] Database performance within acceptable ranges
- [ ] No orphaned data or constraint violations
- [ ] Backup and recovery procedures still functional

---

## 📚 Integration Instructions

Add this to your project's CLAUDE.md:

```markdown
# 📚 Database Operations Documentation
This project follows database best practices.
For detailed guidance, see: database-operations.md

# Database Information
- Database Type: SQL Server | PostgreSQL | MySQL | SQLite
- ORM: Entity Framework Core | Dapper | Raw SQL
- Migration Strategy: Code First | Database First

# Additional References
- Universal patterns: universal-patterns.md
- Security guidelines: security-guidelines.md
```

---

*This document covers database operations across all platforms and should be used alongside framework-specific guidance.*