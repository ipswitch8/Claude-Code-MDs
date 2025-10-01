# PostgreSQL Claude Code Guidelines

*Last Updated: 2025-01-16 | Version: 1.0*

## 🗄️ PostgreSQL Database Management

### **PostgreSQL Project Structure**
```
postgres-project/
├── sql/
│   ├── migrations/
│   │   ├── 001_create_schema.sql
│   │   ├── 002_create_tables.sql
│   │   └── 003_add_indexes.sql
│   ├── functions/
│   │   ├── user_functions.sql
│   │   └── audit_functions.sql
│   ├── views/
│   │   ├── user_views.sql
│   │   └── reporting_views.sql
│   ├── procedures/
│   ├── triggers/
│   └── seeds/
│       ├── reference_data.sql
│       └── test_data.sql
├── scripts/
│   ├── backup.sh
│   ├── restore.sh
│   ├── deploy.sh
│   └── maintenance.sh
├── config/
│   ├── postgresql.conf
│   ├── pg_hba.conf
│   └── environment.conf
├── docs/
│   ├── schema_design.md
│   └── performance_tuning.md
└── tests/
    ├── unit_tests.sql
    └── integration_tests.sql
```

## 🔧 PostgreSQL Commands

### **Database Administration**
```bash
# Connect to PostgreSQL
psql -h localhost -U username -d database_name
psql postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}

# Database operations
createdb myapp_development
createdb myapp_test
createdb myapp_production

dropdb myapp_test

# User management
createuser --interactive myapp_user
createuser --pwprompt myapp_user

# Backup and restore
pg_dump myapp_production > backup.sql
pg_dump -Fc myapp_production > backup.dump  # Custom format
pg_dump -t users myapp_production > users_backup.sql  # Single table

pg_restore -d myapp_production backup.dump
psql myapp_production < backup.sql

# Copy database
pg_dump source_db | psql target_db
```

### **PostgreSQL Service Management**
```bash
# SystemD (Linux)
sudo systemctl start postgresql
sudo systemctl stop postgresql
sudo systemctl restart postgresql
sudo systemctl status postgresql
sudo systemctl enable postgresql

# macOS (Homebrew)
brew services start postgresql
brew services stop postgresql
brew services restart postgresql

# Windows
net start postgresql-x64-14
net stop postgresql-x64-14
```

### **Performance and Monitoring**
```bash
# Check PostgreSQL version
psql -c "SELECT version();"

# List databases
psql -l

# List tables in database
psql -d myapp -c "\dt"

# Show database size
psql -d myapp -c "
SELECT
    pg_database.datname,
    pg_size_pretty(pg_database_size(pg_database.datname)) AS size
FROM pg_database
ORDER BY pg_database_size(pg_database.datname) DESC;
"

# Show table sizes
psql -d myapp -c "
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
LIMIT 10;
"
```

## 🚨 PostgreSQL Testing Protocol

### **When Database Restart is Required**
- Configuration file changes (`postgresql.conf`, `pg_hba.conf`)
- Memory allocation changes
- Connection limit modifications
- Extension installations requiring restart
- Major version upgrades

### **When Database Reload is Sufficient**
- User permission changes
- Most configuration parameter changes
- Adding new users or databases
- View and function modifications

### **Testing Protocol Additions**
After the universal 7-step protocol, add these PostgreSQL-specific checks:

8. **[ ] Check PostgreSQL service status** - Verify database is running
9. **[ ] Test database connections** - Confirm applications can connect
10. **[ ] Verify schema integrity** - Check tables, indexes, and constraints
11. **[ ] Run migration status check** - Ensure all migrations are applied
12. **[ ] Test query performance** - Verify no performance degradation
13. **[ ] Validate connection pooling** - Ensure connection limits are not exceeded

## 🏗️ Schema Design Best Practices

### **Table Design Patterns**
```sql
-- Base table with common fields
CREATE TABLE base_entity (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    created_by INTEGER REFERENCES users(id),
    updated_by INTEGER REFERENCES users(id),
    deleted_at TIMESTAMP WITH TIME ZONE,
    version INTEGER DEFAULT 1 NOT NULL
);

-- Users table with proper constraints
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    email_verified_at TIMESTAMP WITH TIME ZONE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,

    -- Constraints
    CONSTRAINT users_email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT users_name_length CHECK (
        char_length(first_name) >= 1 AND
        char_length(last_name) >= 1
    )
);

-- Unique indexes
CREATE UNIQUE INDEX idx_users_email_unique ON users (lower(email)) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_active ON users (is_active, created_at) WHERE is_active = TRUE;
CREATE INDEX idx_users_login ON users (last_login_at) WHERE last_login_at IS NOT NULL;

-- Orders table with foreign keys and check constraints
CREATE TABLE orders (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    order_number VARCHAR(50) NOT NULL,
    status order_status_enum DEFAULT 'pending' NOT NULL,
    total_amount DECIMAL(12,2) NOT NULL,
    currency_code CHAR(3) DEFAULT 'USD' NOT NULL,
    order_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    shipped_date TIMESTAMP WITH TIME ZONE,
    delivered_date TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,

    -- Constraints
    CONSTRAINT orders_total_positive CHECK (total_amount >= 0),
    CONSTRAINT orders_date_logic CHECK (
        shipped_date IS NULL OR shipped_date >= order_date
    ),
    CONSTRAINT orders_delivery_logic CHECK (
        delivered_date IS NULL OR
        (shipped_date IS NOT NULL AND delivered_date >= shipped_date)
    )
);

-- Custom enum types
CREATE TYPE order_status_enum AS ENUM (
    'pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'
);
```

### **Advanced PostgreSQL Features**
```sql
-- JSONB for flexible data
CREATE TABLE user_preferences (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    preferences JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- GIN index for JSONB queries
CREATE INDEX idx_user_preferences_jsonb ON user_preferences USING GIN (preferences);

-- Query JSONB data
-- Find users with email notifications enabled
SELECT u.*, up.preferences
FROM users u
JOIN user_preferences up ON u.id = up.user_id
WHERE up.preferences->>'email_notifications' = 'true';

-- Array fields
CREATE TABLE tags (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    color VARCHAR(7) -- Hex color code
);

CREATE TABLE posts (
    id BIGSERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    content TEXT,
    tag_ids INTEGER[] DEFAULT '{}',
    published_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Index for array queries
CREATE INDEX idx_posts_tag_ids ON posts USING GIN (tag_ids);

-- Query posts with specific tags
SELECT * FROM posts WHERE tag_ids @> ARRAY[1, 3];

-- Full-text search
ALTER TABLE posts ADD COLUMN search_vector tsvector;

-- Update search vector
UPDATE posts SET search_vector =
    to_tsvector('english', coalesce(title, '') || ' ' || coalesce(content, ''));

-- Create index for full-text search
CREATE INDEX idx_posts_search ON posts USING GIN (search_vector);

-- Search posts
SELECT * FROM posts
WHERE search_vector @@ plainto_tsquery('english', 'database optimization');
```

## 🔧 Functions and Procedures

### **Stored Functions**
```sql
-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to all tables with updated_at
CREATE TRIGGER set_timestamp_users
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION trigger_set_timestamp();

-- User authentication function
CREATE OR REPLACE FUNCTION authenticate_user(
    p_email VARCHAR(255),
    p_password VARCHAR(255)
)
RETURNS TABLE (
    user_id BIGINT,
    email VARCHAR(255),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    is_active BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        u.id,
        u.email,
        u.first_name,
        u.last_name,
        u.is_active
    FROM users u
    WHERE
        lower(u.email) = lower(p_email)
        AND u.password_hash = crypt(p_password, u.password_hash)
        AND u.is_active = TRUE
        AND u.deleted_at IS NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function with error handling
CREATE OR REPLACE FUNCTION create_user_with_profile(
    p_email VARCHAR(255),
    p_password VARCHAR(255),
    p_first_name VARCHAR(100),
    p_last_name VARCHAR(100)
)
RETURNS BIGINT AS $$
DECLARE
    v_user_id BIGINT;
    v_password_hash VARCHAR(255);
BEGIN
    -- Hash password
    v_password_hash := crypt(p_password, gen_salt('bf', 12));

    -- Create user
    INSERT INTO users (email, password_hash, first_name, last_name)
    VALUES (lower(p_email), v_password_hash, p_first_name, p_last_name)
    RETURNING id INTO v_user_id;

    -- Create user profile
    INSERT INTO user_profiles (user_id)
    VALUES (v_user_id);

    RETURN v_user_id;

EXCEPTION
    WHEN unique_violation THEN
        RAISE EXCEPTION 'Email already exists: %', p_email;
    WHEN OTHERS THEN
        RAISE EXCEPTION 'Error creating user: %', SQLERRM;
END;
$$ LANGUAGE plpgsql;
```

### **Audit and History Tracking**
```sql
-- Audit table structure
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    record_id BIGINT NOT NULL,
    operation CHAR(1) NOT NULL CHECK (operation IN ('I', 'U', 'D')),
    old_values JSONB,
    new_values JSONB,
    changed_by BIGINT REFERENCES users(id),
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Generic audit trigger function
CREATE OR REPLACE FUNCTION audit_trigger_function()
RETURNS TRIGGER AS $$
DECLARE
    v_old_data JSONB;
    v_new_data JSONB;
    v_user_id BIGINT;
BEGIN
    -- Get current user (assuming it's set in session)
    v_user_id := current_setting('app.current_user_id', true)::BIGINT;

    IF TG_OP = 'DELETE' THEN
        v_old_data := to_jsonb(OLD);
        v_new_data := NULL;

        INSERT INTO audit_log (table_name, record_id, operation, old_values, new_values, changed_by)
        VALUES (TG_TABLE_NAME, OLD.id, 'D', v_old_data, v_new_data, v_user_id);

        RETURN OLD;
    ELSIF TG_OP = 'UPDATE' THEN
        v_old_data := to_jsonb(OLD);
        v_new_data := to_jsonb(NEW);

        INSERT INTO audit_log (table_name, record_id, operation, old_values, new_values, changed_by)
        VALUES (TG_TABLE_NAME, NEW.id, 'U', v_old_data, v_new_data, v_user_id);

        RETURN NEW;
    ELSIF TG_OP = 'INSERT' THEN
        v_old_data := NULL;
        v_new_data := to_jsonb(NEW);

        INSERT INTO audit_log (table_name, record_id, operation, old_values, new_values, changed_by)
        VALUES (TG_TABLE_NAME, NEW.id, 'I', v_old_data, v_new_data, v_user_id);

        RETURN NEW;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Apply audit trigger to tables
CREATE TRIGGER users_audit_trigger
    AFTER INSERT OR UPDATE OR DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();
```

## 📊 Performance Optimization

### **Query Optimization**
```sql
-- Analyze query performance
EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT u.email, COUNT(o.id) as order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
WHERE u.created_at >= '2024-01-01'
GROUP BY u.id, u.email
ORDER BY order_count DESC
LIMIT 100;

-- Index optimization
-- Composite index for common query patterns
CREATE INDEX idx_orders_user_date ON orders (user_id, order_date DESC);
CREATE INDEX idx_orders_status_date ON orders (status, order_date) WHERE status != 'cancelled';

-- Partial indexes for specific conditions
CREATE INDEX idx_users_active_recent ON users (created_at)
WHERE is_active = TRUE AND created_at >= '2024-01-01';

-- Index for sorting and filtering
CREATE INDEX idx_orders_complex ON orders (user_id, status, order_date DESC)
WHERE status IN ('confirmed', 'shipped', 'delivered');

-- Materialized views for expensive aggregations
CREATE MATERIALIZED VIEW user_order_summary AS
SELECT
    u.id as user_id,
    u.email,
    COUNT(o.id) as total_orders,
    COALESCE(SUM(o.total_amount), 0) as total_spent,
    MAX(o.order_date) as last_order_date,
    AVG(o.total_amount) as avg_order_value
FROM users u
LEFT JOIN orders o ON u.id = o.user_id AND o.status != 'cancelled'
GROUP BY u.id, u.email;

-- Index on materialized view
CREATE INDEX idx_user_order_summary_spent ON user_order_summary (total_spent DESC);

-- Refresh materialized view
REFRESH MATERIALIZED VIEW user_order_summary;

-- Automatic refresh with function
CREATE OR REPLACE FUNCTION refresh_user_order_summary()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY user_order_summary;
END;
$$ LANGUAGE plpgsql;
```

### **Connection and Resource Management**
```sql
-- Monitor active connections
SELECT
    datname,
    usename,
    client_addr,
    state,
    query_start,
    state_change,
    query
FROM pg_stat_activity
WHERE state = 'active'
ORDER BY query_start;

-- Monitor database statistics
SELECT
    schemaname,
    tablename,
    n_tup_ins as inserts,
    n_tup_upd as updates,
    n_tup_del as deletes,
    n_live_tup as live_rows,
    n_dead_tup as dead_rows,
    last_vacuum,
    last_autovacuum,
    last_analyze,
    last_autoanalyze
FROM pg_stat_user_tables
ORDER BY n_live_tup DESC;

-- Check index usage
SELECT
    schemaname,
    tablename,
    indexname,
    idx_tup_read,
    idx_tup_fetch,
    idx_scan
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;
```

## 🔒 Security and Access Control

### **User and Role Management**
```sql
-- Create roles
CREATE ROLE app_readonly;
CREATE ROLE app_readwrite;
CREATE ROLE app_admin;

-- Grant permissions to roles
GRANT CONNECT ON DATABASE myapp TO app_readonly;
GRANT USAGE ON SCHEMA public TO app_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_readonly;

GRANT app_readonly TO app_readwrite;
GRANT INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_readwrite;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_readwrite;

GRANT app_readwrite TO app_admin;
GRANT CREATE ON SCHEMA public TO app_admin;

-- Create application users
-- SECURITY: Use environment variables for passwords, never hardcode
CREATE USER app_read_user WITH PASSWORD :'DB_READ_PASSWORD';
CREATE USER app_write_user WITH PASSWORD :'DB_WRITE_PASSWORD';
CREATE USER app_admin_user WITH PASSWORD :'DB_ADMIN_PASSWORD';

-- Assign roles
GRANT app_readonly TO app_read_user;
GRANT app_readwrite TO app_write_user;
GRANT app_admin TO app_admin_user;

-- Row Level Security (RLS)
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;

-- Policy for users to see only their own orders
CREATE POLICY user_orders_policy ON orders
    FOR ALL TO app_readwrite
    USING (user_id = current_setting('app.current_user_id')::BIGINT);

-- Policy for admins to see all orders
CREATE POLICY admin_orders_policy ON orders
    FOR ALL TO app_admin
    USING (true);
```

### **Data Protection and Encryption**
```sql
-- Install pgcrypto extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Encrypt sensitive data
CREATE TABLE sensitive_data (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    encrypted_ssn BYTEA,
    encrypted_credit_card BYTEA,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Functions for encryption/decryption
CREATE OR REPLACE FUNCTION encrypt_data(data TEXT, key TEXT)
RETURNS BYTEA AS $$
BEGIN
    RETURN pgp_sym_encrypt(data, key);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION decrypt_data(encrypted_data BYTEA, key TEXT)
RETURNS TEXT AS $$
BEGIN
    RETURN pgp_sym_decrypt(encrypted_data, key);
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Mask sensitive data in views
CREATE VIEW users_safe AS
SELECT
    id,
    first_name,
    last_name,
    CASE
        WHEN current_user = 'app_admin_user' THEN email
        ELSE regexp_replace(email, '(.{2}).*@', '\1***@')
    END as email,
    is_active,
    created_at
FROM users;
```

## 🔄 Backup and Maintenance

### **Backup Strategies**
```bash
#!/bin/bash
# backup_postgres.sh

DB_NAME="myapp_production"
BACKUP_DIR="/var/backups/postgresql"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Full database backup
pg_dump -Fc "$DB_NAME" > "$BACKUP_DIR/${DB_NAME}_full_${DATE}.dump"

# Schema-only backup
pg_dump -s "$DB_NAME" > "$BACKUP_DIR/${DB_NAME}_schema_${DATE}.sql"

# Data-only backup
pg_dump -a "$DB_NAME" > "$BACKUP_DIR/${DB_NAME}_data_${DATE}.sql"

# Compress and upload to cloud storage (example)
gzip "$BACKUP_DIR/${DB_NAME}_full_${DATE}.dump"
aws s3 cp "$BACKUP_DIR/${DB_NAME}_full_${DATE}.dump.gz" \
    "s3://my-backups/postgresql/${DB_NAME}/"

# Clean up old backups
find "$BACKUP_DIR" -name "${DB_NAME}_*" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: ${DB_NAME}_full_${DATE}.dump"
```

### **Maintenance Tasks**
```sql
-- Manual vacuum and analyze
VACUUM ANALYZE users;
VACUUM FULL orders;  -- Use carefully, locks table

-- Reindex for performance
REINDEX INDEX idx_users_email_unique;
REINDEX TABLE users;

-- Update table statistics
ANALYZE users;
ANALYZE orders;

-- Check for bloat
SELECT
    schemaname,
    tablename,
    n_dead_tup,
    n_live_tup,
    ROUND((n_dead_tup::numeric / NULLIF(n_live_tup + n_dead_tup, 0)) * 100, 2) as bloat_percentage
FROM pg_stat_user_tables
WHERE n_dead_tup > 1000
ORDER BY bloat_percentage DESC;
```

## 🧪 Testing and Migration

### **Migration Scripts**
```sql
-- Migration: 001_create_initial_schema.sql
BEGIN;

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create custom types
CREATE TYPE user_status AS ENUM ('active', 'inactive', 'suspended');

-- Create tables
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    status user_status DEFAULT 'active' NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Create indexes
CREATE UNIQUE INDEX idx_users_email ON users (lower(email));

-- Insert reference data
INSERT INTO reference_tables (name, value) VALUES
    ('system_version', '1.0.0'),
    ('migration_version', '001');

COMMIT;
```

### **Test Data and Verification**
```sql
-- test_data.sql
-- Create test users
-- SECURITY: Use environment variables for passwords in production
INSERT INTO users (email, password_hash, first_name, last_name) VALUES
    ('test1@example.com', crypt(:'TEST_USER_PASSWORD', gen_salt('bf')), 'Test', 'User1'),
    ('test2@example.com', crypt(:'TEST_USER_PASSWORD', gen_salt('bf')), 'Test', 'User2'),
    ('admin@example.com', crypt(:'TEST_ADMIN_PASSWORD', gen_salt('bf')), 'Admin', 'User');

-- Create test orders
INSERT INTO orders (user_id, order_number, total_amount, status)
SELECT
    u.id,
    'ORD-' || lpad((row_number() OVER())::text, 6, '0'),
    (random() * 1000 + 10)::decimal(10,2),
    (ARRAY['pending', 'confirmed', 'shipped', 'delivered'])[floor(random() * 4 + 1)]
FROM users u
CROSS JOIN generate_series(1, 10);

-- Verification queries
SELECT 'Users created: ' || count(*) FROM users;
SELECT 'Orders created: ' || count(*) FROM orders;
SELECT 'Email uniqueness check: ' ||
       CASE WHEN count(*) = count(DISTINCT email) THEN 'PASS' ELSE 'FAIL' END
FROM users;
```

---

*This document covers PostgreSQL best practices and should be used alongside universal patterns. For consolidated security guidance including environment variables and secrets management, see security-guidelines.md.*