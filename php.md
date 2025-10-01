# PHP Claude Code Guidelines

*Last Updated: 2025-01-16 | Version: 1.0*

## 🏗️ PHP Project Structure

### **Modern PHP Project Layout**
```
myproject/
├── composer.json
├── composer.lock
├── .env
├── .env.example
├── .gitignore
├── README.md
├── public/
│   ├── index.php
│   ├── assets/
│   └── .htaccess
├── src/
│   ├── Controllers/
│   ├── Models/
│   ├── Services/
│   ├── Middleware/
│   ├── Config/
│   └── Utils/
├── templates/
├── storage/
│   ├── logs/
│   ├── cache/
│   └── uploads/
├── tests/
│   ├── Unit/
│   ├── Integration/
│   └── Feature/
├── vendor/ (ignored)
└── docker/
```

### **Laravel Project Structure**
```
laravel-app/
├── app/
│   ├── Http/
│   │   ├── Controllers/
│   │   ├── Middleware/
│   │   └── Requests/
│   ├── Models/
│   ├── Services/
│   └── Providers/
├── database/
│   ├── migrations/
│   ├── seeders/
│   └── factories/
├── resources/
│   ├── views/
│   ├── js/
│   └── css/
├── routes/
├── storage/
├── tests/
└── vendor/
```

## 🔧 Development Commands

### **Composer Package Management**
```bash
# Install dependencies
composer install

# Install for production (no dev dependencies)
composer install --no-dev --optimize-autoloader

# Update dependencies
composer update

# Add new package
composer require package/name

# Add development package
composer require --dev package/name

# Remove package
composer remove package/name

# Generate autoload files
composer dump-autoload

# Validate composer.json
composer validate

# Check for security vulnerabilities
composer audit
```

### **Laravel Artisan Commands**
```bash
# Start development server
php artisan serve
php artisan serve --host=0.0.0.0 --port=8080

# Database operations
php artisan migrate
php artisan migrate:fresh
php artisan migrate:rollback
php artisan migrate:status
php artisan db:seed

# Clear caches
php artisan cache:clear
php artisan config:clear
php artisan route:clear
php artisan view:clear

# Generate application key
php artisan key:generate

# Create resources
php artisan make:controller UserController
php artisan make:model User -m  # with migration
php artisan make:middleware AuthMiddleware
php artisan make:request StoreUserRequest
php artisan make:seeder UserSeeder

# Queue management
php artisan queue:work
php artisan queue:restart
php artisan queue:failed
```

### **Symfony Console Commands**
```bash
# Clear cache
php bin/console cache:clear

# Database operations
php bin/console doctrine:migrations:migrate
php bin/console doctrine:schema:update --force

# Create resources
php bin/console make:controller
php bin/console make:entity
php bin/console make:form

# Debug tools
php bin/console debug:router
php bin/console debug:container
```

## 🚨 PHP Testing Protocol

### **When Server Restart is Required**
- Changes to `.env` files or environment configuration
- Composer dependency changes (`composer.json`)
- PHP configuration changes (`php.ini`)
- Web server configuration changes (`.htaccess`, nginx config)
- Framework configuration cache updates
- New service provider registrations

### **When PHP Auto-reloads (Development)**
- Most PHP file changes (controllers, models, views)
- Template/view modifications
- Route changes (in some frameworks)

### **After the universal 7-step protocol, add these framework-specific steps:**

8. **[ ] Check PHP error logs** - Verify no fatal errors or warnings
9. **[ ] Test autoloader** - Ensure all classes load correctly
10. **[ ] Verify database connections** - Test DB connectivity and migrations
11. **[ ] Check framework cache** - Clear and regenerate caches if needed
12. **[ ] Validate routes** - Ensure all routes respond correctly

## 🛡️ Security Best Practices

### **Input Validation and Sanitization**
```php
<?php

class InputValidator
{
    public static function sanitizeString(string $input): string
    {
        return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
    }

    public static function validateEmail(string $email): bool
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    public static function validateInteger(mixed $value, int $min = null, int $max = null): bool
    {
        $int = filter_var($value, FILTER_VALIDATE_INT);
        if ($int === false) return false;

        if ($min !== null && $int < $min) return false;
        if ($max !== null && $int > $max) return false;

        return true;
    }

    public static function validateUrl(string $url): bool
    {
        return filter_var($url, FILTER_VALIDATE_URL) !== false;
    }
}

// Usage example
$email = $_POST['email'] ?? '';
if (!InputValidator::validateEmail($email)) {
    throw new InvalidArgumentException('Invalid email format');
}
$cleanEmail = InputValidator::sanitizeString($email);
```

### **SQL Injection Prevention**
```php
<?php

// GOOD: Using PDO prepared statements
class UserRepository
{
    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function findById(int $id): ?User
    {
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE id = :id');
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->execute();

        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result ? User::fromArray($result) : null;
    }

    public function create(User $user): bool
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO users (email, password_hash, created_at) VALUES (:email, :password, :created_at)'
        );

        return $stmt->execute([
            ':email' => $user->getEmail(),
            ':password' => $user->getPasswordHash(),
            ':created_at' => date('Y-m-d H:i:s')
        ]);
    }
}

// BAD: String concatenation (vulnerable to SQL injection)
// $query = "SELECT * FROM users WHERE id = " . $_GET['id']; // NEVER DO THIS
```

### **Password Security**
```php
<?php

class PasswordManager
{
    private const MIN_LENGTH = 8;
    private const HASH_COST = 12;

    public static function hash(string $password): string
    {
        if (strlen($password) < self::MIN_LENGTH) {
            throw new InvalidArgumentException('Password too short');
        }

        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536, // 64 MB
            'time_cost' => 4,       // 4 iterations
            'threads' => 3,         // 3 threads
        ]);
    }

    public static function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    public static function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 3,
        ]);
    }

    public static function validateStrength(string $password): array
    {
        $errors = [];

        if (strlen($password) < self::MIN_LENGTH) {
            $errors[] = 'Password must be at least ' . self::MIN_LENGTH . ' characters';
        }

        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Password must contain at least one uppercase letter';
        }

        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = 'Password must contain at least one lowercase letter';
        }

        if (!preg_match('/\d/', $password)) {
            $errors[] = 'Password must contain at least one number';
        }

        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors[] = 'Password must contain at least one special character';
        }

        return $errors;
    }
}
```

### **Session Security**
```php
<?php

class SecureSession
{
    public static function start(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            // Configure secure session settings
            ini_set('session.cookie_httponly', 1);
            ini_set('session.cookie_secure', 1); // HTTPS only
            ini_set('session.cookie_samesite', 'Strict');
            ini_set('session.use_strict_mode', 1);
            ini_set('session.cookie_lifetime', 0); // Session cookie

            session_start();

            // Regenerate session ID periodically
            if (!isset($_SESSION['created'])) {
                session_regenerate_id(true);
                $_SESSION['created'] = time();
            } elseif (time() - $_SESSION['created'] > 300) { // 5 minutes
                session_regenerate_id(true);
                $_SESSION['created'] = time();
            }
        }
    }

    public static function destroy(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION = [];

            if (ini_get('session.use_cookies')) {
                $params = session_get_cookie_params();
                setcookie(session_name(), '', time() - 42000,
                    $params['path'], $params['domain'],
                    $params['secure'], $params['httponly']
                );
            }

            session_destroy();
        }
    }
}
```

## 🗄️ Database Operations

### **PDO Database Class**
```php
<?php

class Database
{
    private static ?PDO $instance = null;
    private string $dsn;
    private string $username;
    private string $password;
    private array $options;

    public function __construct()
    {
        $this->dsn = $_ENV['DB_DSN'] ?? 'mysql:host=localhost;dbname=myapp;charset=utf8mb4';
        $this->username = $_ENV['DB_USERNAME'] ?? 'root';
        $this->password = $_ENV['DB_PASSWORD'] ?? '';

        $this->options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
        ];
    }

    public static function getInstance(): PDO
    {
        if (self::$instance === null) {
            $db = new self();
            self::$instance = new PDO($db->dsn, $db->username, $db->password, $db->options);
        }

        return self::$instance;
    }

    public static function transaction(callable $callback): mixed
    {
        $pdo = self::getInstance();

        try {
            $pdo->beginTransaction();
            $result = $callback($pdo);
            $pdo->commit();
            return $result;
        } catch (Exception $e) {
            $pdo->rollBack();
            throw $e;
        }
    }
}
```

### **Migration System**
```php
<?php

abstract class Migration
{
    protected PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    abstract public function up(): void;
    abstract public function down(): void;

    protected function createTable(string $tableName, array $columns): void
    {
        $columnDefinitions = [];
        foreach ($columns as $name => $definition) {
            $columnDefinitions[] = "`{$name}` {$definition}";
        }

        $sql = "CREATE TABLE `{$tableName}` (" . implode(', ', $columnDefinitions) . ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
        $this->pdo->exec($sql);
    }

    protected function dropTable(string $tableName): void
    {
        $this->pdo->exec("DROP TABLE IF EXISTS `{$tableName}`");
    }
}

class CreateUsersTable extends Migration
{
    public function up(): void
    {
        $this->createTable('users', [
            'id' => 'INT AUTO_INCREMENT PRIMARY KEY',
            'email' => 'VARCHAR(255) NOT NULL UNIQUE',
            'password_hash' => 'VARCHAR(255) NOT NULL',
            'first_name' => 'VARCHAR(100)',
            'last_name' => 'VARCHAR(100)',
            'is_active' => 'BOOLEAN DEFAULT TRUE',
            'created_at' => 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
            'updated_at' => 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP'
        ]);
    }

    public function down(): void
    {
        $this->dropTable('users');
    }
}
```

## 🧪 Testing

### **PHPUnit Testing**
```php
<?php

use PHPUnit\Framework\TestCase;

class UserTest extends TestCase
{
    private PDO $pdo;
    private UserRepository $userRepository;

    protected function setUp(): void
    {
        // Create in-memory SQLite database for testing
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Create tables
        $this->pdo->exec('
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ');

        $this->userRepository = new UserRepository($this->pdo);
    }

    protected function tearDown(): void
    {
        $this->pdo = null;
    }

    public function testUserCreation(): void
    {
        $user = new User([
            'email' => 'test@example.com',
            'password_hash' => password_hash($_ENV['TEST_PASSWORD'] ?? 'password123', PASSWORD_DEFAULT)
        ]);

        $result = $this->userRepository->create($user);

        $this->assertTrue($result);

        $savedUser = $this->userRepository->findByEmail('test@example.com');
        $this->assertNotNull($savedUser);
        $this->assertEquals('test@example.com', $savedUser->getEmail());
    }

    public function testPasswordValidation(): void
    {
        $weakPasswords = ['123', 'password', 'abc'];

        foreach ($weakPasswords as $password) {
            $errors = PasswordManager::validateStrength($password);
            $this->assertNotEmpty($errors, "Password '{$password}' should have validation errors");
        }

        $strongPassword = 'StrongP@ssw0rd123!';
        $errors = PasswordManager::validateStrength($strongPassword);
        $this->assertEmpty($errors, 'Strong password should pass validation');
    }

    public function testEmailValidation(): void
    {
        $validEmails = ['test@example.com', 'user.name+tag@domain.co.uk'];
        $invalidEmails = ['invalid-email', '@domain.com', 'user@'];

        foreach ($validEmails as $email) {
            $this->assertTrue(InputValidator::validateEmail($email));
        }

        foreach ($invalidEmails as $email) {
            $this->assertFalse(InputValidator::validateEmail($email));
        }
    }
}
```

### **Integration Testing**
```php
<?php

class UserControllerTest extends TestCase
{
    private array $server;

    protected function setUp(): void
    {
        // Set up test environment
        $_ENV['DB_DSN'] = 'sqlite::memory:';
        $this->server = $_SERVER;

        // Initialize test database
        $this->initializeTestDatabase();
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->server;
    }

    public function testUserRegistration(): void
    {
        $_POST = [
            'email' => 'newuser@example.com',
            'password' => $_ENV['TEST_PASSWORD'] ?? 'TestPassword123!',
            'first_name' => 'John',
            'last_name' => 'Doe'
        ];
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['REQUEST_URI'] = '/users/register';

        ob_start();
        $controller = new UserController();
        $response = $controller->register();
        $output = ob_get_clean();

        $this->assertEquals(201, http_response_code());
        $this->assertJsonStringEqualsJsonString(
            json_encode(['status' => 'success', 'message' => 'User created successfully']),
            $output
        );
    }

    private function initializeTestDatabase(): void
    {
        $pdo = Database::getInstance();
        $migration = new CreateUsersTable($pdo);
        $migration->up();
    }
}
```

## 🔧 Configuration Management

### **Environment Configuration**
```php
<?php

class Config
{
    private static array $config = [];

    public static function load(string $path = '.env'): void
    {
        if (!file_exists($path)) {
            throw new RuntimeException("Environment file not found: {$path}");
        }

        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        foreach ($lines as $line) {
            if (strpos(trim($line), '#') === 0) {
                continue; // Skip comments
            }

            list($name, $value) = explode('=', $line, 2);
            $name = trim($name);
            $value = trim($value, '"\'');

            $_ENV[$name] = $value;
            self::$config[$name] = $value;
        }
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        return $_ENV[$key] ?? self::$config[$key] ?? $default;
    }

    public static function set(string $key, mixed $value): void
    {
        $_ENV[$key] = $value;
        self::$config[$key] = $value;
    }

    public static function has(string $key): bool
    {
        return isset($_ENV[$key]) || isset(self::$config[$key]);
    }
}

// Load environment variables
Config::load();

// Usage
$dbHost = Config::get('DB_HOST', 'localhost');
$debugMode = Config::get('DEBUG', false);
```

## 🚀 Performance Optimization

### **Caching Implementation**
```php
<?php

interface CacheInterface
{
    public function get(string $key): mixed;
    public function set(string $key, mixed $value, int $ttl = 3600): bool;
    public function delete(string $key): bool;
    public function clear(): bool;
}

class FileCache implements CacheInterface
{
    private string $cacheDir;

    public function __construct(string $cacheDir = 'storage/cache')
    {
        $this->cacheDir = rtrim($cacheDir, '/');
        if (!is_dir($this->cacheDir)) {
            mkdir($this->cacheDir, 0755, true);
        }
    }

    public function get(string $key): mixed
    {
        $filename = $this->getFilename($key);

        if (!file_exists($filename)) {
            return null;
        }

        $data = file_get_contents($filename);
        $cached = unserialize($data);

        if ($cached['expires'] < time()) {
            unlink($filename);
            return null;
        }

        return $cached['value'];
    }

    public function set(string $key, mixed $value, int $ttl = 3600): bool
    {
        $filename = $this->getFilename($key);
        $data = [
            'value' => $value,
            'expires' => time() + $ttl
        ];

        return file_put_contents($filename, serialize($data), LOCK_EX) !== false;
    }

    public function delete(string $key): bool
    {
        $filename = $this->getFilename($key);
        return file_exists($filename) ? unlink($filename) : true;
    }

    public function clear(): bool
    {
        $files = glob($this->cacheDir . '/*.cache');
        foreach ($files as $file) {
            unlink($file);
        }
        return true;
    }

    private function getFilename(string $key): string
    {
        return $this->cacheDir . '/' . md5($key) . '.cache';
    }
}
```

### **Database Query Optimization**
```php
<?php

class QueryBuilder
{
    private string $table;
    private array $select = ['*'];
    private array $where = [];
    private array $joins = [];
    private array $orderBy = [];
    private ?int $limit = null;
    private ?int $offset = null;
    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function table(string $table): self
    {
        $this->table = $table;
        return $this;
    }

    public function select(array $columns): self
    {
        $this->select = $columns;
        return $this;
    }

    public function where(string $column, string $operator, mixed $value): self
    {
        $this->where[] = [$column, $operator, $value];
        return $this;
    }

    public function join(string $table, string $first, string $operator, string $second): self
    {
        $this->joins[] = "JOIN {$table} ON {$first} {$operator} {$second}";
        return $this;
    }

    public function orderBy(string $column, string $direction = 'ASC'): self
    {
        $this->orderBy[] = "{$column} {$direction}";
        return $this;
    }

    public function limit(int $limit, int $offset = 0): self
    {
        $this->limit = $limit;
        $this->offset = $offset;
        return $this;
    }

    public function get(): array
    {
        $sql = $this->buildSelect();
        $stmt = $this->pdo->prepare($sql);

        $params = [];
        foreach ($this->where as $index => $condition) {
            $params["param_{$index}"] = $condition[2];
        }

        $stmt->execute($params);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    private function buildSelect(): string
    {
        $sql = "SELECT " . implode(', ', $this->select) . " FROM {$this->table}";

        if (!empty($this->joins)) {
            $sql .= ' ' . implode(' ', $this->joins);
        }

        if (!empty($this->where)) {
            $conditions = [];
            foreach ($this->where as $index => $condition) {
                $conditions[] = "{$condition[0]} {$condition[1]} :param_{$index}";
            }
            $sql .= ' WHERE ' . implode(' AND ', $conditions);
        }

        if (!empty($this->orderBy)) {
            $sql .= ' ORDER BY ' . implode(', ', $this->orderBy);
        }

        if ($this->limit !== null) {
            $sql .= " LIMIT {$this->limit}";
            if ($this->offset !== null) {
                $sql .= " OFFSET {$this->offset}";
            }
        }

        return $sql;
    }
}
```

## 📦 Dependency Management

### **Composer.json Example**
```json
{
    "name": "mycompany/myproject",
    "description": "A modern PHP application",
    "type": "project",
    "license": "MIT",
    "require": {
        "php": "^8.1",
        "ext-pdo": "*",
        "ext-json": "*",
        "monolog/monolog": "^3.0",
        "vlucas/phpdotenv": "^5.4",
        "guzzlehttp/guzzle": "^7.4"
    },
    "require-dev": {
        "phpunit/phpunit": "^10.0",
        "squizlabs/php_codesniffer": "^3.7",
        "phpstan/phpstan": "^1.9",
        "psalm/plugin-phpunit": "^0.18"
    },
    "autoload": {
        "psr-4": {
            "App\\": "src/"
        },
        "files": [
            "src/helpers.php"
        ]
    },
    "autoload-dev": {
        "psr-4": {
            "Tests\\": "tests/"
        }
    },
    "scripts": {
        "test": "phpunit",
        "test-coverage": "phpunit --coverage-html coverage",
        "cs-check": "phpcs --standard=PSR12 src tests",
        "cs-fix": "phpcbf --standard=PSR12 src tests",
        "analyze": "phpstan analyse src tests --level=8",
        "psalm": "psalm"
    },
    "config": {
        "optimize-autoloader": true,
        "sort-packages": true
    },
    "minimum-stability": "stable",
    "prefer-stable": true
}
```

---

*This document covers PHP development best practices and should be used alongside universal patterns. For consolidated security guidance including environment variables and secrets management, see security-guidelines.md.*