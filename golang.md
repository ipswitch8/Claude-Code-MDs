# Go (Golang) Claude Code Guidelines

*Last Updated: 2025-01-16 | Version: 1.0*

## 🏗️ Go Project Structure

### **Standard Go Project Layout**
```
go-project/
├── cmd/
│   ├── api/
│   │   └── main.go
│   ├── worker/
│   │   └── main.go
│   └── cli/
│       └── main.go
├── internal/
│   ├── config/
│   ├── handler/
│   ├── service/
│   ├── repository/
│   ├── model/
│   └── middleware/
├── pkg/
│   ├── auth/
│   ├── logger/
│   └── database/
├── api/
│   └── openapi.yaml
├── web/
│   ├── static/
│   └── templates/
├── scripts/
├── deployments/
├── docs/
├── test/
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
└── README.md
```

### **Simple Go Application Structure**
```
simple-go-app/
├── main.go
├── handlers/
│   ├── user.go
│   └── order.go
├── models/
│   ├── user.go
│   └── order.go
├── database/
│   └── connection.go
├── middleware/
│   └── auth.go
├── config/
│   └── config.go
├── go.mod
├── go.sum
└── README.md
```

## 🔧 Development Commands

### **Go Module Management**
```bash
# Initialize new module
go mod init example.com/myproject

# Download dependencies
go mod download

# Add dependency
go get github.com/gin-gonic/gin
go get -u github.com/gin-gonic/gin  # Update to latest

# Remove unused dependencies
go mod tidy

# Verify dependencies
go mod verify

# Show dependency graph
go mod graph

# Show why dependency is needed
go mod why github.com/gin-gonic/gin

# Create vendor directory
go mod vendor
```

### **Build and Run Commands**
```bash
# Run application
go run main.go
go run cmd/api/main.go

# Build application
go build
go build -o myapp
go build cmd/api/main.go

# Cross-compilation
GOOS=linux GOARCH=amd64 go build -o myapp-linux
GOOS=windows GOARCH=amd64 go build -o myapp.exe

# Install binary to $GOPATH/bin
go install

# Clean build cache
go clean
go clean -cache
```

### **Testing Commands**
```bash
# Run tests
go test
go test ./...
go test -v ./...

# Run tests with coverage
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run benchmarks
go test -bench=.
go test -bench=BenchmarkFunction

# Race condition detection
go test -race ./...

# Run specific test
go test -run TestUserCreate
go test -run TestUser ./handlers
```

### **Code Quality Tools**
```bash
# Format code
go fmt ./...
gofmt -w .

# Import organization
goimports -w .

# Linting
golint ./...
golangci-lint run

# Vet (static analysis)
go vet ./...

# Generate code
go generate ./...
```

## 🚨 Go Testing Protocol

### **When Binary Rebuild is Required**
- Code changes to any `.go` files
- Changes to `go.mod` or `go.sum`
- Addition or removal of dependencies
- Changes to build tags or compiler directives
- Configuration changes that affect compilation

### **When Service Restart is Required**
- Configuration file changes
- Environment variable modifications
- Database connection changes
- Port or network configuration updates

### **Testing Protocol Additions**
After the universal 7-step protocol, add these framework-specific steps:

8. **[ ] Run go fmt and goimports** - Ensure code formatting is correct
9. **[ ] Run go vet** - Check for static analysis issues
10. **[ ] Run tests with race detection** - Execute `go test -race ./...`
11. **[ ] Check module dependencies** - Run `go mod tidy` and verify
12. **[ ] Verify binary builds correctly** - Test cross-compilation if needed

## 💻 Go Best Practices

### **Code Structure and Organization**
```go
// Package documentation
// Package user provides user management functionality
package user

import (
    "context"
    "database/sql"
    "fmt"
    "log"
    "time"

    "github.com/google/uuid"
    _ "github.com/lib/pq" // PostgreSQL driver
)

// User represents a user in the system
type User struct {
    ID        uuid.UUID  `json:"id" db:"id"`
    Email     string     `json:"email" db:"email"`
    FirstName string     `json:"first_name" db:"first_name"`
    LastName  string     `json:"last_name" db:"last_name"`
    IsActive  bool       `json:"is_active" db:"is_active"`
    CreatedAt time.Time  `json:"created_at" db:"created_at"`
    UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
}

// Repository defines the interface for user data operations
type Repository interface {
    Create(ctx context.Context, user *User) error
    GetByID(ctx context.Context, id uuid.UUID) (*User, error)
    GetByEmail(ctx context.Context, email string) (*User, error)
    Update(ctx context.Context, user *User) error
    Delete(ctx context.Context, id uuid.UUID) error
    List(ctx context.Context, limit, offset int) ([]*User, error)
}

// Service defines the interface for user business logic
type Service interface {
    CreateUser(ctx context.Context, email, firstName, lastName string) (*User, error)
    AuthenticateUser(ctx context.Context, email, password string) (*User, error)
    UpdateUser(ctx context.Context, id uuid.UUID, updates map[string]interface{}) (*User, error)
    DeactivateUser(ctx context.Context, id uuid.UUID) error
}

// PostgreSQLRepository implements Repository interface
type PostgreSQLRepository struct {
    db *sql.DB
}

// NewPostgreSQLRepository creates a new PostgreSQL repository
func NewPostgreSQLRepository(db *sql.DB) *PostgreSQLRepository {
    return &PostgreSQLRepository{db: db}
}

// Create inserts a new user into the database
func (r *PostgreSQLRepository) Create(ctx context.Context, user *User) error {
    query := `
        INSERT INTO users (id, email, first_name, last_name, is_active, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)`

    user.ID = uuid.New()
    user.CreatedAt = time.Now()
    user.UpdatedAt = time.Now()

    _, err := r.db.ExecContext(ctx, query,
        user.ID, user.Email, user.FirstName, user.LastName,
        user.IsActive, user.CreatedAt, user.UpdatedAt,
    )
    if err != nil {
        return fmt.Errorf("failed to create user: %w", err)
    }

    return nil
}

// GetByID retrieves a user by ID
func (r *PostgreSQLRepository) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
    query := `
        SELECT id, email, first_name, last_name, is_active, created_at, updated_at
        FROM users WHERE id = $1`

    user := &User{}
    err := r.db.QueryRowContext(ctx, query, id).Scan(
        &user.ID, &user.Email, &user.FirstName, &user.LastName,
        &user.IsActive, &user.CreatedAt, &user.UpdatedAt,
    )
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("user not found: %s", id)
        }
        return nil, fmt.Errorf("failed to get user: %w", err)
    }

    return user, nil
}

// UserService implements Service interface
type UserService struct {
    repo Repository
}

// NewUserService creates a new user service
func NewUserService(repo Repository) *UserService {
    return &UserService{repo: repo}
}

// CreateUser creates a new user with validation
func (s *UserService) CreateUser(ctx context.Context, email, firstName, lastName string) (*User, error) {
    // Validation
    if email == "" {
        return nil, fmt.Errorf("email is required")
    }
    if firstName == "" {
        return nil, fmt.Errorf("first name is required")
    }
    if lastName == "" {
        return nil, fmt.Errorf("last name is required")
    }

    // Check if user already exists
    existingUser, err := s.repo.GetByEmail(ctx, email)
    if err == nil && existingUser != nil {
        return nil, fmt.Errorf("user with email %s already exists", email)
    }

    user := &User{
        Email:     email,
        FirstName: firstName,
        LastName:  lastName,
        IsActive:  true,
    }

    if err := s.repo.Create(ctx, user); err != nil {
        return nil, fmt.Errorf("failed to create user: %w", err)
    }

    return user, nil
}
```

### **Error Handling**
```go
package errors

import (
    "errors"
    "fmt"
)

// Custom error types
var (
    ErrNotFound      = errors.New("resource not found")
    ErrUnauthorized  = errors.New("unauthorized access")
    ErrInvalidInput  = errors.New("invalid input")
    ErrInternalError = errors.New("internal server error")
)

// AppError represents an application error with context
type AppError struct {
    Code    string `json:"code"`
    Message string `json:"message"`
    Err     error  `json:"-"`
}

func (e *AppError) Error() string {
    if e.Err != nil {
        return fmt.Sprintf("%s: %v", e.Message, e.Err)
    }
    return e.Message
}

func (e *AppError) Unwrap() error {
    return e.Err
}

// Error constructors
func NewNotFoundError(message string) *AppError {
    return &AppError{
        Code:    "NOT_FOUND",
        Message: message,
        Err:     ErrNotFound,
    }
}

func NewValidationError(message string, err error) *AppError {
    return &AppError{
        Code:    "VALIDATION_ERROR",
        Message: message,
        Err:     err,
    }
}

func NewInternalError(message string, err error) *AppError {
    return &AppError{
        Code:    "INTERNAL_ERROR",
        Message: message,
        Err:     err,
    }
}

// Error handling in service
func (s *UserService) GetUser(ctx context.Context, id uuid.UUID) (*User, error) {
    user, err := s.repo.GetByID(ctx, id)
    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            return nil, NewNotFoundError(fmt.Sprintf("user with ID %s not found", id))
        }
        return nil, NewInternalError("failed to retrieve user", err)
    }
    return user, nil
}
```

### **HTTP Handlers with Gin**
```go
package handler

import (
    "net/http"
    "strconv"

    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
    "myapp/internal/service"
    "myapp/pkg/errors"
)

// UserHandler handles HTTP requests for users
type UserHandler struct {
    userService service.UserService
}

// NewUserHandler creates a new user handler
func NewUserHandler(userService service.UserService) *UserHandler {
    return &UserHandler{userService: userService}
}

// CreateUserRequest represents the request for creating a user
type CreateUserRequest struct {
    Email     string `json:"email" binding:"required,email"`
    FirstName string `json:"first_name" binding:"required,min=1,max=50"`
    LastName  string `json:"last_name" binding:"required,min=1,max=50"`
}

// UserResponse represents the response for user operations
type UserResponse struct {
    ID        uuid.UUID `json:"id"`
    Email     string    `json:"email"`
    FirstName string    `json:"first_name"`
    LastName  string    `json:"last_name"`
    IsActive  bool      `json:"is_active"`
    CreatedAt string    `json:"created_at"`
}

// CreateUser handles POST /users
func (h *UserHandler) CreateUser(c *gin.Context) {
    var req CreateUserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Invalid input",
            "details": err.Error(),
        })
        return
    }

    user, err := h.userService.CreateUser(c.Request.Context(), req.Email, req.FirstName, req.LastName)
    if err != nil {
        handleError(c, err)
        return
    }

    response := UserResponse{
        ID:        user.ID,
        Email:     user.Email,
        FirstName: user.FirstName,
        LastName:  user.LastName,
        IsActive:  user.IsActive,
        CreatedAt: user.CreatedAt.Format("2006-01-02T15:04:05Z"),
    }

    c.JSON(http.StatusCreated, response)
}

// GetUser handles GET /users/:id
func (h *UserHandler) GetUser(c *gin.Context) {
    idStr := c.Param("id")
    id, err := uuid.Parse(idStr)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Invalid user ID format",
        })
        return
    }

    user, err := h.userService.GetUser(c.Request.Context(), id)
    if err != nil {
        handleError(c, err)
        return
    }

    response := UserResponse{
        ID:        user.ID,
        Email:     user.Email,
        FirstName: user.FirstName,
        LastName:  user.LastName,
        IsActive:  user.IsActive,
        CreatedAt: user.CreatedAt.Format("2006-01-02T15:04:05Z"),
    }

    c.JSON(http.StatusOK, response)
}

// ListUsers handles GET /users
func (h *UserHandler) ListUsers(c *gin.Context) {
    limitStr := c.DefaultQuery("limit", "10")
    offsetStr := c.DefaultQuery("offset", "0")

    limit, err := strconv.Atoi(limitStr)
    if err != nil || limit < 1 || limit > 100 {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Invalid limit parameter (1-100)",
        })
        return
    }

    offset, err := strconv.Atoi(offsetStr)
    if err != nil || offset < 0 {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Invalid offset parameter",
        })
        return
    }

    users, err := h.userService.ListUsers(c.Request.Context(), limit, offset)
    if err != nil {
        handleError(c, err)
        return
    }

    var responses []UserResponse
    for _, user := range users {
        responses = append(responses, UserResponse{
            ID:        user.ID,
            Email:     user.Email,
            FirstName: user.FirstName,
            LastName:  user.LastName,
            IsActive:  user.IsActive,
            CreatedAt: user.CreatedAt.Format("2006-01-02T15:04:05Z"),
        })
    }

    c.JSON(http.StatusOK, gin.H{
        "users": responses,
        "pagination": gin.H{
            "limit":  limit,
            "offset": offset,
            "count":  len(responses),
        },
    })
}

// handleError converts service errors to HTTP responses
func handleError(c *gin.Context, err error) {
    var appErr *errors.AppError
    if errors.As(err, &appErr) {
        switch appErr.Code {
        case "NOT_FOUND":
            c.JSON(http.StatusNotFound, gin.H{"error": appErr.Message})
        case "VALIDATION_ERROR":
            c.JSON(http.StatusBadRequest, gin.H{"error": appErr.Message})
        case "UNAUTHORIZED":
            c.JSON(http.StatusUnauthorized, gin.H{"error": appErr.Message})
        default:
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
        }
    } else {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
    }
}

// RegisterRoutes registers all user routes
func (h *UserHandler) RegisterRoutes(r *gin.Engine) {
    userGroup := r.Group("/users")
    {
        userGroup.POST("", h.CreateUser)
        userGroup.GET("/:id", h.GetUser)
        userGroup.GET("", h.ListUsers)
    }
}
```

## 🧪 Testing in Go

### **Unit Testing**
```go
// user_test.go
package user

import (
    "context"
    "testing"
    "time"

    "github.com/google/uuid"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
)

// MockRepository is a mock implementation of Repository
type MockRepository struct {
    mock.Mock
}

func (m *MockRepository) Create(ctx context.Context, user *User) error {
    args := m.Called(ctx, user)
    return args.Error(0)
}

func (m *MockRepository) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
    args := m.Called(ctx, id)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*User), args.Error(1)
}

func (m *MockRepository) GetByEmail(ctx context.Context, email string) (*User, error) {
    args := m.Called(ctx, email)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*User), args.Error(1)
}

func TestUserService_CreateUser(t *testing.T) {
    mockRepo := new(MockRepository)
    service := NewUserService(mockRepo)

    ctx := context.Background()
    email := "test@example.com"
    firstName := "John"
    lastName := "Doe"

    t.Run("successful user creation", func(t *testing.T) {
        // Setup mock expectations
        mockRepo.On("GetByEmail", ctx, email).Return(nil, errors.New("not found"))
        mockRepo.On("Create", ctx, mock.AnythingOfType("*user.User")).Return(nil)

        // Execute
        user, err := service.CreateUser(ctx, email, firstName, lastName)

        // Assert
        assert.NoError(t, err)
        assert.NotNil(t, user)
        assert.Equal(t, email, user.Email)
        assert.Equal(t, firstName, user.FirstName)
        assert.Equal(t, lastName, user.LastName)
        assert.True(t, user.IsActive)

        // Verify mock expectations
        mockRepo.AssertExpectations(t)
    })

    t.Run("user already exists", func(t *testing.T) {
        existingUser := &User{
            ID:    uuid.New(),
            Email: email,
        }

        mockRepo.On("GetByEmail", ctx, email).Return(existingUser, nil)

        // Execute
        user, err := service.CreateUser(ctx, email, firstName, lastName)

        // Assert
        assert.Error(t, err)
        assert.Nil(t, user)
        assert.Contains(t, err.Error(), "already exists")

        mockRepo.AssertExpectations(t)
    })

    t.Run("missing required fields", func(t *testing.T) {
        testCases := []struct {
            name      string
            email     string
            firstName string
            lastName  string
        }{
            {"empty email", "", firstName, lastName},
            {"empty first name", email, "", lastName},
            {"empty last name", email, firstName, ""},
        }

        for _, tc := range testCases {
            t.Run(tc.name, func(t *testing.T) {
                user, err := service.CreateUser(ctx, tc.email, tc.firstName, tc.lastName)
                assert.Error(t, err)
                assert.Nil(t, user)
            })
        }
    })
}

func TestUserService_GetUser(t *testing.T) {
    mockRepo := new(MockRepository)
    service := NewUserService(mockRepo)

    ctx := context.Background()
    userID := uuid.New()

    t.Run("user found", func(t *testing.T) {
        expectedUser := &User{
            ID:        userID,
            Email:     "test@example.com",
            FirstName: "John",
            LastName:  "Doe",
            IsActive:  true,
            CreatedAt: time.Now(),
        }

        mockRepo.On("GetByID", ctx, userID).Return(expectedUser, nil)

        user, err := service.GetUser(ctx, userID)

        assert.NoError(t, err)
        assert.Equal(t, expectedUser, user)
        mockRepo.AssertExpectations(t)
    })

    t.Run("user not found", func(t *testing.T) {
        mockRepo.On("GetByID", ctx, userID).Return(nil, sql.ErrNoRows)

        user, err := service.GetUser(ctx, userID)

        assert.Error(t, err)
        assert.Nil(t, user)
        assert.Contains(t, err.Error(), "not found")
        mockRepo.AssertExpectations(t)
    })
}
```

### **Integration Testing**
```go
// integration_test.go
package handler

import (
    "bytes"
    "database/sql"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/gin-gonic/gin"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/suite"
    _ "github.com/lib/pq"

    "myapp/internal/repository"
    "myapp/internal/service"
)

type UserHandlerTestSuite struct {
    suite.Suite
    db      *sql.DB
    router  *gin.Engine
    handler *UserHandler
}

func (suite *UserHandlerTestSuite) SetupSuite() {
    // Setup test database
    // Use environment variables even in tests for security
    dbURL := os.Getenv("TEST_DATABASE_URL")
    if dbURL == "" {
        dbURL = os.Getenv("TEST_DATABASE_URL") // fallback for local dev
    }
    db, err := sql.Open("postgres", dbURL)
    suite.Require().NoError(err)
    suite.db = db

    // Setup dependencies
    repo := repository.NewPostgreSQLRepository(db)
    userService := service.NewUserService(repo)
    suite.handler = NewUserHandler(userService)

    // Setup router
    gin.SetMode(gin.TestMode)
    suite.router = gin.New()
    suite.handler.RegisterRoutes(suite.router)
}

func (suite *UserHandlerTestSuite) TearDownSuite() {
    suite.db.Close()
}

func (suite *UserHandlerTestSuite) SetupTest() {
    // Clean database before each test
    _, err := suite.db.Exec("DELETE FROM users")
    suite.Require().NoError(err)
}

func (suite *UserHandlerTestSuite) TestCreateUser() {
    requestBody := CreateUserRequest{
        Email:     "test@example.com",
        FirstName: "John",
        LastName:  "Doe",
    }

    jsonBody, err := json.Marshal(requestBody)
    suite.Require().NoError(err)

    req, err := http.NewRequest("POST", "/users", bytes.NewBuffer(jsonBody))
    suite.Require().NoError(err)
    req.Header.Set("Content-Type", "application/json")

    w := httptest.NewRecorder()
    suite.router.ServeHTTP(w, req)

    assert.Equal(suite.T(), http.StatusCreated, w.Code)

    var response UserResponse
    err = json.Unmarshal(w.Body.Bytes(), &response)
    suite.Require().NoError(err)

    assert.Equal(suite.T(), requestBody.Email, response.Email)
    assert.Equal(suite.T(), requestBody.FirstName, response.FirstName)
    assert.Equal(suite.T(), requestBody.LastName, response.LastName)
    assert.True(suite.T(), response.IsActive)
    assert.NotEmpty(suite.T(), response.ID)
}

func (suite *UserHandlerTestSuite) TestCreateUser_ValidationError() {
    requestBody := CreateUserRequest{
        Email:     "invalid-email",
        FirstName: "",
        LastName:  "Doe",
    }

    jsonBody, err := json.Marshal(requestBody)
    suite.Require().NoError(err)

    req, err := http.NewRequest("POST", "/users", bytes.NewBuffer(jsonBody))
    suite.Require().NoError(err)
    req.Header.Set("Content-Type", "application/json")

    w := httptest.NewRecorder()
    suite.router.ServeHTTP(w, req)

    assert.Equal(suite.T(), http.StatusBadRequest, w.Code)
}

func TestUserHandlerTestSuite(t *testing.T) {
    suite.Run(t, new(UserHandlerTestSuite))
}
```

### **Benchmark Testing**
```go
// benchmark_test.go
package user

import (
    "context"
    "testing"

    "github.com/google/uuid"
)

func BenchmarkUserService_CreateUser(b *testing.B) {
    // Setup
    mockRepo := new(MockRepository)
    service := NewUserService(mockRepo)
    ctx := context.Background()

    mockRepo.On("GetByEmail", ctx, mock.AnythingOfType("string")).Return(nil, errors.New("not found"))
    mockRepo.On("Create", ctx, mock.AnythingOfType("*user.User")).Return(nil)

    b.ResetTimer()

    for i := 0; i < b.N; i++ {
        email := fmt.Sprintf("user%d@example.com", i)
        _, err := service.CreateUser(ctx, email, "John", "Doe")
        if err != nil {
            b.Fatal(err)
        }
    }
}

func BenchmarkUserService_GetUser(b *testing.B) {
    mockRepo := new(MockRepository)
    service := NewUserService(mockRepo)
    ctx := context.Background()
    userID := uuid.New()

    user := &User{
        ID:        userID,
        Email:     "test@example.com",
        FirstName: "John",
        LastName:  "Doe",
        IsActive:  true,
    }

    mockRepo.On("GetByID", ctx, userID).Return(user, nil)

    b.ResetTimer()

    for i := 0; i < b.N; i++ {
        _, err := service.GetUser(ctx, userID)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

## 🔒 Security and Configuration

### **Configuration Management**
```go
// config/config.go
package config

import (
    "fmt"
    "os"
    "strconv"
    "time"
)

// Config holds application configuration
type Config struct {
    Server   ServerConfig
    Database DatabaseConfig
    JWT      JWTConfig
    Log      LogConfig
}

type ServerConfig struct {
    Port            int
    Host            string
    ReadTimeout     time.Duration
    WriteTimeout    time.Duration
    ShutdownTimeout time.Duration
}

type DatabaseConfig struct {
    Host         string
    Port         int
    User         string
    Password     string
    Database     string
    MaxOpenConns int
    MaxIdleConns int
    MaxLifetime  time.Duration
}

type JWTConfig struct {
    Secret     string
    Expiration time.Duration
}

type LogConfig struct {
    Level  string
    Format string
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
    config := &Config{
        Server: ServerConfig{
            Port:            getEnvAsInt("SERVER_PORT", 8080),
            Host:            getEnv("SERVER_HOST", "0.0.0.0"),
            ReadTimeout:     getEnvAsDuration("SERVER_READ_TIMEOUT", 15*time.Second),
            WriteTimeout:    getEnvAsDuration("SERVER_WRITE_TIMEOUT", 15*time.Second),
            ShutdownTimeout: getEnvAsDuration("SERVER_SHUTDOWN_TIMEOUT", 30*time.Second),
        },
        Database: DatabaseConfig{
            Host:         getEnv("DB_HOST", "localhost"),
            Port:         getEnvAsInt("DB_PORT", 5432),
            User:         getEnv("DB_USER", "postgres"),
            Password:     getEnv("DB_PASSWORD", ""),
            Database:     getEnv("DB_NAME", "myapp"),
            MaxOpenConns: getEnvAsInt("DB_MAX_OPEN_CONNS", 25),
            MaxIdleConns: getEnvAsInt("DB_MAX_IDLE_CONNS", 5),
            MaxLifetime:  getEnvAsDuration("DB_MAX_LIFETIME", 5*time.Minute),
        },
        JWT: JWTConfig{
            Secret:     getEnv("JWT_SECRET", ""),
            Expiration: getEnvAsDuration("JWT_EXPIRATION", 24*time.Hour),
        },
        Log: LogConfig{
            Level:  getEnv("LOG_LEVEL", "info"),
            Format: getEnv("LOG_FORMAT", "json"),
        },
    }

    if err := config.Validate(); err != nil {
        return nil, fmt.Errorf("invalid configuration: %w", err)
    }

    return config, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
    if c.JWT.Secret == "" {
        return fmt.Errorf("JWT_SECRET is required")
    }
    if c.Database.Password == "" {
        return fmt.Errorf("DB_PASSWORD is required")
    }
    return nil
}

// Database connection string
func (c *Config) DatabaseURL() string {
    return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
        c.Database.User,
        c.Database.Password,
        c.Database.Host,
        c.Database.Port,
        c.Database.Database,
    )
}

// Helper functions
func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
    if value := os.Getenv(key); value != "" {
        if intValue, err := strconv.Atoi(value); err == nil {
            return intValue
        }
    }
    return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
    if value := os.Getenv(key); value != "" {
        if duration, err := time.ParseDuration(value); err == nil {
            return duration
        }
    }
    return defaultValue
}
```

### **JWT Authentication Middleware**
```go
// middleware/auth.go
package middleware

import (
    "net/http"
    "strings"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v4"
    "github.com/google/uuid"
)

// Claims represents JWT claims
type Claims struct {
    UserID uuid.UUID `json:"user_id"`
    Email  string    `json:"email"`
    jwt.RegisteredClaims
}

// JWTAuth creates JWT authentication middleware
func JWTAuth(secret string) gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
            c.Abort()
            return
        }

        bearerToken := strings.Split(authHeader, " ")
        if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
            c.Abort()
            return
        }

        tokenString := bearerToken[1]
        claims := &Claims{}

        token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
            return []byte(secret), nil
        })

        if err != nil || !token.Valid {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }

        // Store user information in context
        c.Set("user_id", claims.UserID)
        c.Set("user_email", claims.Email)

        c.Next()
    }
}

// GenerateToken generates a JWT token
func GenerateToken(userID uuid.UUID, email, secret string, expiration time.Duration) (string, error) {
    claims := &Claims{
        UserID: userID,
        Email:  email,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiration)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            Issuer:    "myapp",
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(secret))
}
```

## 🚀 Deployment and Production

### **Dockerfile**
```dockerfile
# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install git and ca-certificates
RUN apk add --no-cache git ca-certificates

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main cmd/api/main.go

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/main .

# Copy any additional files needed
COPY --from=builder /app/web ./web

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
CMD ["./main"]
```

### **Makefile**
```makefile
# Variables
APP_NAME := myapp
VERSION := $(shell git describe --tags --always --dirty)
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

# Go commands
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOMOD := $(GOCMD) mod

# Build targets
.PHONY: build
build:
	$(GOBUILD) $(LDFLAGS) -o bin/$(APP_NAME) cmd/api/main.go

.PHONY: build-linux
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(APP_NAME)-linux cmd/api/main.go

.PHONY: build-windows
build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(APP_NAME).exe cmd/api/main.go

# Development targets
.PHONY: run
run:
	$(GOCMD) run cmd/api/main.go

.PHONY: test
test:
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

.PHONY: test-coverage
test-coverage: test
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

.PHONY: benchmark
benchmark:
	$(GOTEST) -bench=. -benchmem ./...

# Code quality
.PHONY: fmt
fmt:
	$(GOCMD) fmt ./...

.PHONY: lint
lint:
	golangci-lint run

.PHONY: vet
vet:
	$(GOCMD) vet ./...

# Dependencies
.PHONY: deps
deps:
	$(GOMOD) download
	$(GOMOD) tidy

.PHONY: deps-update
deps-update:
	$(GOMOD) get -u ./...
	$(GOMOD) tidy

# Docker
.PHONY: docker-build
docker-build:
	docker build -t $(APP_NAME):$(VERSION) .

.PHONY: docker-run
docker-run:
	docker run -p 8080:8080 $(APP_NAME):$(VERSION)

# Clean
.PHONY: clean
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build         Build the application"
	@echo "  build-linux   Build for Linux"
	@echo "  build-windows Build for Windows"
	@echo "  run           Run the application"
	@echo "  test          Run tests"
	@echo "  test-coverage Run tests with coverage"
	@echo "  benchmark     Run benchmarks"
	@echo "  fmt           Format code"
	@echo "  lint          Run linter"
	@echo "  vet           Run go vet"
	@echo "  deps          Download dependencies"
	@echo "  deps-update   Update dependencies"
	@echo "  docker-build  Build Docker image"
	@echo "  docker-run    Run Docker container"
	@echo "  clean         Clean build artifacts"
```

---

*This document covers Go development best practices and should be used alongside universal patterns. For consolidated security guidance including environment variables and secrets management, see security-guidelines.md.*