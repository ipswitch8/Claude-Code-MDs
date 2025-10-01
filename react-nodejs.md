# React/Node.js Claude Code Guidelines

*Last Updated: 2025-01-16 | Version: 1.0*

## 🏗️ Project Structure

### **Typical React Project Structure**
```
src/
├── components/          # Reusable UI components
├── pages/              # Page-level components
├── hooks/              # Custom React hooks
├── context/            # React Context providers
├── services/           # API calls and external services
├── utils/              # Utility functions
├── types/              # TypeScript type definitions
├── assets/             # Static assets (images, fonts)
└── styles/             # CSS/SCSS files
```

### **Node.js Backend Structure**
```
backend/
├── controllers/        # Route handlers
├── middleware/         # Express middleware
├── models/            # Database models
├── routes/            # API route definitions
├── services/          # Business logic
├── config/            # Configuration files
├── utils/             # Utility functions
└── tests/             # Test files
```

## 🔧 Development Commands

### **React Development**
```bash
# Install dependencies
npm install
# or
yarn install

# Start development server
npm start
# or
yarn start

# Build for production
npm run build
# or
yarn build

# Run tests
npm test
# or
yarn test

# Run tests with coverage
npm run test:coverage

# Run E2E Selenium tests
npm run test:e2e
# or
yarn test:e2e
```

### **Node.js Development**
```bash
# Install dependencies
npm install

# Start development server with nodemon
npm run dev

# Start production server
npm start

# Run tests
npm test

# Run linting
npm run lint

# Run TypeScript compilation (if using TS)
npm run build
```

## 🚨 React/Node.js Testing Protocol

### **Mandatory E2E Testing Requirements**
**ALL React/Node.js applications MUST include Selenium E2E testing:**

1. **[ ] Selenium Grid configured** - Docker containers running for cross-browser testing
2. **[ ] User workflows tested** - Complete user journeys automated via Selenium
3. **[ ] Form interactions validated** - All forms tested through browser automation
4. **[ ] API integration verified** - Frontend-backend communication tested E2E
5. **[ ] Cross-browser compatibility** - Chrome, Firefox minimum via Selenium Grid
6. **[ ] Responsive design verified** - Mobile, tablet, desktop viewports tested

### **When Server Restart is Required**
- Changes to `package.json` or `package-lock.json`
- Environment variable changes (`.env` files)
- Configuration file changes (`webpack.config.js`, `vite.config.js`)
- New dependencies installed
- Server-side code changes (Node.js backend)

### **When Hot Reload Handles Changes**
- React component modifications
- CSS/SCSS changes
- Most JavaScript file changes
- Asset additions

### **After the universal 7-step protocol, add these framework-specific steps:**

8. **[ ] Check browser console** - No errors in DevTools console
9. **[ ] Verify hot reload works** - Changes reflect without manual refresh
10. **[ ] Test API endpoints** - Backend routes return correct responses
11. **[ ] Check bundle size** - No unexpected increases in build output
12. **[ ] Validate responsive design** - Test on different screen sizes (E2E + manual)
13. **[ ] Run complete E2E test suite** - Full Selenium test coverage completed

## ⚡ Performance Optimization

### **React Performance**
```jsx
// Use React.memo for expensive components
const ExpensiveComponent = React.memo(({ data }) => {
  return <div>{/* expensive rendering */}</div>;
});

// Use useMemo for expensive calculations
const memoizedValue = useMemo(() => {
  return expensiveCalculation(a, b);
}, [a, b]);

// Use useCallback for stable function references
const memoizedCallback = useCallback(() => {
  doSomething(a, b);
}, [a, b]);

// Lazy load components
const LazyComponent = lazy(() => import('./LazyComponent'));
```

### **Bundle Optimization**
```javascript
// Code splitting with dynamic imports
const handleClick = async () => {
  const { heavyFunction } = await import('./heavyModule');
  heavyFunction();
};

// Tree shaking - import only what you need
import { debounce } from 'lodash/debounce';  // Good
import _ from 'lodash';  // Bad - imports entire library
```

### **Node.js Performance**
```javascript
// Use compression middleware
const compression = require('compression');
app.use(compression());

// Implement caching
const NodeCache = require('node-cache');
const cache = new NodeCache({ stdTTL: 600 }); // 10 minutes

// Connection pooling for databases
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20, // maximum number of connections
});
```

## 🔐 Security Best Practices

### **Frontend Security**
```jsx
// Sanitize user input
import DOMPurify from 'dompurify';

const SafeHTML = ({ html }) => {
  const sanitized = DOMPurify.sanitize(html);
  return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
};

// Secure API calls
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL,
  withCredentials: true, // Include cookies
  headers: {
    'Content-Type': 'application/json',
  },
});
```

### **Backend Security**
```javascript
// Essential middleware
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

app.use(helmet()); // Security headers
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api', limiter);

// Input validation
const { body, validationResult } = require('express-validator');

app.post('/api/users',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    // Process valid input
  }
);
```

## 📱 State Management

### **React Context Pattern**
```jsx
// AuthContext.js
const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const login = async (credentials) => {
    setLoading(true);
    try {
      const response = await api.post('/auth/login', credentials);
      setUser(response.data.user);
    } catch (error) {
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    setUser(null);
    api.post('/auth/logout');
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};
```

### **Redux/Zustand for Complex State**
```javascript
// Zustand store
import { create } from 'zustand';

const useStore = create((set, get) => ({
  todos: [],
  addTodo: (todo) => set((state) => ({
    todos: [...state.todos, todo]
  })),
  removeTodo: (id) => set((state) => ({
    todos: state.todos.filter(todo => todo.id !== id)
  })),
}));
```

## 🧪 Testing Strategies

### **Selenium E2E Testing Setup**
```json
// package.json dependencies
{
  "devDependencies": {
    "selenium-webdriver": "^4.15.0",
    "chromedriver": "^118.0.0",
    "geckodriver": "^3.2.0",
    "jest": "^29.0.0",
    "@testing-library/jest-dom": "^6.0.0"
  },
  "scripts": {
    "test:e2e": "jest tests/e2e",
    "test:e2e:watch": "jest tests/e2e --watch",
    "selenium:grid": "docker-compose -f docker-compose.selenium.yml up -d"
  }
}
```

```javascript
// tests/e2e/setup/driver.js
const { Builder, Capabilities } = require('selenium-webdriver');
const chrome = require('selenium-webdriver/chrome');
const firefox = require('selenium-webdriver/firefox');

class DriverFactory {
  static async createDriver(browserName = 'chrome', options = {}) {
    const { headless = true, gridUrl = null } = options;

    let driver;

    if (gridUrl) {
      // Use Selenium Grid
      const capabilities = this.getBrowserCapabilities(browserName, headless);
      driver = await new Builder()
        .usingServer(gridUrl)
        .withCapabilities(capabilities)
        .build();
    } else {
      // Local browser
      driver = await this.createLocalDriver(browserName, headless);
    }

    await driver.manage().setTimeouts({ implicit: 10000 });
    return driver;
  }

  static async createLocalDriver(browserName, headless) {
    switch (browserName) {
      case 'chrome':
        const chromeOptions = new chrome.Options();
        if (headless) chromeOptions.addArguments('--headless');
        chromeOptions.addArguments('--no-sandbox', '--disable-dev-shm-usage');
        return await new Builder()
          .forBrowser('chrome')
          .setChromeOptions(chromeOptions)
          .build();

      case 'firefox':
        const firefoxOptions = new firefox.Options();
        if (headless) firefoxOptions.addArguments('--headless');
        return await new Builder()
          .forBrowser('firefox')
          .setFirefoxOptions(firefoxOptions)
          .build();

      default:
        throw new Error(`Unsupported browser: ${browserName}`);
    }
  }

  static getBrowserCapabilities(browserName, headless) {
    const capabilities = Capabilities[browserName]();

    if (browserName === 'chrome') {
      capabilities.set('goog:chromeOptions', {
        args: headless ? ['--headless', '--no-sandbox', '--disable-dev-shm-usage'] : []
      });
    } else if (browserName === 'firefox') {
      capabilities.set('moz:firefoxOptions', {
        args: headless ? ['--headless'] : []
      });
    }

    return capabilities;
  }
}

module.exports = DriverFactory;
```

```javascript
// tests/e2e/pages/BasePage.js
const { By, until } = require('selenium-webdriver');

class BasePage {
  constructor(driver) {
    this.driver = driver;
    this.baseUrl = process.env.BASE_URL || 'http://localhost:3000';
  }

  async navigateTo(path = '/') {
    await this.driver.get(`${this.baseUrl}${path}`);
  }

  async waitForElement(locator, timeout = 10000) {
    return await this.driver.wait(until.elementLocated(locator), timeout);
  }

  async waitForElementVisible(locator, timeout = 10000) {
    const element = await this.waitForElement(locator, timeout);
    await this.driver.wait(until.elementIsVisible(element), timeout);
    return element;
  }

  async clickElement(locator) {
    const element = await this.waitForElementVisible(locator);
    await this.driver.executeScript('arguments[0].scrollIntoView(true);', element);
    await element.click();
  }

  async sendKeys(locator, text) {
    const element = await this.waitForElementVisible(locator);
    await element.clear();
    await element.sendKeys(text);
  }

  async getText(locator) {
    const element = await this.waitForElementVisible(locator);
    return await element.getText();
  }

  async takeScreenshot(filename) {
    const screenshot = await this.driver.takeScreenshot();
    require('fs').writeFileSync(`screenshots/${filename}.png`, screenshot, 'base64');
  }

  async setViewport(width, height) {
    await this.driver.manage().window().setRect({ width, height });
  }
}

module.exports = BasePage;
```

```javascript
// tests/e2e/user-workflow.test.js
const DriverFactory = require('./setup/driver');
const BasePage = require('./pages/BasePage');
const { By } = require('selenium-webdriver');

describe('User Workflow E2E Tests', () => {
  let driver;
  let page;

  beforeAll(async () => {
    driver = await DriverFactory.createDriver('chrome', {
      headless: process.env.CI === 'true',
      gridUrl: process.env.SELENIUM_GRID_URL
    });
    page = new BasePage(driver);
  });

  afterAll(async () => {
    if (driver) {
      await driver.quit();
    }
  });

  describe('Authentication Flow', () => {
    test('User can login and access dashboard', async () => {
      // Navigate to login page
      await page.navigateTo('/login');

      // Fill login form
      await page.sendKeys(By.css('input[type="email"]'), process.env.TEST_USER_EMAIL || 'test@example.com');
      await page.sendKeys(By.css('input[type="password"]'), process.env.TEST_USER_PASSWORD || 'password123');
      await page.clickElement(By.css('button[type="submit"]'));

      // Verify dashboard loads
      await page.waitForElementVisible(By.css('[data-testid="dashboard"]'));
      const welcomeText = await page.getText(By.css('.welcome-message'));
      expect(welcomeText).toContain('Welcome');
    });

    test('Invalid credentials show error message', async () => {
      await page.navigateTo('/login');

      await page.sendKeys(By.css('input[type="email"]'), process.env.TEST_INVALID_EMAIL || 'invalid@example.com');
      await page.sendKeys(By.css('input[type="password"]'), process.env.TEST_INVALID_PASSWORD || 'wrongpassword');
      await page.clickElement(By.css('button[type="submit"]'));

      const errorMessage = await page.getText(By.css('.error-message'));
      expect(errorMessage).toContain('Invalid credentials');
    });
  });

  describe('Responsive Design', () => {
    const viewports = [
      { name: 'mobile', width: 375, height: 667 },
      { name: 'tablet', width: 768, height: 1024 },
      { name: 'desktop', width: 1920, height: 1080 }
    ];

    test.each(viewports)('Navigation works on $name viewport', async ({ width, height }) => {
      await page.setViewport(width, height);
      await page.navigateTo('/');

      if (width < 768) {
        // Mobile - check hamburger menu
        await page.clickElement(By.css('.mobile-menu-toggle'));
        await page.waitForElementVisible(By.css('.mobile-menu'));
      } else {
        // Desktop/Tablet - check regular navigation
        await page.waitForElementVisible(By.css('.desktop-nav'));
      }
    });
  });

  describe('Form Interactions', () => {
    test('User can create new item', async () => {
      // Login first
      await page.navigateTo('/login');
      await page.sendKeys(By.css('input[type="email"]'), process.env.TEST_USER_EMAIL || 'test@example.com');
      await page.sendKeys(By.css('input[type="password"]'), process.env.TEST_USER_PASSWORD || 'password123');
      await page.clickElement(By.css('button[type="submit"]'));

      // Navigate to create form
      await page.navigateTo('/items/create');

      // Fill form
      await page.sendKeys(By.css('input[name="title"]'), 'Test Item');
      await page.sendKeys(By.css('textarea[name="description"]'), 'Test Description');
      await page.clickElement(By.css('button[type="submit"]'));

      // Verify success
      const successMessage = await page.getText(By.css('.success-message'));
      expect(successMessage).toContain('Item created successfully');
    });
  });
});
```

### **Cross-Browser Testing Configuration**
```javascript
// tests/e2e/cross-browser.test.js
const browsers = ['chrome', 'firefox'];

describe.each(browsers)('Cross-browser tests - %s', (browserName) => {
  let driver;
  let page;

  beforeAll(async () => {
    driver = await DriverFactory.createDriver(browserName, {
      gridUrl: process.env.SELENIUM_GRID_URL
    });
    page = new BasePage(driver);
  });

  afterAll(async () => {
    if (driver) await driver.quit();
  });

  test('Homepage loads correctly', async () => {
    await page.navigateTo('/');

    const title = await driver.getTitle();
    expect(title).toContain('React App');

    await page.waitForElementVisible(By.css('main'));
  });
});
```

### **React Testing**
```jsx
// Component testing with Testing Library
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import LoginForm from './LoginForm';

test('submits form with correct data', async () => {
  const mockSubmit = jest.fn();
  render(<LoginForm onSubmit={mockSubmit} />);

  const testEmail = process.env.TEST_USER_EMAIL || 'user@example.com';
  const testPassword = process.env.TEST_USER_PASSWORD || 'password123';

  fireEvent.change(screen.getByLabelText(/email/i), {
    target: { value: testEmail }
  });
  fireEvent.change(screen.getByLabelText(/password/i), {
    target: { value: testPassword }
  });

  fireEvent.click(screen.getByRole('button', { name: /login/i }));

  expect(mockSubmit).toHaveBeenCalledWith({
    email: testEmail,
    password: testPassword
  });
});
```

### **Node.js Testing**
```javascript
// API testing with Jest and Supertest
const request = require('supertest');
const app = require('../app');

describe('POST /api/users', () => {
  test('creates a new user', async () => {
    const userData = {
      email: process.env.TEST_USER_EMAIL || 'test@example.com',
      password: process.env.TEST_USER_PASSWORD || 'password123',
      name: 'Test User'
    };

    const response = await request(app)
      .post('/api/users')
      .send(userData)
      .expect(201);

    expect(response.body).toHaveProperty('id');
    expect(response.body.email).toBe(userData.email);
  });

  test('returns 400 for invalid email', async () => {
    const userData = {
      email: 'invalid-email',
      password: process.env.TEST_USER_PASSWORD || 'password123'
    };

    await request(app)
      .post('/api/users')
      .send(userData)
      .expect(400);
  });
});
```

## 🌐 API Integration

### **React API Patterns**
```jsx
// Custom hook for API calls
const useApi = (url) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        const response = await api.get(url);
        setData(response.data);
      } catch (err) {
        setError(err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [url]);

  return { data, loading, error };
};

// Usage in component
const UserProfile = ({ userId }) => {
  const { data: user, loading, error } = useApi(`/users/${userId}`);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error.message}</div>;
  if (!user) return <div>User not found</div>;

  return <div>{user.name}</div>;
};
```

### **Error Handling**
```jsx
// Global error boundary
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Error caught by boundary:', error, errorInfo);
    // Log to error reporting service
  }

  render() {
    if (this.state.hasError) {
      return (
        <div>
          <h2>Something went wrong.</h2>
          <button onClick={() => this.setState({ hasError: false, error: null })}>
            Try again
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
```

## 📦 Environment Management

### **Environment Variables**
```bash
# .env.development
REACT_APP_API_URL=http://localhost:3001
REACT_APP_DEBUG=true

# .env.production
REACT_APP_API_URL=https://api.myapp.com
REACT_APP_DEBUG=false
```

```javascript
// Node.js environment configuration
const config = {
  development: {
    PORT: process.env.PORT || 3001,
    DATABASE_URL: process.env.DEV_DATABASE_URL,
    JWT_SECRET: process.env.JWT_SECRET,
  },
  production: {
    PORT: process.env.PORT || 80,
    DATABASE_URL: process.env.DATABASE_URL,
    JWT_SECRET: process.env.JWT_SECRET,
  }
};

module.exports = config[process.env.NODE_ENV || 'development'];
```

## 🚀 Build and Deployment

### **React Build Optimization**
```javascript
// webpack.config.js customization
module.exports = {
  optimization: {
    splitChunks: {
      chunks: 'all',
      cacheGroups: {
        vendor: {
          test: /[\\/]node_modules[\\/]/,
          name: 'vendors',
          chunks: 'all',
        },
      },
    },
  },
};
```

### **Docker Configuration**
```dockerfile
# React Dockerfile
FROM node:16-alpine as build
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

---

*This document covers React/Node.js development best practices and should be used alongside universal patterns. For consolidated security guidance including environment variables and secrets management, see security-guidelines.md.*