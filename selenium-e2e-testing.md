# Selenium End-to-End Testing Guidelines

*All web-based interfaces MUST include Selenium testing to emulate actual user viewing and interaction patterns.*

## 🎯 Core Principle

**Every web application requires comprehensive E2E testing with Selenium to validate real user workflows and interface behavior.**

## 📋 Selenium Testing Requirements

### **Mandatory E2E Test Coverage**
- [ ] **User Authentication Flow** - Login, logout, session management
- [ ] **Core User Journeys** - Primary application workflows
- [ ] **Form Validation** - Client-side and server-side validation
- [ ] **Navigation** - Menu systems, routing, deep linking
- [ ] **Responsive Design** - Mobile, tablet, desktop viewports
- [ ] **Cross-Browser Compatibility** - Chrome, Firefox, Safari, Edge
- [ ] **Error Handling** - 404s, 500s, network failures
- [ ] **Data CRUD Operations** - Create, Read, Update, Delete workflows

## 🛠 Selenium Grid Setup

### **Docker Selenium Grid**
```yaml
# docker-compose.selenium.yml
version: '3.8'
services:
  selenium-hub:
    image: selenium/hub:4.15.0
    container_name: selenium-hub
    ports:
      - "4444:4444"
    environment:
      - GRID_MAX_SESSION=16
      - GRID_BROWSER_TIMEOUT=300
      - GRID_TIMEOUT=300

  chrome:
    image: selenium/node-chrome:4.15.0
    shm_size: 2gb
    depends_on:
      - selenium-hub
    environment:
      - HUB_HOST=selenium-hub
      - NODE_MAX_INSTANCES=4
      - NODE_MAX_SESSION=4
    scale: 2

  firefox:
    image: selenium/node-firefox:4.15.0
    shm_size: 2gb
    depends_on:
      - selenium-hub
    environment:
      - HUB_HOST=selenium-hub
      - NODE_MAX_INSTANCES=4
      - NODE_MAX_SESSION=4
    scale: 2

  edge:
    image: selenium/node-edge:4.15.0
    shm_size: 2gb
    depends_on:
      - selenium-hub
    environment:
      - HUB_HOST=selenium-hub
      - NODE_MAX_INSTANCES=4
      - NODE_MAX_SESSION=4
```

### **Grid Management Commands**
```bash
# Start Selenium Grid
docker-compose -f docker-compose.selenium.yml up -d

# Scale browser nodes
docker-compose -f docker-compose.selenium.yml up -d --scale chrome=4 --scale firefox=2

# Monitor grid status
curl http://localhost:4444/wd/hub/status

# Stop grid
docker-compose -f docker-compose.selenium.yml down
```

## 🧪 Test Framework Structure

### **Page Object Model Implementation**
```
tests/
├── e2e/
│   ├── pages/
│   │   ├── base_page.py
│   │   ├── login_page.py
│   │   ├── dashboard_page.py
│   │   └── user_management_page.py
│   ├── fixtures/
│   │   ├── test_data.json
│   │   └── user_credentials.json
│   ├── utils/
│   │   ├── driver_factory.py
│   │   ├── wait_helpers.py
│   │   └── screenshot_helper.py
│   └── test_suites/
│       ├── test_authentication.py
│       ├── test_user_workflows.py
│       └── test_responsive_design.py
```

### **Base Page Class**
```python
# pages/base_page.py
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException
import logging

class BasePage:
    def __init__(self, driver):
        self.driver = driver
        self.wait = WebDriverWait(driver, 10)
        self.logger = logging.getLogger(__name__)

    def wait_for_element(self, locator, timeout=10):
        """Wait for element to be present and visible"""
        try:
            element = WebDriverWait(self.driver, timeout).until(
                EC.visibility_of_element_located(locator)
            )
            return element
        except TimeoutException:
            self.logger.error(f"Element not found: {locator}")
            self.take_screenshot("element_not_found")
            raise

    def wait_for_clickable(self, locator, timeout=10):
        """Wait for element to be clickable"""
        return WebDriverWait(self.driver, timeout).until(
            EC.element_to_be_clickable(locator)
        )

    def safe_click(self, locator):
        """Click element with wait and error handling"""
        element = self.wait_for_clickable(locator)
        self.driver.execute_script("arguments[0].scrollIntoView(true);", element)
        element.click()

    def safe_send_keys(self, locator, text):
        """Send keys with wait and clear"""
        element = self.wait_for_element(locator)
        element.clear()
        element.send_keys(text)

    def get_text(self, locator):
        """Get element text with wait"""
        element = self.wait_for_element(locator)
        return element.text

    def take_screenshot(self, name):
        """Take screenshot for debugging"""
        filename = f"screenshots/{name}_{self.driver.current_url.split('/')[-1]}.png"
        self.driver.save_screenshot(filename)
        self.logger.info(f"Screenshot saved: {filename}")

    def scroll_to_element(self, locator):
        """Scroll element into view"""
        element = self.wait_for_element(locator)
        self.driver.execute_script("arguments[0].scrollIntoView(true);", element)
```

### **Driver Factory**
```python
# utils/driver_factory.py
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.edge.options import Options as EdgeOptions
import os

class DriverFactory:
    @staticmethod
    def create_driver(browser="chrome", headless=False, grid_url=None):
        """Create WebDriver instance"""

        if grid_url:
            return DriverFactory._create_remote_driver(browser, headless, grid_url)
        else:
            return DriverFactory._create_local_driver(browser, headless)

    @staticmethod
    def _create_remote_driver(browser, headless, grid_url):
        """Create remote WebDriver for Selenium Grid"""
        options = DriverFactory._get_browser_options(browser, headless)

        return webdriver.Remote(
            command_executor=grid_url,
            options=options
        )

    @staticmethod
    def _create_local_driver(browser, headless):
        """Create local WebDriver"""
        if browser.lower() == "chrome":
            options = ChromeOptions()
            if headless:
                options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-infobars")
            options.add_argument("--disable-popup-blocking")
            options.add_argument("--disable-notifications")

            # Set clipboard and popup preferences
            prefs = {
                "profile.content_settings.exceptions.clipboard": {
                    "*": {"setting": 1}
                },
                "profile.default_content_settings.popups": 0
            }
            options.add_experimental_option("prefs", prefs)

            return webdriver.Chrome(options=options)

        elif browser.lower() == "firefox":
            options = FirefoxOptions()
            if headless:
                options.add_argument("--headless")
            return webdriver.Firefox(options=options)

        elif browser.lower() == "edge":
            options = EdgeOptions()
            if headless:
                options.add_argument("--headless")
            return webdriver.Edge(options=options)

        else:
            raise ValueError(f"Unsupported browser: {browser}")

    @staticmethod
    def _get_browser_options(browser, headless):
        """Get browser-specific options"""
        if browser.lower() == "chrome":
            options = ChromeOptions()
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--window-size=1920,1080")
            options.add_argument("--disable-infobars")
            options.add_argument("--disable-popup-blocking")
            options.add_argument("--disable-notifications")

            # Set clipboard and popup preferences
            prefs = {
                "profile.content_settings.exceptions.clipboard": {
                    "*": {"setting": 1}
                },
                "profile.default_content_settings.popups": 0
            }
            options.add_experimental_option("prefs", prefs)
        elif browser.lower() == "firefox":
            options = FirefoxOptions()
            options.add_argument("--width=1920")
            options.add_argument("--height=1080")
        elif browser.lower() == "edge":
            options = EdgeOptions()
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
        else:
            raise ValueError(f"Unsupported browser: {browser}")

        if headless:
            options.add_argument("--headless")

        return options
```

## 🎭 Cross-Browser Testing Strategy

### **Browser Matrix Configuration**
```python
# conftest.py for pytest
import pytest
from utils.driver_factory import DriverFactory

BROWSERS = ["chrome", "firefox", "edge"]
VIEWPORTS = [
    (1920, 1080),  # Desktop
    (1366, 768),   # Laptop
    (768, 1024),   # Tablet
    (375, 667)     # Mobile
]

@pytest.fixture(params=BROWSERS)
def browser_driver(request):
    """Parameterized browser fixture"""
    browser = request.param
    grid_url = "http://localhost:4444/wd/hub"

    driver = DriverFactory.create_driver(
        browser=browser,
        headless=True,
        grid_url=grid_url
    )

    yield driver
    driver.quit()

@pytest.fixture(params=VIEWPORTS)
def viewport_driver(browser_driver, request):
    """Parameterized viewport fixture"""
    width, height = request.param
    browser_driver.set_window_size(width, height)
    return browser_driver
```

## 📱 Responsive Design Testing

### **Viewport Testing Implementation**
```python
# test_responsive_design.py
import pytest
from pages.dashboard_page import DashboardPage

class TestResponsiveDesign:

    @pytest.mark.parametrize("viewport", [
        (1920, 1080, "desktop"),
        (1366, 768, "laptop"),
        (768, 1024, "tablet"),
        (375, 667, "mobile")
    ])
    def test_navigation_responsive(self, browser_driver, viewport):
        """Test navigation adapts to different viewports"""
        width, height, device_type = viewport
        browser_driver.set_window_size(width, height)

        dashboard = DashboardPage(browser_driver)
        dashboard.navigate_to_dashboard()

        # Verify navigation elements based on viewport
        if device_type in ["mobile", "tablet"]:
            assert dashboard.is_hamburger_menu_visible()
            dashboard.click_hamburger_menu()
            assert dashboard.is_mobile_menu_expanded()
        else:
            assert dashboard.is_desktop_navigation_visible()
            assert not dashboard.is_hamburger_menu_visible()

    def test_form_layouts_responsive(self, viewport_driver):
        """Test form layouts across viewports"""
        dashboard = DashboardPage(viewport_driver)
        dashboard.navigate_to_user_form()

        # Verify form adapts properly
        assert dashboard.is_form_visible()
        assert dashboard.are_form_fields_accessible()

        # Test form submission
        dashboard.fill_user_form({
            "name": "Test User",
            "email": "test@example.com"
        })
        dashboard.submit_form()
        assert dashboard.is_success_message_visible()
```

## 🔄 CI/CD Integration

### **GitHub Actions Selenium Pipeline**
```yaml
# .github/workflows/e2e-tests.yml
name: E2E Tests

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  e2e-tests:
    runs-on: ubuntu-latest

    services:
      selenium-hub:
        image: selenium/hub:4.15.0
        ports:
          - 4444:4444

      chrome:
        image: selenium/node-chrome:4.15.0
        env:
          HUB_HOST: selenium-hub

    steps:
    - uses: actions/checkout@v3

    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'

    - name: Install dependencies
      run: |
        pip install -r requirements-test.txt

    - name: Wait for Selenium Grid
      run: |
        timeout 60 bash -c 'until curl -f http://localhost:4444/wd/hub/status; do sleep 2; done'

    - name: Run E2E Tests
      run: |
        pytest tests/e2e/ --html=reports/e2e-report.html --self-contained-html
      env:
        SELENIUM_GRID_URL: http://localhost:4444/wd/hub
        BASE_URL: http://localhost:3000

    - name: Upload test reports
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: e2e-test-reports
        path: |
          reports/
          screenshots/
```

## 🚨 Selenium Testing Protocol

### **Pre-Development Requirements**
- [ ] **Selenium Grid configured** - Docker containers running
- [ ] **Test data prepared** - Fixtures and mock data ready
- [ ] **Page objects defined** - All pages have corresponding classes
- [ ] **Test scenarios documented** - User stories translated to test cases

### **During Development**
- [ ] **Write E2E tests alongside features** - Test-driven development
- [ ] **Validate across browsers** - Chrome, Firefox, Edge minimum
- [ ] **Test responsive behavior** - Mobile, tablet, desktop viewports
- [ ] **Verify accessibility** - Screen reader compatibility, keyboard navigation

### **Pre-Deployment Validation**
- [ ] **Full E2E test suite passes** - All critical user journeys work
- [ ] **Cross-browser compatibility confirmed** - No browser-specific issues
- [ ] **Performance acceptable** - Page load times under thresholds
- [ ] **Error scenarios handled** - Graceful degradation tested

## 📊 Reporting and Monitoring

### **Test Reporting Configuration**
```python
# pytest.ini
[tool:pytest]
addopts =
    --html=reports/selenium-report.html
    --self-contained-html
    --capture=tee-sys
    --tb=short
    -v
testpaths = tests/e2e
python_files = test_*.py
python_classes = Test*
python_functions = test_*
markers =
    smoke: Quick smoke tests
    regression: Full regression suite
    cross_browser: Cross-browser tests
```

### **Monitoring Integration**
```python
# utils/test_monitor.py
import requests
import json
from datetime import datetime

class TestMonitor:
    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url

    def report_test_results(self, results):
        """Send test results to monitoring system"""
        payload = {
            "timestamp": datetime.utcnow().isoformat(),
            "test_suite": "e2e_selenium",
            "total_tests": results.total,
            "passed": results.passed,
            "failed": results.failed,
            "skipped": results.skipped,
            "duration": results.duration
        }

        if self.webhook_url:
            requests.post(self.webhook_url, json=payload)
```

---

*This document ensures comprehensive E2E testing coverage for all web-based interfaces using Selenium automation.*