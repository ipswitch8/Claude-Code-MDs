# Python/Django Claude Code Guidelines

*Last Updated: 2025-01-16 | Version: 1.0*

## 🏗️ Django Project Structure

### **Standard Django Layout**
```
myproject/
├── manage.py
├── requirements/
│   ├── base.txt
│   ├── development.txt
│   └── production.txt
├── myproject/
│   ├── settings/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── development.py
│   │   └── production.py
│   ├── urls.py
│   └── wsgi.py
├── apps/
│   ├── accounts/
│   ├── core/
│   └── api/
├── static/
├── media/
├── templates/
└── tests/
```

### **App Structure Best Practices**
```
myapp/
├── __init__.py
├── admin.py
├── apps.py
├── models.py
├── views.py
├── urls.py
├── forms.py
├── serializers.py (for DRF)
├── managers.py
├── signals.py
├── utils.py
├── migrations/
├── templates/myapp/
└── tests/
    ├── __init__.py
    ├── test_models.py
    ├── test_views.py
    └── test_forms.py
```

## 🔧 Development Commands

### **Django Management**
```bash
# Install dependencies
pip install -r requirements/development.txt

# Database operations
python manage.py makemigrations
python manage.py migrate
python manage.py showmigrations
python manage.py sqlmigrate app_name migration_name

# Create superuser
python manage.py createsuperuser

# Run development server
python manage.py runserver
python manage.py runserver 8080
python manage.py runserver 0.0.0.0:8000

# Shell access
python manage.py shell
python manage.py shell_plus  # if using django-extensions

# Static files
python manage.py collectstatic
python manage.py findstatic filename.css

# Testing
python manage.py test
python manage.py test myapp.tests.test_models
python -m pytest  # if using pytest
```

### **Virtual Environment Management**
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

# Deactivate
deactivate

# Install from requirements
pip install -r requirements.txt

# Freeze current packages
pip freeze > requirements.txt
```

## 🚨 Python/Django Testing Protocol

### **When Server Restart is Required**
- Changes to `settings.py` or environment-specific settings
- New app additions to `INSTALLED_APPS`
- Middleware configuration changes
- URL configuration changes at project level
- Database migrations (sometimes requires restart)
- Changes to `requirements.txt` (new packages installed)

### **When Django Auto-reloads**
- Model changes (after migrations)
- View and template modifications
- Form changes
- Most Python code changes in development

### **After the universal 7-step protocol, add these framework-specific steps:**

8. **[ ] Check Django debug toolbar** - No SQL query issues or performance warnings
9. **[ ] Verify migrations applied** - `python manage.py showmigrations` shows all applied
10. **[ ] Test admin interface** - Admin panels load correctly for modified models
11. **[ ] Check static files** - CSS/JS files served correctly
12. **[ ] Validate forms and serializers** - All validation rules working

## 🗄️ Models and Database

### **Model Best Practices**
```python
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone

class TimestampedModel(models.Model):
    """Abstract base class with created/updated timestamps."""
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

class User(TimestampedModel):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'auth_user'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.first_name} {self.last_name}"

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

class Order(TimestampedModel):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='orders')
    total_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)]
    )
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('confirmed', 'Confirmed'),
            ('shipped', 'Shipped'),
            ('delivered', 'Delivered'),
            ('cancelled', 'Cancelled'),
        ],
        default='pending'
    )

    class Meta:
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['created_at']),
        ]
```

### **Migration Best Practices**
```python
# Custom migration example
from django.db import migrations, models

def populate_default_data(apps, schema_editor):
    """Populate default categories after creating the table."""
    Category = apps.get_model('myapp', 'Category')
    Category.objects.bulk_create([
        Category(name='Electronics', slug='electronics'),
        Category(name='Books', slug='books'),
        Category(name='Clothing', slug='clothing'),
    ])

def reverse_populate_default_data(apps, schema_editor):
    """Remove default categories."""
    Category = apps.get_model('myapp', 'Category')
    Category.objects.filter(slug__in=['electronics', 'books', 'clothing']).delete()

class Migration(migrations.Migration):
    dependencies = [
        ('myapp', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(
            populate_default_data,
            reverse_populate_default_data
        ),
    ]
```

## 🎯 Views and URLs

### **Class-Based Views**
```python
from django.views.generic import ListView, DetailView, CreateView, UpdateView
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.urls import reverse_lazy
from django.contrib import messages

class OrderListView(LoginRequiredMixin, ListView):
    model = Order
    template_name = 'orders/order_list.html'
    context_object_name = 'orders'
    paginate_by = 20

    def get_queryset(self):
        return Order.objects.filter(user=self.request.user).select_related('user')

class OrderCreateView(LoginRequiredMixin, CreateView):
    model = Order
    fields = ['total_amount', 'status']
    template_name = 'orders/order_form.html'
    success_url = reverse_lazy('orders:list')

    def form_valid(self, form):
        form.instance.user = self.request.user
        messages.success(self.request, 'Order created successfully!')
        return super().form_valid(form)

class OrderUpdateView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
    model = Order
    fields = ['status']
    template_name = 'orders/order_form.html'

    def test_func(self):
        order = self.get_object()
        return order.user == self.request.user or self.request.user.is_staff

    def get_success_url(self):
        return reverse_lazy('orders:detail', kwargs={'pk': self.object.pk})
```

### **URL Configuration**
```python
# myapp/urls.py
from django.urls import path
from . import views

app_name = 'orders'

urlpatterns = [
    path('', views.OrderListView.as_view(), name='list'),
    path('create/', views.OrderCreateView.as_view(), name='create'),
    path('<int:pk>/', views.OrderDetailView.as_view(), name='detail'),
    path('<int:pk>/edit/', views.OrderUpdateView.as_view(), name='edit'),
    path('api/', include('myapp.api.urls')),
]

# Main urls.py
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('django.contrib.auth.urls')),
    path('api/v1/', include('api.urls')),
    path('orders/', include('orders.urls')),
    path('', include('core.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
```

## 🔐 Authentication and Permissions

### **Custom User Model**
```python
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.contrib.auth.base_user import BaseUserManager

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return self.email
```

### **Custom Permissions**
```python
# In models.py
class Order(models.Model):
    # ... fields ...

    class Meta:
        permissions = [
            ('can_view_all_orders', 'Can view all orders'),
            ('can_approve_orders', 'Can approve orders'),
            ('can_cancel_orders', 'Can cancel orders'),
        ]

# In views.py
from django.contrib.auth.decorators import permission_required
from django.utils.decorators import method_decorator

@method_decorator(permission_required('orders.can_view_all_orders'), name='dispatch')
class AllOrdersView(ListView):
    model = Order
    template_name = 'orders/all_orders.html'
```

## 🧪 Testing

### **Model Testing**
```python
from django.test import TestCase
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from myapp.models import Order

User = get_user_model()

class OrderModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password=os.environ.get('TEST_PASSWORD', 'testpass123'),
            first_name='Test',
            last_name='User'
        )

    def test_order_creation(self):
        order = Order.objects.create(
            user=self.user,
            total_amount=99.99,
            status='pending'
        )
        self.assertEqual(order.user, self.user)
        self.assertEqual(order.total_amount, 99.99)
        self.assertEqual(order.status, 'pending')

    def test_order_str_method(self):
        order = Order.objects.create(
            user=self.user,
            total_amount=99.99
        )
        expected_str = f"Order {order.id} - {self.user.email}"
        self.assertEqual(str(order), expected_str)

    def test_negative_amount_validation(self):
        with self.assertRaises(ValidationError):
            order = Order(
                user=self.user,
                total_amount=-10.00
            )
            order.full_clean()
```

### **View Testing**
```python
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model

User = get_user_model()

class OrderViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.test_password = os.environ.get('TEST_PASSWORD', 'testpass123')
        self.user = User.objects.create_user(
            email='test@example.com',
            password=self.test_password
        )
        self.order = Order.objects.create(
            user=self.user,
            total_amount=99.99
        )

    def test_order_list_view_authenticated(self):
        self.client.login(email='test@example.com', password=self.test_password)
        response = self.client.get(reverse('orders:list'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Orders')
        self.assertContains(response, '99.99')

    def test_order_list_view_anonymous(self):
        response = self.client.get(reverse('orders:list'))
        self.assertRedirects(response, '/accounts/login/?next=/orders/')

    def test_order_create_post(self):
        self.client.login(email='test@example.com', password=self.test_password)
        response = self.client.post(reverse('orders:create'), {
            'total_amount': '150.00',
            'status': 'pending'
        })
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Order.objects.filter(total_amount=150.00).exists())
```

## 🔧 Settings Configuration

### **Environment-Specific Settings**
```python
# settings/base.py
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

SECRET_KEY = os.environ.get('SECRET_KEY') or (
    lambda: exec('raise ValueError("SECRET_KEY environment variable is required")')
)()  # Force requirement of environment variable

DEBUG = False

ALLOWED_HOSTS = []

# Application definition
DJANGO_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

THIRD_PARTY_APPS = [
    'rest_framework',
    'corsheaders',
    'django_extensions',
]

LOCAL_APPS = [
    'apps.core',
    'apps.accounts',
    'apps.orders',
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'myproject.urls'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME', 'myproject'),
        'USER': os.environ.get('DB_USER', 'myuser'),
        'PASSWORD': os.environ.get('DB_PASSWORD'),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '5432'),
    }
}

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# Static files
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Custom user model
AUTH_USER_MODEL = 'accounts.User'

# REST Framework
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20
}
```

```python
# settings/development.py
from .base import *

DEBUG = True

ALLOWED_HOSTS = ['localhost', '127.0.0.1']

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Email backend for development
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Django Debug Toolbar
if DEBUG:
    INSTALLED_APPS += ['debug_toolbar']
    MIDDLEWARE += ['debug_toolbar.middleware.DebugToolbarMiddleware']
    INTERNAL_IPS = ['127.0.0.1']
```

## 📦 Requirements Management

### **requirements/base.txt**
```
Django>=4.2,<5.0
psycopg2-binary>=2.9.5
djangorestframework>=3.14.0
django-cors-headers>=3.13.0
Pillow>=9.4.0
celery>=5.2.0
redis>=4.5.0
```

### **requirements/development.txt**
```
-r base.txt
django-debug-toolbar>=3.2.4
django-extensions>=3.2.1
ipython>=8.8.0
pytest-django>=4.5.2
factory-boy>=3.2.1
coverage>=7.0.5
black>=22.12.0
flake8>=6.0.0
isort>=5.12.0
```

### **requirements/production.txt**
```
-r base.txt
gunicorn>=20.1.0
whitenoise>=6.2.0
sentry-sdk>=1.14.0
```

## 🚀 Deployment

### **Docker Configuration**
```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements/production.txt .
RUN pip install --no-cache-dir -r production.txt

# Copy project
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput

# Run gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "myproject.wsgi:application"]
```

### **Environment Variables**
```bash
# .env
DEBUG=True
SECRET_KEY=${DJANGO_SECRET_KEY}
DB_NAME=${DATABASE_NAME}
DB_USER=${DATABASE_USER}
DB_PASSWORD=${DATABASE_PASSWORD}
DB_HOST=${DATABASE_HOST}
DB_PORT=${DATABASE_PORT}
ALLOWED_HOSTS=localhost,127.0.0.1
```

---

*This document covers Python/Django development best practices and should be used alongside universal patterns. For consolidated security guidance including environment variables and secrets management, see security-guidelines.md.*