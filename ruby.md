# Ruby Claude Code Guidelines

*Last Updated: 2025-01-16 | Version: 1.0*

## 🏗️ Ruby Project Structure

### **Standard Ruby Application Layout**
```
ruby-app/
├── Gemfile
├── Gemfile.lock
├── Rakefile
├── .ruby-version
├── .gitignore
├── README.md
├── app/
│   ├── models/
│   ├── controllers/
│   ├── views/
│   ├── services/
│   └── lib/
├── config/
│   ├── application.rb
│   ├── database.yml
│   └── environments/
├── db/
│   ├── migrate/
│   └── seeds.rb
├── lib/
│   └── tasks/
├── spec/ (or test/)
│   ├── models/
│   ├── controllers/
│   ├── services/
│   └── spec_helper.rb
├── public/
├── tmp/
└── vendor/
```

### **Rails Application Structure**
```
rails-app/
├── Gemfile
├── Gemfile.lock
├── Rakefile
├── config.ru
├── app/
│   ├── assets/
│   ├── controllers/
│   ├── helpers/
│   ├── jobs/
│   ├── mailers/
│   ├── models/
│   ├── views/
│   └── channels/
├── bin/
├── config/
│   ├── application.rb
│   ├── routes.rb
│   ├── database.yml
│   └── environments/
├── db/
├── lib/
├── log/
├── public/
├── storage/
├── test/ (or spec/)
├── tmp/
└── vendor/
```

## 🔧 Development Commands

### **Ruby/Bundler Commands**
```bash
# Install Ruby version manager (rbenv or RVM)
# rbenv
curl -fsSL https://github.com/rbenv/rbenv-installer/raw/HEAD/bin/rbenv-installer | bash
rbenv install 3.2.0
rbenv global 3.2.0

# RVM
curl -sSL https://get.rvm.io | bash -s stable
rvm install 3.2.0
rvm use 3.2.0 --default

# Bundler gem management
gem install bundler
bundle install
bundle update
bundle exec rake
bundle exec ruby script.rb

# Check for security vulnerabilities
bundle audit

# Check for outdated gems
bundle outdated

# Add new gem
echo 'gem "gem_name"' >> Gemfile
bundle install
```

### **Rails Commands**
```bash
# Create new Rails application
rails new myapp
rails new myapp --api  # API-only mode
rails new myapp --database=postgresql

# Server management
rails server
rails server -p 3001
rails server -e production

# Database operations
rails db:migrate
rails db:rollback
rails db:migrate:status
rails db:seed
rails db:reset
rails db:drop
rails db:create

# Generate resources
rails generate controller Users index show create
rails generate model User name:string email:string
rails generate migration AddIndexToUsersEmail
rails generate scaffold Post title:string content:text user:references

# Console and debugging
rails console
rails console --sandbox  # Changes are rolled back
rails dbconsole

# Testing
rails test
rails test:system
bundle exec rspec

# Asset management
rails assets:precompile
rails assets:clean

# Routes
rails routes
rails routes --grep user
```

### **Rake Tasks**
```bash
# List available tasks
rake -T

# Run specific tasks
rake db:migrate
rake test
rake spec

# Custom tasks
rake app:setup
rake app:deploy
```

## 🚨 Ruby Testing Protocol

### **When Server Restart is Required**
- Changes to `Gemfile` or `Gemfile.lock`
- Modifications to configuration files (`config/application.rb`, environment files)
- Database migrations (sometimes requires restart)
- Changes to initializers (`config/initializers/`)
- New gem installations
- Environment variable changes

### **When Rails Auto-reloads (Development)**
- Model, controller, and view changes
- Helper modifications
- Route changes
- Most Ruby class changes in `app/` directory

### **Testing Protocol Additions**
After the universal 7-step protocol, add:

7. **[ ] Check Ruby syntax** - Run `ruby -c file.rb` for syntax validation
8. **[ ] Run RuboCop** - Check code style with `bundle exec rubocop`
9. **[ ] Verify database state** - Ensure migrations are current
10. **[ ] Test gem dependencies** - Confirm all gems load correctly
11. **[ ] Check Rails environment** - Verify correct environment configuration

## 💎 Ruby Best Practices

### **Code Style and Structure**
```ruby
# frozen_string_literal: true

# Class definition with proper documentation
# Manages user authentication and profile information
class User
  include ActiveModel::Validations
  include ActiveModel::Serialization

  # Constants
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i
  MIN_PASSWORD_LENGTH = 8

  # Attributes
  attr_accessor :name, :email, :password
  attr_reader :id, :created_at, :updated_at

  # Validations
  validates :name, presence: true, length: { minimum: 2, maximum: 50 }
  validates :email, presence: true, format: { with: VALID_EMAIL_REGEX }
  validates :password, length: { minimum: MIN_PASSWORD_LENGTH }

  # Class methods
  def self.find_by_email(email)
    # Implementation
  end

  def self.authenticate(email, password)
    user = find_by_email(email)
    user&.authenticate(password) ? user : nil
  end

  # Instance methods
  def initialize(attributes = {})
    @id = attributes[:id]
    @name = attributes[:name]
    @email = attributes[:email]
    @created_at = attributes[:created_at] || Time.now
    @updated_at = attributes[:updated_at] || Time.now
  end

  def full_name
    "#{first_name} #{last_name}".strip
  end

  def authenticate(password)
    BCrypt::Password.new(password_hash) == password
  end

  def to_hash
    {
      id: id,
      name: name,
      email: email,
      created_at: created_at,
      updated_at: updated_at
    }
  end

  private

  def generate_password_hash
    @password_hash = BCrypt::Password.create(password)
  end

  def normalize_email
    @email = email.downcase.strip if email
  end
end
```

### **Error Handling and Validation**
```ruby
# Custom exception classes
class ApplicationError < StandardError
  attr_reader :code, :message

  def initialize(message, code = nil)
    @message = message
    @code = code
    super(message)
  end
end

class ValidationError < ApplicationError; end
class NotFoundError < ApplicationError; end
class UnauthorizedError < ApplicationError; end

# Service objects with error handling
class UserRegistrationService
  include ActiveModel::Validations

  attr_accessor :name, :email, :password

  validates :name, presence: true
  validates :email, presence: true, format: { with: User::VALID_EMAIL_REGEX }
  validates :password, length: { minimum: User::MIN_PASSWORD_LENGTH }

  def initialize(params)
    @name = params[:name]
    @email = params[:email]
    @password = params[:password]
  end

  def call
    validate!
    create_user
  rescue ActiveRecord::RecordInvalid => e
    raise ValidationError, e.message
  rescue StandardError => e
    Rails.logger.error "User registration failed: #{e.message}"
    raise ApplicationError, "Registration failed"
  end

  private

  def validate!
    raise ValidationError, errors.full_messages.join(', ') unless valid?
    raise ValidationError, "Email already exists" if User.exists?(email: email)
  end

  def create_user
    User.create!(
      name: name,
      email: email.downcase,
      password: password
    )
  end
end

# Usage
begin
  user = UserRegistrationService.new(params).call
  render json: { user: user.to_hash }, status: :created
rescue ValidationError => e
  render json: { error: e.message }, status: :unprocessable_entity
rescue ApplicationError => e
  render json: { error: e.message }, status: :internal_server_error
end
```

### **Database Operations and ActiveRecord**
```ruby
# Model with proper associations and validations
class User < ApplicationRecord
  has_many :posts, dependent: :destroy
  has_many :comments, dependent: :destroy
  has_one :profile, dependent: :destroy

  validates :email, presence: true, uniqueness: { case_sensitive: false }
  validates :name, presence: true, length: { minimum: 2 }

  scope :active, -> { where(active: true) }
  scope :created_after, ->(date) { where('created_at > ?', date) }

  before_save :normalize_email
  after_create :create_profile

  def self.search(query)
    where('name ILIKE ? OR email ILIKE ?', "%#{query}%", "%#{query}%")
  end

  def deactivate!
    update!(active: false, deactivated_at: Time.current)
  end

  private

  def normalize_email
    self.email = email.downcase.strip
  end

  def create_profile
    Profile.create!(user: self)
  end
end

# Migration example
class CreateUsers < ActiveRecord::Migration[7.0]
  def change
    create_table :users do |t|
      t.string :name, null: false
      t.string :email, null: false
      t.boolean :active, default: true
      t.datetime :deactivated_at
      t.timestamps
    end

    add_index :users, :email, unique: true
    add_index :users, [:active, :created_at]
  end
end

# Advanced query patterns
class UserRepository
  def self.active_users_with_recent_posts
    User.active
        .joins(:posts)
        .where('posts.created_at > ?', 1.week.ago)
        .includes(:profile)
        .distinct
  end

  def self.find_with_stats(id)
    User.select(
      'users.*',
      'COUNT(posts.id) as posts_count',
      'COUNT(comments.id) as comments_count'
    )
    .left_joins(:posts, :comments)
    .group('users.id')
    .find(id)
  end
end
```

## 🧪 Testing with RSpec

### **Model Testing**
```ruby
# spec/models/user_spec.rb
require 'rails_helper'

RSpec.describe User, type: :model do
  let(:valid_attributes) do
    {
      name: 'John Doe',
      email: 'john@example.com',
      password: 'securepassword123'
    }
  end

  describe 'validations' do
    it 'is valid with valid attributes' do
      user = User.new(valid_attributes)
      expect(user).to be_valid
    end

    it 'is invalid without a name' do
      user = User.new(valid_attributes.except(:name))
      expect(user).not_to be_valid
      expect(user.errors[:name]).to include("can't be blank")
    end

    it 'is invalid with duplicate email' do
      User.create!(valid_attributes)
      duplicate_user = User.new(valid_attributes)

      expect(duplicate_user).not_to be_valid
      expect(duplicate_user.errors[:email]).to include('has already been taken')
    end

    it 'is invalid with short password' do
      user = User.new(valid_attributes.merge(password: '123'))
      expect(user).not_to be_valid
      expect(user.errors[:password]).to include('is too short (minimum is 8 characters)')
    end
  end

  describe 'associations' do
    it { should have_many(:posts).dependent(:destroy) }
    it { should have_many(:comments).dependent(:destroy) }
    it { should have_one(:profile).dependent(:destroy) }
  end

  describe 'scopes' do
    let!(:active_user) { User.create!(valid_attributes) }
    let!(:inactive_user) { User.create!(valid_attributes.merge(email: 'inactive@example.com', active: false)) }

    describe '.active' do
      it 'returns only active users' do
        expect(User.active).to include(active_user)
        expect(User.active).not_to include(inactive_user)
      end
    end
  end

  describe '#deactivate!' do
    let(:user) { User.create!(valid_attributes) }

    it 'sets active to false and sets deactivated_at' do
      expect { user.deactivate! }.to change(user, :active).from(true).to(false)
      expect(user.deactivated_at).to be_present
    end
  end
end
```

### **Controller Testing**
```ruby
# spec/controllers/users_controller_spec.rb
require 'rails_helper'

RSpec.describe UsersController, type: :controller do
  let(:valid_attributes) do
    {
      name: 'John Doe',
      email: 'john@example.com',
      password: 'securepassword123'
    }
  end

  describe 'POST #create' do
    context 'with valid parameters' do
      it 'creates a new user' do
        expect {
          post :create, params: { user: valid_attributes }
        }.to change(User, :count).by(1)
      end

      it 'returns created status' do
        post :create, params: { user: valid_attributes }
        expect(response).to have_http_status(:created)
      end

      it 'returns user data' do
        post :create, params: { user: valid_attributes }
        json_response = JSON.parse(response.body)
        expect(json_response['user']['name']).to eq('John Doe')
      end
    end

    context 'with invalid parameters' do
      it 'does not create a user' do
        expect {
          post :create, params: { user: { name: '' } }
        }.not_to change(User, :count)
      end

      it 'returns unprocessable entity status' do
        post :create, params: { user: { name: '' } }
        expect(response).to have_http_status(:unprocessable_entity)
      end
    end
  end

  describe 'GET #show' do
    let(:user) { User.create!(valid_attributes) }

    it 'returns user data' do
      get :show, params: { id: user.id }
      expect(response).to have_http_status(:ok)

      json_response = JSON.parse(response.body)
      expect(json_response['user']['id']).to eq(user.id)
    end

    it 'returns not found for non-existent user' do
      get :show, params: { id: 9999 }
      expect(response).to have_http_status(:not_found)
    end
  end
end
```

### **Service Testing**
```ruby
# spec/services/user_registration_service_spec.rb
require 'rails_helper'

RSpec.describe UserRegistrationService do
  let(:valid_params) do
    {
      name: 'John Doe',
      email: 'john@example.com',
      password: 'securepassword123'
    }
  end

  describe '#call' do
    context 'with valid parameters' do
      it 'creates a new user' do
        expect {
          described_class.new(valid_params).call
        }.to change(User, :count).by(1)
      end

      it 'returns the created user' do
        user = described_class.new(valid_params).call
        expect(user).to be_a(User)
        expect(user.name).to eq('John Doe')
      end
    end

    context 'with invalid parameters' do
      it 'raises ValidationError for missing name' do
        service = described_class.new(valid_params.except(:name))
        expect { service.call }.to raise_error(ValidationError)
      end

      it 'raises ValidationError for duplicate email' do
        User.create!(valid_params)
        service = described_class.new(valid_params)
        expect { service.call }.to raise_error(ValidationError, /Email already exists/)
      end
    end
  end
end
```

## 🔒 Security Best Practices

### **Parameter Sanitization**
```ruby
# Strong parameters in controllers
class UsersController < ApplicationController
  before_action :authenticate_user!, except: [:create]
  before_action :set_user, only: [:show, :update, :destroy]

  def create
    @user = User.new(user_params)

    if @user.save
      render json: { user: @user.to_hash }, status: :created
    else
      render json: { errors: @user.errors }, status: :unprocessable_entity
    end
  end

  def update
    if @user.update(user_params)
      render json: { user: @user.to_hash }
    else
      render json: { errors: @user.errors }, status: :unprocessable_entity
    end
  end

  private

  def user_params
    params.require(:user).permit(:name, :email, :password)
  end

  def set_user
    @user = User.find(params[:id])
  rescue ActiveRecord::RecordNotFound
    render json: { error: 'User not found' }, status: :not_found
  end
end
```

### **Authentication and Authorization**
```ruby
# JWT authentication
class AuthenticationService
  SECRET_KEY = Rails.application.secrets.secret_key_base

  def self.encode_token(payload)
    JWT.encode(payload, SECRET_KEY, 'HS256')
  end

  def self.decode_token(token)
    JWT.decode(token, SECRET_KEY, true, algorithm: 'HS256')[0]
  rescue JWT::DecodeError
    nil
  end

  def self.authenticate_user(token)
    decoded_token = decode_token(token)
    return nil unless decoded_token

    user_id = decoded_token['user_id']
    User.find(user_id)
  rescue ActiveRecord::RecordNotFound
    nil
  end
end

# Authorization concern
module Authorizable
  extend ActiveSupport::Concern

  included do
    before_action :authenticate_request
    before_action :authorize_user
  end

  private

  def authenticate_request
    token = request.headers['Authorization']&.split(' ')&.last
    @current_user = AuthenticationService.authenticate_user(token)

    render json: { error: 'Unauthorized' }, status: :unauthorized unless @current_user
  end

  def authorize_user
    # Override in controllers for specific authorization logic
  end

  def current_user
    @current_user
  end
end
```

### **Input Validation and Sanitization**
```ruby
# Custom validators
class EmailValidator < ActiveModel::EachValidator
  def validate_each(record, attribute, value)
    return if value.blank?

    unless value.match?(URI::MailTo::EMAIL_REGEXP)
      record.errors.add(attribute, 'is not a valid email address')
    end

    if value.length > 255
      record.errors.add(attribute, 'is too long')
    end
  end
end

# HTML sanitization
class ContentSanitizer
  def self.sanitize(content)
    ActionController::Base.helpers.sanitize(
      content,
      tags: %w[p br strong em ul ol li a],
      attributes: %w[href]
    )
  end

  def self.strip_tags(content)
    ActionController::Base.helpers.strip_tags(content)
  end
end

# SQL injection prevention (using ActiveRecord)
class UserRepository
  def self.search(query)
    # GOOD: Using parameterized queries
    User.where('name ILIKE ? OR email ILIKE ?', "%#{query}%", "%#{query}%")
  end

  def self.unsafe_search(query)
    # BAD: String interpolation (vulnerable to SQL injection)
    # User.where("name ILIKE '%#{query}%'")  # NEVER DO THIS
  end
end
```

## 🔧 Configuration and Environment Management

### **Environment Configuration**
```ruby
# config/application.rb
require_relative 'boot'

require 'rails/all'

module MyApp
  class Application < Rails::Application
    config.load_defaults 7.0

    # Custom configuration
    config.api_only = true if defined?(Rails::API)

    # CORS configuration
    config.middleware.insert_before 0, Rack::Cors do
      allow do
        origins Rails.env.production? ? ENV['ALLOWED_ORIGINS'].split(',') : '*'
        resource '*',
                 headers: :any,
                 methods: [:get, :post, :put, :patch, :delete, :options, :head],
                 credentials: true
      end
    end

    # Custom settings
    config.x.encryption_key = ENV['ENCRYPTION_KEY']
    config.x.api_rate_limit = ENV.fetch('API_RATE_LIMIT', 100).to_i
  end
end

# config/environments/production.rb
Rails.application.configure do
  config.cache_classes = true
  config.eager_load = true
  config.consider_all_requests_local = false
  config.public_file_server.enabled = true
  config.force_ssl = true
  config.log_level = :info
  config.active_record.dump_schema_after_migration = false

  # Error monitoring
  config.middleware.use ExceptionNotification::Rack,
    email: {
      email_prefix: '[ERROR] ',
      sender_address: ENV['ERROR_EMAIL_SENDER'],
      exception_recipients: ENV['ERROR_EMAIL_RECIPIENTS'].split(',')
    }
end
```

### **Secrets and Credentials Management**
```ruby
# config/credentials.yml.enc (encrypted)
# Use: rails credentials:edit

secret_key_base: xxxx
database:
  password: xxxx
api_keys:
  stripe: xxxx
  sendgrid: xxxx

# Access in application
Rails.application.credentials.database[:password]
Rails.application.credentials.api_keys[:stripe]

# Environment-specific credentials
Rails.application.credentials.dig(:database, Rails.env.to_sym, :password)
```

## 📦 Gem Management and Dependencies

### **Gemfile Best Practices**
```ruby
# Gemfile
source 'https://rubygems.org'
git_source(:github) { |repo| "https://github.com/#{repo}.git" }

ruby '3.2.0'

# Core gems
gem 'rails', '~> 7.0.0'
gem 'pg', '~> 1.4'
gem 'puma', '~> 6.0'
gem 'bootsnap', '>= 1.4.4', require: false

# Authentication & Authorization
gem 'devise', '~> 4.8'
gem 'jwt', '~> 2.7'
gem 'cancancan', '~> 3.4'

# API gems
gem 'jbuilder', '~> 2.11'
gem 'rack-cors', '~> 1.1'

# Background jobs
gem 'sidekiq', '~> 7.0'
gem 'redis', '~> 5.0'

# Monitoring and logging
gem 'sentry-ruby', '~> 5.8'
gem 'sentry-rails', '~> 5.8'

group :development, :test do
  gem 'rspec-rails', '~> 6.0'
  gem 'factory_bot_rails', '~> 6.2'
  gem 'faker', '~> 3.1'
  gem 'pry-rails', '~> 0.3'
  gem 'byebug', platforms: [:mri, :mingw, :x64_mingw]
end

group :development do
  gem 'listen', '~> 3.8'
  gem 'spring', '~> 4.1'
  gem 'spring-watcher-listen', '~> 2.1'
  gem 'rubocop', '~> 1.48', require: false
  gem 'rubocop-rails', '~> 2.17', require: false
  gem 'rubocop-rspec', '~> 2.18', require: false
end

group :test do
  gem 'shoulda-matchers', '~> 5.3'
  gem 'database_cleaner-active_record', '~> 2.0'
  gem 'webmock', '~> 3.18'
  gem 'vcr', '~> 6.1'
end
```

---

## 📚 Integration Instructions

Add this to your Ruby project's CLAUDE.md:

```markdown
# 📚 Ruby Documentation
This project follows Ruby best practices.
For detailed guidance, see: ruby.md

# Framework Information
- Ruby Version: 3.2.0
- Framework: Rails | Sinatra | Plain Ruby
- Database: PostgreSQL | MySQL | SQLite

# Additional References
- Universal patterns: universal-patterns.md
- Database operations: database-operations.md
- Security guidelines: security-guidelines.md
```

---

*This document covers Ruby development across frameworks and should be used alongside universal patterns.*