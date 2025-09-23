# Apache HTTP Server Administration Guide for Claude Code

## When to Use This Guide
- Apache web server configuration and management
- Multi-site hosting environments
- Performance optimization and security hardening
- SSL/TLS certificate management
- DevOps and production deployment scenarios

## Security-First Apache Configuration

### Core Security Configuration
```apache
# /etc/apache2/apache2.conf or httpd.conf

# Hide Apache version and OS information
ServerTokens Prod
ServerSignature Off

# Disable server-status and server-info by default
<Location "/server-status">
    Require all denied
</Location>
<Location "/server-info">
    Require all denied
</Location>

# Prevent access to .htaccess and other sensitive files
<FilesMatch "^\.">
    Require all denied
</FilesMatch>

# Prevent access to backup and temporary files
<FilesMatch "\.(bak|backup|old|tmp|temp|log|orig|save|~)$">
    Require all denied
</FilesMatch>

# Disable directory browsing
Options -Indexes -Includes -ExecCGI

# Security headers (requires mod_headers)
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Content-Security-Policy "default-src 'self'"

# Remove sensitive headers
Header unset Server
Header unset X-Powered-By
```

### SSL/TLS Hardening
```apache
# /etc/apache2/sites-available/ssl.conf

<IfModule mod_ssl.c>
    # Modern SSL configuration
    SSLEngine on
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder off
    SSLSessionTickets off

    # OCSP Stapling
    SSLUseStapling on
    SSLStaplingCache "shmcb:logs/stapling-cache(150000)"

    # Certificate files
    SSLCertificateFile /path/to/certificate.crt
    SSLCertificateKeyFile /path/to/private.key
    SSLCertificateChainFile /path/to/chain.crt

    # Security headers for HTTPS
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>

# Redirect HTTP to HTTPS
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    Redirect permanent / https://example.com/
</VirtualHost>
```

### File Upload Security
```apache
# Restrict file uploads
<Directory "/var/www/uploads">
    # Disable script execution
    Options -ExecCGI
    AddHandler cgi-script .php .pl .py .jsp .asp .sh

    # File size limits
    LimitRequestBody 10485760  # 10MB limit

    # File type restrictions
    <FilesMatch "\.(php|phtml|php3|php4|php5|pl|py|jsp|asp|sh|cgi)$">
        Require all denied
    </FilesMatch>
</Directory>

# Upload timeout settings
Timeout 60
KeepAliveTimeout 5
```

## Performance Optimization

### Caching Configuration
```apache
# Enable caching modules
LoadModule expires_module modules/mod_expires.so
LoadModule headers_module modules/mod_headers.so

# Browser caching
<IfModule mod_expires.c>
    ExpiresActive On

    # Images
    ExpiresByType image/jpg "access plus 1 month"
    ExpiresByType image/jpeg "access plus 1 month"
    ExpiresByType image/gif "access plus 1 month"
    ExpiresByType image/png "access plus 1 month"
    ExpiresByType image/webp "access plus 1 month"
    ExpiresByType image/svg+xml "access plus 1 month"

    # CSS and JavaScript
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
    ExpiresByType text/javascript "access plus 1 month"

    # Fonts
    ExpiresByType font/woff "access plus 1 year"
    ExpiresByType font/woff2 "access plus 1 year"
    ExpiresByType application/font-woff "access plus 1 year"

    # Default
    ExpiresDefault "access plus 2 days"
</IfModule>

# Compression
<IfModule mod_deflate.c>
    # Compress HTML, CSS, JavaScript, Text, XML and fonts
    AddOutputFilterByType DEFLATE application/javascript
    AddOutputFilterByType DEFLATE application/rss+xml
    AddOutputFilterByType DEFLATE application/vnd.ms-fontobject
    AddOutputFilterByType DEFLATE application/x-font
    AddOutputFilterByType DEFLATE application/x-font-opentype
    AddOutputFilterByType DEFLATE application/x-font-otf
    AddOutputFilterByType DEFLATE application/x-font-truetype
    AddOutputFilterByType DEFLATE application/x-font-ttf
    AddOutputFilterByType DEFLATE application/x-javascript
    AddOutputFilterByType DEFLATE application/xhtml+xml
    AddOutputFilterByType DEFLATE application/xml
    AddOutputFilterByType DEFLATE font/opentype
    AddOutputFilterByType DEFLATE font/otf
    AddOutputFilterByType DEFLATE font/ttf
    AddOutputFilterByType DEFLATE image/svg+xml
    AddOutputFilterByType DEFLATE image/x-icon
    AddOutputFilterByType DEFLATE text/css
    AddOutputFilterByType DEFLATE text/html
    AddOutputFilterByType DEFLATE text/javascript
    AddOutputFilterByType DEFLATE text/plain
    AddOutputFilterByType DEFLATE text/xml

    # Remove browser bugs (only needed for really old browsers)
    BrowserMatch ^Mozilla/4 gzip-only-text/html
    BrowserMatch ^Mozilla/4\.0[678] no-gzip
    BrowserMatch \bMSIE !no-gzip !gzip-only-text/html
    Header append Vary User-Agent
</IfModule>
```

### Connection Optimization
```apache
# /etc/apache2/mods-available/mpm_prefork.conf
<IfModule mpm_prefork_module>
    StartServers             8
    MinSpareServers          5
    MaxSpareServers         20
    ServerLimit            256
    MaxRequestWorkers      256
    MaxConnectionsPerChild   0
</IfModule>

# /etc/apache2/mods-available/mpm_worker.conf
<IfModule mpm_worker_module>
    StartServers             3
    MinSpareThreads         75
    MaxSpareThreads        250
    ThreadsPerChild         25
    MaxRequestWorkers      400
    MaxConnectionsPerChild   0
</IfModule>

# Keep-Alive settings
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5
```

## Security Monitoring and Logging

### Comprehensive Logging
```apache
# Custom log format with security fields
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\" %D %{X-Forwarded-For}i" combined_security

# Security-focused log format
LogFormat "%t %h \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"%{X-Forwarded-For}i\"" security

# Separate logs for different purposes
ErrorLog ${APACHE_LOG_DIR}/error.log
CustomLog ${APACHE_LOG_DIR}/access.log combined_security
CustomLog ${APACHE_LOG_DIR}/security.log security

# Log level for security monitoring
LogLevel warn ssl:warn

# Rotate logs
ErrorLogFormat "[%{u}t] [%-m:%l] [pid %P:tid %T] %7F: %E: [client\ %a] %M% ,\ referer\ %{Referer}i"
```

### Security Module Configuration
```apache
# mod_security (if available)
<IfModule mod_security2.c>
    SecRuleEngine On
    SecRequestBodyAccess On
    SecRule REQUEST_HEADERS:Content-Type "text/xml" \
         "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
    SecRequestBodyLimit 13107200
    SecRequestBodyNoFilesLimit 131072
    SecRequestBodyInMemoryLimit 131072
    SecRequestBodyLimitAction Reject
    SecRule REQBODY_ERROR "!@eq 0" \
    "id:'200001', phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'%{reqbody_error_msg}',severity:2"
    SecRuleRemoveById 960335
    SecDefaultAction "phase:2,deny,log,status:406"
    SecRule &REQUEST_HEADERS:Host "@eq 0" \
         "id:960008,phase:2,rev:2,ver:'OWASP_CRS/2.2.9',maturity:9,accuracy:9,block,msg:'Request Missing a Host Header',logdata:'%{MATCHED_VAR}',severity:'4',id:960008,tag:'OWASP_CRS/PROTOCOL_VIOLATION/MISSING_HEADER_HOST',tag:'WASCTC/WASC-21',tag:'OWASP_TOP_10/A7',tag:'PCI/6.5.10',setvar:'tx.msg=%{rule.msg}',setvar:tx.anomaly_score=+%{tx.notice_anomaly_score},setvar:tx.protocol_violation_score=+%{tx.notice_anomaly_score},setvar:tx.%{rule.id}-OWASP_CRS/PROTOCOL_VIOLATION/MISSING_HEADER-%{matched_var_name}=%{matched_var}"
</IfModule>

# mod_evasive (DDoS protection)
<IfModule mod_evasive24.c>
    DOSHashTableSize    2048
    DOSPageCount        2
    DOSPageInterval     1
    DOSSiteCount        50
    DOSSiteInterval     1
    DOSBlockingPeriod   600
    DOSLogDir           "/var/log/apache2"
    DOSEmailNotify      admin@example.com
</IfModule>
```

## Virtual Host Security Templates

### Production Virtual Host
```apache
<VirtualHost *:443>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /var/www/example.com/public

    # SSL Configuration
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/example.com.crt
    SSLCertificateKeyFile /etc/ssl/private/example.com.key
    SSLCertificateChainFile /etc/ssl/certs/intermediate.crt

    # Security headers
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"

    # Directory protection
    <Directory /var/www/example.com/public>
        Options -Indexes -Includes +FollowSymLinks
        AllowOverride FileInfo Options
        Require all granted

        # PHP security (if using PHP)
        <FilesMatch "\.php$">
            SetHandler application/x-httpd-php
        </FilesMatch>
    </Directory>

    # Deny access to sensitive directories
    <DirectoryMatch "/(\.git|\.svn|config|logs|temp|cache)">
        Require all denied
    </DirectoryMatch>

    # Custom error pages
    ErrorDocument 404 /error/404.html
    ErrorDocument 500 /error/500.html

    # Logging
    ErrorLog ${APACHE_LOG_DIR}/example.com_error.log
    CustomLog ${APACHE_LOG_DIR}/example.com_access.log combined_security
</VirtualHost>
```

### Development Virtual Host
```apache
<VirtualHost *:80>
    ServerName dev.example.com
    DocumentRoot /var/www/dev.example.com/public

    # Development-specific settings
    <Directory /var/www/dev.example.com/public>
        Options +Indexes +FollowSymLinks
        AllowOverride All
        Require ip 192.168.1.0/24
        Require ip 10.0.0.0/8
        Require ip 127.0.0.1
    </Directory>

    # Enable server-status for development
    <Location "/server-status">
        SetHandler server-status
        Require ip 127.0.0.1
        Require ip 192.168.1.0/24
    </Location>

    # Development logging (more verbose)
    LogLevel info ssl:warn
    ErrorLog ${APACHE_LOG_DIR}/dev.example.com_error.log
    CustomLog ${APACHE_LOG_DIR}/dev.example.com_access.log combined
</VirtualHost>
```

## Security Hardening Checklist

### Server Hardening
```bash
# 1. Update Apache and modules
sudo apt update && sudo apt upgrade apache2

# 2. Disable unnecessary modules
sudo a2dismod cgi
sudo a2dismod userdir
sudo a2dismod autoindex
sudo a2dismod status
sudo a2dismod info

# 3. Enable security modules
sudo a2enmod headers
sudo a2enmod ssl
sudo a2enmod rewrite
sudo a2enmod deflate

# 4. Set proper file permissions
sudo chown -R www-data:www-data /var/www/
sudo find /var/www/ -type d -exec chmod 755 {} \;
sudo find /var/www/ -type f -exec chmod 644 {} \;

# 5. Secure Apache configuration files
sudo chmod 644 /etc/apache2/apache2.conf
sudo chmod 644 /etc/apache2/sites-available/*
sudo chown root:root /etc/apache2/apache2.conf
```

### File System Protection
```apache
# Prevent access to version control files
<DirectoryMatch "/(\.git|\.svn|\.hg|\.bzr|CVS)">
    Require all denied
</DirectoryMatch>

# Prevent access to backup files
<FilesMatch "\.(bak|backup|old|tmp|temp|orig|save|~)$">
    Require all denied
</FilesMatch>

# Prevent access to configuration files
<FilesMatch "\.(conf|ini|log|yml|yaml|json)$">
    Require all denied
</FilesMatch>

# Prevent execution of uploaded files
<Directory "/var/www/uploads">
    <FilesMatch "\.(php|phtml|php3|php4|php5|pl|py|jsp|asp|sh|cgi)$">
        Require all denied
    </FilesMatch>
    Options -ExecCGI
    AddHandler text/plain .php .phtml .php3 .php4 .php5 .pl .py .jsp .asp .sh .cgi
</Directory>
```

## Monitoring and Alerting

### Log Analysis Scripts
```bash
#!/bin/bash
# security-monitor.sh - Basic Apache security monitoring

LOG_FILE="/var/log/apache2/access.log"
ALERT_EMAIL="admin@example.com"
TEMP_DIR="/tmp/apache-monitor"

mkdir -p $TEMP_DIR

# Check for common attack patterns
grep -E "(sqlmap|nikto|nmap|phpMyAdmin|\.php\?|union.*select|script.*alert)" $LOG_FILE > $TEMP_DIR/attacks.log

# Check for excessive 404s (potential scanning)
awk '$9 == 404 {print $1}' $LOG_FILE | sort | uniq -c | awk '$1 > 50 {print $2 " - " $1 " 404 errors"}' > $TEMP_DIR/scan_attempts.log

# Check for large POST requests
awk '$6 == "POST" && $10 > 1000000 {print $1 " - " $10 " bytes"}' $LOG_FILE > $TEMP_DIR/large_posts.log

# Send alerts if issues found
if [ -s $TEMP_DIR/attacks.log ] || [ -s $TEMP_DIR/scan_attempts.log ] || [ -s $TEMP_DIR/large_posts.log ]; then
    {
        echo "Apache Security Alert - $(date)"
        echo "=================================="
        echo
        echo "Attack Patterns Detected:"
        cat $TEMP_DIR/attacks.log
        echo
        echo "Potential Scanning Activity:"
        cat $TEMP_DIR/scan_attempts.log
        echo
        echo "Large POST Requests:"
        cat $TEMP_DIR/large_posts.log
    } | mail -s "Apache Security Alert" $ALERT_EMAIL
fi
```

### Real-time Monitoring
```bash
# Install and configure fail2ban for Apache
sudo apt install fail2ban

# /etc/fail2ban/jail.local
[apache-auth]
enabled = true
port = http,https
logpath = /var/log/apache2/error.log
maxretry = 3
bantime = 3600

[apache-badbots]
enabled = true
port = http,https
logpath = /var/log/apache2/access.log
maxretry = 2
bantime = 86400

[apache-noscript]
enabled = true
port = http,https
logpath = /var/log/apache2/access.log
maxretry = 6
bantime = 86400
```

## Performance Monitoring

### Server Status Monitoring
```apache
# Enable mod_status securely
<IfModule mod_status.c>
    <Location "/server-status">
        SetHandler server-status
        Require ip 127.0.0.1
        Require ip 192.168.1.0/24  # Your admin network
    </Location>

    <Location "/server-info">
        SetHandler server-info
        Require ip 127.0.0.1
        Require ip 192.168.1.0/24  # Your admin network
    </Location>
</IfModule>
```

### Performance Metrics Collection
```bash
#!/bin/bash
# apache-metrics.sh - Collect Apache performance metrics

# CPU and Memory usage
ps aux | grep apache2 | awk '{cpu+=$3; mem+=$4} END {print "CPU: " cpu "%, Memory: " mem "%"}'

# Active connections
ss -tuln | grep :80 | wc -l
ss -tuln | grep :443 | wc -l

# Response time check
curl -w "@curl-format.txt" -o /dev/null -s "http://localhost/"

# Log file sizes
du -h /var/log/apache2/

# Apache server status
curl -s http://localhost/server-status?auto | grep -E "(Total Accesses|Total kBytes|CPULoad|Uptime|ReqPerSec|BytesPerSec|BytesPerReq)"
```

## Backup and Recovery

### Configuration Backup
```bash
#!/bin/bash
# apache-backup.sh - Backup Apache configuration

BACKUP_DIR="/backup/apache/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# Backup configuration files
tar -czf $BACKUP_DIR/apache-config.tar.gz /etc/apache2/

# Backup SSL certificates
tar -czf $BACKUP_DIR/ssl-certs.tar.gz /etc/ssl/

# Backup website files
tar -czf $BACKUP_DIR/www-data.tar.gz /var/www/

# Create checksums
find $BACKUP_DIR -name "*.tar.gz" -exec sha256sum {} \; > $BACKUP_DIR/checksums.sha256

echo "Backup completed: $BACKUP_DIR"
```

### Disaster Recovery
```bash
#!/bin/bash
# apache-restore.sh - Restore Apache from backup

BACKUP_DIR="$1"

if [ -z "$BACKUP_DIR" ]; then
    echo "Usage: $0 /path/to/backup"
    exit 1
fi

# Verify checksums
cd $BACKUP_DIR && sha256sum -c checksums.sha256

# Stop Apache
sudo systemctl stop apache2

# Restore configuration
sudo tar -xzf $BACKUP_DIR/apache-config.tar.gz -C /

# Restore SSL certificates
sudo tar -xzf $BACKUP_DIR/ssl-certs.tar.gz -C /

# Restore website files
sudo tar -xzf $BACKUP_DIR/www-data.tar.gz -C /

# Test configuration
sudo apache2ctl configtest

# Start Apache
sudo systemctl start apache2

echo "Restore completed"
```

This guide provides comprehensive Apache administration with security-first principles, performance optimization, and robust monitoring capabilities for production environments.