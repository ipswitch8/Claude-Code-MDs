# Nginx Web Server Administration Guide for Claude Code

## When to Use This Guide
- Nginx web server configuration and management
- Reverse proxy and load balancing setups
- High-performance web serving and caching
- SSL/TLS termination and security hardening
- Microservices and API gateway configurations

## Security-First Nginx Configuration

### Core Security Configuration
```nginx
# /etc/nginx/nginx.conf

user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

# Security settings
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    # Hide nginx version
    server_tokens off;

    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'" always;

    # Remove server information
    more_clear_headers Server;
    more_clear_headers X-Powered-By;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;

    # Request size limits
    client_max_body_size 16M;
    client_body_buffer_size 128k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 4k;

    # Timeouts
    client_body_timeout 12;
    client_header_timeout 12;
    keepalive_timeout 15;
    send_timeout 10;

    # Buffer overflow protection
    client_body_buffer_size 100K;
    client_header_buffer_size 1k;
    client_max_body_size 100k;
    large_client_header_buffers 2 1k;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging format with security information
    log_format security '$remote_addr - $remote_user [$time_local] '
                       '"$request" $status $body_bytes_sent '
                       '"$http_referer" "$http_user_agent" '
                       '$request_time $upstream_response_time '
                       '"$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log security;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
```

### SSL/TLS Security Configuration
```nginx
# /etc/nginx/snippets/ssl-params.conf

# Modern SSL configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;

# SSL session settings
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;

# OCSP stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;

# DH parameters
ssl_dhparam /etc/nginx/dhparam.pem;

# Security headers for HTTPS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# /etc/nginx/snippets/ssl-certificates.conf
ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;
```

### Request Filtering and Protection
```nginx
# /etc/nginx/snippets/security-rules.conf

# Block common attack patterns
location ~* \.(php|aspx|asp|jsp)$ {
    deny all;
    return 444;
}

# Block access to sensitive files
location ~* \.(htaccess|htpasswd|ini|log|sh|sql|conf)$ {
    deny all;
    return 444;
}

# Block access to version control directories
location ~ /\.(git|svn|hg|bzr) {
    deny all;
    return 444;
}

# Block access to backup and temporary files
location ~* \.(bak|backup|old|orig|tmp|temp|~)$ {
    deny all;
    return 444;
}

# Block suspicious user agents
if ($http_user_agent ~* (nmap|nikto|wikto|sf|sqlmap|bsqlbf|w3af|acunetix|havij|appscan)) {
    return 444;
}

# Block bad bots
if ($http_user_agent ~* (360Spider|80legs|Aboundex|Abonti|Acunetix|^AIBOT|^Alexibot|Alligator|AllSubmitter|Apexoo|^asterias|^attach|^BackDoorBot|^BackWeb|^BAD|Bandit|^BatchFTP|^Bigfoot|^Black.Hole|^BlackWidow|^BlowFish|^BotALot|Buddy|^BuiltBotTough|^Bullseye|^BunnySlippers|^Cegbfeieh|^CheeseBot|^CherryPicker|^ChinaClaw|Collector|Copier|^CopyRightCheck|^cosmos|^Crescent|^Custo|^DEMON|^DISCo|^DIIbot|^DittoSpyder|^Download\.Demon|^Download\.Devil|^Download\.Wonder|^dragonfly|^Drip|^eCatch|^EasyDL|^ebingbong|^EirGrabber|^EmailCollector|^EmailSiphon|^EmailWolf|^Express\.WebPictures|Extract|^EyeNetIE|^Eyeotine|^FairAd|^FlashGet|^flunky|^frontpage|^GetRight|^GetWeb!|^Go!Zilla|^Go-Ahead-Got-It|^GrabNet|^Grafula|^GREEN\.ROBOT|^Harvest|^hloader|^HMView|^HTTrack|^ia_archiver|^Image\.Stripper|^Image\.Sucker|^InterGET|^Internet\.Ninja|^InternetSeer\.com|^Iria|^Jakarta|^JetCar|^JOC|^JustView|^Jyxobot|^Kenjin\.Spider|^Keyword\.Density|^larbin|^LeechFTP|^LexiBot|^lftp|^libWeb|^likse|^LinkextractorPro|^LinkScan/8\.1a\.Unix|^LNSpiderguy|^LocalLink|^lwp-trivial|^LWP::Simple|^Magnet|^Mag-Net|^MarkWatch|^Mass\.Downloader|^Mata\.Hari|^Memo|^MIIxpc|^Mirror|^Missigua\.Locator|^Mister\.PiX|^moget|^Mozilla.*NEWT|^NAMEPROTECT|^Navroad|^NearSite|^NetAnts|^Netcraft|^NetMechanic|^NetSpider|^Net\.Vampire|^NetZIP|^NextGenSearchBot|^NG|^NICErsPRO|^NimbleCrawler|^Ninja|^NPbot|^Octopus|^Offline\.Explorer|^Offline\.Navigator|^Openfind|^OutfoxBot|^PageGrabber|^Papa\.Foto|^pavuk|^pcBrowser|^PeoplePal|^planetwork|^Platform|^psbot|^purebot|^pycurl|^QueryN\.Metasearch|^RealDownload|^Reaper|^Recorder|^ReGet|^RepoMonkey|^RMA|^roach|^RobotEmails|^SBIDer|^ScoutJet|^Script|^Siphon|^SiteSnagger|^SlySearch|^SmartDownload|^Snake|^Snapbot|^Snoopy|^sogou|^SpaceBison|^spanhews|^SpankBot|^spanner|^Sqworm|^Stripper|^Sucker|^SuperBot|^SuperHTTP|^Surfbot|^suzuran|^Szukacz|^Teleport|^Telesoft|^TurnitinBot|^Union\.Operator|^UrlDispatcher|^Vacuum|^VCI|^VoidEYE|^Web\.Image\.Collector|^Web\.Sucker|^WebAuto|^WebBandit|^WebCopier|^WebEMailExtrac.*|^WebEnhancer|^WebFetch|^WebGo\.IS|^WebLeacher|^WebMasterWorldForumBot|^webmirror|^WebReaper|^WebSauger|^Website\.eXtractor|^Website\.Quester|^WebStripper|^WebWhacker|^WebZIP|^Whacker|^Widow|^WWWOFFLE|^x-Tractor|^Xaldon|^Zeus)) {
    return 444;
}

# Prevent image hotlinking
location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
    valid_referers none blocked server_names *.yourdomain.com yourdomain.com;
    if ($invalid_referer) {
        return 403;
    }
}
```

## Performance Optimization

### Caching Configuration
```nginx
# /etc/nginx/snippets/cache-params.conf

# Browser caching
location ~* \.(jpg|jpeg|png|gif|ico|svg)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    add_header Vary Accept-Encoding;
    access_log off;
}

location ~* \.(css|js)$ {
    expires 1y;
    add_header Cache-Control "public";
    add_header Vary Accept-Encoding;
    access_log off;
}

location ~* \.(woff|woff2|ttf|eot)$ {
    expires 1y;
    add_header Cache-Control "public";
    access_log off;
}

# Proxy caching
proxy_cache_path /var/cache/nginx/app levels=1:2 keys_zone=app_cache:10m max_size=1g
                 inactive=60m use_temp_path=off;

upstream backend {
    server 127.0.0.1:3000;
    server 127.0.0.1:3001 backup;
    keepalive 32;
}

server {
    location / {
        proxy_cache app_cache;
        proxy_cache_valid 200 302 10m;
        proxy_cache_valid 404 1m;
        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
        proxy_cache_lock on;
        proxy_cache_background_update on;

        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        add_header X-Cache-Status $upstream_cache_status;
    }
}
```

### Load Balancing and High Availability
```nginx
# /etc/nginx/conf.d/load-balancer.conf

upstream backend_pool {
    least_conn;
    server 192.168.1.10:80 max_fails=3 fail_timeout=30s;
    server 192.168.1.11:80 max_fails=3 fail_timeout=30s;
    server 192.168.1.12:80 max_fails=3 fail_timeout=30s;
    server 192.168.1.13:80 backup;
}

upstream api_pool {
    ip_hash;
    server 192.168.1.20:8080 weight=3;
    server 192.168.1.21:8080 weight=2;
    server 192.168.1.22:8080 weight=1;
}

# Health checks (nginx plus feature, alternative with nginx_upstream_check_module)
upstream backend_with_health {
    server 192.168.1.10:80 max_fails=3 fail_timeout=30s;
    server 192.168.1.11:80 max_fails=3 fail_timeout=30s;

    # Custom health check endpoint
    check interval=3000 rise=2 fall=5 timeout=1000 type=http;
    check_http_send "HEAD /health HTTP/1.0\r\n\r\n";
    check_http_expect_alive http_2xx http_3xx;
}
```

## Security Monitoring and Logging

### Advanced Logging Configuration
```nginx
# /etc/nginx/nginx.conf

http {
    # Custom log formats
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                   '$status $body_bytes_sent "$http_referer" '
                   '"$http_user_agent" "$http_x_forwarded_for"';

    log_format security '$time_iso8601 $remote_addr $remote_user $request_method '
                       '$scheme $server_name $uri $args $status $body_bytes_sent '
                       '$request_time $upstream_response_time "$http_referer" '
                       '"$http_user_agent" "$http_x_forwarded_for"';

    log_format json_logs escape=json '{'
                        '"timestamp":"$time_iso8601",'
                        '"remote_addr":"$remote_addr",'
                        '"request_method":"$request_method",'
                        '"request_uri":"$request_uri",'
                        '"status":$status,'
                        '"body_bytes_sent":$body_bytes_sent,'
                        '"request_time":$request_time,'
                        '"upstream_response_time":"$upstream_response_time",'
                        '"http_referer":"$http_referer",'
                        '"http_user_agent":"$http_user_agent",'
                        '"http_x_forwarded_for":"$http_x_forwarded_for"'
                        '}';

    access_log /var/log/nginx/access.log json_logs;
    error_log /var/log/nginx/error.log warn;
}
```

### Rate Limiting and DDoS Protection
```nginx
# /etc/nginx/conf.d/rate-limiting.conf

# Define rate limiting zones
limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=search:10m rate=5r/s;
limit_req_zone $server_name zone=perserver:10m rate=100r/s;

# Connection limiting
limit_conn_zone $binary_remote_addr zone=addr:10m;
limit_conn_zone $server_name zone=perip:10m;

server {
    # Apply rate limits
    location /login {
        limit_req zone=login burst=5 nodelay;
        limit_conn addr 5;

        # Additional security for login
        access_log /var/log/nginx/login_attempts.log security;

        proxy_pass http://backend;
    }

    location /api/ {
        limit_req zone=api burst=20 nodelay;
        limit_conn addr 10;

        proxy_pass http://api_pool;
    }

    location /search {
        limit_req zone=search burst=10;

        proxy_pass http://backend;
    }

    # Global connection limit
    limit_conn perip 20;
}
```

### Security Headers and Content Security Policy
```nginx
# /etc/nginx/snippets/security-headers.conf

# Security headers
add_header X-Frame-Options "DENY" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header X-Download-Options "noopen" always;
add_header X-Permitted-Cross-Domain-Policies "none" always;

# Content Security Policy
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;

# HSTS (HTTP Strict Transport Security)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Remove server information
more_clear_headers Server;
more_clear_headers X-Powered-By;
more_clear_headers X-AspNet-Version;
more_clear_headers X-AspNetMvc-Version;
```

## Virtual Host Templates

### Production Virtual Host with SSL
```nginx
# /etc/nginx/sites-available/production.example.com

server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://example.com$request_uri;
}

server {
    listen 443 ssl http2;
    server_name www.example.com;
    return 301 https://example.com$request_uri;

    include /etc/nginx/snippets/ssl-certificates.conf;
    include /etc/nginx/snippets/ssl-params.conf;
}

server {
    listen 443 ssl http2;
    server_name example.com;

    root /var/www/example.com/public;
    index index.html index.php;

    # SSL configuration
    include /etc/nginx/snippets/ssl-certificates.conf;
    include /etc/nginx/snippets/ssl-params.conf;

    # Security configuration
    include /etc/nginx/snippets/security-headers.conf;
    include /etc/nginx/snippets/security-rules.conf;

    # Rate limiting
    limit_req zone=api burst=20 nodelay;
    limit_conn addr 10;

    # Logging
    access_log /var/log/nginx/example.com_access.log security;
    error_log /var/log/nginx/example.com_error.log;

    # Main location
    location / {
        try_files $uri $uri/ /index.php$is_args$args;
    }

    # PHP processing
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;

        # PHP security
        fastcgi_hide_header X-Powered-By;
    }

    # Static files caching
    include /etc/nginx/snippets/cache-params.conf;

    # Deny access to sensitive files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    location ~ ~$ {
        deny all;
        access_log off;
        log_not_found off;
    }
}
```

### API Gateway Configuration
```nginx
# /etc/nginx/sites-available/api.example.com

upstream auth_service {
    server 127.0.0.1:3001;
    server 127.0.0.1:3002 backup;
}

upstream user_service {
    server 127.0.0.1:3003;
    server 127.0.0.1:3004 backup;
}

upstream payment_service {
    server 127.0.0.1:3005;
    server 127.0.0.1:3006 backup;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;

    include /etc/nginx/snippets/ssl-certificates.conf;
    include /etc/nginx/snippets/ssl-params.conf;
    include /etc/nginx/snippets/security-headers.conf;

    # API-specific security headers
    add_header X-API-Version "v1" always;

    # Global rate limiting for API
    limit_req zone=api burst=50 nodelay;
    limit_conn addr 20;

    # Logging for API calls
    access_log /var/log/nginx/api_access.log json_logs;
    error_log /var/log/nginx/api_error.log;

    # Authentication endpoint
    location /auth/ {
        limit_req zone=login burst=10 nodelay;

        proxy_pass http://auth_service/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Short timeout for auth
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
    }

    # User service
    location /users/ {
        proxy_pass http://user_service/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Caching for read operations
        proxy_cache app_cache;
        proxy_cache_valid 200 5m;
        proxy_cache_methods GET HEAD;
        proxy_cache_key "$scheme$request_method$host$request_uri";
    }

    # Payment service (extra security)
    location /payments/ {
        limit_req zone=login burst=5 nodelay;

        # Allow only specific methods
        limit_except GET POST {
            deny all;
        }

        proxy_pass http://payment_service/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # No caching for payments
        proxy_cache off;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }

    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
```

## Monitoring and Alerting

### Nginx Status Monitoring
```nginx
# /etc/nginx/sites-available/monitoring

server {
    listen 127.0.0.1:8080;
    server_name localhost;

    location /nginx_status {
        stub_status on;
        access_log off;
        allow 127.0.0.1;
        allow 192.168.1.0/24;
        deny all;
    }

    location /health {
        access_log off;
        return 200 "nginx is running\n";
        add_header Content-Type text/plain;
    }
}
```

### Log Analysis and Alerting
```bash
#!/bin/bash
# nginx-security-monitor.sh

LOG_FILE="/var/log/nginx/access.log"
ERROR_LOG="/var/log/nginx/error.log"
ALERT_EMAIL="admin@example.com"
TEMP_DIR="/tmp/nginx-monitor"

mkdir -p $TEMP_DIR

# Check for 4xx/5xx errors
awk '$9 ~ /^4/ || $9 ~ /^5/ {print $1, $9, $7}' $LOG_FILE | sort | uniq -c | sort -nr > $TEMP_DIR/errors.log

# Check for potential attacks
grep -E "(sqlmap|nikto|nmap|\.php\?|union.*select|script.*alert)" $LOG_FILE > $TEMP_DIR/attacks.log

# Check for rate limit violations
grep "limiting requests" $ERROR_LOG > $TEMP_DIR/rate_limits.log

# Check for unusual user agents
awk -F'"' '{print $6}' $LOG_FILE | sort | uniq -c | sort -nr | head -20 > $TEMP_DIR/user_agents.log

# Check for large number of requests from single IP
awk '{print $1}' $LOG_FILE | sort | uniq -c | sort -nr | awk '$1 > 1000 {print}' > $TEMP_DIR/high_volume_ips.log

# Generate alert if issues found
if [ -s $TEMP_DIR/attacks.log ] || [ -s $TEMP_DIR/rate_limits.log ] || [ -s $TEMP_DIR/high_volume_ips.log ]; then
    {
        echo "Nginx Security Alert - $(date)"
        echo "=================================="
        echo
        echo "Potential Attacks:"
        head -10 $TEMP_DIR/attacks.log
        echo
        echo "Rate Limit Violations:"
        head -10 $TEMP_DIR/rate_limits.log
        echo
        echo "High Volume IPs:"
        head -10 $TEMP_DIR/high_volume_ips.log
        echo
        echo "Top Errors:"
        head -10 $TEMP_DIR/errors.log
    } | mail -s "Nginx Security Alert" $ALERT_EMAIL
fi
```

### Performance Monitoring Script
```bash
#!/bin/bash
# nginx-performance-monitor.sh

# Nginx status metrics
curl -s http://localhost:8080/nginx_status | {
    read active_connections_line
    read server_accepts_handled_requests
    read reading_writing_waiting

    active_connections=$(echo $active_connections_line | awk '{print $3}')
    accepts=$(echo $server_accepts_handled_requests | awk '{print $1}')
    handled=$(echo $server_accepts_handled_requests | awk '{print $2}')
    requests=$(echo $server_accepts_handled_requests | awk '{print $3}')
    reading=$(echo $reading_writing_waiting | awk '{print $2}')
    writing=$(echo $reading_writing_waiting | awk '{print $4}')
    waiting=$(echo $reading_writing_waiting | awk '{print $6}')

    echo "Active Connections: $active_connections"
    echo "Accepts: $accepts"
    echo "Handled: $handled"
    echo "Requests: $requests"
    echo "Reading: $reading"
    echo "Writing: $writing"
    echo "Waiting: $waiting"
}

# Response time monitoring
curl -w "@curl-format.txt" -o /dev/null -s "https://example.com/"

# SSL certificate monitoring
echo | openssl s_client -servername example.com -connect example.com:443 2>/dev/null | openssl x509 -noout -dates

# Log file sizes
du -h /var/log/nginx/
```

## Backup and Disaster Recovery

### Configuration Backup
```bash
#!/bin/bash
# nginx-backup.sh

BACKUP_DIR="/backup/nginx/$(date +%Y%m%d_%H%M%S)"
mkdir -p $BACKUP_DIR

# Backup Nginx configuration
tar -czf $BACKUP_DIR/nginx-config.tar.gz /etc/nginx/

# Backup SSL certificates
tar -czf $BACKUP_DIR/ssl-certs.tar.gz /etc/letsencrypt/ /etc/ssl/

# Backup website files
tar -czf $BACKUP_DIR/www-data.tar.gz /var/www/

# Backup logs (last 7 days)
find /var/log/nginx/ -name "*.log" -mtime -7 | tar -czf $BACKUP_DIR/nginx-logs.tar.gz -T -

# Create checksums
find $BACKUP_DIR -name "*.tar.gz" -exec sha256sum {} \; > $BACKUP_DIR/checksums.sha256

echo "Backup completed: $BACKUP_DIR"
```

### Auto-renewal and Configuration Testing
```bash
#!/bin/bash
# nginx-maintenance.sh

# Test configuration before reload
nginx -t
if [ $? -eq 0 ]; then
    echo "Configuration test passed"
    systemctl reload nginx
    echo "Nginx reloaded successfully"
else
    echo "Configuration test failed - NOT reloading"
    exit 1
fi

# SSL certificate renewal (with Let's Encrypt)
certbot renew --quiet --no-self-upgrade --post-hook "systemctl reload nginx"

# Log rotation
logrotate -f /etc/logrotate.d/nginx

echo "Maintenance completed: $(date)"
```

This comprehensive Nginx administration guide provides security-first configuration, performance optimization, monitoring, and disaster recovery capabilities for production environments.

*This document covers Nginx administration best practices and should be used alongside universal patterns. For consolidated security guidance, see security-guidelines.md.*