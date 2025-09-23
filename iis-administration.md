# IIS (Internet Information Services) Administration Guide for Claude Code

## When to Use This Guide
- Windows Server environments with IIS
- ASP.NET, ASP.NET Core, and PHP applications on Windows
- Enterprise Windows-based web hosting
- Integration with Active Directory and Windows authentication
- Legacy application hosting and migration scenarios

## Security-First IIS Configuration

### Core Security Configuration
```xml
<!-- web.config - Global security settings -->
<configuration>
  <system.web>
    <!-- Remove version information -->
    <httpRuntime enableVersionHeader="false" />

    <!-- Session security -->
    <httpCookies httpOnlyCookies="true" requireSSL="true" sameSite="Lax" />

    <!-- Request limits -->
    <httpRuntime maxRequestLength="51200" executionTimeout="110" />
  </system.web>

  <system.webServer>
    <!-- Remove server header -->
    <httpProtocol>
      <customHeaders>
        <remove name="Server" />
        <add name="X-Content-Type-Options" value="nosniff" />
        <add name="X-Frame-Options" value="DENY" />
        <add name="X-XSS-Protection" value="1; mode=block" />
        <add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
        <add name="Content-Security-Policy" value="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'" />
      </customHeaders>
    </httpProtocol>

    <!-- Request filtering -->
    <security>
      <requestFiltering>
        <requestLimits maxAllowedContentLength="52428800" />
        <fileExtensions>
          <remove fileExtension=".config" />
          <remove fileExtension=".log" />
          <remove fileExtension=".txt" />
          <add fileExtension=".config" allowed="false" />
          <add fileExtension=".log" allowed="false" />
          <add fileExtension=".ini" allowed="false" />
          <add fileExtension=".old" allowed="false" />
          <add fileExtension=".bak" allowed="false" />
        </fileExtensions>
        <hiddenSegments>
          <add segment="bin" />
          <add segment="App_code" />
          <add segment="App_GlobalResources" />
          <add segment="App_LocalResources" />
          <add segment="App_WebReferences" />
          <add segment="App_Data" />
          <add segment="logs" />
          <add segment="config" />
        </hiddenSegments>
        <verbs>
          <add verb="TRACE" allowed="false" />
          <add verb="DEBUG" allowed="false" />
        </verbs>
      </requestFiltering>
    </security>

    <!-- Directory browsing disabled -->
    <directoryBrowse enabled="false" />

    <!-- Default documents -->
    <defaultDocument>
      <files>
        <clear />
        <add value="index.html" />
        <add value="index.aspx" />
        <add value="default.aspx" />
      </files>
    </defaultDocument>
  </system.webServer>
</configuration>
```

### PowerShell Security Configuration Scripts
```powershell
# iis-security-hardening.ps1
Import-Module WebAdministration

# Remove default website if not needed
Remove-Website -Name "Default Web Site" -ErrorAction SilentlyContinue

# Remove unnecessary features
Disable-WindowsOptionalFeature -Online -FeatureName IIS-WebDAV -All
Disable-WindowsOptionalFeature -Online -FeatureName IIS-ServerSideIncludes -All

# Configure global security settings
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/requestFiltering/requestLimits" -Name "maxAllowedContentLength" -Value 52428800

# Hide IIS version
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -Value @{name="Server";value=""}

# Configure failed request tracing
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/Default Web Site" -Filter "system.webServer/tracing/traceFailedRequests" -Name "enabled" -Value $true

# Set up custom error pages
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/httpErrors" -Name "errorMode" -Value "Custom"

# Configure logging
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/Default Web Site" -Filter "system.webServer/httpLogging" -Name "enabled" -Value $true
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/Default Web Site" -Filter "system.webServer/httpLogging" -Name "logExtFileFlags" -Value "Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Cookie,Referer,ProtocolVersion,Host,HttpSubStatus"

Write-Host "IIS security hardening completed" -ForegroundColor Green
```

### SSL/TLS Configuration
```powershell
# ssl-configuration.ps1

# Enable modern TLS protocols only
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -PropertyType DWORD -Value 0

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -PropertyType DWORD -Value 0

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -PropertyType DWORD -Value 1

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "Enabled" -PropertyType DWORD -Value 1

# Disable weak ciphers
$WeakCiphers = @(
    "DES 56/56",
    "RC2 40/128",
    "RC2 56/128",
    "RC2 128/128",
    "RC4 40/128",
    "RC4 56/128",
    "RC4 64/128",
    "RC4 128/128"
)

foreach ($Cipher in $WeakCiphers) {
    $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$Cipher"
    New-Item -Path $Path -Force
    New-ItemProperty -Path $Path -Name "Enabled" -PropertyType DWORD -Value 0
}

Write-Host "SSL/TLS configuration completed" -ForegroundColor Green
```

### Application Pool Security
```powershell
# app-pool-security.ps1

# Create secure application pool
New-WebAppPool -Name "SecureAppPool"

# Configure identity
Set-ItemProperty -Path "IIS:\AppPools\SecureAppPool" -Name "processModel.identityType" -Value "ApplicationPoolIdentity"

# Set resource limits
Set-ItemProperty -Path "IIS:\AppPools\SecureAppPool" -Name "processModel.idleTimeout" -Value "00:20:00"
Set-ItemProperty -Path "IIS:\AppPools\SecureAppPool" -Name "recycling.periodicRestart.time" -Value "1.05:00:00"
Set-ItemProperty -Path "IIS:\AppPools\SecureAppPool" -Name "processModel.maxProcesses" -Value 1

# Configure failure detection
Set-ItemProperty -Path "IIS:\AppPools\SecureAppPool" -Name "failure.rapidFailProtection" -Value $true
Set-ItemProperty -Path "IIS:\AppPools\SecureAppPool" -Name "failure.rapidFailProtectionInterval" -Value "00:05:00"
Set-ItemProperty -Path "IIS:\AppPools\SecureAppPool" -Name "failure.rapidFailProtectionMaxCrashes" -Value 5

# Set CPU limits
Set-ItemProperty -Path "IIS:\AppPools\SecureAppPool" -Name "cpu.limit" -Value 0
Set-ItemProperty -Path "IIS:\AppPools\SecureAppPool" -Name "cpu.action" -Value "Throttle"

Write-Host "Application pool security configured" -ForegroundColor Green
```

## Performance Optimization

### Output Caching Configuration
```xml
<!-- web.config - Output caching settings -->
<configuration>
  <system.webServer>
    <!-- Static content caching -->
    <staticContent>
      <clientCache cacheControlMode="UseMaxAge" cacheControlMaxAge="365.00:00:00" />
    </staticContent>

    <!-- HTTP compression -->
    <httpCompression directory="%SystemDrive%\inetpub\temp\IIS Temporary Compressed Files">
      <scheme name="gzip" dll="%Windir%\system32\inetsrv\gzip.dll" />
      <dynamicTypes>
        <add mimeType="text/*" enabled="true" />
        <add mimeType="message/*" enabled="true" />
        <add mimeType="application/x-javascript" enabled="true" />
        <add mimeType="application/javascript" enabled="true" />
        <add mimeType="application/json" enabled="true" />
        <add mimeType="*/*" enabled="false" />
      </dynamicTypes>
      <staticTypes>
        <add mimeType="text/*" enabled="true" />
        <add mimeType="message/*" enabled="true" />
        <add mimeType="application/javascript" enabled="true" />
        <add mimeType="application/atom+xml" enabled="true" />
        <add mimeType="application/xaml+xml" enabled="true" />
        <add mimeType="image/svg+xml" enabled="true" />
        <add mimeType="*/*" enabled="false" />
      </staticTypes>
    </httpCompression>

    <!-- URL compression -->
    <urlCompression doStaticCompression="true" doDynamicCompression="true" />
  </system.webServer>

  <!-- ASP.NET output caching -->
  <system.web>
    <caching>
      <outputCacheSettings>
        <outputCacheProfiles>
          <add name="StaticContent" duration="86400" varyByParam="none" />
          <add name="DynamicContent" duration="300" varyByParam="*" />
        </outputCacheProfiles>
      </outputCacheSettings>
    </caching>
  </system.web>
</configuration>
```

### IIS Performance Tuning
```powershell
# performance-tuning.ps1

# Configure worker processes
Set-ItemProperty -Path "IIS:\AppPools\DefaultAppPool" -Name "processModel.maxProcesses" -Value ([Environment]::ProcessorCount)

# Configure request limits
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/serverRuntime" -Name "maxRequestEntityAllowed" -Value 52428800

# Configure connection limits
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/serverRuntime" -Name "maxConcurrentRequestsPerCPU" -Value 5000

# Enable kernel mode caching
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/caching" -Name "enabled" -Value $true

# Configure output caching
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/caching/profiles/add[@extension='.html']" -Name "policy" -Value "CacheUntilChange"

Write-Host "Performance tuning completed" -ForegroundColor Green
```

### Application Request Routing (ARR) Load Balancing
```xml
<!-- applicationHost.config - ARR configuration -->
<configuration>
  <system.webServer>
    <proxy enabled="true" />
    <rewrite>
      <rules>
        <rule name="LoadBalancer" stopProcessing="true">
          <match url=".*" />
          <action type="Rewrite" url="http://ServerFarm/{R:0}" />
        </rule>
      </rules>
    </rewrite>
  </system.webServer>
</configuration>
```

```powershell
# Configure server farm
Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "webFarms" -Name "." -Value @{name="ServerFarm"}

# Add servers to farm
Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "webFarms/webFarm[@name='ServerFarm']" -Name "." -Value @{address="192.168.1.10";httpPort="80";httpsPort="443"}
Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "webFarms/webFarm[@name='ServerFarm']" -Name "." -Value @{address="192.168.1.11";httpPort="80";httpsPort="443"}

# Configure health monitoring
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "webFarms/webFarm[@name='ServerFarm']/applicationRequestRouting/healthCheck" -Name "enabled" -Value $true
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "webFarms/webFarm[@name='ServerFarm']/applicationRequestRouting/healthCheck" -Name "interval" -Value "00:00:30"
```

## Security Monitoring and Logging

### Advanced Logging Configuration
```xml
<!-- web.config - Advanced logging -->
<configuration>
  <system.webServer>
    <httpLogging enabled="true">
      <logFile logFormat="W3C" directory="%SystemDrive%\inetpub\logs\LogFiles" />
    </httpLogging>

    <!-- Failed request tracing -->
    <tracing>
      <traceFailedRequests>
        <add path="*">
          <traceAreas>
            <add provider="ASP" verbosity="Verbose" />
            <add provider="ASPNET" areas="Infrastructure,Module,Page,AppServices" verbosity="Verbose" />
            <add provider="ISAPI Extension" verbosity="Verbose" />
            <add provider="WWW Server" areas="Authentication,Security,Filter,StaticFile,CGI,Compression,Cache,RequestNotifications,Module,FastCGI" verbosity="Verbose" />
          </traceAreas>
          <failureDefinitions statusCodes="400-999" />
        </add>
      </traceFailedRequests>
    </tracing>
  </system.webServer>
</configuration>
```

### Security Event Monitoring
```powershell
# security-monitoring.ps1

# Enable IIS logging
Enable-WebRequestTracing -Name "Default Web Site"

# Configure Windows Event Log
$LogName = "Application"
$Source = "IIS Security Monitor"

if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
    [System.Diagnostics.EventLog]::CreateEventSource($Source, $LogName)
}

# Function to log security events
function Write-SecurityEvent {
    param(
        [string]$Message,
        [System.Diagnostics.EventLogEntryType]$EntryType = [System.Diagnostics.EventLogEntryType]::Warning
    )

    Write-EventLog -LogName $LogName -Source $Source -EntryType $EntryType -EventId 1001 -Message $Message
}

# Monitor for suspicious activity
$SuspiciousPatterns = @(
    "sqlmap",
    "nikto",
    "nmap",
    "union.*select",
    "script.*alert",
    "\.php\?",
    "admin/config",
    "/etc/passwd"
)

# Parse IIS logs for security events
$LogPath = "C:\inetpub\logs\LogFiles\W3SVC1"
$LatestLog = Get-ChildItem $LogPath | Sort-Object LastWriteTime | Select-Object -Last 1

if ($LatestLog) {
    $LogContent = Get-Content $LatestLog.FullName | Where-Object { $_ -notlike "#*" }

    foreach ($Line in $LogContent) {
        $Fields = $Line -split ' '
        $Request = $Fields[7] # cs-uri-stem + cs-uri-query

        foreach ($Pattern in $SuspiciousPatterns) {
            if ($Request -match $Pattern) {
                $ClientIP = $Fields[2]
                $Message = "Suspicious request detected from $ClientIP`: $Request"
                Write-SecurityEvent -Message $Message -EntryType Warning
                break
            }
        }
    }
}

Write-Host "Security monitoring completed" -ForegroundColor Green
```

### Rate Limiting with Dynamic IP Restrictions
```powershell
# dynamic-ip-restrictions.ps1

# Install Dynamic IP Restrictions module
# Download from: https://www.iis.net/downloads/microsoft/dynamic-ip-restrictions

# Configure dynamic IP restrictions
Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/dynamicIpSecurity" -Name "." -Value @{enableLoggingOnlyMode="false"}

# Set request thresholds
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -Name "enabled" -Value $true
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -Name "maxConcurrentRequests" -Value 20

Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/dynamicIpSecurity/denyByRequestRate" -Name "enabled" -Value $true
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/dynamicIpSecurity/denyByRequestRate" -Name "maxRequests" -Value 100
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/security/dynamicIpSecurity/denyByRequestRate" -Name "requestIntervalInMilliseconds" -Value 60000

Write-Host "Dynamic IP restrictions configured" -ForegroundColor Green
```

## Virtual Host and Application Configuration

### Secure Website Configuration
```powershell
# create-secure-website.ps1

param(
    [Parameter(Mandatory=$true)]
    [string]$SiteName,

    [Parameter(Mandatory=$true)]
    [string]$PhysicalPath,

    [Parameter(Mandatory=$true)]
    [string]$HostHeader,

    [string]$CertificateThumbprint
)

# Create application pool
$AppPoolName = "$SiteName-AppPool"
New-WebAppPool -Name $AppPoolName

# Configure application pool security
Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name "processModel.identityType" -Value "ApplicationPoolIdentity"
Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name "processModel.loadUserProfile" -Value $false
Set-ItemProperty -Path "IIS:\AppPools\$AppPoolName" -Name "processModel.setProfileEnvironment" -Value $false

# Create website
New-Website -Name $SiteName -PhysicalPath $PhysicalPath -ApplicationPool $AppPoolName -HostHeader $HostHeader

# Configure HTTPS if certificate provided
if ($CertificateThumbprint) {
    New-WebBinding -Name $SiteName -Protocol "https" -Port 443 -HostHeader $HostHeader
    $Binding = Get-WebBinding -Name $SiteName -Protocol "https"
    $Binding.AddSslCertificate($CertificateThumbprint, "my")
}

# Configure security headers
$SitePath = "IIS:\Sites\$SiteName"
Set-WebConfigurationProperty -PSPath $SitePath -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -Value @{name="X-Content-Type-Options";value="nosniff"}
Set-WebConfigurationProperty -PSPath $SitePath -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -Value @{name="X-Frame-Options";value="DENY"}

# Configure request filtering
Set-WebConfigurationProperty -PSPath $SitePath -Filter "system.webServer/security/requestFiltering/fileExtensions" -Name "." -Value @{fileExtension=".config";allowed="false"}

Write-Host "Secure website '$SiteName' created successfully" -ForegroundColor Green
```

### ASP.NET Core Configuration
```xml
<!-- web.config for ASP.NET Core -->
<configuration>
  <location path="." inheritInChildApplications="false">
    <system.webServer>
      <handlers>
        <add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified" />
      </handlers>

      <aspNetCore processPath="dotnet"
                  arguments=".\MyApp.dll"
                  stdoutLogEnabled="true"
                  stdoutLogFile=".\logs\stdout"
                  hostingModel="InProcess">
        <environmentVariables>
          <environmentVariable name="ASPNETCORE_ENVIRONMENT" value="Production" />
          <environmentVariable name="ASPNETCORE_HTTPS_PORT" value="443" />
        </environmentVariables>
      </aspNetCore>

      <security>
        <requestFiltering removeServerHeader="true">
          <requestLimits maxAllowedContentLength="52428800" />
        </requestFiltering>
      </security>

      <httpProtocol>
        <customHeaders>
          <remove name="Server" />
          <add name="X-Content-Type-Options" value="nosniff" />
          <add name="X-Frame-Options" value="DENY" />
          <add name="X-XSS-Protection" value="1; mode=block" />
          <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
        </customHeaders>
      </httpProtocol>
    </system.webServer>
  </location>
</configuration>
```

## Monitoring and Health Checks

### IIS Health Monitoring
```powershell
# iis-health-monitor.ps1

function Test-IISHealth {
    $Results = @()

    # Check IIS service status
    $IISService = Get-Service -Name "W3SVC"
    $Results += [PSCustomObject]@{
        Component = "IIS Service"
        Status = $IISService.Status
        Healthy = ($IISService.Status -eq "Running")
    }

    # Check application pools
    $AppPools = Get-IISAppPool
    foreach ($Pool in $AppPools) {
        $Results += [PSCustomObject]@{
            Component = "AppPool: $($Pool.Name)"
            Status = $Pool.State
            Healthy = ($Pool.State -eq "Started")
        }
    }

    # Check websites
    $Sites = Get-IISSite
    foreach ($Site in $Sites) {
        $Results += [PSCustomObject]@{
            Component = "Site: $($Site.Name)"
            Status = $Site.State
            Healthy = ($Site.State -eq "Started")
        }
    }

    # Check SSL certificates
    $Bindings = Get-IISSiteBinding | Where-Object { $_.Protocol -eq "https" }
    foreach ($Binding in $Bindings) {
        if ($Binding.CertificateHash) {
            $Cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Thumbprint -eq $Binding.CertificateHash }
            if ($Cert) {
                $DaysUntilExpiry = ($Cert.NotAfter - (Get-Date)).Days
                $Results += [PSCustomObject]@{
                    Component = "SSL Cert: $($Binding.BindingInformation)"
                    Status = "Expires in $DaysUntilExpiry days"
                    Healthy = ($DaysUntilExpiry -gt 30)
                }
            }
        }
    }

    return $Results
}

# Generate health report
$HealthResults = Test-IISHealth
$UnhealthyComponents = $HealthResults | Where-Object { -not $_.Healthy }

if ($UnhealthyComponents) {
    Write-Warning "Unhealthy components detected:"
    $UnhealthyComponents | Format-Table -AutoSize

    # Send alert email
    $Body = $UnhealthyComponents | ConvertTo-Html -Property Component, Status, Healthy
    Send-MailMessage -To "admin@example.com" -From "iis-monitor@example.com" -Subject "IIS Health Alert" -Body $Body -BodyAsHtml -SmtpServer "smtp.example.com"
} else {
    Write-Host "All IIS components are healthy" -ForegroundColor Green
}
```

### Performance Counter Monitoring
```powershell
# performance-counters.ps1

$Counters = @(
    "\Web Service(_Total)\Current Connections",
    "\Web Service(_Total)\Bytes Received/sec",
    "\Web Service(_Total)\Bytes Sent/sec",
    "\Web Service(_Total)\Get Requests/sec",
    "\Web Service(_Total)\Post Requests/sec",
    "\ASP.NET Applications(__Total__)\Requests/Sec",
    "\ASP.NET Applications(__Total__)\Request Execution Time",
    "\Process(w3wp)\% Processor Time",
    "\Process(w3wp)\Working Set"
)

$Results = @()
foreach ($Counter in $Counters) {
    try {
        $Value = (Get-Counter -Counter $Counter -SampleInterval 1 -MaxSamples 1).CounterSamples.CookedValue
        $Results += [PSCustomObject]@{
            Counter = $Counter
            Value = [math]::Round($Value, 2)
            Timestamp = Get-Date
        }
    } catch {
        Write-Warning "Failed to collect counter: $Counter"
    }
}

$Results | Format-Table -AutoSize
```

## Backup and Disaster Recovery

### IIS Configuration Backup
```powershell
# iis-backup.ps1

param(
    [string]$BackupPath = "C:\WebBackups\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

# Create backup directory
New-Item -Path $BackupPath -ItemType Directory -Force

# Backup IIS configuration
& "$env:SystemRoot\System32\inetsrv\appcmd.exe" add backup "AutoBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

# Export IIS configuration
& "$env:SystemRoot\System32\inetsrv\appcmd.exe" list config /config.section:system.webServer > "$BackupPath\webServer_config.xml"
& "$env:SystemRoot\System32\inetsrv\appcmd.exe" list sites > "$BackupPath\sites_config.xml"
& "$env:SystemRoot\System32\inetsrv\appcmd.exe" list apppools > "$BackupPath\apppools_config.xml"

# Backup SSL certificates
$Certs = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Subject -like "*example.com*" }
foreach ($Cert in $Certs) {
    $CertPath = "$BackupPath\cert_$($Cert.Thumbprint).cer"
    Export-Certificate -Cert $Cert -FilePath $CertPath
}

# Backup website files
$Sites = Get-IISSite
foreach ($Site in $Sites) {
    $SitePath = (Get-IISApplication -SiteName $Site.Name | Where-Object { $_.Path -eq "/" }).PhysicalPath
    if (Test-Path $SitePath) {
        $ZipPath = "$BackupPath\$($Site.Name)_files.zip"
        Compress-Archive -Path $SitePath -DestinationPath $ZipPath
    }
}

# Create backup manifest
$Manifest = @{
    BackupDate = Get-Date
    IISVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\InetStp").VersionString
    Sites = (Get-IISSite).Name
    AppPools = (Get-IISAppPool).Name
    BackupLocation = $BackupPath
}

$Manifest | ConvertTo-Json | Out-File "$BackupPath\manifest.json"

Write-Host "IIS backup completed: $BackupPath" -ForegroundColor Green
```

### Automated SSL Certificate Renewal
```powershell
# ssl-renewal.ps1

# Example using ACMESharp for Let's Encrypt
Import-Module ACMESharp

function Update-SSLCertificate {
    param(
        [string]$Domain,
        [string]$SiteName
    )

    try {
        # Request new certificate
        $Cert = New-ACMECertificate -Domain $Domain -Path "C:\SSLCertificates"

        # Install certificate in IIS
        $CertThumbprint = (Import-PfxCertificate -FilePath $Cert.PfxFile -CertStoreLocation "Cert:\LocalMachine\My" -Password (ConvertTo-SecureString -String $Cert.Password -AsPlainText -Force)).Thumbprint

        # Update IIS binding
        $Binding = Get-WebBinding -Name $SiteName -Protocol "https"
        if ($Binding) {
            Remove-WebBinding -Name $SiteName -Protocol "https" -Port 443 -HostHeader $Domain
        }

        New-WebBinding -Name $SiteName -Protocol "https" -Port 443 -HostHeader $Domain
        $NewBinding = Get-WebBinding -Name $SiteName -Protocol "https"
        $NewBinding.AddSslCertificate($CertThumbprint, "my")

        Write-Host "SSL certificate updated for $Domain" -ForegroundColor Green

    } catch {
        Write-Error "Failed to update SSL certificate for $Domain`: $($_.Exception.Message)"

        # Send alert
        Send-MailMessage -To "admin@example.com" -From "iis-ssl@example.com" -Subject "SSL Certificate Renewal Failed" -Body "Failed to renew certificate for $Domain" -SmtpServer "smtp.example.com"
    }
}

# Check and renew certificates expiring within 30 days
$Sites = Get-IISSite
foreach ($Site in $Sites) {
    $Bindings = Get-IISSiteBinding -Name $Site.Name | Where-Object { $_.Protocol -eq "https" }

    foreach ($Binding in $Bindings) {
        if ($Binding.CertificateHash) {
            $Cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Thumbprint -eq $Binding.CertificateHash }

            if ($Cert -and ($Cert.NotAfter - (Get-Date)).Days -lt 30) {
                Update-SSLCertificate -Domain $Binding.Host -SiteName $Site.Name
            }
        }
    }
}
```

This comprehensive IIS administration guide provides Windows-specific security hardening, performance optimization, monitoring, and enterprise-grade management capabilities for production environments.