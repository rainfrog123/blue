#!/usr/bin/env pwsh
#
# Decodo SmartProxy HTTPS Checker (PowerShell 7)
# Tests multiple proxy sessions using HTTPS ports and checks IPs with IPQS fraud scoring
#

# Load shared configuration
. "$PSScriptRoot\..\..\lib\config.ps1"

# ============================================
# Configuration
# ============================================

$sessionDuration = "60"  # in minutes (1-1440)
$country = "gb"          # two-letter country code

# Session naming
$sessionPrefix = "session"

# Number of sessions to test
$numSessions = 33

# ============================================
# Main Script
# ============================================

# Initialize collections
$ipList = @()
$cityList = @()
$countryList = @()
$proxyLinks = @{}
$sessionToIp = @{}
$fraudScores = @{}
$cleanIps = @()

Write-Banner "Decodo SmartProxy HTTPS Checker"
Write-Host "Proxy host: $script:ProxyHostHttps"
Write-Host "Port range: $script:ProxyPortHttpsMin-$script:ProxyPortHttpsMax (random)"
Write-Host "Location: $country"
Write-Host "Session duration: $sessionDuration minutes"
Write-Host "Sessions to test: $numSessions"
Write-Host "======================================"

Write-Host "`nPhase 1: Collecting IPs from SmartProxy..."

# Function to test sessions
$testSessionScript = {
    param($SessionNum, $Username, $Password, $ProxyHost, $ProxyPortMin, $ProxyPortMax, $SessionDuration, $Country, $BaseUrl, $SessionPrefix)
    
    $authString = "$Username-sessionduration-$SessionDuration-country-$Country"
    $proxyPort = Get-Random -Minimum $ProxyPortMin -Maximum ($ProxyPortMax + 1)
    $proxyUrl = "https://$ProxyHost`:$proxyPort"
    $credential = New-Object PSCredential($authString, (ConvertTo-SecureString $Password -AsPlainText -Force))
    $sessionName = "$SessionPrefix$SessionNum"
    
    try {
        $response = Invoke-RestMethod -Uri $BaseUrl -Proxy $proxyUrl -ProxyCredential $credential -TimeoutSec 30
        
        if ($response.proxy.ip) {
            return @{
                Success = $true
                SessionName = $sessionName
                IP = $response.proxy.ip
                City = $response.city.name
                CountryCode = $response.country.code
                CountryName = $response.country.name
                AuthString = $authString
                ProxyPort = $proxyPort
            }
        }
        else {
            return @{ Success = $false; SessionName = $sessionName; ProxyPort = $proxyPort }
        }
    }
    catch {
        return @{ Success = $false; SessionName = $sessionName; ProxyPort = $proxyPort; Error = $_.Exception.Message }
    }
}

# Launch session tests in parallel
$jobs = @()
for ($i = 1; $i -le $numSessions; $i++) {
    $job = Start-Job -ScriptBlock $testSessionScript -ArgumentList $i, $script:DecodoUsername, $script:DecodoPassword, $script:ProxyHostHttps, $script:ProxyPortHttpsMin, $script:ProxyPortHttpsMax, $sessionDuration, $country, $script:DecodoIpApi, $sessionPrefix
    $jobs += $job
}

$results = $jobs | Wait-Job | Receive-Job
$jobs | Remove-Job

Write-Host "All session tests completed. Processing results..."

foreach ($result in $results) {
    if ($result.Success) {
        Write-Host "OK - $($result.SessionName) (port $($result.ProxyPort)): $($result.IP) ($($result.City))" -ForegroundColor Green
        
        $duplicate = $false
        foreach ($existingIp in $ipList) {
            if ($existingIp -eq $result.IP) {
                Write-Host "DUPLICATE IP: $($result.IP)" -ForegroundColor Yellow
                $duplicate = $true
                break
            }
        }
        
        if (-not $duplicate) {
            $ipList += $result.IP
            $cityList += $result.City
            $countryList += $result.CountryName
            $proxyLinks[$result.IP] = "https://$($result.AuthString):$script:DecodoPassword@$script:ProxyHostHttps`:$($result.ProxyPort)"
            $sessionToIp[$result.SessionName] = $result.IP
        }
    }
    else {
        Write-Host "Failed - $($result.SessionName) (port $($result.ProxyPort))" -ForegroundColor Red
    }
}

Write-Host "`nPhase 2: Checking IPs with IPQS..."

# Check IPs
$checkIpScript = {
    param($IP, $IpqsBaseUrl, $IpqsApiKey, $UserAgent)
    
    try {
        $url = "$IpqsBaseUrl/$IpqsApiKey/$IP"
        $params = @{ strictness = 3; user_agent = $UserAgent; user_language = "en-US" }
        $response = Invoke-RestMethod -Uri $url -Method Get -Body $params -TimeoutSec 30
        
        if ($response.success) {
            return @{ Success = $true; IP = $IP; FraudScore = $response.fraud_score }
        }
        return @{ Success = $false; IP = $IP }
    }
    catch {
        return @{ Success = $false; IP = $IP }
    }
}

$ipJobs = @()
foreach ($ip in $ipList) {
    Start-Sleep -Milliseconds 100
    $job = Start-Job -ScriptBlock $checkIpScript -ArgumentList $ip, $script:IpqsBaseUrl, $script:IpqsApiKey, $script:UserAgent
    $ipJobs += $job
}

$ipResults = $ipJobs | Wait-Job | Receive-Job
$ipJobs | Remove-Job

Write-Host "All IP checks completed. Processing results..."

foreach ($result in $ipResults) {
    if ($result.Success) {
        $ip = $result.IP
        $fraudScore = $result.FraudScore
        $fraudScores[$ip] = $fraudScore
        
        $index = $ipList.IndexOf($ip)
        if ($index -ge 0) {
            $city = $cityList[$index]
        }
        
        $sessionsWithIp = @()
        foreach ($session in $sessionToIp.Keys) {
            if ($sessionToIp[$session] -eq $ip) {
                $sessionsWithIp += $session
            }
        }
        $sessionsStr = $sessionsWithIp -join ", "
        
        Write-Host ("IP: {0,-45} Score: {1,3} - {2} (Sessions: {3})" -f $ip, $fraudScore, $city, $sessionsStr)
        
        if ($fraudScore -lt 50) {
            $cleanIps += $ip
        }
    }
}

Write-Banner "Ranked Clean IPs by Fraud Score"

if ($cleanIps.Count -gt 0) {
    $sortedIps = $cleanIps | Sort-Object { $fraudScores[$_] }
    
    foreach ($ip in $sortedIps) {
        $score = $fraudScores[$ip]
        
        $session = ""
        foreach ($s in $sessionToIp.Keys) {
            if ($sessionToIp[$s] -eq $ip) {
                $session = $s
                break
            }
        }
        
        $index = $ipList.IndexOf($ip)
        $city = if ($index -ge 0) { $cityList[$index] } else { "Unknown" }
        
        $link = $proxyLinks[$ip]
        $emoji = Get-ScoreEmoji -Score $score
        
        Write-Host "$emoji Score: $score - IP: $ip ($city, Session: $session)" -ForegroundColor Green
        Write-Host "$link" -ForegroundColor Blue
    }
    
    if ($sortedIps.Count -gt 0) {
        $bestIp = $sortedIps[0]
        $bestLink = $proxyLinks[$bestIp]
        Write-Host ""
        Write-Banner "Best Proxy Connection"
        Write-Host "$bestLink" -ForegroundColor Green
    }
}
else {
    Write-Host "No clean IPs found (score < 50)" -ForegroundColor Red
}
