#!/usr/bin/env pwsh
#
# Decodo SmartProxy SOCKS5 Checker (PowerShell 7)
# Tests multiple proxy sessions and checks IPs with IPQS fraud scoring
#

# Load shared configuration
. "$PSScriptRoot\..\..\lib\config.ps1"

# ============================================
# Configuration
# ============================================

$sessionDuration = "60"  # in minutes (1-1440)
$country = "gb"          # two-letter country code

# Session prefix (randomly generated)
$sessionPrefix = New-SessionPrefix

# Number of sessions to test
$numSessions = 23

# Maximum concurrent processes
$maxConcurrent = 10

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

Write-Banner "Decodo SmartProxy SOCKS5 Checker (PowerShell 7)"
Write-Host "Proxy server: ${script:ProxyHostSocks5}:${script:ProxyPortSocks5}" -ForegroundColor White
Write-Host "Location: $country" -ForegroundColor White
Write-Host "Session duration: $sessionDuration minutes" -ForegroundColor White
Write-Host "Sessions to test: $numSessions" -ForegroundColor White
Write-Host "Max concurrent: $maxConcurrent" -ForegroundColor White
Write-Host "======================================" -ForegroundColor Cyan

Write-Host "`nPhase 1: Collecting IPs from SmartProxy..." -ForegroundColor Yellow

# Create session list
$sessions = 1..$numSessions | ForEach-Object { "${sessionPrefix}$_" }

# Test sessions in parallel
$sessionResults = $sessions | ForEach-Object -Parallel {
    $session = $_
    $authString = $using:script:DecodoUsername
    
    # Add session parameters
    $authString += "-session-$session"
    $authString += "-sessionduration-$($using:sessionDuration)"
    $authString += "-country-$($using:country)"
    $authString += ":$($using:script:DecodoPassword)"
    
    try {
        $proxyUri = "socks5h://${authString}@$($using:script:ProxyHostSocks5):$($using:script:ProxyPortSocks5)"
        
        # Use curl with SOCKS5H proxy
        $curlOutput = & curl -s -x $proxyUri $using:script:DecodoIpApi 2>$null
        
        if ($LASTEXITCODE -eq 0 -and $curlOutput) {
            $jsonData = $curlOutput | ConvertFrom-Json
            
            if ($jsonData.proxy.ip -and $jsonData.proxy.ip -ne $null) {
                Write-Host "OK - $session`: $($jsonData.proxy.ip) ($($jsonData.city.name))" -ForegroundColor Green
                
                return @{
                    Success = $true
                    Session = $session
                    IP = $jsonData.proxy.ip
                    City = $jsonData.city.name
                    CountryCode = $jsonData.country.code
                    CountryName = $jsonData.country.name
                    AuthString = $authString
                }
            }
        }
        
        Write-Host "Failed to get IP for session $session" -ForegroundColor Red
        return @{ Success = $false }
    }
    catch {
        Write-Host "Failed to connect for session $session`: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false }
    }
} -ThrottleLimit $maxConcurrent

Write-Host "All session tests completed. Processing results..." -ForegroundColor Yellow

# Process successful results
$processedIPs = @{}
foreach ($result in $sessionResults | Where-Object { $_.Success }) {
    if ($processedIPs.ContainsKey($result.IP)) {
        Write-Host "DUPLICATE IP: $($result.IP) (Session: $($result.Session))" -ForegroundColor Red
    }
    else {
        $ipList += $result.IP
        $cityList += $result.City
        $countryList += $result.CountryName
        $proxyLinks[$result.IP] = $result.AuthString
        $sessionToIp[$result.Session] = $result.IP
        $processedIPs[$result.IP] = $true
    }
}

if ($ipList.Count -eq 0) {
    Write-Host "No IPs collected. Exiting..." -ForegroundColor Red
    exit 1
}

Write-Host "`nPhase 2: Checking IPs with IPQS..." -ForegroundColor Yellow

# Check IPs in parallel
$ipqsResults = $ipList | ForEach-Object -Parallel {
    $ip = $_
    
    try {
        $url = "$($using:script:IpqsBaseUrl)/$($using:script:IpqsApiKey)/${ip}?strictness=3&user_language=en-US"
        $curlOutput = & curl -s "$url" 2>$null
        
        if ($LASTEXITCODE -eq 0 -and $curlOutput) {
            $response = $curlOutput | ConvertFrom-Json
            
            if ($response.success -eq $true) {
                return @{
                    Success = $true
                    IP = $ip
                    FraudScore = [int]$response.fraud_score
                }
            }
        }
        
        return @{ Success = $false }
    }
    catch {
        return @{ Success = $false }
    }
    
    Start-Sleep -Milliseconds 200
} -ThrottleLimit $maxConcurrent

Write-Host "All IP checks completed. Processing results..." -ForegroundColor Yellow

# Process IPQS results
foreach ($result in $ipqsResults | Where-Object { $_.Success }) {
    $ip = $result.IP
    $fraudScore = $result.FraudScore
    $fraudScores[$ip] = $fraudScore
    
    $index = $ipList.IndexOf($ip)
    if ($index -ge 0) {
        $city = $cityList[$index]
    }
    
    # Find sessions
    $sessionsWithIp = @()
    foreach ($session in $sessionToIp.Keys) {
        if ($sessionToIp[$session] -eq $ip) {
            $sessionsWithIp += $session
        }
    }
    $sessionList = $sessionsWithIp -join ", "
    
    Write-Host ("IP: {0,-45} Score: {1,3} - {2} (Sessions: {3})" -f $ip, $fraudScore, $city, $sessionList)
    
    if ($fraudScore -lt 50) {
        $cleanIps += $ip
    }
}

Write-Banner "Ranked Clean IPs by Fraud Score"

if ($cleanIps.Count -gt 0) {
    $sortedIps = $cleanIps | Sort-Object { $fraudScores[$_] }
    
    foreach ($ip in $sortedIps) {
        $score = $fraudScores[$ip]
        
        # Find session
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
        Write-Host "socks5h://$link@${script:ProxyHostSocks5}:${script:ProxyPortSocks5}" -ForegroundColor Cyan
    }
    
    if ($sortedIps.Count -gt 0) {
        $bestIp = $sortedIps[0]
        $bestLink = $proxyLinks[$bestIp]
        Write-Host ""
        Write-Banner "Best Proxy Connection"
        Write-Host "socks5h://$bestLink@${script:ProxyHostSocks5}:${script:ProxyPortSocks5}" -ForegroundColor Green
    }
}
else {
    Write-Host "No clean IPs found (score < 50)" -ForegroundColor Red
}
