#!/usr/bin/env pwsh

# SmartProxy Configuration - Load from cred.json
$credPath = Join-Path $env:USERPROFILE "Documents\cred.json"
$cred = Get-Content $credPath | ConvertFrom-Json
$baseUrl = "https://ip.decodo.com/json"
$username = $cred.proxy.decodo.username
$password = $cred.proxy.decodo.password
$proxyServer = "gate.decodo.com:7000"
$sessionDuration = "60"  # in minutes (1-1440)
$country = "gb"          # two-letter country code

# Session prefix (p = persistent, r = random)
$fruits = @("apple", "banana", "orange", "grape", "kiwi", "mango", "peach", "cherry", "lemon", "lime", "plum", "berry", "melon", "papaya")
$chars = @("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z")
$randomFruit = $fruits | Get-Random
$randomNums = "{0:D2}" -f (Get-Random -Maximum 100)
$randomChar1 = $chars | Get-Random
$randomChar2 = $chars | Get-Random
$randomChar3 = $chars | Get-Random
$sessionPrefix = "${randomFruit}${randomNums}${randomChar1}${randomChar2}${randomChar3}"

# Define number of sessions to test
$numSessions = 23

# IPQS Configuration - Load from cred.json
$ipqsApiKey = $cred.ipqs.default_key
$ipqsBaseUrl = "https://ipqualityscore.com/api/json/ip/$ipqsApiKey"
$userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# Maximum number of concurrent processes
$maxConcurrent = 10

# Initialize collections
$ipList = @()
$cityList = @()
$countryList = @()
$proxyLinks = @{}
$sessionToIp = @{}
$fraudScores = @{}
$cleanIps = @()


Write-Host "====================================== 🚀🚀🚀" -ForegroundColor Cyan
Write-Host "Decodo SmartProxy IP Checker (PowerShell 7)" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Proxy server: $proxyServer" -ForegroundColor White
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
    $authString = $using:username
    
    # Add session parameters first
    $authString += "-session-$session"
    $authString += "-sessionduration-$($using:sessionDuration)"
    
    # Add location parameters
    $authString += "-country-$($using:country)"
    
    $authString += ":$($using:password)"
    
    try {
        $proxyUri = "socks5h://${authString}@$($using:proxyServer)"
        
        # Use curl with SOCKS5H proxy
        $curlOutput = & curl -s -x $proxyUri $using:baseUrl 2>$null
        
        if ($LASTEXITCODE -eq 0 -and $curlOutput) {
            $jsonData = $curlOutput | ConvertFrom-Json
            
            if ($jsonData.proxy.ip -and $jsonData.proxy.ip -ne $null) {
                $ip = $jsonData.proxy.ip
                $city = $jsonData.city.name
                $countryCode = $jsonData.country.code
                $countryName = $jsonData.country.name
                
                Write-Host "OK - $session`: $ip ($city)" -ForegroundColor Green
                
                return @{
                    Success = $true
                    Session = $session
                    IP = $ip
                    City = $city
                    CountryCode = $countryCode
                    CountryName = $countryName
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

# Process successful results and check for duplicates
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
    $ipqsApiKey = $using:ipqsApiKey
    $ipqsBaseUrl = $using:ipqsBaseUrl
    $userAgent = $using:userAgent
    
    try {
        $url = "${ipqsBaseUrl}/${ip}?strictness=3&user_language=en-US"
        
        # Use curl for IPQS API calls
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
            else {
                Write-Host "IP: $ip - API error: $($response.message)" -ForegroundColor Red
                return @{ Success = $false }
            }
        }
        else {
            Write-Host "IP: $ip - Failed to connect to IPQS API" -ForegroundColor Red
            return @{ Success = $false }
        }
    }
    catch {
        Write-Host "IP: $ip - Failed to connect to IPQS API: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false }
    }
    
    Start-Sleep -Milliseconds 200  # Rate limiting
} -ThrottleLimit $maxConcurrent

Write-Host "All IP checks completed. Processing results..." -ForegroundColor Yellow

# Process IPQS results
foreach ($result in $ipqsResults | Where-Object { $_.Success }) {
    $ip = $result.IP
    $fraudScore = $result.FraudScore
    $fraudScores[$ip] = $fraudScore
    
    # Find corresponding city and country
    $index = $ipList.IndexOf($ip)
    if ($index -ge 0) {
        $city = $cityList[$index]
        $country = $countryList[$index]
    }
    
    # Find sessions associated with this IP
    $sessionsWithIp = @()
    foreach ($session in $sessionToIp.Keys) {
        if ($sessionToIp[$session] -eq $ip) {
            $sessionsWithIp += $session
        }
    }
    $sessionList = $sessionsWithIp -join ", "
    
    # Print result
    Write-Host ("IP: {0,-45} Score: {1,3} - {2} (Sessions: {3})" -f $ip, $fraudScore, $city, $sessionList) -ForegroundColor White
    
    # If fraud score is less than 50, add to clean IPs array
    if ($fraudScore -lt 50) {
        $cleanIps += $ip
    }
}

Write-Host "`n====================================== 🚀🚀🚀" -ForegroundColor Cyan
Write-Host "Ranked Clean IPs by Fraud Score" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

# Sort and display clean IPs by fraud score
if ($cleanIps.Count -gt 0) {
    # Sort clean IPs by fraud score (low to high)
    $sortedIps = $cleanIps | Sort-Object { $fraudScores[$_] }
    
    # Display sorted clean IPs
    foreach ($ip in $sortedIps) {
        $score = $fraudScores[$ip]
        
        # Find session for this IP
        $session = ""
        foreach ($s in $sessionToIp.Keys) {
            if ($sessionToIp[$s] -eq $ip) {
                $session = $s
                break
            }
        }
        
        # Find city for this IP
        $index = $ipList.IndexOf($ip)
        $city = if ($index -ge 0) { $cityList[$index] } else { "Unknown" }
        
        # Get proxy link
        $link = $proxyLinks[$ip]
        
        # Print with emojis based on score
        $emoji = switch ($score) {
            0 { "✅✅✅" }
            { $_ -lt 20 } { "✅✅" }
            { $_ -lt 40 } { "✅" }
            default { "⚠️" }
        }
        
        Write-Host "$emoji Score: $score - IP: $ip ($city, Session: $session)" -ForegroundColor Green
        Write-Host "socks5h://$link@gate.decodo.com:7000" -ForegroundColor Cyan
    }
    
    # Print the final best link
    if ($sortedIps.Count -gt 0) {
        $bestIp = $sortedIps[0]
        $bestLink = $proxyLinks[$bestIp]
        Write-Host "`n====================================== 🚀🚀🚀" -ForegroundColor Cyan
        Write-Host "Best Proxy Connection:" -ForegroundColor Cyan
        Write-Host "======================================" -ForegroundColor Cyan
        Write-Host "socks5h://$bestLink@gate.decodo.com:7000" -ForegroundColor Green
    }
}
else {
    Write-Host "No clean IPs found (score < 50)" -ForegroundColor Red
}
