#!/usr/bin/env pwsh

# SmartProxy Configuration (HTTPS Proxy Version) - Load from cred.json
$credPath = Join-Path $env:USERPROFILE "Documents\cred.json"
$cred = Get-Content $credPath | ConvertFrom-Json
$baseUrl = "https://ip.decodo.com/json"
$username = $cred.proxy.decodo.username
$password = $cred.proxy.decodo.password
$proxyHost = "gb.decodo.com"
$proxyPortMin = 30001    # Minimum port range
$proxyPortMax = 40000    # Maximum port range
$sessionDuration = "60"  # in minutes (1-1440)
$country = "gb"          # two-letter country code
# $city = "Hamburg"      # city name (use underscores for spaces)
# $state = ""            # state code (for US - use us_state_name format)
# $continent = ""        # continent code (eu, na, as, sa, af, oc)
# $asn = ""              # ASN number

# Session naming
$sessionPrefix = "session"

# Define number of sessions to test
$numSessions = 33

# IPQS Configuration - Load from cred.json (use key index 1)
$ipqsApiKey = $cred.ipqs.api_keys[1]
$ipqsBaseUrl = "https://ipqualityscore.com/api/json/ip/$ipqsApiKey"
$userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# Build the authentication string for HTTPS proxy
function Build-AuthString {
    param([int]$SessionNum)
    
    $authString = "$username-sessionduration-$sessionDuration"
    
    # Add location parameters (in priority order)
    if ($continent) {
        $authString = "$authString-continent-$continent"
    } elseif ($country) {
        $authString = "$authString-country-$country"
        
        if ($state) {
            $authString = "$authString-state-$state"
        } elseif ($city) {
            $authString = "$authString-city-$city"
        }
    }
    
    # Add ASN if specified (cannot be combined with city)
    if ($asn -and -not $city) {
        $authString = "$authString-asn-$asn"
    }
    
    return $authString
}

# Get random proxy port within range
function Get-ProxyPort {
    param([int]$SessionNum)
    return Get-Random -Minimum $proxyPortMin -Maximum ($proxyPortMax + 1)
}


# Initialize collections
$ipList = @()
$cityList = @()
$countryList = @()
$proxyLinks = @{}
$sessionToIp = @{}
$fraudScores = @{}
$cleanIps = @()

Write-Host "====================================== 🚀🚀🚀" -ForegroundColor Cyan
Write-Host "Decodo SmartProxy HTTPS Checker (Async Mode)" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Proxy host: $proxyHost"
Write-Host "Port range: $proxyPortMin-$proxyPortMax (random)"

if ($city) {
    Write-Host "Location: $city, $country"
} else {
    Write-Host "Location: $country"
}

Write-Host "Session duration: $sessionDuration minutes"
Write-Host "Sessions to test: $numSessions"
Write-Host "======================================"

Write-Host "Phase 1: Collecting IPs from SmartProxy..."

# Function to test a single session
$testSessionScript = {
    param($SessionNum, $Username, $Password, $ProxyHost, $ProxyPortMin, $ProxyPortMax, $SessionDuration, $Country, $City, $State, $Continent, $Asn, $BaseUrl, $SessionPrefix)
    
    function Build-AuthString {
        param([int]$SessionNum, $Username, $SessionDuration, $Country, $City, $State, $Continent, $Asn)
        
        $authString = "$Username-sessionduration-$SessionDuration"
        
        if ($Continent) {
            $authString = "$authString-continent-$Continent"
        } elseif ($Country) {
            $authString = "$authString-country-$Country"
            
            if ($State) {
                $authString = "$authString-state-$State"
            } elseif ($City) {
                $authString = "$authString-city-$City"
            }
        }
        
        if ($Asn -and -not $City) {
            $authString = "$authString-asn-$Asn"
        }
        
        return $authString
    }
    
    $authString = Build-AuthString -SessionNum $SessionNum -Username $Username -SessionDuration $SessionDuration -Country $Country -City $City -State $State -Continent $Continent -Asn $Asn
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
        } else {
            return @{
                Success = $false
                SessionName = $sessionName
                ProxyPort = $proxyPort
                Error = "No IP returned"
            }
        }
    } catch {
        return @{
            Success = $false
            SessionName = $sessionName
            ProxyPort = $proxyPort
            Error = $_.Exception.Message
        }
    }
}

# Launch all session tests in parallel using jobs
$jobs = @()
for ($i = 1; $i -le $numSessions; $i++) {
    $job = Start-Job -ScriptBlock $testSessionScript -ArgumentList $i, $username, $password, $proxyHost, $proxyPortMin, $proxyPortMax, $sessionDuration, $country, $city, $state, $continent, $asn, $baseUrl, $sessionPrefix
    $jobs += $job
}

# Wait for all jobs to complete and process results
$results = $jobs | Wait-Job | Receive-Job
$jobs | Remove-Job

Write-Host "All session tests completed. Processing results..."

# Process results in order
foreach ($result in $results) {
    if ($result.Success) {
        Write-Host "OK - $($result.SessionName) (port $($result.ProxyPort)): $($result.IP) ($($result.City))" -ForegroundColor Green
        
        # Check for duplicates
        $duplicate = $false
        foreach ($existingIp in $ipList) {
            if ($existingIp -eq $result.IP) {
                Write-Host "DUPLICATE IP: $($result.IP) (Session: $($result.SessionName), Port: $($result.ProxyPort))" -ForegroundColor Yellow
                $duplicate = $true
                break
            }
        }
        
        if (-not $duplicate) {
            $ipList += $result.IP
            $cityList += $result.City
            $countryList += $result.CountryName
            $proxyLinks[$result.IP] = "https://$($result.AuthString):$password@$proxyHost`:$($result.ProxyPort)"
            $sessionToIp[$result.SessionName] = $result.IP
        }
    } else {
        Write-Host "Failed - $($result.SessionName) (port $($result.ProxyPort))" -ForegroundColor Red
    }
}

Write-Host "`nPhase 2: Checking IPs with IPQS..."

# Function to check a single IP
$checkIpScript = {
    param($IP, $IpqsBaseUrl, $UserAgent)
    
    try {
        $url = "$IpqsBaseUrl/$IP"
        $params = @{
            strictness = 3
            user_agent = $UserAgent
            user_language = "en-US"
        }
        
        $response = Invoke-RestMethod -Uri $url -Method Get -Body $params -TimeoutSec 30
        
        if ($response.success) {
            return @{
                Success = $true
                IP = $IP
                FraudScore = $response.fraud_score
            }
        } else {
            Write-Host "IP: $IP - API error: $($response.message)" -ForegroundColor Red
            return @{
                Success = $false
                IP = $IP
                Error = $response.message
            }
        }
    } catch {
        Write-Host "IP: $IP - Failed to connect to IPQS API: $($_.Exception.Message)" -ForegroundColor Red
        return @{
            Success = $false
            IP = $IP
            Error = $_.Exception.Message
        }
    }
}

# Launch all IP checks in parallel
$ipJobs = @()
foreach ($ip in $ipList) {
    Start-Sleep -Milliseconds 100  # Small delay to avoid rate limits
    $job = Start-Job -ScriptBlock $checkIpScript -ArgumentList $ip, $ipqsBaseUrl, $userAgent
    $ipJobs += $job
}

# Wait for all IP check jobs to complete
$ipResults = $ipJobs | Wait-Job | Receive-Job
$ipJobs | Remove-Job

Write-Host "All IP checks completed. Processing results..."

# Process IP check results
foreach ($result in $ipResults) {
    if ($result.Success) {
        $ip = $result.IP
        $fraudScore = $result.FraudScore
        $fraudScores[$ip] = $fraudScore
        
        # Find corresponding city and country
        $index = $ipList.IndexOf($ip)
        if ($index -ge 0) {
            $city = $cityList[$index]
            $country = $countryList[$index]
        }
        
        # Find session names associated with this IP
        $sessionsWithIp = @()
        foreach ($session in $sessionToIp.Keys) {
            if ($sessionToIp[$session] -eq $ip) {
                $sessionsWithIp += $session
            }
        }
        
        # Print minimal info with score
        $sessionsStr = $sessionsWithIp -join ", "
        Write-Host ("IP: {0,-45} Score: {1,3} - {2} (Sessions: {3})" -f $ip, $fraudScore, $city, $sessionsStr)
        
        # If fraud score is less than 50, add to clean IPs array
        if ($fraudScore -lt 50) {
            $cleanIps += $ip
        }
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
        Write-Host "$link" -ForegroundColor Blue
    }
    
    # Print the final best link
    if ($sortedIps.Count -gt 0) {
        $bestIp = $sortedIps[0]
        $bestLink = $proxyLinks[$bestIp]
        Write-Host "`n====================================== 🚀🚀🚀" -ForegroundColor Cyan
        Write-Host "Best Proxy Connection:" -ForegroundColor Cyan
        Write-Host "======================================" -ForegroundColor Cyan
        Write-Host "$bestLink" -ForegroundColor Green
    }
} else {
    Write-Host "No clean IPs found (score < 50)" -ForegroundColor Red
}
