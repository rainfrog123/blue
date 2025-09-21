#!/usr/bin/env pwsh

# SmartProxy Configuration
$baseUrl = "https://ip.decodo.com/json"
$username = "user-sp19qgy7m9"
$password = "+26iSboeQ0wUyx4qEw"
$proxyServer = "gate.decodo.com:7000"
$sessionDuration = "60"  # in minutes (1-1440)
$country = "gb"          # two-letter country code
# $city = "Hamburg"      # city name (use underscores for spaces)
# $state = ""            # state code (for US - use us_state_name format)
# $continent = ""        # continent code (eu, na, as, sa, af, oc)
# $asn = ""              # ASN number

# Session prefix generation
$fruits = @("apple", "banana", "orange", "grape", "kiwi", "mango", "peach", "cherry", "lemon", "lime", "plum", "berry", "melon", "papaya")
$chars = @("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z")
$randomFruit = $fruits | Get-Random
$randomNums = "{0:D2}" -f (Get-Random -Maximum 100)
$randomChar1 = $chars | Get-Random
$randomChar2 = $chars | Get-Random
$randomChar3 = $chars | Get-Random
$sessionPrefix = "$randomFruit$randomNums$randomChar1$randomChar2$randomChar3"

# Define number of sessions to test
$numSessions = 33
$maxRetries = 2

# IPQS Configuration
$ipqsApiKey = "POYGDAv8gXSH6CRWUMqFlTUlyZDhPJt5"
$ipqsBaseUrl = "https://ipqualityscore.com/api/json/ip/$ipqsApiKey"
$userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# Maximum number of concurrent processes
$maxConcurrent = 10

# Initialize collections
$ipList = [System.Collections.ArrayList]::new()
$cityList = [System.Collections.ArrayList]::new()
$countryList = [System.Collections.ArrayList]::new()
$proxyLinks = @{}
$sessionToIp = @{}
$fraudScores = @{}
$cleanIps = [System.Collections.ArrayList]::new()

# Build the authentication string based on configured parameters
function Build-AuthString {
    param([string]$sessionName)
    
    $authString = $username
    
    # Add session parameters first
    $authString = "$authString-session-$sessionName"
    $authString = "$authString-sessionduration-$sessionDuration"
    
    # Add location parameters (in priority order)
    if ($continent) {
        $authString = "$authString-continent-$continent"
    }
    elseif ($country) {
        $authString = "$authString-country-$country"
        
        if ($state) {
            $authString = "$authString-state-$state"
        }
        elseif ($city) {
            $authString = "$authString-city-$city"
        }
    }
    
    # Add ASN if specified (cannot be combined with city)
    if ($asn -and -not $city) {
        $authString = "$authString-asn-$asn"
    }
    
    return "$authString`:$password"
}

# Set console to UTF-8 for emoji support
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    if ($Host.UI.RawUI | Get-Member -Name OutputEncoding -ErrorAction SilentlyContinue) {
        $Host.UI.RawUI.OutputEncoding = [System.Text.Encoding]::UTF8
    }
} catch {
    # Ignore encoding errors on older PowerShell versions
}

Write-Host "====================================== " -NoNewline -ForegroundColor Cyan
Write-Host "[ROCKETS]" -ForegroundColor Cyan
Write-Host "Decodo SmartProxy IP Checker (Async Mode)" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Proxy server: $proxyServer"
if ($city) {
    Write-Host "Location: $city, $country"
} else {
    Write-Host "Location: $country"
}
Write-Host "Session duration: $sessionDuration minutes"
Write-Host "Concurrent jobs: 5"
Write-Host "======================================"

Write-Host "Phase 1: Collecting IPs from SmartProxy..." -ForegroundColor Yellow

# Test single connection first
Write-Host "Testing single connection..." -ForegroundColor Gray
$testSession = "$sessionPrefix-test"
$testAuthString = Build-AuthString $testSession

# Test connection function
function Test-Connection {
    param([string]$session, [string]$authString)
    
    Write-Host "Auth string: $authString" -ForegroundColor Gray
    Write-Host "Proxy server: $proxyServer" -ForegroundColor Gray
    
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "curl.exe"
        $psi.Arguments = "-v -m 30 --connect-timeout 15 -U `"$authString`" --proxy socks5h://$proxyServer `"$baseUrl`""
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        
        Write-Host "Executing: curl.exe $($psi.Arguments)" -ForegroundColor Gray
        
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $psi
        $null = $process.Start()
        $null = $process.WaitForExit(35000)
        
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $exitCode = $process.ExitCode
        $process.Dispose()
        
        Write-Host "Exit Code: $exitCode" -ForegroundColor Gray
        if ($stderr) { Write-Host "STDERR: $stderr" -ForegroundColor Yellow }
        if ($stdout) { Write-Host "STDOUT: $stdout" -ForegroundColor Gray }
        
        if ($exitCode -eq 0 -and $stdout) {
            $json = $stdout | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($json -and $json.proxy.ip) {
                Write-Host "TEST SUCCESS: Got IP $($json.proxy.ip) from $($json.city.name)" -ForegroundColor Green
                return $true
            } else {
                Write-Host "TEST FAILED: No proxy IP in JSON response" -ForegroundColor Red
                return $false
            }
        } else {
            Write-Host "TEST FAILED: Connection error" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "TEST FAILED: Exception - $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

if (-not (Test-Connection $testSession $testAuthString)) {
    Write-Host "Initial connection test failed. Please check your configuration." -ForegroundColor Red
    Write-Host "Press any key to continue anyway or Ctrl+C to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Function to test a single session
function Test-Session {
    param([string]$session, [string]$authString)
    
    try {
        # Use curl if available (more reliable than PowerShell web clients with SOCKS5)
        if (Get-Command curl -ErrorAction SilentlyContinue) {
            $curlCmd = "curl -s -U `"$authString`" -x `"$proxyServer`" `"$baseUrl`""
            $response = Invoke-Expression $curlCmd
        } else {
            # Fallback to PowerShell method
            $proxyUri = "http://$proxyServer"
            $credential = [System.Net.NetworkCredential]::new(($authString -split ':')[0], ($authString -split ':',2)[1])
            $proxy = [System.Net.WebProxy]::new($proxyUri, $true)
            $proxy.Credentials = $credential
            
            $webRequest = [System.Net.WebRequest]::Create($baseUrl)
            $webRequest.Proxy = $proxy
            $webRequest.Timeout = 30000
            $webRequest.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            
            $webResponse = $webRequest.GetResponse()
            $reader = [System.IO.StreamReader]::new($webResponse.GetResponseStream())
            $response = $reader.ReadToEnd()
            $reader.Close()
            $webResponse.Close()
        }
        
        if ($response) {
            $json = $response | ConvertFrom-Json
            
            if ($json.proxy.ip) {
                return @{
                    Success = $true
                    Session = $session
                    IP = $json.proxy.ip
                    City = $json.city.name
                    CountryCode = $json.country.code
                    CountryName = $json.country.name
                    AuthString = $authString
                }
            }
        }
        
        return @{Success = $false; Session = $session; Error = "No IP returned"}
    }
    catch {
        return @{Success = $false; Session = $session; Error = $_.Exception.Message}
    }
}

# Sequential approach with basic concurrency (more reliable)
$activeJobs = @()
$maxJobs = 5  # Reduced for stability
$failedSessions = @()
$sessionRetries = @{}

for ($i = 1; $i -le $numSessions; $i++) {
    $session = "$sessionPrefix$i"
    $authString = Build-AuthString $session
    
    # Wait if we have too many active jobs
    while ($activeJobs.Count -ge $maxJobs) {
        $completedJobs = @()
        foreach ($job in $activeJobs) {
            if ($job.State -eq 'Completed') {
                $completedJobs += $job
            }
        }
        
        foreach ($job in $completedJobs) {
            $result = Receive-Job $job -ErrorAction SilentlyContinue
            Remove-Job $job
            $activeJobs = $activeJobs | Where-Object { $_ -ne $job }
            
            if ($result) {
                if ($result.Success) {
                    Write-Host "OK - $($result.Session): $($result.IP) ($($result.City))" -ForegroundColor Green
                    
                    # Check for duplicates
                    $duplicate = $false
                    foreach ($existingIp in $ipList) {
                        if ($existingIp -eq $result.IP) {
                            Write-Host "DUPLICATE IP: $($result.IP) (Session: $($result.Session))" -ForegroundColor Yellow
                            $duplicate = $true
                            break
                        }
                    }
                    
                    if (-not $duplicate) {
                        $null = $ipList.Add($result.IP)
                        $null = $cityList.Add($result.City)
                        $null = $countryList.Add($result.CountryName)
                        $proxyLinks[$result.IP] = $result.AuthString
                        $sessionToIp[$result.Session] = $result.IP
                    }
                } else {
                    Write-Host "Failed - $($result.Session): $($result.Error)" -ForegroundColor Red
                    # Track failed sessions for retry
                    if (-not $sessionRetries.ContainsKey($result.Session)) {
                        $sessionRetries[$result.Session] = 0
                    }
                    if ($sessionRetries[$result.Session] -lt $maxRetries) {
                        $failedSessions += $result.Session
                        $sessionRetries[$result.Session]++
                        Write-Host "  -> Will retry (attempt $($sessionRetries[$result.Session])/$maxRetries)" -ForegroundColor Yellow
                    } else {
                        Write-Host "  -> Max retries reached" -ForegroundColor Red
                    }
                }
            }
        }
        
        if ($activeJobs.Count -ge $maxJobs) {
            Start-Sleep -Milliseconds 200
        }
    }
    
    # Test session function for jobs
    $jobScript = {
        param($session, $authString, $proxyServer, $baseUrl)
        
        try {
            # Direct curl.exe call with better error handling
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "curl.exe"
            $psi.Arguments = "-v -m 30 --connect-timeout 15 -U `"$authString`" --proxy socks5h://$proxyServer `"$baseUrl`""
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            
            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $psi
            $null = $process.Start()
            $null = $process.WaitForExit(35000) # 35 second timeout
            
            $stdout = $process.StandardOutput.ReadToEnd()
            $stderr = $process.StandardError.ReadToEnd()
            $exitCode = $process.ExitCode
            $process.Dispose()
            
            if ($exitCode -eq 0 -and $stdout) {
                $json = $stdout | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($json -and $json.proxy.ip) {
                    return @{
                        Success = $true
                        Session = $session
                        IP = $json.proxy.ip
                        City = $json.city.name
                        CountryCode = $json.country.code
                        CountryName = $json.country.name
                        AuthString = $authString
                    }
                } elseif ($json) {
                    return @{Success = $false; Session = $session; Error = "No proxy IP in response: $stdout"}
                } else {
                    return @{Success = $false; Session = $session; Error = "Invalid JSON response: $stdout"}
                }
            } else {
                $errorMsg = "Exit code: $exitCode"
                if ($stderr) { $errorMsg += " - STDERR: $stderr" }
                if ($stdout) { $errorMsg += " - STDOUT: $stdout" }
                return @{Success = $false; Session = $session; Error = $errorMsg}
            }
        }
        catch {
            return @{Success = $false; Session = $session; Error = "Exception: $($_.Exception.Message)"}
        }
    }
    
    # Start job
    $job = Start-Job -ScriptBlock $jobScript -ArgumentList $session, $authString, $proxyServer, $baseUrl
    $activeJobs += $job
    
    Write-Host "Started $session..." -ForegroundColor Gray
    Start-Sleep -Milliseconds 100  # Small delay between starts
}

# Wait for remaining jobs
Write-Host "Waiting for remaining sessions..." -ForegroundColor Yellow
while ($activeJobs.Count -gt 0) {
    $completedJobs = @()
    foreach ($job in $activeJobs) {
        if ($job.State -eq 'Completed') {
            $completedJobs += $job
        }
    }
    
    foreach ($job in $completedJobs) {
        $result = Receive-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job
        $activeJobs = $activeJobs | Where-Object { $_ -ne $job }
        
        if ($result) {
            if ($result.Success) {
                Write-Host "OK - $($result.Session): $($result.IP) ($($result.City))" -ForegroundColor Green
                
                # Check for duplicates
                $duplicate = $false
                foreach ($existingIp in $ipList) {
                    if ($existingIp -eq $result.IP) {
                        Write-Host "DUPLICATE IP: $($result.IP) (Session: $($result.Session))" -ForegroundColor Yellow
                        $duplicate = $true
                        break
                    }
                }
                
                if (-not $duplicate) {
                    $null = $ipList.Add($result.IP)
                    $null = $cityList.Add($result.City)
                    $null = $countryList.Add($result.CountryName)
                    $proxyLinks[$result.IP] = $result.AuthString
                    $sessionToIp[$result.Session] = $result.IP
                }
            } else {
                Write-Host "Failed - $($result.Session): $($result.Error)" -ForegroundColor Red
                # Track failed sessions for retry
                if (-not $sessionRetries.ContainsKey($result.Session)) {
                    $sessionRetries[$result.Session] = 0
                }
                if ($sessionRetries[$result.Session] -lt $maxRetries) {
                    $failedSessions += $result.Session
                    $sessionRetries[$result.Session]++
                    Write-Host "  -> Will retry (attempt $($sessionRetries[$result.Session])/$maxRetries)" -ForegroundColor Yellow
                } else {
                    Write-Host "  -> Max retries reached" -ForegroundColor Red
                }
            }
        }
    }
    
    if ($activeJobs.Count -gt 0) {
        Write-Host "Remaining: $($activeJobs.Count) sessions..." -ForegroundColor Gray
        Start-Sleep -Seconds 1
    }
}

# Retry failed sessions
if ($failedSessions.Count -gt 0) {
    Write-Host "`nRetrying failed sessions..." -ForegroundColor Yellow
    
    while ($failedSessions.Count -gt 0) {
        $sessionToRetry = $failedSessions[0]
        $failedSessions = $failedSessions[1..($failedSessions.Length-1)]
        
        $authString = Build-AuthString $sessionToRetry
        
        # Wait for available slot
        while ($activeJobs.Count -ge $maxJobs) {
            $completedJobs = @()
            foreach ($job in $activeJobs) {
                if ($job.State -eq 'Completed') {
                    $completedJobs += $job
                }
            }
            
            foreach ($job in $completedJobs) {
                $result = Receive-Job $job -ErrorAction SilentlyContinue
                Remove-Job $job
                $activeJobs = $activeJobs | Where-Object { $_ -ne $job }
                
                if ($result) {
                    if ($result.Success) {
                        Write-Host "OK - $($result.Session): $($result.IP) ($($result.City))" -ForegroundColor Green
                        
                        # Check for duplicates
                        $duplicate = $false
                        foreach ($existingIp in $ipList) {
                            if ($existingIp -eq $result.IP) {
                                Write-Host "DUPLICATE IP: $($result.IP) (Session: $($result.Session))" -ForegroundColor Yellow
                                $duplicate = $true
                                break
                            }
                        }
                        
                        if (-not $duplicate) {
                            $null = $ipList.Add($result.IP)
                            $null = $cityList.Add($result.City)
                            $null = $countryList.Add($result.CountryName)
                            $proxyLinks[$result.IP] = $result.AuthString
                            $sessionToIp[$result.Session] = $result.IP
                        }
                    } else {
                        Write-Host "Retry Failed - $($result.Session): $($result.Error)" -ForegroundColor Red
                        # Don't add to retry list again
                    }
                }
            }
            
            if ($activeJobs.Count -ge $maxJobs) {
                Start-Sleep -Milliseconds 200
            }
        }
        
        # Start retry job
        $job = Start-Job -ScriptBlock $jobScript -ArgumentList $sessionToRetry, $authString, $proxyServer, $baseUrl
        $activeJobs += $job
        
        Write-Host "Retrying $sessionToRetry..." -ForegroundColor Gray
        Start-Sleep -Milliseconds 100
    }
    
    # Wait for retry jobs to complete
    while ($activeJobs.Count -gt 0) {
        $completedJobs = @()
        foreach ($job in $activeJobs) {
            if ($job.State -eq 'Completed') {
                $completedJobs += $job
            }
        }
        
        foreach ($job in $completedJobs) {
            $result = Receive-Job $job -ErrorAction SilentlyContinue
            Remove-Job $job
            $activeJobs = $activeJobs | Where-Object { $_ -ne $job }
            
            if ($result) {
                if ($result.Success) {
                    Write-Host "OK - $($result.Session): $($result.IP) ($($result.City))" -ForegroundColor Green
                    
                    # Check for duplicates
                    $duplicate = $false
                    foreach ($existingIp in $ipList) {
                        if ($existingIp -eq $result.IP) {
                            Write-Host "DUPLICATE IP: $($result.IP) (Session: $($result.Session))" -ForegroundColor Yellow
                            $duplicate = $true
                            break
                        }
                    }
                    
                    if (-not $duplicate) {
                        $null = $ipList.Add($result.IP)
                        $null = $cityList.Add($result.City)
                        $null = $countryList.Add($result.CountryName)
                        $proxyLinks[$result.IP] = $result.AuthString
                        $sessionToIp[$result.Session] = $result.IP
                    }
                } else {
                    Write-Host "Retry Failed - $($result.Session): $($result.Error)" -ForegroundColor Red
                }
            }
        }
        
        if ($activeJobs.Count -gt 0) {
            Write-Host "Remaining retries: $($activeJobs.Count)..." -ForegroundColor Gray
            Start-Sleep -Seconds 1
        }
    }
}

Write-Host "`nPhase 2: Checking IPs with IPQS..." -ForegroundColor Yellow

# Function to check a single IP
$checkIpScript = {
    param($ip, $ipqsBaseUrl, $userAgent)
    
    try {
        $url = "$ipqsBaseUrl/$ip"
        $params = @{
            strictness = 3
            user_agent = $userAgent
            user_language = "en-US"
        }
        
        $response = Invoke-RestMethod -Uri $url -Method Get -Body $params -UserAgent $userAgent
        
        if ($response.success -eq $true) {
            return @{
                Success = $true
                IP = $ip
                FraudScore = $response.fraud_score
            }
        } else {
            return @{Success = $false; IP = $ip; Error = $response.message}
        }
    }
    catch {
        return @{Success = $false; IP = $ip; Error = $_.Exception.Message}
    }
}

# Launch IP checks in parallel
$jobs = @()
foreach ($ip in $ipList) {
    # Wait if we have too many concurrent jobs
    while (($jobs | Where-Object { $_.State -eq 'Running' }).Count -ge $maxConcurrent) {
        Start-Sleep -Milliseconds 200
        $jobs | Where-Object { $_.State -eq 'Completed' } | ForEach-Object {
            $result = Receive-Job $_
            Remove-Job $_
            
            if ($result.Success) {
                $fraudScores[$result.IP] = $result.FraudScore
                
                # Find city and country for this IP
                $city = ""
                $country = ""
                for ($i = 0; $i -lt $ipList.Count; $i++) {
                    if ($ipList[$i] -eq $result.IP) {
                        $city = $cityList[$i]
                        $country = $countryList[$i]
                        break
                    }
                }
                
                # Find sessions with this IP
                $sessionsWithIp = @()
                foreach ($kvp in $sessionToIp.GetEnumerator()) {
                    if ($kvp.Value -eq $result.IP) {
                        $sessionsWithIp += $kvp.Key
                    }
                }
                
                Write-Host ("IP: {0,-15} Score: {1,3} - {2} (Sessions: {3})" -f $result.IP, $result.FraudScore, $city, ($sessionsWithIp -join ', '))
                
                if ($result.FraudScore -lt 50) {
                    $null = $cleanIps.Add($result.IP)
                }
            } else {
                Write-Host "IP: $($result.IP) - Error: $($result.Error)" -ForegroundColor Red
            }
        }
        $jobs = $jobs | Where-Object { $_.State -ne 'Completed' }
    }
    
    # Start new job
    $job = Start-Job -ScriptBlock $checkIpScript -ArgumentList $ip, $ipqsBaseUrl, $userAgent
    $jobs += $job
    
    Start-Sleep -Milliseconds 200  # Rate limiting
}

# Wait for remaining jobs to complete
while ($jobs.Count -gt 0) {
    Start-Sleep -Milliseconds 200
    $jobs | Where-Object { $_.State -eq 'Completed' } | ForEach-Object {
        $result = Receive-Job $_
        Remove-Job $_
        
        if ($result.Success) {
            $fraudScores[$result.IP] = $result.FraudScore
            
            # Find city and country for this IP
            $city = ""
            $country = ""
            for ($i = 0; $i -lt $ipList.Count; $i++) {
                if ($ipList[$i] -eq $result.IP) {
                    $city = $cityList[$i]
                    $country = $countryList[$i]
                    break
                }
            }
            
            # Find sessions with this IP
            $sessionsWithIp = @()
            foreach ($kvp in $sessionToIp.GetEnumerator()) {
                if ($kvp.Value -eq $result.IP) {
                    $sessionsWithIp += $kvp.Key
                }
            }
            
            Write-Host ("IP: {0,-15} Score: {1,3} - {2} (Sessions: {3})" -f $result.IP, $result.FraudScore, $city, ($sessionsWithIp -join ', '))
            
            if ($result.FraudScore -lt 50) {
                $null = $cleanIps.Add($result.IP)
            }
        } else {
            Write-Host "IP: $($result.IP) - Error: $($result.Error)" -ForegroundColor Red
        }
    }
    $jobs = $jobs | Where-Object { $_.State -ne 'Completed' }
}

Write-Host "`n====================================== " -NoNewline -ForegroundColor Cyan
Write-Host "[ROCKETS]" -ForegroundColor Cyan
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
        foreach ($kvp in $sessionToIp.GetEnumerator()) {
            if ($kvp.Value -eq $ip) {
                $session = $kvp.Key
                break
            }
        }
        
        # Find city for this IP
        $city = ""
        for ($i = 0; $i -lt $ipList.Count; $i++) {
            if ($ipList[$i] -eq $ip) {
                $city = $cityList[$i]
                break
            }
        }
        
        # Get proxy link
        $link = $proxyLinks[$ip]
        
        # Print with indicators based on score
        $indicator = switch ($score) {
            { $_ -eq 0 } { "[EXCELLENT]" }
            { $_ -lt 20 } { "[GREAT]" }
            { $_ -lt 40 } { "[GOOD]" }
            default { "[WARNING]" }
        }
        
        Write-Host "$indicator Score: $score - IP: $ip ($city, Session: $session)" -ForegroundColor Green
        Write-Host "socks5h://$link@gate.decodo.com:7000" -ForegroundColor Blue
    }
    
    # Print the final best link
    if ($sortedIps.Count -gt 0) {
        $bestIp = $sortedIps[0]
        $bestLink = $proxyLinks[$bestIp]
        Write-Host "`n====================================== " -NoNewline -ForegroundColor Cyan
        Write-Host "[ROCKETS]" -ForegroundColor Cyan
        Write-Host "Best Proxy Connection:" -ForegroundColor Cyan
        Write-Host "======================================" -ForegroundColor Cyan
        Write-Host "socks5h://$bestLink@gate.decodo.com:7000" -ForegroundColor Green
    }
} else {
    Write-Host "No clean IPs found (score < 50)" -ForegroundColor Red
}
