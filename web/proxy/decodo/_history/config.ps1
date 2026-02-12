# Shared configuration for Decodo SmartProxy scripts (PowerShell)
# Dot-source this file in your scripts: . "$PSScriptRoot\..\lib\config.ps1"

# ============================================
# Credential Loading
# ============================================

# Credentials file path
$script:CredFile = "/allah/blue/cred.json"

function Get-DecodoCreds {
    if (Test-Path $script:CredFile) {
        return Get-Content $script:CredFile | ConvertFrom-Json
    }
    return $null
}

function Initialize-Credentials {
    $script:Creds = Get-DecodoCreds
    
    # Decodo proxy credentials
    if ($script:Creds) {
        $script:DecodoUsername = $script:Creds.proxy.decodo.username
        $script:DecodoPassword = $script:Creds.proxy.decodo.password
        $script:IpqsApiKey = $script:Creds.ipqs.default_key
    } else {
        $script:DecodoUsername = $env:DECODO_USERNAME ?? "user-sp3j58curv"
        $script:DecodoPassword = $env:DECODO_PASSWORD ?? "SET_DECODO_PASSWORD_ENV"
        $script:IpqsApiKey = $env:IPQS_API_KEY ?? "SET_IPQS_API_KEY_ENV"
    }
}

# ============================================
# Proxy Configuration
# ============================================

$script:ProxyHostSocks5 = "gate.decodo.com"
$script:ProxyPortSocks5 = "7000"
$script:ProxyHostHttps = "gate.decodo.com"
$script:ProxyPortHttpsMin = 10001
$script:ProxyPortHttpsMax = 49999

# API endpoints
$script:DecodoIpApi = "https://ip.decodo.com/json"
$script:IpqsBaseUrl = "https://ipqualityscore.com/api/json/ip"

# Default request settings
$script:UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# ============================================
# Helper Functions
# ============================================

function Get-ProjectRoot {
    return Split-Path -Parent $PSScriptRoot
}

function Get-CountryName {
    param([string]$Prefix)
    
    $projectRoot = Get-ProjectRoot
    $countryFile = Join-Path $projectRoot "data\countries.txt"
    
    if (Test-Path $countryFile) {
        $content = Get-Content $countryFile -Raw
        if ($content -match "'prefix': '$Prefix'.*?'location': '([^']+)'") {
            return $matches[1]
        }
    }
    
    return $Prefix
}

function New-SessionPrefix {
    $fruits = @("apple", "banana", "orange", "grape", "kiwi", "mango", "peach", "cherry", "lemon", "lime", "plum", "berry", "melon", "papaya")
    $chars = @("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z")
    
    $randomFruit = $fruits | Get-Random
    $randomNums = "{0:D2}" -f (Get-Random -Maximum 100)
    $randomChar1 = $chars | Get-Random
    $randomChar2 = $chars | Get-Random
    $randomChar3 = $chars | Get-Random
    
    return "${randomFruit}${randomNums}${randomChar1}${randomChar2}${randomChar3}"
}

function Get-RandomHttpsPort {
    return Get-Random -Minimum $script:ProxyPortHttpsMin -Maximum ($script:ProxyPortHttpsMax + 1)
}

function Write-Banner {
    param([string]$Title)
    
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
}

function Get-ScoreEmoji {
    param([int]$Score)
    
    switch ($Score) {
        0 { return "✅✅✅" }
        { $_ -lt 20 } { return "✅✅" }
        { $_ -lt 40 } { return "✅" }
        { $_ -lt 70 } { return "⚠️" }
        default { return "🚨" }
    }
}

# Auto-initialize when dot-sourced
Initialize-Credentials
