# PowerShell script to swap IP addresses between two Linode instances
# Load credentials from cred.json
$credPath = Join-Path $env:USERPROFILE "Documents\cred.json"
$cred = Get-Content $credPath | ConvertFrom-Json
$linodeToken = $cred.linode.tokens[3]  # Use token index 3

$Headers = @{
    "Authorization" = "Bearer $linodeToken"
    "Content-type" = "application/json"
}
$Proxy = "http://127.0.0.1:7890"

# Linode IDs (Ensure these are integers)
$LinodeId1 = 61857756
$LinodeId2 = 61857931

# Step 1: Retrieve current IP configurations
$Uri1 = "https://api.linode.com/v4/linode/instances/$LinodeId1"
$Uri2 = "https://api.linode.com/v4/linode/instances/$LinodeId2"

$Linode1 = Invoke-WebRequest -Uri $Uri1 -Headers $Headers -Proxy $Proxy -ProxyUseDefaultCredentials | ConvertFrom-Json
$Linode2 = Invoke-WebRequest -Uri $Uri2 -Headers $Headers -Proxy $Proxy -ProxyUseDefaultCredentials | ConvertFrom-Json

# Extract IP addresses
$Ip1 = $Linode1.ipv4[0]
$Ip2 = $Linode2.ipv4[0]

# Step 2: Swap IP addresses using the Linode API
$SwapBody = @{
    "region" = "id-cgk" # Specify the region of the Linodes
    "assignments" = @(
        @{
            "address" = $Ip1
            "linode_id" = $LinodeId2
        },
        @{
            "address" = $Ip2
            "linode_id" = $LinodeId1
        }
    )
} | ConvertTo-Json

$SwapUri = "https://api.linode.com/v4/networking/ipv4/assign"
Invoke-WebRequest -Uri $SwapUri -Method Post -Headers $Headers -Body $SwapBody -Proxy $Proxy -ProxyUseDefaultCredentials | Out-Null

# Step 3: Reboot both Linode instances to apply changes
$LinodeIds = @($LinodeId1, $LinodeId2)
foreach ($LinodeId in $LinodeIds) {
    $RebootUri = "https://api.linode.com/v4/linode/instances/$LinodeId/reboot"
    Invoke-WebRequest -Uri $RebootUri -Method Post -Headers $Headers -Proxy $Proxy -ProxyUseDefaultCredentials | Out-Null
    Write-Output "Reboot request sent for Linode ID: $LinodeId."
}
