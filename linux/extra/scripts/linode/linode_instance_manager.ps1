# 085f18ba0344aa246b8202761fbb4da201c131dc93985b97b5fa6da9c4576db9
# 631d8d13ec21eff1ee1f7df8ecac180a0c932b5587ab178ea854b962dfca9af8
# wilcox_danny——tY380h7b3%Vb+fv.Q——9df9bf013e43b56aabf8be1758dbc690a788c5e287b796a03585fc429204dfca
# ritaholm——DAl3Yk!B15)!ihWI——19756de4a2fcc796663de2eb65efececb9cfec81e853103d174ec202bdd5e2a6
# Define headers and proxy settings for the account
$Headers = @{
    "Authorization" = "Bearer 9df9bf013e43b56aabf8be1758dbc690a788c5e287b796a03585fc429204dfca"
    "Content-type" = "application/json"
}
$Proxy = "http://127.0.0.1:7890"

# Fetch account details
Invoke-WebRequest -Uri "https://api.linode.com/v4/account" -Headers $Headers -Proxy $Proxy -ProxyUseDefaultCredentials | ConvertFrom-Json | ConvertTo-Json

# Fetch invoices
Invoke-WebRequest -Uri "https://api.linode.com/v4/account/invoices" -Headers $Headers -Proxy $Proxy -ProxyUseDefaultCredentials | ConvertFrom-Json | ConvertTo-Json

# List Linode instances
Invoke-WebRequest -Uri "https://api.linode.com/v4/linode/instances" -Headers $Headers -Proxy $Proxy -ProxyUseDefaultCredentials | ConvertFrom-Json | ConvertTo-Json

# List Linode Types
Invoke-WebRequest -Uri "https://api.linode.com/v4/linode/types" -Headers $Headers -Proxy $Proxy -ProxyUseDefaultCredentials | ConvertFrom-Json | ConvertTo-Json

# Create a Linode Instance in ap-south region
# sg-sin-2

$BodyApSouth = @{
    "type" = "g6-nanode-1"
    "region" = "us-lax"
    "image" = "linode/debian12"
    "root_pass" = "4dwlq5!H4uA26A8"
} | ConvertTo-Json
Invoke-WebRequest -Uri "https://api.linode.com/v4/linode/instances" -Method Post -Headers $Headers -Body $BodyApSouth -Proxy $Proxy -ProxyUseDefaultCredentials | ConvertFrom-Json | ConvertTo-Json

# Create a Linode Instance in Jakarta region
$BodyJakarta = @{
    "type" = "g7-premium-4"
    "region" = "ap-northeast"
    "image" = "linode/debian12"
    "root_pass" = "4dwlq5!H4uA26A8"
} | ConvertTo-Json
Invoke-WebRequest -Uri "https://api.linode.com/v4/linode/instances" -Method Post -Headers $Headers -Body $BodyJakarta -Proxy $Proxy -ProxyUseDefaultCredentials | ConvertFrom-Json | ConvertTo-Json

# Rebuild a Linode Instance
$RebuildBody = @{
    "image" = "linode/debian12"
    "root_pass" = "4dwlq5!H4uA26A8"
} | ConvertTo-Json
Invoke-WebRequest -Uri "https://api.linode.com/v4/linode/instances/67514156/rebuild" -Method Post -Headers $Headers -Body $RebuildBody -Proxy $Proxy -ProxyUseDefaultCredentials | ConvertFrom-Json | ConvertTo-Json

# Delete a Linode Instance
$LinodeId = "68233363"
$UriDeleteInstance = "https://api.linode.com/v4/linode/instances/" + $LinodeId
Invoke-WebRequest -Uri $UriDeleteInstance -Method Delete -Headers $Headers -Proxy $Proxy -ProxyUseDefaultCredentials | ConvertFrom-Json | ConvertTo-Json

# Reboot Multiple Linode Instances
$LinodeIds = @("67860825", "61857932")
foreach ($LinodeId in $LinodeIds) {
    $UriReboot = "https://api.linode.com/v4/linode/instances/$LinodeId/reboot"
    Invoke-WebRequest -Uri $UriReboot -Method Post -Headers $Headers -Proxy $Proxy -ProxyUseDefaultCredentials | Out-Null
    Write-Output "Reboot request sent for Linode ID: $LinodeId."
}

# List Linode Types
Invoke-WebRequest -Uri "https://api.linode.com/v4/regions" -Headers $Headers -Proxy $Proxy -ProxyUseDefaultCredentials | ConvertFrom-Json | ConvertTo-Json



# 85E77FB4-AECB-473F-80527EE9756B1E6B
# 4E8886E5-080F-489E-80BEB4E3D6E59F4A