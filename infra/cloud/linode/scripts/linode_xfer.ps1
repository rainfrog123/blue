# Define headers and proxy settings for the source account
# Load credentials from cred.json
$credPath = Join-Path $env:USERPROFILE "Documents\cred.json"
$cred = Get-Content $credPath | ConvertFrom-Json
$linodeTokenSource = $cred.linode.tokens[1]  # Use token index 1

$Headers = @{
    "Authorization" = "Bearer $linodeTokenSource"
    "Content-type" = "application/json"
}

$Proxy = "http://127.0.0.1:7890"  # Adjust this if your proxy settings differ

# Step 1: Generate a Service Transfer Token from the source account
$TransferBody = @{
    "entities" = @{
        "linodes" = @(61857931)  # Replace with the actual Linode instance ID as an integer
    }
} | ConvertTo-Json

# Execute the API request to generate the transfer token
$GenerateTokenResponse = Invoke-WebRequest `
    -Uri "https://api.linode.com/v4/account/service-transfers" `
    -Method Post `
    -Headers $Headers `
    -Body $TransferBody `
    -Proxy $Proxy `
    -ProxyUseDefaultCredentials | ConvertFrom-Json

# Retrieve the transfer token from the response
$TransferToken = $GenerateTokenResponse.token

# Output the transfer token (ensure this is securely sent to the receiving account)
Write-Output "Service Transfer Token: $TransferToken"

# 9E327FBA-0C9B-477D-8F73487B02D8256F

# Define headers and proxy settings for the receiving account
$linodeTokenReceiving = $cred.linode.tokens[2]  # Use token index 2
$Headers = @{
    "Authorization" = "Bearer $linodeTokenReceiving"
    "Content-type" = "application/json"
}

$Proxy = "http://127.0.0.1:7890"  # Adjust this if your proxy settings differ

# Step 1: Accept the Service Transfer using the provided token
$ServiceTransferToken = "YOUR_SERVICE_TRANSFER_TOKEN"  # Replace with actual token when needed

# Execute the API request to accept the transfer
$AcceptTransferResponse = Invoke-WebRequest `
    -Uri "https://api.linode.com/v4/account/service-transfers/$ServiceTransferToken/accept" `
    -Method Post `
    -Headers $Headers `
    -Proxy $Proxy `
    -ProxyUseDefaultCredentials | ConvertFrom-Json

# Output the response to confirm the transfer acceptance
Write-Output "Service Transfer Response: $AcceptTransferResponse"
