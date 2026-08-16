# Define headers and proxy settings for the source account
$Headers = @{
    "Authorization" = "Bearer e5a9dadb3e13d693b0eeb31f62b82155a15bcabc07e008f0cf1bb3ad9201df50"  # Replace with your actual Linode API token
    "Content-type" = "application/json"
}

$Proxy = "http://127.0.0.1:7890"  # Adjust this if your proxy settings differ

# Step 1: Generate a Service Transfer Token from the source account
$TransferBody = @{
    "entities" = @{
        "linodes" = @(61857756)  # Replace with the actual Linode instance ID as an integer
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

# Define headers and proxy settings for the receiving account
$Headers = @{
    "Authorization" = "Bearer 85288d761d1201cd2ebd48a89d2b16fb831a3e81551ea58f71777f0d4c290532"  
    "Content-type" = "application/json"
}

$Proxy = "http://127.0.0.1:7890"  # Adjust this if your proxy settings differ

# Step 1: Accept the Service Transfer using the provided token
$ServiceTransferToken = "4E8886E5-080F-489E-80BEB4E3D6E59F4A"  # Replace with the actual service transfer token

# Execute the API request to accept the transfer
$AcceptTransferResponse = Invoke-WebRequest `
    -Uri "https://api.linode.com/v4/account/service-transfers/$ServiceTransferToken/accept" `
    -Method Post `
    -Headers $Headers `
    -Proxy $Proxy `
    -ProxyUseDefaultCredentials | ConvertFrom-Json

# Output the response to confirm the transfer acceptance
Write-Output "Service Transfer Response: $AcceptTransferResponse"
