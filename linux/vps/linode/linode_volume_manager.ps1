# Define headers and proxy settings for the account
$Headers = @{
    "Authorization" = "Bearer adc11bb37cb79693d9beacdd803605619d024c686a779e50895b3e30881df1c5"  # Replace with your actual Linode API token
    "Content-type" = "application/json"
}
$Proxy = "http://127.0.0.1:7890"  # Adjust if you have different proxy settings

# Define Linode and Volume details
$LinodeId = 61670275  # The ID of your Linode instance
$DiskId = 121060435  # The ID of your Linode disk
$VolumeId = 5181529  # The ID of your Linode volume
$NewSize = 300000  # New size in MB

# Get the list of disks for the Linode instance
$UriDisks = "https://api.linode.com/v4/linode/instances/$LinodeId/disks"
$responseDisks = Invoke-WebRequest -Uri $UriDisks -Headers $Headers -Proxy $Proxy -ProxyUseDefaultCredentials
$disks = $responseDisks.Content | ConvertFrom-Json

# Display the disk information
$disks.data | Format-Table id, label, size, filesystem

# Create a new volume
$VolumeBody = @{
    "label" = "new-volume"
    "size" = 128  # Size in GB
    "region" = "id-cgk"
    "linode_id" = $LinodeId
} | ConvertTo-Json

$UriCreateVolume = "https://api.linode.com/v4/volumes"
$responseCreateVolume = Invoke-WebRequest -Uri $UriCreateVolume -Method Post -Headers $Headers -Body $VolumeBody -Proxy $Proxy -ProxyUseDefaultCredentials | ConvertFrom-Json

Write-Output "New volume created and attached to Linode ID: $LinodeId."

# Get the list of volumes
$UriVolumes = "https://api.linode.com/v4/volumes"
$responseVolumes = Invoke-WebRequest -Uri $UriVolumes -Headers $Headers -Proxy $Proxy -ProxyUseDefaultCredentials
$volumes = $responseVolumes.Content | ConvertFrom-Json

# Display the volume information
$volumes.data | Format-Table id, label, size, region, status

# Attach a volume to Linode
$AttachVolumeBody = @{
    "linode_id" = $LinodeId
} | ConvertTo-Json

$UriAttachVolume = "https://api.linode.com/v4/volumes/$VolumeId/attach"
$responseAttachVolume = Invoke-WebRequest -Uri $UriAttachVolume -Method Post -Headers $Headers -Body $AttachVolumeBody | ConvertFrom-Json

Write-Output "Volume attached to Linode ID: $LinodeId"

# Resize the disk
$BodyResize = @{
    "size" = $NewSize
} | ConvertTo-Json

$UriResize = "https://api.linode.com/v4/linode/instances/$LinodeId/disks/$DiskId/resize"
Invoke-WebRequest -Uri $UriResize -Method Post -Headers $Headers -Body $BodyResize -Proxy $Proxy -ProxyUseDefaultCredentials | ConvertFrom-Json | ConvertTo-Json
Write-Output "Disk resize request sent for Linode ID: $LinodeId, Disk ID: $DiskId, New Size: $NewSize MB."

# Shut down the Linode
$HeadersShutdown = @{
    "Authorization" = "Bearer addd2c109dff650e576d27c0e4ced525526011ebbc1aa3b0dd0b26563a179270"  # Replace with your actual Linode API token
    "Content-type" = "application/json"
}

Invoke-WebRequest -Uri "https://api.linode.com/v4/linode/instances/$LinodeId/shutdown" -Method Post -Headers $HeadersShutdown -Proxy $Proxy -ProxyUseDefaultCredentials
Write-Output "Shutdown request sent for Linode ID: $LinodeId."

# Delete the block storage volume
$VolumeIdToDelete = 5181529  # Replace with the actual Volume ID you want to delete

$UriDeleteVolume = "https://api.linode.com/v4/volumes/$VolumeIdToDelete"
$responseDeleteVolume = Invoke-WebRequest -Uri $UriDeleteVolume -Method Delete -Headers $Headers -Proxy $Proxy -ProxyUseDefaultCredentials
Write-Output "Volume with ID $VolumeIdToDelete has been deleted."

# Resize the disk with error handling
try {
    $responseResize = Invoke-WebRequest -Uri $UriResize -Method Post -Headers $Headers -Body $BodyResize -Proxy $Proxy -ProxyUseDefaultCredentials
    $responseContentResize = $responseResize.Content | ConvertFrom-Json
    Write-Output "Disk resize request sent for Linode ID: $LinodeId, Disk ID: $DiskId, New Size: $NewSize MB."
    Write-Output $responseContentResize | ConvertTo-Json
} catch {
    Write-Error "Failed to resize the disk: $_"
}
