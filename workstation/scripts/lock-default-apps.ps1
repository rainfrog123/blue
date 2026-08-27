# Snapshot current UserChoiceLatest (and UserChoice) into a full
# DefaultAssociations XML, then remove Chrome's 11-line GPO so logon/Update
# stop resetting every other default app to OEM.
#
# Run elevated. Chrome Update may recreate the tiny XML + policy key.

$ErrorActionPreference = 'Stop'

$outDir = 'C:\ProgramData\DefaultAssociations'
$outXml = Join-Path $outDir 'this-pc.xml'
$chromeXml = 'C:\ProgramData\ChromeDefaultAssociations\chrome-defaults.xml'
$policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
$policyName = 'DefaultAssociationsConfiguration'

$names = @{
  ChromeHTML = 'Google Chrome'
  MSEdgeHTM = 'Microsoft Edge'
  MSEdgePDF = 'Microsoft Edge'
  'AppX43hnxtbyyps62jhe9sqpdzxn1790zetc' = 'Photos'
  'AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h' = 'Photos'
  'AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs' = 'Movies & TV'
  'AppXkv2jqn1pq8ajm0p5dhgqde7aafykkrrn' = 'Notepad'
  'AppXfeq5vwnakrw6cy02kzhq8ekhhsremh62' = 'Snipping Tool'
}

function Get-LatestProgId($base) {
  $ulp = Join-Path $base 'UserChoiceLatest\ProgId'
  if (Test-Path $ulp) {
    $p = (Get-ItemProperty $ulp -ErrorAction SilentlyContinue).ProgId
    if ($p) { return [string]$p }
  }
  $uc = Join-Path $base 'UserChoice'
  if (Test-Path $uc) {
    $p = (Get-ItemProperty $uc -ErrorAction SilentlyContinue).ProgId
    if ($p) { return [string]$p }
  }
  return $null
}

$rows = New-Object System.Collections.Generic.List[object]

$extRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts'
Get-ChildItem $extRoot -ErrorAction SilentlyContinue | ForEach-Object {
  $id = $_.PSChildName
  if ($id -notmatch '^\.') { return }
  $prog = Get-LatestProgId $_.PSPath
  if (-not $prog) { return }
  $rows.Add([pscustomobject]@{ Identifier = $id; ProgId = $prog })
}

$urlRoot = 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations'
Get-ChildItem $urlRoot -ErrorAction SilentlyContinue | ForEach-Object {
  $id = $_.PSChildName
  if ($id -eq 'microsoft-edge' -or $id -eq 'microsoft-edge-holographic') { return }
  $prog = Get-LatestProgId $_.PSPath
  if (-not $prog) { return }
  $rows.Add([pscustomobject]@{ Identifier = $id; ProgId = $prog })
}

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
[void]$sb.AppendLine('<DefaultAssociations>')
$rows | Sort-Object Identifier -Unique | ForEach-Object {
  $app = $names[$_.ProgId]
  if (-not $app) { $app = $_.ProgId }
  $id = [System.Security.SecurityElement]::Escape($_.Identifier)
  $prog = [System.Security.SecurityElement]::Escape($_.ProgId)
  $app = [System.Security.SecurityElement]::Escape($app)
  [void]$sb.AppendLine("  <Association Identifier=`"$id`" ProgId=`"$prog`" ApplicationName=`"$app`" />")
}
[void]$sb.AppendLine('</DefaultAssociations>')
$xml = $sb.ToString()

New-Item -ItemType Directory -Force -Path $outDir | Out-Null
Set-Content -Path $outXml -Value $xml -Encoding UTF8
Write-Host "Wrote $outXml ($($rows.Count) associations)"

$chromeDir = Split-Path $chromeXml
if (Test-Path $chromeDir) {
  Copy-Item -Path $outXml -Destination $chromeXml -Force
  Write-Host "Replaced $chromeXml with the full snapshot"
}

# Stop Windows re-applying any XML on logon. Needs elevation.
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
  Write-Host 'Not elevated — policy key left as-is. Re-run as Administrator to delete DefaultAssociationsConfiguration.'
  exit 2
}

if (Get-ItemProperty -Path $policyKey -Name $policyName -ErrorAction SilentlyContinue) {
  Remove-ItemProperty -Path $policyKey -Name $policyName -Force
  Write-Host "Removed $policyKey\$policyName"
} else {
  Write-Host 'Policy key already absent'
}

Write-Host 'Done. Set defaults in Settings if a type still falls through to OEM. Chrome Update may recreate the tiny GPO.'
