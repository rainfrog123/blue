$ErrorActionPreference = 'SilentlyContinue'

Write-Host '=== policy ==='
Write-Host (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System').DefaultAssociationsConfiguration

Write-Host ''
Write-Host '=== XML files ==='
@(
  'C:\Windows\System32\OEMDefaultAssociations.xml',
  'C:\Windows\System32\DefaultAssociations.xml',
  'C:\ProgramData\ChromeDefaultAssociations\chrome-defaults.xml'
) | ForEach-Object {
  if (Test-Path $_) {
    $i = Get-Item $_
    Write-Host ("{0}  {1} bytes  {2}" -f $i.FullName, $i.Length, $i.LastWriteTime)
  } else {
    Write-Host "missing $_"
  }
}

Write-Host ''
Write-Host '=== FileExts with UserChoice or Latest ==='
$root = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts'
$rows = @()
Get-ChildItem $root | ForEach-Object {
  $ext = $_.PSChildName
  if ($ext -notmatch '^\.') { return }
  $uc = Join-Path $_.PSPath 'UserChoice'
  $ul = Join-Path $_.PSPath 'UserChoiceLatest'
  $prog = $null; $hash = $null; $lprog = $null
  if (Test-Path $uc) {
    $p = Get-ItemProperty $uc
    $prog = $p.ProgId
    $hash = $p.Hash
  }
  $ulp = Join-Path $ul 'ProgId'
  if (Test-Path $ulp) { $lprog = (Get-ItemProperty $ulp).ProgId }
  elseif (Test-Path $ul) { $lprog = (Get-ItemProperty $ul).ProgId }
  $rows += [pscustomobject]@{ Ext = $ext; UserChoice = $prog; Hash = $hash; Latest = $lprog }
}
$has = @($rows | Where-Object { $_.UserChoice -or $_.Latest })
$empty = @($rows | Where-Object { -not $_.UserChoice -and -not $_.Latest })
$mismatch = @($has | Where-Object { $_.UserChoice -and $_.Latest -and ($_.UserChoice -ne $_.Latest) })
$choiceOnly = @($has | Where-Object { $_.UserChoice -and -not $_.Latest })
$latestOnly = @($has | Where-Object { $_.Latest -and -not $_.UserChoice })
Write-Host ("total FileExts: {0}" -f $rows.Count)
Write-Host ("has a user choice: {0}" -f $has.Count)
Write-Host ("neither (OEM/Windows fallback): {0}" -f $empty.Count)
Write-Host ("UserChoice vs Latest mismatch: {0}" -f $mismatch.Count)
Write-Host ("classic only: {0}" -f $choiceOnly.Count)
Write-Host ("Latest only: {0}" -f $latestOnly.Count)
Write-Host ''
Write-Host '-- HAS --'
$has | Sort-Object Ext | Format-Table Ext, UserChoice, Latest -AutoSize | Out-String -Width 200 | Write-Host
if ($mismatch.Count) {
  Write-Host '-- MISMATCH --'
  $mismatch | Sort-Object Ext | Format-Table Ext, UserChoice, Latest -AutoSize | Out-String -Width 200 | Write-Host
}

Write-Host '=== HashVersion ==='
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SystemProtectedUserData' | ForEach-Object {
  $p = Join-Path $_.PSPath 'AnyoneRead\AppDefaults'
  if (Test-Path $p) {
    Write-Host $_.PSChildName
    Get-ItemProperty $p | Select-Object HashVersion | Format-List | Out-String | Write-Host
  }
}

Write-Host '=== chrome-defaults.xml head ==='
$cx = 'C:\ProgramData\ChromeDefaultAssociations\chrome-defaults.xml'
if (Test-Path $cx) { Get-Content $cx -TotalCount 80 }

Write-Host ''
Write-Host '=== OEMDefaultAssociations.xml association count ==='
$oem = 'C:\Windows\System32\OEMDefaultAssociations.xml'
if (Test-Path $oem) {
  [xml]$x = Get-Content $oem
  $assoc = $x.SelectNodes('//Association')
  Write-Host ("OEM Association nodes: {0}" -f $assoc.Count)
  $assoc | Select-Object -First 25 Identifier, ProgId | Format-Table -AutoSize | Out-String | Write-Host
}
