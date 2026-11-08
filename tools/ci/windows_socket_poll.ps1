# Polls the sockets owned by the desktop app and its WebView2 processes, for VS-1a's no-socket capture
# evidence on Windows (plan-v1.1 section C). It runs until the stop file exists, and writes one line per
# socket seen. Polling misses a socket that opens and closes between samples, and DNS through the shared
# Dnscache service is not attributed to the app. `netstat -ano` is used because Get-NetTCPConnection takes
# seconds per call, which would leave most of a short run unsampled.
param([Parameter(Mandatory)] [string] $Out, [Parameter(Mandatory)] [string] $Stop, [string] $Root = 'safeevidence-desktop.exe')

$ErrorActionPreference = 'Stop'
New-Item -ItemType File -Force -Path $Out | Out-Null
$samples = 0
while (-not (Test-Path $Stop)) {
  $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name
  $names = @{}
  foreach ($process in $processes) { $names[[int]$process.ProcessId] = $process.Name }
  $tree = [System.Collections.Generic.HashSet[int]]::new()
  foreach ($process in $processes) {
    if ($process.Name -eq $Root) { [void]$tree.Add([int]$process.ProcessId) }
  }
  # WebView2's processes descend from the app, through its browser process.
  do {
    $added = $false
    foreach ($process in $processes) {
      if ($tree.Contains([int]$process.ParentProcessId) -and $tree.Add([int]$process.ProcessId)) { $added = $true }
    }
  } while ($added)
  if ($tree.Count -gt 0) {
    $lines = @("tree|" + (($tree | ForEach-Object { $names[$_] }) | Sort-Object -Unique) -join ',')
    foreach ($row in (netstat -ano)) {
      $fields = -split $row
      # TCP rows: proto, local, remote, state, pid. UDP rows: proto, local, remote, pid.
      if ($fields.Count -eq 5 -and $fields[0] -eq 'TCP') {
        $owner = [int]$fields[4]; $state = $fields[3]
      } elseif ($fields.Count -eq 4 -and $fields[0] -eq 'UDP') {
        $owner = [int]$fields[3]; $state = 'Bound'
      } else { continue }
      if (-not $tree.Contains($owner)) { continue }
      $local = $fields[1]; $remote = $fields[2]
      $lp = $local.Substring($local.LastIndexOf(':') + 1); $la = $local.Substring(0, $local.LastIndexOf(':')).Trim('[', ']')
      $rp = $remote.Substring($remote.LastIndexOf(':') + 1); $ra = $remote.Substring(0, $remote.LastIndexOf(':')).Trim('[', ']')
      if ($state -eq 'LISTENING') { $state = 'Listen' }
      if ($state -eq 'Bound') { $ra = ''; $rp = '' }
      $lines += "$($fields[0].ToLower())|$($names[$owner])|$la|$lp|$ra|$rp|$state"
    }
    $samples += 1
    if ($lines.Count -gt 0) { Add-Content -Path $Out -Value $lines }
  }
  Start-Sleep -Milliseconds 100
}
Add-Content -Path $Out -Value "samples|$samples"
