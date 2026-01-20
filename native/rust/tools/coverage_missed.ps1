param(
  [int]$Top = 25,
  [int]$RangesPerFile = 12
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$lcov = Join-Path $PSScriptRoot '..\coverage\lcov.info'
$lcov = (Resolve-Path $lcov).Path

if (!(Test-Path $lcov)) {
  throw "LCOV not found: $lcov"
}

$miss = @{}
$current = $null

Get-Content $lcov | ForEach-Object {
  if ($_ -like 'SF:*') {
    $current = $_.Substring(3)
    if (-not $miss.ContainsKey($current)) {
      $miss[$current] = New-Object System.Collections.Generic.List[int]
    }
    return
  }

  if ($current -and $_ -like 'DA:*') {
    $parts = $_.Substring(3).Split(',')
    $line = [int]$parts[0]
    $hits = [int]$parts[1]
    if ($hits -eq 0) {
      $miss[$current].Add($line)
    }
    return
  }

  if ($_ -eq 'end_of_record') {
    $current = $null
  }
}

function Get-Ranges([int[]]$Lines) {
  if ($null -eq $Lines -or $Lines.Count -eq 0) {
    return New-Object System.Collections.Generic.List[string]
  }

  $Lines = $Lines | Sort-Object
  $ranges = New-Object System.Collections.Generic.List[string]

  $start = $Lines[0]
  $prev = $Lines[0]

  for ($i = 1; $i -lt $Lines.Count; $i++) {
    $v = $Lines[$i]
    if ($v -eq ($prev + 1)) {
      $prev = $v
      continue
    }

    if ($start -eq $prev) { $ranges.Add("$start") } else { $ranges.Add("$start-$prev") }
    $start = $v
    $prev = $v
  }

  if ($start -eq $prev) { $ranges.Add("$start") } else { $ranges.Add("$start-$prev") }
  return $ranges
}

$topFiles = $miss.GetEnumerator() | ForEach-Object {
  [pscustomobject]@{ File = $_.Key; Missed = $_.Value.Count }
} | Sort-Object Missed -Descending | Select-Object -First $Top

$topFiles | Format-Table -AutoSize

foreach ($t in $topFiles) {
  $f = $t.File
  $ranges = Get-Ranges ($miss[$f].ToArray())
  Write-Output ""
  Write-Output "== $f == missed=$($t.Missed)"
  $ranges | Select-Object -First $RangesPerFile | ForEach-Object { Write-Output ("  " + $_) }
}
