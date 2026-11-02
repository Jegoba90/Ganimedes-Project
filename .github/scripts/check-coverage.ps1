param(
    [string]$Profile = 'coverage.out',
    [string]$Baseline = '.github/coverage-baseline.json'
)

$ErrorActionPreference = 'Stop'
$floors = Get-Content -LiteralPath $Baseline -Raw | ConvertFrom-Json
$totals = @{}
$covered = @{}
$lines = Get-Content -LiteralPath $Profile
if ($lines.Count -lt 2 -or $lines[0] -notmatch '^mode: (set|count|atomic)$') {
    throw 'Missing or invalid Go coverage profile'
}
foreach ($line in $lines[1..($lines.Count - 1)]) {
    if ($line -notmatch '^github\.com/Jegoba90/Ganimedes-Project/(.+)/[^/:]+\.go:\d+\.\d+,\d+\.\d+ (\d+) (\d+)$') {
        throw "Invalid coverage record: $line"
    }
    $package = $Matches[1]
    $statements = [long]$Matches[2]
    $count = [long]$Matches[3]
    $totals[$package] += $statements
    if ($count -gt 0) { $covered[$package] += $statements }
}
foreach ($property in $floors.PSObject.Properties) {
    $package = $property.Name
    if (-not $totals.ContainsKey($package) -or $totals[$package] -eq 0) {
        throw "Package absent from coverage profile: $package"
    }
    $actual = [Math]::Round(100.0 * $covered[$package] / $totals[$package], 1)
    if ($actual -lt [double]$property.Value) {
        throw "Coverage decreased for ${package}: $actual% < $($property.Value)%"
    }
    Write-Output "${package}: $actual% (minimum $($property.Value)%)"
}
foreach ($package in $totals.Keys) {
    # main is deliberately one os.Exit call; behavior is tested through cli.Run.
    if ($package -ne 'cmd/ganimedes' -and $package -notin $floors.PSObject.Properties.Name) {
        throw "New package needs a measured coverage floor: $package"
    }
}
