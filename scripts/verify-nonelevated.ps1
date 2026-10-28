[CmdletBinding()]
param(
    [string]$Filter = ''
)

$ErrorActionPreference = 'Continue'
$repo = Split-Path $PSScriptRoot -Parent
Set-Location $repo

$cargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
if (-not (Test-Path $cargo)) { throw "cargo not found at $cargo" }

Write-Host '== building test binaries (elevated) =='
$json = & cmd.exe /c "`"$cargo`" test --no-run --message-format=json 2>nul"
$cargoExit = $LASTEXITCODE
if ($cargoExit -ne 0) { throw "cargo test --no-run failed with $cargoExit" }

$exes = @()
foreach ($line in $json) {
    if ($line -notmatch '"executable"') { continue }
    $msg = $null
    try { $msg = $line | ConvertFrom-Json } catch { continue }
    if ($msg.reason -ne 'compiler-artifact') { continue }
    if (-not $msg.executable) { continue }
    if (-not $msg.profile.test) { continue }
    $exes += $msg.executable
}
$exes = $exes | Select-Object -Unique
if ($exes.Count -eq 0) { throw 'no test executables were reported by cargo' }
$exes | ForEach-Object { Write-Host ('  ' + (Split-Path $_ -Leaf)) }

Write-Host ''
Write-Host '== integrity level of the launched token =='
$probeOut = Join-Path $env:TEMP 'memscope-nonelevated-il.txt'
Remove-Item $probeOut -ErrorAction SilentlyContinue
$probeCmd = Join-Path $env:TEMP 'memscope-nonelevated-il.cmd'
Set-Content -Path $probeCmd -Encoding ascii -Value "whoami /groups > `"$probeOut`" 2>&1"
& (Join-Path $PSScriptRoot 'run-medium.ps1') -Command 'cmd.exe', '/c', $probeCmd -WorkingDirectory $env:TEMP | Out-Null
if (-not (Test-Path $probeOut)) { throw 'the integrity probe produced no output' }
$label = (Get-Content $probeOut | Select-String -Pattern 'Mandatory Label').Line
if ($label -notmatch 'Medium Mandatory Level') {
    throw "the launched token is not medium integrity: $label"
}
Write-Host ($label.Trim() -replace '\s+', ' ')
$adminGroup = (Get-Content $probeOut | Select-String -Pattern 'BUILTIN\\Administrators')
if ($adminGroup) {
    Write-Host 'NOTE: Administrators remains enabled in this token; the LUA_TOKEN mode is rejected by this window station.'
    Write-Host '      The verified property is medium integrity, not a fully UAC-filtered token.'
}

$failures = 0
foreach ($exe in $exes) {
    $name = Split-Path $exe -Leaf
    Write-Host ''
    Write-Host "== $name at medium integrity =="
    $log = Join-Path $env:TEMP ("memscope-nonelevated-" + $name + '.log')
    Remove-Item $log -ErrorAction SilentlyContinue
    $runner = Join-Path $env:TEMP ("memscope-nonelevated-" + $name + '.cmd')
    $args = if ($Filter) { " $Filter" } else { '' }
    Set-Content -Path $runner -Encoding ascii -Value @(
        "cd /d `"$repo`"",
        "`"$exe`"$args --test-threads 2 > `"$log`" 2>&1",
        "exit /b %ERRORLEVEL%"
    )
    $code = 0
    try {
        & (Join-Path $PSScriptRoot 'run-medium.ps1') -Command 'cmd.exe', '/c', $runner -WorkingDirectory $repo | Out-Null
        $code = $LASTEXITCODE
    }
    catch {
        Write-Host "launch failed: $($_.Exception.Message)"
        $code = 1
    }
    if (Test-Path $log) {
        Get-Content $log | Select-String -Pattern 'running \d+ tests|test result|^test .*(ok|FAILED)|panicked' |
            ForEach-Object { Write-Host ('  ' + $_.Line) }
    }
    else {
        Write-Host '  (no log produced)'
    }
    if ($code -ne 0) {
        $failures++
        Write-Host "  exit code $code"
    }
}

Write-Host ''
if ($failures -eq 0) {
    Write-Host 'All test binaries passed at medium integrity.' -ForegroundColor Green
    exit 0
}
Write-Host "$failures test binaries FAILED at medium integrity." -ForegroundColor Red
exit 1
