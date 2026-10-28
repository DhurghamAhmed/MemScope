#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\memscope",
    [string]$Version = 'latest',
    [switch]$Skills,
    [string]$SkillsDir = (Join-Path (Get-Location) '.claude\skills'),
    [switch]$NoPathSetup
)

$ErrorActionPreference = 'Stop'
$repo = 'DhurghamAhmed/MemScope'
$branch = 'main'

if ([Environment]::OSVersion.Platform -ne 'Win32NT') {
    throw 'MemScope runs on Windows only.'
}
if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'MemScope requires 64-bit Windows.'
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ($Version -eq 'latest') {
    $base = "https://github.com/$repo/releases/latest/download"
} else {
    $base = "https://github.com/$repo/releases/download/$Version"
}

$staging = Join-Path ([IO.Path]::GetTempPath()) ("memscope-" + [Guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $staging -Force | Out-Null

try {
    $exe = Join-Path $staging 'memscope.exe'
    $sums = Join-Path $staging 'SHA256SUMS.txt'

    Write-Host "Downloading memscope.exe ($Version)..."
    Invoke-WebRequest -Uri "$base/memscope.exe" -OutFile $exe -UseBasicParsing
    Invoke-WebRequest -Uri "$base/SHA256SUMS.txt" -OutFile $sums -UseBasicParsing

    $expected = $null
    foreach ($line in (Get-Content $sums)) {
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?memscope\.exe\s*$') {
            $expected = $matches[1].ToLower()
            break
        }
    }
    if (-not $expected) {
        throw 'SHA256SUMS.txt does not contain a hash for memscope.exe. Refusing to install.'
    }

    $actual = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected) {
        throw "Hash mismatch. Expected $expected, got $actual. The download was NOT installed."
    }
    Write-Host "Verified sha256 $actual"

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $target = Join-Path $InstallDir 'memscope.exe'
    Copy-Item $exe $target -Force
    Copy-Item $sums (Join-Path $InstallDir 'SHA256SUMS.txt') -Force
    Write-Host "Installed $target"

    [Environment]::SetEnvironmentVariable('MEMSCOPE_BIN', $target, 'User')
    $env:MEMSCOPE_BIN = $target
    Write-Host 'Set MEMSCOPE_BIN for your user account.'

    if (-not $NoPathSetup) {
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if ($null -eq $userPath) { $userPath = '' }
        if (($userPath -split ';') -notcontains $InstallDir) {
            [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $InstallDir).TrimStart(';'), 'User')
            Write-Host "Added $InstallDir to your user Path."
        }
    }

    if ($Skills) {
        $skillDest = Join-Path $SkillsDir 'memory-investigation'
        New-Item -ItemType Directory -Path $skillDest -Force | Out-Null
        $skillUrl = "https://raw.githubusercontent.com/$repo/$branch/plugin/memscope/skills/memory-investigation/SKILL.md"
        Invoke-WebRequest -Uri $skillUrl -OutFile (Join-Path $skillDest 'SKILL.md') -UseBasicParsing
        Write-Host "Installed the memory-investigation skill into $skillDest"
    }

    $json = @"
{
  "mcpServers": {
    "memscope": {
      "command": "$($target -replace '\\', '\\\\')",
      "args": ["serve"]
    }
  }
}
"@

    Write-Host ''
    Write-Host 'Next: register the server with your MCP client.'
    Write-Host ''
    Write-Host 'Claude Code plugin (server and skill together):'
    Write-Host "  /plugin marketplace add $repo"
    Write-Host '  /plugin install memscope'
    Write-Host ''
    Write-Host 'Or add this to .mcp.json in your project:'
    Write-Host $json
    Write-Host ''
    Write-Host 'Then restart the session. Writes stay disabled until you add'
    Write-Host '"MEMSCOPE_ALLOW_WRITE": "1" to the env block AND send confirm: true per call.'
    if (-not $Skills) {
        Write-Host ''
        Write-Host 'Re-run with -Skills to also install the investigation skill into .claude/skills.'
    }
}
finally {
    Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
}
