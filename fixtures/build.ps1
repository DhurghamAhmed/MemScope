[CmdletBinding()]
param(
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

$fixtures = $PSScriptRoot
$binRoot = Join-Path $fixtures 'bin'
$anchorSrc = Join-Path $fixtures 'anchor\anchor.c'
$anchorDef = Join-Path $fixtures 'anchor\anchor.def'
$fixtureSrc = Join-Path $fixtures 'MemScopeFixture.cs'

if ($Clean -and (Test-Path $binRoot)) {
    Remove-Item $binRoot -Recurse -Force
}

$csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) {
    throw "csc.exe not found at $csc. See the build dependencies in fixtures/README.md."
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) {
    throw "vswhere.exe not found at $vswhere; cannot locate vcvarsall.bat."
}

$vsPath = & $vswhere -products * -format value -property installationPath |
    Where-Object { Test-Path (Join-Path $_ 'VC\Auxiliary\Build\vcvarsall.bat') } |
    Select-Object -First 1
if (-not $vsPath) {
    throw 'No Visual Studio installation with VC\Auxiliary\Build\vcvarsall.bat was found.'
}
$vcvarsall = Join-Path $vsPath 'VC\Auxiliary\Build\vcvarsall.bat'

Write-Host "csc:       $csc"
Write-Host "vcvarsall: $vcvarsall"
Write-Host ''

function Build-Anchor {
    param(
        [Parameter(Mandatory)][ValidateSet('x64', 'x86')][string]$Arch,
        [Parameter(Mandatory)][string]$OutDir
    )

    $scratch = Join-Path $OutDir '.obj'
    New-Item -ItemType Directory -Force -Path $scratch | Out-Null

    $dll = Join-Path $OutDir 'memscope_anchor.dll'

    $clArgs = @(
        '/nologo', '/W4', '/WX', '/Od', '/MT', '/Zi',
        "/Fo$scratch\", "/Fd$scratch\anchor.pdb",
        '/LD', $AnchorSrcResolved,
        '/link', "/DEF:$AnchorDefResolved", "/OUT:$dll",
        "/IMPLIB:$scratch\memscope_anchor.lib", "/PDB:$scratch\memscope_anchor.pdb"
    )

    $installerDir = Split-Path $vswhere -Parent
    $command = 'set "PATH=' + $installerDir + ';%PATH%" && call "' + $vcvarsall + '" ' + $Arch +
        ' >nul && cl ' + ($clArgs -join ' ')
    Write-Host "[$Arch] building memscope_anchor.dll"
    & cmd.exe /c $command
    if ($LASTEXITCODE -ne 0) {
        throw "[$Arch] cl.exe failed with exit code $LASTEXITCODE"
    }
    if (-not (Test-Path $dll)) {
        throw "[$Arch] cl.exe reported success but $dll does not exist"
    }
    Remove-Item $scratch -Recurse -Force
}

function Build-Fixture {
    param(
        [Parameter(Mandatory)][ValidateSet('x64', 'x86')][string]$Arch,
        [Parameter(Mandatory)][string]$OutDir
    )

    $exe = Join-Path $OutDir 'memscope-fixture.exe'

    $cscArgs = @(
        '/nologo', '/warn:4', '/warnaserror+', '/optimize-', '/debug:pdbonly',
        "/platform:$Arch",
        '/target:exe', "/out:$exe",
        '/reference:System.dll', '/reference:System.Core.dll',
        $fixtureSrc
    )
    Write-Host "[$Arch] building memscope-fixture.exe"
    & $csc @cscArgs
    if ($LASTEXITCODE -ne 0) {
        throw "[$Arch] csc.exe failed with exit code $LASTEXITCODE"
    }
}

$AnchorSrcResolved = $anchorSrc
$AnchorDefResolved = $anchorDef

foreach ($arch in @('x64', 'x86')) {
    $outDir = Join-Path $binRoot $arch
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    Build-Anchor -Arch $arch -OutDir $outDir
    Build-Fixture -Arch $arch -OutDir $outDir
}

Write-Host ''
Write-Host 'Built:'
Get-ChildItem $binRoot -Recurse -Include '*.exe', '*.dll' |
    ForEach-Object {
        $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        Write-Host ('  {0,-56} {1,8} bytes  {2}' -f $_.FullName.Substring($binRoot.Length + 1), $_.Length, $hash.Substring(0, 16))
    }
