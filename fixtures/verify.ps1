[CmdletBinding()]
param(
    [ValidateSet('x64', 'x86', 'both')][string]$Arch = 'both',
    [switch]$Bench
)

$ErrorActionPreference = 'Stop'
$script:Failures = 0
$script:Checks = 0

function Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    $script:Checks++
    if ($Ok) {
        Write-Host ('  PASS  ' + $Name) -ForegroundColor Green
    }
    else {
        $script:Failures++
        Write-Host ('  FAIL  ' + $Name + '  ' + $Detail) -ForegroundColor Red
    }
}

function Test-Fixture {
    param([string]$Architecture)

    $exe = Join-Path $PSScriptRoot "bin\$Architecture\memscope-fixture.exe"
    if (-not (Test-Path $exe)) {
        throw "$exe not found; run fixtures/build.ps1 first."
    }

    Write-Host ''
    Write-Host "=== $Architecture : $exe ===" -ForegroundColor Cyan

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    if ($Bench) { $psi.Arguments = '--bench' }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = Split-Path $exe -Parent

    $proc = [System.Diagnostics.Process]::Start($psi)
    $client = $null
    try {

        $jsonLine = $proc.StandardOutput.ReadLine()
        $readyLine = $proc.StandardOutput.ReadLine()

        Check 'startup emits a readiness sentinel' ($readyLine -eq 'ready') "got '$readyLine'"
        $meta = $null
        try { $meta = $jsonLine | ConvertFrom-Json } catch { }
        Check 'startup line is machine-readable JSON' ($null -ne $meta)
        if ($null -eq $meta) { return }

        Check 'metadata reports the real PID' ($meta.pid -eq $proc.Id) "meta=$($meta.pid) actual=$($proc.Id)"
        $expectedArch = if ($Architecture -eq 'x64') { 'x64' } else { 'x86' }
        Check "metadata reports arch $expectedArch" ($meta.arch -eq $expectedArch) "got $($meta.arch)"
        $expectedPtr = if ($Architecture -eq 'x64') { 8 } else { 4 }
        Check "pointer size is $expectedPtr" ($meta.pointer_size -eq $expectedPtr) "got $($meta.pointer_size)"
        if ($Architecture -eq 'x86') {
            Check 'x86 fixture reports itself as WOW64' ($meta.wow64 -eq $true) "got $($meta.wow64)"
        }
        Check 'control channel id is unique per run' ($meta.pipe_name -match '^memscope-fixture-[0-9a-f]{32}$') "got $($meta.pipe_name)"
        Check 'block address is reported' ($meta.areas.block.address -match '^0x[0-9a-f]+$')
        Check 'noaccess area is flagged unreadable' ($meta.areas.noaccess.readable -eq $false)
        Check 'guard area is flagged unreadable' ($meta.areas.guard.readable -eq $false)

        $rootRva = [Convert]::ToUInt64($meta.pointer_chain.root_rva.Substring(2), 16)
        $anchorBase = [Convert]::ToUInt64($meta.pointer_chain.anchor_base.Substring(2), 16)
        $rootAddr = [Convert]::ToUInt64($meta.pointer_chain.root_address.Substring(2), 16)
        Check 'root address equals anchor base + RVA' (($anchorBase + $rootRva) -eq $rootAddr) `
            "base=$anchorBase rva=$rootRva root=$rootAddr"
        Check 'root RVA is non-zero and small (a data-section offset)' ($rootRva -gt 0 -and $rootRva -lt 0x200000) "rva=$rootRva"

        $client = New-Object System.IO.Pipes.NamedPipeClientStream('.', $meta.pipe_name, [System.IO.Pipes.PipeDirection]::InOut)
        $client.Connect(5000)
        $writer = New-Object System.IO.StreamWriter($client)
        $writer.AutoFlush = $true
        $reader = New-Object System.IO.StreamReader($client)

        function Send {
            param([string]$Command)
            $writer.WriteLine($Command)
            return $reader.ReadLine()
        }

        Check 'ping round trip' ((Send 'ping') -eq 'pong')
        Check 'initial counter is 100' ((Send 'get') -eq 'value=100')
        Check 'set' ((Send 'set 500') -eq 'value=500')
        Check 'add' ((Send 'add 25') -eq 'value=525')
        Check 'sub' ((Send 'sub 5') -eq 'value=520')
        Check 'get reflects the arithmetic' ((Send 'get') -eq 'value=520')

        $blockAddr = $meta.areas.block.address
        $counterOff = [int]$meta.layout.counter
        $counterAddr = '0x' + ([Convert]::ToUInt64($blockAddr.Substring(2), 16) + $counterOff).ToString('x')
        $readReply = Send ("read $counterAddr 4")
        Check 'raw byte read agrees with the decoded counter' ($readReply -eq 'bytes=08020000 area=block') "got '$readReply'"

        $sentBeforeAddr = '0x' + ([Convert]::ToUInt64($blockAddr.Substring(2), 16) + [int]$meta.layout.sentinel_before).ToString('x')
        $sentAfterAddr = '0x' + ([Convert]::ToUInt64($blockAddr.Substring(2), 16) + [int]$meta.layout.sentinel_after).ToString('x')
        Check 'sentinel before the counter is intact' ((Send "read $sentBeforeAddr 4") -eq 'bytes=a5a5a5a5 area=block')
        Check 'sentinel after the counter is intact' ((Send "read $sentAfterAddr 4") -eq 'bytes=5a5a5a5a area=block')

        $tenthAddr = '0x' + ([Convert]::ToUInt64($blockAddr.Substring(2), 16) + [int]$meta.layout.f32_tenth).ToString('x')
        Check 'binary32 0.1 is cd cc cc 3d in memory' ((Send "read $tenthAddr 4") -eq 'bytes=cdcccc3d area=block')

        $guardAddr = '0x' + ([Convert]::ToUInt64($blockAddr.Substring(2), 16) + [int]$meta.layout.pointer_guard_after).ToString('x')
        Check 'guard bytes after the pointer are non-zero' ((Send "read $guardAddr 8") -eq 'bytes=bebafecaefbeadde area=block') `
            "got '$(Send "read $guardAddr 8")'"

        $chain = Send 'chain'
        Check 'chain reports the leaf value' ($chain -match 'value=1337$') "got '$chain'"
        Check 'chain node1 matches the metadata' ($chain -match ('node1=' + [regex]::Escape($meta.pointer_chain.node1).Replace('\+', '\+'))) "got '$chain'"

        Check 'noaccess area refuses a peek' ((Send 'peek noaccess') -eq 'err=area_is_deliberately_inaccessible')
        Check 'an address outside the fixture is refused' ((Send 'read 0x1 4') -eq 'err=address_outside_readable_fixture_area')

        Check 'protect noaccess succeeds' ((Send 'protect noaccess') -match '^protect=noaccess previous=0x4$')
        Check 'protect readwrite restores' ((Send 'protect rw') -match '^protect=rw previous=0x1$')

        Check 'tick accepts a bounded interval' ((Send 'tick 20') -eq 'tick=20')
        Start-Sleep -Milliseconds 300
        $running = [int]((Send 'get') -replace '^value=', '')
        Check 'self-mutation advances the counter' ($running -gt 520) "value=$running"
        Check 'pause is acknowledged' ((Send 'pause') -eq 'paused=1')
        Start-Sleep -Milliseconds 250
        $a = [int]((Send 'get') -replace '^value=', '')
        Start-Sleep -Milliseconds 250
        $b = [int]((Send 'get') -replace '^value=', '')
        Check 'the counter is stable while paused' ($a -eq $b) "a=$a b=$b"
        Check 'resume is acknowledged' ((Send 'resume') -eq 'resumed=1')
        Start-Sleep -Milliseconds 250
        $c = [int]((Send 'get') -replace '^value=', '')
        Check 'the counter advances again after resume' ($c -gt $b) "b=$b c=$c"
        Check 'tick 0 stops self-mutation' ((Send 'tick 0') -eq 'tick=0')

        Check 'an out-of-range tick interval is refused' ((Send 'tick 5') -eq 'err=interval_out_of_range')
        Check 'a non-integer operand is refused' ((Send 'add kittens') -eq 'err=not_an_integer')
        Check 'an over-long read is refused' ((Send "read $blockAddr 9999") -eq 'err=length_out_of_range')
        Check 'an unknown command is refused' ((Send 'frobnicate') -eq 'err=unknown_command')

        $ext = Send 'externals'
        Check 'no external change has been observed yet' ($ext -match '^external_changes=0 ') "got '$ext'"

        if ($Bench) {
            Check 'bench workload is reported as enabled' ($meta.datasets.bench_enabled -eq $true)
            Check 'bench workload is 128 MiB' ($meta.datasets.bench_size -eq 134217728) "got $($meta.datasets.bench_size)"
            Check 'bench match count was measured, not assumed' ($meta.datasets.bench_matches -ge 34) "got $($meta.datasets.bench_matches)"
        }

        Check 'exit is acknowledged' ((Send 'exit') -eq 'bye')
        $exited = $proc.WaitForExit(5000)
        Check 'the fixture exits gracefully' ($exited -and $proc.ExitCode -eq 0) "exited=$exited code=$($proc.ExitCode)"
    }
    finally {
        if ($null -ne $client) { $client.Dispose() }
        if (-not $proc.HasExited) {
            $proc.Kill()
            $proc.WaitForExit(2000) | Out-Null
        }
    }
}

$targets = if ($Arch -eq 'both') { @('x64', 'x86') } else { @($Arch) }
foreach ($t in $targets) {
    Test-Fixture -Architecture $t
}

Write-Host ''
if ($script:Failures -eq 0) {
    Write-Host ("All $script:Checks checks passed.") -ForegroundColor Green
    exit 0
}
Write-Host ("$script:Failures of $script:Checks checks FAILED.") -ForegroundColor Red
exit 1
