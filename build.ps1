<#
.SYNOPSIS
    Builds the AMI TAPI service provider (amitsp.dll) and its control tool.

.DESCRIPTION
    The provider is a cgo c-shared DLL and must be 64-bit: TapiSrv is 64-bit
    on 64-bit Windows and loads providers in-process. A 32-bit build is not
    possible with cgo, because exported Go functions use cdecl on 386 while
    TSPI requires stdcall.

    Requires:
      * Go 1.22 or newer
      * an x86_64 mingw-w64 gcc on PATH

    Both are available from winget:
      winget install GoLang.Go
      winget install BrechtSanders.WinLibs.POSIX.UCRT

.PARAMETER OutDir
    Where to place the build output. Defaults to .\dist

.PARAMETER KeepSymbols
    Keep the symbol table and DWARF info, for debugging a crash in TapiSrv.
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path $PSScriptRoot 'dist'),
    [switch]$KeepSymbols
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Assert-Tool {
    param([string]$Name, [string]$Hint)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $cmd) { throw "$Name not found on PATH. $Hint" }
    return $cmd.Source
}

$go  = Assert-Tool 'go'  'winget install GoLang.Go, then reopen the shell.'
$gcc = Assert-Tool 'gcc' 'winget install BrechtSanders.WinLibs.POSIX.UCRT, then reopen the shell.'

Write-Host "go  : $go"
Write-Host "gcc : $gcc"

# cgo needs a 64-bit gcc; a 32-bit one produces a DLL TapiSrv cannot load.
$gccTarget = (& gcc -dumpmachine)
if ($gccTarget -notmatch '^x86_64') {
    throw "gcc targets '$gccTarget'; an x86_64 mingw-w64 toolchain is required."
}

$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '1'

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

$ldflags = '-s -w'
if ($KeepSymbols) { $ldflags = '' }

$dll = Join-Path $OutDir 'amitsp.dll'
Write-Host "`nbuilding $dll ..."
& go build -buildmode=c-shared -ldflags $ldflags -o $dll ./tsp
if ($LASTEXITCODE -ne 0) { throw "go build (provider) failed with exit code $LASTEXITCODE" }

# The install-time UI half. TAPI loads this one into the *client* process, so
# it must stay plain C: a cgo DLL would drag a Go runtime in with it.
$uiDll = Join-Path $OutDir 'amitspui.dll'
Write-Host "building $uiDll ..."
& gcc -O2 -shared -municode -o $uiDll (Join-Path $PSScriptRoot 'ui\amitspui.c')
if ($LASTEXITCODE -ne 0) { throw "gcc (ui dll) failed with exit code $LASTEXITCODE" }

$ctl = Join-Path $OutDir 'amitsp-ctl.exe'
Write-Host "building $ctl ..."
& go build -ldflags $ldflags -o $ctl ./cmd/amitsp-ctl
if ($LASTEXITCODE -ne 0) { throw "go build (ctl) failed with exit code $LASTEXITCODE" }

# The export table is what TapiSrv actually resolves against, and the import
# table decides whether the DLL can load at all inside svchost.exe.
$objdump = Get-Command objdump -ErrorAction SilentlyContinue
if ($objdump) {
    $dump = & objdump -p $dll

    Write-Host "`nexported TSPI entry points:"
    $dump |
        Select-String -Pattern '\b((?:TSPI|TUISPI)_\w+)' -AllMatches |
        ForEach-Object { $_.Matches } |
        ForEach-Object { $_.Groups[1].Value } |
        Sort-Object -Unique |
        ForEach-Object { Write-Host "  $_" }

    # A dependency on libgcc/libwinpthread would make TapiSrv fail to load
    # the provider with no useful error, so surface it now.
    $dlls = $dump |
        Select-String -Pattern '^\s*DLL Name:\s*(\S+)' |
        ForEach-Object { $_.Matches[0].Groups[1].Value }
    Write-Host "`nimported DLLs:"
    foreach ($d in $dlls) {
        if ($d -match '^(lib|msys)') {
            Write-Warning "  $d  <-- not present in System32; copy it beside the provider or rebuild statically"
        } else {
            Write-Host "  $d"
        }
    }
} else {
    Write-Host "`n(install binutils for objdump to verify the export and import tables)"
}

Write-Host "`ndone. Next steps:"
Write-Host "  1. copy config\ami-tsp.example.json to $env:ProgramData\AmiTSP\ami-tsp.json and edit it"
Write-Host "  2. $ctl config      # validate"
Write-Host "  3. $ctl test        # watch live AMI call events, no TAPI involved"
Write-Host "  4. (elevated) $ctl install $dll   # installs as System32\amitsp.tsp"
