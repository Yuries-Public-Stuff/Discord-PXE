[CmdletBinding()]
param(
    [string]$BindIP = '192.168.1.181',
    [string]$ComPort = 'AUTO',
    [switch]$SkipBuild,
    [switch]$NoSerial
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$BuildScript = Join-Path $RepoRoot 'tools\build.ps1'
$Stage1 = Join-Path $RepoRoot 'build\stage1.pxe'
$Runtime = Join-Path $RepoRoot 'build\runtime.bin'
$LocalToken = Join-Path $RepoRoot 'config\token.txt'
$PxeRoot = Join-Path $RepoRoot 'build\pxe'
$ZipPath = Join-Path $PxeRoot 'tinypxe.zip'
$ServerRoot = Join-Path $PxeRoot 'server'
$TinyUrl = 'https://raw.githubusercontent.com/erwan2212/tinypxeserver/main/pxesrv.zip'

$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $admin) { throw 'Run this as Administrator.' }

if (-not $SkipBuild) {
    Write-Host ''
    Write-Host '[BUILD] PXE images' -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $BuildScript
    if ($LASTEXITCODE -ne 0) { throw "build failed with exit code $LASTEXITCODE" }
}

if (-not (Test-Path $Stage1)) { throw 'build\stage1.pxe does not exist.' }
if (-not (Test-Path $Runtime)) { throw 'build\runtime.bin does not exist.' }

New-Item -ItemType Directory -Path $PxeRoot -Force | Out-Null
New-Item -ItemType Directory -Path $ServerRoot -Force | Out-Null

$PxeExe = Get-ChildItem -Path $ServerRoot -Filter 'pxesrv.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $PxeExe) {
    Write-Host '[FETCH] TinyPXE' -ForegroundColor Cyan
    Invoke-WebRequest -UseBasicParsing -Uri $TinyUrl -OutFile $ZipPath
    if (-not (Test-Path $ZipPath)) { throw 'TinyPXE download failed.' }
    try { Expand-Archive -Path $ZipPath -DestinationPath $ServerRoot -Force }
    catch { throw "TinyPXE extract failed: $($_.Exception.Message)" }
    $PxeExe = Get-ChildItem -Path $ServerRoot -Filter 'pxesrv.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
}
if (-not $PxeExe) { throw 'pxesrv.exe was not found after setup.' }

$ServerDir = $PxeExe.Directory.FullName
$FilesDir = Join-Path $ServerDir 'files'
$DiscordDir = Join-Path $FilesDir 'discord'
$ConfigPath = Join-Path $ServerDir 'config.ini'
New-Item -ItemType Directory -Path $FilesDir -Force | Out-Null
New-Item -ItemType Directory -Path $DiscordDir -Force | Out-Null
$builtStage1Hash = (Get-FileHash -Algorithm SHA256 -Path $Stage1).Hash
$builtRuntimeHash = (Get-FileHash -Algorithm SHA256 -Path $Runtime).Hash
$stage1Tag = $builtStage1Hash.Substring(0,12).ToLowerInvariant()
$BootFileName = "discord-pxe-sharded-$stage1Tag.pxe"
$ServedStage1 = Join-Path $FilesDir $BootFileName
$ServedRuntime = Join-Path $FilesDir 'runtime.bin'

# make stale-nbp execution impossible from this tinypxe root. every run removes every old
# .pxe image, then serves a filename derived from the fresh stage1 hash.
Get-ChildItem -LiteralPath $FilesDir -File -Filter '*.pxe' -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue

Copy-Item $Stage1 $ServedStage1 -Force
Copy-Item $Runtime $ServedRuntime -Force

$servedStage1Hash = (Get-FileHash -Algorithm SHA256 -Path $ServedStage1).Hash
$servedRuntimeHash = (Get-FileHash -Algorithm SHA256 -Path $ServedRuntime).Hash
if ($builtStage1Hash -ne $servedStage1Hash) { throw 'served sharded NBP hash does not match the freshly built image.' }
if ($builtRuntimeHash -ne $servedRuntimeHash) { throw 'served runtime hash does not match the freshly built image.' }

Write-Host "[VERIFY] built stage1 SHA256=$builtStage1Hash" -ForegroundColor Green
Write-Host "[VERIFY] served $BootFileName SHA256=$servedStage1Hash" -ForegroundColor Green
Write-Host "[VERIFY] served runtime SHA256=$servedRuntimeHash" -ForegroundColor Green

try {
    $gitBranch = (& git -C $RepoRoot rev-parse --abbrev-ref HEAD 2>$null).Trim()
    $gitHead = (& git -C $RepoRoot rev-parse HEAD 2>$null).Trim()
    $gitRemote = (& git -C $RepoRoot remote get-url origin 2>$null).Trim()
    Write-Host "[GIT] branch=$gitBranch head=$gitHead" -ForegroundColor Cyan
    Write-Host "[GIT] origin=$gitRemote" -ForegroundColor Cyan
} catch {
    Write-Host '[GIT] could not read local git metadata' -ForegroundColor Yellow
}

# certificate trust is self-contained in runtime.bin now. never generate or serve the old
# discord/pin.bin artifact; remove any stale copy left by older builds.
$OldPinPath = Join-Path $DiscordDir 'pin.bin'
Remove-Item $OldPinPath -Force -ErrorAction SilentlyContinue

$ServedToken = Join-Path $DiscordDir 'token.txt'
if (Test-Path $LocalToken) {
    Copy-Item $LocalToken $ServedToken -Force
    Write-Host '[CONFIG] token.txt copied' -ForegroundColor Green
} else {
    Remove-Item $ServedToken -Force -ErrorAction SilentlyContinue
    Write-Host '[CONFIG] config\token.txt missing, discord login will stay disabled' -ForegroundColor Yellow
}

$ManifestPath = Join-Path $FilesDir 'files.txt'
$files = Get-ChildItem -Path $FilesDir -File -Recurse |
    ForEach-Object { $_.FullName.Substring($FilesDir.Length).TrimStart('\','/') -replace '\\','/' } |
    Where-Object { $_ -ne 'files.txt' -and $_ -ne 'discord/token.txt' -and $_ -ne 'discord/pin.bin' } |
    Sort-Object -Unique
$files | Set-Content -Path $ManifestPath -Encoding Ascii

$Config = @"
[arch]
00000=$BootFileName
00006=$BootFileName

[dhcp]
root=$FilesDir\
filename=$BootFileName
proxydhcp=1
httpd=1
tftpd=1
bind=1
start=1
binl=0
dnsd=0
smb=0
log=1
poolsize=0
opt54=$BindIP
next-server=$BindIP
opt66=$BindIP
opt60=PXEClient

[web]
port=8080
"@
Set-Content -Path $ConfigPath -Value $Config -Encoding Ascii

Get-NetFirewallRule -DisplayName 'discord-pxe *' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'discord-pxe dhcp' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 67 | Out-Null
New-NetFirewallRule -DisplayName 'discord-pxe tftp' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 69 | Out-Null
New-NetFirewallRule -DisplayName 'discord-pxe proxy' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 4011 | Out-Null
New-NetFirewallRule -DisplayName 'discord-pxe http' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080 | Out-Null

Get-Process pxesrv -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 400
Start-Process -FilePath $PxeExe.FullName -WorkingDirectory $ServerDir

if (-not $NoSerial) {
    $Capture = Join-Path $RepoRoot 'tools\capture-com.ps1'
    Start-Process powershell.exe -ArgumentList @(
        '-NoExit','-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $Capture + '"'),'-Port',$ComPort
    )
}

Write-Host ''
Write-Host "[PXE] $BootFileName + runtime.bin are live" -ForegroundColor Green
Write-Host "IP       : $BindIP"
Write-Host "Stage1   : $ServedStage1"
Write-Host "BootFile : $BootFileName"
Write-Host "Runtime  : $FilesDir\runtime.bin"
Write-Host "Files    : $ManifestPath"
Write-Host "Discord  : $DiscordDir"
Write-Host "COM      : $ComPort"
Write-Host ''
