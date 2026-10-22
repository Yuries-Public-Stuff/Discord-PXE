[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$BuildDir = Join-Path $RepoRoot 'build'
$GeneratedDir = Join-Path $BuildDir 'generated'
$LegacyDir = Join-Path $RepoRoot 'src\legacy'
$Stage1Source = Join-Path $RepoRoot 'src\stage1\loader.asm'
$RuntimeSource = Join-Path $LegacyDir 'pxe_boot.asm'
$Stage1Output = Join-Path $BuildDir 'stage1.pxe'
$RuntimeOutput = Join-Path $BuildDir 'runtime.bin'
$RuntimeList = Join-Path $BuildDir 'runtime.lst'
$LocalToken = Join-Path $RepoRoot 'config\token.txt'
$PocAccountToken = Join-Path $RepoRoot 'config\poc-account-token.txt'
$GeneratedSecrets = Join-Path $GeneratedDir 'local-secrets.inc'
$OldRuntimeGenerated = Join-Path $BuildDir 'runtime-generated.asm'

function Find-Nasm {
    $paths = @(
        'C:\Program Files\NASM\nasm.exe',
        'C:\Program Files (x86)\NASM\nasm.exe'
    )
    foreach ($path in $paths) {
        if (Test-Path $path) { return $path }
    }
    $cmd = Get-Command nasm.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw 'NASM was not found.'
}

function Format-DbBytes {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Count -eq 0) { return '0' }
    return (($Bytes | ForEach-Object { '0x{0:X2}' -f $_ }) -join ',')
}

function Normalize-DiscordToken {
    param([string]$Token)

    if ($null -eq $Token) { return '' }
    $value = $Token.Trim()

    if ($value.Length -ge 2) {
        $first = $value[0]
        $last = $value[$value.Length - 1]
        if (($first -eq '"' -and $last -eq '"') -or ($first -eq "'" -and $last -eq "'")) {
            $value = $value.Substring(1, $value.Length - 2).Trim()
        }
    }

    if ($value.StartsWith('Bot ', [System.StringComparison]::OrdinalIgnoreCase)) {
        $value = $value.Substring(4).Trim()
    }

    return $value
}

$Nasm = Find-Nasm
New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
New-Item -ItemType Directory -Path $GeneratedDir -Force | Out-Null

Get-ChildItem -LiteralPath $GeneratedDir -File -Filter '*.inc' -ErrorAction SilentlyContinue | Remove-Item -Force
Remove-Item $OldRuntimeGenerated -Force -ErrorAction SilentlyContinue
Remove-Item $GeneratedSecrets -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $GeneratedDir 'discord-pin.bin') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $GeneratedDir 'discord-pin.bin.endpoint') -Force -ErrorAction SilentlyContinue

$NasmDefines = @('-DUNDI_TX_STATUS=0')

# optional proof-of-concept credential. this is deliberately separate from the
# real bot token and is never inserted into discord gateway/rest traffic
$pocAccountTokenBytes = [byte[]]@()
if (Test-Path $PocAccountToken) {
    $pocAccountToken = (Get-Content -LiteralPath $PocAccountToken -Raw).Trim()
    if ([string]::IsNullOrWhiteSpace($pocAccountToken)) { throw 'config\poc-account-token.txt is empty.' }
    if ($pocAccountToken.Length -ge 256) { throw 'PoC account token is too long.' }
    $pocAccountTokenBytes = [Text.Encoding]::ASCII.GetBytes($pocAccountToken)
    Write-Host ("[POC] account credential loaded locally ({0} bytes); outbound transmission is hard-disabled" -f $pocAccountTokenBytes.Length) -ForegroundColor Yellow
}

if (Test-Path $LocalToken) {
    $token = Normalize-DiscordToken (Get-Content -LiteralPath $LocalToken -Raw)
    if ([string]::IsNullOrWhiteSpace($token)) { throw 'config\token.txt is empty.' }
    if ($token.IndexOf('"') -ge 0 -or $token.IndexOf("'") -ge 0 -or $token.IndexOf('\') -ge 0) {
        throw 'config\token.txt still contains quote/backslash characters after normalization.'
    }

    $tokenBytes = [Text.Encoding]::ASCII.GetBytes($token)
    if ($tokenBytes.Length -ge 256) { throw 'discord token is too long.' }

    # build the exact gateway identify body once at build time. validate it with
    # powershell's json parser, then embed those exact
    $identify = '{"op":2,"d":{"token":"' + $token + '","properties":{"os":"legacy","browser":"discord-pxe","device":"discord-pxe"},"intents":0}}'
    try {
        $parsedIdentify = $identify | ConvertFrom-Json
    } catch {
        throw 'generated Discord Identify JSON failed local validation.'
    }
    if ($parsedIdentify.op -ne 2 -or $null -eq $parsedIdentify.d -or [string]::IsNullOrWhiteSpace([string]$parsedIdentify.d.token)) {
        throw 'generated Discord Identify JSON has the wrong structure.'
    }
    $identifyBytes = [Text.Encoding]::UTF8.GetBytes($identify)
    if ($identifyBytes.Length -gt 4096) { throw 'generated Discord Identify JSON is too large.' }

    # sharded identify keeps every secret-bearing/static byte build-validated too.
    # runtime appends only the two decimal shard numbers between these fragments.
    $shardIdentifyPrefix = '{"op":2,"d":{"token":"' + $token + '","properties":{"os":"legacy","browser":"discord-pxe-sharded","device":"discord-pxe"},"intents":0,"shard":['
    $shardIdentifySuffix = ']}}'
    $shardIdentifyProbe = $shardIdentifyPrefix + '0,2' + $shardIdentifySuffix
    try {
        $parsedShardIdentify = $shardIdentifyProbe | ConvertFrom-Json
    } catch {
        throw 'generated sharded Discord Identify JSON failed local validation.'
    }
    if ($parsedShardIdentify.op -ne 2 -or $parsedShardIdentify.d.shard.Count -ne 2 -or $parsedShardIdentify.d.shard[0] -ne 0 -or $parsedShardIdentify.d.shard[1] -ne 2) {
        throw 'generated sharded Discord Identify JSON has the wrong structure.'
    }
    $shardIdentifyPrefixBytes = [Text.Encoding]::UTF8.GetBytes($shardIdentifyPrefix)
    $shardIdentifySuffixBytes = [Text.Encoding]::UTF8.GetBytes($shardIdentifySuffix)

    # x509 trust lives entirely in src/legacy/legacy_x509_self.inc. keep
    # zero-sized compatibility pin symbols for legacy_config.inc only.
    $secretAsm = @(
        '%define LEGACY_EMBEDDED_CONFIG 1',
        ('legacy_embedded_poc_account_token_len equ {0}' -f $pocAccountTokenBytes.Length),
        ('legacy_embedded_poc_account_token db {0}' -f (Format-DbBytes $pocAccountTokenBytes)),
        ('legacy_embedded_token_len equ {0}' -f $tokenBytes.Length),
        ('legacy_embedded_token db {0}' -f (Format-DbBytes $tokenBytes)),
        ('legacy_embedded_identify_len equ {0}' -f $identifyBytes.Length),
        ('legacy_embedded_identify db {0}' -f (Format-DbBytes $identifyBytes)),
        ('legacy_embedded_shard_ident_prefix_len equ {0}' -f $shardIdentifyPrefixBytes.Length),
        ('legacy_embedded_shard_ident_prefix db {0}' -f (Format-DbBytes $shardIdentifyPrefixBytes)),
        ('legacy_embedded_shard_ident_suffix_len equ {0}' -f $shardIdentifySuffixBytes.Length),
        ('legacy_embedded_shard_ident_suffix db {0}' -f (Format-DbBytes $shardIdentifySuffixBytes)),
        'legacy_embedded_pin_count equ 0',
        'legacy_embedded_pins db 0'
    ) -join "`r`n"
    Set-Content -LiteralPath $GeneratedSecrets -Value $secretAsm -Encoding ASCII
    $NasmDefines += '-DLEGACY_HAVE_LOCAL_SECRETS=1'
    Write-Host ("[CONFIG] local token + validated singleton/sharded Gateway Identify bytes embedded ({0} singleton bytes); X509 trust store is built into runtime" -f $identifyBytes.Length) -ForegroundColor Green
} else {
    # even without a bot token, emit the poc credential symbols so the runtime can
    # expose local-only proof-of-concept status without a
    $secretAsm = @(
        '%define LEGACY_EMBEDDED_CONFIG 0',
        ('legacy_embedded_poc_account_token_len equ {0}' -f $pocAccountTokenBytes.Length),
        ('legacy_embedded_poc_account_token db {0}' -f (Format-DbBytes $pocAccountTokenBytes)),
        'legacy_embedded_token_len equ 0',
        'legacy_embedded_token db 0',
        'legacy_embedded_identify_len equ 0',
        'legacy_embedded_identify db 0',
        'legacy_embedded_shard_ident_prefix_len equ 0',
        'legacy_embedded_shard_ident_prefix db 0',
        'legacy_embedded_shard_ident_suffix_len equ 0',
        'legacy_embedded_shard_ident_suffix db 0',
        'legacy_embedded_pin_count equ 0',
        'legacy_embedded_pins db 0'
    ) -join "`r`n"
    Set-Content -LiteralPath $GeneratedSecrets -Value $secretAsm -Encoding ASCII
    $NasmDefines += '-DLEGACY_HAVE_LOCAL_SECRETS=1'
    Write-Host '[CONFIG] config\token.txt missing; Discord bot auth stays deferred' -ForegroundColor Yellow
}

Write-Host '[BUILD] stage1.pxe' -ForegroundColor Cyan
& $Nasm -f bin -Wall -o $Stage1Output $Stage1Source
if ($LASTEXITCODE -ne 0) { throw "stage1 build failed with exit code $LASTEXITCODE" }

Write-Host '[BUILD] runtime.bin direct from source' -ForegroundColor Cyan
$includeLegacy = $LegacyDir + '\'
$includeGenerated = $GeneratedDir + '\'
& $Nasm -f bin -Wall -l $RuntimeList @NasmDefines -I $includeLegacy -I $includeGenerated -o $RuntimeOutput $RuntimeSource
if ($LASTEXITCODE -ne 0) { throw "runtime build failed with exit code $LASTEXITCODE" }

$stage1Size = (Get-Item $Stage1Output).Length
$runtimeSize = (Get-Item $RuntimeOutput).Length
$stage1Hash = (Get-FileHash -Algorithm SHA256 -Path $Stage1Output).Hash
$runtimeHash = (Get-FileHash -Algorithm SHA256 -Path $RuntimeOutput).Hash
if ($stage1Size -le 0 -or $runtimeSize -le 0) { throw 'one of the PXE images is empty.' }
if ($stage1Size -gt 16384) { throw "stage1.pxe is $stage1Size bytes. keep stage1 under 16 KiB." }
if ($runtimeSize -gt 851968) { throw "runtime.bin is $runtimeSize bytes. legacy stage1 can load at most 851968 bytes (0xD0000)." }

Write-Host "[STAGE1] $stage1Size bytes $stage1Hash"
Write-Host "[RUNTIME] $runtimeSize bytes $runtimeHash"
Write-Host '[READY] stage1.pxe + runtime.bin' -ForegroundColor Green
Write-Host ''