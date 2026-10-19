[CmdletBinding()]
param(
    [string]$Port = 'AUTO',
    [int]$Baud = 115200,
    [string]$LogDirectory = 'build\serial-logs'
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

if (-not [IO.Path]::IsPathRooted($LogDirectory)) {
    $LogDirectory = Join-Path $RepoRoot $LogDirectory
}
New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null

$available = @([System.IO.Ports.SerialPort]::GetPortNames() | Sort-Object)
$deviceNames = @{}
try {
    Get-CimInstance Win32_PnPEntity -ErrorAction Stop |
        Where-Object { $_.Name -match '\(COM\d+\)' } |
        ForEach-Object {
            if ($_.Name -match '\((COM\d+)\)') {
                $deviceNames[$matches[1].ToUpperInvariant()] = $_.Name
            }
        }
} catch {}

if ($available.Count -eq 0) {
    throw 'no Windows COM ports were detected.'
}

if ($Port.ToUpperInvariant() -eq 'AUTO') {
    $selected = $available
}
else {
    $wanted = $Port.ToUpperInvariant()
    if ($available -notcontains $wanted) {
        throw "serial port $wanted was not detected. found: $($available -join ', ')"
    }
    $selected = @($wanted)
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = Join-Path $LogDirectory ("discord-pxe-serial-{0}.log" -f $stamp)
$writer = New-Object System.IO.StreamWriter($log, $false, [Text.Encoding]::ASCII)
$writer.AutoFlush = $true
$openPorts = New-Object System.Collections.Generic.List[System.IO.Ports.SerialPort]

function New-ConsolePort([string]$Name) {
    $serial = New-Object System.IO.Ports.SerialPort
    $serial.PortName = $Name
    $serial.BaudRate = $Baud
    $serial.DataBits = 8
    $serial.Parity = [System.IO.Ports.Parity]::None
    $serial.StopBits = [System.IO.Ports.StopBits]::One
    $serial.Handshake = [System.IO.Ports.Handshake]::None
    $serial.DtrEnable = $true
    $serial.RtsEnable = $true
    $serial.ReadTimeout = 25
    $serial.WriteTimeout = 250
    $serial.Encoding = [Text.Encoding]::ASCII
    return $serial
}

try {
    foreach ($name in $selected) {
        try {
            $serial = New-ConsolePort $name
            $serial.Open()
            # do not discard input here. target boot text may already be waiting.
            $openPorts.Add($serial)
            $friendly = $deviceNames[$name.ToUpperInvariant()]
            if ([string]::IsNullOrWhiteSpace($friendly)) { $friendly = 'unknown device' }
            Write-Host "[SERIAL] opened $name : $friendly" -ForegroundColor Green
        }
        catch {
            Write-Host "[SERIAL] could not open $name : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    if ($openPorts.Count -eq 0) {
        throw 'none of the detected COM ports could be opened.'
    }

    Write-Host ''
    Write-Host '[SERIAL] discord-pxe interactive console' -ForegroundColor Green
    Write-Host "Mode : $Baud baud, 8 data bits, no parity, 1 stop bit, no flow control"
    Write-Host 'Target: 115200 baud, 8 data bits, no parity, 1 stop bit, no flow control'
    Write-Host "Open : $((@($openPorts | ForEach-Object { $_.PortName })) -join ', ')"
    Write-Host "Found: $($available -join ', ')"
    Write-Host "Log  : $log"
    Write-Host 'AUTO listens on every available COM port and sends typed keys to all of them.'
    Write-Host 'A harmless CR probe is transmitted once per second for the first 10 seconds.'
    Write-Host 'The PXE runtime also transmits [SERIAL-BEACON] once per second on physical COM1.'
    Write-Host 'Ctrl+C stops.'
    Write-Host ''

    $probeCount = 0
    $nextProbe = Get-Date

    while ($true) {
        foreach ($serial in @($openPorts)) {
            try {
                $text = $serial.ReadExisting()
                if ($text.Length -gt 0) {
                    if ($openPorts.Count -gt 1) {
                        $prefix = "[$($serial.PortName)] "
                        [Console]::Write($prefix)
                        $writer.Write($prefix)
                    }
                    [Console]::Write($text)
                    $writer.Write($text)
                }
            }
            catch {}
        }

        $now = Get-Date
        if ($probeCount -lt 10 -and $now -ge $nextProbe) {
            foreach ($serial in @($openPorts)) {
                try {
                    $serial.Write("`r")
                    Write-Host "[TX] startup CR -> $($serial.PortName)" -ForegroundColor DarkGray
                }
                catch {}
            }
            $probeCount++
            $nextProbe = $now.AddSeconds(1)
        }

        while ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            $out = $null
            switch ($key.Key) {
                'Enter'     { $out = "`r" }
                'Backspace' { $out = [char]8 }
                'Tab'       { $out = "`t" }
                default {
                    if ([int]$key.KeyChar -ge 32 -and [int]$key.KeyChar -le 126) {
                        $out = [string]$key.KeyChar
                    }
                }
            }

            if ($null -ne $out) {
                foreach ($serial in @($openPorts)) {
                    try { $serial.Write($out) } catch {}
                }
            }
        }

        Start-Sleep -Milliseconds 2
    }
}
finally {
    try { $writer.Flush() } catch {}
    try { $writer.Dispose() } catch {}
    foreach ($serial in @($openPorts)) {
        try { if ($serial.IsOpen) { $serial.Close() } } catch {}
        try { $serial.Dispose() } catch {}
    }
    Write-Host ''
    Write-Host "[SAVED] $log" -ForegroundColor Cyan
}
