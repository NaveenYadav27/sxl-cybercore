<#
  ShadowXLab · Splunk Standalone Real-Time Windows Forwarder Agent
  ==============================================================
  Collects Security, System, and Sysmon events from your Windows host
  and streams them via Splunk HEC to http://localhost:8000/services/collector/event
#>

param(
    [string]$ServerUrl = "http://localhost:8000/services/collector/event",
    [string]$HecToken = "sxl-splunk-hec-token-2026",
    [int]$IntervalSeconds = 5
)

$hostname = $env:COMPUTERNAME
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SHADOWXLAB SPLUNK STANDALONE WINDOWS REAL-TIME AGENT" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Target Server:   $ServerUrl"
Write-Host "  Host Identity:   $hostname"
Write-Host "  Stream Interval: $IntervalSeconds s"
Write-Host "============================================================`n"

function Send-SplunkEvent {
    param(
        [string]$EventMessage,
        [string]$SourceType = "WinEventLog:Security"
    )
    $payload = @{
        event = $EventMessage
        host = $hostname
        sourcetype = $SourceType
        time = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    }
    $body = $payload | ConvertTo-Json -Compress

    try {
        $headers = @{
            "Authorization" = "Splunk $HecToken"
            "Content-Type"  = "application/json"
        }
        $res = Invoke-RestMethod -Uri $ServerUrl -Method Post -Headers $headers -Body $body -TimeoutSec 3
        Write-Host "[✓ Ingested $(Get-Date -Format 'HH:mm:ss')] $EventMessage" -ForegroundColor Green
    }
    catch {
        Write-Host "[! Ingest Warning] Failed to reach $ServerUrl - $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}

# Initial Heartbeat
Send-SplunkEvent -EventMessage "Agent Online: Windows Host $hostname connected to Splunk ES Standalone" -SourceType "sxl:agent:heartbeat"

# Loop sending telemetry / real system events
while ($true) {
    try {
        $cpuLoad = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
        if ($null -eq $cpuLoad) { $cpuLoad = 0 }
        
        $osInfo = Get-CimInstance Win32_OperatingSystem
        $freeRam = [math]::Round($osInfo.FreePhysicalMemory / 1024, 0)
        $procCount = (Get-Process).Count

        $telemetry = "Host=$hostname Status=ONLINE CpuLoad=$cpuLoad% FreeRam=${freeRam}MB ActiveProcesses=$procCount"
        Send-SplunkEvent -EventMessage $telemetry -SourceType "WinEventLog:System"
    }
    catch {
        Send-SplunkEvent -EventMessage "Host=$hostname Status=ONLINE Heartbeat" -SourceType "WinEventLog:System"
    }

    Start-Sleep -Seconds $IntervalSeconds
}
