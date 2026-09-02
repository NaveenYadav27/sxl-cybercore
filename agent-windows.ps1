# ShadowXLab Splunk Standalone Windows Real-Time Agent
param(
    [string]$ServerUrl = 'http://localhost:8000/services/collector/event',
    [string]$HecToken = 'sxl-splunk-hec-token-2026',
    [int]$IntervalSeconds = 5
)

$hostname = $env:COMPUTERNAME
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '  SHADOWXLAB SPLUNK STANDALONE WINDOWS REAL-TIME AGENT' -ForegroundColor Green
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ('  Target Server:   ' + $ServerUrl)
Write-Host ('  Host Identity:   ' + $hostname)
Write-Host ('  Stream Interval: ' + $IntervalSeconds + ' s')
Write-Host '============================================================'


function Send-SplunkEvent {
    param(
        [string]$EventMessage,
        [string]$SourceType = 'WinEventLog:Security'
    )
    $bodyObj = @{
        event = $EventMessage
        host = $hostname
        sourcetype = $SourceType
        time = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    }
    $bodyJson = $bodyObj | ConvertTo-Json -Compress

    try {
        $authHeader = 'Splunk ' + $HecToken
        $headers = @{
            'Authorization' = $authHeader
            'Content-Type'  = 'application/json'
        }
        $res = Invoke-RestMethod -Uri $ServerUrl -Method Post -Headers $headers -Body $bodyJson -TimeoutSec 3
        $nowStr = Get-Date -Format 'HH:mm:ss'
        Write-Host ('[✓ Ingested ' + $nowStr + '] ' + $EventMessage) -ForegroundColor Green
    }
    catch {
        $errText = $_.Exception.Message
        Write-Host ('[! Ingest Warning] ' + $errText) -ForegroundColor DarkYellow
    }
}

# Initial Heartbeat
Send-SplunkEvent -EventMessage ('Agent Online: Windows Host ' + $hostname + ' connected to Splunk ES Standalone') -SourceType 'sxl:agent:heartbeat'

# Continuous Metric Loop
while ($true) {
    try {
        $cpuLoad = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
        if ($null -eq $cpuLoad) { $cpuLoad = 0 }
        $osInfo = Get-CimInstance Win32_OperatingSystem
        $freeRam = [math]::Round($osInfo.FreePhysicalMemory / 1024, 0)
        $procCount = (Get-Process).Count
        $msg = 'Host=' + $hostname + ' Status=ONLINE CpuLoad=' + $cpuLoad + '% FreeRam=' + $freeRam + 'MB ActiveProcesses=' + $procCount
        Send-SplunkEvent -EventMessage $msg -SourceType 'WinEventLog:System'
    }
    catch {
        Send-SplunkEvent -EventMessage ('Host=' + $hostname + ' Status=ONLINE Heartbeat') -SourceType 'WinEventLog:System'
    }

    Start-Sleep -Seconds $IntervalSeconds
}
