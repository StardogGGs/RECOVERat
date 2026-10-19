# RECOVERat - read-only WMI persistence review
param([switch]$Full, [switch]$Pause, [string]$LogDir)
if ($LogDir) { Start-Transcript -Path (Join-Path $LogDir 'WMICHECK.log') -Append | Out-Null }
try {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Warning 'Not admin: root/subscription may be unreadable.' }
    $ns = 'root/subscription'

    Write-Host '=== WMI EVENT FILTERS ===' -ForegroundColor Cyan
    $f = @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction SilentlyContinue)
    if ($Full) { $f | Format-List * } else { $f | Format-List Name,Query,QueryLanguage,EventNamespace }

    Write-Host '=== WMI EVENT CONSUMERS ===' -ForegroundColor Cyan
    $c = @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction SilentlyContinue)
    foreach ($x in $c) {
        $cls = $x.CimClass.CimClassName
        $risky = $cls -in 'CommandLineEventConsumer','ActiveScriptEventConsumer'
        $color = if ($risky) { 'Red' } else { 'Gray' }
        Write-Host ("[{0}] {1}{2}" -f $cls, $x.Name, $(if ($risky) { '  <-- command/script consumer: SUSPICIOUS unless you recognize it' } else { '' })) -ForegroundColor $color
        if ($Full) { $x | Format-List * }
        else { $x | Format-List Name,CommandLineTemplate,ExecutablePath,ScriptingEngine,ScriptText,ScriptFileName,Filename }
    }

    Write-Host '=== WMI FILTER BINDINGS ===' -ForegroundColor Cyan
    $b = @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)
    if ($Full) { $b | Format-List * } else { $b | Format-List Filter,Consumer }

    Write-Host "Filters: $($f.Count)  Consumers: $($c.Count)  Bindings: $($b.Count)" -ForegroundColor Yellow
    Write-Host "Note: Windows ships a benign 'SCM Event Log Filter' + NTEventLogEventConsumer binding. Anything else, especially CommandLine/ActiveScript consumers, needs review." -ForegroundColor Yellow
    Write-Host '=== SCAN COMPLETE ===' -ForegroundColor Green
    if ($Pause) { Read-Host 'Press Enter to exit' }
} finally {
    if ($LogDir) { Stop-Transcript | Out-Null }
}
