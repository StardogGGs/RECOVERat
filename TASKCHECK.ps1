# RECOVERat - read-only scheduled task review
param([switch]$All, [string]$LogDir)
if ($LogDir) { Start-Transcript -Path (Join-Path $LogDir 'TASKCHECK.log') -Append | Out-Null }
try {
    Write-Host '=== SCHEDULED TASK CHECK ===' -ForegroundColor Cyan
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Warning 'NOT ADMIN: some tasks will be hidden. Re-run elevated.' }

    $rows = foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
        $parts = @(); $hasCom = $false
        foreach ($a in @($t.Actions)) {
            if ($a.CimClass.CimClassName -eq 'MSFT_TaskComHandlerAction') { $hasCom = $true; $parts += "COM:$($a.ClassId)" }
            else { $parts += (($a.Execute, $a.Arguments) -join ' ').Trim() }
        }
        $actions = $parts -join ' | '
        $user = [string]$t.Principal.UserId
        $isSystem = $user -match '(?i)^(SYSTEM|S-1-5-18|NT AUTHORITY\\SYSTEM)$'
        $userPath = $actions -match '(?i)\\(AppData|Temp|Downloads|ProgramData|Users\\Public)\\'
        $flag = @()
        if ($userPath) { $flag += 'User/temp path' }
        if ($actions -match '(?i)(powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)(\.exe)?\b') { $flag += 'Script/LOLBIN host' }
        if ($actions -match '(?i)(-enc(odedcommand)?\b|frombase64string|downloadstring|https?://)') { $flag += 'Encoded/download reference' }
        if ($t.Settings.Hidden) { $flag += 'Hidden' }
        if ($isSystem -and $userPath) { $flag += 'SYSTEM from user-writable path' }
        if ($hasCom -and $t.TaskPath -notlike '\Microsoft\*') { $flag += 'Non-Microsoft COM handler' }
        if (-not $actions.Trim()) { $flag += 'No action' }
        [pscustomobject]@{ Task=($t.TaskPath + $t.TaskName); State=$t.State; Author=$t.Author; RunAs=$user; Action=$actions; Review=($flag -join '; ') }
    }
    Write-Host "Tasks: $($rows.Count); flagged for review: $( @($rows | Where-Object Review).Count)"
    if ($All) { $rows | Sort-Object Task | Format-Table Task,State,Author,RunAs,Action,Review -Wrap -AutoSize }
    else { $rows | Where-Object Review | Sort-Object Task | Format-Table Task,State,Author,RunAs,Action,Review -Wrap -AutoSize }
    Write-Host 'Microsoft and third-party tasks may legitimately match these heuristics.' -ForegroundColor Yellow
} finally {
    if ($LogDir) { Stop-Transcript | Out-Null }
}
