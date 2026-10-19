# RECOVERat - read-only startup persistence review
param([switch]$All, [string]$LogDir)
if ($LogDir) { Start-Transcript -Path (Join-Path $LogDir 'STARTUPCHECK.log') -Append | Out-Null }
try {
    Write-Host '=== STARTUP CHECK ===' -ForegroundColor Cyan
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Warning 'Not admin: results may be incomplete.' }

    $rows = New-Object System.Collections.ArrayList
    function Get-Flags([string]$cmd) {
        $f = @()
        if ($cmd -match '(?i)\\(AppData|Temp|Downloads|ProgramData|Users\\Public)\\') { $f += 'User/temp path' }
        if ($cmd -match '(?i)(powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)(\.exe)?\b') { $f += 'Script/LOLBIN host' }
        if ($cmd -match '(?i)(-enc(odedcommand)?\b|frombase64string|https?://)') { $f += 'Encoded/download reference' }
        return ($f -join '; ')
    }
    function Add-Row($loc, $name, $cmd, $extra) {
        $fl = @((Get-Flags $cmd), $extra) | Where-Object { $_ }
        [void]$rows.Add([pscustomobject]@{ Location=$loc; Name=$name; Command=$cmd; Review=($fl -join '; ') })
    }
    function Read-Key($key, $valueNamesOnly) {
        if (-not (Test-Path -LiteralPath $key)) { return }
        $e = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        if (-not $e) { return }
        foreach ($prop in $e.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' }) {
            Add-Row $key $prop.Name ([string]$prop.Value) $null
        }
    }

    # Run-style keys
    $runKeys = @()
    foreach ($root in 'HKLM:\SOFTWARE','HKLM:\SOFTWARE\WOW6432Node','HKCU:\SOFTWARE') {
        foreach ($leaf in 'Microsoft\Windows\CurrentVersion\Run','Microsoft\Windows\CurrentVersion\RunOnce','Microsoft\Windows\CurrentVersion\RunServices','Microsoft\Windows\CurrentVersion\RunServicesOnce','Microsoft\Windows\CurrentVersion\Policies\Explorer\Run') {
            $runKeys += "$root\$leaf"
        }
    }
    foreach ($sid in (Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object PSChildName -Match '^S-1-5-21-\d+-\d+-\d+-\d+$')) {
        foreach ($leaf in 'Run','RunOnce','Policies\Explorer\Run') { $runKeys += "Registry::HKEY_USERS\$($sid.PSChildName)\Software\Microsoft\Windows\CurrentVersion\$leaf" }
    }
    foreach ($k in ($runKeys | Select-Object -Unique)) { Read-Key $k }

    # Offline user hives (users not currently logged on)
    $skip = 'Public','Default','Default User','All Users'
    foreach ($u in (Get-ChildItem C:\Users -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $skip -notcontains $_.Name })) {
        $hive = Join-Path $u.FullName 'NTUSER.DAT'
        if (-not (Test-Path -LiteralPath $hive -ErrorAction SilentlyContinue)) { continue }
        $null = & reg.exe load 'HKU\RECOVERAT_TMP' $hive 2>&1
        if ($LASTEXITCODE -ne 0) { continue }   # already loaded / in use
        try {
            foreach ($leaf in 'Run','RunOnce','Policies\Explorer\Run') {
                $k = "Registry::HKEY_USERS\RECOVERAT_TMP\Software\Microsoft\Windows\CurrentVersion\$leaf"
                if (Test-Path -LiteralPath $k) {
                    $e = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
                    foreach ($prop in $e.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' }) {
                        Add-Row "OFFLINE:$($u.Name)\$leaf" $prop.Name ([string]$prop.Value) $null
                    }
                }
            }
        } finally {
            [gc]::Collect(); [gc]::WaitForPendingFinalizers()
            $null = & reg.exe unload 'HKU\RECOVERAT_TMP' 2>&1
        }
    }

    # Winlogon Shell / Userinit
    $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    if ($wl) {
        if ($wl.Shell -and $wl.Shell -ne 'explorer.exe') { Add-Row 'Winlogon' 'Shell' $wl.Shell 'Non-default Shell' }
        if ($wl.Userinit -and $wl.Userinit -notmatch '(?i)^C:\\Windows\\system32\\userinit\.exe,?$') { Add-Row 'Winlogon' 'Userinit' $wl.Userinit 'Non-default Userinit' }
        if ($All) { Add-Row 'Winlogon' 'Shell (default)' ([string]$wl.Shell) $null; Add-Row 'Winlogon' 'Userinit (default)' ([string]$wl.Userinit) $null }
    }

    # IFEO debuggers
    foreach ($ifeo in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
        foreach ($sub in Get-ChildItem $ifeo -ErrorAction SilentlyContinue) {
            $d = (Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue).Debugger
            if ($d) { Add-Row "IFEO:$($sub.PSChildName)" 'Debugger' $d 'IFEO debugger hijack' }
        }
    }

    # AppInit_DLLs
    foreach ($ai in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $v = (Get-ItemProperty $ai -ErrorAction SilentlyContinue).AppInit_DLLs
        if ($v) { Add-Row $ai 'AppInit_DLLs' $v 'AppInit_DLLs set' }
    }

    # Active Setup
    foreach ($as in 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components') {
        foreach ($sub in Get-ChildItem $as -ErrorAction SilentlyContinue) {
            $stub = (Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue).StubPath
            if ($stub) { Add-Row "ActiveSetup:$($sub.PSChildName)" 'StubPath' $stub $null }
        }
    }

    # Startup folders: common + every user profile
    $folders = @([Environment]::GetFolderPath('CommonStartup'))
    $folders += @(Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' })
    foreach ($folder in ($folders | Where-Object { $_ } | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        foreach ($item in (Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue | Where-Object Name -ne 'desktop.ini')) {
            Add-Row $folder $item.Name $item.FullName 'Startup folder item'
        }
    }

    Write-Host "Entries: $($rows.Count); flagged for review: $( @($rows | Where-Object Review).Count)"
    if ($All) { $rows | Sort-Object Location,Name | Format-Table Location,Name,Command,Review -Wrap -AutoSize }
    else { $rows | Where-Object Review | Sort-Object Location,Name | Format-Table Location,Name,Command,Review -Wrap -AutoSize }
    Write-Host 'Use Autoruns for wider persistence coverage (services, tasks, drivers, WMI, etc.).' -ForegroundColor Yellow
} finally {
    if ($LogDir) { Stop-Transcript | Out-Null }
}
