# RECOVERat - read-only service review
param([switch]$All, [string]$LogDir)
if ($LogDir) { Start-Transcript -Path (Join-Path $LogDir 'SERVICECHECK.log') -Append | Out-Null }
try {
    Write-Host '=== SERVICE CHECK ===' -ForegroundColor Cyan
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Warning 'Not admin: results may be incomplete.' }

    $sigCache = @{}
    function Get-ImageExe([string]$cmd) {
        $cmd = $cmd.Trim()
        if ($cmd -match '^"([^"]+)"') { return [Environment]::ExpandEnvironmentVariables($Matches[1]) }
        if ($cmd -match '^(.+?\.(exe|sys|dll))\b') { return [Environment]::ExpandEnvironmentVariables($Matches[1]) }
        return $null
    }

    $rows = foreach ($s in @(Get-CimInstance Win32_Service)) {
        $path = [string]$s.PathName
        $flag = @()
        if (-not $path.Trim()) { $flag += 'No image path' }
        else {
            if ($path -match '(?i)\\(AppData|Temp|Downloads|ProgramData|Users\\Public)\\') { $flag += 'User/temp path' }
            if ($path -match '(?i)(powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)(\.exe)?\b') { $flag += 'Script/LOLBIN host' }
            if ($path -notmatch '^"' -and $path -match '^(.+?\.exe)\b' -and $Matches[1] -match '\s') { $flag += 'Unquoted path with spaces' }
            $exe = Get-ImageExe $path
            if ($exe) {
                if (-not (Test-Path -LiteralPath $exe)) { $flag += 'Image missing' }
                else {
                    if (-not $sigCache.ContainsKey($exe)) { $sigCache[$exe] = (Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction SilentlyContinue).Status }
                    if ($sigCache[$exe] -ne 'Valid') { $flag += "Signature: $($sigCache[$exe])" }
                }
            }
        }
        [pscustomobject]@{ Name=$s.Name; State=$s.State; Start=$s.StartMode; Account=$s.StartName; ImagePath=$path; Review=($flag -join '; ') }
    }
    Write-Host "Services: $($rows.Count); flagged for review: $( @($rows | Where-Object Review).Count)"
    if ($All) { $rows | Sort-Object Name | Format-Table Name,State,Start,Account,ImagePath,Review -Wrap -AutoSize }
    else { $rows | Where-Object Review | Sort-Object Name | Format-Table Name,State,Start,Account,ImagePath,Review -Wrap -AutoSize }
    Write-Host 'Flags are leads, not evidence of malware. Use -All for the complete inventory.' -ForegroundColor Yellow
} finally {
    if ($LogDir) { Stop-Transcript | Out-Null }
}
