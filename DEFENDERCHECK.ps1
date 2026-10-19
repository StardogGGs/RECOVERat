# RECOVERat - read-only Defender configuration review
param([string]$LogDir)
if ($LogDir) { Start-Transcript -Path (Join-Path $LogDir 'DEFENDERCHECK.log') -Append | Out-Null }
try {
    Write-Host '=== MICROSOFT DEFENDER CHECK ===' -ForegroundColor Cyan
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Write-Warning 'NOT ADMIN: Defender hides exclusions from non-elevated sessions. Re-run elevated.'; return }
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { Write-Warning 'Defender cmdlets unavailable on this system.'; return }

    try {
        Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,OnAccessProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated | Format-List
        $p = Get-MpPreference -ErrorAction Stop

        Write-Host '=== EXCLUSIONS (Get-MpPreference) - review individually ===' -ForegroundColor Cyan
        [pscustomobject]@{
            ExclusionPath      = ($p.ExclusionPath -join '; ')
            ExclusionProcess   = ($p.ExclusionProcess -join '; ')
            ExclusionExtension = ($p.ExclusionExtension -join '; ')
            ExclusionIpAddress = ($p.ExclusionIpAddress -join '; ')
            ASROnlyExclusions  = ($p.AttackSurfaceReductionOnlyExclusions -join '; ')
        } | Format-List

        Write-Host '=== EXCLUSIONS (registry, incl. policy-set) ===' -ForegroundColor Cyan
        foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions','HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions') {
            if (-not (Test-Path $k)) { continue }
            foreach ($sub in Get-ChildItem $k -ErrorAction SilentlyContinue) {
                Write-Host ("{0} [{1}]: {2}" -f $sub.PSChildName, $k, ($sub.Property -join '; '))
            }
        }

        Write-Host '=== SELECTED PREFERENCES ===' -ForegroundColor Cyan
        $p | Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableIOAVProtection,DisableScriptScanning,PUAProtection,MAPSReporting,SubmitSamplesConsent | Format-List

        Write-Host '=== ASR RULES (action: 0=off 1=block 2=audit) ===' -ForegroundColor Cyan
        $ids = @($p.AttackSurfaceReductionRules_Ids); $act = @($p.AttackSurfaceReductionRules_Actions)
        if ($ids.Count -eq 0 -or -not $ids[0]) { Write-Host 'None configured.' }
        else { for ($i = 0; $i -lt $ids.Count; $i++) { Write-Host ("{0}  action={1}" -f $ids[$i], $act[$i]) } }
    } catch {
        Write-Warning "Could not read all Defender settings: $($_.Exception.Message)"
    }

    Write-Host '=== REGISTERED ANTIVIRUS PRODUCTS (SecurityCenter2) ===' -ForegroundColor Cyan
    try { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | Select-Object displayName,productState,pathToSignedProductExe | Format-Table -AutoSize -Wrap }
    catch { Write-Host 'SecurityCenter2 unavailable (normal on Windows Server).' }

    Write-Host 'Settings can be unavailable or managed by policy. Read-only report.' -ForegroundColor Yellow
} finally {
    if ($LogDir) { Stop-Transcript | Out-Null }
}
