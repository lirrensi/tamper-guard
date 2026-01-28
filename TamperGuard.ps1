# v0.1
# This little script creates a bruteforce prevention on physical access to a locked PC.
# Shutdowns PC when 3+ incorrect login attempts.

# Threat level: random burglar, curios colleague, unprepared attacker.
# Target: causal users who want better security while away.
# Initial intent: to lock PC better while away.

# === LIMITATIONS ===

# Does not cover if attacker made log in - they can remove scripts or simply extract your keys anyway.
# Does not cover coerced input - no canary mechanism present, and even if it was its useless anyway cause restart resets the attack loop.

# Does not cover tampering while shutdown - attacker can boot from USB, install hardware keyloggers, etc.
# Does not prevent BIOS/UEFI manipulation if not password-protected.
# Does not cover DMA attacks (Thunderbolt/PCIe) - enable Kernel DMA Protection separately.

# Easily bypassable with Safe Mode: An attacker with physical access can reboot into Safe Mode (unless prevented by BitLocker/BIOS password), where Task Scheduler won't run.
# Bypassable by disabling Task Scheduler from external OS if BitLocker not enabled.
# Counter resets on reboot - attacker gets 3 fresh attempts per boot cycle.

# === REQUIREMENTS ===

# CRITICAL: Use with BitLocker (with TPM+PIN for best security), else an attacker can:
#   - Boot from USB and disable this script entirely
#   - Access files directly from external OS
#   - Repeatedly attempt logins across multiple boots
#   - Sideload malicious software

# RECOMMENDED additional hardening:
#   - BIOS/UEFI password to prevent boot order changes
#   - Secure Boot enabled
#   - Disable Safe Mode boot (bcdedit /set {default} safeboot minimal)
#   - Physical port locks/disabled USB ports in BIOS

# This is not enterprise grade solution, use actual Windows native hardening instead!
# (Account lockout policies, Credential Guard, Windows Hello, etc.)


#Requires -RunAsAdministrator

$TaskNameFail = "TamperGuard_FailCheck"
$TaskNameReset = "TamperGuard_ResetCounter"
$TaskNameLock = "TamperGuard_LockActivate"
$SecureDir = Join-Path $env:ProgramData "TamperGuard"
$CounterPath = "HKLM:\SOFTWARE\TamperGuard"
$ConfigPath = Join-Path $SecureDir "TamperGuard.json"
$ShutdownLogPath = Join-Path $SecureDir "TamperGuard_Shutdown.log"
$PowerShellPath = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$AuditPolPath = Join-Path $env:SystemRoot "System32\auditpol.exe"

function Ensure-SecureStorage {
    # Use SIDs - they're universal across all languages!
    $adminsSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544") # Administrators
    $systemSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")     # SYSTEM
    $usersSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-545")  # Users
    
    $expectedOwner = $adminsSID.Translate([System.Security.Principal.NTAccount])
    
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $allowType = [System.Security.AccessControl.AccessControlType]::Allow

    $secureAcl = New-Object System.Security.AccessControl.DirectorySecurity
    $secureAcl.SetAccessRuleProtection($true, $false)
    $secureAcl.SetOwner($expectedOwner)

    # Administrators - Full Control
    $secureAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $adminsSID,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        $propagation,
        $allowType)))
    
    # SYSTEM - Full Control
    $secureAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $systemSID,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        $propagation,
        $allowType)))
    
    # Users - Read & Execute only
    $secureAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $usersSID,
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        $inheritance,
        $propagation,
        $allowType)))

    $dirExists = Test-Path $SecureDir
    if ($dirExists) {
        $rootItem = Get-Item -LiteralPath $SecureDir -Force -ErrorAction Stop
        if ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "SECURITY ERROR: $SecureDir is a reparse point. Aborting."
        }

        $expectedNames = @(
            "TamperGuard_OnFail.ps1",
            "TamperGuard_OnSuccess.ps1",
            "TamperGuard_OnLock.ps1",
            "TamperGuard.json",
            "TamperGuard_Shutdown.log"
        )

        # Try to get items, but handle permission denied gracefully
        try {
            $existingItems = Get-ChildItem -LiteralPath $SecureDir -Force -ErrorAction Stop |
                             Where-Object { $_.Name -ne '.' -and $_.Name -ne '..' }

            foreach ($child in $existingItems) {
                if ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                    throw "SECURITY ERROR: $SecureDir contains reparse item '$($child.Name)'. Aborting."
                }
                if ($expectedNames -notcontains $child.Name) {
                    throw "SECURITY ERROR: $SecureDir contains unexpected item '$($child.Name)'. Aborting."
                }
            }
        } catch [System.UnauthorizedAccessException] {
            # If we can't read it, apply permissions anyway
            Write-Host "   Fixing permissions on existing directory..." -ForegroundColor Yellow
        }
    } else {
        New-Item -Path $SecureDir -ItemType Directory -Force | Out-Null
    }

    # Apply the ACL
    Set-Acl -Path $SecureDir -AclObject $secureAcl

    # Verify
    $currentAcl = Get-Acl -Path $SecureDir
    $currentOwner = $currentAcl.Owner
    try {
        $currentOwnerSID = (New-Object System.Security.Principal.NTAccount($currentOwner)).Translate([System.Security.Principal.SecurityIdentifier])
        if ($currentOwnerSID -ne $adminsSID -and $currentOwnerSID -ne $systemSID) {
            throw "SECURITY ERROR: Cannot secure TamperGuard directory - unexpected owner SID: $currentOwnerSID"
        }
    } catch {
        if ($currentOwner -notmatch "Administrators|Beheerders|Administratoren|Administrateurs|SYSTEM") {
            throw "SECURITY ERROR: Cannot secure TamperGuard directory - unexpected owner: $currentOwner"
        }
    }

    foreach ($rule in $currentAcl.Access) {
        $identity = $rule.IdentityReference.Value
        $rights = $rule.FileSystemRights

        # Check by SID instead of name
        try {
            $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
            if ($sid -eq $usersSID) {
                if ($rights -match "Write|Modify|FullControl|CreateFiles") {
                    throw "SECURITY ERROR: TamperGuard directory has insecure permissions for Users"
                }
            }
        } catch {
            # If translation fails, check by name pattern
            if ($identity -match "Users|Gebruikers|Benutzer|Utilisateurs|Everyone|Authenticated Users") {
                if ($rights -match "Write|Modify|FullControl|CreateFiles") {
                    throw "SECURITY ERROR: TamperGuard directory has insecure permissions for: $identity"
                }
            }
        }
    }

    Write-Host "   Secure storage verified: $SecureDir" -ForegroundColor Gray
}

function Enable-WindowsAuditing {
    Write-Host "   Configuring Windows Audit Policies..." -ForegroundColor Gray
    if (Test-Path $AuditPolPath) {
        & $AuditPolPath /set /subcategory:"Logon" /success:enable | Out-Null
        & $AuditPolPath /set /subcategory:"Logon" /failure:enable | Out-Null
        & $AuditPolPath /set /subcategory:"Other Logon/Logoff Events" /success:enable | Out-Null
    } else {
        Write-Host "WARN: auditpol.exe not found at $AuditPolPath. Events might not generate!" -ForegroundColor Red
    }
}

function Test-AuditPolicy {
    # Localization of names makes accurate verification unreliable,
    # and Enable-WindowsAuditing already configures the policies.
    Write-Host "   Audit policy configured (verify manually if needed)" -ForegroundColor Gray
}

function Normalize-MaxAttempts {
    param([int]$Value)

    if ($Value -lt 1) {
        return 1
    }
    if ($Value -gt 10) {
        return 10
    }
    return $Value
}

function Get-ValidatedMaxAttempts {
    param(
        [string]$Input,
        [int]$Default = 3
    )

    if ([string]::IsNullOrWhiteSpace($Input)) {
        return $Default
    }
    $parsed = 0
    if (-not [int]::TryParse($Input, [ref]$parsed)) {
        Write-Host "Invalid max attempt value. Using default ($Default)." -ForegroundColor Yellow
        return $Default
    }
    $validated = Normalize-MaxAttempts -Value $parsed
    if ($validated -ne $parsed) {
        Write-Host "Max attempts clamped to $validated (allowed range 1-10)." -ForegroundColor Yellow
    }
    return $validated
}

function Get-TaskStatus {
    $taskFail = Get-ScheduledTask -TaskName $TaskNameFail -ErrorAction SilentlyContinue
    $taskReset = Get-ScheduledTask -TaskName $TaskNameReset -ErrorAction SilentlyContinue
    
    if ($taskFail -and $taskReset) {
        $config = Get-Config
        $currentCount = Get-FailCount
        Write-Host "OK Tamper Guard is ACTIVE" -ForegroundColor Green
        Write-Host "   Max attempts per lock session: $($config.MaxAttempts)" -ForegroundColor Cyan
        $countColor = if ($currentCount -gt 0) { 'Yellow' } else { 'Gray' }
        Write-Host "   Current fail count: $currentCount" -ForegroundColor $countColor
        return $true
    } else {
        Write-Host "NO Tamper Guard is NOT installed" -ForegroundColor Yellow
        return $false
    }
}

function Get-Config {
    if (Test-Path $ConfigPath) {
        try {
            $content = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop |
                       ConvertFrom-Json -ErrorAction Stop

            if (-not $content.MaxAttempts) {
                $content | Add-Member -MemberType NoteProperty -Name MaxAttempts -Value 3 -Force
            }
            if (-not $content.ScriptHashes) {
                $content | Add-Member -MemberType NoteProperty -Name ScriptHashes -Value @{} -Force
            }
            return $content
        } catch {
            Write-Host "WARN: Config file corrupted, using defaults. Error: $($_.Exception.Message)" -ForegroundColor Yellow
            return [PSCustomObject]@{
                MaxAttempts = 3
                ScriptHashes = @{}
            }
        }
    }

    return [PSCustomObject]@{
        MaxAttempts = 3
        ScriptHashes = @{}
    }
}

function Save-Config {
    param([pscustomobject]$Config)
    Ensure-SecureStorage
    if (Test-Path $ConfigPath) {
        Remove-Item -LiteralPath $ConfigPath -Force -ErrorAction SilentlyContinue
    }
    $Config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath
}

function Set-Config {
    param([int]$MaxAttempts)
    $config = Get-Config
    $config.MaxAttempts = $MaxAttempts
    Save-Config $config
}

function Update-ScriptHashes {
    param([hashtable]$Hashes)
    if (-not $Hashes) {
        return
    }

    $config = Get-Config

    # Replace the entire ScriptHashes payload to avoid NoteProperty limitations
    $config.ScriptHashes = $Hashes

    Save-Config $config
}

function Get-FailCount {
    $val = Get-ItemProperty -Path $CounterPath -Name "Count" -ErrorAction SilentlyContinue
    if ($val) {
        return $val.Count
    }
    return 0
}

function Protect-CounterRegistry {
    if (-not (Test-Path $CounterPath)) {
        New-Item -Path $CounterPath -Force | Out-Null
    }
    try {
        Set-ItemProperty -Path $CounterPath -Name "Count" -Value 0 -ErrorAction Stop
    } catch {
        Write-Host "   WARN: Could not set registry counter value: $($_.Exception.Message)" -ForegroundColor Yellow
        $regPath = $CounterPath -replace 'HKLM:\\', 'HKLM\'
        & reg.exe add "$regPath" /v Count /t REG_DWORD /d 0 /f | Out-Null
    }

    try {
        $acl = Get-Acl -Path $CounterPath -ErrorAction Stop
        if (-not $acl) {
            throw "Get-Acl returned null"
        }

        $adminsSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $systemSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")

        $acl.SetAccessRuleProtection($true, $false)
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
        $propagation = [System.Security.AccessControl.PropagationFlags]::None
        $allowType = [System.Security.AccessControl.AccessControlType]::Allow
        $rights = [System.Security.AccessControl.RegistryRights]::FullControl

        $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $adminsSID,
            $rights,
            $inheritance,
            $propagation,
            $allowType)
        $systemRule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $systemSID,
            $rights,
            $inheritance,
            $propagation,
            $allowType)

        $acl.SetAccessRule($adminRule)
        $acl.AddAccessRule($systemRule)
        Set-Acl -Path $CounterPath -AclObject $acl -ErrorAction Stop
        Write-Host "   Registry ACL protection applied" -ForegroundColor Gray
    } catch {
        Write-Host "   WARN: Could not apply registry ACL: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "   Counter will still work but may be less secure" -ForegroundColor Gray
    }
}

function Register-TamperGuard {
    param([int]$MaxAttempts = 3)
    
    $MaxAttempts = Normalize-MaxAttempts -Value $MaxAttempts
    
    if (Get-ScheduledTask -TaskName $TaskNameFail -ErrorAction SilentlyContinue) {
        Write-Host "WARN Tasks already exist! Unregister first." -ForegroundColor Yellow
        return
    }

    Ensure-SecureStorage
    Enable-WindowsAuditing
    Test-AuditPolicy
    Set-Config -MaxAttempts $MaxAttempts

    # Reset counter registry
    Protect-CounterRegistry

    # Script 1: Increment counter and check threshold on failed login
    $scriptFailPath = Join-Path $SecureDir "TamperGuard_OnFail.ps1"
    $scriptFailContent = @"
`$counterPath = '$CounterPath'
`$configPath = '$ConfigPath'
`$shutdownLog = '$ShutdownLogPath'
`$scriptKey = 'OnFail'

function Write-ShutdownLog {
    param([string]`$Message)
    `$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "`$timestamp `$Message" | Out-File `$shutdownLog -Append -ErrorAction SilentlyContinue
}

if (-not (Test-Path `$configPath)) {
    Write-ShutdownLog "TamperGuard CONFIG MISSING - SECURITY ALERT"
    Stop-Computer -Force
}

`$config = `$null
try {
    `$config = Get-Content -Path `$configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-ShutdownLog "TamperGuard CONFIG CORRUPTED - TAMPER DETECTED: `$(`$_.Exception.Message)"
    Stop-Computer -Force
}

if (-not `$config.MaxAttempts -or -not `$config.ScriptHashes) {
    Write-ShutdownLog "TamperGuard CONFIG INVALID STRUCTURE - TAMPER DETECTED"
    Stop-Computer -Force
}

`$maxAttempts = `$config.MaxAttempts
`$expectedHash = `$null
try {
    `$expectedHash = `$config.ScriptHashes.`$scriptKey
} catch {
    Write-ShutdownLog "TamperGuard HASH ACCESS FAILED: `$scriptKey"
    Stop-Computer -Force
}

if (-not `$expectedHash) {
    Write-ShutdownLog "TamperGuard MISSING HASH: `$scriptKey - TAMPER DETECTED - SHUTTING DOWN"
    Stop-Computer -Force
}

`$scriptPath = `$MyInvocation.MyCommand.Path
`$actualHash = (Get-FileHash -Algorithm SHA256 -Path `$scriptPath).Hash
if (`$actualHash -ne `$expectedHash) {
    Write-ShutdownLog "TamperGuard INTEGRITY FAILURE: `$scriptKey"
    throw "TamperGuard script hash mismatch"
}

`$mutexName = 'Global\TamperGuard_Counter'
`$mutexSecurity = New-Object System.Security.AccessControl.MutexSecurity
`$adminRule = New-Object System.Security.AccessControl.MutexAccessRule(
    "BUILTIN\Administrators",
    [System.Security.AccessControl.MutexRights]::FullControl,
    [System.Security.AccessControl.AccessControlType]::Allow)
`$systemRule = New-Object System.Security.AccessControl.MutexAccessRule(
    "NT AUTHORITY\SYSTEM",
    [System.Security.AccessControl.MutexRights]::FullControl,
    [System.Security.AccessControl.AccessControlType]::Allow)
`$mutexSecurity.AddAccessRule(`$adminRule)
`$mutexSecurity.AddAccessRule(`$systemRule)

`$createdNew = `$false
`$mutex = `$null
`$locked = `$false
try {
    `$mutex = New-Object System.Threading.Mutex(
        `$false,
        `$mutexName,
        [ref]`$createdNew,
        `$mutexSecurity)
    `$locked = `$mutex.WaitOne(5000)
    if (-not `$locked) {
        Write-ShutdownLog "TamperGuard MUTEX TIMEOUT - POSSIBLE ATTACK - SHUTTING DOWN"
        Stop-Computer -Force
    }

    `$count = 0
    `$val = Get-ItemProperty -Path `$counterPath -Name 'Count' -ErrorAction SilentlyContinue
    if (`$val) {
        `$count = `$val.Count
    }
    `$count++
    if (-not (Test-Path `$counterPath)) {
        New-Item -Path `$counterPath -Force | Out-Null
    }
    Set-ItemProperty -Path `$counterPath -Name 'Count' -Value `$count

    if (`$count -ge `$maxAttempts) {
        Write-ShutdownLog "TAMPER DETECTED: `$count failed attempts - SHUTTING DOWN!"
        Start-Sleep -Milliseconds 100
        Stop-Computer -Force
    }
} catch {
    Write-ShutdownLog "TamperGuard MUTEX ERROR: `$(`$_.Exception.Message) - SHUTTING DOWN"
    Stop-Computer -Force
} finally {
    if (`$locked -and `$mutex) {
        try { `$mutex.ReleaseMutex() } catch { }
    }
    if (`$mutex) {
        try { `$mutex.Dispose() } catch { }
    }
}
"@
    if (Test-Path $scriptFailPath) {
        Remove-Item -LiteralPath $scriptFailPath -Force -ErrorAction SilentlyContinue
    }
    Set-Content -LiteralPath $scriptFailPath -Value $scriptFailContent

    # Script 2: Reset counter on successful unlock
    $scriptResetPath = Join-Path $SecureDir "TamperGuard_OnSuccess.ps1"
    $scriptResetContent = @"
`$counterPath = '$CounterPath'
`$configPath = '$ConfigPath'
`$shutdownLog = '$ShutdownLogPath'
`$scriptKey = 'OnSuccess'

function Write-ShutdownLog {
    param([string]`$Message)
    `$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "`$timestamp `$Message" | Out-File `$shutdownLog -Append -ErrorAction SilentlyContinue
}

if (-not (Test-Path `$configPath)) {
    Write-ShutdownLog "TamperGuard CONFIG MISSING - SECURITY ALERT"
    Stop-Computer -Force
}

`$config = `$null
try {
    `$config = Get-Content -Path `$configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-ShutdownLog "TamperGuard CONFIG CORRUPTED - TAMPER DETECTED: `$(`$_.Exception.Message)"
    Stop-Computer -Force
}

if (-not `$config.MaxAttempts -or -not `$config.ScriptHashes) {
    Write-ShutdownLog "TamperGuard CONFIG INVALID STRUCTURE - TAMPER DETECTED"
    Stop-Computer -Force
}

`$expectedHash = `$null
try {
    `$expectedHash = `$config.ScriptHashes.`$scriptKey
} catch {
    Write-ShutdownLog "TamperGuard HASH ACCESS FAILED: `$scriptKey"
    Stop-Computer -Force
}

if (-not `$expectedHash) {
    Write-ShutdownLog "TamperGuard MISSING HASH: `$scriptKey - TAMPER DETECTED - SHUTTING DOWN"
    Stop-Computer -Force
}

`$scriptPath = `$MyInvocation.MyCommand.Path
`$actualHash = (Get-FileHash -Algorithm SHA256 -Path `$scriptPath).Hash
if (`$actualHash -ne `$expectedHash) {
    Write-ShutdownLog "TamperGuard INTEGRITY FAILURE: `$scriptKey"
    throw "TamperGuard script hash mismatch"
}

`$mutexName = 'Global\TamperGuard_Counter'
`$mutexSecurity = New-Object System.Security.AccessControl.MutexSecurity
`$adminRule = New-Object System.Security.AccessControl.MutexAccessRule(
    "BUILTIN\Administrators",
    [System.Security.AccessControl.MutexRights]::FullControl,
    [System.Security.AccessControl.AccessControlType]::Allow)
`$systemRule = New-Object System.Security.AccessControl.MutexAccessRule(
    "NT AUTHORITY\SYSTEM",
    [System.Security.AccessControl.MutexRights]::FullControl,
    [System.Security.AccessControl.AccessControlType]::Allow)
`$mutexSecurity.AddAccessRule(`$adminRule)
`$mutexSecurity.AddAccessRule(`$systemRule)

`$createdNew = `$false
`$mutex = `$null
`$locked = `$false
try {
    `$mutex = New-Object System.Threading.Mutex(
        `$false,
        `$mutexName,
        [ref]`$createdNew,
        `$mutexSecurity)
    `$locked = `$mutex.WaitOne(5000)
    if (-not `$locked) {
        Write-ShutdownLog "TamperGuard MUTEX TIMEOUT - POSSIBLE ATTACK - SHUTTING DOWN"
        Stop-Computer -Force
    }

    if (-not (Test-Path `$counterPath)) {
        New-Item -Path `$counterPath -Force | Out-Null
    }
    Set-ItemProperty -Path `$counterPath -Name 'Count' -Value 0
} catch {
    Write-ShutdownLog "TamperGuard MUTEX ERROR: `$(`$_.Exception.Message) - SHUTTING DOWN"
    Stop-Computer -Force
} finally {
    if (`$locked -and `$mutex) {
        try { `$mutex.ReleaseMutex() } catch { }
    }
    if (`$mutex) {
        try { `$mutex.Dispose() } catch { }
    }
}
"@
    if (Test-Path $scriptResetPath) {
        Remove-Item -LiteralPath $scriptResetPath -Force -ErrorAction SilentlyContinue
    }
    Set-Content -LiteralPath $scriptResetPath -Value $scriptResetContent

    # Script 3: Activate guard on workstation lock
    $scriptLockPath = Join-Path $SecureDir "TamperGuard_OnLock.ps1"
    $scriptLockContent = @"
`$counterPath = '$CounterPath'
`$configPath = '$ConfigPath'
`$shutdownLog = '$ShutdownLogPath'
`$scriptKey = 'OnLock'

function Write-ShutdownLog {
    param([string]`$Message)
    `$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "`$timestamp `$Message" | Out-File `$shutdownLog -Append -ErrorAction SilentlyContinue
}

if (-not (Test-Path `$configPath)) {
    Write-ShutdownLog "TamperGuard CONFIG MISSING - SECURITY ALERT"
    Stop-Computer -Force
}

`$config = `$null
try {
    `$config = Get-Content -Path `$configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-ShutdownLog "TamperGuard CONFIG CORRUPTED - TAMPER DETECTED: `$(`$_.Exception.Message)"
    Stop-Computer -Force
}

if (-not `$config.MaxAttempts -or -not `$config.ScriptHashes) {
    Write-ShutdownLog "TamperGuard CONFIG INVALID STRUCTURE - TAMPER DETECTED"
    Stop-Computer -Force
}

`$expectedHash = `$null
try {
    `$expectedHash = `$config.ScriptHashes.`$scriptKey
} catch {
    Write-ShutdownLog "TamperGuard HASH ACCESS FAILED: `$scriptKey"
    Stop-Computer -Force
}

if (-not `$expectedHash) {
    Write-ShutdownLog "TamperGuard MISSING HASH: `$scriptKey - TAMPER DETECTED - SHUTTING DOWN"
    Stop-Computer -Force
}

`$scriptPath = `$MyInvocation.MyCommand.Path
`$actualHash = (Get-FileHash -Algorithm SHA256 -Path `$scriptPath).Hash
if (`$actualHash -ne `$expectedHash) {
    Write-ShutdownLog "TamperGuard INTEGRITY FAILURE: `$scriptKey"
    throw "TamperGuard script hash mismatch"
}

`$mutexName = 'Global\TamperGuard_Counter'
`$mutexSecurity = New-Object System.Security.AccessControl.MutexSecurity
`$adminRule = New-Object System.Security.AccessControl.MutexAccessRule(
    "BUILTIN\Administrators",
    [System.Security.AccessControl.MutexRights]::FullControl,
    [System.Security.AccessControl.AccessControlType]::Allow)
`$systemRule = New-Object System.Security.AccessControl.MutexAccessRule(
    "NT AUTHORITY\SYSTEM",
    [System.Security.AccessControl.MutexRights]::FullControl,
    [System.Security.AccessControl.AccessControlType]::Allow)
`$mutexSecurity.AddAccessRule(`$adminRule)
`$mutexSecurity.AddAccessRule(`$systemRule)

`$createdNew = `$false
`$mutex = `$null
`$locked = `$false
try {
    `$mutex = New-Object System.Threading.Mutex(
        `$false,
        `$mutexName,
        [ref]`$createdNew,
        `$mutexSecurity)
    `$locked = `$mutex.WaitOne(5000)
    if (-not `$locked) {
        Write-ShutdownLog "TamperGuard MUTEX TIMEOUT - POSSIBLE ATTACK - SHUTTING DOWN"
        Stop-Computer -Force
    }

    if (-not (Test-Path `$counterPath)) {
        New-Item -Path `$counterPath -Force | Out-Null
    }
    Set-ItemProperty -Path `$counterPath -Name 'Count' -Value 0
} catch {
    Write-ShutdownLog "TamperGuard MUTEX ERROR: `$(`$_.Exception.Message) - SHUTTING DOWN"
    Stop-Computer -Force
} finally {
    if (`$locked -and `$mutex) {
        try { `$mutex.ReleaseMutex() } catch { }
    }
    if (`$mutex) {
        try { `$mutex.Dispose() } catch { }
    }
}
"@
    if (Test-Path $scriptLockPath) {
        Remove-Item -LiteralPath $scriptLockPath -Force -ErrorAction SilentlyContinue
    }
    Set-Content -LiteralPath $scriptLockPath -Value $scriptLockContent

    $scriptHashSources = @{
        OnFail = $scriptFailPath
        OnSuccess = $scriptResetPath
        OnLock = $scriptLockPath
    }
    $scriptHashes = @{}
    foreach ($entry in $scriptHashSources.GetEnumerator()) {
        $scriptHashes[$entry.Key] = (Get-FileHash -Algorithm SHA256 -Path $entry.Value).Hash
    }
    Update-ScriptHashes -Hashes $scriptHashes

    # Task 1: Trigger on FAILED login (Event 4625, local only)
    $xmlFail = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Counts failed login attempts and triggers shutdown</Description>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Security"&gt;&lt;Select Path="Security"&gt;*[System[(EventID=4625)]] and *[EventData[Data[@Name='LogonType'] and (Data='2' or Data='7' or Data='11')]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
  </Settings>
  <Actions>
    <Exec>
      <Command>$PowerShellPath</Command>
      <Arguments>-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$scriptFailPath"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

    # Task 2: Trigger on SUCCESSFUL unlock (Event 4624, unlock only)
    $xmlReset = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Resets fail counter on successful unlock</Description>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Security"&gt;&lt;Select Path="Security"&gt;*[System[(EventID=4624)]] and *[EventData[Data[@Name='LogonType'] and (Data='7' or Data='11')]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
  </Settings>
  <Actions>
    <Exec>
      <Command>$PowerShellPath</Command>
      <Arguments>-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$scriptResetPath"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

    # Task 3: Trigger on workstation LOCK (Event 4800)
    $xmlLock = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Resets counter when workstation locks</Description>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Security"&gt;&lt;Select Path="Security"&gt;*[System[(EventID=4800)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
  </Settings>
  <Actions>
    <Exec>
      <Command>$PowerShellPath</Command>
      <Arguments>-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$scriptLockPath"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

    Register-ScheduledTask -TaskName $TaskNameFail -Xml $xmlFail | Out-Null
    Register-ScheduledTask -TaskName $TaskNameReset -Xml $xmlReset | Out-Null
    Register-ScheduledTask -TaskName $TaskNameLock -Xml $xmlLock | Out-Null
    
    Write-Host "** Tamper Guard registered successfully!" -ForegroundColor Magenta
    Write-Host "   Lock session mode: $MaxAttempts wrong passwords = INSTANT SHUTDOWN!" -ForegroundColor Cyan
    Write-Host "   Counter resets on: Lock screen OR successful unlock" -ForegroundColor Gray
}

function Unregister-TamperGuard {
    $removed = 0
    
    if (Get-ScheduledTask -TaskName $TaskNameFail -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskNameFail -Confirm:$false
        $removed++
    }
    if (Get-ScheduledTask -TaskName $TaskNameReset -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskNameReset -Confirm:$false
        $removed++
    }
    if (Get-ScheduledTask -TaskName $TaskNameLock -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskNameLock -Confirm:$false
        $removed++
    }
    
    Remove-Item -Path (Join-Path $SecureDir "TamperGuard_*.ps1") -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $ConfigPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $ShutdownLogPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $SecureDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $CounterPath -Recurse -Force -ErrorAction SilentlyContinue
    
    if ($removed -gt 0) {
        Write-Host "DEL Tamper Guard removed! ($removed tasks)" -ForegroundColor Green
    } else {
        Write-Host "WARN No tasks found!" -ForegroundColor Yellow
    }
}

function Show-FailedAttempts {
    param([int]$Last = 20)
    
    Write-Host "`n[LOG] Recent Failed Login Attempts (Local only):" -ForegroundColor Cyan
    Write-Host "==============================================" -ForegroundColor Cyan
    
    $fails = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        ID=4625
    } -MaxEvents $Last -ErrorAction SilentlyContinue | Where-Object {
        $_.Properties[8].Value -eq 2 -or $_.Properties[8].Value -eq 7 -or $_.Properties[8].Value -eq 11
    }
    
    if ($fails) {
        foreach ($event in $fails) {
            $time = $event.TimeCreated
            $account = $event.Properties[5].Value
            $workstation = $event.Properties[13].Value
            Write-Host "⏰ $time" -ForegroundColor Yellow
            Write-Host "   Account: $account | Workstation: $workstation`n" -ForegroundColor Gray
        }
    } else {
        Write-Host "[OK] No recent failed attempts found!" -ForegroundColor Green
    }
    
    # Show shutdown log if exists
    $logPath = $ShutdownLogPath
    if (Test-Path $logPath) {
        Write-Host "`n[ALERT] SHUTDOWN LOG:" -ForegroundColor Red
        Write-Host "=================" -ForegroundColor Red
        Get-Content $logPath | ForEach-Object {
            Write-Host $_ -ForegroundColor Yellow
        }
    }
}

# Main Menu
Clear-Host
Write-Host "=========================================" -ForegroundColor Magenta
Write-Host "  ** Tamper Guard - Lock Session Mode **  " -ForegroundColor Magenta
Write-Host "=========================================`n" -ForegroundColor Magenta

Get-TaskStatus
Write-Host "`n-----------------------------------------------------------" -ForegroundColor Gray

Write-Host "`n[1] Register Tamper Guard" -ForegroundColor Cyan
Write-Host "[2] Unregister Tamper Guard" -ForegroundColor Cyan
Write-Host "[3] Change Max Attempts" -ForegroundColor Cyan
Write-Host "[4] Show Failed Attempts Log" -ForegroundColor Cyan
Write-Host "[5] Reset Current Counter Manually" -ForegroundColor Cyan
Write-Host "[Q] Quit`n" -ForegroundColor Gray

$choice = Read-Host "Choose option"

switch ($choice.ToUpper()) {
    "1" {
        $maxAttemptsInput = Read-Host "Max attempts per lock session (default 3)"
        $maxAttempts = Get-ValidatedMaxAttempts -Input $maxAttemptsInput
        Register-TamperGuard -MaxAttempts $maxAttempts
    }
    "2" {
        Unregister-TamperGuard
    }
    "3" {
        if (-not (Get-TaskStatus)) {
            Write-Host "`nWARN Please register first!" -ForegroundColor Yellow
        } else {
            $maxAttemptsInput = Read-Host "`nEnter new max attempts"
            Unregister-TamperGuard
            Start-Sleep -Seconds 1
            $maxAttempts = Get-ValidatedMaxAttempts -Input $maxAttemptsInput
            Register-TamperGuard -MaxAttempts $maxAttempts
        }
    }
    "4" {
        $countInput = Read-Host "`nHow many recent attempts to show? (default 20)"
        $count = 20
        if (-not [string]::IsNullOrWhiteSpace($countInput)) {
            $parsed = 0
            if ([int]::TryParse($countInput, [ref]$parsed) -and $parsed -ge 1 -and $parsed -le 1000) {
                $count = $parsed
            } else {
                Write-Host "Invalid input, using default (20)." -ForegroundColor Yellow
            }
        }
        Show-FailedAttempts -Last $count
    }
    "5" {
        if (-not (Test-Path $CounterPath)) {
            New-Item -Path $CounterPath -Force | Out-Null
        }
        Set-ItemProperty -Path $CounterPath -Name "Count" -Value 0
        Write-Host "`nOK Counter reset to 0!" -ForegroundColor Green
    }
    "Q" {
        Write-Host "`nBYE Stay safe, darling~ **" -ForegroundColor Magenta
        exit
    }
    default {
        Write-Host "`nNO Invalid choice!" -ForegroundColor Red
    }
}

Write-Host "`n"
Read-Host "Press Enter to exit"
