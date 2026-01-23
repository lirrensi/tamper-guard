# This little script creates a bruteforce prevention on physical access to a locked PC.
# Shutdowns PC when 3+ incorrect login attempts.

# Threat level: random burglar, curios colleague, unprepared attacker.
# Target: causal users who want better security while away.
# Initial intent: to lock PC better while away.

# Does not cover if attacker made log in - they can remove scripts or simply extract your keys anyway.
# Does not cover coerced input - no canary mechanism present, and even if it was its useless anyway cause restart resets the attack loop.

# Use with BitLocker, else an attacker can repeat attempts multiple times or sideload if hardware is stolen.
# Easily bypassable with Safe Mode: An attacker with physical access can reboot into Safe Mode (unless prevented by BitLocker/BIOS password), where Task Scheduler won't run.
# This is not enterprise grade solution, use actual windows native hardening instead!


#Requires -RunAsAdministrator

$TaskNameFail = "TamperGuard_FailCheck"
$TaskNameReset = "TamperGuard_ResetCounter"
$TaskNameLock = "TamperGuard_LockActivate"
$SecureDir = Join-Path $env:ProgramData "TamperGuard"
$CounterPath = "HKLM:\SOFTWARE\TamperGuard"
$ConfigPath = Join-Path $SecureDir "TamperGuard.json"
$ShutdownLogPath = Join-Path $SecureDir "TamperGuard_Shutdown.log"

function Ensure-SecureStorage {
    if (-not (Test-Path $SecureDir)) {
        New-Item -Path $SecureDir -ItemType Directory -Force | Out-Null
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        $propagation = [System.Security.AccessControl.PropagationFlags]::None
        $ruleType = [System.Security.AccessControl.AccessControlType]::Allow

        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)

        $acl.AddAccessRule((
            New-Object System.Security.AccessControl.FileSystemAccessRule(
                "BUILTIN\Administrators",
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance,
                $propagation,
                $ruleType)))
        $acl.AddAccessRule((
            New-Object System.Security.AccessControl.FileSystemAccessRule(
                "NT AUTHORITY\SYSTEM",
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                $inheritance,
                $propagation,
                $ruleType)))
        $acl.AddAccessRule((
            New-Object System.Security.AccessControl.FileSystemAccessRule(
                "Users",
                [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
                $inheritance,
                $propagation,
                $ruleType)))

        Set-Acl -Path $SecureDir -AclObject $acl
    }
}

function Enable-WindowsAuditing {
    Write-Host "   Configuring Windows Audit Policies..." -ForegroundColor Gray
    if (Get-Command "auditpol.exe" -ErrorAction SilentlyContinue) {
        auditpol /set /subcategory:"Logon" /success:enable | Out-Null
        auditpol /set /subcategory:"Logon" /failure:enable | Out-Null
        auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable | Out-Null
    } else {
        Write-Host "WARN: auditpol.exe not found. Events might not generate!" -ForegroundColor Red
    }
}

function Test-AuditPolicy {
    if (-not (Get-Command "auditpol.exe" -ErrorAction SilentlyContinue)) {
        Write-Warning "auditpol.exe is missing; unable to verify audit policy."
        return
    }

    $policy = auditpol /get /subcategory:"Logon" 2>$null
    if ($policy -and ($policy -notmatch "Success and Failure|Failure")) {
        Write-Warning "Audit policy for Logon may not be configured!"
        Write-Warning 'Run: auditpol /set /subcategory:"Logon" /failure:enable'
    }
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
        $content = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
        if (-not $content.MaxAttempts) {
            $content | Add-Member -MemberType NoteProperty -Name MaxAttempts -Value 3 -Force
        }
        if (-not $content.ScriptHashes) {
            $content | Add-Member -MemberType NoteProperty -Name ScriptHashes -Value @{} -Force
        }
        return $content
    }
    return [PSCustomObject]@{
        MaxAttempts = 3
        ScriptHashes = @{}
    }
}

function Save-Config {
    param([pscustomobject]$Config)
    Ensure-SecureStorage
    $Config | ConvertTo-Json -Depth 5 | Set-Content -Path $ConfigPath
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
    if (-not $config.ScriptHashes) {
        $config | Add-Member -MemberType NoteProperty -Name ScriptHashes -Value @{} -Force
    }

    foreach ($key in $Hashes.Keys) {
        $config.ScriptHashes.$key = $Hashes[$key]
    }

    Save-Config $config
}

function Get-FailCount {
    $val = Get-ItemProperty -Path $CounterPath -Name "Count" -ErrorAction SilentlyContinue
    if ($val) {
        return $val.Count
    }
    return 0
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
    if (-not (Test-Path $CounterPath)) {
        New-Item -Path $CounterPath -Force | Out-Null
    }
    Set-ItemProperty -Path $CounterPath -Name "Count" -Value 0

    # Script 1: Increment counter and check threshold on failed login
    $scriptFailPath = Join-Path $SecureDir "TamperGuard_OnFail.ps1"
    $scriptFailContent = @"
`$counterPath = '$CounterPath'
`$configPath = '$ConfigPath'
`$shutdownLog = '$ShutdownLogPath'
`$scriptKey = 'OnFail'

function Write-ShutdownLog {
    param([string]$Message)
    `$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "`$timestamp `$Message" | Out-File "$shutdownLog" -Append
}

if (-not (Test-Path `$configPath)) {
    Write-ShutdownLog "TamperGuard CONFIG MISSING - SECURITY ALERT"
    Stop-Computer -Force
}

`$scriptPath = `$MyInvocation.MyCommand.Path
`$config = if (Test-Path `$configPath) { Get-Content `$configPath -Raw | ConvertFrom-Json } else { $null }
`$maxAttempts = if (`$config -and `$config.MaxAttempts) { `$config.MaxAttempts } else { 3 }
`$expectedHash = if (`$config.ScriptHashes) { `$config.ScriptHashes.$scriptKey } else { $null }

if (-not `$expectedHash) {
    Write-ShutdownLog "TamperGuard MISSING HASH: `$scriptKey - BLOCKING EXECUTION"
    throw "TamperGuard hash not configured - refusing to run"
}

`$actualHash = (Get-FileHash -Algorithm SHA256 -Path `$scriptPath).Hash
if (`$actualHash -ne `$expectedHash) {
    Write-ShutdownLog "TamperGuard INTEGRITY FAILURE: `$scriptKey"
    throw "TamperGuard script hash mismatch"
}

`$mutexName = 'Global\TamperGuard_Counter'
`$mutex = New-Object System.Threading.Mutex($false, `$mutexName)
`$locked = $false
try {
    `$locked = `$mutex.WaitOne(5000)
    if (-not `$locked) {
        Write-ShutdownLog "TamperGuard LOCK TIMEOUT: `$scriptKey"
        throw "Unable to acquire TamperGuard counter lock"
    }

    # Increment counter
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

    # Check threshold
    if (`$count -ge `$maxAttempts) {
        # Log the shutdown reason
        Write-ShutdownLog "TAMPER DETECTED: `$count failed attempts - SHUTTING DOWN!"
        Start-Sleep -Milliseconds 100
        Stop-Computer -Force
    }
} finally {
    if (`$locked) {
        `$mutex.ReleaseMutex()
    }
    `$mutex.Dispose()
}
"@
    Set-Content -Path $scriptFailPath -Value $scriptFailContent

    # Script 2: Reset counter on successful unlock
    $scriptResetPath = Join-Path $SecureDir "TamperGuard_OnSuccess.ps1"
    $scriptResetContent = @"
`$counterPath = '$CounterPath'
`$configPath = '$ConfigPath'
`$shutdownLog = '$ShutdownLogPath'
`$scriptKey = 'OnSuccess'

function Write-ShutdownLog {
    param([string]$Message)
    `$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "`$timestamp `$Message" | Out-File "$shutdownLog" -Append
}

if (-not (Test-Path `$configPath)) {
    Write-ShutdownLog "TamperGuard CONFIG MISSING - SECURITY ALERT"
    Stop-Computer -Force
}

`$scriptPath = `$MyInvocation.MyCommand.Path
`$config = if (Test-Path `$configPath) { Get-Content `$configPath -Raw | ConvertFrom-Json } else { $null }
`$expectedHash = if (`$config.ScriptHashes) { `$config.ScriptHashes.$scriptKey } else { $null }

if (-not `$expectedHash) {
    Write-ShutdownLog "TamperGuard MISSING HASH: `$scriptKey - BLOCKING EXECUTION"
    throw "TamperGuard hash not configured - refusing to run"
}

`$actualHash = (Get-FileHash -Algorithm SHA256 -Path `$scriptPath).Hash
if (`$actualHash -ne `$expectedHash) {
    Write-ShutdownLog "TamperGuard INTEGRITY FAILURE: `$scriptKey"
    throw "TamperGuard script hash mismatch"
}

`$mutexName = 'Global\TamperGuard_Counter'
`$mutex = New-Object System.Threading.Mutex($false, `$mutexName)
`$locked = $false
try {
    `$locked = `$mutex.WaitOne(5000)
    if (-not `$locked) {
        Write-ShutdownLog "TamperGuard LOCK TIMEOUT: `$scriptKey"
        throw "Unable to acquire TamperGuard counter lock"
    }

    if (-not (Test-Path `$counterPath)) {
        New-Item -Path `$counterPath -Force | Out-Null
    }
    Set-ItemProperty -Path `$counterPath -Name 'Count' -Value 0
} finally {
    if (`$locked) {
        `$mutex.ReleaseMutex()
    }
    `$mutex.Dispose()
}
"@
    Set-Content -Path $scriptResetPath -Value $scriptResetContent

    # Script 3: Activate guard on workstation lock
    $scriptLockPath = Join-Path $SecureDir "TamperGuard_OnLock.ps1"
    $scriptLockContent = @"
`$counterPath = '$CounterPath'
`$configPath = '$ConfigPath'
`$shutdownLog = '$ShutdownLogPath'
`$scriptKey = 'OnLock'

function Write-ShutdownLog {
    param([string]$Message)
    `$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "`$timestamp `$Message" | Out-File "$shutdownLog" -Append
}

if (-not (Test-Path `$configPath)) {
    Write-ShutdownLog "TamperGuard CONFIG MISSING - SECURITY ALERT"
    Stop-Computer -Force
}

`$scriptPath = `$MyInvocation.MyCommand.Path
`$config = if (Test-Path `$configPath) { Get-Content `$configPath -Raw | ConvertFrom-Json } else { $null }
`$expectedHash = if (`$config.ScriptHashes) { `$config.ScriptHashes.$scriptKey } else { $null }

if (-not `$expectedHash) {
    Write-ShutdownLog "TamperGuard MISSING HASH: `$scriptKey - BLOCKING EXECUTION"
    throw "TamperGuard hash not configured - refusing to run"
}

`$actualHash = (Get-FileHash -Algorithm SHA256 -Path `$scriptPath).Hash
if (`$actualHash -ne `$expectedHash) {
    Write-ShutdownLog "TamperGuard INTEGRITY FAILURE: `$scriptKey"
    throw "TamperGuard script hash mismatch"
}

`$mutexName = 'Global\TamperGuard_Counter'
`$mutex = New-Object System.Threading.Mutex($false, `$mutexName)
`$locked = $false
try {
    `$locked = `$mutex.WaitOne(5000)
    if (-not `$locked) {
        Write-ShutdownLog "TamperGuard LOCK TIMEOUT: `$scriptKey"
        throw "Unable to acquire TamperGuard counter lock"
    }

    if (-not (Test-Path `$counterPath)) {
        New-Item -Path `$counterPath -Force | Out-Null
    }
    Set-ItemProperty -Path `$counterPath -Name 'Count' -Value 0
} finally {
    if (`$locked) {
        `$mutex.ReleaseMutex()
    }
    `$mutex.Dispose()
}
"@
    Set-Content -Path $scriptLockPath -Value $scriptLockContent

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
      <Command>powershell.exe</Command>
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
      <Command>powershell.exe</Command>
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
      <Command>powershell.exe</Command>
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
        $count = Read-Host "`nHow many recent attempts to show? (default 20)"
        if ([string]::IsNullOrWhiteSpace($count)) { $count = 20 }
        Show-FailedAttempts -Last ([int]$count)
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
