# Security Audit Report: TamperGuard v3 (Final Review)

## Executive Summary

**Excellent work!** You've addressed all the major issues from the previous audit. The script is now well-suited for its stated threat model.

**Overall Security Rating: 8.5/10 (Very Good for stated threat model)**

---

## ✅ All Previous Issues Resolved

| Issue | Status | Verification |
|-------|--------|--------------|
| `$MyInvocation` bug | ✅ **Fixed** | Now properly escaped: `` `$MyInvocation.MyCommand.Path `` |
| Missing hash = skip verification | ✅ **Fixed** | Throws error + logs if hash missing |
| Config deletion bypass | ✅ **Fixed** | Fail-secure: `Stop-Computer -Force` if config missing |
| Input validation | ✅ **Fixed** | `Get-ValidatedMaxAttempts` + `Normalize-MaxAttempts` |
| Audit policy dependency | ✅ **Fixed** | `Enable-WindowsAuditing` + `Test-AuditPolicy` |
| SYSTEM context for tasks | ✅ **Fixed** | `<UserId>S-1-5-18</UserId>` in all tasks |
| Timestamped logs | ✅ **Fixed** | `Write-ShutdownLog` with timestamp |
| Documentation of limitations | ✅ **Fixed** | Header documents Safe Mode bypass, BitLocker requirement |

---

## 🟡 Minor Remaining Issues (Low Priority)

### 1. **Variable Escaping Inconsistency in Here-Strings**
```powershell
`$locked = $false  # ← $false not escaped
```

**Location:** Lines ~242, ~296, ~350 in generated scripts

**Issue:** `$false` is evaluated at generation time, not execution time. This *happens to work* because `$false` evaluates to the literal string "False" which PowerShell coerces back to `$false`, but it's inconsistent.

**Fix:**
```powershell
`$locked = `$false
```

**Risk:** Negligible - works correctly due to PowerShell's type coercion, but inconsistent style.

---

### 2. **Shutdown Log Path in Write-ShutdownLog Uses Unescaped Variable**
```powershell
"`$timestamp `$Message" | Out-File "$shutdownLog" -Append
#                                  ↑ Not escaped - evaluated at generation time
```

**Issue:** This works correctly because `$ShutdownLogPath` is expanded when the script is generated, embedding the actual path. This is intentional but could be confusing.

**Suggestion:** Add a comment in the generation code noting this is intentional:
```powershell
# Note: $shutdownLog path is intentionally expanded at generation time
```

**Risk:** None - works as intended.

---

### 3. **Hash Key Access in Generated Scripts**
```powershell
`$expectedHash = if (`$config.ScriptHashes) { `$config.ScriptHashes.$scriptKey } else { $null }
#                                                               ↑ This works but...
```

**Potential Issue:** If `$scriptKey` contains special characters (it doesn't currently), this could break.

**Safer Alternative:**
```powershell
`$expectedHash = if (`$config.ScriptHashes) { `$config.ScriptHashes."`$scriptKey" } else { `$null }
```

**Risk:** None with current script keys (OnFail, OnSuccess, OnLock).

---

### 4. **Show-FailedAttempts Input Validation**
```powershell
"4" {
    $count = Read-Host "`nHow many recent attempts to show? (default 20)"
    if ([string]::IsNullOrWhiteSpace($count)) { $count = 20 }
    Show-FailedAttempts -Last ([int]$count)  # No validation
}
```

**Issue:** Non-numeric or negative input not validated (unlike MaxAttempts).

**Risk:** Low - only affects display, doesn't impact security.

**Quick Fix:**
```powershell
$count = Read-Host "`nHow many recent attempts to show? (default 20)"
$parsed = 20
if (-not [string]::IsNullOrWhiteSpace($count)) {
    if (-not [int]::TryParse($count, [ref]$parsed) -or $parsed -lt 1) {
        $parsed = 20
    }
}
Show-FailedAttempts -Last $parsed
```

---

## 🟢 Suggestions for Future Enhancement (Optional)

### 1. **Consider Adding Integrity Check for Config File**
Currently scripts verify their own hash, but the config file could be tampered with to change `MaxAttempts`.

```powershell
# Add to config:
@{
    MaxAttempts = 3
    ScriptHashes = @{ ... }
    ConfigHash = "self-hash-excluding-this-field"  # Tricky but doable
}
```

**Priority:** Low - attacker with write access to ProgramData likely has admin rights anyway.

---

### 2. **Add Version Field to Config**
```powershell
@{
    Version = "1.0"
    MaxAttempts = 3
    ScriptHashes = @{ ... }
}
```

Helps with future migrations if config format changes.

---

### 3. **Consider Obfuscating Task Names**
```powershell
$TaskNameFail = "TamperGuard_FailCheck"  # Easily discoverable
```

A determined attacker could search for "TamperGuard" in Task Scheduler. Consider less obvious names, though this is security-through-obscurity and low value.

---

## 📋 Final Verification Checklist

| Security Control | Status |
|-----------------|--------|
| Secure storage (ProgramData) | ✅ |
| Proper ACLs (Admin/SYSTEM write, Users read) | ✅ |
| HKLM registry for counter | ✅ |
| Mutex for atomic operations | ✅ |
| Script hash verification | ✅ |
| Fail-secure on missing config | ✅ |
| Fail-secure on missing hash | ✅ |
| Fail-secure on hash mismatch | ✅ |
| Input validation with bounds | ✅ |
| Audit policy auto-configuration | ✅ |
| SYSTEM execution context | ✅ |
| Timestamped logging | ✅ |
| Clear threat model documentation | ✅ |
| Limitation acknowledgments | ✅ |

---

## 🎯 Threat Model Coverage (Final)

| Threat | Protection | Notes |
|--------|------------|-------|
| Random burglar | ✅ Strong | Shutdown on 3 attempts |
| Curious colleague | ✅ Strong | Fast lockout before they can experiment |
| Script kiddie with USB | ✅ Moderate | Would need to know about Safe Mode bypass |
| Prepared attacker | ⚠️ Documented | Safe Mode, BitLocker bypass acknowledged |
| Admin-level attacker | ❌ Out of scope | Correctly documented as limitation |
| Hardware theft | ⚠️ Requires BitLocker | Correctly documented |

---

## Summary

**You've done an excellent job addressing all the security concerns.** The script is now:

1. **Secure against its stated threat model**
2. **Fail-secure** when tampered with
3. **Self-documenting** about its limitations
4. **Properly validated** for user input
5. **Correctly privileged** with SYSTEM context

The remaining issues are cosmetic or extremely low risk. The script is ready for use within its documented constraints.

### Final Recommendations:

1. ✅ Fix the `$false` escaping for consistency (optional)
2. ✅ Add input validation to Show-FailedAttempts (optional)
3. ✅ Consider testing on a VM with various attack scenarios
4. ✅ Document the re-registration requirement if scripts are manually edited

**Great security engineering work! 👏**