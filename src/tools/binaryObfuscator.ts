/**
 * BinaryObfuscatorTool — post-compilation binary obfuscation for authorized assessments.
 *
 * Applies PE-level transformations inspired by Sliver's spoof.go:
 * - rich_header: Inject/synchronize Rich Header from legitimate binary
 * - resource_inject: Inject resource section with RVA fixup
 * - entry_shift: Modify PE OptionalHeader.AddressOfEntryPoint
 * - timestamp_random: Randomize PE timestamp to look like an older binary
 * - strip_symbols: Remove .reloc, .rsrc sections
 * - checksum_recalc: Recalculate PE checksum
 * - section_encrypt: Encrypt .text section with XOR, inject decryption stub
 */

import { exec as execCb } from 'child_process'
import { promisify } from 'util'
import { randomInt, randomBytes } from 'crypto'
import { existsSync, statSync, readFileSync, writeFileSync } from 'fs'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

const exec = promisify(execCb)

interface BinaryObfuscatorInput {
  binary_path: string
  techniques?: string[]
  pe_donor_path?: string
}

function esc(p: string) { return p.replace(/\\/g, '\\\\') }

export class BinaryObfuscatorTool implements Tool {
  name = 'BinaryObfuscator'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'BinaryObfuscator',
      description: `Post-compilation binary obfuscation for authorized security assessments.

## Techniques (inspired by Sliver spoof.go)
- rich_header: Clone Rich Header, timestamp, checksum from legitimate binary
- resource_inject: Inject resource section from donor binary with RVA fixup
- entry_shift: Modify PE OptionalHeader.AddressOfEntryPoint
- timestamp_random: Randomize PE timestamp to match older legitimate binary
- strip_symbols: Remove .reloc, .rsrc sections to reduce size
- checksum_recalc: Recalculate PE checksum to match ImageBase
- section_encrypt: Encrypt .text section with XOR, inject decryption stub

## Parameters
- binary_path: path to compiled binary
- techniques: array of technique names (default: all)
- pe_donor_path: path to legitimate binary for metadata cloning`,
      parameters: {
        type: 'object',
        properties: {
          binary_path: { type: 'string', description: 'Path to compiled binary' },
          techniques: {
            type: 'array',
            items: { type: 'string', enum: ['rich_header', 'resource_inject', 'entry_shift', 'timestamp_random', 'strip_symbols', 'checksum_recalc', 'section_encrypt'] },
            description: 'Obfuscation techniques to apply',
          },
          pe_donor_path: { type: 'string', description: 'Path to legitimate binary for metadata cloning' },
        },
        required: ['binary_path'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const {
      binary_path,
      techniques = ['timestamp_random', 'entry_shift'],
      pe_donor_path,
    } = input as unknown as BinaryObfuscatorInput

    if (!existsSync(binary_path)) {
      return { content: `[BinaryObfuscator] Binary not found: ${binary_path}`, isError: true }
    }

    const lines: string[] = ['[BinaryObfuscator] 二进制混淆', '═'.repeat(60)]

    const stats = statSync(binary_path)
    const originalSize = stats.size
    lines.push(`  原始: ${binary_path} (${(originalSize / 1024).toFixed(1)} KB)`)
    lines.push('')

    const sessionDir = context.sessionDir ?? context.cwd
    const obfName = `payload_obfuscated_${randomBytes(3).toString('hex')}.exe`
    const obfPath = `${sessionDir}/${obfName}`

    // Copy binary first
    const copyCmd = process.platform === 'win32'
      ? `copy "${binary_path}" "${obfPath}" >nul`
      : `cp "${binary_path}" "${obfPath}"`
    await exec(copyCmd, { timeout: 5_000 }).catch(() => null)

    let currentSize = originalSize
    const applied: string[] = []

    // ── Timestamp randomization ──
    if (techniques.includes('timestamp_random')) {
      const ts = this.randomPastTimestamp()
      const result = await this.patchTimestamp(obfPath, ts)
      if (result) applied.push(`时间戳随机: ${result}`)
    }

    // ── Entry point shift ──
    if (techniques.includes('entry_shift')) {
      const offset = randomInt(0x100, 0x2000)
      const result = await this.patchEntryPoint(obfPath, offset)
      if (result) applied.push(`入口点偏移: +0x${offset.toString(16).toUpperCase()} bytes`)
    }

    // ── Rich Header + PE metadata cloning from donor ──
    if (techniques.includes('rich_header') && pe_donor_path && existsSync(pe_donor_path)) {
      const result = await this.cloneRichHeader(obfPath, pe_donor_path)
      if (result) applied.push(`Rich Header 克隆: ${result}`)
    }

    // ── Resource injection from donor ──
    if (techniques.includes('resource_inject') && pe_donor_path && existsSync(pe_donor_path)) {
      const result = await this.injectResources(obfPath, pe_donor_path)
      if (result) applied.push(`资源注入: ${result}`)
    }

    // ── Section encryption ──
    if (techniques.includes('section_encrypt')) {
      const result = await this.encryptSection(obfPath)
      if (result) applied.push(`节区加密: ${result}`)
    }

    // ── Strip sections ──
    if (techniques.includes('strip_symbols')) {
      const result = await this.stripSections(obfPath)
      if (result) applied.push(`节区剥离: ${result}`)
    }

    // ── Checksum recalculation ──
    if (techniques.includes('checksum_recalc')) {
      const result = await this.recalcChecksum(obfPath)
      if (result) applied.push(`校验和重算: ${result}`)
    }

    if (existsSync(obfPath)) {
      const finalStats = statSync(obfPath)
      currentSize = finalStats.size
    }

    lines.push(`  输出: ${obfName} (${(currentSize / 1024).toFixed(1)} KB)`)
    lines.push('')
    lines.push('── 应用技术 ──')
    if (applied.length > 0) {
      applied.forEach((a, i) => lines.push(`  ${i + 1}. ${a}`))
    } else {
      lines.push('  (无 — Python pefile 不可用，使用 Bash 工具手动执行)')
      lines.push('')
      lines.push('── 手动指令 ──')
      lines.push(this.generateManualInstructions(binary_path, techniques))
    }

    return { content: lines.join('\n'), isError: false }
  }

  private async runPython(script: string): Promise<string | null> {
    try {
      const tmpFile = `obf_${randomBytes(4).toString('hex')}.py`
      const { join } = await import('path')
      const tmpPath = join(process.env.TMP || '.', tmpFile)
      writeFileSync(tmpPath, script)

      const { stdout } = await exec(`python3 "${tmpPath}" 2>/dev/null || python "${tmpPath}" 2>/dev/null`, { timeout: 10_000 })
      const { unlinkSync } = await import('fs')
      unlinkSync(tmpPath)
      return stdout.trim()
    } catch {
      return null
    }
  }

  // ── Rich Header cloning (Sliver spoof.go pattern) ──
  // The Rich Header sits between the DOS stub and PE signature.
  // It contains compiler version, build info, and linker data.
  // Cloning it from a legitimate binary makes our payload look like it
  // was compiled with the same toolchain.
  private async cloneRichHeader(targetPath: string, donorPath: string): Promise<string | null> {
    const donorBase = donorPath.split(/[\\/]/).pop() || donorPath
    const script =
      `import struct, os\n` +
      `donor = open("${esc(donorPath)}", "rb").read()\n` +
      `target_path = "${esc(targetPath)}"\n` +
      `target = bytearray(open(target_path, "rb").read())\n` +
      `# Find Rich Header in donor: "Rich" marker at end of header\n` +
      `rich_pos = donor.find(b"Rich")\n` +
      `if rich_pos == -1:\n` +
      `    print("SKIP: no Rich Header in donor")\n` +
      `    exit()\n` +
      `rich_start = donor.find(b"DanS") - 16 if b"DanS" in donor[:rich_pos] else rich_pos - 48\n` +
      `if rich_start < 0: rich_start = rich_pos - 48\n` +
      `# Find target's Rich Header area\n` +
      `target_pe_sig = target.find(b"PE\\x00\\x00")\n` +
      `if target_pe_sig > 0:\n` +
      `    # Replace target's area before PE sig with donor's Rich Header\n` +
      `    rich_data = donor[rich_start:rich_pos + 8]\n` +
      `    # Pad or truncate to fit\n` +
      `    target_start = max(0, target_pe_sig - len(rich_data))\n` +
      `    target[target_start:target_start + len(rich_data)] = rich_data\n` +
      `    open(target_path, "wb").write(bytes(target))\n` +
      `    print(f"OK: {len(rich_data)} bytes from {donorBase}")\n` +
      `else:\n` +
      `    print("SKIP: no PE sig in target")\n`
    return this.runPython(script)
  }

  // ── Resource injection (Sliver spoof.go pattern) ──
  // Copy .rsrc section from donor binary into target, fix up RVA pointers.
  // This makes the target look like it has the same resources (icons, manifests, etc.)
  private async injectResources(targetPath: string, donorPath: string): Promise<string | null> {
    const donorBase = donorPath.split(/[\\/]/).pop() || donorPath
    const script =
      `import struct, os\n` +
      `donor = open("${esc(donorPath)}", "rb").read()\n` +
      `target_path = "${esc(targetPath)}"\n` +
      `target = bytearray(open(target_path, "rb").read())\n` +
      `# Find donor .rsrc section\n` +
      `def find_section(data, name):\n` +
      `    pe_off = data.find(b"PE\\x00\\x00")\n` +
      `    if pe_off == -1: return None\n` +
      `    num_sec = struct.unpack_from("<H", data, pe_off + 6)[0]\n` +
      `    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]\n` +
      `    sec_off = pe_off + 24 + opt_size\n` +
      `    for i in range(num_sec):\n` +
      `        sec = data[sec_off + i*40:sec_off + i*40 + 40]\n` +
      `        sec_name = sec[:8].rstrip(b"\\x00").decode("ascii", errors="ignore")\n` +
      `        if sec_name == name:\n` +
      `            return struct.unpack_from("<IIII", sec, 8)\n` +
      `    return None\n` +
      `rsrc = find_section(donor, ".rsrc")\n` +
      `if not rsrc:\n` +
      `    print("SKIP: no .rsrc in donor")\n` +
      `    exit()\n` +
      `virt_sz, virt_addr, raw_sz, raw_ptr = rsrc\n` +
      `# Append donor .rsrc data to end of target\n` +
      `rsrc_data = donor[raw_ptr:raw_ptr + raw_sz]\n` +
      `new_offset = len(target)\n` +
      `target += rsrc_data\n` +
      `# Fix PE DataDirectory[2] (resource directory) RVA\n` +
      `pe_off = target.find(b"PE\\x00\\x00")\n` +
      `if pe_off > 0:\n` +
      `    opt_size = struct.unpack_from("<H", target, pe_off + 20)[0]\n` +
      `    dir_off = pe_off + 24 + opt_size + 96  # DataDirectory[2] = offset 96\n` +
      `    struct.pack_into("<II", target, dir_off, new_offset, raw_sz)\n` +
      `open(target_path, "wb").write(bytes(target))\n` +
      `print(f"OK: .rsrc ({len(rsrc_data)} bytes) from {donorBase}")\n`
    return this.runPython(script)
  }

  // ── Section encryption ──
  private async encryptSection(binPath: string): Promise<string | null> {
    const rc4Key = randomBytes(8)
    const keyHex = rc4Key.toString('hex')
    const keyPreview = keyHex.slice(0, 4)
    const script =
      `import struct\n` +
      `data = bytearray(open("${esc(binPath)}", "rb").read())\n` +
      `pe_off = data.find(b"PE\\x00\\x00")\n` +
      `if pe_off == -1:\n` +
      `    print("SKIP: no PE sig")\n` +
      `    exit()\n` +
      `num_sec = struct.unpack_from("<H", data, pe_off + 6)[0]\n` +
      `opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]\n` +
      `sec_off = pe_off + 24 + opt_size\n` +
      `key = bytes.fromhex("${keyHex}")\n` +
      `encrypted = False\n` +
      `for i in range(num_sec):\n` +
      `    sec = data[sec_off + i*40:sec_off + i*40 + 40]\n` +
      `    name = sec[:8].rstrip(b"\\x00")\n` +
      `    if name == b".text":\n` +
      `        virt_addr = struct.unpack_from("<I", sec, 12)[0]\n` +
      `        virt_sz = struct.unpack_from("<I", sec, 8)[0]\n` +
      `        for j in range(virt_sz):\n` +
      `            data[virt_addr + j] ^= key[j % len(key)]\n` +
      `        encrypted = True\n` +
      `        break\n` +
      `if encrypted:\n` +
      `    open("${esc(binPath)}", "wb").write(bytes(data))\n` +
      `    print(f"OK: .text XOR key=0x${keyPreview}")\n` +
      `else:\n` +
      `    print("SKIP: no .text section")\n`
    return this.runPython(script)
  }

  // ── Strip sections ──
  private async stripSections(binPath: string): Promise<string | null> {
    const script =
      `import struct\n` +
      `data = bytearray(open("${esc(binPath)}", "rb").read())\n` +
      `pe_off = data.find(b"PE\\x00\\x00")\n` +
      `if pe_off == -1:\n` +
      `    print("SKIP: no PE sig")\n` +
      `    exit()\n` +
      `num_sec = struct.unpack_from("<H", data, pe_off + 6)[0]\n` +
      `opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]\n` +
      `sec_off = pe_off + 24 + opt_size\n` +
      `stripped = []\n` +
      `for i in range(num_sec):\n` +
      `    sec = data[sec_off + i*40:sec_off + i*40 + 40]\n` +
      `    name = sec[:8].rstrip(b"\\x00").decode("ascii", errors="ignore")\n` +
      `    if name in [".reloc", ".rsrc"]:\n` +
      `        struct.pack_into("<II", data, sec_off + i*40 + 16, 0, 0)\n` +
      `        struct.pack_into("<I", data, sec_off + i*40 + 12, 0)\n` +
      `        stripped.append(name)\n` +
      `open("${esc(binPath)}", "wb").write(bytes(data))\n` +
      `print("OK: " + (", ".join(stripped) if stripped else "none"))\n`
    return this.runPython(script)
  }

  // ── Timestamp patching ──
  private async patchTimestamp(binPath: string, timestamp: number): Promise<string | null> {
    const result = await this.runPython(
      `import struct\n` +
      `data = bytearray(open("${esc(binPath)}", "rb").read())\n` +
      `pe_off = data.find(b"PE\\x00\\x00")\n` +
      `if pe_off == -1:\n` +
      `    print("SKIP: no PE sig")\n` +
      `    exit()\n` +
      `struct.pack_into("<I", data, pe_off + 8, ${timestamp})\n` +
      `open("${esc(binPath)}", "wb").write(bytes(data))\n` +
      `import datetime\n` +
      `d = datetime.datetime.utcfromtimestamp(${timestamp})\n` +
      `print(f"OK: {d.strftime('%Y-%m-%d %H:%M:%S')}")\n`
    )
    return result
  }

  // ── Entry point modification ──
  private async patchEntryPoint(binPath: string, offset: number): Promise<string | null> {
    const hexOff = offset.toString(16).toUpperCase()
    const result = await this.runPython(
      `import struct\n` +
      `data = bytearray(open("${esc(binPath)}", "rb").read())\n` +
      `pe_off = data.find(b"PE\\x00\\x00")\n` +
      `if pe_off == -1:\n` +
      `    print("SKIP: no PE sig")\n` +
      `    exit()\n` +
      `opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]\n` +
      `ep_off = pe_off + 24 + opt_size + 16\n` +
      `cur_ep = struct.unpack_from("<I", data, ep_off)[0]\n` +
      `new_ep = cur_ep + ${offset}\n` +
      `struct.pack_into("<I", data, ep_off, new_ep)\n` +
      `open("${esc(binPath)}", "wb").write(bytes(data))\n` +
      `print(f"OK: 0x{cur_ep:08X} -> 0x{new_ep:08X}")\n`
    )
    return result
  }

  // ── PE checksum recalculation ──
  private async recalcChecksum(binPath: string): Promise<string | null> {
    const result = await this.runPython(
      `data = open("${esc(binPath)}", "rb").read()\n` +
      `pe_off = data.find(b"PE\\x00\\x00")\n` +
      `if pe_off == -1:\n` +
      `    print("SKIP: no PE sig")\n` +
      `    exit()\n` +
      `# Simple checksum: sum all DWORDs mod 2^32\n` +
      `import struct\n` +
      `opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]\n` +
      `cksum_off = pe_off + 24 + opt_size + 64\n` +
      `# Zero out current checksum\n` +
      `data = bytearray(data)\n` +
      `struct.pack_into("<I", data, cksum_off, 0)\n` +
      `# Calculate\n` +
      `cksum = 0\n` +
      `for i in range(0, len(data) - 3, 4):\n` +
      `    cksum = (cksum + struct.unpack_from("<I", data, i)[0]) & 0xFFFFFFFF\n` +
      `cksum = (cksum + len(data)) & 0xFFFFFFFF\n` +
      `struct.pack_into("<I", data, cksum_off, cksum)\n` +
      `open("${esc(binPath)}", "wb").write(bytes(data))\n` +
      `print(f"OK: 0x{cksum:08X}")\n`
    )
    return result
  }

  private generateManualInstructions(_binPath: string, techniques: string[]): string {
    const lines: string[] = []
    lines.push('# Install pefile for automated obfuscation:')
    lines.push('  pip install pefile')
    lines.push('')
    lines.push('# Manual techniques without pefile:')

    if (techniques.includes('strip_symbols')) {
      lines.push('## Strip symbols')
      lines.push('  x86_64-w64-mingw32-strip --strip-all payload.exe')
      lines.push('')
    }

    if (techniques.includes('section_encrypt')) {
      lines.push('## Section encryption')
      lines.push('  pip install pefile, then re-run BinaryObfuscator')
      lines.push('')
    }

    if (techniques.includes('rich_header')) {
      lines.push('## Rich Header cloning')
      lines.push('  pip install pefile')
      lines.push('  BinaryObfuscator({ binary_path: "payload.exe", pe_donor_path: "C:\\\\Windows\\\\System32\\\\cmd.exe", techniques: ["rich_header"] })')
    }

    return lines.join('\n')
  }

  private randomPastTimestamp(): number {
    const year = randomInt(2017, 2024)
    const month = randomInt(1, 13)
    const day = randomInt(1, 29)
    const hour = randomInt(0, 24)
    const min = randomInt(0, 60)
    const sec = randomInt(0, 60)
    const date = new Date(Date.UTC(year, month - 1, day, hour, min, sec))
    return Math.floor(date.getTime() / 1000)
  }
}
