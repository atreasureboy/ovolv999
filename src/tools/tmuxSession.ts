/**
 * TmuxSession — 交互式终端会话管理工具
 *
 * 解决"本地交互式进程（msfconsole / sqlmap / python REPL 等）无法程序化控制"的问题。
 * 传统 Bash 工具遇到交互式提示符会挂满超时。
 * TmuxSession 将进程运行在 tmux 后台会话中，通过 send-keys 注入输入，
 * 通过 capture-pane 捕获输出，用 wait_for 等待特定提示符出现。
 *
 * 典型流程（msfconsole）：
 *   1. TmuxSession({ action: "new", session: "msf", command: "msfconsole -q" })
 *   2. TmuxSession({ action: "wait_for", session: "msf", pattern: "msf6 >" })
 *   3. TmuxSession({ action: "send", session: "msf", text: "use exploit/multi/handler" })
 *   4. TmuxSession({ action: "send", session: "msf", text: "set PAYLOAD linux/x64/shell_reverse_tcp" })
 *   5. TmuxSession({ action: "send", session: "msf", text: "run -j" })
 *   6. TmuxSession({ action: "wait_for", session: "msf", pattern: "session \\d+ opened", timeout: 120000 })
 *   7. TmuxSession({ action: "send", session: "msf", text: "sessions -i 1 -C 'id'" })
 *   8. TmuxSession({ action: "capture", session: "msf", lines: 20 })
 */

import { exec as execCb } from 'child_process'
import { promisify } from 'util'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

const exec = promisify(execCb)

/** Run a tmux sub-command and return stdout+stderr */
async function tmux(args: string): Promise<string> {
  try {
    const { stdout, stderr } = await exec(`tmux ${args}`)
    return (stdout + stderr).trim()
  } catch (e: unknown) {
    const err = e as { stdout?: string; stderr?: string; message?: string }
    const out = ((err.stdout ?? '') + (err.stderr ?? '')).trim()
    throw new Error(out || err.message || String(e))
  }
}

/** Check if a tmux session exists */
async function sessionExists(name: string): Promise<boolean> {
  try {
    await exec(`tmux has-session -t ${shellEsc(name)} 2>/dev/null`)
    return true
  } catch {
    return false
  }
}

/** Shell-escape a single argument (wrap in single quotes, escape internal single quotes) */
function shellEsc(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`
}

/** Split text into ≤50-char chunks for safe send-keys paste */
function chunkText(text: string, size = 50): string[] {
  const chunks: string[] = []
  for (let i = 0; i < text.length; i += size) {
    chunks.push(text.slice(i, i + size))
  }
  return chunks
}

export class TmuxSessionTool implements Tool {
  name = 'TmuxSession'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'TmuxSession',
      description: `管理本地交互式终端会话（tmux），用于控制需要双向交互的进程（msfconsole、sqlmap、Python REPL 等）。

与 ShellSession 的区别：
- ShellSession 管理从目标机反弹来的 TCP 连接（入站 reverse shell）
- TmuxSession 管理本地交互式进程（本地进程 <-> AI 双向控制）

## 操作类型

| action    | 用途 |
|-----------|------|
| new       | 创建 tmux 后台会话，可指定初始命令（如 msfconsole -q） |
| send      | 向会话发送文本（自动追加 Enter），长文本自动分块防溢出 |
| keys      | 发送特殊按键（C-c / C-d / Escape / Enter 等） |
| capture   | 捕获会话当前屏幕或完整历史（最近 N 行） |
| wait_for  | 轮询直到输出匹配正则模式（等待提示符/关键字） |
| list      | 列出所有 tmux 会话 |
| kill      | 销毁指定会话 |

## 标准工作流

### msfconsole 交互
\`\`\`
TmuxSession({ action: "new", session: "msf", command: "msfconsole -q" })
TmuxSession({ action: "wait_for", session: "msf", pattern: "msf6 >" })
TmuxSession({ action: "send", session: "msf", text: "use exploit/multi/handler" })
TmuxSession({ action: "wait_for", session: "msf", pattern: "msf6.*handler" })
TmuxSession({ action: "send", session: "msf", text: "set PAYLOAD linux/x64/shell_reverse_tcp" })
TmuxSession({ action: "send", session: "msf", text: "set LHOST 0.0.0.0" })
TmuxSession({ action: "send", session: "msf", text: "set LPORT 4444" })
TmuxSession({ action: "send", session: "msf", text: "run -j" })
TmuxSession({ action: "wait_for", session: "msf", pattern: "session \\d+ opened", timeout: 120000 })
TmuxSession({ action: "send", session: "msf", text: "sessions -i 1 -C 'id; whoami; hostname'" })
TmuxSession({ action: "capture", session: "msf", lines: 30 })
\`\`\`

### Meterpreter 会话控制
\`\`\`
TmuxSession({ action: "send", session: "msf", text: "sessions -i 1" })
TmuxSession({ action: "wait_for", session: "msf", pattern: "meterpreter >" })
TmuxSession({ action: "send", session: "msf", text: "getuid" })
TmuxSession({ action: "capture", session: "msf", lines: 10 })
TmuxSession({ action: "keys", session: "msf", key: "C-z" })   # 后台挂起 meterpreter
\`\`\`

### 中断卡住的进程
\`\`\`
TmuxSession({ action: "keys", session: "msf", key: "C-c" })   # 中断当前命令
TmuxSession({ action: "capture", session: "msf", lines: 5 })  # 确认恢复到提示符
\`\`\``,
      parameters: {
        type: 'object',
        properties: {
          action: {
            type: 'string',
            enum: ['new', 'send', 'keys', 'capture', 'wait_for', 'list', 'kill'],
            description: '操作类型',
          },
          session: {
            type: 'string',
            description: '会话名称（new 时创建，其他时引用）。建议语义化命名：msf / sqlmap / shell-1',
          },
          command: {
            type: 'string',
            description: '(new) 会话启动后立即执行的命令，如 "msfconsole -q"。不填则创建空 shell',
          },
          text: {
            type: 'string',
            description: '(send) 要发送的文本，自动追加 Enter。长文本会自动分 50 字节块发送',
          },
          key: {
            type: 'string',
            description: '(keys) tmux 特殊按键名：C-c / C-d / Escape / Enter / Up / Down / Tab。支持多个用空格分隔',
          },
          lines: {
            type: 'number',
            description: '(capture) 返回最近 N 行输出，默认 50。设为 0 返回完整历史（可能很长）',
          },
          pattern: {
            type: 'string',
            description: '(wait_for) 等待匹配的正则表达式，如 "msf6 >" / "session \\\\d+ opened" / "\\\\$"',
          },
          timeout: {
            type: 'number',
            description: '(wait_for) 最长等待毫秒数，默认 30000。msfconsole 首次加载用 60000，等 session 用 120000',
          },
          interval: {
            type: 'number',
            description: '(wait_for) 轮询间隔毫秒数，默认 1000',
          },
        },
        required: ['action'],
      },
    },
  }

  async execute(input: Record<string, unknown>, _context: ToolContext): Promise<ToolResult> {
    switch (String(input.action)) {
      case 'new':      return this._new(input)
      case 'send':     return this._send(input)
      case 'keys':     return this._keys(input)
      case 'capture':  return this._capture(input)
      case 'wait_for': return this._waitFor(input)
      case 'list':     return this._list()
      case 'kill':     return this._kill(input)
      default:
        return { content: `Unknown action "${input.action}". Use: new | send | keys | capture | wait_for | list | kill`, isError: true }
    }
  }

  // ── new ───────────────────────────────────────────────────────────────────

  private async _new(input: Record<string, unknown>): Promise<ToolResult> {
    const name    = String(input.session ?? `ovo-${Date.now()}`)
    const command = input.command ? String(input.command) : ''

    if (await sessionExists(name)) {
      return { content: `Session "${name}" already exists. Use capture to check its state, or kill to recreate.`, isError: false }
    }

    try {
      if (command) {
        // new-session -d (detached), -s name, then run command in the shell
        await tmux(`new-session -d -s ${shellEsc(name)}`)
        await tmux(`send-keys -t ${shellEsc(name)} ${shellEsc(command)} Enter`)
      } else {
        await tmux(`new-session -d -s ${shellEsc(name)}`)
      }

      return {
        content: [
          `[TmuxSession] Session "${name}" created.`,
          command ? `Running: ${command}` : 'Empty shell ready.',
          ``,
          `Next steps:`,
          `  TmuxSession({ action: "capture", session: "${name}", lines: 20 })         # check current output`,
          command ? `  TmuxSession({ action: "wait_for", session: "${name}", pattern: "..." })  # wait for prompt` : '',
          `  TmuxSession({ action: "send", session: "${name}", text: "your command" })  # send input`,
        ].filter(Boolean).join('\n'),
        isError: false,
      }
    } catch (e) {
      return { content: `Failed to create session "${name}": ${(e as Error).message}`, isError: true }
    }
  }

  // ── send ──────────────────────────────────────────────────────────────────

  private async _send(input: Record<string, unknown>): Promise<ToolResult> {
    const name = String(input.session ?? '')
    const text = String(input.text ?? '')

    if (!name) return { content: 'Error: session is required for send', isError: true }
    if (!text) return { content: 'Error: text is required for send', isError: true }

    if (!await sessionExists(name)) {
      return { content: `Session "${name}" not found. Use: TmuxSession({ action: "list" })`, isError: true }
    }

    try {
      // Split into chunks to avoid paste overflow
      const chunks = chunkText(text)
      for (const chunk of chunks) {
        await tmux(`send-keys -t ${shellEsc(name)} -l -- ${shellEsc(chunk)}`)
      }
      // Send Enter separately
      await tmux(`send-keys -t ${shellEsc(name)} Enter`)

      return {
        content: `Sent to "${name}": ${text.length > 80 ? text.slice(0, 80) + '…' : text}\nUse capture to see output.`,
        isError: false,
      }
    } catch (e) {
      return { content: `Failed to send to "${name}": ${(e as Error).message}`, isError: true }
    }
  }

  // ── keys ──────────────────────────────────────────────────────────────────

  private async _keys(input: Record<string, unknown>): Promise<ToolResult> {
    const name = String(input.session ?? '')
    const key  = String(input.key ?? '')

    if (!name) return { content: 'Error: session is required for keys', isError: true }
    if (!key)  return { content: 'Error: key is required for keys (e.g. C-c, C-d, Escape, Enter)', isError: true }

    if (!await sessionExists(name)) {
      return { content: `Session "${name}" not found. Use: TmuxSession({ action: "list" })`, isError: true }
    }

    try {
      await tmux(`send-keys -t ${shellEsc(name)} ${key}`)
      return { content: `Sent key "${key}" to "${name}".`, isError: false }
    } catch (e) {
      return { content: `Failed to send keys to "${name}": ${(e as Error).message}`, isError: true }
    }
  }

  // ── capture ───────────────────────────────────────────────────────────────

  private async _capture(input: Record<string, unknown>): Promise<ToolResult> {
    const name  = String(input.session ?? '')
    const lines = input.lines !== undefined ? Number(input.lines) : 50

    if (!name) return { content: 'Error: session is required for capture', isError: true }

    if (!await sessionExists(name)) {
      return { content: `Session "${name}" not found. Use: TmuxSession({ action: "list" })`, isError: true }
    }

    try {
      let output: string
      if (lines === 0) {
        // Full history
        output = await tmux(`capture-pane -t ${shellEsc(name)} -p -S -`)
      } else {
        // Last N lines — capture only what we need (avoid pulling full history)
        output = await tmux(`capture-pane -t ${shellEsc(name)} -p -S -${lines}`)
      }

      return {
        content: output.trim() || '(no output)',
        isError: false,
      }
    } catch (e) {
      return { content: `Failed to capture "${name}": ${(e as Error).message}`, isError: true }
    }
  }

  // ── wait_for ──────────────────────────────────────────────────────────────

  private async _waitFor(input: Record<string, unknown>): Promise<ToolResult> {
    const name     = String(input.session ?? '')
    const pattern  = String(input.pattern ?? '')
    const timeout  = Number(input.timeout  ?? 30_000)
    const interval = Number(input.interval ?? 1_000)

    if (!name)    return { content: 'Error: session is required for wait_for', isError: true }
    if (!pattern) return { content: 'Error: pattern is required for wait_for', isError: true }

    if (!await sessionExists(name)) {
      return { content: `Session "${name}" not found. Use: TmuxSession({ action: "list" })`, isError: true }
    }

    let regex: RegExp
    try {
      regex = new RegExp(pattern)
    } catch {
      return { content: `Invalid regex pattern: "${pattern}"`, isError: true }
    }

    const deadline = Date.now() + timeout
    let lastOutput = ''

    while (Date.now() < deadline) {
      try {
        const raw = await tmux(`capture-pane -t ${shellEsc(name)} -p -S -`)
        lastOutput = raw

        if (regex.test(raw)) {
          // Return last 30 lines as context
          const lines = raw.split('\n').slice(-30).join('\n')
          return {
            content: `[wait_for] Pattern "${pattern}" matched.\n\n${lines.trim()}`,
            isError: false,
          }
        }
      } catch (e) {
        return { content: `Error polling "${name}": ${(e as Error).message}`, isError: true }
      }

      await new Promise(r => setTimeout(r, interval))
    }

    // Timeout — return last output for diagnosis
    const lastLines = lastOutput.split('\n').slice(-20).join('\n')
    return {
      content: [
        `[wait_for] Timeout after ${timeout}ms waiting for pattern "${pattern}" in session "${name}".`,
        ``,
        `Last output:`,
        lastLines.trim() || '(empty)',
        ``,
        `Troubleshooting:`,
        `  • Use capture to see full state: TmuxSession({ action: "capture", session: "${name}", lines: 50 })`,
        `  • If process is stuck, send Ctrl+C: TmuxSession({ action: "keys", session: "${name}", key: "C-c" })`,
        `  • Adjust pattern — it may be different from expected`,
      ].join('\n'),
      isError: true,
    }
  }

  // ── list ──────────────────────────────────────────────────────────────────

  private async _list(): Promise<ToolResult> {
    try {
      const output = await tmux('list-sessions')
      if (!output) {
        return { content: 'No active tmux sessions.\nCreate one: TmuxSession({ action: "new", session: "msf", command: "msfconsole -q" })', isError: false }
      }
      return { content: `Active tmux sessions:\n${output}`, isError: false }
    } catch {
      return { content: 'No active tmux sessions (tmux server not running).\nCreate one: TmuxSession({ action: "new", session: "msf", command: "msfconsole -q" })', isError: false }
    }
  }

  // ── kill ──────────────────────────────────────────────────────────────────

  private async _kill(input: Record<string, unknown>): Promise<ToolResult> {
    const name = String(input.session ?? '')
    if (!name) return { content: 'Error: session is required for kill', isError: true }

    if (!await sessionExists(name)) {
      return { content: `Session "${name}" not found.`, isError: true }
    }

    try {
      await tmux(`kill-session -t ${shellEsc(name)}`)
      return { content: `Session "${name}" killed.`, isError: false }
    } catch (e) {
      return { content: `Failed to kill "${name}": ${(e as Error).message}`, isError: true }
    }
  }
}
