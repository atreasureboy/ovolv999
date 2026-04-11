/**
 * Terminal UI Renderer — pure process.stdout.write, zero UI frameworks
 *
 * Visual design:
 * - OVOGO ASCII art banner at startup
 * - Colored left-border stripes per section type
 * - Gradient-style separators
 * - ✻ spinner with rotating verbs during thinking
 * - Tool call boxes with per-tool color coding
 *
 * Supports writing to a custom stream (e.g. a file WriteStream for sub-agent panes).
 * Use Renderer.forFile(path) to create a file-backed renderer.
 */

import { createWriteStream } from 'fs'
import type { WriteStream } from 'fs'

// ─────────────────────────────────────────────────────────────
// ANSI helpers
// ─────────────────────────────────────────────────────────────

const ESC = '\x1b['
const RESET = '\x1b[0m'
const BOLD = '\x1b[1m'
const DIM = '\x1b[2m'
const ITALIC = '\x1b[3m'

// Foreground colors
const FG = {
  black: `${ESC}30m`,
  red: `${ESC}31m`,
  green: `${ESC}32m`,
  yellow: `${ESC}33m`,
  blue: `${ESC}34m`,
  magenta: `${ESC}35m`,
  cyan: `${ESC}36m`,
  white: `${ESC}37m`,
  brightBlack: `${ESC}90m`,
  brightRed: `${ESC}91m`,
  brightGreen: `${ESC}92m`,
  brightYellow: `${ESC}93m`,
  brightBlue: `${ESC}94m`,
  brightMagenta: `${ESC}95m`,
  brightCyan: `${ESC}96m`,
  brightWhite: `${ESC}97m`,
}

// Background colors (subtle tints for stripe accents)
const BG = {
  blue: `${ESC}44m`,
  magenta: `${ESC}45m`,
}

// Cursor
const CURSOR = {
  up: (n: number) => `${ESC}${n}A`,
  down: (n: number) => `${ESC}${n}B`,
  col: (n: number) => `${ESC}${n}G`,
  save: `${ESC}s`,
  restore: `${ESC}u`,
  hide: `${ESC}?25l`,
  show: `${ESC}?25h`,
  clearLine: `${ESC}2K`,
  clearToEnd: `${ESC}0K`,
}

// ─────────────────────────────────────────────────────────────
// OVOGO ASCII art logo (block font)
// ─────────────────────────────────────────────────────────────

const LOGO_LINES = [
  ' ██████╗ ██╗   ██╗ ██████╗  ██████╗  ██████╗ ',
  '██╔═══██╗██║   ██║██╔═══██╗██╔════╝ ██╔═══██╗',
  '██║   ██║╚██╗ ██╔╝██║   ██║██║  ███╗██║   ██║',
  '╚██████╔╝ ╚████╔╝ ╚██████╔╝╚██████╔╝╚██████╔╝',
  ' ╚═════╝   ╚═══╝   ╚═════╝  ╚═════╝  ╚═════╝ ',
]

// ─────────────────────────────────────────────────────────────
// Spinner frames (Braille Unicode)
// ─────────────────────────────────────────────────────────────

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

// Verbs for spinner animation
export const SPINNER_VERBS = [
  'Accomplishing',
  'Architecting',
  'Baking',
  'Calculating',
  'Cerebrating',
  'Cogitating',
  'Composing',
  'Computing',
  'Concocting',
  'Considering',
  'Crafting',
  'Crunching',
  'Crystallizing',
  'Deliberating',
  'Determining',
  'Distilling',
  'Elaborating',
  'Engineering',
  'Examining',
  'Executing',
  'Exploring',
  'Figuring',
  'Generating',
  'Hatching',
  'Implementing',
  'Inferring',
  'Initializing',
  'Innovating',
  'Mulling',
  'Noodling',
  'Orchestrating',
  'Pondering',
  'Processing',
  'Reasoning',
  'Ruminating',
  'Sautéing',
  'Scheming',
  'Solving',
  'Synthesizing',
  'Thinking',
  'Transmuting',
  'Vibing',
  'Wrangling',
]

// ─────────────────────────────────────────────────────────────
// Word wrap utility
// ─────────────────────────────────────────────────────────────

export function wrapText(text: string, width: number, indent = ''): string {
  if (!text) return ''
  const lines: string[] = []
  const paragraphs = text.split('\n')
  for (const paragraph of paragraphs) {
    if (!paragraph.trim()) {
      lines.push('')
      continue
    }
    const words = paragraph.split(' ')
    let line = indent
    for (const word of words) {
      if (line.length + word.length + 1 > width && line.trim()) {
        lines.push(line.trimEnd())
        line = indent + word + ' '
      } else {
        line += word + ' '
      }
    }
    if (line.trim()) lines.push(line.trimEnd())
  }
  return lines.join('\n')
}

// ─────────────────────────────────────────────────────────────
// Stripe helpers — colored left-border per section type
// ─────────────────────────────────────────────────────────────

// Heavy vertical bar for emphasis sections
const STRIPE = {
  user: `${FG.brightBlue}│${RESET}`,
  assistant: `${FG.brightCyan}│${RESET}`,
  tool: `${FG.brightYellow}┃${RESET}`,
  result: `${FG.brightGreen}│${RESET}`,
  error: `${FG.brightRed}│${RESET}`,
  agent: `${FG.brightMagenta}│${RESET}`,
  compact: `${FG.yellow}│${RESET}`,
}

// ─────────────────────────────────────────────────────────────
// Renderer class
// ─────────────────────────────────────────────────────────────

export class Renderer {
  private spinnerInterval: NodeJS.Timeout | null = null
  private spinnerFrame = 0
  private spinnerVerbIndex = 0
  private spinnerVerbRotateCounter = 0
  private lastSpinnerLineLen = 0
  private termWidth: number
  private _assistantLineStarted = false

  /** Instance-level write function — routes to stdout or a file stream */
  private write: (s: string) => void
  /** Whether the output stream is a real TTY (affects spinner, cursor codes) */
  private isTTY: boolean

  constructor(options?: { stream?: NodeJS.WritableStream }) {
    const stream = options?.stream ?? process.stdout
    this.write = (s: string) => { stream.write(s) }
    this.isTTY = (stream as NodeJS.WriteStream).isTTY === true
    this.termWidth = this.isTTY ? ((stream as NodeJS.WriteStream).columns ?? 80) : 80
    if (this.isTTY) {
      (stream as NodeJS.WriteStream).on?.('resize', () => {
        this.termWidth = (stream as NodeJS.WriteStream).columns ?? 80
      })
    }
  }

  /**
   * Create a renderer that writes to a log file.
   * Ideal for sub-agent panes in tmux 4-grid layout.
   * ANSI escape codes are preserved so tmux pane `tail -f` renders color.
   */
  static forFile(filePath: string): Renderer {
    const fileStream = createWriteStream(filePath, { flags: 'a' }) as unknown as NodeJS.WritableStream
    return new Renderer({ stream: fileStream })
  }

  // ── Banner ───────────────────────────────────────────────────

  banner(version: string, model: string): void {
    const barWidth = Math.min(this.termWidth - 4, 48)
    const bar = `${FG.brightBlack}${'━'.repeat(barWidth)}${RESET}`

    this.write('\n')
    for (const line of LOGO_LINES) {
      this.write(`  ${FG.brightMagenta}${BOLD}${line}${RESET}\n`)
    }
    this.write('\n')
    this.write(`  ${bar}\n`)
    this.write(
      `  ${DIM}version${RESET} ${FG.brightWhite}${version}${RESET}` +
        `   ${DIM}model${RESET} ${FG.brightCyan}${model}${RESET}\n`,
    )
    this.write(`  ${bar}\n`)
    this.write('\n')
  }

  // ── Section separator — gradient style ───────────────────────

  separator(): void {
    const innerWidth = Math.min(this.termWidth - 10, 68)
    const mid = `${DIM}${'─'.repeat(innerWidth)}${RESET}`
    const cap = `${FG.brightBlack}▒${RESET}`
    this.write(`\n  ${cap}${mid}${cap}\n`)
  }

  // ── Human message — blue framed box with stripe ──────────────

  humanPrompt(text: string): void {
    const innerWidth = Math.min(this.termWidth - 8, 72)
    const topBar = `${FG.brightBlue}╭${'─'.repeat(innerWidth)}╮${RESET}`
    const botBar = `${FG.brightBlue}╰${'─'.repeat(innerWidth)}╯${RESET}`

    this.write('\n')
    this.write(`  ${topBar}\n`)

    const lines = text.split('\n')
    for (const line of lines) {
      const content = `${FG.brightBlue}❯${RESET} ${BOLD}${FG.brightWhite}${line}${RESET}`
      this.write(`  ${FG.brightBlue}│${RESET} ${content}\n`)
    }

    this.write(`  ${botBar}\n`)
  }

  // ── Assistant text output (non-streaming) ────────────────────

  assistantText(text: string): void {
    const width = Math.min(this.termWidth - 8, 96)
    const lines = wrapText(text, width).split('\n')
    this.write('\n')
    for (const line of lines) {
      this.write(`  ${STRIPE.assistant} ${line}\n`)
    }
  }

  // ── Streaming text output ────────────────────────────────────

  private streamingActive = false

  beginAssistantText(): void {
    this.streamingActive = true
    this._assistantLineStarted = false
    this.write('\n')
  }

  streamToken(token: string): void {
    if (!this.streamingActive) {
      this.beginAssistantText()
    }
    if (!this._assistantLineStarted) {
      this.write(`  ${STRIPE.assistant} `)
      this._assistantLineStarted = true
    }
    // After each newline, re-emit the left stripe prefix
    const indented = token.replace(/\n/g, `\n  ${STRIPE.assistant} `)
    this.write(indented)
  }

  endAssistantText(): void {
    if (this.streamingActive) {
      this.write('\n')
      this.streamingActive = false
      this._assistantLineStarted = false
    }
  }

  // ── Tool call display ─────────────────────────────────────────
  // Yellow stripe for tool invocations, per-tool color for name

  toolStart(toolName: string, input: Record<string, unknown>): void {
    const preview = this.formatToolPreview(toolName, input)
    const nameColor = this.toolColor(toolName)
    this.write(
      `\n  ${STRIPE.tool}  ${BOLD}${nameColor}${toolName}${RESET}` +
        `  ${FG.brightBlack}${preview}${RESET}\n`,
    )
  }

  toolResult(toolName: string, result: string, isError: boolean): void {
    const stripe = isError ? STRIPE.error : STRIPE.result
    const maxPreview = 300
    const truncated =
      result.length > maxPreview
        ? result.slice(0, maxPreview) + `\n… (${result.length - maxPreview} more chars)`
        : result

    if (isError) {
      this.write(`  ${stripe}  ${FG.brightRed}${truncated}${RESET}\n`)
      return
    }

    const lines = truncated.split('\n')
    const shown = lines.slice(0, 8)
    const hidden = lines.length - shown.length

    for (const line of shown) {
      this.write(`  ${stripe}  ${DIM}${line}${RESET}\n`)
    }
    if (hidden > 0) {
      this.write(`  ${stripe}  ${DIM}… ${hidden} more line${hidden !== 1 ? 's' : ''}${RESET}\n`)
    }
  }

  private toolColor(name: string): string {
    const colors: Record<string, string> = {
      Bash: FG.brightYellow,
      Read: FG.brightCyan,
      Write: FG.brightGreen,
      Edit: FG.brightBlue,
      Glob: FG.brightMagenta,
      Grep: FG.brightMagenta,
      WebFetch: FG.cyan,
      WebSearch: FG.cyan,
      TodoWrite: FG.brightGreen,
      Agent: FG.brightMagenta,
    }
    return colors[name] ?? FG.white
  }

  private formatToolPreview(toolName: string, input: Record<string, unknown>): string {
    switch (toolName) {
      case 'Bash': {
        const cmd = String(input.command ?? '').trim()
        return cmd.length > 80 ? cmd.slice(0, 77) + '…' : cmd
      }
      case 'Read': {
        const fp = String(input.file_path ?? '')
        const offset = input.offset ? ` +${input.offset}` : ''
        return fp + offset
      }
      case 'Write': {
        const fp = String(input.file_path ?? '')
        const content = String(input.content ?? '')
        const lines = content.split('\n').length
        return `${fp}  (${lines} lines)`
      }
      case 'Edit': {
        const fp = String(input.file_path ?? '')
        const old = String(input.old_string ?? '').split('\n')[0]?.slice(0, 40) ?? ''
        return `${fp}  "${old}…"`
      }
      case 'Glob': {
        const pattern = String(input.pattern ?? '')
        const path = input.path ? ` in ${input.path}` : ''
        return `${pattern}${path}`
      }
      case 'Grep': {
        const pattern = String(input.pattern ?? '')
        const glob = input.glob ? ` [${input.glob}]` : ''
        return `/${pattern}/${glob}`
      }
      default:
        return JSON.stringify(input).slice(0, 80)
    }
  }

  // ── Spinner ───────────────────────────────────────────────────

  startSpinner(initialVerb?: string): void {
    if (!this.isTTY) return
    if (this.spinnerInterval) this.stopSpinner()

    this.spinnerVerbIndex = Math.floor(Math.random() * SPINNER_VERBS.length)
    this.spinnerVerbRotateCounter = 0
    if (initialVerb) {
      const idx = SPINNER_VERBS.findIndex((v) =>
        v.toLowerCase().startsWith(initialVerb.toLowerCase()),
      )
      if (idx !== -1) this.spinnerVerbIndex = idx
    }

    this.write(CURSOR.hide)
    this.renderSpinner()

    this.spinnerInterval = setInterval(() => {
      this.spinnerFrame = (this.spinnerFrame + 1) % SPINNER_FRAMES.length
      this.spinnerVerbRotateCounter++
      if (this.spinnerVerbRotateCounter >= 24) {
        this.spinnerVerbRotateCounter = 0
        this.spinnerVerbIndex = (this.spinnerVerbIndex + 1) % SPINNER_VERBS.length
      }
      this.renderSpinner()
    }, 50)
  }

  private renderSpinner(): void {
    if (!this.isTTY) return
    const frame = SPINNER_FRAMES[this.spinnerFrame]
    const verb = SPINNER_VERBS[this.spinnerVerbIndex]
    const line =
      `  ${FG.brightMagenta}${frame}${RESET} ` +
      `${FG.brightBlack}${verb}${RESET}${FG.brightBlack}…${RESET}`
    this.write(CURSOR.col(1) + CURSOR.clearToEnd + line)
    this.lastSpinnerLineLen = line.replace(/\x1b\[[^m]*m/g, '').length
  }

  stopSpinner(): void {
    if (!this.spinnerInterval) return
    clearInterval(this.spinnerInterval)
    this.spinnerInterval = null
    if (this.isTTY) {
      this.write(CURSOR.col(1) + CURSOR.clearLine + CURSOR.show)
    }
    this.lastSpinnerLineLen = 0
  }

  // ── Status / info messages ────────────────────────────────────

  info(msg: string): void {
    this.write(`  ${DIM}${msg}${RESET}\n`)
  }

  success(msg: string): void {
    this.write(`  ${FG.brightGreen}✓${RESET} ${msg}\n`)
  }

  error(msg: string): void {
    this.write(`  ${FG.brightRed}✗${RESET} ${FG.red}${msg}${RESET}\n`)
  }

  warn(msg: string): void {
    this.write(`  ${FG.yellow}⚠${RESET} ${FG.yellow}${msg}${RESET}\n`)
  }

  // ── Sub-agent display ─────────────────────────────────────────

  agentStart(description: string, agentType = 'general-purpose'): void {
    const typeLabel = agentType !== 'general-purpose' ? `  ${FG.brightBlack}[${agentType}]${RESET}` : ''
    this.write(`\n  ${STRIPE.agent}  ${BOLD}${FG.brightMagenta}⎇ Agent${RESET}${typeLabel}  ${DIM}${description}${RESET}\n`)
  }

  agentDone(description: string, success: boolean): void {
    const icon = success ? `${FG.brightGreen}✓${RESET}` : `${FG.brightRed}✗${RESET}`
    this.write(`  ${STRIPE.agent}  ${icon} ${DIM}Agent "${description}" done${RESET}\n`)
  }

  /**
   * Print a brief summary of a completed sub-agent in the main terminal.
   * Shows the first few lines of the agent's output so the user can see
   * progress without switching to the tmux window.
   */
  agentSummary(agentType: string, description: string, summary: string): void {
    const header = `  ${STRIPE.agent}  ${BOLD}${FG.brightMagenta}[${agentType}]${RESET} ${DIM}${description}${RESET}\n`
    const body = summary
      .split('\n')
      .map(line => `  ${STRIPE.agent}    ${DIM}${line}${RESET}`)
      .join('\n')
    this.write(`${header}${body}\n`)
  }

  /** Show plan mode banner before a plan run */
  planModeStart(): void {
    this.write(
      `\n  ${FG.brightBlue}┌${'─'.repeat(50)}┐${RESET}\n` +
      `  ${FG.brightBlue}│${RESET}  ${BOLD}${FG.brightCyan}✦ PLAN MODE${RESET}  ${DIM}(read-only analysis)${RESET}` +
      `${' '.repeat(17)}${FG.brightBlue}│${RESET}\n` +
      `  ${FG.brightBlue}└${'─'.repeat(50)}┘${RESET}\n`,
    )
  }

  /** Ask the user to confirm plan execution, returns the raw line */
  planConfirmPrompt(): void {
    this.write(`\n  ${FG.brightYellow}?${RESET} Proceed with execution? ${DIM}[y/N]${RESET} `)
  }

  // ── Compact notifications ─────────────────────────────────────

  compactStart(tokenCount: number): void {
    this.write(
      `\n  ${STRIPE.compact}  ${FG.yellow}⟳${RESET}` +
        `  ${DIM}Context ~${Math.round(tokenCount / 1000)}k tokens — compacting…${RESET}\n`,
    )
  }

  compactDone(originalTokens: number, summaryTokens: number): void {
    const saved = Math.round((1 - summaryTokens / originalTokens) * 100)
    this.write(
      `  ${STRIPE.compact}  ${FG.brightGreen}✓${RESET}` +
        `  ${DIM}~${Math.round(originalTokens / 1000)}k → ~${Math.round(summaryTokens / 1000)}k tokens (${saved}% saved)${RESET}\n`,
    )
  }

  // ── Turn stats ────────────────────────────────────────────────

  turnStats(iterations: number, model: string): void {
    this.write(`\n  ${DIM}↩ ${iterations} turn${iterations !== 1 ? 's' : ''} · ${model}${RESET}\n`)
  }

  // ── Input prompt ──────────────────────────────────────────────

  writePrompt(): void {
    this.write(`\n${FG.brightBlue}❯${RESET} `)
  }

  writeInterruptPrompt(): void {
    // \x07 = BEL — terminal bell to alert user
    this.write(
      `\x07\n` +
      `${FG.brightYellow}${'─'.repeat(60)}${RESET}\n` +
      `${FG.brightYellow}  ⚡ 任务已暂停${RESET}  ${BOLD}输入建议后按 Enter 注入并继续${RESET}\n` +
      `${DIM}  直接按 Enter = 静默恢复  |  Ctrl+D = 终止${RESET}\n` +
      `${FG.brightYellow}${'─'.repeat(60)}${RESET}\n` +
      `${FG.brightYellow}▶${RESET} `,
    )
  }

  interruptInjected(msg: string): void {
    this.write(
      `\n  ${FG.brightYellow}⚡${RESET} ${DIM}已注入:${RESET} ${FG.brightWhite}${msg.slice(0, 120)}${msg.length > 120 ? '…' : ''}${RESET}\n`,
    )
  }

  newline(): void {
    this.write('\n')
  }
}
