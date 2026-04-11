/**
 * TmuxLayout — 4-pane grid layout for sub-agent monitoring
 *
 * Layout (用户视角):
 *   ┌─────────────────────┬─────────────────────┐
 *   │  ● OVOGO — Main     │  ○ Agent 0 — idle   │
 *   │                     │                     │
 *   ├─────────────────────┼─────────────────────┤
 *   │  ○ Agent 2 — idle   │  ○ Agent 1 — idle   │
 *   │                     │                     │
 *   └─────────────────────┴─────────────────────┘
 *
 * - 每个格子通过 tmux pane-border-status 显示标题
 * - Agent 格子运行 `tail -f agent-N.log`，实时显示 agent 输出
 * - Sub-agents 通过 Renderer.forFile() 写入对应日志文件
 * - 不在 tmux 时优雅降级（全部输出到主 stdout）
 *
 * 注意：tryAutoLaunchInTmux() 在 main() 最开头调用，确保用户始终在 tmux 里运行
 */

import { execSync, spawnSync } from 'child_process'
import { mkdirSync, writeFileSync } from 'fs'
import { join } from 'path'

const MAX_AGENT_PANES = 3

interface PaneSlot {
  logFile: string
  paneId: string
  occupied: boolean
  agentLabel: string
}

// ─────────────────────────────────────────────────────────────
// Shell-safe single-quote escaping
// ─────────────────────────────────────────────────────────────
function sq(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`
}

// ─────────────────────────────────────────────────────────────
// Auto-launch in tmux if not already inside one
// ─────────────────────────────────────────────────────────────

/**
 * If the current process is NOT inside tmux and stdin/stdout are a TTY,
 * spawn a new tmux session and re-exec the same Node.js command inside it.
 * Blocks until the tmux session ends (attach), then returns true so the
 * caller can exit(0).
 *
 * Returns false if tmux is unavailable, already in tmux, or not a TTY.
 */
export function tryAutoLaunchInTmux(): boolean {
  if (process.env.TMUX) return false              // already in tmux
  if (!process.stdin.isTTY) return false          // pipe / script mode
  if (!process.stdout.isTTY) return false         // not a real terminal

  // Check tmux is installed
  const check = spawnSync('tmux', ['-V'], { stdio: 'pipe' })
  if (check.status !== 0) return false

  // Reconstruct the command to run inside tmux
  const nodeExe   = process.execPath              // e.g. /usr/bin/node
  const script    = process.argv[1]               // e.g. dist/bin/ovogogogo.js
  const extraArgs = process.argv.slice(2)

  // Forward key environment variables into the tmux session
  const envKeys = [
    'OPENAI_API_KEY', 'OPENAI_BASE_URL',
    'OVOGO_MODEL', 'OVOGO_MAX_ITER', 'OVOGO_CWD',
    'PATH', 'HOME', 'USER', 'LOGNAME',
    'TERM', 'COLORTERM', 'LANG', 'LC_ALL',
    'GOPATH', 'GOROOT',
  ]
  const envFwd = envKeys
    .filter(k => process.env[k] !== undefined)
    .map(k => `${k}=${sq(process.env[k]!)}`)
    .join(' ')

  const parts = [envFwd, sq(nodeExe), sq(script), ...extraArgs.map(sq)]
  const innerCmd = parts.filter(Boolean).join(' ')

  const sessionName = `ovogo-${Date.now()}`
  const W = process.stdout.columns || 220
  const H = process.stdout.rows    || 50

  try {
    // Create a detached tmux session with the right dimensions
    execSync(`tmux new-session -d -s ${sq(sessionName)} -x ${W} -y ${H}`)

    // Run our command inside it
    execSync(`tmux send-keys -t ${sq(sessionName)} ${JSON.stringify(innerCmd)} Enter`)

    // Attach (blocks until session ends)
    execSync(`tmux attach-session -t ${sq(sessionName)}`, { stdio: 'inherit' })

    return true
  } catch {
    // If anything fails, fall through to normal mode
    return false
  }
}

// ─────────────────────────────────────────────────────────────
// TmuxLayout — 4宫格管理
// ─────────────────────────────────────────────────────────────

export class TmuxLayout {
  private slots: PaneSlot[] = []
  private initialized = false
  private mainPaneId  = ''

  /**
   * 在当前 tmux 窗口内创建四宫格布局。
   * @param logDir  Agent 日志文件目录（session dir 下的 agent-logs/）
   * @returns true 表示成功，false 表示非 tmux 或分屏失败（自动降级）
   */
  init(logDir: string): boolean {
    if (!process.env.TMUX) return false
    if (this.initialized) return true

    try {
      mkdirSync(logDir, { recursive: true })
    } catch {
      return false
    }

    try {
      // 记录主 pane ID
      this.mainPaneId = execSync('tmux display-message -p "#{pane_id}"', { encoding: 'utf8' }).trim()

      // ── 创建右侧上格（top-right）
      const p1 = execSync('tmux split-window -h -p 50 -P -F "#{pane_id}"', { encoding: 'utf8' }).trim()

      // ── 右下格（bottom-right）：在 p1 上再拆
      const p2 = execSync(`tmux split-window -v -p 50 -t ${sq(p1)} -P -F "#{pane_id}"`, { encoding: 'utf8' }).trim()

      // ── 切回主格，创建左下格（bottom-left）
      execSync(`tmux select-pane -t ${sq(this.mainPaneId)}`)
      const p3 = execSync('tmux split-window -v -p 50 -P -F "#{pane_id}"', { encoding: 'utf8' }).trim()

      // ── 焦点回到主格
      execSync(`tmux select-pane -t ${sq(this.mainPaneId)}`)

      // ── 开启 pane 边框标题（每个格子顶部显示名称）
      execSync('tmux set-option -w pane-border-status top 2>/dev/null || true')
      execSync([
        'tmux set-option -w pane-border-format',
        '" #[bold]#{?pane_active,#[fg=colour51],#[fg=colour240]}#{pane_title}#[default] "',
      ].join(' ') + ' 2>/dev/null || true')

      // ── 设置主格标题
      execSync(`tmux select-pane -t ${sq(this.mainPaneId)} -T ${sq('● OVOGO — Main')}`)

      const paneIds   = [p1, p2, p3]
      const positions = ['右上 Agent 0', '右下 Agent 1', '左下 Agent 2']

      for (let i = 0; i < MAX_AGENT_PANES; i++) {
        const logFile = join(logDir, `agent-${i}.log`)
        const paneId  = paneIds[i]
        const label   = positions[i]

        // 写入初始占位内容，使 tail -f 有内容可显示
        writeFileSync(logFile,
          `\x1b[2m${'─'.repeat(60)}\x1b[0m\n` +
          `\x1b[2m  ${label} — 等待 agent 任务…\x1b[0m\n` +
          `\x1b[2m${'─'.repeat(60)}\x1b[0m\n`,
        )

        // 设置 pane 标题
        execSync(`tmux select-pane -t ${sq(paneId)} -T ${sq(`○ ${label} — idle`)}`)

        // 在该格子里运行 tail -f
        const tailCmd = `tail -f ${sq(logFile)}`
        execSync(`tmux send-keys -t ${sq(paneId)} ${JSON.stringify(tailCmd)} Enter`)

        this.slots.push({ logFile, paneId, occupied: false, agentLabel: '' })
      }

      this.initialized = true
      return true

    } catch (e) {
      // 分屏失败 — 清空已创建的格子，优雅降级
      this.slots = []
      return false
    }
  }

  /**
   * 为新 agent 分配一个空闲格子。
   * 返回日志文件路径（传给 Renderer.forFile()），或 null（无空闲格子，降级到主 stdout）。
   */
  acquireSlot(agentLabel: string): { slot: number; logFile: string } | null {
    if (!this.initialized) return null

    for (let i = 0; i < this.slots.length; i++) {
      if (!this.slots[i].occupied) {
        this.slots[i].occupied   = true
        this.slots[i].agentLabel = agentLabel

        // 更新 pane 标题为 "● [类型] 描述"
        try {
          const title = `● ${agentLabel.slice(0, 40)}`
          execSync(`tmux select-pane -t ${sq(this.slots[i].paneId)} -T ${sq(title)}`)
        } catch { /* best-effort */ }

        // 在日志文件里写入 agent 启动 banner
        const banner =
          `\n\x1b[1m\x1b[95m${'═'.repeat(58)}\x1b[0m\n` +
          `\x1b[1m\x1b[95m  ⎇  ${agentLabel}\x1b[0m\n` +
          `\x1b[2m     ${new Date().toLocaleTimeString()}\x1b[0m\n` +
          `\x1b[1m\x1b[95m${'═'.repeat(58)}\x1b[0m\n`
        try { writeFileSync(this.slots[i].logFile, banner, { flag: 'a' }) } catch { /* best-effort */ }

        return { slot: i, logFile: this.slots[i].logFile }
      }
    }
    return null
  }

  /**
   * Agent 完成后释放格子，重置为 idle。
   */
  releaseSlot(slot: number): void {
    const s = this.slots[slot]
    if (!s) return

    // 写入完成 footer
    const footer =
      `\n\x1b[2m${'─'.repeat(58)}\x1b[0m\n` +
      `\x1b[2m  ✓ "${s.agentLabel}" 已完成\x1b[0m\n` +
      `\x1b[2m  等待下一个 agent 任务…\x1b[0m\n` +
      `\x1b[2m${'─'.repeat(58)}\x1b[0m\n`
    try { writeFileSync(s.logFile, footer, { flag: 'a' }) } catch { /* best-effort */ }

    // 恢复 pane 标题为 idle
    try {
      const idx   = this.slots.indexOf(s)
      const names = ['右上 Agent 0', '右下 Agent 1', '左下 Agent 2']
      execSync(`tmux select-pane -t ${sq(s.paneId)} -T ${sq(`○ ${names[idx]} — idle`)}`)
    } catch { /* best-effort */ }

    s.occupied   = false
    s.agentLabel = ''
  }

  isReady(): boolean {
    return this.initialized
  }
}

/** Singleton — 在 agent.ts 和 ovogogogo.ts 中共用 */
export const tmuxLayout = new TmuxLayout()
