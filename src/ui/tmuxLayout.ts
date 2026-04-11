/**
 * TmuxLayout — 4-pane grid layout for sub-agent monitoring
 *
 * Layout:
 *   ┌──────────────┬──────────────┐
 *   │   Main       │   Agent 0    │
 *   │  (top-left)  │  (top-right) │
 *   ├──────────────┼──────────────┤
 *   │   Agent 2    │   Agent 1    │
 *   │  (bot-left)  │  (bot-right) │
 *   └──────────────┴──────────────┘
 *
 * On init(), if running inside tmux, the current window is split into 4 panes.
 * Panes 1/2/3 run `tail -f` on per-agent log files.
 * Sub-agents write to those log files via Renderer.forFile().
 *
 * Gracefully degrades: if not in tmux or splits fail, everything still works —
 * sub-agents just write to the main stdout renderer instead.
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

export class TmuxLayout {
  private slots: PaneSlot[] = []
  private initialized = false
  private logDir = ''

  /**
   * Initialize the 4-pane layout.
   * @param logDir Directory where agent log files are written.
   * @returns true if tmux layout was created, false if degraded (not in tmux or error).
   */
  init(logDir: string): boolean {
    // Only run inside an active tmux session
    if (!process.env.TMUX) return false
    if (this.initialized) return true

    this.logDir = logDir
    try {
      mkdirSync(logDir, { recursive: true })
    } catch {
      return false
    }

    try {
      // ── Step 1: Split current pane right (top-right)
      const p1 = execSync('tmux split-window -h -p 50 -P -F "#{pane_id}"', { encoding: 'utf8' }).trim()

      // ── Step 2: Split top-right down (bottom-right)
      const p2 = execSync(`tmux split-window -v -p 50 -t "${p1}" -P -F "#{pane_id}"`, { encoding: 'utf8' }).trim()

      // ── Step 3: Go back to main (left), split down (bottom-left)
      execSync('tmux select-pane -t 0')
      const p3 = execSync('tmux split-window -v -p 50 -P -F "#{pane_id}"', { encoding: 'utf8' }).trim()

      // ── Step 4: Return focus to main pane
      execSync('tmux select-pane -t 0')

      const paneIds = [p1, p2, p3]
      const positions = ['top-right', 'bot-right', 'bot-left']

      for (let i = 0; i < MAX_AGENT_PANES; i++) {
        const logFile = join(logDir, `agent-${i}.log`)
        const paneId  = paneIds[i]
        const pos     = positions[i]

        // Seed log file with a header so tail -f has something to show
        writeFileSync(logFile, `\x1b[2m── Agent Pane ${i} (${pos}) — waiting for task… ──\x1b[0m\n`)

        // Start tail -f in the pane
        const tailCmd = `tail -f '${logFile}'`
        execSync(`tmux send-keys -t "${paneId}" ${JSON.stringify(tailCmd)} Enter`)

        this.slots.push({ logFile, paneId, occupied: false, agentLabel: '' })
      }

      this.initialized = true
      return true
    } catch {
      // Layout setup failed — clear partial state and degrade gracefully
      this.slots = []
      return false
    }
  }

  /**
   * Acquire a free pane slot for a new agent.
   * Returns the log file path to pass to Renderer.forFile(), or null if no slot available.
   */
  acquireSlot(agentLabel: string): { slot: number; logFile: string } | null {
    if (!this.initialized) return null

    for (let i = 0; i < this.slots.length; i++) {
      if (!this.slots[i].occupied) {
        this.slots[i].occupied = true
        this.slots[i].agentLabel = agentLabel

        // Write agent header into log file
        const header =
          `\n\x1b[1m\x1b[95m${'═'.repeat(56)}\x1b[0m\n` +
          `\x1b[1m\x1b[95m⎇  ${agentLabel}\x1b[0m\n` +
          `\x1b[2m   ${new Date().toISOString()}\x1b[0m\n` +
          `\x1b[1m\x1b[95m${'═'.repeat(56)}\x1b[0m\n`
        try {
          writeFileSync(this.slots[i].logFile, header, { flag: 'a' })
        } catch { /* best-effort */ }

        return { slot: i, logFile: this.slots[i].logFile }
      }
    }
    return null
  }

  /**
   * Release a pane slot so it can be reused by the next agent.
   */
  releaseSlot(slot: number): void {
    if (this.slots[slot]) {
      this.slots[slot].occupied = false

      // Write a footer into the log file
      const footer =
        `\n\x1b[2m── Agent "${this.slots[slot].agentLabel}" finished ──\x1b[0m\n` +
        `\x1b[2m── Waiting for next agent… ──\x1b[0m\n`
      try {
        writeFileSync(this.slots[slot].logFile, footer, { flag: 'a' })
      } catch { /* best-effort */ }

      this.slots[slot].agentLabel = ''
    }
  }

  isReady(): boolean {
    return this.initialized
  }
}

/** Singleton — imported by agent.ts and ovogogogo.ts */
export const tmuxLayout = new TmuxLayout()
