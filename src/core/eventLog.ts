/**
 * EventLog — 不可变事件流，记录渗透测试的完整审计轨迹
 *
 * 每条事件为 NDJSON 格式，追加写入 session 目录下的 events.ndjson。
 * 支持按类型/标签查询，供 critic 检查、上下文压缩、agent 回调等系统使用。
 */

import { appendFileSync, mkdirSync, existsSync, readFileSync } from 'fs'
import { join } from 'path'

export type EventType =
  | 'tool_call'
  | 'tool_result'
  | 'agent_spawn'
  | 'agent_complete'
  | 'memory_write'
  | 'memory_read'
  | 'context_compact'
  | 'critic_flag'
  | 'user_input'
  | 'user_interrupt'
  | 'dispatch_start'
  | 'dispatch_complete'

export interface EventLogEntry {
  id: string
  timestamp: string  // ISO 8601
  type: EventType
  source: string     // 工具名 / agent 类型 / 系统模块
  detail: Record<string, unknown>
  tags?: string[]
}

let _counter = 0
function nextId(): string {
  _counter++
  return `evt_${Date.now()}_${_counter}`
}

export class EventLog {
  private filePath: string

  constructor(sessionDir: string) {
    this.filePath = join(sessionDir, 'events.ndjson')
    try { mkdirSync(sessionDir, { recursive: true }) } catch { /* best-effort */ }
  }

  /** Append a new event (best-effort, never throws) */
  append(
    type: EventType,
    source: string,
    detail: Record<string, unknown>,
    tags?: string[],
  ): EventLogEntry {
    const entry: EventLogEntry = {
      id: nextId(),
      timestamp: new Date().toISOString(),
      type,
      source,
      detail,
      tags,
    }
    try {
      appendFileSync(this.filePath, JSON.stringify(entry) + '\n', 'utf8')
    } catch {
      // silently ignore — event log must never break the engine
    }
    return entry
  }

  /** Read all events from the file */
  readAll(): EventLogEntry[] {
    if (!existsSync(this.filePath)) return []
    try {
      const lines = readFileSync(this.filePath, 'utf8').trim().split('\n').filter(Boolean)
      return lines.map((l) => JSON.parse(l) as EventLogEntry)
    } catch {
      return []
    }
  }

  /** Query events by type and/or tags */
  query(options: { type?: EventType; tags?: string[]; limit?: number }): EventLogEntry[] {
    const all = this.readAll()
    let filtered = all
    if (options.type) {
      filtered = filtered.filter((e) => e.type === options.type)
    }
    if (options.tags && options.tags.length > 0) {
      filtered = filtered.filter((e) =>
        e.tags && options.tags!.some((t) => e.tags!.includes(t)),
      )
    }
    const limit = options.limit ?? 50
    return filtered.slice(-limit)
  }

  /** Get the file path (for tools that want to cat/tail it) */
  getFilePath(): string {
    return this.filePath
  }
}
