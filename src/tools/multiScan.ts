/**
 * MultiScan — 并行扫描执行器
 *
 * 两种模式：
 *
 * detach: false（默认）— 等待模式
 *   适合预期 <5 分钟完成的任务（subfinder / httpx / dnsx / naabu 快速扫描）
 *   Promise.all 并行执行，全部完成后返回汇总结果。
 *
 * detach: true — 后台启动模式
 *   适合长时间任务（nmap -p- / nuclei 全模板 / hydra 爆破）
 *   所有任务立即以 detached 子进程启动，<1s 返回 PID 列表和输出文件路径。
 *   LLM 之后用 Bash("tail -20 output_file") 检查进度，用 Bash("kill PID") 终止。
 */

import { spawn, execSync } from 'child_process'
import { mkdirSync, statSync, existsSync } from 'fs'
import { dirname } from 'path'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

// ─── 类型 ────────────────────────────────────────────────────────────────────

export interface ScanTask {
  command:      string   // bash 命令（输出必须重定向到 output_file）
  output_file:  string   // 输出文件绝对路径
  description:  string   // 任务简述
  timeout_ms?:  number   // 等待模式的单任务超时，默认 300000（5min）
}

interface ScanResult {
  description:  string
  output_file:  string
  status:       'completed' | 'failed' | 'timeout'
  exit_code:    number | null
  elapsed_s:    number
  output_size:  string
  tail:         string
  error?:       string
}

interface DetachResult {
  description:  string
  output_file:  string
  pid:          number | undefined
  started:      boolean
  error?:       string
}

// ─── 工具函数 ─────────────────────────────────────────────────────────────────

const DEFAULT_WAIT_TIMEOUT_MS = 300_000   // 5min（等待模式默认）
const TAIL_LINES = 6

function humanSize(bytes: number): string {
  if (bytes < 1024)        return `${bytes}B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`
  return `${(bytes / 1024 / 1024).toFixed(1)}MB`
}

function getFileSizeStr(path: string): string {
  try { return humanSize(statSync(path).size) } catch { return '(未生成)' }
}

function getTail(outputFile: string): string {
  if (!existsSync(outputFile)) return '(文件不存在)'
  try {
    return execSync(`tail -${TAIL_LINES} "${outputFile}" 2>/dev/null`, {
      timeout: 3000, encoding: 'utf8',
    }).trim() || '(空)'
  } catch { return '(读取失败)' }
}

function ensureDir(file: string) {
  try { mkdirSync(dirname(file), { recursive: true }) } catch { /* ok */ }
}

// ─── 等待模式：runTask ────────────────────────────────────────────────────────

function runTask(task: ScanTask, signal?: AbortSignal): Promise<ScanResult> {
  const timeoutMs = task.timeout_ms ?? DEFAULT_WAIT_TIMEOUT_MS
  const start = Date.now()
  ensureDir(task.output_file)

  return new Promise((resolve) => {
    let settled = false

    const done = (status: ScanResult['status'], code: number | null, error?: string) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      const elapsed_s = parseFloat(((Date.now() - start) / 1000).toFixed(1))
      resolve({
        description:  task.description,
        output_file:  task.output_file,
        status,
        exit_code:    code,
        elapsed_s,
        output_size:  getFileSizeStr(task.output_file),
        tail:         status !== 'timeout' ? getTail(task.output_file) : '(已超时)',
        error,
      })
    }

    const child = spawn('bash', ['-c', task.command], { stdio: 'ignore' })

    const timer = setTimeout(() => {
      if (settled) return
      try { process.kill(-(child.pid!), 'SIGTERM') } catch {
        try { child.kill('SIGTERM') } catch { /* ignore */ }
      }
      setTimeout(() => {
        try { process.kill(-(child.pid!), 'SIGKILL') } catch {
          try { child.kill('SIGKILL') } catch { /* ignore */ }
        }
      }, 3000)
      done('timeout', null, `超时（>${timeoutMs / 1000}s）`)
    }, timeoutMs)

    child.on('close', (code) => done(code === 0 ? 'completed' : 'failed', code))
    child.on('error', (err) => done('failed', null, err.message))

    if (signal) {
      const onAbort = () => {
        if (settled) return
        clearTimeout(timer)
        try { process.kill(-(child.pid!), 'SIGTERM') } catch {
          try { child.kill('SIGTERM') } catch { /* ignore */ }
        }
        done('failed', null, '已取消')
      }
      if (signal.aborted) { onAbort(); return }
      signal.addEventListener('abort', onAbort, { once: true })
    }
  })
}

// ─── 后台模式：launchDetached ─────────────────────────────────────────────────

function launchDetached(task: ScanTask): DetachResult {
  ensureDir(task.output_file)
  try {
    // 将命令包一层 nohup，确保父进程退出后继续运行，stderr 同样写入输出文件
    const wrapped = `nohup bash -c ${JSON.stringify(task.command)} >> "${task.output_file}" 2>&1 &`
    const child = spawn('bash', ['-c', wrapped], {
      detached: true,
      stdio:    'ignore',
    })
    child.unref()
    return { description: task.description, output_file: task.output_file, pid: child.pid, started: true }
  } catch (e) {
    return { description: task.command, output_file: task.output_file, pid: undefined, started: false, error: (e as Error).message }
  }
}

// ─── 渲染 ────────────────────────────────────────────────────────────────────

function renderWaitSummary(results: ScanResult[]): string {
  const done    = results.filter(r => r.status === 'completed').length
  const failed  = results.filter(r => r.status === 'failed').length
  const timeout = results.filter(r => r.status === 'timeout').length
  const totalS  = results.length ? Math.max(...results.map(r => r.elapsed_s)) : 0

  const lines = [
    `并行扫描完成 — 总耗时 ${totalS}s | ✓ ${done}  ✗ ${failed}  ⏱ ${timeout}`,
    '─'.repeat(68),
  ]
  for (const r of results) {
    const icon = r.status === 'completed' ? '✓' : r.status === 'timeout' ? '⏱' : '✗'
    lines.push(`${icon} [${r.elapsed_s}s] ${r.description}  →  ${r.output_file} (${r.output_size})`)
    if (r.error) lines.push(`   错误: ${r.error}`)
    else if (r.tail && r.tail !== '(空)') {
      lines.push(r.tail.split('\n').slice(-3).map(l => '   ' + l).join('\n'))
    }
  }
  lines.push('─'.repeat(68))
  return lines.join('\n')
}

function renderDetachSummary(results: DetachResult[]): string {
  const ok = results.filter(r => r.started).length

  const lines = [
    `后台启动完成 — ${ok}/${results.length} 个任务已启动，继续执行其他侦察任务`,
    '─'.repeat(68),
  ]
  for (const r of results) {
    const icon = r.started ? '▶' : '✗'
    const pid  = r.pid ? `  PID: ${r.pid}` : ''
    lines.push(`${icon} ${r.description}${pid}`)
    lines.push(`   输出: ${r.output_file}`)
    if (r.error) lines.push(`   错误: ${r.error}`)
  }
  lines.push('─'.repeat(68))
  lines.push('检查进度:  tail -20 <output_file>')
  lines.push('终止任务:  kill <PID>')
  lines.push('等完成后读结果:  cat <output_file>  或  grep 关键词 <output_file>')
  return lines.join('\n')
}

// ─── 工具类 ──────────────────────────────────────────────────────────────────

export class MultiScanTool implements Tool {
  name = 'MultiScan'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'MultiScan',
      description: `并行启动多个扫描命令。两种模式，根据任务时长选择：

★ detach: false（等待模式，默认）
  适合预期 <5 分钟的任务：subfinder / httpx / dnsx / naabu / nikto / 快速 nmap
  所有任务并行跑，全部完成后返回结果摘要 + 输出文件末尾预览。

★ detach: true（后台启动模式）
  适合长时间任务：nmap -p- / nuclei 全模板 / hydra 爆破 / sqlmap
  所有任务立即以 nohup 后台进程启动，<1 秒返回 PID 和输出文件路径。
  之后用 Bash("tail -20 output_file") 检查进度。

选择规则：
  - 预计 <5 分钟 → detach: false
  - 预计 >5 分钟，或不确定 → detach: true
  - nmap --top-ports 1000 → detach: false
  - nmap -p- (全端口) → detach: true
  - nuclei 全模板 → detach: true
  - subfinder / httpx → detach: false

每个命令必须把输出写到 output_file（用 -o、-oN、或 > 重定向）。`,
      parameters: {
        type: 'object',
        properties: {
          tasks: {
            type: 'array',
            description: '并行任务列表',
            items: {
              type: 'object',
              properties: {
                command:     { type: 'string', description: 'bash 命令，输出必须写入 output_file' },
                output_file: { type: 'string', description: '输出文件绝对路径' },
                description: { type: 'string', description: '任务简述，如 "nmap 全端口扫描"' },
                timeout_ms:  { type: 'number', description: '等待模式超时（ms），默认 300000（5min）' },
              },
              required: ['command', 'output_file', 'description'],
            },
          },
          detach: {
            type: 'boolean',
            description: 'true = 后台启动立即返回（长任务用）；false = 等待全部完成再返回（短任务用）。默认 false。',
          },
        },
        required: ['tasks'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const tasks  = input.tasks  as ScanTask[] | undefined
    const detach = Boolean(input.detach ?? false)

    if (!Array.isArray(tasks) || tasks.length === 0) {
      return { content: 'Error: tasks 不能为空', isError: true }
    }
    if (tasks.length > 20) {
      return { content: 'Error: 单次最多 20 个任务', isError: true }
    }
    for (const t of tasks) {
      if (!t.command || !t.output_file || !t.description) {
        return { content: `Error: 缺少 command/output_file/description: ${JSON.stringify(t)}`, isError: true }
      }
    }

    if (detach) {
      // ── 后台模式：全部立即启动，<1s 返回 ───────────────────────
      const results = tasks.map(t => launchDetached(t))
      const anyFailed = results.some(r => !r.started)
      return { content: renderDetachSummary(results), isError: anyFailed }
    } else {
      // ── 等待模式：Promise.all 并行，全部完成后返回 ───────────────
      const promises = tasks.map(t => runTask(t, context.signal))
      const results  = await Promise.all(promises)
      const anyBad   = results.some(r => r.status !== 'completed')
      return { content: renderWaitSummary(results), isError: anyBad }
    }
  }
}
