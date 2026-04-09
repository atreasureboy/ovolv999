/**
 * FindingWrite / FindingList — 红队漏洞记录工具
 *
 * 持久化存储到 .ovogo/findings/ 目录（每条 finding 一个 JSON 文件）
 * FindingWrite  — 新增或更新一条漏洞记录
 * FindingList   — 列举所有记录，支持按严重等级/阶段过滤
 */

import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from 'fs'
import { resolve, join } from 'path'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Phase =
  | 'recon'
  | 'initial-access'
  | 'lateral-movement'
  | 'post-exploitation'
  | 'exfiltration'
  | 'other'
export type FindingStatus = 'open' | 'confirmed' | 'false-positive'

export interface Finding {
  id: string
  title: string
  type: string           // SQLi / XSS / RCE / LFI / SSRF / privilege-escalation / ...
  target: string         // IP / URL / host
  severity: Severity
  phase: Phase
  description: string
  poc?: string           // Proof of Concept 命令或步骤
  cve?: string           // e.g. CVE-2021-44228
  mitre_ttp?: string     // e.g. T1190, T1078
  screenshot_path?: string
  status: FindingStatus
  timestamp: string      // ISO 8601
}

function getFindingsDir(cwd: string): string {
  return resolve(cwd, '.ovogo', 'findings')
}

function ensureFindingsDir(dir: string): void {
  mkdirSync(dir, { recursive: true })
}

function loadAllFindings(dir: string): Finding[] {
  if (!existsSync(dir)) return []
  const files = readdirSync(dir).filter((f) => f.endsWith('.json'))
  return files.flatMap((f) => {
    try {
      return [JSON.parse(readFileSync(join(dir, f), 'utf8')) as Finding]
    } catch {
      return []
    }
  })
}

function severityOrder(s: Severity): number {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s] ?? 5
}

function renderFindingLine(f: Finding): string {
  const sev = f.severity.toUpperCase().padEnd(8)
  const phase = f.phase.padEnd(18)
  const status = f.status.padEnd(14)
  return `[${sev}] ${f.id.padEnd(12)} ${phase} ${status} ${f.target} — ${f.title}${f.cve ? ` (${f.cve})` : ''}${f.mitre_ttp ? ` [${f.mitre_ttp}]` : ''}`
}

// ─── FindingWrite ────────────────────────────────────────────────────────────

export class FindingWriteTool implements Tool {
  name = 'FindingWrite'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'FindingWrite',
      description: `记录一条渗透测试漏洞 Finding，持久化到 .ovogo/findings/ 目录。
用于在渗透过程中记录发现的漏洞、配置缺陷、信息泄露等。
支持新建和通过 id 更新已有记录。`,
      parameters: {
        type: 'object',
        properties: {
          id: {
            type: 'string',
            description: '唯一标识符，如 "f001"、"sqli-login"。更新时使用已有 id。',
          },
          title: {
            type: 'string',
            description: '漏洞标题，简短描述，如 "登录页面 SQL 注入"',
          },
          type: {
            type: 'string',
            description: '漏洞类型，如 SQLi / XSS / RCE / LFI / SSRF / privilege-escalation / info-disclosure / misconfig / weak-cred / ...',
          },
          target: {
            type: 'string',
            description: '目标 IP、URL 或主机名，如 "192.168.1.10" 或 "https://zhhovo.top/login"',
          },
          severity: {
            type: 'string',
            enum: ['critical', 'high', 'medium', 'low', 'info'],
            description: '严重等级',
          },
          phase: {
            type: 'string',
            enum: ['recon', 'initial-access', 'lateral-movement', 'post-exploitation', 'exfiltration', 'other'],
            description: '发现该漏洞所处的渗透阶段',
          },
          description: {
            type: 'string',
            description: '详细描述：漏洞成因、影响范围、复现条件',
          },
          poc: {
            type: 'string',
            description: 'Proof of Concept：完整的复现命令或步骤',
          },
          cve: {
            type: 'string',
            description: 'CVE 编号（如适用），如 "CVE-2021-44228"',
          },
          mitre_ttp: {
            type: 'string',
            description: 'MITRE ATT&CK TTP 编号，如 "T1190"（利用面向公众的应用程序）',
          },
          screenshot_path: {
            type: 'string',
            description: '截图文件路径（相对或绝对路径）',
          },
          status: {
            type: 'string',
            enum: ['open', 'confirmed', 'false-positive'],
            description: '漏洞状态',
          },
        },
        required: ['id', 'title', 'type', 'target', 'severity', 'phase', 'description', 'status'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const {
      id, title, type, target, severity, phase,
      description, poc, cve, mitre_ttp, screenshot_path, status,
    } = input as Partial<Finding>

    if (!id || !title || !type || !target || !severity || !phase || !description || !status) {
      return { content: 'Error: 缺少必填字段 (id/title/type/target/severity/phase/description/status)', isError: true }
    }

    const dir = getFindingsDir(context.cwd)
    ensureFindingsDir(dir)

    const filePath = join(dir, `${id}.json`)
    const isUpdate = existsSync(filePath)

    const finding: Finding = {
      id,
      title,
      type,
      target,
      severity,
      phase,
      description,
      poc,
      cve,
      mitre_ttp,
      screenshot_path,
      status,
      timestamp: new Date().toISOString(),
    }

    // 更新时保留原始 timestamp，新增用当前时间
    if (isUpdate) {
      try {
        const existing = JSON.parse(readFileSync(filePath, 'utf8')) as Finding
        finding.timestamp = existing.timestamp
      } catch { /* 忽略读取失败 */ }
    }

    writeFileSync(filePath, JSON.stringify(finding, null, 2), 'utf8')

    const action = isUpdate ? '已更新' : '已记录'
    return {
      content: `Finding ${action}: [${severity.toUpperCase()}] ${id} — ${title}\n目标: ${target}\n阶段: ${phase}\n文件: ${filePath}`,
      isError: false,
    }
  }
}

// ─── FindingList ─────────────────────────────────────────────────────────────

export class FindingListTool implements Tool {
  name = 'FindingList'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'FindingList',
      description: `列举所有已记录的渗透测试 Findings。
可按严重等级或阶段过滤。输出适合用于生成报告或快速回顾当前进展。`,
      parameters: {
        type: 'object',
        properties: {
          severity_filter: {
            type: 'string',
            enum: ['critical', 'high', 'medium', 'low', 'info', 'all'],
            description: '按严重等级过滤，"all" 显示全部',
          },
          phase_filter: {
            type: 'string',
            enum: ['recon', 'initial-access', 'lateral-movement', 'post-exploitation', 'exfiltration', 'other', 'all'],
            description: '按攻击阶段过滤，"all" 显示全部',
          },
          status_filter: {
            type: 'string',
            enum: ['open', 'confirmed', 'false-positive', 'all'],
            description: '按状态过滤，"all" 显示全部',
          },
        },
        required: [],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const severityFilter = (input.severity_filter as string) || 'all'
    const phaseFilter = (input.phase_filter as string) || 'all'
    const statusFilter = (input.status_filter as string) || 'all'

    const dir = getFindingsDir(context.cwd)
    let findings = loadAllFindings(dir)

    if (findings.length === 0) {
      return { content: '暂无 Findings。使用 FindingWrite 记录第一条漏洞。', isError: false }
    }

    if (severityFilter !== 'all') {
      findings = findings.filter((f) => f.severity === severityFilter)
    }
    if (phaseFilter !== 'all') {
      findings = findings.filter((f) => f.phase === phaseFilter)
    }
    if (statusFilter !== 'all') {
      findings = findings.filter((f) => f.status === statusFilter)
    }

    if (findings.length === 0) {
      return { content: '没有符合过滤条件的 Findings。', isError: false }
    }

    // 按严重等级排序
    findings.sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity))

    const total = loadAllFindings(dir)
    const stats = {
      critical: total.filter((f) => f.severity === 'critical').length,
      high:     total.filter((f) => f.severity === 'high').length,
      medium:   total.filter((f) => f.severity === 'medium').length,
      low:      total.filter((f) => f.severity === 'low').length,
      info:     total.filter((f) => f.severity === 'info').length,
    }

    const lines: string[] = [
      `Findings 总计: ${total.length} 条 | CRIT:${stats.critical} HIGH:${stats.high} MED:${stats.medium} LOW:${stats.low} INFO:${stats.info}`,
      `显示: ${findings.length} 条 (过滤: sev=${severityFilter} phase=${phaseFilter} status=${statusFilter})`,
      '─'.repeat(80),
      ...findings.map(renderFindingLine),
    ]

    return { content: lines.join('\n'), isError: false }
  }
}

// ─── 辅助：导出所有 findings 为结构化数据（供 report skill 使用）─────────────

export function exportFindings(cwd: string): Finding[] {
  return loadAllFindings(getFindingsDir(cwd)).sort(
    (a, b) => severityOrder(a.severity) - severityOrder(b.severity),
  )
}
