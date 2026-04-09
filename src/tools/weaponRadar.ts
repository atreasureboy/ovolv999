/**
 * WeaponRadar — 武器库语义检索工具
 *
 * 调用 /data/poc_db/weapon_radar_query.py，对公司 22W Nuclei PoC 数据库
 * 进行自然语言向量检索（BGE-M3 + pgvector），返回最匹配的漏洞武器。
 *
 * 注意：首次调用需加载 BGE-M3 模型，约 30-60 秒；后续调用因 OS 缓存
 * 会快很多。超时设为 180s 以覆盖最慢情况。
 */

import { exec } from 'child_process'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

const RADAR_SCRIPT = '/data/poc_db/weapon_radar_query.py'
const TIMEOUT_MS   = 180_000   // 3 分钟：首次加载 BGE-M3 可能需要 60s+

interface RadarResult {
  rank:         number
  id:           number
  module_name:  string
  attack_logic: string
  score:        number
  score_pct:    number
  poc_code?:    string
}

interface RadarOutput {
  query:     string
  results:   RadarResult[]
  total:     number
  encode_ms: number
  search_ms: number
  error?:    string
}

function formatResults(output: RadarOutput): string {
  const lines: string[] = [
    `武器库检索 — 查询: "${output.query}"`,
    `返回 ${output.total} 条 | 编码 ${output.encode_ms}ms | 检索 ${output.search_ms}ms`,
    '─'.repeat(72),
  ]

  for (const r of output.results) {
    const scoreBar = r.score_pct >= 80 ? '★★★' : r.score_pct >= 60 ? '★★☆' : '★☆☆'
    lines.push(`#${r.rank}  [${r.score_pct}%] ${scoreBar}  ${r.module_name}  (ID: ${r.id})`)
    if (r.attack_logic) {
      lines.push(`    攻击逻辑: ${r.attack_logic}`)
    }
    if (r.poc_code) {
      const preview = r.poc_code.length > 1200
        ? r.poc_code.slice(0, 1200) + '\n... (已截断)'
        : r.poc_code
      lines.push(`    PoC 代码:\n${preview.split('\n').map(l => '    ' + l).join('\n')}`)
    }
    lines.push('')
  }

  return lines.join('\n').trimEnd()
}

export class WeaponRadarTool implements Tool {
  name = 'WeaponRadar'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'WeaponRadar',
      description: `检索公司内部 22W Nuclei PoC 武器数据库，使用自然语言描述攻击意图，返回最匹配的漏洞武器。

使用 BGE-M3 向量语义搜索，可以用中文或英文描述：
- 攻击目标特征："Apache Log4j RCE"、"WordPress 插件漏洞"
- 攻击类型："SSRF via URL 参数"、"SQL 注入 登录绕过"
- 服务+版本："Shiro 反序列化"、"Tomcat 文件上传"
- 已发现的服务："目标跑了 Jenkins 2.3，找 RCE"

⚠️ 首次调用需加载语义模型（约 30-60 秒），请耐心等待。`,
      parameters: {
        type: 'object',
        properties: {
          query: {
            type: 'string',
            description: '自然语言攻击意图描述，支持中英文。例如："Apache Struts2 RCE"、"Shiro 反序列化认证绕过"、"WordPress 文件上传 getshell"',
          },
          top_k: {
            type: 'number',
            description: '返回结果数量，默认 3，最多 10。发现目标服务时建议用 5，针对性查找用 3。',
          },
          show_code: {
            type: 'boolean',
            description: '是否返回完整 PoC YAML 代码。准备直接利用时设 true，快速筛选时设 false（默认）。',
          },
        },
        required: ['query'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const query     = input.query as string | undefined
    const topK      = Math.min(Math.max(Number(input.top_k ?? 3), 1), 10)
    const showCode  = Boolean(input.show_code ?? false)

    if (!query || !query.trim()) {
      return { content: 'Error: query 不能为空', isError: true }
    }

    // 构造命令，shell 转义 query
    const escapedQuery = query.replace(/'/g, "'\\''")
    const cmd = [
      `python3 ${RADAR_SCRIPT}`,
      `-q '${escapedQuery}'`,
      `-n ${topK}`,
      showCode ? '--show-code' : '',
    ].filter(Boolean).join(' ')

    return new Promise<ToolResult>((resolve) => {
      let settled = false

      const child = exec(cmd, {
        timeout: TIMEOUT_MS,
        maxBuffer: 10 * 1024 * 1024,   // 10MB：PoC 代码可能很长
        cwd: context.cwd,
        env: { ...process.env },
      }, (err, stdout, stderr) => {
        if (context.signal) context.signal.removeEventListener('abort', onAbort)
        if (settled) return
        settled = true

        if (context.signal?.aborted) {
          resolve({ content: 'WeaponRadar: 已取消', isError: true })
          return
        }

        if (err) {
          const nodeErr = err as NodeJS.ErrnoException & { killed?: boolean }
          if (nodeErr.killed) {
            resolve({ content: `WeaponRadar: 超时（>${TIMEOUT_MS / 1000}s），模型加载过慢或数据库无响应`, isError: true })
            return
          }
          // 非超时错误：尝试解析 JSON（脚本可能输出了 {"error": "..."}）
          const raw = stdout.trim() || stderr.trim()
          try {
            const parsed = JSON.parse(raw) as RadarOutput
            if (parsed.error) {
              resolve({ content: `WeaponRadar 错误: ${parsed.error}`, isError: true })
              return
            }
          } catch { /* 非 JSON，直接输出 */ }
          resolve({
            content: `WeaponRadar 执行失败 (exit ${(err as NodeJS.ErrnoException).code ?? 1}):\n${raw}`,
            isError: true,
          })
          return
        }

        // 成功 — 解析 JSON 并格式化
        const raw = stdout.trim()
        let parsed: RadarOutput
        try {
          parsed = JSON.parse(raw) as RadarOutput
        } catch {
          // 解析失败，直接返回原始输出（可能含 rich 格式）
          resolve({ content: raw || '(无输出)', isError: false })
          return
        }

        if (parsed.error) {
          resolve({ content: `WeaponRadar 错误: ${parsed.error}`, isError: true })
          return
        }

        if (!parsed.results || parsed.results.length === 0) {
          resolve({ content: `武器库中未找到匹配 "${query}" 的 PoC，尝试换用不同关键词。`, isError: false })
          return
        }

        resolve({ content: formatResults(parsed), isError: false })
      })

      const onAbort = () => {
        if (settled) return
        settled = true
        const pid = child.pid
        if (pid !== undefined) {
          try { process.kill(-pid, 'SIGTERM') } catch {
            try { child.kill('SIGTERM') } catch { /* ignore */ }
          }
        }
        resolve({ content: 'WeaponRadar: 已取消', isError: true })
      }

      if (context.signal) {
        if (context.signal.aborted) {
          onAbort()
        } else {
          context.signal.addEventListener('abort', onAbort, { once: true })
        }
      }
    })
  }
}
