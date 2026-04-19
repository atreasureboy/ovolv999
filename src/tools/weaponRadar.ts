/**
 * WeaponRadar — 武器库语义检索工具
 *
 * 通过 HTTP 调用 WeaponRadar API 服务（/project/poc_db/server.py），
 * 对 22W Nuclei PoC 数据库进行自然语言向量检索（BGE-M3 + pgvector）。
 *
 * API 地址通过环境变量 WEAPON_RADAR_URL 配置，默认 http://127.0.0.1:8765
 */

import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

function getApiBase(): string {
  return (process.env.WEAPON_RADAR_URL ?? 'http://127.0.0.1:8765').replace(/\/$/, '')
}

const TIMEOUT_MS = 180_000   // 3 分钟：首次请求需等模型加载

interface RadarResult {
  rank:              number
  id:                number
  module_name:       string
  attack_logic:      string
  opsec_risk?:       number
  cve_list?:         string[]
  required_options?: Record<string, string>
  auto_parameters?:  Record<string, string>
  score:             number
  score_pct:         number
  poc_code?:         string
}

interface RadarOutput {
  query:     string
  results:   RadarResult[]
  total:     number
  encode_ms: number
  search_ms: number
  error?:    string
}

function formatSingleResult(output: RadarOutput): string {
  const lines: string[] = [
    `武器库检索 — 查询: "${output.query}"`,
    `返回 ${output.total} 条 | 编码 ${output.encode_ms}ms | 检索 ${output.search_ms}ms`,
    '─'.repeat(72),
  ]

  for (const r of output.results) {
    const scoreBar = r.score_pct >= 80 ? '★★★' : r.score_pct >= 60 ? '★★☆' : '★☆☆'
    const riskStr  = r.opsec_risk !== undefined ? ` | 噪音风险:${r.opsec_risk}/5` : ''
    lines.push(`#${r.rank}  [${r.score_pct}%] ${scoreBar}  ${r.module_name}  (ID: ${r.id})${riskStr}`)

    if (r.cve_list && r.cve_list.length > 0) {
      lines.push(`    CVE: ${r.cve_list.join(', ')}`)
    }
    if (r.attack_logic) {
      lines.push(`    攻击逻辑: ${r.attack_logic}`)
    }
    if (r.auto_parameters && Object.keys(r.auto_parameters).length > 0) {
      lines.push(`    参数说明: ${JSON.stringify(r.auto_parameters)}`)
    }

    if (r.poc_code) {
      // ⚠️ poc_code 是漏洞原理参考，不是 nuclei 模板。
      // 从 attack_logic 中提取关键信息，给出 curl/Python 验证建议。
      lines.push(`    ▶ PoC 原理参考（需改写为手动 exploit）:`)
      lines.push(`      ${r.poc_code.slice(0, 300)}${r.poc_code.length > 300 ? '...' : ''}`)
      if (r.cve_list && r.cve_list.length > 0) {
        lines.push(`      快速验证: nuclei -u TARGET -id ${r.cve_list[0]} -silent`)
      }
      lines.push(`      利用步骤: 1) 从 poc_code 提取 endpoint+payload → 2) curl 验证 → 3) 利用`)
    }
    lines.push('')
  }

  return lines.join('\n').trimEnd()
}

function formatBatchResults(outputs: RadarOutput[]): string {
  return outputs.map((output, i) => {
    if (output.error) {
      return `[${i + 1}] 查询 "${output.query}" 失败: ${output.error}`
    }
    if (!output.results || output.results.length === 0) {
      return `[${i + 1}] 查询 "${output.query}": 未找到匹配 PoC`
    }
    return formatSingleResult(output)
  }).join('\n\n' + '═'.repeat(72) + '\n\n')
}

async function fetchWithTimeout(url: string, body: unknown, signal?: AbortSignal): Promise<RadarOutput | RadarOutput[]> {
  const ac = new AbortController()
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS)

  // 如果外部取消也触发 abort
  signal?.addEventListener('abort', () => ac.abort(), { once: true })

  try {
    const resp = await fetch(url, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
      signal:  ac.signal,
    })
    if (!resp.ok) {
      const text = await resp.text().catch(() => '')
      throw new Error(`HTTP ${resp.status}: ${text}`)
    }
    return await resp.json() as RadarOutput | RadarOutput[]
  } finally {
    clearTimeout(timer)
  }
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

返回结果包含：攻击逻辑分析、完整可执行 PoC YAML、nuclei 执行命令（可直接复制运行）。

批量查询优化：如需同时检索多个目标/漏洞，使用 queries[] 参数，比多次调用快很多。`,
      parameters: {
        type: 'object',
        properties: {
          query: {
            type: 'string',
            description: '单个查询：自然语言攻击意图描述，支持中英文。例如："Apache Struts2 RCE"、"Shiro 反序列化认证绕过"',
          },
          queries: {
            type: 'array',
            items: { type: 'string' },
            description: '批量查询（推荐）：多个查询组成的数组。例如：["Apache Log4j RCE", "WordPress 文件上传", "Spring Boot Actuator"]',
          },
          top_k: {
            type: 'number',
            description: '每个查询返回结果数量，默认 3，最多 10。',
          },
          hide_code: {
            type: 'boolean',
            description: '设为 true 时不返回 PoC YAML 代码（默认 false，即默认返回完整可执行 PoC）。',
          },
        },
        required: [],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const query    = input.query as string | undefined
    const queries  = input.queries as string[] | undefined
    const topK     = Math.min(Math.max(Number(input.top_k ?? 3), 1), 10)
    const hideCode = Boolean(input.hide_code ?? false)
    const base     = getApiBase()

    try {
      // 批量模式
      if (queries && queries.length > 0) {
        const resp = await fetchWithTimeout(
          `${base}/batch`,
          {
            queries: queries.map(q => ({ query: q.trim(), top_k: topK })),
            no_code: hideCode,
          },
          context.signal,
        ) as unknown as { results: RadarOutput[] }

        return { content: formatBatchResults(resp.results), isError: false }
      }

      // 单查询模式
      if (!query?.trim()) {
        return { content: 'Error: 必须提供 query 或 queries 参数', isError: true }
      }

      const resp = await fetchWithTimeout(
        `${base}/query`,
        { query: query.trim(), top_k: topK, no_code: hideCode },
        context.signal,
      ) as RadarOutput

      if (resp.error) {
        return { content: `WeaponRadar 错误: ${resp.error}`, isError: true }
      }
      if (!resp.results || resp.results.length === 0) {
        return { content: `武器库中未找到匹配 "${query}" 的 PoC，尝试换用不同关键词。`, isError: false }
      }

      return { content: formatSingleResult(resp), isError: false }

    } catch (err: unknown) {
      const e = err as Error
      if (e.name === 'AbortError') {
        return { content: 'WeaponRadar: 已取消', isError: true }
      }
      if (e.message?.includes('fetch failed') || e.message?.includes('ECONNREFUSED')) {
        return {
          content: `WeaponRadar: 无法连接 API 服务 ${base}\n请确认 weapon-radar 服务正在运行：systemctl status weapon-radar`,
          isError: true,
        }
      }
      return { content: `WeaponRadar 请求失败: ${e.message}`, isError: true }
    }
  }
}
