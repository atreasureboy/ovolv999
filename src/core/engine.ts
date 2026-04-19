/**
 * Think-Act-Observe Engine — with streaming output
 *
 * Key improvements over naïve implementation:
 *
 * 1. Parallel tool execution
 *    Read-only tools (Read/Glob/Grep/WebFetch/WebSearch) are batched and run
 *    with Promise.all.  Write/exec tools run serially.
 *
 * 2. AbortController per turn
 *    engine.abort() cancels the current turn at any point — including inside
 *    long-running Bash commands and network fetches.
 *
 * 3. Plan mode — only read-only tools are exposed/executed.
 *
 * 4. Hook callbacks around every tool call.
 *
 * 5. Critic loop — every CRITIC_INTERVAL iterations a lightweight LLM call
 *    reviews recent context for common failure modes and injects corrections
 *    as a user message before the next main LLM call.
 */

import OpenAI from 'openai'
import type {
  EngineConfig,
  OpenAIMessage,
  Tool,
  ToolContext,
  ToolResult,
  TurnResult,
} from './types.js'
import { createTools, findTool, getToolDefinitions } from '../tools/index.js'
import { getPlanModePrefix } from '../prompts/system.js'
import type { Renderer } from '../ui/renderer.js'
import { maybeCompact, calculateContextState, MODEL_MAX_CONTEXT_TOKENS } from './compact.js'
import { ContextBudgetManager, CompressionStrategy } from './contextBudget.js'

const MAX_TOOL_RESULT_LENGTH = 20_000

// ── Critic configuration ─────────────────────────────────────────────────────
/** Run critic every N iterations (only when there are enough messages to review) */
const CRITIC_INTERVAL = 5
/** Don't bother before this many iterations */
const CRITIC_MIN_ITERATIONS = 4
/** How many recent messages to feed the critic */
const CRITIC_CONTEXT_MESSAGES = 24
/** Max tokens the critic can produce */
const CRITIC_MAX_TOKENS = 400

const CRITIC_SYSTEM_PROMPT = `你是一个二进制武器化会话的批判性监督 agent。
你只阅读操作历史，不执行操作。你的职责是发现以下常见失误并给出简短纠正：

1. **绕过缺失** — 针对已知防护（WAF/EDR/AMSI）没有先执行绕过就投递 payload
2. **技术栈偏离** — 生成的 payload 指纹明显、无随机化、未参考 Havoc/Sliver/APT28 技术
3. **EnvAnalyzer 未执行** — 对新目标没有先做环境检测就直接武器化
4. **TechniqueGenerator 滥用** — 多次生成相同技术的 payload 没有引入新绕过组合
5. **交互式进程阻塞** — 使用 msfconsole/sliver 等交互式进程但未用 TmuxSession，导致 Bash 调用超时
6. **防御者思维** — 输出了"建议修复"/"加固配置"等内容，这是红队工具，只攻不守
7. **文件未保存** — 生成的 payload/脚本没有保存到 session 目录
8. **重复劳动** — 正在重复已经完成过的操作

输出规则：
- 发现问题：用 "⚠️ [问题] {描述}" + "↳ [纠正] {具体应执行什么}" 格式，最多 3 条
- 没有问题：只输出 "OK"
- 不解释你的角色，不废话，直接结论`

function formatMessagesForCritic(messages: OpenAIMessage[]): string {
  return messages
    .map((m) => {
      if (m.role === 'assistant') {
        const toolCalls = (m as { tool_calls?: Array<{ function: { name: string; arguments: string } }> }).tool_calls
        if (toolCalls && toolCalls.length > 0) {
          const calls = toolCalls
            .map((tc) => {
              let args: Record<string, unknown>
              try { args = JSON.parse(tc.function.arguments) } catch { args = {} }
              // Truncate large fields (e.g. poc_code in WeaponRadar results)
              const truncated = Object.fromEntries(
                Object.entries(args).map(([k, v]) => [
                  k,
                  typeof v === 'string' && v.length > 300 ? v.slice(0, 300) + '…' : v,
                ]),
              )
              return `  [TOOL_CALL] ${tc.function.name}(${JSON.stringify(truncated)})`
            })
            .join('\n')
          const text = typeof m.content === 'string' && m.content ? `  ${m.content}\n` : ''
          return `[ASSISTANT]\n${text}${calls}`
        }
        return `[ASSISTANT] ${m.content ?? ''}`
      }
      if (m.role === 'tool') {
        const content = typeof m.content === 'string' ? m.content.slice(0, 800) : ''
        const name = (m as { name?: string }).name ?? 'tool'
        return `[TOOL_RESULT:${name}] ${content}${content.length >= 800 ? '…' : ''}`
      }
      if (m.role === 'user') {
        const content = typeof m.content === 'string' ? m.content.slice(0, 400) : ''
        return `[USER] ${content}`
      }
      return ''
    })
    .filter(Boolean)
    .join('\n')
}

function truncateToolResult(result: string): string {
  if (result.length <= MAX_TOOL_RESULT_LENGTH) return result
  const half = MAX_TOOL_RESULT_LENGTH / 2
  return (
    result.slice(0, half) +
    `\n\n[... ${result.length - MAX_TOOL_RESULT_LENGTH} chars truncated ...]\n\n` +
    result.slice(result.length - half)
  )
}

// Accumulated tool call during streaming
interface StreamingToolCall {
  index: number
  id: string
  name: string
  arguments: string
}

// Parsed tool call ready for execution
interface ParsedToolCall {
  tc: StreamingToolCall
  input: Record<string, unknown>
}

// Tool batch for parallel vs serial scheduling
interface ToolBatch {
  safe: boolean
  calls: ParsedToolCall[]
}

/** Plan mode — tools allowed in read-only analysis */
const PLAN_MODE_TOOLS = new Set(['Read', 'Glob', 'Grep', 'WebFetch', 'WebSearch'])

/**
 * Concurrency-safe tools: run in parallel within a single LLM response.
 *
 * Rule: if the LLM emits multiple tool calls in one response, it intends them
 * to be independent — execute them all concurrently (Promise.all).
 *
 * Serial exceptions (own batch): Write, Edit — these mutate shared state.
 */
const CONCURRENCY_SAFE_TOOLS = new Set([
  'Read', 'Glob', 'Grep', 'WebFetch', 'WebSearch',
  'Bash',        // parallel — dependent ops should be chained with && in one call
  'Agent',       // parallel — multiple sub-agents run simultaneously via Promise.all
  'ShellSession', // parallel — listen / list / exec on different sessions
  'TmuxSession',  // parallel — new / list / capture on different sessions
])

/**
 * Partition tool calls into batches for scheduling:
 * - All tools in CONCURRENCY_SAFE_TOOLS → merged into one parallel batch (Promise.all)
 * - Write / Edit / FindingWrite and other stateful tools → own serial batch
 */
function partitionToolCalls(calls: ParsedToolCall[]): ToolBatch[] {
  const batches: ToolBatch[] = []

  for (const call of calls) {
    const safe = CONCURRENCY_SAFE_TOOLS.has(call.tc.name)
    const last = batches[batches.length - 1]

    if (last && last.safe && safe) {
      last.calls.push(call)   // extend existing parallel batch
    } else {
      batches.push({ safe, calls: [call] })  // new batch
    }
  }

  return batches
}

export class ExecutionEngine {
  private client: OpenAI
  private tools: Tool[]
  private config: EngineConfig
  private renderer: Renderer
  /** Abort controller for the current turn — null when idle */
  private currentTurnAbortController: AbortController | null = null
  /** Soft-interrupt flag: pause after current tool finishes, preserve history */
  private softAbortRequested = false
  /** Event log — may be undefined if not configured */
  private eventLog: EngineConfig['eventLog']
  /** Context budget manager — may be undefined if not configured */
  private contextBudget: EngineConfig['contextBudget']

  constructor(config: EngineConfig, renderer: Renderer) {
    this.config = config
    this.renderer = renderer
    this.client = new OpenAI({
      apiKey: config.apiKey,
      baseURL: config.baseURL,
    })
    this.tools = createTools(config.extraTools ?? [])
    this.eventLog = config.eventLog
    this.contextBudget = config.contextBudget
  }

  /**
   * Hard cancel — immediately aborts in-flight API calls and tool executions.
   * Propagates via AbortSignal into Bash (kills process group) and WebFetch.
   */
  abort(): void {
    this.currentTurnAbortController?.abort('user_cancelled')
  }

  /**
   * Soft interrupt — sets a flag the main loop checks at the START of each
   * iteration (after current tool finishes).  Causes runTurn() to return
   * with reason='interrupted' while preserving the full conversation history,
   * allowing the caller to inject a user message and resume.
   */
  softAbort(): void {
    this.softAbortRequested = true
  }

  /**
   * Run a lightweight critic check over recent conversation history.
   * Returns a correction string to inject, or null if everything looks fine.
   * Errors are swallowed — critic failures must never break the main loop.
   */
  private async runCriticCheck(messages: OpenAIMessage[]): Promise<string | null> {
    const recent = messages.slice(-CRITIC_CONTEXT_MESSAGES)
    if (recent.length < 4) return null

    try {
      const response = await this.client.chat.completions.create({
        model: this.config.model,
        messages: [
          { role: 'system', content: CRITIC_SYSTEM_PROMPT },
          {
            role: 'user',
            content: `以下是最近的操作历史，请检查是否存在失误：\n\n${formatMessagesForCritic(recent)}`,
          },
        ],
        temperature: 0,
        max_tokens: CRITIC_MAX_TOKENS,
      })

      const output = response.choices[0]?.message?.content?.trim() ?? ''
      if (!output || /^ok$/i.test(output)) return null
      return output
    } catch {
      return null
    }
  }

  /**
   * Execute a single user turn with streaming output.
   * Full Think → Act → Observe loop.
   */
  async runTurn(
    userMessage: string,
    history: OpenAIMessage[],
  ): Promise<{ result: TurnResult; newHistory: OpenAIMessage[] }> {
    const planMode = this.config.planMode ?? false

    // Build system prompt: optional plan-mode prefix + pre-assembled prompt
    const baseSystemPrompt = this.config.systemPrompt ?? ''
    const systemPrompt = planMode
      ? getPlanModePrefix() + baseSystemPrompt
      : baseSystemPrompt

    // Per-turn AbortController — cancelled by engine.abort() or SIGINT
    const turnAbortController = new AbortController()
    this.currentTurnAbortController = turnAbortController

    const toolContext: ToolContext = {
      cwd: this.config.cwd,
      permissionMode: this.config.permissionMode,
      signal: turnAbortController.signal,
      // Forward API config so vision/doc tools can make their own LLM calls
      apiConfig: {
        apiKey: this.config.apiKey,
        baseURL: this.config.baseURL,
        model: this.config.model,
      },
      // Inject sessionDir for tools that need anchor updates
      sessionDir: this.config.sessionDir,
      // Inject new systems into tool context
      eventLog: this.eventLog,
      semanticMemory: this.config.semanticMemory,
      episodicMemory: this.config.episodicMemory,
    }

    const messages: OpenAIMessage[] = [
      ...history,
      { role: 'user', content: userMessage },
    ]

    // In plan mode, only expose read-only tools
    const allToolDefs = getToolDefinitions(this.tools)
    let toolDefs = allToolDefs
    if (planMode) {
      toolDefs = allToolDefs.filter((t) => PLAN_MODE_TOOLS.has(t.function.name))
    }

    let iterations = 0
    let finalOutput = ''

    try {
      while (iterations < this.config.maxIterations) {
        // Check for cancellation at the top of each loop
        if (turnAbortController.signal.aborted) {
          return {
            result: { stopped: true, reason: 'error', output: finalOutput },
            newHistory: messages,
          }
        }

        iterations++

        // ── Soft-interrupt check — pause after current tool, preserve history ─
        if (this.softAbortRequested) {
          this.softAbortRequested = false
          return {
            result: { stopped: true, reason: 'interrupted', output: finalOutput },
            newHistory: messages,
          }
        }

        // ── Context stats + auto-compact ────────────────────────
        const maxCtxTokens = this.config.maxContextTokens ?? MODEL_MAX_CONTEXT_TOKENS

        // Use ContextBudgetManager if available, else fall back to percentage-based thresholds
        const baseCtxState = calculateContextState(messages, maxCtxTokens)
        let ctxState: ReturnType<typeof calculateContextState> & { strategy?: CompressionStrategy }
        if (this.contextBudget) {
          const budgetState = this.contextBudget.evaluate(baseCtxState.currentTokens)
          ctxState = {
            ...baseCtxState,
            strategy: budgetState.strategy,
            shouldCompact: budgetState.shouldCompact,
            shouldWarn: budgetState.shouldWarn,
          }
        } else {
          ctxState = baseCtxState as ReturnType<typeof calculateContextState> & { strategy?: CompressionStrategy }
        }

        // Show context stats every 5 iterations (main agent only, not sub-agents)
        if (this.config.sessionDir && iterations % 5 === 0) {
          this.renderer.contextStats(ctxState.currentTokens, ctxState.maxTokens, ctxState.pct)
        }

        if (ctxState.shouldCompact) {
          this.renderer.compactStart(ctxState.currentTokens)
          this.eventLog?.append('context_compact', 'engine', {
            strategy: ctxState.strategy,
            tokens_before: ctxState.currentTokens,
            pct: ctxState.pct,
          })
          const compactResult = await maybeCompact(this.client, this.config.model, messages, undefined, this.config.sessionDir)
          if (compactResult.compacted) {
            messages.length = 0
            messages.push(...compactResult.messages)
            this.renderer.compactDone(compactResult.originalTokens, compactResult.summaryTokens)
            this.eventLog?.append('context_compact', 'engine', {
              tokens_after: compactResult.summaryTokens,
              reduction: compactResult.originalTokens - compactResult.summaryTokens,
            })
          }
        } else if (ctxState.shouldWarn) {
          this.renderer.contextWarning(ctxState.currentTokens, ctxState.maxTokens, ctxState.pct)
        }

        // ── Critic injection — every CRITIC_INTERVAL iterations ──
        // Only for the main agent (not sub-agents) to avoid recursive critic calls.
        // Sub-agents have shorter maxIterations and no sessionDir typically.
        if (
          iterations >= CRITIC_MIN_ITERATIONS &&
          iterations % CRITIC_INTERVAL === 0 &&
          !planMode &&
          this.config.sessionDir  // only main agent has sessionDir
        ) {
          const criticism = await this.runCriticCheck(messages)
          if (criticism) {
            this.renderer.warn(`[批判检查] ${criticism.split('\n')[0]}`)
            this.eventLog?.append('critic_flag', 'critic', {
              criticism: criticism.slice(0, 500),
              iteration: iterations,
            })
            messages.push({
              role: 'user',
              content: `[🔍 自动纠错检查]\n${criticism}\n\n请根据以上纠错提示立即调整行动。`,
            })
          }
        }

        // ── Streaming API call ───────────────────────────────────
        this.renderer.startSpinner()

        let stream: AsyncIterable<OpenAI.Chat.ChatCompletionChunk>
        try {
          stream = await this.client.chat.completions.create(
            {
              model: this.config.model,
              messages: [
                { role: 'system', content: systemPrompt },
                ...(messages as OpenAI.Chat.ChatCompletionMessageParam[]),
              ],
              tools: toolDefs as OpenAI.Chat.ChatCompletionTool[],
              tool_choice: 'auto',
              temperature: 0,
              max_tokens: 8192,
              stream: true,
            },
            // Pass abort signal to the HTTP request
            { signal: turnAbortController.signal },
          )
        } catch (err: unknown) {
          this.renderer.stopSpinner()
          const error = err as Error
          if (error.name === 'AbortError' || turnAbortController.signal.aborted) {
            return {
              result: { stopped: true, reason: 'error', output: finalOutput },
              newHistory: messages,
            }
          }
          this.renderer.error(`API error: ${error.message}`)
          return {
            result: { stopped: true, reason: 'error', output: error.message },
            newHistory: messages,
          }
        }

        // ── Consume stream ───────────────────────────────────────
        let assistantText = ''
        let finishReason: string | null = null
        const toolCallsMap = new Map<number, StreamingToolCall>()
        let firstToken = true

        try {
          for await (const chunk of stream) {
            if (turnAbortController.signal.aborted) break

            const delta = chunk.choices[0]?.delta
            if (!delta) continue

            if (delta.content) {
              if (firstToken) {
                this.renderer.stopSpinner()
                this.renderer.beginAssistantText()
                firstToken = false
              }
              this.renderer.streamToken(delta.content)
              assistantText += delta.content
            }

            if (delta.tool_calls) {
              for (const tc of delta.tool_calls) {
                const idx = tc.index
                if (!toolCallsMap.has(idx)) {
                  toolCallsMap.set(idx, { index: idx, id: '', name: '', arguments: '' })
                }
                const acc = toolCallsMap.get(idx)!
                if (tc.id) acc.id = tc.id
                if (tc.function?.name) acc.name += tc.function.name
                if (tc.function?.arguments) acc.arguments += tc.function.arguments
              }
            }

            if (chunk.choices[0]?.finish_reason) {
              finishReason = chunk.choices[0].finish_reason
            }
          }
        } catch (err: unknown) {
          this.renderer.stopSpinner()
          const error = err as Error
          if (error.name === 'AbortError' || turnAbortController.signal.aborted) {
            return {
              result: { stopped: true, reason: 'error', output: finalOutput },
              newHistory: messages,
            }
          }
          this.renderer.error(`Stream error: ${error.message}`)
          return {
            result: { stopped: true, reason: 'error', output: error.message },
            newHistory: messages,
          }
        }

        this.renderer.stopSpinner()

        if (assistantText) {
          this.renderer.endAssistantText()
          finalOutput = assistantText
        }

        const rawToolCalls = Array.from(toolCallsMap.values()).sort((a, b) => a.index - b.index)

        const assistantMsg: OpenAIMessage = {
          role: 'assistant',
          content: assistantText || null,
          tool_calls: rawToolCalls.length > 0
            ? rawToolCalls.map((tc) => ({
                id: tc.id,
                type: 'function' as const,
                function: { name: tc.name, arguments: tc.arguments },
              }))
            : undefined,
        }
        messages.push(assistantMsg)

        if (finishReason === 'stop' || rawToolCalls.length === 0) {
          return {
            result: { stopped: true, reason: 'stop_sequence', output: finalOutput },
            newHistory: messages,
          }
        }

        // ── Parse inputs ─────────────────────────────────────────
        const parsedCalls: ParsedToolCall[] = rawToolCalls.map((tc) => {
          let input: Record<string, unknown>
          try {
            input = JSON.parse(tc.arguments || '{}') as Record<string, unknown>
          } catch {
            input = {}
          }
          return { tc, input }
        })

        // ── Schedule: parallel (safe) vs serial (unsafe) ─────────
        const batches = partitionToolCalls(parsedCalls)

        for (const batch of batches) {
          if (turnAbortController.signal.aborted) break

          if (batch.safe && batch.calls.length > 1) {
            // ── Parallel batch ───────────────────────────────────
            // Show all tool starts up front
            for (const { tc, input } of batch.calls) {
              this.renderer.toolStart(tc.name, input)
              this.config.hookRunner?.runPreToolCall(tc.name, input)
              this.eventLog?.append('tool_call', tc.name, { input }, [tc.name])
            }

            // Execute concurrently
            const results = await Promise.all(
              batch.calls.map(({ tc, input }) =>
                this.executeToolCall(tc.name, input, toolContext, planMode),
              ),
            )

            // Collect results in original order
            for (let i = 0; i < batch.calls.length; i++) {
              const { tc } = batch.calls[i]
              const result = results[i]
              this.config.hookRunner?.runPostToolCall(tc.name, result.content, result.isError)
              this.renderer.toolResult(tc.name, result.content, result.isError)
              this.eventLog?.append('tool_result', tc.name, { content: result.content.slice(0, 500), isError: result.isError }, [tc.name, result.isError ? 'error' : 'success'])
              messages.push({
                role: 'tool',
                tool_call_id: tc.id,
                content: truncateToolResult(result.content),
                name: tc.name,
              })
            }
          } else {
            // ── Serial batch ─────────────────────────────────────
            for (const { tc, input } of batch.calls) {
              if (turnAbortController.signal.aborted) break

              this.renderer.toolStart(tc.name, input)
              this.config.hookRunner?.runPreToolCall(tc.name, input)
              this.eventLog?.append('tool_call', tc.name, { input }, [tc.name])

              const result = await this.executeToolCall(tc.name, input, toolContext, planMode)

              this.config.hookRunner?.runPostToolCall(tc.name, result.content, result.isError)
              this.renderer.toolResult(tc.name, result.content, result.isError)
              this.eventLog?.append('tool_result', tc.name, { content: result.content.slice(0, 500), isError: result.isError }, [tc.name, result.isError ? 'error' : 'success'])

              messages.push({
                role: 'tool',
                tool_call_id: tc.id,
                content: truncateToolResult(result.content),
                name: tc.name,
              })

              // ── Soft-interrupt check after each serial tool ──────
              // Checked here (not just at iteration start) so ESC takes
              // effect after the current tool, not after the full batch.
              if (this.softAbortRequested) {
                this.softAbortRequested = false
                return {
                  result: { stopped: true, reason: 'interrupted', output: finalOutput },
                  newHistory: messages,
                }
              }
            }
          }

          // ── Soft-interrupt check after each batch (parallel too) ─
          if (this.softAbortRequested) {
            this.softAbortRequested = false
            return {
              result: { stopped: true, reason: 'interrupted', output: finalOutput },
              newHistory: messages,
            }
          }
        }
      }
    } finally {
      this.currentTurnAbortController = null
    }

    this.renderer.warn(`Max iterations (${this.config.maxIterations}) reached`)
    return {
      result: { stopped: true, reason: 'max_iterations', output: finalOutput },
      newHistory: messages,
    }
  }

  private async executeToolCall(
    toolName: string,
    input: Record<string, unknown>,
    context: ToolContext,
    planMode = false,
  ): Promise<ToolResult> {
    // In plan mode, block write tools (defence in depth — tool defs already filtered)
    if (planMode && !PLAN_MODE_TOOLS.has(toolName)) {
      return {
        content: `Tool "${toolName}" is not available in plan mode. Only read-only tools are allowed. Output your plan as text.`,
        isError: true,
      }
    }

    const tool = findTool(this.tools, toolName)
    if (!tool) {
      return { content: `Unknown tool: ${toolName}`, isError: true }
    }

    const result = await tool.execute(input, context)

    // Write episodic memory entry
    const epiMem = this.config.episodicMemory
    if (epiMem && !result.isError) {
      epiMem.write({
        turn: 0,
        toolName,
        inputSummary: JSON.stringify(input).slice(0, 200),
        resultSummary: result.content.slice(0, 300),
        outcome: 'success',
        timestamp: new Date().toISOString(),
      })
    }

    return result
  }

  getModel(): string {
    return this.config.model
  }
}
