/**
 * Think-Act-Observe Engine — streaming tool execution
 *
 * 1. Parallel tool execution
 *    Read-only tools (Read/Glob/Grep) are batched and run with Promise.all.
 *    Write/exec tools run serially.
 *
 * 2. AbortController per turn
 *    engine.abort() cancels the current turn at any point.
 *
 * 3. Hook callbacks around every tool call.
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
import type { Renderer } from '../ui/renderer.js'

const MAX_TOOL_RESULT_LENGTH = 20_000

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

/**
 * Concurrency-safe tools: run in parallel within a single LLM response.
 */
const CONCURRENCY_SAFE_TOOLS = new Set([
  'Read', 'Glob', 'Grep',
  'TmuxSession',
  'ShellSession',
  'C2',
  'TechniqueGenerator',
])

/**
 * Tools whose results must never be cached.
 */
const NO_CACHE_TOOLS = new Set([
  'Bash', 'TmuxSession', 'ShellSession', 'C2',
  'Write', 'Edit', 'FileEdit',
  'Read', 'Glob', 'Grep',
  'TechniqueGenerator',
])

/**
 * Partition tool calls into batches for scheduling.
 */
function partitionToolCalls(calls: ParsedToolCall[]): ToolBatch[] {
  const batches: ToolBatch[] = []
  for (const call of calls) {
    const safe = CONCURRENCY_SAFE_TOOLS.has(call.tc.name)
    const last = batches[batches.length - 1]
    if (last && last.safe && safe) {
      last.calls.push(call)
    } else {
      batches.push({ safe, calls: [call] })
    }
  }
  return batches
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

export class ExecutionEngine {
  private client: OpenAI
  private tools: Tool[]
  private config: EngineConfig
  private renderer: Renderer
  private currentTurnAbortController: AbortController | null = null
  private softAbortRequested = false

  constructor(config: EngineConfig, renderer: Renderer) {
    this.config = config
    this.renderer = renderer
    this.client = new OpenAI({
      apiKey: config.apiKey,
      baseURL: config.baseURL,
    })
    this.tools = createTools(config.extraTools ?? [])
  }

  abort(): void {
    this.currentTurnAbortController?.abort('user_cancelled')
  }

  softAbort(): void {
    this.softAbortRequested = true
  }

  /**
   * Execute a single user turn with streaming output.
   * Full Think → Act → Observe loop.
   */
  async runTurn(
    userMessage: string,
    history: OpenAIMessage[],
  ): Promise<{ result: TurnResult; newHistory: OpenAIMessage[] }> {
    const baseSystemPrompt = this.config.systemPrompt ?? ''

    const turnAbortController = new AbortController()
    this.currentTurnAbortController = turnAbortController

    const toolContext: ToolContext = {
      cwd: this.config.cwd,
      permissionMode: this.config.permissionMode,
      signal: turnAbortController.signal,
      apiConfig: {
        apiKey: this.config.apiKey,
        baseURL: this.config.baseURL,
        model: this.config.model,
      },
      sessionDir: this.config.sessionDir,
    }

    const messages: OpenAIMessage[] = [
      ...history,
      { role: 'user', content: userMessage },
    ]

    const toolDefs = getToolDefinitions(this.tools)

    let iterations = 0
    let finalOutput = ''

    try {
      while (iterations < this.config.maxIterations) {
        if (turnAbortController.signal.aborted) {
          return {
            result: { stopped: true, reason: 'error', output: finalOutput },
            newHistory: messages,
          }
        }

        iterations++

        if (this.softAbortRequested) {
          this.softAbortRequested = false
          return {
            result: { stopped: true, reason: 'interrupted', output: finalOutput },
            newHistory: messages,
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
                { role: 'system', content: baseSystemPrompt },
                ...(messages as OpenAI.Chat.ChatCompletionMessageParam[]),
              ],
              tools: toolDefs as OpenAI.Chat.ChatCompletionTool[],
              tool_choice: 'auto',
              temperature: 0,
              max_tokens: 8192,
              stream: true,
            },
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
            for (const { tc, input } of batch.calls) {
              this.renderer.toolStart(tc.name, input)
              this.config.hookRunner?.runPreToolCall(tc.name, input)
            }

            const results = await Promise.all(
              batch.calls.map(({ tc, input }) =>
                this.executeToolCall(tc.name, input, toolContext),
              ),
            )

            for (let i = 0; i < batch.calls.length; i++) {
              const { tc } = batch.calls[i]
              const result = results[i]
              this.config.hookRunner?.runPostToolCall(tc.name, result.content, result.isError)
              this.renderer.toolResult(tc.name, result.content, result.isError)
              messages.push({
                role: 'tool',
                tool_call_id: tc.id,
                content: truncateToolResult(result.content),
                name: tc.name,
              })
            }
          } else {
            for (const { tc, input } of batch.calls) {
              if (turnAbortController.signal.aborted) break

              this.renderer.toolStart(tc.name, input)
              this.config.hookRunner?.runPreToolCall(tc.name, input)

              const result = await this.executeToolCall(tc.name, input, toolContext)

              this.config.hookRunner?.runPostToolCall(tc.name, result.content, result.isError)
              this.renderer.toolResult(tc.name, result.content, result.isError)

              messages.push({
                role: 'tool',
                tool_call_id: tc.id,
                content: truncateToolResult(result.content),
                name: tc.name,
              })

              if (this.softAbortRequested) {
                this.softAbortRequested = false
                return {
                  result: { stopped: true, reason: 'interrupted', output: finalOutput },
                  newHistory: messages,
                }
              }
            }
          }

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
  ): Promise<ToolResult> {
    const tool = findTool(this.tools, toolName)
    if (!tool) {
      return { content: `Unknown tool: ${toolName}`, isError: true }
    }

    const result = await tool.execute(input, context)

    if (!result.isError && !NO_CACHE_TOOLS.has(toolName)) {
      // Simple in-memory cache for non-volatile tools
      // Could be expanded later if needed
    }

    return result
  }

  getModel(): string {
    return this.config.model
  }
}
