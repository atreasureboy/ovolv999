/**
 * ContextBudgetManager — explicit token budget allocation for different
 * sections of the prompt, with runtime compression strategy selection.
 *
 * Replaces the flat percentage-based thresholds (70% warn / 85% compact)
 * with granular budget control per section.
 */

export type CompressionStrategy = 'proportional' | 'priority' | 'aggressive'

export interface ContextBudgetConfig {
  maxTokens: number
  systemPrompt: number     // reserved for system prompt
  memory: number           // reserved for memory entries
  history: number          // variable: recent messages
  toolResults: number      // variable: recent tool results
  reserved: number         // reserved for LLM output
}

export interface BudgetState {
  currentTokens: number
  maxTokens: number
  pct: number
  strategy: CompressionStrategy
  shouldCompact: boolean
  shouldWarn: boolean
  /** How many tokens to trim from each section under current strategy */
  trimTargets: {
    history: number
    toolResults: number
    memory: number
  }
}

export class ContextBudgetManager {
  private config: ContextBudgetConfig

  constructor(config: ContextBudgetConfig) {
    this.config = config
  }

  /** Evaluate current token usage against budget */
  evaluate(currentTokens: number): BudgetState {
    const pct = currentTokens / this.config.maxTokens
    const available = this.config.maxTokens - this.config.systemPrompt - this.config.reserved

    // Determine strategy based on pressure
    let strategy: CompressionStrategy
    if (pct > 0.9) {
      strategy = 'aggressive'
    } else if (pct > 0.75) {
      strategy = 'priority'
    } else {
      strategy = 'proportional'
    }

    const shouldWarn = pct > 0.6
    const shouldCompact = pct > 0.75

    // Calculate trim targets based on strategy
    const trimTargets = this.calculateTrimTargets(currentTokens, available, strategy)

    return {
      currentTokens,
      maxTokens: this.config.maxTokens,
      pct,
      strategy,
      shouldCompact,
      shouldWarn,
      trimTargets,
    }
  }

  private calculateTrimTargets(
    currentTokens: number,
    availableBudget: number,
    strategy: CompressionStrategy,
  ): { history: number; toolResults: number; memory: number } {
    const overBudget = currentTokens - availableBudget
    if (overBudget <= 0) {
      return { history: 0, toolResults: 0, memory: 0 }
    }

    switch (strategy) {
      case 'aggressive':
        // Trim 80% from history, 15% from tool results, 5% from memory
        return {
          history: Math.ceil(overBudget * 0.8),
          toolResults: Math.ceil(overBudget * 0.15),
          memory: Math.ceil(overBudget * 0.05),
        }
      case 'priority':
        // Trim 50% from history, 35% from tool results, 15% from memory
        return {
          history: Math.ceil(overBudget * 0.5),
          toolResults: Math.ceil(overBudget * 0.35),
          memory: Math.ceil(overBudget * 0.15),
        }
      case 'proportional':
        // Equal proportional trim
        return {
          history: Math.ceil(overBudget * 0.4),
          toolResults: Math.ceil(overBudget * 0.4),
          memory: Math.ceil(overBudget * 0.2),
        }
    }
  }

  /** Get the current budget config */
  getConfig(): ContextBudgetConfig {
    return { ...this.config }
  }

  /** Update the max tokens (e.g. if model context changes) */
  updateMaxTokens(maxTokens: number): void {
    this.config = { ...this.config, maxTokens }
  }
}
