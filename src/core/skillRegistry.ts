/**
 * SkillRegistry — phase-based dynamic tool loading/unloading
 *
 * Skills group tools by penetration testing phase. The engine activates
 * only the skills relevant to the current phase, reducing prompt size
 * and limiting tool exposure.
 */

import type { Tool, ToolDefinition } from './types.js'

export interface SkillDefinition {
  name: string
  description: string
  /** Which engagement phases this skill is active in */
  phases: string[]
  /** Tools provided by this skill */
  tools: Tool[]
}

export class SkillRegistry {
  private skills = new Map<string, SkillDefinition>()
  private activePhases = new Set<string>()

  /** Register a skill definition */
  register(skill: SkillDefinition): void {
    this.skills.set(skill.name, skill)
  }

  /** Set the current engagement phases */
  setPhases(phases: string[]): void {
    this.activePhases = new Set(phases)
  }

  /** Get all tools active in the current phases */
  getActiveTools(): Tool[] {
    const tools: Tool[] = []
    for (const skill of this.skills.values()) {
      if (skill.phases.some((p) => this.activePhases.has(p))) {
        tools.push(...skill.tools)
      }
    }
    return tools
  }

  /** Get tool definitions for active skills (for LLM tool injection) */
  getActiveToolDefinitions(): ToolDefinition[] {
    return this.getActiveTools().map((t) => t.definition)
  }

  /** Get all registered skill names */
  getSkillNames(): string[] {
    return Array.from(this.skills.keys())
  }

  /** Check if a specific skill is active in current phases */
  isSkillActive(name: string): boolean {
    const skill = this.skills.get(name)
    if (!skill) return false
    return skill.phases.some((p) => this.activePhases.has(p))
  }
}
