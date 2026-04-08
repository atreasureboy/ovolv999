/**
 * Settings loader — reads .ovogo/settings.json from project and global dirs
 *
 * Config resolution order (later entries win):
 *   ~/.ovogo/settings.json   (global user defaults)
 *   .ovogo/settings.json     (project-specific, relative to cwd)
 *
 * Example settings.json:
 * {
 *   "hooks": {
 *     "PreToolCall": [
 *       { "matcher": "Bash", "command": "echo \"Running: $OVOGO_TOOL_INPUT\"" }
 *     ],
 *     "PostToolCall": [
 *       { "matcher": "Write,Edit", "command": "npx prettier --write \"$OVOGO_TOOL_NAME\" 2>/dev/null || true" }
 *     ],
 *     "UserPromptSubmit": [
 *       { "command": "logger -t ovogogogo \"prompt: $OVOGO_PROMPT\"" }
 *     ]
 *   }
 * }
 *
 * Hook env vars:
 *   PreToolCall:       OVOGO_TOOL_NAME, OVOGO_TOOL_INPUT (JSON)
 *   PostToolCall:      OVOGO_TOOL_NAME, OVOGO_TOOL_RESULT, OVOGO_TOOL_IS_ERROR
 *   UserPromptSubmit:  OVOGO_PROMPT
 */

import { readFileSync, existsSync } from 'fs'
import { resolve, join } from 'path'
import { homedir } from 'os'

export interface HookEntry {
  /** Comma-separated tool names to match, or "*" / omit for all. Supports trailing "*" wildcard. */
  matcher?: string
  /** Shell command to execute. Runs with tool env vars set. */
  command: string
}

export interface HooksConfig {
  PreToolCall?: HookEntry[]
  PostToolCall?: HookEntry[]
  UserPromptSubmit?: HookEntry[]
}

export interface OvogoSettings {
  hooks?: HooksConfig
}

function tryParse(path: string): OvogoSettings {
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as OvogoSettings
  } catch {
    return {}
  }
}

function mergeSettings(a: OvogoSettings, b: OvogoSettings): OvogoSettings {
  return {
    hooks: {
      PreToolCall: [...(a.hooks?.PreToolCall ?? []), ...(b.hooks?.PreToolCall ?? [])],
      PostToolCall: [...(a.hooks?.PostToolCall ?? []), ...(b.hooks?.PostToolCall ?? [])],
      UserPromptSubmit: [...(a.hooks?.UserPromptSubmit ?? []), ...(b.hooks?.UserPromptSubmit ?? [])],
    },
  }
}

export function loadSettings(cwd: string): OvogoSettings {
  const globalPath = join(homedir(), '.ovogo', 'settings.json')
  const projectPath = resolve(cwd, '.ovogo', 'settings.json')

  let settings: OvogoSettings = {}
  if (existsSync(globalPath)) settings = mergeSettings(settings, tryParse(globalPath))
  if (existsSync(projectPath)) settings = mergeSettings(settings, tryParse(projectPath))
  return settings
}
