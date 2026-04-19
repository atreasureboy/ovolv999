/**
 * Tool registry — ovolv999 weaponization-focused agent plugin
 */

import type { Tool } from '../core/types.js'
import { BashTool } from './bash.js'
import { FileReadTool } from './fileRead.js'
import { FileWriteTool } from './fileWrite.js'
import { FileEditTool } from './fileEdit.js'
import { GlobTool } from './glob.js'
import { GrepTool } from './grep.js'
import { TodoWriteTool } from './todo.js'
import { WebFetchTool } from './webFetch.js'
import { WebSearchTool } from './webSearch.js'
import { AgentTool } from './agent.js'
import { TmuxSessionTool } from './tmuxSession.js'
import { ShellSessionTool } from './shellSession.js'
import { C2Tool } from './c2.js'
import { DocReadTool } from './docRead.js'
import { EnvAnalyzerTool } from './envAnalyzer.js'
import { TechniqueGeneratorTool } from './techniqueGenerator.js'
import { PayloadCompilerTool } from './payloadCompiler.js'
import { ShellcodeGenTool } from './shellcodeGen.js'
import { BinaryObfuscatorTool } from './binaryObfuscator.js'
import { PayloadDeliveryTool } from './payloadDelivery.js'

export function createTools(extraTools: Tool[] = []): Tool[] {
  return [
    new BashTool(),
    new FileReadTool(),
    new FileWriteTool(),
    new FileEditTool(),
    new GlobTool(),
    new GrepTool(),
    new TodoWriteTool(),
    new WebFetchTool(),
    new WebSearchTool(),
    new AgentTool(),
    new TmuxSessionTool(),
    new ShellSessionTool(),
    new C2Tool(),
    new DocReadTool(),
    new EnvAnalyzerTool(),
    new TechniqueGeneratorTool(),
    new PayloadCompilerTool(),
    new ShellcodeGenTool(),
    new BinaryObfuscatorTool(),
    new PayloadDeliveryTool(),
    ...extraTools,
  ]
}

export function getToolDefinitions(tools: Tool[]) {
  return tools.map((t) => t.definition)
}

export function findTool(tools: Tool[], name: string): Tool | undefined {
  return tools.find((t) => t.name === name)
}

export {
  DocReadTool,
  BashTool,
  FileReadTool,
  FileWriteTool,
  FileEditTool,
  GlobTool,
  GrepTool,
  TodoWriteTool,
  WebFetchTool,
  WebSearchTool,
  AgentTool,
  TmuxSessionTool,
  ShellSessionTool,
  C2Tool,
  EnvAnalyzerTool,
  TechniqueGeneratorTool,
  PayloadCompilerTool,
  ShellcodeGenTool,
  BinaryObfuscatorTool,
  PayloadDeliveryTool,
}
