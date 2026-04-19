/**
 * Recon Skill — tools for reconnaissance phase
 *
 * Phases: recon, dns-recon, port-scan, web-probe, osint
 */

import { SkillDefinition } from '../core/skillRegistry.js'
import { BashTool } from '../tools/bash.js'
import { WebFetchTool } from '../tools/webFetch.js'
import { WebSearchTool } from '../tools/webSearch.js'
import { GlobTool } from '../tools/glob.js'
import { GrepTool } from '../tools/grep.js'
import { FileReadTool } from '../tools/fileRead.js'
import { FileWriteTool } from '../tools/fileWrite.js'

export const reconSkill: SkillDefinition = {
  name: 'recon',
  description: '侦察工具集：Bash、WebSearch、WebFetch、文件读写',
  phases: ['recon', 'dns-recon', 'port-scan', 'web-probe', 'osint', 'phase1', 'phase:recon'],
  tools: [
    new BashTool(),
    new WebSearchTool(),
    new WebFetchTool(),
    new FileReadTool(),
    new FileWriteTool(),
    new GlobTool(),
    new GrepTool(),
  ],
}
