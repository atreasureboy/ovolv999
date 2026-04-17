/**
 * Vuln Scan Skill — tools for vulnerability scanning phase
 */

import { SkillDefinition } from '../core/skillRegistry.js'
import { BashTool } from '../tools/bash.js'
import { WebFetchTool } from '../tools/webFetch.js'
import { WebSearchTool } from '../tools/webSearch.js'
import { FileReadTool } from '../tools/fileRead.js'
import { FileWriteTool } from '../tools/fileWrite.js'
import { FindingWriteTool, FindingListTool } from '../tools/finding.js'
import { WeaponRadarTool } from '../tools/weaponRadar.js'
import { GlobTool } from '../tools/glob.js'
import { GrepTool } from '../tools/grep.js'

export const vulnScanSkill: SkillDefinition = {
  name: 'vuln-scan',
  description: '漏洞扫描工具集：Bash、WeaponRadar、Finding 管理',
  phases: ['vuln-scan', 'web-vuln', 'service-vuln', 'auth-attack', 'phase2', 'phase:scanning'],
  tools: [
    new BashTool(),
    new WeaponRadarTool(),
    new FindingWriteTool(),
    new FindingListTool(),
    new WebFetchTool(),
    new WebSearchTool(),
    new FileReadTool(),
    new FileWriteTool(),
    new GlobTool(),
    new GrepTool(),
  ],
}
