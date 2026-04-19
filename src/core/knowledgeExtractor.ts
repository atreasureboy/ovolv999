/**
 * KnowledgeExtractor — rule-based knowledge extraction from agent sessions
 *
 * Extracts attack patterns, CVE notes, tool combos, and target profiles from:
 * 1. Real-time: each successful tool execution (extractFromToolResult)
 * 2. Session-end: full event log analysis (extractFromSession)
 *
 * Rule-based extraction — zero LLM cost, instant.
 */

import type { KnowledgeBase, CveNoteEntry, ToolComboEntry, AttackPatternEntry, TargetProfileEntry } from './knowledgeBase.js'
import type { EventLogEntry } from './eventLog.js'

// Known CVE regex patterns in tool input/output
const CVE_REGEX = /CVE-\d{4}-\d{4,}/gi
const KNOWN_CVE_SERVICES: Record<string, string[]> = {
  // 2017-2021
  'CVE-2017-5638': ['Apache Struts2', 'OGNL RCE'],
  'CVE-2017-12615': ['Apache Tomcat', '远程文件上传'],
  'CVE-2018-11776': ['Apache Struts2', '命名空间绕过'],
  'CVE-2018-19585': ['GitLab', '邮件导入 SSRF'],
  'CVE-2019-0193': ['Apache Solr', 'DataImportHandler RCE'],
  'CVE-2019-0230': ['Apache Struts2', 'S2-059 OGNL'],
  'CVE-2019-17558': ['Apache Solr', 'Velocity RCE'],
  'CVE-2019-19781': ['Citrix ADC', '路径遍历'],
  'CVE-2020-1472': ['Windows', 'Zerologon 域控提权'],
  'CVE-2020-1938': ['Apache Tomcat', 'Ghostcat AJP 文件包含'],
  'CVE-2021-21972': ['VMware vCenter', 'SSRF → RCE'],
  'CVE-2021-25646': ['Apache Druid', 'RCE'],
  'CVE-2021-26855': ['Exchange Server', 'ProxyLogon SSRF'],
  'CVE-2021-3129': ['Laravel', 'Ignition 反序列化 RCE'],
  'CVE-2021-34527': ['Windows PrintNightmare', '远程代码执行'],
  'CVE-2021-35464': ['Atlassian Bamboo', 'SSRF'],
  'CVE-2021-41773': ['Apache HTTPD', '路径遍历 RCE'],
  'CVE-2021-42013': ['Apache HTTPD 2.4.50', '路径遍历 RCE'],
  'CVE-2021-44228': ['Log4Shell', 'JNDI 注入 RCE'],
  'CVE-2021-45046': ['Log4Shell', 'JNDI 绕过'],
  'CVE-2022-22963': ['Spring Cloud', 'SpEL 函数路由 RCE'],
  'CVE-2022-22965': ['Spring4Shell', '数据绑定 RCE'],
  'CVE-2022-26134': ['Confluence', 'OGNL 表达式 RCE'],
  'CVE-2022-42889': ['Apache Commons Text', 'Text4Shell'],
  'CVE-2023-22515': ['Atlassian Confluence', '权限绕过'],
  'CVE-2023-27350': ['PaperCut MF/NG', '认证绕过 RCE'],
  'CVE-2023-34362': ['MOVEit Transfer', 'SQL 注入 RCE'],
  'CVE-2023-36884': ['Windows', 'Office 远程代码执行'],
  'CVE-2023-46604': ['Apache ActiveMQ', 'RCE 反序列化'],
  'CVE-2024-21887': ['Ivanti Connect Secure', '命令注入'],
  'CVE-2024-23897': ['Jenkins', '任意文件读取 → Groovy RCE'],
  'CVE-2024-29059': ['Ivanti CSA', '认证绕过 RCE'],
  'CVE-2024-3400': ['Palo Alto PAN-OS', '命令注入'],
  'CVE-2024-4577': ['PHP CGI', '参数注入 RCE'],
  'CVE-2024-6387': ['OpenSSH', 'regreSSHion 远程代码执行'],
  // 新增: 更多常见靶场 CVE
  'CVE-2023-22527': ['Atlassian Confluence', 'OGNL 模板注入'],
  'CVE-2023-4966': ['Citrix Bleed', '内存信息泄露'],
  'CVE-2024-10674': ['GoAnywhere MFT', '反序列化 RCE'],
  'CVE-2024-50623': ['JBoss', '反序列化 RCE'],
}

// Known exploit command patterns
const EXPLOIT_PATTERNS = [
  // Shell 反弹
  { name: 'bash反弹', regex: /bash\s+-[ci].*\/dev\/tcp\//i, type: 'curl' },
  { name: 'nc反弹', regex: /\bnc\b.*-e\s+\/bin\/(ba)?sh/i, type: 'curl' },
  { name: 'ncat反弹', regex: /\bncat\b.*-e\s+\/bin\/sh/i, type: 'curl' },
  { name: 'python反弹', regex: /python.*socket.*connect/i, type: 'python' },
  { name: 'perl反弹', regex: /perl.*socket.*connect/i, type: 'python' },
  { name: 'openssl反弹', regex: /openssl.*s_client/i, type: 'curl' },
  { name: 'php反弹', regex: /php.*fsockopen.*\/dev\/tcp/i, type: 'python' },
  { name: 'socat反弹', regex: /socat.*exec.*tty/i, type: 'curl' },
  { name: 'mkfifo反弹', regex: /mkfifo.*\/tmp\/pipe/i, type: 'curl' },
  // 工具利用
  { name: 'sqlmap os-shell', regex: /sqlmap.*--os-shell/i, type: 'python' },
  { name: 'msf exploit', regex: /msfconsole.*exploit/i, type: 'msf' },
  { name: 'searchsploit利用', regex: /searchsploit.*-m\s/i, type: 'msf' },
  // 框架利用
  { name: 'redis RCE', regex: /redis-cli.*config\s+set\s+dir/i, type: 'curl' },
  { name: 'ThinkPHP RCE', regex: /think\\app\/invokefunction/i, type: 'curl' },
  { name: 'Shiro RCE', regex: /rememberMe=.*ysoserial/i, type: 'python' },
  { name: 'Fastjson RCE', regex: /@type.*JdbcRowSetImpl/i, type: 'curl' },
  { name: 'Log4Shell JNDI', regex: /\$\{jndi:ldap[s]?:\/\//i, type: 'curl' },
  { name: 'Spring4Shell', regex: /class\.module\.classLoader/i, type: 'curl' },
  { name: 'Confluence OGNL', regex: /%7B.*@java\.lang\.Runtime/i, type: 'curl' },
  { name: 'Struts2 OGNL', regex: /Content-Type.*%7B.*ognl/i, type: 'curl' },
  { name: 'Laravel Ignition', regex: /_ignition\/execute-solution/i, type: 'curl' },
  { name: 'Jenkins Script Console', regex: /\/scriptText.*println.*execute/i, type: 'curl' },
  { name: 'Druid RCE', regex: /druid\/indexer\/v1\/sampler/i, type: 'curl' },
  // 文件写入
  { name: 'INTO OUTFILE webshell', regex: /INTO\s+OUTFILE.*\.(php|jsp|asp)/i, type: 'python' },
  { name: 'COPY PROGRAM', regex: /COPY.*FROM\s+PROGRAM/i, type: 'python' },
  { name: 'Docker socket', regex: /docker\.sock.*containers.*create/i, type: 'curl' },
  { name: 'K8s API abuse', regex: /kubernetes.*\/api\/v1\/pods/i, type: 'curl' },
]

// Tool chain patterns — sequences that form effective combos
const KNOWN_TOOL_CHAINS: Record<string, string[]> = {
  'Web资产发现': ['subfinder', 'httpx', 'katana'],
  '全量漏洞扫描': ['nmap', 'nuclei', 'ffuf'],
  '认证爆破': ['nuclei', 'hydra'],
  '内网侦察': ['nmap', 'enum4linux', 'crackmapexec'],
  '容器逃逸': ['docker', 'curl', 'chisel'],
  'DNS深度枚举': ['subfinder', 'amass', 'dnsx'],
  'Web指纹识别': ['httpx', 'wafw00f', 'nuclei'],
  '端口→服务→漏洞': ['masscan', 'nmap', 'nuclei'],
  'Git泄露利用': ['git-dumper', 'gitleaks', 'trufflehog'],
  'AD域攻击': ['bloodhound', 'impacket', 'hashcat'],
  'K8s攻击': ['kubectl', 'kubesploit', 'cdks-k8s'],
  'SSRF链式攻击': ['gopherus', 'curl', 'burp'],
  'C2全流程': ['msfconsole', 'sliver', 'chisel'],
  '后渗透信息收集': ['linpeas', 'winpeas', 'mimikatz'],
  '横向移动': ['crackmapexec', 'impacket', 'proxychains'],
}

// Shell acquisition indicators
const SHELL_INDICATORS = [
  /uid=\d+\(/,                  // Linux: uid=0(root)
  /Linux\s+\S+\s+\d+\.\d+\.\d+/, // Linux kernel info
  /Microsoft Windows/,           // Windows target
  /NT\s+AUTHORITY/,              // Windows SYSTEM
  /root@/,                       // root shell prompt
  /meterpreter>/,                // Metasploit session
  /C:\\Users\\/,                 // Windows path in output
  /Microsoft Windows \[Version/, // Windows version string
  /sh-\d\.\d\$\s/,               // shell prompt pattern
  /# $/,                         // root prompt (line end)
]

export class KnowledgeExtractor {
  private kb: KnowledgeBase
  private toolCallSequence: Array<{ tool: string; input: string; result: string; timestamp: string }> = []
  private attackChainSteps: string[] = []
  private detectedTargetType: string = 'unknown'
  private detectedCves: Set<string> = new Set()
  private shellAcquired = false

  constructor(kb: KnowledgeBase) {
    this.kb = kb
  }

  /** Reset real-time state between user tasks in the REPL loop */
  reset(): void {
    this.toolCallSequence = []
    this.attackChainSteps = []
    this.detectedCves = new Set()
    this.shellAcquired = false
  }

  /**
   * Real-time extraction — called after each successful tool execution.
   * Detects CVE exploitation, shell acquisition, and tool chain building.
   */
  extractFromToolResult(toolName: string, input: Record<string, unknown>, result: string): void {
    const cmd = String(input.command || '')
    const combinedText = `${cmd} ${result}`.slice(0, 5000) // limit analysis size

    // Track tool sequence for combo detection
    this.toolCallSequence.push({
      tool: toolName,
      input: cmd,
      result: result.slice(0, 500),
      timestamp: new Date().toISOString(),
    })
    // Keep only last 50 tool calls
    if (this.toolCallSequence.length > 50) {
      this.toolCallSequence = this.toolCallSequence.slice(-50)
    }

    // Extract CVE references
    const cves = combinedText.match(CVE_REGEX)
    if (cves) {
      for (const cve of cves) {
        this.detectedCves.add(cve.toUpperCase())
      }
    }

    // Detect target type from tool results
    this._detectTargetType(combinedText)

    // Detect shell acquisition
    if (!this.shellAcquired && this._checkShellAcquired(result)) {
      this.shellAcquired = true
      this.attackChainSteps.push('获取shell')
    }

    // Check for successful exploit execution
    this._extractCveNoteIfExploit(cmd, result, combinedText)

    // Track attack chain steps
    this._trackAttackStep(toolName, cmd, result)
  }

  /**
   * Session-end extraction — called when a session completes.
   * Extracts attack patterns, tool combos, target profiles from EventLog
   * and internal tool call sequence.
   */
  extractFromSession(events: EventLogEntry[]): void {
    // Extract from full event log
    this.extractAttackChains(events)
    this.extractToolCombos(events)
    this.extractTargetProfile(events)

    // Extract from real-time tool call sequence (accumulated during session)
    if (this.attackChainSteps.length >= 2) {
      this._extractAttackPattern()
    }
    if (this.toolCallSequence.length > 0) {
      this._extractToolCombos()
    }
  }

  /**
   * Extract attack chains from EventLog entries.
   * Analyzes the full event sequence to identify successful attack paths.
   */
  extractAttackChains(events: EventLogEntry[]): void {
    // Find successful exploit sequences in event log
    const toolCalls = events.filter((e) => e.type === 'tool_call')
    const toolResults = events.filter((e) => e.type === 'tool_result' && !e.detail?.isError)

    if (toolResults.length < 2) return

    // Look for recon → scan → exploit → shell patterns
    const phases = this._classifyEventPhases(toolCalls, toolResults)
    if (phases.recon.length > 0 && phases.exploit.length > 0) {
      const chain: string[] = []
      if (phases.recon.length > 0) chain.push('侦察发现资产')
      if (phases.scan.length > 0) chain.push('漏洞扫描发现弱点')
      if (phases.exploit.length > 0) chain.push('漏洞利用成功')
      if (this.shellAcquired) chain.push('获取shell')

      if (chain.length >= 2) {
        this.kb.write('attack_patterns', {
          title: `自动化攻击链: ${chain.join(' → ')}`,
          chain,
          target_type: this.detectedTargetType,
          techniques: this._extractTechniques(events),
          success_rate: 0.8, // Initial confidence from successful chain
          used_count: 1,
          last_used: new Date().toISOString(),
        })
      }
    }
  }

  /**
   * Extract CVE notes from Finding entries.
   */
  extractCveNotes(findings: Array<{ title: string; description: string; severity: string }>): void {
    for (const finding of findings) {
      const cves = finding.title.match(CVE_REGEX) || finding.description.match(CVE_REGEX)
      if (!cves) continue

      for (const cve of cves) {
        const cveUpper = cve.toUpperCase()
        const serviceInfo = KNOWN_CVE_SERVICES[cveUpper] || ['Unknown']

        this.kb.write('cve_notes', {
          cve: cveUpper,
          service: serviceInfo[0],
          exploit_summary: finding.title,
          payload_type: this._detectPayloadType(finding.description),
          success: finding.severity === 'critical' || finding.severity === 'high',
          confidence: finding.severity === 'critical' ? 0.95 : finding.severity === 'high' ? 0.8 : 0.6,
          notes: finding.description.slice(0, 500),
        })
      }
    }
  }

  /**
   * Extract tool combos from tool call sequence.
   */
  extractToolCombos(events: EventLogEntry[]): void {
    const toolNames = events
      .filter((e) => e.type === 'tool_call')
      .map((e) => e.source)

    // Check against known combo patterns
    for (const [name, tools] of Object.entries(KNOWN_TOOL_CHAINS)) {
      const present = tools.filter((t) =>
        toolNames.some((tn) => tn.toLowerCase().includes(t.toLowerCase()))
      )

      if (present.length >= Math.ceil(tools.length * 0.6)) {
        // At least 60% of the combo tools were used → valid combo
        this.kb.write('tool_combos', {
          name,
          tools: present,
          command_template: present.join(' → '),
          purpose: `${name} — 在本次session中验证有效`,
          used_count: 1,
          success_rate: 0.75,
        })
      }
    }
  }

  /**
   * Extract target profile from session data.
   */
  extractTargetProfile(events: EventLogEntry[]): void {
    if (this.detectedTargetType === 'unknown') return

    const weaknesses = this._extractWeaknesses(events)
    const techniques = this._extractTechniques(events)

    if (weaknesses.length > 0 || techniques.length > 0) {
      this.kb.write('target_profiles', {
        target_type: this.detectedTargetType,
        indicators: this._extractIndicators(events),
        common_weaknesses: weaknesses,
        successful_techniques: techniques,
      })
    }
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  private _checkShellAcquired(result: string): boolean {
    return SHELL_INDICATORS.some((re) => re.test(result))
  }

  private _detectTargetType(text: string): void {
    // Lock in first detected type (best-effort, no re-detection needed)
    if (this.detectedTargetType !== 'unknown') return

    const typePatterns: Record<string, RegExp[]> = {
      // Java 生态
      'Spring Boot': [/actuator/, /\/env/, /heapdump/, /spring\.cloud/],
      'ThinkPHP': [/think\\app/, /invokefunction/, /thinkphp/i],
      'Apache Solr': [/solr/, /solr\/select/],
      'Java Web': [/\.jsp/, /tomcat/, /weblogic/, /jboss/, /glassfish/],
      'Confluence': [/confluence/, /atlassian/i, /rest\/api\/content/],
      'Jenkins': [/jenkins\/manage/, /scriptText/, /\/jenkins/i],
      'GitLab': [/gitlab/, /\/api\/v4\/projects/, /\/users\/sign_in/],
      'VMware': [/vmware/, /vcenter/, /vsphere/],
      // PHP 生态
      'WordPress': [/wp-content/, /wp-admin/, /wordpress/i, /wp-includes/],
      'PHP': [/\.php/, /phpinfo/, /eval\(/, /phpmyadmin/],
      'Laravel': [/laravel/, /\/_ignition/, /artisan/i],
      // Python 生态
      'Flask': [/flask/, /werkzeug/, /python.*flask/i],
      'Django': [/django/, /admin\/login/, /python.*django/i],
      'Node.js': [/node_modules/, /express/, /next\.js/, /nestjs/i],
      'Python': [/python/, /\.py/, /\/api\/.*python/i],
      // 基础设施
      'Redis': [/redis-cli/, /6379/, /redis\s+server/],
      'Docker': [/docker\.sock/, /\/var\/run\/docker/, /container\/json/],
      'Kubernetes': [/kubernetes/, /kubectl/, /pods/, /\/api\/v1\//],
      'Nginx': [/nginx/i, /\/nginx_status/, /X-Powered-By.*nginx/],
      'Apache HTTPD': [/apache/, /httpd/, /server-status/],
      'Elasticsearch': [/elasticsearch/, /9200/, /\/_cat\/indices/],
      'MongoDB': [/mongod/, /27017/, /mongodb/i],
      'MySQL': [/mysql/, /3306/, /phpmyadmin/],
      // Windows / AD
      'Windows AD': [/domain\.controller/, /kerberos/, /445/, /smb/, /NT AUTHORITY/, /Active Directory/],
      'Windows Server': [/Windows Server/, /iis/, /\.asp/, /\.aspx/, /powershell/],
      // 云原生
      'AWS': [/169\.254\.169\.254/, /aws/, /ec2/, /s3/, /iam/],
      'Azure': [/azure/, /microsoftonline/, /168\.63\.129\.16/],
      // 安全设备
      'WAF/IPS': [/cloudflare/, /akamai/, /imperva/, /f5 big-ip/, /fortinet/],
    }

    for (const [type, patterns] of Object.entries(typePatterns)) {
      if (patterns.some((p) => p.test(text))) {
        this.detectedTargetType = type
        break
      }
    }
  }

  private _extractCveNoteIfExploit(cmd: string, result: string, combined: string): void {
    // Check if this looks like a successful exploit
    if (!this._checkShellAcquired(result) && !SHELL_INDICATORS.some((re) => re.test(cmd))) {
      return // Not a clear exploit success
    }

    const cves = combined.match(CVE_REGEX)
    if (!cves || cves.length === 0) return

    for (const cve of cves) {
      const cveUpper = cve.toUpperCase()
      const serviceInfo = KNOWN_CVE_SERVICES[cveUpper] || ['Unknown']
      const exploitType = this._detectPayloadType(combined)

      this.kb.write('cve_notes', {
        cve: cveUpper,
        service: serviceInfo[0],
        exploit_summary: `成功利用 ${cveUpper} 获取命令执行`,
        payload_type: exploitType,
        success: true,
        confidence: 0.9,
        notes: `命令: ${cmd.slice(0, 200)}`,
      })
    }
  }

  private _detectPayloadType(text: string): string {
    for (const p of EXPLOIT_PATTERNS) {
      if (p.regex.test(text)) return p.type
    }
    if (text.includes('curl')) return 'curl'
    if (text.includes('python')) return 'python'
    if (text.includes('msf') || text.includes('metasploit')) return 'msf'
    return 'other'
  }

  private _trackAttackStep(toolName: string, cmd: string, result: string): void {
    // Map tool usage to attack chain phases
    if (/subfinder|amass|dnsx|dns/.test(cmd)) {
      if (!this.attackChainSteps.includes('DNS子域名枚举')) this.attackChainSteps.push('DNS子域名枚举')
    }
    if (/nmap|masscan|naabu/.test(cmd)) {
      if (!this.attackChainSteps.includes('端口扫描')) this.attackChainSteps.push('端口扫描')
    }
    if (/httpx|wafw00f/.test(cmd)) {
      if (!this.attackChainSteps.includes('Web指纹识别')) this.attackChainSteps.push('Web指纹识别')
    }
    if (/nuclei|nikto/.test(cmd)) {
      if (!this.attackChainSteps.includes('漏洞扫描')) this.attackChainSteps.push('漏洞扫描')
    }
    if (/ffuf|dirsearch|gobuster/.test(cmd)) {
      if (!this.attackChainSteps.includes('目录枚举')) this.attackChainSteps.push('目录枚举')
    }
    if (/hydra|kerbrute/.test(cmd)) {
      if (!this.attackChainSteps.includes('暴力破解')) this.attackChainSteps.push('暴力破解')
    }
    if (/git-dumper|gitleaks|trufflehog/.test(cmd)) {
      if (!this.attackChainSteps.includes('代码仓库泄露')) this.attackChainSteps.push('代码仓库泄露')
    }
    if (/katana|gau|crawl/.test(cmd)) {
      if (!this.attackChainSteps.includes('URL爬取')) this.attackChainSteps.push('URL爬取')
    }
    if (/bloodhound|sharphound/.test(cmd)) {
      if (!this.attackChainSteps.includes('AD信息收集')) this.attackChainSteps.push('AD信息收集')
    }
    if (/curl.*system|curl.*\/etc\/passwd|curl.*id['"`]/.test(cmd)) {
      if (!this.attackChainSteps.includes('漏洞利用')) this.attackChainSteps.push('漏洞利用')
    }
    if (/mimikatz|secretsdump|hashcat/.test(cmd)) {
      if (!this.attackChainSteps.includes('凭证提取')) this.attackChainSteps.push('凭证提取')
    }
    if (/psexec|wmiexec|crackmapexec|evil-winrm/.test(cmd)) {
      if (!this.attackChainSteps.includes('横向移动')) this.attackChainSteps.push('横向移动')
    }
    if (/linpeas|winpeas|sudo.*-l/.test(cmd)) {
      if (!this.attackChainSteps.includes('提权检测')) this.attackChainSteps.push('提权检测')
    }
    if (/proxychains|chisel|socat.*forward/.test(cmd)) {
      if (!this.attackChainSteps.includes('隧道建立')) this.attackChainSteps.push('隧道建立')
    }
    if (/docker\.sock|kubectl/.test(cmd)) {
      if (!this.attackChainSteps.includes('云原生攻击')) this.attackChainSteps.push('云原生攻击')
    }
    if (/find.*flag|cat.*flag/.test(cmd)) {
      if (!this.attackChainSteps.includes('Flag收集')) this.attackChainSteps.push('Flag收集')
    }
  }

  private _extractAttackPattern(): void {
    if (this.attackChainSteps.length < 2) return

    this.kb.write('attack_patterns', {
      title: `攻击链: ${this.attackChainSteps.join(' → ')}`,
      chain: [...this.attackChainSteps],
      target_type: this.detectedTargetType,
      techniques: this._extractTechniquesFromSteps(this.attackChainSteps),
      success_rate: this.shellAcquired ? 0.85 : 0.5,
      used_count: 1,
      last_used: new Date().toISOString(),
    })
  }

  private _extractToolCombos(): void {
    // Find contiguous sequences of tool calls that form combos
    const tools = this.toolCallSequence.map((t) => t.tool)
    const uniqueTools = [...new Set(tools)].filter((t) => t !== 'Bash' && t !== 'Read')

    if (uniqueTools.length >= 2) {
      this.kb.write('tool_combos', {
        name: `Session工具组合: ${uniqueTools.join('+')}`,
        tools: uniqueTools.slice(0, 8),
        command_template: uniqueTools.slice(0, 4).join(' → '),
        purpose: `本次session验证的组合: ${uniqueTools.join(', ')}`,
        used_count: 1,
        success_rate: this.shellAcquired ? 0.8 : 0.5,
      })
    }
  }

  private _extractTechniques(events: EventLogEntry[]): string[] {
    // Map observed actions to MITRE ATT&CK TTPs
    const ttps = new Set<string>()
    for (const event of events) {
      const detail = JSON.stringify(event.detail)
      // Recon
      if (/subfinder|amass|dnsx|subdomain/.test(detail)) ttps.add('T1592') // Gather Victim Host Info
      if (/nmap|port.*scan/.test(detail)) ttps.add('T1046') // Network Service Scanning
      if (/httpx|wafw00f|finger/.test(detail)) ttps.add('T1592') // Gather Victim Host Info
      if (/katana|gau|crawl/.test(detail)) ttps.add('T1593') // Search Open Technical Resources
      // Scanning
      if (/nuclei|vuln|nikto|ffuf|dirsearch/.test(detail)) ttps.add('T1595') // Active Scanning
      // Brute Force
      if (/hydra|kerbrute|password|brute/.test(detail)) ttps.add('T1110') // Brute Force
      // Exploitation
      if (/curl.*exploit|python.*reverse|sqlmap|msf|exploit/.test(detail)) ttps.add('T1190') // Exploit Public App
      // Shell / Execution
      if (/uid=0|root|meterpreter|reverse/.test(detail)) ttps.add('T1059') // Command and Scripting Interpreter
      if (/bash.*-i|nc\s.*-e|ncat|socat/.test(detail)) ttps.add('T1059.004') // Unix Shell
      // Privilege Escalation
      if (/sudo|suid|linpeas|winpeas|JuicyPotato|BadPotato/.test(detail)) ttps.add('T1068') // Exploitation for Privilege Escalation
      if (/kernel.*exploit|CVE.*privilege/.test(detail)) ttps.add('T1068') // Exploitation for Priv Esc
      // Credential Access
      if (/mimikatz|hashcat|dump.*credential|secretsdump/.test(detail)) ttps.add('T1003') // OS Credential Dumping
      if (/bloodhound|sharphound|kerberoast|GetUserSPNs/.test(detail)) ttps.add('T1558') // Steal or Forge Kerberos Tickets
      if (/NTLM|responder|ntlmrelayx/.test(detail)) ttps.add('T1557') // Adversary-in-the-Middle
      // Lateral Movement
      if (/psexec|wmiexec|smbexec|crackmapexec|evil-winrm/.test(detail)) ttps.add('T1021') // Remote Services
      if (/proxychains|chisel|socks|tunnel/.test(detail)) ttps.add('T1572') // Protocol Tunneling
      // Collection
      if (/find.*flag|flag\{|cat.*flag/.test(detail)) ttps.add('T1005') // Data from Local System
      if (/enum4linux|crackmapexec.*--sam|crackmapexec.*--ntds/.test(detail)) ttps.add('T1087') // Account Discovery
      // Persistence
      if (/crontab|authorized_keys|systemctl.*enable/.test(detail)) ttps.add('T1053') // Scheduled Task/Job
      if (/docker.*run.*privileged/.test(detail)) ttps.add('T1613') // Container and Resource Discovery
      // Cloud
      if (/169\.254\.169\.254|kubernetes.*api|kubectl/.test(detail)) ttps.add('T1526') // Cloud Service Dashboard
      // Docker
      if (/docker\.sock|container.*create/.test(detail)) ttps.add('T1610') // Deploy Container
      // Defense Evasion
      if (/obfuscate|encode|base64|bypass/.test(detail)) ttps.add('T1027') // Obfuscated Files or Information
    }
    return Array.from(ttps)
  }

  private _extractTechniquesFromSteps(steps: string[]): string[] {
    const ttps = new Set<string>()
    for (const step of steps) {
      if (step.includes('DNS') || step.includes('子域名')) ttps.add('T1592')
      if (step.includes('端口')) ttps.add('T1046')
      if (step.includes('指纹')) ttps.add('T1592')
      if (step.includes('漏洞扫描')) ttps.add('T1595')
      if (step.includes('目录')) ttps.add('T1083')
      if (step.includes('暴力')) ttps.add('T1110')
      if (step.includes('利用')) ttps.add('T1190')
      if (step.includes('shell')) ttps.add('T1059')
    }
    return Array.from(ttps)
  }

  private _extractWeaknesses(events: EventLogEntry[]): string[] {
    const weaknesses = new Set<string>()
    for (const event of events) {
      const detail = JSON.stringify(event.detail)
      if (/default.*(login|credential|password)/i.test(detail)) weaknesses.add('默认凭证')
      if (/unauthorized|unauthenticated/i.test(detail)) weaknesses.add('未授权访问')
      if (/information.?disclosure|info.?leak/i.test(detail)) weaknesses.add('信息泄露')
      if (/rce|remote.*code.*execution/i.test(detail)) weaknesses.add('远程代码执行')
      if (/sql.?injection/i.test(detail)) weaknesses.add('SQL注入')
      if (/xss|cross.*site.*scripting/i.test(detail)) weaknesses.add('XSS')
      if (/file.?upload/i.test(detail)) weaknesses.add('文件上传')
      if (/path.?traversal|directory.?traversal/i.test(detail)) weaknesses.add('路径遍历')
      if (/ssrf|server.?side.*request/i.test(detail)) weaknesses.add('SSRF')
      if (/ssti|server.*side.*template.*injection/i.test(detail)) weaknesses.add('SSTI')
      if (/deserializ|unserialize|ObjectInputStream/i.test(detail)) weaknesses.add('反序列化')
      if (/idor|insecure.*direct.*object/i.test(detail)) weaknesses.add('IDOR')
      if (/csrf|cross.*site.*request.*forgery/i.test(detail)) weaknesses.add('CSRF')
      if (/jwt.*alg.*none|jwt.*weak.*key/i.test(detail)) weaknesses.add('JWT攻击')
      if (/lfi|local.*file.*inclusion/i.test(detail)) weaknesses.add('LFI')
      if (/rfi|remote.*file.*inclusion/i.test(detail)) weaknesses.add('RFI')
      if (/xxe|xml.*external.*entity/i.test(detail)) weaknesses.add('XXE')
      if (/prototype.*pollution/i.test(detail)) weaknesses.add('原型链污染')
      if (/command.*injection|cmd.*inject/i.test(detail)) weaknesses.add('命令注入')
      if (/privilege.*escalation|提权/i.test(detail)) weaknesses.add('权限提升')
      if (/kerberos|kerberoast|AS-REP/i.test(detail)) weaknesses.add('Kerberos攻击')
      if (/pass.*the.*hash|pth|NTLM.*relay/i.test(detail)) weaknesses.add('NTLM攻击')
      if (/docker.*escape|container.*escape/i.test(detail)) weaknesses.add('容器逃逸')
    }
    return Array.from(weaknesses)
  }

  private _extractIndicators(events: EventLogEntry[]): string[] {
    const indicators = new Set<string>()
    for (const event of events) {
      const src = event.source.toLowerCase()
      if (src.includes('httpx')) indicators.add('Web服务存活')
      if (src.includes('nmap')) indicators.add('端口开放')
      if (src.includes('nuclei')) indicators.add('存在CVE漏洞')
      if (src.includes('subfinder')) indicators.add('子域名枚举')
      if (src.includes('ffuf')) indicators.add('隐藏路径发现')
      if (src.includes('wafw00f')) indicators.add('WAF检测')
      if (src.includes('hydra')) indicators.add('认证服务发现')
      if (src.includes('katana') || src.includes('gau')) indicators.add('URL资产')
      if (src.includes('amass')) indicators.add('被动子域名')
      if (src.includes('enum4linux')) indicators.add('SMB共享发现')
      if (src.includes('crackmapexec')) indicators.add('内网主机存活')
      if (src.includes('bloodhound') || src.includes('sharphound')) indicators.add('AD域关系映射')
      if (src.includes('masscan') || src.includes('naabu')) indicators.add('快速端口扫描')
      if (src.includes('gitleaks') || src.includes('trufflehog')) indicators.add('代码凭证泄露')
    }
    return Array.from(indicators)
  }

  private _classifyEventPhases(
    toolCalls: EventLogEntry[],
    toolResults: EventLogEntry[],
  ): { recon: EventLogEntry[]; scan: EventLogEntry[]; exploit: EventLogEntry[] } {
    const recon: EventLogEntry[] = []
    const scan: EventLogEntry[] = []
    const exploit: EventLogEntry[] = []

    for (const event of toolCalls) {
      const src = event.source.toLowerCase()
      const detail = JSON.stringify(event.detail).toLowerCase()
      if (/subfinder|dnsx|amass|httpx|wafw00f/.test(src) || /subdomain|dns|web.*probe/.test(detail)) {
        recon.push(event)
      } else if (/nmap|nuclei|nikto|ffuf|masscan|naabu/.test(src) || /scan|enum|probe/.test(detail)) {
        scan.push(event)
      } else if (/curl.*system|python.*exploit|msf|sqlmap|hydra/.test(detail)) {
        exploit.push(event)
      }
    }

    return { recon, scan, exploit }
  }
}
