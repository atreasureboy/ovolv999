# ovolv999 — APT 思维注入的攻防代理引擎

<div align="center">

**Playbook 驱动 · 单链路串行 · 防护感知 · 全阶段渗透测试自动化**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node](https://img.shields.io/badge/Node-%3E%3D20-339933?logo=node.js)](https://nodejs.org/)
[![Claude](https://img.shields.io/badge/AI-Claude%20%7C%20OpenAI-191919)](https://claude.ai/)

> `npx tsx bin/ovogogogo.ts --mode lv999 --playbook default.json`

</div>

## 简介

ovolv999 是一个面向**高防护靶场**的自主攻防代理框架。与传统渗透测试工具的本质区别在于：

- **不是暴力扫描器** — 单 Agent 串行推进，每个阶段独立思考、独立决策
- **APT 思维注入** — 系统提示词嵌入"如何像黑客一样思考"，而非"要做什么"
- **Playbook 驱动** — 状态机按阶段推进，阶段间通过 Snapshot 传递上下文
- **防护感知** — 内置 WAF/EDR/沙箱检测 + 23 种绕过技术（Havoc/Sliver/APT28 提取）
- **上下文重置** — 每阶段清空历史，避免无关信息干扰当前决策
- **18 个专用工具** — 从 C2 管理到 Payload 工厂，覆盖全攻击面

## 完整架构全景图

```
===================================================================================
                          ovolv999 — 完整架构全景图
===================================================================================

  用户输入: "以 Lv999 模式渗透测试 http://target.com"
       │
       ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  CLI Entry  src/lv999/cli.ts                                             │
  │  ├── 加载 Playbook (JSON → 阶段定义)                                     │
  │  ├── 注入 Renderer (终端 UI / Tmux 面板)                                 │
  │  └── 创建 State Machine 实例                                             │
  └────────────────────────────┬────────────────────────────────────────────┘
                               │
                               ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  State Machine  src/lv999/stateMachine.ts                                │
  │                                                                          │
  │  Phase 1 ──Snapshot──▶ Phase 2 ──Snapshot──▶ Phase 3 ──Snapshot──▶ Phase 4│
  │  (侦察)     (画像)     (武器化)   (方案)      (投递)    (结果)    (后渗透)  │
  │                                                                          │
  │  每个阶段: 独立 Engine + 隔离工具集 + 清空历史 + 超时保护                 │
  └────────────────────────────┬────────────────────────────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
  ┌──────────────────┐ ┌──────────────┐ ┌──────────────────┐
  │  PromptBuilder   │ │  ToolFilter  │ │  PlaybookParser  │
  │  • APT Mindset   │ │  白名单过滤  │ │  JSON→PhaseDef   │
  │  • 威胁模型注入  │ │  并发安全标记│ │  决策树/过渡规则 │
  │  • 决策树渲染    │ │  NO_CACHE强制│ │  Snapshot配置    │
  │  • {{snapshot}}  │ │  工具过滤    │ │  maxTurns        │
  │    上下文替换    │ │              │ │  turnTimeoutMs   │
  └────────┬─────────┘ └──────┬───────┘ └────────┬─────────┘
           │                  │                   │
           └──────────────────┼───────────────────┘
                              ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  Execution Engine  src/core/engine.ts                                    │
  │                                                                          │
  │  ┌───────────────────────────────────────────────────────────────────┐  │
  │  │  runTurn(message, history)                                        │  │
  │  │  ├── LLM API 调用 (Claude / OpenAI)                               │  │
  │  │  ├── 解析 tool_calls 响应                                         │  │
  │  │  ├── 并发批次执行 (CONCURRENCY_SAFE_TOOLS)                        │  │
  │  │  └── 结果注入 → 下一轮                                            │  │
  │  └───────────────────────────────────────────────────────────────────┘  │
  │                               │                                         │
  │  ┌────────────────────────────▼────────────────────────────────────┐   │
  │  │  Tool Dispatcher (18 个工具 · 动态路由)                           │   │
  │  │                                                                  │   │
  │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │   │
  │  │  │ Bash     │ │ WebFetch │ │WebSearch │ │Glob/Grep │           │   │
  │  │  │ 命令执行 │ │ HTTP请求 │ │ 搜索引擎 │ │ 文件检索 │           │   │
  │  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │   │
  │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │   │
  │  │  │FileRead  │ │FileWrite │ │FileEdit  │ │TodoWrite │           │   │
  │  │  │ 文件读取 │ │ 文件写入 │ │ 文件编辑 │ │ 任务追踪 │           │   │
  │  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │   │
  │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │   │
  │  │  │ Agent    │ │TmuxSession│ │DocRead  │ │ShellSess │           │   │
  │  │  │ 子代理   │ │ 交互终端  │ │ 文档读取 │ │反弹shell │           │   │
  │  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │   │
  │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │   │
  │  │  │ C2       │ │EnvAnalyze│ │Technique │ │WeaponRadar│          │   │
  │  │  │Metasploit│ │WAF/EDR/  │ │Gen       │ │PoC语义检索│          │   │
  │  │  │Sliver    │ │沙箱检测  │ │23种绕过  │ │HTTP API  │          │   │
  │  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │   │
  │  └──────────────────────────────────────────────────────────────────┘   │
  └─────────────────────────────────────────────────────────────────────────┘
       │
  ┌────▼──────────────────────────────────────────────────────────────────┐
  │  知识库 & 提示词注入层                                                  │
  │  ┌─────────────────────────┐  ┌─────────────────────────┐             │
  │  │ attackKnowledge.ts      │  │ agentPrompts.ts         │             │
  │  │ • Web/框架/云原生/数据库 │  │ • manual-exploit        │             │
  │  │ • AD/内网横向移动        │  │ • tool-exploit          │             │
  │  │ • EDR/AV 绕过 (26模块)   │  │ • privesc / lateral     │             │
  │  │   Havoc: Indirect Syscall│  │ • target-recon / report │             │
  │  │   Sliver: RefreshPE/0xC3 │  │ • general-purpose       │             │
  │  │   APT28: XOR/PNG/APC    │  └─────────────────────────┘             │
  │  │ • 红旗信号 / 错误处理     │                                          │
  │  └─────────────────────────┘                                          │
  └───────────────────────────────────────────────────────────────────────┘
       │
  ┌────▼──────────────────────────────────────────────────────────────────┐
  │  基础设施 & 支撑层                                                      │
  │  ┌──────────┐ ┌──────────────┐ ┌──────────┐ ┌──────────────┐         │
  │  │ Renderer │ │ContextBudget │ │EpisodeMem│ │ SemanticMem  │         │
  │  │ 终端UI   │ │ 上下文截断   │ │ 过程记忆 │ │ 语义记忆     │         │
  │  └──────────┘ └──────────────┘ └──────────┘ └──────────────┘         │
  │  ┌──────────┐ ┌──────────────┐ ┌──────────┐ ┌──────────────┐         │
  │  │ToolCache │ │ EventLog     │ │ProgTrack │ │PriorityQueue │         │
  │  │ 结果缓存 │ │ 事件日志     │ │ 进度追踪 │ │ 优先级队列   │         │
  │  └──────────┘ └──────────────┘ └──────────┘ └──────────────┘         │
  │  ┌──────────┐ ┌──────────────┐ ┌──────────┐ ┌──────────────┐         │
  │  │ MCP      │ │ MCP Loader   │ │SkillReg  │ │ Settings/Hooks│        │
  │  │ 客户端   │ │ 动态加载     │ │ 技能注册 │ │ 配置/钩子    │         │
  │  └──────────┘ └──────────────┘ └──────────┘ └──────────────┘         │
  └───────────────────────────────────────────────────────────────────────┘

  输出: session/Target_Profile.json → Weaponization_Plan.md → Pentest_Report.md
===================================================================================
```

## 核心模块详解

### State Machine — 状态机引擎

```
┌──────────────────────────────────────────────────────────────┐
│                    Lv999StateMachine                          │
│                                                               │
│  run() ──▶ for each phase:                                    │
│              buildPhaseConfig()                               │
│                ├── filterToolsForPhase()                      │
│                └── buildPhaseSystemPrompt()                   │
│              runPhase() ──▶ while (turn < maxTurns):          │
│                               runTurnWithTimeout()            │
│                               checkTransition()               │
│              snapshotPhase()                                  │
│              ──▶ next phase (snapshot as userMessage)         │
│                                                               │
│  Transition Strategies: stop_sequence | keyword | tool_pattern│
└──────────────────────────────────────────────────────────────┘
```

每个阶段获得**独立的执行环境**：
- 独立 `ExecutionEngine` 实例
- 隔离的工具集（白名单过滤）
- 清空的历史记录（避免上下文污染）
- 每轮超时保护（默认 5 分钟）

阶段间通过 **Snapshot** 传递摘要，而非完整历史，确保 LLM 聚焦当前阶段目标。

### Playbook — 剧本定义

```
┌──────────────────────────────────────────────────────────────┐
│                     Playbook (JSON)                           │
│                                                               │
│  ┌───────────────┐    ┌───────────────┐                      │
│  │ Phase 1: 侦察  │───▶│ Phase 2: 武器化│                      │
│  │ maxTurns: 60  │    │ maxTurns: 80  │                      │
│  │ keyword: json │    │ keyword: md   │                      │
│  └───────────────┘    └───────────────┘                      │
│         │                      │                              │
│         ▼                      ▼                              │
│  ┌───────────────┐    ┌───────────────┐                      │
│  │ Phase 3: 投递  │───▶│ Phase 4: 后渗透│                      │
│  │ maxTurns: 100 │    │ maxTurns: 150 │                      │
│  │ stop_sequence │    │ keyword: report│                      │
│  └───────────────┘    └───────────────┘                      │
│                                                               │
│  GlobalDecisionTree: 通用操作原则 → 所有阶段继承                 │
│  PhaseDecisionTree: 阶段内分支策略 → 动态渲染到提示词            │
└──────────────────────────────────────────────────────────────┘
```

当前提供两个 Playbook：
- **default.json** — 标准 Web 应用 APT 模拟，4 阶段
- **high-defense.json** — 高防护靶场精英通道，零痕迹侦察 + 精准投递

### Prompt Builder — 提示词组装

```
┌──────────────────────────────────────────────────────────────┐
│                  buildPhaseSystemPrompt()                     │
│                                                               │
│  1. APT Mindset ── "如何像黑客一样思考"                         │
│  2. Threat Mindset ── 根据检测到的防护类型注入对应策略           │
│  3. Phase Template ── 阶段专属指令 + {{phase_snapshot}} 替换  │
│  4. Phase DecisionTree ── 阶段内分支策略                       │
│  5. Global DecisionTree ── 全局操作原则                        │
│  6. One-Step-Think-Act ── 一步一动作规则                       │
│                                                               │
│  最终输出: 完整的系统提示词，注入给 LLM                         │
└──────────────────────────────────────────────────────────────┘
```

### Tool Dispatcher — 工具分发器

```
┌──────────────────────────────────────────────────────────────┐
│                     Tool Dispatcher                           │
│                                                               │
│  LLM 请求 ──▶ 解析 tool_calls ──▶ 分发到对应工具               │
│                                                               │
│  ┌───────────────────────────────────────────────────────┐   │
│  │  文件操作: Read | Write | Edit | Glob | Grep          │   │
│  │  网络操作: Bash | WebFetch | WebSearch                │   │
│  │  会话管理: ShellSession | TmuxSession | C2            │   │
│  │  攻防专用: EnvAnalyzer | TechniqueGenerator           │   │
│  │             | WeaponRadar | Agent                     │   │
│  │  基础设施: TodoWrite | DocRead                        │   │
│  └───────────────────────────────────────────────────────┘   │
│                                                               │
│  调度策略:                                                    │
│  • CONCURRENCY_SAFE_TOOLS → 无副作用工具可并行执行             │
│  • NO_CACHE_TOOLS → 状态敏感工具强制刷新（EnvAnalyzer等）       │
└──────────────────────────────────────────────────────────────┘
```

### Execution Engine — 执行引擎

```
┌──────────────────────────────────────────────────────────────┐
│                    ExecutionEngine                            │
│                                                               │
│  runTurn(message, history)                                    │
│    │                                                          │
│    ├─▶ LLM API 调用 (Claude / OpenAI)                        │
│    │                                                          │
│    ├─▶ 解析响应:                                              │
│    │    ├── 纯文本 → 注入历史 → 返回                          │
│    │    └── tool_calls → 分发执行 → 结果注入 → 继续           │
│    │                                                          │
│    └─▶ 并发优化:                                             │
│         ├── 安全工具批次 → 并行执行                           │
│         └── 状态工具 → 串行执行                               │
│                                                               │
│  超时包装: runTurnWithTimeout()                               │
│  • 默认 5 分钟/轮                                             │
│  • 超时后中止当前 turn，返回错误状态                           │
│  • State Machine 根据错误状态决定是否继续                      │
└──────────────────────────────────────────────────────────────┘
```

### Attack Knowledge — 攻击知识库

注入到 LLM 系统提示词的结构化攻击方法论，包含：

| 模块 | 内容 |
|------|------|
| Web 攻击 | SQLi/XSS/SSRF/文件上传/命令注入 |
| 框架漏洞 | Spring/Struts2/ThinkPHP/Fastjson/Shiro |
| 云原生 | Docker逃逸/K8s配置错误/容器权限提升 |
| 数据库 | MySQL/MSSQL/Redis/PostgreSQL 提权 |
| AD/内网 | Kerberoasting/PTH/PTT/DCSync |
| **EDR/AV 绕过** | Havoc 26 模块 + Sliver C2 + APT28 战术 |
| 红旗信号 | 被发现的征兆 + 应急响应对应关系 |

### EnvAnalyzer — 环境检测工具

```
┌──────────────────────────────────────────────────────────────┐
│                    EnvAnalyzerTool                            │
│                                                               │
│  输入: { target, detect_mode: 'waf'|'edr'|'sandbox'|'all' }  │
│                                                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ WAF 检测    │  │ EDR 检测    │  │ 沙箱检测    │          │
│  │ wafw00f →   │  │ tasklist →  │  │ CPU ≤ 2     │          │
│  │ curl 探针 → │  │ 进程名匹配  │  │ RAM < 2GB   │          │
│  │ 10种WAF特征 │  │ 9种EDR进程  │  │ VM MAC前缀  │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
│                                                               │
│  输出: "WAF: 宝塔 | EDR: Windows Defender | 沙箱: false"      │
│        "建议: 1) 分块传输绕过WAF 2) AMSI bypass后再执行PS"    │
└──────────────────────────────────────────────────────────────┘
```

### TechniqueGenerator — 绕过技术生成器

覆盖 23 种逃逸技术，从三大来源提取：

| 来源 | 技术 |
|------|------|
| **Havoc C2** | Indirect Syscall, Hardware BP AMSI, Sleep Obf, Stack Spoofing, Hash API |
| **Sliver C2** | RefreshPE, 0xC3 AMSI/ETW Patch, SGN Polymorphic, Traffic Encoder, PE Donor |
| **APT28** | Alternating Byte XOR, Rotating XOR, PNG Stego, RW→RX, APC Inject, COM Hijack, Dead Drop, WebDAV UNC |

## 快速开始

### 安装

```bash
git clone https://github.com/atreasureboy/ovolv999.git
cd ovolv999
npm install
```

### 配置

设置环境变量：

```bash
# Claude API
export ANTHROPIC_API_KEY="your-key"

# 或 OpenAI 兼容 API
export OPENAI_API_KEY="your-key"
export OPENAI_BASE_URL="https://your-proxy.com/v1"
export OPENAI_MODEL="claude-sonnet-4-6-20250514"

# 可选：Weapon Radar API
export WEAPON_RADAR_URL="http://127.0.0.1:8765"
```

### 使用

```bash
# 标准模式 — 默认 Playbook
npx tsx bin/ovogogogo.ts --mode lv999 --playbook default.json

# 高防护靶场模式
npx tsx bin/ovogogogo.ts --mode lv999 --playbook high-defense.json

# 指定工作目录
npx tsx bin/ovogogogo.ts --mode lv999 --playbook default.json --cwd ./session-01
```

## 项目结构

```
ovolv999/
├── bin/
│   └── ovogogogo.ts          # 主入口 — CLI 参数解析 + 模式路由
├── playbooks/
│   ├── default.json          # 标准 APT 模拟 Playbook (4 阶段)
│   └── high-defense.json     # 高防护靶场 Playbook (4 阶段)
├── src/
│   ├── config/
│   │   ├── hooks.ts          # 钩子系统 — 工具执行前后钩子
│   │   ├── settings.ts       # 配置解析 — 环境变量/JSON 配置
│   │   └── ovogomd.ts        # Markdown 配置加载器
│   ├── core/
│   │   ├── engine.ts         # 核心执行引擎 — LLM 调用 + 工具分发
│   │   ├── types.ts          # 类型定义 — Tool/TurnResult/EngineConfig
│   │   ├── agentTypes.ts     # Agent 类型定义
│   │   ├── contextBudget.ts  # 上下文截断管理
│   │   ├── episodicMemory.ts # 过程记忆 — 记录已执行操作
│   │   ├── semanticMemory.ts # 语义记忆 — 概念/知识存储
│   │   ├── toolCache.ts      # 工具结果缓存
│   │   ├── eventLog.ts       # 事件日志
│   │   ├── progressTracker.ts# 进度追踪
│   │   ├── priorityQueue.ts  # 优先级队列
│   │   └── skillRegistry.ts  # 技能注册表
│   ├── lv999/
│   │   ├── cli.ts            # Lv999 模式入口
│   │   ├── stateMachine.ts   # 状态机 — Playbook 驱动阶段推进
│   │   ├── playbookTypes.ts  # Playbook 类型定义
│   │   ├── promptBuilder.ts  # 提示词组装 — Mindset + 决策树 + Snapshot
│   │   ├── mindset.ts        # APT 思维模板
│   │   ├── toolFilter.ts     # 工具白名单过滤
│   │   └── cli.ts            # Lv999 CLI 入口
│   ├── prompts/
│   │   ├── system.ts         # 基础系统提示词
│   │   ├── tools.ts          # 工具描述模板
│   │   ├── attackKnowledge.ts# 攻击方法论知识库
│   │   └── agentPrompts.ts   # 各角色 Agent 提示词
│   ├── tools/
│   │   ├── index.ts          # 工具注册中心
│   │   ├── bash.ts           # Bash 命令执行
│   │   ├── fileRead.ts       # 文件读取
│   │   ├── fileWrite.ts      # 文件写入
│   │   ├── fileEdit.ts       # 文件编辑
│   │   ├── glob.ts           # 文件模式匹配
│   │   ├── grep.ts           # 内容搜索
│   │   ├── webFetch.ts       # HTTP 请求
│   │   ├── webSearch.ts      # 搜索引擎
│   │   ├── agent.ts          # 子代理委派
│   │   ├── todo.ts           # 任务追踪
│   │   ├── tmuxSession.ts    # Tmux 交互式会话
│   │   ├── shellSession.ts   # 反弹 Shell 管理
│   │   ├── docRead.ts        # 文档读取
│   │   ├── c2.ts             # C2 框架接口 (Metasploit/Sliver)
│   │   ├── envAnalyzer.ts    # WAF/EDR/沙箱检测
│   │   ├── techniqueGenerator.ts # 绕过技术生成器 (23 种)
│   │   └── weaponRadar.ts    # PoC 语义检索 (HTTP API)
│   ├── services/
│   │   └── mcp/              # MCP 协议支持
│   │       ├── client.ts     # MCP 客户端
│   │       ├── loader.ts     # MCP 服务器加载
│   │       ├── mcpTool.ts    # MCP 工具适配
│   │       └── types.ts      # MCP 类型定义
│   ├── skills/
│   │   └── loader.ts         # 技能加载器
│   ├── memory/
│   │   └── index.ts          # 记忆系统入口
│   └── ui/
│       ├── renderer.ts       # 终端 UI 渲染器
│       ├── input.ts          # 用户输入处理
│       └── tmuxLayout.ts     # Tmux 面板布局
└── package.json
```

## 设计决策

### 为什么单 Agent 串行？

多 Agent 并行的问题：
- 工具冲突（多个 Agent 同时操作 ShellSession/C2）
- 上下文混乱（各自的历史记录无法共享关键发现）
- 无法形成连贯的攻击链

单 Agent 串行通过 State Machine 实现：
- 每个阶段一个 Agent，专注一个目标
- 阶段间 Snapshot 传递关键信息
- 上下文重置避免无关信息干扰
- 符合真实 APT 攻击的串行特性（侦察 → 武器化 → 投递 → 后渗透）

### 为什么 Playbook 驱动？

硬编码阶段流程的问题：
- 无法适配不同场景（标准靶场 vs 高防护）
- 修改逻辑需要改代码
- 无法自定义过渡条件

Playbook 驱动的优势：
- JSON 定义即可定制完整攻击流程
- 每个阶段的工具集、超时、过渡规则独立配置
- 决策树动态渲染到提示词，影响 LLM 决策

### 为什么上下文重置？

保留完整历史的问题：
- 侦察阶段的几十个发现会污染武器化阶段的决策
- LLM 上下文越长，推理质量越低
- 无法聚焦当前阶段的核心目标

Snapshot 方案：
- 阶段结束时提取摘要（可配置策略）
- 新阶段只收到摘要，不收到原始对话
- 摘要质量直接影响下一阶段效果

## 技术栈

| 组件 | 技术 |
|------|------|
| 语言 | TypeScript 5.7 (ESM) |
| 运行时 | Node.js ≥ 20 |
| LLM API | Claude (Anthropic SDK) / OpenAI SDK |
| C2 框架 | Metasploit / Sliver (通过 HTTP API) |
| 攻击知识 | Havoc C2 26 模块 / Sliver C2 / APT28 战术提取 |
| 协议支持 | MCP (Model Context Protocol) |
| 终端 UI | 自定义 Renderer + Tmux 面板 |

## 安全声明

本项目仅用于**授权安全测试**和**教育研究**目的。在未经授权的 target 上使用本工具可能违反当地法律。使用者需自行承担法律责任。

## 许可

MIT License
