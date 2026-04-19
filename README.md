# ovolv999 — 多 Agent 协同的攻防执行引擎

<div align="center">

**Orchestrator 调度 · 子 Agent 分工 · 二进制武器化 · Havoc/Sliver/APT28 技术栈**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node](https://img.shields.io/badge/Node-%3E%3D20-339933?logo=node.js)](https://nodejs.org/)
[![Claude](https://img.shields.io/badge/AI-Claude%20%7C%20OpenAI-191919)](https://claude.ai/)

> `ovogogogo "recon and exploit http://target.com"`

</div>

## 简介

ovolv999 是一个**多 Agent 协同的攻防执行引擎**。主 Agent 作为协调者（Orchestrator），将任务分发给专用子 Agent（侦察 / 漏洞扫描 / 利用 / 提权 / 横向移动 / 报告），每个子 Agent 拥有独立的工具集和知识库，专注于自己的领域。

- **Orchestrator 模式** — 主 Agent 只做决策，不执行具体操作
- **子 Agent 分工** — 7 类专用 Agent 各司其职，可并行调度
- **二进制武器化** — TechniqueGenerator 编译免杀二进制，随机指纹，参考 Havoc/Sliver/APT28 真实链路
- **上下文优化** — Critic 纠错、自动压缩、预算分配、知识积累
- **MCP 协议** — 支持外部工具服务器动态加载
- **Skills 系统** — 50+ 安全工具 skill 模板（nmap/nuclei/hydra/Sliver/Impacket…）

## 完整架构全景图

```
===================================================================================
                       ovolv999 — 完整架构全景图
===================================================================================

  用户输入: "recon and exploit http://target.com"
       │
       ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  CLI Entry  bin/ovogogogo.ts                                             │
  │  ├── 解析参数 → REPL 或单任务模式                                       │
  │  ├── 加载 MCP 服务器 → 动态工具注入                                     │
  │  ├── 加载 Skills → 50+ 安全工具模板                                     │
  │  ├── 加载 OVOGO.md → 项目特定指令                                       │
  │  └── 创建 Engine + Orchestrator → 启动执行                              │
  └────────────────────────────┬────────────────────────────────────────────┘
                               │
                               ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  Execution Engine  src/core/engine.ts                                    │
  │  ├── Streaming LLM API (Claude / OpenAI)                                │
  │  ├── Critic 检查 → 每 N 轮自动纠错                                      │
  │  ├── Context 压缩 → 自动上下文预算                                      │
  │  └── 工具分发 → 并行(安全) vs 串行(状态) 调度                           │
  └────────────────────────────┬────────────────────────────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
  ┌──────────────────┐ ┌──────────────┐ ┌──────────────────┐
  │  Orchestrator    │ │ DispatchMgr  │ │ TaskScheduler    │
  │  (战斗编排)       │ │ (异步分发)   │ │ (任务队列/超时)  │
  │  LLM Supervisor  │ │ launch/check │ │ timeout per task │
  │  决定: 并行/串行 │ │ result/revoke│ │ status tracking  │
  │  选择: Agent类型 │ │              │ │                  │
  └────────┬─────────┘ └──────────────┘ └──────────────────┘
           │
           ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                     子 Agent 执行体系 (7+ 类型)                            │
  │                                                                          │
  │  ┌───────────┐ ┌────────────┐ ┌───────────┐ ┌────────────┐             │
  │  │ recon     │ │ vuln-scan  │ │ exploit   │ │ privesc    │             │
  │  │ 信息收集  │ │ 漏洞扫描   │ │ 漏洞利用  │ │ 权限提升   │             │
  │  │ httpx/nmap│ │ nuclei/    │ │ msfvenom/ │ │ linpeas/   │             │
  │  │ subfinder │ │ dalfox/ffuf│ │ sliver/   │ │ winpeas/   │             │
  │  │           │ │            │ │ custom    │ │ GTFOBins   │             │
  │  └───────────┘ └────────────┘ └───────────┘ └────────────┘             │
  │  ┌───────────┐ ┌────────────┐ ┌───────────┐                            │
  │  │ lateral   │ │post-exploit│ │ report    │                            │
  │  │ 横向移动  │ │ 后渗透     │ │ 报告生成  │                            │
  │  │ chisel/   │ │ hashdump/  │ │ 执行摘要  │                            │
  │  │ ligolo/   │ │ mimikatz/  │ │ 技术发现  │                            │
  │  │ impacket  │ │ pivoting   │ │ 修复建议  │                            │
  │  └───────────┘ └────────────┘ └───────────┘                            │
  │                                                                          │
  │  每个 Agent: 独立 Engine + 隔离工具集 + 专属 Skills + 独立会话目录        │
  └─────────────────────────────────────────────────────────────────────────┘
       │
  ┌────▼──────────────────────────────────────────────────────────────────┐
  │  工具层 (22 个 Tools)                                                   │
  │  ┌────────┬────────┬────────┬────────┬────────┬────────┬────────┐     │
  │  │ Bash   │ Read   │ Write  │ Edit   │ Glob   │ Grep   │ Todo   │     │
  │  │ 命令   │ 读取   │ 写入   │ 编辑   │ 匹配   │ 搜索   │ 任务   │     │
  │  └────────┴────────┴────────┴────────┴────────┴────────┴────────┘     │
  │  ┌────────┬────────┬────────┬────────┬────────┬────────┬────────┐     │
  │  │WebFetch│WebSearch│ Agent  │ MultiA │ Dispatch│Finding │WeaponR │     │
  │  │ HTTP   │ 搜索   │ 子代理 │ 多代理 │ 异步   │ 漏洞记录│ PoC检索│     │
  │  └────────┴────────┴────────┴────────┴────────┴────────┴────────┘     │
  │  ┌────────┬────────┬────────┬────────┬────────┬────────┬────────┐     │
  │  │TmuxSess│ShellSess│ C2     │ DocRead│ MultiScan│EnvAnlzr│TechGen │     │
  │  │ 交互终 │ 反弹sh │ 框架   │ 文档   │ 扫描分发│ 环境检测│ 武器化 │     │
  │  └────────┴────────┴────────┴────────┴────────┴────────┴────────┘     │
  └───────────────────────────────────────────────────────────────────────┘
       │
  ┌────▼──────────────────────────────────────────────────────────────────┐
  │  知识库 & 记忆层                                                        │
  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │
  │  │ SemanticMem  │ │ EpisodicMem  │ │ KnowledgeBase│ │ SkillLoader  │ │
  │  │ 概念知识存储 │ │ 行为轨迹记录 │ │ 攻击知识积累 │ │ 技能模板加载 │ │
  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘ │
  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │
  │  │ ContextBudget│ │ Compaction   │ │ EventLog     │ │ ToolCache    │ │
  │  │ 上下文预算   │ │ 自动压缩     │ │ 事件日志     │ │ 结果缓存     │ │
  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘ │
  └───────────────────────────────────────────────────────────────────────┘
       │
  ┌────▼──────────────────────────────────────────────────────────────────┐
  │  提示词注入层                                                           │
  │  ┌────────────────────────┐ ┌────────────────────────┐               │
  │  │ attackKnowledge.ts     │ │ agentPrompts.ts        │               │
  │  │ • Web/框架/云原生/DB   │ │ • manual-exploit       │               │
  │  │ • AD/内网横向移动       │ │ • tool-exploit         │               │
  │  │ • EDR/AV 绕过 (26模块) │ │ • privesc / lateral    │               │
  │  │   Havoc/Sliver/APT28   │ │ • target-recon / report│               │
  │  │ • 红旗信号 / 错误处理   │ │ • general-purpose      │               │
  │  └────────────────────────┘ └────────────────────────┘               │
  └───────────────────────────────────────────────────────────────────────┘

  输出: sessions/YYYY_MM_DD_HHMM/ → 所有发现、报告、编译产物
===================================================================================
```

## 核心模块详解

### Orchestrator — 战斗编排

```
┌──────────────────────────────────────────────────────────────┐
│                    BattleOrchestrator                         │
│                                                               │
│  主 Agent 作为 LLM 协调者，决定:                               │
│  1. 当前阶段需要哪些子 Agent                                   │
│  2. 哪些可以并行 (recon + vuln-scan)                          │
│  3. 哪些需要串行 (exploit 依赖 vuln-scan 结果)                 │
│  4. 如何根据子 Agent 返回结果调整下一步策略                     │
│                                                               │
│  MultiAgent 并行分发:                                         │
│    ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐               │
│    │ recon  │ │vulnscan│ │exploit │ │privesc │ → 同时启动   │
│    └────────┘ └────────┘ └────────┘ └────────┘               │
│                                                               │
│  协调规则: 主 Agent 不直接执行扫描/利用，必须通过 Agent 委派   │
└──────────────────────────────────────────────────────────────┘
```

### 子 Agent 体系

| Agent 类型 | 职责 | 核心工具 |
|-----------|------|---------|
| **recon** | 信息收集、资产发现 | httpx, nmap, subfinder, masscan |
| **vuln-scan** | 漏洞扫描、PoC 验证 | nuclei, dalfox, ffuf, sqlmap |
| **exploit** | 漏洞利用、shell 获取 | msfvenom, sliver, custom PoC |
| **privesc** | 权限提升 | linpeas, winpeas, GTFOBins |
| **lateral** | 横向移动 | chisel, ligolo-ng, impacket |
| **post-exploit** | 后渗透、数据收集 | mimikatz, hashdump, pivoting |
| **report** | 报告生成 | FindingWrite, 执行总结 |

### TechniqueGenerator — 二进制武器化核心

```
┌──────────────────────────────────────────────────────────────┐
│                  TechniqueGeneratorTool                       │
│                                                               │
│  输入: { technique, payload, platform, analysis_context }    │
│                                                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ AMSI Bypass │  │ ETW Bypass  │  │ WAF Evasion │          │
│  │ 反射补丁    │  │ 反射补丁    │  │ 分块编码    │          │
│  │ 字符串混淆  │  │ 注册表禁用  │  │ 参数污染    │          │
│  │ 环境变量    │  │             │  │ Unicode编码 │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
│                                                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │Shellcode编码│  │ ObfuscatedPS│  │ Havoc策略  │          │
│  │ XOR/Hex/Base│  │ IEX/base64 │  │ 间接syscall │          │
│  │ 解码stub    │  │ 字符串拆分  │  │ 硬件断点    │          │
│  └─────────────┘  └─────────────┘  │ 睡眠混淆    │          │
│                                    │ 栈欺骗      │          │
│  ┌─────────────┐  ┌─────────────┐  │ Hash API    │          │
│  │ Sliver策略  │  │ APT28策略   │  └─────────────┘          │
│  │ RefreshPE   │  │ 交替XOR     │                           │
│  │ SGN编码     │  │ 76字节轮转  │                           │
│  │ 流量多态    │  │ PNG隐写     │                           │
│  │ PE Donor    │  │ RW→RX转换   │                           │
│  │ .NET双模式  │  │ APC注入     │                           │
│  │ Go模板      │  │ COM劫持     │                           │
│  └─────────────┘  │ Dead Drop   │                           │
│                   │ WebDAV UNC  │                           │
│                   └─────────────┘                           │
│                                                               │
│  每次编译唯一指纹: 不同时间戳 / XOR密钥 / 编码顺序             │
└──────────────────────────────────────────────────────────────┘
```

### Execution Engine — 执行引擎

```
┌──────────────────────────────────────────────────────────────┐
│                    ExecutionEngine                            │
│                                                               │
│  runTurn(message, history)                                    │
│    │                                                          │
│    ├─▶ Streaming LLM API 调用                                │
│    │                                                          │
│    ├─▶ 解析响应:                                              │
│    │    ├── 纯文本 → 注入历史 → 返回                          │
│    │    └── tool_calls → 分发执行 → 结果注入 → 继续           │
│    │                                                          │
│    ├─▶ Critic 检查 → 每 N 轮自动纠错                          │
│    │                                                          │
│    └─▶ 并发优化:                                             │
│         ├── 安全工具批次 → Promise.all 并行                   │
│         └── 状态工具 → 串行执行                               │
│                                                               │
│  支持: softAbort (ESC 暂停) / hardAbort (Ctrl+C 取消)         │
└──────────────────────────────────────────────────────────────┘
```

### 工具层 (22 个 Tools)

| 类别 | 工具 | 职责 |
|------|------|------|
| 基础 | Bash, Read, Write, Edit, Glob, Grep, TodoWrite | 文件操作、命令执行 |
| 网络 | WebFetch, WebSearch | HTTP 请求、搜索引擎 |
| 委派 | Agent, MultiAgent | 子 Agent 调度 |
| 异步 | DispatchAgent, CheckDispatch, GetDispatchResult | 异步任务管理 |
| 发现 | FindingWrite, FindingList | 漏洞记录管理 |
| 智能 | WeaponRadar, MultiScan, KnowledgeQuery | PoC 检索、扫描分发 |
| 会话 | TmuxSession, ShellSession | 交互进程、反弹 Shell |
| C2 | C2 | Metasploit/Sliver 接口 |
| 武器化 | EnvAnalyzer, TechniqueGenerator | 环境检测、二进制编译 |
| 文档 | DocRead | PDF/Excel/图片读取 |

## 快速开始

### 安装

```bash
git clone https://github.com/atreasureboy/ovolv999.git
cd ovolv999
npm install
```

### 配置

```bash
# OpenAI API (或兼容端点)
export OPENAI_API_KEY="your-key"
# export OPENAI_BASE_URL="https://your-proxy.com/v1"
# export OVOGO_MODEL="claude-sonnet-4-6-20250514"
```

### 使用

```bash
# 交互模式 — REPL
npx tsx bin/ovogogogo.ts

# 单任务模式
npx tsx bin/ovogogogo.ts "recon http://target.com"

# Orchestrator 模式 — LLM 自动调度多 Agent
npx tsx bin/ovogogogo.ts --orchestrator "full pentest http://target.com"

# 指定模型和工作目录
npx tsx bin/ovogogogo.ts -m claude-sonnet-4-6 --cwd /my/project
```

## 项目结构

```
ovolv999/
├── bin/
│   └── ovogogogo.ts          # 主入口 — CLI + REPL + Orchestrator 路由
├── .ovogo/skills/            # 50+ 安全工具 skill 模板
├── playbooks/                # Lv999 阶段流程定义 (已精简)
├── src/
│   ├── config/
│   │   ├── hooks.ts          # 钩子系统 — 工具执行前后回调
│   │   ├── settings.ts       # 配置解析 — 环境变量/JSON/engagement
│   │   └── ovogomd.ts        # Markdown 配置加载器
│   ├── core/
│   │   ├── engine.ts         # 核心执行引擎 — LLM + 工具分发
│   │   ├── orchestrator.ts   # 战斗编排 — LLM 决定子 Agent 调度
│   │   ├── taskScheduler.ts  # 任务调度 — 队列管理 + 超时
│   │   ├── dispatch.ts       # 异步分发 — launch/check/result
│   │   ├── shell.ts          # Shell 管理 — 主 agent shell 抽象
│   │   ├── knowledgeBase.ts  # 知识库 — 攻击知识持久化
│   │   ├── knowledgeExtractor.ts # 知识提取 — 从操作中提取模式
│   │   ├── compact.ts        # 上下文压缩 — 自动截断/摘要
│   │   ├── contextBudget.ts  # 预算分配 — token 比例管理
│   │   ├── episodicMemory.ts # 过程记忆 — 行为轨迹
│   │   ├── semanticMemory.ts # 语义记忆 — 概念存储
│   │   ├── eventLog.ts       # 事件日志 — 审计追踪
│   │   ├── toolCache.ts      # 工具缓存 — 避免重复执行
│   │   ├── progressTracker.ts# 进度追踪 — 长任务状态
│   │   ├── skillRegistry.ts  # 技能注册表
│   │   ├── agentResultTypes.ts # Agent 结果类型
│   │   ├── agentTypes.ts     # Agent 类型定义
│   │   └── types.ts          # 核心类型定义
│   ├── prompts/
│   │   ├── system.ts         # 完整系统提示词组装
│   │   ├── tools.ts          # 工具描述常量
│   │   ├── attackKnowledge.ts# 攻击方法论知识库
│   │   └── agentPrompts.ts   # 各角色 Agent 提示词
│   ├── tools/
│   │   ├── index.ts          # 工具注册中心 (22 个)
│   │   ├── bash.ts           # Bash 命令执行
│   │   ├── agent.ts          # 子 Agent 委派 + 异步分发
│   │   ├── multiAgent.ts     # 多 Agent 并行分发
│   │   ├── multiScan.ts      # 扫描任务分发
│   │   ├── finding.ts        # 漏洞记录管理
│   │   ├── c2.ts             # C2 框架接口
│   │   ├── shellSession.ts   # 反弹 Shell 管理
│   │   ├── tmuxSession.ts    # Tmux 交互会话
│   │   ├── envAnalyzer.ts    # WAF/EDR/沙箱检测
│   │   ├── techniqueGenerator.ts # 二进制武器化 (23种技术)
│   │   ├── weaponRadar.ts    # PoC 语义检索
│   │   └── ... (标准工具)
│   ├── services/mcp/         # MCP 协议支持
│   ├── skills/               # Skill 加载 + 各阶段 skill 定义
│   ├── memory/               # 记忆系统入口
│   ├── recon/                # 侦察 Agent + Skills + Tools
│   ├── vuln-scan/            # 漏洞扫描 Agent + Skills + Tools
│   ├── exploit/              # 漏洞利用 Agent + Skills + Tools
│   ├── privesc/              # 提权 Agent + Skills + Tools
│   ├── lateral/              # 横向移动 Agent + Skills + Tools
│   ├── post-exploit/         # 后渗透 Agent + Skills + Tools
│   ├── report/               # 报告 Agent + Skills + Tools
│   ├── c2/                   # C2 专用 Agent + Skills + Tools
│   └── ui/
│       ├── renderer.ts       # 终端 UI 渲染
│       ├── input.ts          # 用户输入处理
│       └── tmuxLayout.ts     # Tmux 面板布局
└── package.json
```

## 设计决策

### 为什么 Orchestrator + 子 Agent？

单 Agent 全流程的问题：
- 上下文容易污染，侦察阶段的发现会干扰武器化阶段的决策
- 无法并行 — 必须先完成侦察才能开始扫描
- 每个领域的专业知识太多，一个 Agent 难以覆盖所有

Orchestrator 方案：
- 主 Agent 只做决策：选择哪些子 Agent、并行还是串行
- 子 Agent 专注领域：recon 只关心信息收集，exploit 只关心利用
- 可并行执行：recon + vuln-scan 同时启动，节省时间
- 上下文隔离：每个子 Agent 独立引擎实例、独立历史

### 为什么参考 Havoc/Sliver/APT28？

这三者代表了实战级别的武器化思路：
- **Havoc**：间接系统调用绕过 EDR hook、硬件断点 AMSI 绕过、睡眠混淆
- **Sliver**：RefreshPE DLL 卸载、SGN 多态编码、PE Donor 元数据伪造
- **APT28**：多层加密链（XOR → 轮转 XOR → PNG 隐写）、WebDAV UNC 无落地、APC 注入

这些不是理论原理，是框架实际使用、APT 组织实战验证的技术。

### 为什么需要 Critic？

自动纠错机制 — 每 N 轮检查 LLM 是否：
- PoC 拿到了但没有执行
- 发现漏洞但没有继续利用
- 陷入重复劳动
- 忽略了重要发现

Critic 是一个轻量级 LLM 调用，只读历史、不执行操作，发现问题后注入纠正指令。

## 技术栈

| 组件 | 技术 |
|------|------|
| 语言 | TypeScript 5.7 (ESM) |
| 运行时 | Node.js ≥ 20 |
| LLM API | Claude (Anthropic SDK) / OpenAI SDK |
| C2 框架 | Metasploit / Sliver (HTTP API) |
| 攻击知识 | Havoc C2 / Sliver C2 / APT28 战术提取 |
| 协议支持 | MCP (Model Context Protocol) |
| 终端 UI | 自定义 Renderer + Tmux 面板 |

## 安全声明

本项目仅用于**授权安全测试**和**教育研究**目的。在未经授权的 target 上使用本工具可能违反当地法律。使用者需自行承担法律责任。

## 许可

MIT License
