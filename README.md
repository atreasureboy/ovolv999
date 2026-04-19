# ovolv999 — 二进制武器化 Agent 插件

<div align="center">

**Orchestrator 调度 · 子 Agent 分工 · 二进制武器化 · Havoc/Sliver/APT28 技术栈**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node](https://img.shields.io/badge/Node-%3E%3D20-339933?logo=node.js)](https://nodejs.org/)
[![Claude](https://img.shields.io/badge/AI-Claude%20%7C%20OpenAI-191919)](https://claude.ai/)

> `ovogogogo "compile evasion payload for target"`

</div>

## 简介

ovolv999 是一个**二进制武器化特化 Agent 插件**。外部系统提供目标信息（架构、漏洞、已有 shell），ovolv999 依据 Havoc/Sliver/APT28 的技术思路，将输入的 payload 进行免杀包装和武器化编译，每次生成随机指纹的二进制武器。

- **环境感知** — EnvAnalyzer 自动检测 WAF/EDR/沙箱防护，生成绕过建议
- **二进制武器化** — TechniqueGenerator 编译免杀二进制，随机指纹，参考 Havoc/Sliver/APT28 真实链路
- **Agent 基座** — 保留 Agent tool 和 engine 机制，未来可扩展 APT34/APT127 等新链路
- **单 Agent 机制** — 主 Agent 直接执行，无多阶段子 Agent 编排
- **上下文优化** — Critic 纠错、自动压缩、预算分配

## 完整架构全景图

```
===================================================================================
                       ovolv999 — 完整架构全景图
===================================================================================

  用户输入: "compile evasion payload for target" / 外部系统传入目标信息
       │
       ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  CLI Entry  bin/ovogogogo.ts                                             │
  │  ├── 解析参数 → REPL 或单任务模式                                       │
  │  ├── 加载 Settings → Hooks + Engagement                                 │
  │  ├── 加载 Skills → 安全工具模板                                         │
  │  ├── 加载 OVOGO.md → 项目特定指令                                       │
  │  └── 创建 Engine → 启动执行                                             │
  └────────────────────────────┬────────────────────────────────────────────┘
                               │
                               ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  Execution Engine  src/core/engine.ts                                    │
  │  ├── Streaming LLM API (Claude / OpenAI)                                │
  │  ├── Critic 检查 → 每 N 轮自动纠错（武器化上下文）                       │
  │  ├── Context 压缩 → 自动上下文预算                                      │
  │  └── 工具分发 → 并行(安全) vs 串行(状态) 调度                           │
  └────────────────────────────┬────────────────────────────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
  ┌──────────────────┐ ┌──────────────┐ ┌──────────────────┐
  │  Agent Tool      │ │ EnvAnalyzer  │ │TechniqueGenerator│
  │  子 Agent 委派   │ │ 防护检测     │ │ 二进制武器化     │
  │  保留机制        │ │ WAF/EDR/沙箱 │ │ 23种绕过技术     │
  │  未来APT扩展     │ │              │ │ 随机指纹         │
  └──────────────────┘ └──────────────┘ └──────────────────┘
       │
  ┌────▼──────────────────────────────────────────────────────────────────┐
  │  工具层 (16 个 Core Tools)                                              │
  │  ┌────────┬────────┬────────┬────────┬────────┬────────┬────────┐     │
  │  │ Bash   │ Read   │ Write  │ Edit   │ Glob   │ Grep   │ Todo   │     │
  │  │ 命令   │ 读取   │ 写入   │ 编辑   │ 匹配   │ 搜索   │ 任务   │     │
  │  └────────┴────────┴────────┴────────┴────────┴────────┴────────┘     │
  │  ┌────────┬────────┬────────┬────────┬────────┬────────┬────────┐     │
  │  │WebFetch│WebSearch│ Agent  │ C2     │TmuxSess│ShellSes│DocRead │     │
  │  │ HTTP   │ 搜索   │ 子代理 │ 框架   │ 交互终 │ 反弹sh │ 文档   │     │
  │  └────────┴────────┴────────┴────────┴────────┴────────┴────────┘     │
  │  ┌────────┬────────┐                                                  │
  │  │EnvAnlzr│TechGen │ ← 核心武器化工具                                  │
  │  │ 防护检测│ 武器化 │                                                  │
  │  └────────┴────────┘                                                  │
  └───────────────────────────────────────────────────────────────────────┘
       │
  ┌────▼──────────────────────────────────────────────────────────────────┐
  │  知识库 & 记忆层                                                        │
  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │
  │  │ SemanticMem  │ │ EpisodicMem  │ │ EventLog     │ │ ContextBudget│ │
  │  │ 概念知识存储 │ │ 行为轨迹记录 │ │ 事件日志     │ │ 上下文预算   │ │
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
  │  │   Havoc/Sliver/APT28   │ │ • general-purpose      │               │
  │  │ • 红旗信号 / 错误处理   │ │ • explore / plan / ... │               │
  │  └────────────────────────┘ └────────────────────────┘               │
  └───────────────────────────────────────────────────────────────────────┘

  输出: sessions/YYYY_MM_DD_HHMM/ → 所有发现、报告、编译产物
===================================================================================
```

## 核心模块详解

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
│    ├─▶ Critic 检查 → 每 N 轮自动纠错（武器化上下文）           │
│    │                                                          │
│    └─▶ 并发优化:                                             │
│         ├── 安全工具批次 → Promise.all 并行                   │
│         └── 状态工具 → 串行执行                               │
│                                                               │
│  支持: softAbort (ESC 暂停) / hardAbort (Ctrl+C 取消)         │
└──────────────────────────────────────────────────────────────┘
```

### Agent Tool — 子 Agent 委派

```
┌──────────────────────────────────────────────────────────────┐
│                       AgentTool                               │
│                                                               │
│  保留 Agent 基座机制，用于未来 APT 链路扩展:                    │
│                                                               │
│  当前可用类型:                                                 │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │ explore     │ │ plan        │ │ code-reviewer│            │
│  │ 代码探索    │ │ 实现规划    │ │ 安全代码审计 │            │
│  │ (只读)      │ │ (只读)      │ │ (只读)       │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
│  ┌─────────────┐                                             │
│  │general-purpose│ ← 红队通用 agent，所有工具可用             │
│  └─────────────┘                                             │
│                                                               │
│  每个 Agent: 独立 Engine + 专属系统提示 + 隔离会话目录         │
└──────────────────────────────────────────────────────────────┘
```

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

### 工具层 (16 个 Core Tools)

| 类别 | 工具 | 职责 |
|------|------|------|
| 基础 | Bash, Read, Write, Edit, Glob, Grep, TodoWrite | 文件操作、命令执行 |
| 网络 | WebFetch, WebSearch | HTTP 请求、搜索引擎 |
| 委派 | Agent | 子 Agent 调度（保留基座） |
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
npx tsx bin/ovogogogo.ts "compile evasion payload"

# 指定模型和工作目录
npx tsx bin/ovogogogo.ts -m claude-sonnet-4-6 --cwd /my/project
```

## 项目结构

```
ovolv999/
├── bin/
│   └── ovogogogo.ts          # 主入口 — CLI + REPL
├── src/
│   ├── config/
│   │   ├── hooks.ts          # 钩子系统 — 工具执行前后回调
│   │   ├── settings.ts       # 配置解析 — 环境变量/JSON/engagement
│   │   └── ovogomd.ts        # Markdown 配置加载器
│   ├── core/
│   │   ├── engine.ts         # 核心执行引擎 — LLM + 工具分发
│   │   ├── types.ts          # 核心类型定义
│   │   ├── compact.ts        # 上下文压缩 — 自动截断/摘要
│   │   ├── contextBudget.ts  # 预算分配 — token 比例管理
│   │   ├── episodicMemory.ts # 过程记忆 — 行为轨迹
│   │   ├── semanticMemory.ts # 语义记忆 — 概念存储
│   │   ├── eventLog.ts       # 事件日志 — 审计追踪
│   │   └── agentResultTypes.ts / agentTypes.ts # Agent 结果类型
│   ├── prompts/
│   │   ├── system.ts         # 完整系统提示词组装
│   │   ├── tools.ts          # 工具描述常量
│   │   ├── attackKnowledge.ts# 攻击方法论知识库
│   │   └── agentPrompts.ts   # 各角色 Agent 提示词
│   ├── tools/
│   │   ├── index.ts          # 工具注册中心 (16 个)
│   │   ├── bash.ts           # Bash 命令执行
│   │   ├── agent.ts          # 子 Agent 委派
│   │   ├── techniqueGenerator.ts # 二进制武器化 (23种技术)
│   │   ├── envAnalyzer.ts    # WAF/EDR/沙箱检测
│   │   ├── c2.ts             # C2 框架接口
│   │   ├── shellSession.ts   # 反弹 Shell 管理
│   │   ├── tmuxSession.ts    # Tmux 交互会话
│   │   ├── docRead.ts        # PDF/Excel/图片读取
│   │   └── ... (标准工具)
│   ├── skills/               # Skill 加载
│   ├── memory/               # Memory stub
│   └── ui/
│       ├── renderer.ts       # 终端 UI 渲染
│       ├── input.ts          # 用户输入处理
│       └── tmuxLayout.ts     # Tmux 面板布局
└── package.json
```

## 设计决策

### 为什么定位为武器化插件？

传统 Agent 框架的问题：
- 信息收集阶段过于困难，Agent 难以在复杂环境中完成全面侦察
- 外部系统已经完成了侦察和漏洞扫描，重复执行浪费资源
- 核心价值不在侦察，在于武器化——如何将已知漏洞转化为有效武器

插件方案：
- 外部系统提供目标信息（架构、漏洞、已有 shell）
- ovolv999 专注武器化：免杀包装、随机指纹、二进制编译
- 参考 Havoc/Sliver/APT28 的真实技术链路

### 为什么保留 Agent 基座？

- 未来可能有 APT34/APT127 等新链路需要 Agent 协调
- TechniqueGenerator 生成的武器需要智能选择和组合
- Agent 基座提供了灵活的扩展机制

### 为什么参考 Havoc/Sliver/APT28？

这三者代表了实战级别的武器化思路：
- **Havoc**：间接系统调用绕过 EDR hook、硬件断点 AMSI 绕过、睡眠混淆
- **Sliver**：RefreshPE DLL 卸载、SGN 多态编码、PE Donor 元数据伪造
- **APT28**：多层加密链（XOR → 轮转 XOR → PNG 隐写）、WebDAV UNC 无落地、APC 注入

这些不是理论原理，是框架实际使用、APT 组织实战验证的技术。

## 技术栈

| 组件 | 技术 |
|------|------|
| 语言 | TypeScript 5.7 (ESM) |
| 运行时 | Node.js ≥ 20 |
| LLM API | Claude (Anthropic SDK) / OpenAI SDK |
| C2 框架 | Metasploit / Sliver (HTTP API) |
| 攻击知识 | Havoc C2 / Sliver C2 / APT28 战术提取 |

## 安全声明

本项目仅用于**授权安全测试**和**教育研究**目的。在未经授权的 target 上使用本工具可能违反当地法律。使用者需自行承担法律责任。

## 许可

MIT License
