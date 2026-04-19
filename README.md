# ovolv999 — Agent 基座

<div align="center">

**可插拔的 Claude Code Agent 插件框架 · 流式引擎 · 并发调度 · 子 Agent 隔离**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node](https://img.shields.io/badge/Node-%3E%3D20-339933?logo=node.js)](https://nodejs.org/)

> `ovogogogo "任何你需要它完成的任务"`

</div>

## 简介

ovolv999 是一个**可插拔的 Agent 基座框架**。它不绑定任何特定领域——你可以通过编写自定义 Tool 插件将其接入任何场景（安全评估、代码审计、运维自动化、数据管道等），基座提供流式 LLM 调度、并发工具分发、子 Agent 隔离执行和上下文预算管理。

- **流式引擎** — Streaming LLM API，tool_call 解析 → 自动执行 → 结果注入 → 循环
- **并发调度** — 安全工具并行 (Promise.all)，状态工具串行，自动分区
- **子 Agent 隔离** — 独立 Engine + 专属系统提示 + 隔离会话目录
- **上下文预算** — 自动压缩、token 比例管理、语义/过程记忆
- **Critic 纠错** — 每 N 轮自动检查，发现错误自动回退重试
- **零领域绑定** — 核心是 Agent 基础设施，业务逻辑通过 Tool 插件注入

## 完整架构全景图

```
╔══════════════════════════════════════════════════════════════════════════╗
║                         ovolv999 — 完整架构全景图                          ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  用户输入: "你的任意任务指令"                                               ║
║       │                                                                 ║
║       ▼                                                                 ║
║  ┌──────────────────────────────────────────────────────────────────┐  ║
║  │  CLI Entry  bin/ovogogogo.ts                                      │  ║
║  │  ├── 参数解析 → REPL 交互 / 单任务模式                             │  ║
║  │  ├── Settings 加载 → 环境变量 / JSON / engagement config         │  ║
║  │  ├── Hooks 加载 → 工具执行前后回调                                │  ║
║  │  └── Engine 创建 → 启动执行循环                                    │  ║
║  └────────────────────────────────┬─────────────────────────────────┘  ║
║                                   │                                     ║
║                                   ▼                                     ║
║  ┌──────────────────────────────────────────────────────────────────┐  ║
║  │  Execution Engine  src/core/engine.ts                             │  ║
║  │  ┌────────────────────────────────────────────────────────────┐  │  ║
║  │  │  Streaming LLM API (Claude / OpenAI)                       │  │  ║
║  │  │       │                                                     │  │  ║
║  │  │       ├─▶ 纯文本 → 注入历史 → 返回                          │  │  ║
║  │  │       │                                                     │  │  ║
║  │  │       └─▶ tool_calls → 分区调度 → 执行 → 结果注入 → 继续   │  │  ║
║  │  └────────────────────────────────────────────────────────────┘  │  ║
║  │                                                                   │  ║
║  │  ├── Critic 检查 → 每 N 轮自动纠错                                 │  ║
║  │  ├── Context 压缩 → 自动上下文预算                                 │  ║
║  │  └── partitionToolCalls → 并行(安全) vs 串行(状态)                │  ║
║  └────────────────────────────────┬─────────────────────────────────┘  ║
║                                   │                                     ║
║              ┌────────────────────┼────────────────────┐               ║
║              │                    │                    │               ║
║              ▼                    ▼                    ▼               ║
║  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐      ║
║  │  Agent Tool      │ │  Bash Tool       │ │  File Tools      │      ║
║  │  子 Agent 委派   │ │  命令执行        │ │  Read/Write/Edit │      ║
║  │  独立 Engine     │ │  && 链式         │ │  Glob/Grep       │      ║
║  └──────────────────┘ └──────────────────┘ └──────────────────┘      ║
║  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐      ║
║  │  Web Tools       │ │  Session Tools   │ │  Todo Tool       │      ║
║  │  Fetch / Search  │ │  Tmux / Shell    │ │  任务跟踪        │      ║
║  └──────────────────┘ └──────────────────┘ └──────────────────┘      ║
║           │                     │                                     ║
║  ┌────────▼─────────────────────▼──────────────────────────────┐     ║
║  │              知识库 & 记忆层                                   │     ║
║  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐       │     ║
║  │  │ SemanticMem  │ │ EpisodicMem  │ │ ContextBudget│       │     ║
║  │  │ 概念知识     │ │ 行为轨迹     │ │ 上下文预算   │       │     ║
║  │  └──────────────┘ └──────────────┘ └──────────────┘       │     ║
║  └───────────────────────────────────────────────────────────┘     ║
║                                                                    ║
║  输出: sessions/YYYY_MM_DD_HHMM/ → 会话产物、报告、文件             ║
╚══════════════════════════════════════════════════════════════════════╝
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
│    │    └── tool_calls → partitionToolCalls → 分区执行       │
│    │                                                          │
│    ├─▶ Critic 检查 → 每 N 轮自动纠错                          │
│    │                                                          │
│    └─▶ 并发调度:                                              │
│         ├── 安全工具批次 → Promise.all 并行                    │
│         ├── Write/Edit → 串行 (状态依赖)                       │
│         └── Agent → 独立 Engine 隔离执行                      │
│                                                               │
│  支持: softAbort (ESC 暂停) / hardAbort (Ctrl+C 取消)         │
└──────────────────────────────────────────────────────────────┘
```

### 并发分区调度

```
tool_calls [A, B, C, D, E, F]
     │
     ├─ partitionToolCalls()
     │
     ├─ Batch 1 (并行): [A=Read, B=Glob, C=WebSearch]
     │     → Promise.all([A, B, C]) → 同时执行
     │
     ├─ Batch 2 (串行): [D=Write]
     │     → 等 Batch 1 完成 → 执行 D
     │
     └─ Batch 3 (并行): [E=Bash, F=Agent]
           → Promise.all([E, F]) → 同时执行
```

### Agent Tool — 子 Agent 隔离

```
┌──────────────────────────────────────────────────────────────┐
│                       AgentTool                               │
│                                                               │
│  子 Agent = 独立 Engine + 专属系统提示 + 隔离会话目录           │
│                                                               │
│  可用类型:                                                     │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │ explore     │ │ plan        │ │ code-reviewer│            │
│  │ 代码探索    │ │ 实现规划    │ │ 安全代码审计 │            │
│  │ (只读)      │ │ (只读)      │ │ (只读)       │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
│  ┌─────────────┐                                             │
│  │general-purpose│ ← 通用 agent，全部工具可用                  │
│  └─────────────┘                                             │
└──────────────────────────────────────────────────────────────┘
```

### 工具层 (11 个 Core Tools)

| 类别 | 工具 | 职责 |
|------|------|------|
| 基础 | Bash, Read, Write, Edit, Glob, Grep, TodoWrite | 文件操作、命令执行、任务跟踪 |
| 网络 | WebFetch, WebSearch | HTTP 请求、搜索引擎 |
| 委派 | Agent | 子 Agent 隔离调度 |
| 会话 | TmuxSession, ShellSession | 交互进程管理 |

## 如何扩展

ovolv999 的核心设计是**基座 + 插件**模式。要添加新能力：

1. **编写 Tool 插件** — 实现 `Tool` 接口，在 `src/tools/index.ts` 注册
2. **添加系统提示** — 在 `src/prompts/` 中注入领域知识
3. **配置 Hooks** — 在 `src/config/hooks.ts` 中添加工具执行前后的钩子

```typescript
// 示例: 添加一个自定义工具
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'

export class MyCustomTool implements Tool {
  name = 'MyCustom'
  definition: ToolDefinition = { /* OpenAI function calling schema */ }
  async execute(input: Record<string, unknown>, ctx: ToolContext): Promise<ToolResult> {
    // 你的业务逻辑
    return { content: 'done', isError: false }
  }
}
```

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
npx tsx bin/ovogogogo.ts "你的任务描述"

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
│   │   └── eventLog.ts       # 事件日志 — 审计追踪
│   ├── prompts/
│   │   ├── system.ts         # 完整系统提示词组装
│   │   ├── tools.ts          # 工具描述常量
│   │   └── agentPrompts.ts   # 各角色 Agent 提示词
│   ├── tools/
│   │   ├── index.ts          # 工具注册中心 (11 个基座工具)
│   │   ├── bash.ts           # Bash 命令执行
│   │   ├── agent.ts          # 子 Agent 委派
│   │   ├── fileRead.ts       # 文件读取
│   │   ├── fileWrite.ts      # 文件写入
│   │   ├── fileEdit.ts       # 文件编辑
│   │   ├── glob.ts           # 文件路径匹配
│   │   ├── grep.ts           # 文件内容搜索
│   │   ├── todo.ts           # 任务跟踪
│   │   ├── webFetch.ts       # 网页抓取
│   │   ├── webSearch.ts      # 网络搜索
│   │   ├── tmuxSession.ts    # Tmux 会话管理
│   │   └── shellSession.ts   # Shell 会话管理
│   ├── skills/               # Skill 加载
│   ├── memory/               # Memory stub
│   └── ui/
│       ├── renderer.ts       # 终端 UI 渲染
│       ├── input.ts          # 用户输入处理
│       └── tmuxLayout.ts     # Tmux 面板布局
└── package.json
```

## 设计决策

### 为什么是纯基座，不绑定领域？

绑定特定领域（如"二进制武器化"）的框架缺乏灵活性——换一个场景就要重写整个 engine。ovolv999 的选择：

- **Engine 是纯调度器** — 不关心业务逻辑，只负责 LLM 调用、工具分区、结果注入
- **业务逻辑在 Tool 层** — 每个 Tool 是独立的 OpenAI function calling 处理器
- **提示词可插拔** — 领域知识通过 prompts 注入，不硬编码到 engine

这意味着同一个基座可以服务完全不同的场景，只需替换 Tool 和 Prompt。

### 为什么保留子 Agent 隔离？

复杂任务需要多角色协作——探索者发现代码结构，规划者设计实现方案，审查者检查安全性。每个角色需要：

- 独立的工具权限（探索者只读，规划者只读，审查者只读）
- 独立的上下文（不需要知道彼此的完整对话）
- 独立的会话目录（产物隔离）

Agent Tool 提供了这个机制，且可以自定义新的子 Agent 类型。

## 技术栈

| 组件 | 技术 |
|------|------|
| 语言 | TypeScript 5.7 (ESM) |
| 运行时 | Node.js ≥ 20 |
| LLM API | Claude (Anthropic SDK) / OpenAI SDK |

## 安全声明

本项目仅用于**授权安全测试**和**教育研究**目的。在未经授权的 target 上使用本工具可能违反当地法律。使用者需自行承担法律责任。

## 许可

MIT License
