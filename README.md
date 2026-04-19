# ovolv999 — 二进制武器化引擎

<div align="center">

**Havoc × Sliver × APT28 技术栈 · 免杀编译 · 随机指纹 · 插件化接口**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node](https://img.shields.io/badge/Node-%3E%3D20-339933?logo=node.js)](https://nodejs.org/)
[![Claude](https://img.shields.io/badge/AI-Claude%20%7C%20OpenAI-191919)](https://claude.ai/)

> `ovolv999 "compile Windows reverse shell with AMSI bypass for x.x.x.x"`

</div>

## 简介

ovolv999 是一个**二进制武器化插件引擎**。外部传入目标信息（架构、漏洞、已有 shell），它负责将原始 payload 编译成高对抗环境下可执行的免杀二进制文件。

- **不是全流程 agent** — 不做侦察、不投递、不后渗透，只做武器化
- **真实编译** — 生成 C/Go 源码 → 交叉编译 → 输出可执行文件
- **随机指纹** — 每次编译唯一：不同时间戳、不同 XOR 密钥、不同编码顺序
- **参考真实链路** — Havoc C2 / Sliver C2 / APT28 的实战操作模式
- **插件化接口** — 外部系统通过 API/CLI 直接调用，无需交互

## 完整架构

```
===================================================================================
                     ovolv999 — 二进制武器化引擎架构
===================================================================================

  外部系统传入: { target: "x.x.x.x", arch: "windows/amd64", payload: "...",
                  evasion: ["amsi_bypass", "indirect_syscall"] }
       │
       ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  CLI / REPL  bin/ovogogogo.ts                                            │
  │  ├── 解析传入的武器化需求                                                │
  │  ├── 注入 TechniqueGenerator 系统提示词                                  │
  │  └── 执行引擎自动循环直到编译完成                                        │
  └────────────────────────────┬────────────────────────────────────────────┘
                               │
                               ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  Execution Engine  src/core/engine.ts                                    │
  │  ├── LLM API 调用 (Claude / OpenAI)                                     │
  │  ├── 解析 tool_calls → 分发到工具                                       │
  │  ├── 并发安全批次: 并行执行无副作用工具                                  │
  │  └── 工具结果注入 → 下一轮循环                                          │
  └────────────────────────────┬────────────────────────────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
  ┌──────────────────┐ ┌──────────────┐ ┌──────────────────┐
  │ TechniqueGenerator│ │  Bash Tool   │ │   C2 Tool        │
  │ (武器化核心)      │ │ (编译执行)   │ │ (Metasploit/     │
  │                  │ │              │ │  Sliver)         │
  │ 输入: technique  │ │ command:     │ │ deploy_listener │
  │   payload        │ │   gcc/       │ │ generate_payload│
  │   platform       │ │   mingw/     │ │                 │
  │   evasion_type   │ │   garble     │ │                 │
  │                  │ │              │ │                 │
  │ 输出: 编译源码   │ │ 输出: 编译   │ │ 输出: session   │
  │  → 编译指令     │ │  结果/错误   │ │  ID/output      │
  │  → 免杀策略     │ │              │ │                 │
  └──────────────────┘ └──────────────┘ └──────────────────┘
       │
  ┌────▼──────────────────────────────────────────────────────────────────┐
  │  知识库层 (硬编码到 TechniqueGenerator)                                  │
  │                                                                       │
  │  ┌────────────────────────┐ ┌────────────────────────┐               │
  │  │ Havoc C2 技术栈         │ │ Sliver C2 技术栈        │               │
  │  │ • 间接系统调用          │ │ • RefreshPE DLL 卸载    │               │
  │  │ • 硬件断点 AMSI 绕过    │ │ │ • 0xC3 AMSI/ETW 补丁 │               │
  │  │ • 睡眠混淆 (Ekko/Zilean)│ │ │ • SGN 多态编码        │               │
  │  │ • 栈欺骗 (Stack Spoof)  │ │ • 流量编码多态          │               │
  │  │ • Hash API 解析         │ │ • PE Donor 元数据伪造   │               │
  │  │ • 编译器标志优化         │ │ • .NET 双模式执行       │               │
  │  └────────────────────────┘ └────────────────────────┘               │
  │  ┌────────────────────────┐                                           │
  │  │ APT28 技术栈            │                                           │
  │  │ • 交替字节 XOR + Null   │                                           │
  │  │   填充字符串混淆        │                                           │
  │  │ • 76字节轮转 XOR 密钥   │                                           │
  │  │ • PNG 隐写 (IDAT LSB)   │                                           │
  │  │ • RW→RX 权限转换        │                                           │
  │  │ • APC 注入 (QueueUserAPC)│                                           │
  │  │ • COM 劫持持久化        │                                           │
  │  │ • Dead Drop Resolver    │                                           │
  │  │ • WebDAV UNC 无落地执行  │                                           │
  │  └────────────────────────┘                                           │
  └───────────────────────────────────────────────────────────────────────┘

  输出: session/YYYY_MM_DD_HHMM/ → 编译好的二进制 + 源码 + 执行说明
===================================================================================
```

## 核心模块详解

### TechniqueGenerator — 武器化核心

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
│  支持: softAbort (暂停) / hardAbort (取消)                    │
└──────────────────────────────────────────────────────────────┘
```

### Tool Dispatcher — 工具集

| 工具 | 职责 | 并发安全 |
|------|------|---------|
| Bash | 编译、运行命令 | ✓ |
| Read | 读取文件 | ✓ |
| Write | 写入文件 | ✗ |
| Edit | 编辑文件 | ✗ |
| Glob | 文件匹配 | ✓ |
| Grep | 内容搜索 | ✓ |
| TodoWrite | 任务追踪 | ✓ |
| TmuxSession | 交互式进程管理 | ✓ |
| ShellSession | 反弹 Shell 管理 | ✓ |
| C2 | Metasploit/Sliver 接口 | ✓ |
| **TechniqueGenerator** | **武器化核心 — 23种绕过技术** | ✗ |

## 快速开始

### 安装

```bash
git clone https://github.com/atreasureboy/ovolv999.git
cd ovolv999
npm install
```

### 配置

```bash
# Claude API
export ANTHROPIC_API_KEY="your-key"

# 或 OpenAI 兼容 API
export OPENAI_API_KEY="your-key"
export OPENAI_BASE_URL="https://your-proxy.com/v1"
export OPENAI_MODEL="claude-sonnet-4-6-20250514"
```

### 使用

```bash
# 单任务模式 — 直接编译请求
npx tsx bin/ovogogogo.ts "compile Windows x64 reverse shell with AMSI bypass"

# 交互模式 — REPL
npx tsx bin/ovogogogo.ts

# 指定模型和工作目录
npx tsx bin/ovogogogo.ts -m claude-sonnet-4-6 --cwd ./output "generate payload"
```

## 项目结构

```
ovolv999/
├── bin/
│   └── ovogogogo.ts          # 主入口 — CLI 参数解析 + REPL
├── src/
│   ├── config/
│   │   ├── hooks.ts          # 钩子系统 — 工具执行前后回调
│   │   ├── settings.ts       # 配置解析 — 环境变量/JSON
│   │   └── ovogomd.ts        # Markdown 配置加载器
│   ├── core/
│   │   ├── engine.ts         # 核心执行引擎 — LLM 调用 + 工具分发
│   │   └── types.ts          # 类型定义 — Tool/TurnResult/EngineConfig
│   ├── prompts/
│   │   └── tools.ts          # 工具描述常量
│   ├── tools/
│   │   ├── index.ts          # 工具注册中心 (11 个工具)
│   │   ├── bash.ts           # Bash 命令执行
│   │   ├── fileRead.ts       # 文件读取
│   │   ├── fileWrite.ts      # 文件写入
│   │   ├── fileEdit.ts       # 文件编辑
│   │   ├── glob.ts           # 文件模式匹配
│   │   ├── grep.ts           # 内容搜索
│   │   ├── todo.ts           # 任务追踪
│   │   ├── tmuxSession.ts    # Tmux 交互式会话
│   │   ├── shellSession.ts   # 反弹 Shell 管理
│   │   ├── c2.ts             # C2 框架接口 (Metasploit/Sliver)
│   │   └── techniqueGenerator.ts # 武器化核心 (23 种绕过技术)
│   └── ui/
│       ├── renderer.ts       # 终端 UI 渲染器
│       ├── input.ts          # 用户输入处理
│       └── tmuxLayout.ts     # Tmux 面板布局
└── package.json
```

## 设计决策

### 为什么做插件而非全流程 agent？

全流程 agent 的问题：
- 侦察、投递、后渗透需要大量外部上下文（目标信息、网络拓扑、权限状态）
- 不同场景下信息收集方式完全不同，agent 无法自主覆盖所有情况
- 长时间运行的任务容易超时和迷失方向

插件化方案的优势：
- 外部系统传入精确的目标信息，武器化引擎专注执行
- 可嵌入任何工作流（独立 CLI、API 调用、其他 agent 的子模块）
- 编译任务有明确边界，超时可控

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
| C2 框架 | Metasploit / Sliver (通过 HTTP API) |
| 攻击知识 | Havoc C2 / Sliver C2 / APT28 战术提取 |
| 终端 UI | 自定义 Renderer + Tmux 面板 |

## 安全声明

本项目仅用于**授权安全测试**和**教育研究**目的。在未经授权的 target 上使用本工具可能违反当地法律。使用者需自行承担法律责任。

## 许可

MIT License
