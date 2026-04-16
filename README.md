# Ovogo - AI-Powered Red Team Automation Framework

<div align="center">

**基于 LangGraph 的智能红队自动化框架 | 三层架构 | LLM 驱动决策**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.2-green.svg)](https://github.com/langchain-ai/langgraph)
[![Claude](https://img.shields.io/badge/Claude-Sonnet%204-purple.svg)](https://www.anthropic.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[English](#english) | [中文](#中文)

</div>

---

## 中文

### 📖 项目简介

Ovogo 是一个革命性的红队自动化框架，将大语言模型（LLM）的智能决策能力与渗透测试工具深度集成。通过创新的三层架构（Tool → Skill → Agent）和 LangGraph 状态管理，实现了从侦察到报告生成的全流程自动化。

**核心特性：**
- 🤖 **8 个专业智能体** - 覆盖完整攻击链的每个阶段
- 🧠 **LLM 驱动决策** - Claude API 提供战略级智能
- 📊 **LangGraph 状态管理** - 清晰的状态流转和共享
- ⚡ **并行执行** - 技能链级别的并行优化
- 📝 **多格式报告** - Markdown、HTML、JSON、PDF

### 🏗️ 架构设计

#### 三层架构

```
┌─────────────────────────────────────────────────────────────┐
│                    Agent Layer (战略层)                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Recon   │  │VulnScan  │  │ Exploit  │  │  Report  │   │
│  │  Agent   │  │  Agent   │  │  Agent   │  │  Agent   │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       │             │              │             │          │
└───────┼─────────────┼──────────────┼─────────────┼──────────┘
        │             │              │             │
┌───────┼─────────────┼──────────────┼─────────────┼──────────┐
│       │             │              │             │          │
│  ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐   │
│  │Recon     │  │VulnScan  │  │Exploit   │  │Report    │   │
│  │Skills    │  │Skills    │  │Skills    │  │Skills    │   │
│  │(6 chains)│  │(6 chains)│  │(6 chains)│  │(4 chains)│   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       │             │              │             │          │
│            Skill Layer (战术层)                              │
└───────┼─────────────┼──────────────┼─────────────┼──────────┘
        │             │              │             │
┌───────┼─────────────┼──────────────┼─────────────┼──────────┐
│       │             │              │             │          │
│  ┌────▼─────────────▼──────────────▼─────────────▼─────┐   │
│  │  Atomic Tools (10+ tools per agent)                  │   │
│  │  • Subfinder  • Nmap      • Metasploit  • Markdown  │   │
│  │  • Amass      • Nikto     • SQLMap      • HTML      │   │
│  │  • Httpx      • Nuclei    • Webshell    • JSON      │   │
│  │  • Katana     • XSStrike  • LinPEAS     • PDF       │   │
│  └───────────────────────────────────────────────────────┘   │
│                    Tool Layer (原子层)                        │
└─────────────────────────────────────────────────────────────┘
```

#### LangGraph 状态图

```
                    ┌──────────────┐
                    │  Initialize  │
                    │    State     │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
              ┌─────┤  Supervisor  ├─────┐
              │     │    (LLM)     │     │
              │     └──────┬───────┘     │
              │            │             │
    ┌─────────▼──┐  ┌──────▼───────┐  ┌─▼──────────┐
    │   Recon    │  │  VulnScan    │  │  Exploit   │
    │   Worker   │  │   Worker     │  │   Worker   │
    └─────┬──────┘  └──────┬───────┘  └─┬──────────┘
          │                │             │
          └────────┬───────┴─────────────┘
                   │
            ┌──────▼───────┐
            │ Shared State │
            │  • findings  │
            │  • ports     │
            │  • shells    │
            │  • creds     │
            └──────────────┘
```

### 🎯 8 大智能体系统

| 智能体 | 工具数 | 技能链 | 核心能力 |
|--------|--------|--------|----------|
| **Recon Agent** | 10+ | 6 | 主机发现、端口扫描、服务识别、DNS枚举、子域名发现、Web技术栈识别 |
| **VulnScan Agent** | 10+ | 6 | Nmap NSE扫描、Nikto扫描、SQLMap注入检测、XSStrike、漏洞数据库匹配、CVSS评分 |
| **Exploit Agent** | 10+ | 6 | Metasploit自动化、Web漏洞利用、SQL注入、XSS、RCE、自定义Exploit执行 |
| **PostExploit Agent** | 10+ | 6 | 系统信息收集、凭证窃取、密码哈希提取、持久化部署、数据窃取、日志清理 |
| **Privesc Agent** | 10+ | 7 | Linux/Windows提权、内核漏洞利用、SUID/Sudo滥用、Docker逃逸、计划任务劫持 |
| **Lateral Agent** | 10+ | 6 | 内网主机发现、凭证收集、SSH/SMB/WinRM/RDP横向、Kerberos票据利用 |
| **C2 Agent** | 10+ | 6 | Metasploit/Sliver/Cobalt Strike部署、多平台Payload生成、Session管理、进程迁移 |
| **Report Agent** | 8+ | 4 | 数据整合、风险评估、多格式报告生成、执行摘要、合规性分析 |

### 💡 核心优势

#### 1. 智能决策引擎
- **LLM 驱动**: 每个 Agent 使用 Claude API 进行战略决策
- **ReAct 循环**: Think-Act-Observe 模式实现自主推理
- **降级逻辑**: LLM 失败时自动切换到规则引擎

#### 2. 状态管理
- **LangGraph StateGraph**: 清晰的状态流转
- **共享状态**: 所有 Agent 共享发现、端口、Shell、凭证
- **自动合并**: 状态更新自动传播到所有节点

#### 3. 三层架构
- **Tool 层**: 原子操作，标准化输出
- **Skill 层**: 战术技能链，支持并行执行
- **Agent 层**: 战略决策，LLM 驱动

#### 4. 工程化设计
- **25,560+ 行代码**: 70 个 TypeScript 文件
- **类型安全**: 完整的 TypeScript 类型定义
- **错误处理**: 统一的 ToolResult<T> 接口
- **可扩展**: 模块化设计，易于添加新工具

### 🚀 快速开始

#### 安装

```bash
# 克隆仓库
git clone https://github.com/atreasureboy/ovogo.git
cd ovogo

# 安装依赖
npm install

# 编译
npm run build
```

#### 配置

创建 `.env` 文件：

```env
ANTHROPIC_API_KEY=your_api_key_here
```

#### 运行

```bash
# 标准模式
npm start

# LangGraph 模式（推荐）
node dist/bin/ovogogogo.js --langgraph "对 example.com 进行渗透测试"
```

### 📊 技术栈

| 类别 | 技术 |
|------|------|
| **语言** | TypeScript 5.7 |
| **AI 框架** | LangGraph 0.2, LangChain Core 0.3 |
| **LLM** | Anthropic Claude (Sonnet 4) |
| **工具集成** | Nmap, Metasploit, Nikto, SQLMap, Nuclei, LinPEAS, WinPEAS, Subfinder, Amass, Httpx, Katana |
| **状态管理** | LangGraph StateGraph |
| **类型系统** | Zod 3.24 |

### 📁 项目结构

```
ovogo/
├── src/
│   ├── core/                    # 核心引擎
│   │   ├── graph/              # LangGraph 状态图
│   │   │   ├── types.ts        # 状态类型定义
│   │   │   ├── nodes/          # Supervisor & Worker 节点
│   │   │   └── builder.ts      # 图构建器
│   │   ├── langGraphEngine.ts  # LangGraph 引擎
│   │   └── types.ts            # 核心类型
│   │
│   ├── recon/                   # 侦察智能体
│   │   ├── tools/              # 10+ 原子工具
│   │   ├── skills/             # 6 个技能链
│   │   └── agent/              # Agent 决策层
│   │
│   ├── vuln-scan/              # 漏洞扫描智能体
│   ├── exploit/                # 漏洞利用智能体
│   ├── post-exploit/           # 后渗透智能体
│   ├── privesc/                # 权限提升智能体
│   ├── lateral/                # 横向移动智能体
│   ├── c2/                     # 命令控制智能体
│   └── report/                 # 报告生成智能体
│
├── bin/
│   └── agent-worker.ts         # Worker 独立进程
│
├── docs/
│   └── LANGGRAPH_GUIDE.md      # LangGraph 使用指南
│
└── package.json
```

### 🔬 工作流程示例

```
用户输入: "对 example.com 进行渗透测试"
    ↓
[Supervisor] 分析任务 → 决策: delegate_recon
    ↓
[Recon Agent] 执行侦察
    ├─ Subfinder: 发现 52 个子域名
    ├─ Nmap: 扫描端口 (80, 443, 8080)
    └─ Httpx: 识别 18 个 Web 服务
    ↓
[Supervisor] 分析状态 → 决策: delegate_vuln_scan
    ↓
[VulnScan Agent] 漏洞扫描
    ├─ Nuclei: 发现 SQL 注入 (CVE-2023-XXXX)
    ├─ Nikto: 发现目录遍历
    └─ SQLMap: 确认注入点
    ↓
[Supervisor] 发现 Critical 漏洞 → 决策: delegate_exploit
    ↓
[Exploit Agent] 漏洞利用
    ├─ SQLMap: 获取数据库权限
    ├─ Webshell: 部署 PHP webshell
    └─ 反弹 Shell: 获得系统访问
    ↓
[Supervisor] 获得 Shell → 决策: delegate_post_exploit
    ↓
[PostExploit Agent] 后渗透
    ├─ 收集系统信息
    ├─ 窃取凭证和哈希
    └─ 部署持久化
    ↓
[Supervisor] 任务完成 → 决策: delegate_report
    ↓
[Report Agent] 生成报告
    ├─ 整合所有发现
    ├─ 计算风险评分
    ├─ 生成 Markdown/HTML/JSON/PDF
    └─ 生成执行摘要和合规性分析
```

### 📈 统计数据

- **代码量**: 25,560+ 行 TypeScript
- **文件数**: 70 个 TypeScript 文件
- **智能体**: 8 个专业智能体
- **工具数**: 80+ 原子工具
- **技能链**: 47 个战术技能链
- **支持工具**: Nmap, Metasploit, Nikto, SQLMap, Nuclei, LinPEAS, WinPEAS, Subfinder, Amass, Httpx, Katana, XSStrike 等

### 🛡️ 安全声明

**本项目仅用于授权的安全测试和教育目的。**

使用者必须：
- ✅ 获得目标系统的书面授权
- ✅ 遵守当地法律法规
- ✅ 仅在授权范围内使用
- ❌ 未经授权的渗透测试是违法行为

### 📄 License

MIT License - 详见 [LICENSE](LICENSE) 文件

### 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

## English

### 📖 Introduction

Ovogo is a revolutionary red team automation framework that deeply integrates Large Language Model (LLM) intelligent decision-making with penetration testing tools. Through an innovative three-layer architecture (Tool → Skill → Agent) and LangGraph state management, it achieves full-process automation from reconnaissance to report generation.

**Key Features:**
- 🤖 **8 Professional Agents** - Covering every stage of the complete attack chain
- 🧠 **LLM-Driven Decisions** - Strategic intelligence powered by Claude API
- 📊 **LangGraph State Management** - Clear state flow and sharing
- ⚡ **Parallel Execution** - Skill chain level parallel optimization
- 📝 **Multi-Format Reports** - Markdown, HTML, JSON, PDF

### 🏗️ Architecture

#### Three-Layer Architecture

```
Agent Layer (Strategic)
    ↓
Skill Layer (Tactical)
    ↓
Tool Layer (Atomic)
```

Each agent contains:
- **Tools**: 10+ atomic operations with standardized output
- **Skills**: 4-7 tactical skill chains supporting parallel execution
- **Agent**: Strategic decision-making powered by LLM

#### LangGraph State Graph

- **Supervisor Node**: LLM-driven decision making and routing
- **Worker Nodes**: Execute specific tasks (recon, exploit, etc.)
- **Shared State**: All nodes share findings, ports, shells, credentials
- **Automatic Merging**: State updates propagate automatically

### 🎯 8 Agent System

| Agent | Tools | Skills | Core Capabilities |
|-------|-------|--------|-------------------|
| **Recon** | 10+ | 6 | Host discovery, port scanning, service identification, DNS enumeration, subdomain discovery, web tech stack identification |
| **VulnScan** | 10+ | 6 | Nmap NSE scanning, Nikto, SQLMap injection detection, XSStrike, vulnerability database matching, CVSS scoring |
| **Exploit** | 10+ | 6 | Metasploit automation, web vulnerability exploitation, SQL injection, XSS, RCE, custom exploit execution |
| **PostExploit** | 10+ | 6 | System info gathering, credential theft, password hash extraction, persistence deployment, data exfiltration, log cleaning |
| **Privesc** | 10+ | 7 | Linux/Windows privilege escalation, kernel exploits, SUID/Sudo abuse, Docker escape, scheduled task hijacking |
| **Lateral** | 10+ | 6 | Internal host discovery, credential collection, SSH/SMB/WinRM/RDP lateral movement, Kerberos ticket exploitation |
| **C2** | 10+ | 6 | Metasploit/Sliver/Cobalt Strike deployment, multi-platform payload generation, session management, process migration |
| **Report** | 8+ | 4 | Data aggregation, risk assessment, multi-format report generation, executive summary, compliance analysis |

### 🚀 Quick Start

#### Installation

```bash
git clone https://github.com/atreasureboy/ovogo.git
cd ovogo
npm install
npm run build
```

#### Configuration

Create `.env` file:

```env
ANTHROPIC_API_KEY=your_api_key_here
```

#### Run

```bash
# Standard mode
npm start

# LangGraph mode (recommended)
node dist/bin/ovogogogo.js --langgraph "Penetration test on example.com"
```

### 📊 Tech Stack

- **Language**: TypeScript 5.7
- **AI Framework**: LangGraph 0.2, LangChain Core 0.3
- **LLM**: Anthropic Claude (Sonnet 4)
- **Tools**: Nmap, Metasploit, Nikto, SQLMap, Nuclei, LinPEAS, WinPEAS, Subfinder, Amass, Httpx, Katana

### 📈 Statistics

- **Code**: 25,560+ lines of TypeScript
- **Files**: 70 TypeScript files
- **Agents**: 8 professional agents
- **Tools**: 80+ atomic tools
- **Skills**: 47 tactical skill chains

### 🛡️ Security Notice

**This project is for authorized security testing and educational purposes only.**

Users must:
- ✅ Obtain written authorization for target systems
- ✅ Comply with local laws and regulations
- ✅ Use only within authorized scope
- ❌ Unauthorized penetration testing is illegal

### 📄 License

MIT License

---

<div align="center">

**Made with ❤️ for the Red Team Community**

[⭐ Star this repo](https://github.com/atreasureboy/ovogo) | [🐛 Report Bug](https://github.com/atreasureboy/ovogo/issues) | [💡 Request Feature](https://github.com/atreasureboy/ovogo/issues)

</div>
