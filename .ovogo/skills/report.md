---
name: report
description: 根据 .ovogo/findings/ 自动生成渗透测试报告（Markdown）
---

你是一名专业的渗透测试报告撰写专家。请根据 .ovogo/findings/ 目录中所有已记录的 Findings，生成一份完整的渗透测试报告。

附加要求或说明：$ARGS

---

## 报告生成步骤

1. 用 Bash 列出所有 findings 文件：
```bash
ls .ovogo/findings/*.json 2>/dev/null || echo "NO_FINDINGS"
```

2. 逐一读取每个 finding JSON 文件。

3. 读取 `.ovogo/settings.json` 获取 engagement 信息（任务名称、目标、日期）。

4. 按以下模板生成完整报告，保存到 `report_$(date +%Y%m%d).md`：

---

## 报告模板

```markdown
# 渗透测试报告

**项目名称：** [engagement.name]
**目标范围：** [engagement.targets]
**测试周期：** [start_date] — [end_date]
**报告日期：** [今日日期]
**执行工具：** ovogogogo red-team agent

---

## 执行摘要

本次渗透测试共发现 [N] 个漏洞，其中严重 [C] 个、高危 [H] 个、中危 [M] 个、低危 [L] 个、信息 [I] 个。

[2-3句高层概述：最关键的发现、总体安全态势]

---

## 漏洞统计

| 严重等级 | 数量 |
|---------|------|
| 严重 (Critical) | C |
| 高危 (High)     | H |
| 中危 (Medium)   | M |
| 低危 (Low)      | L |
| 信息 (Info)     | I |
| **合计**        | N |

---

## 漏洞详情

按严重等级从高到低排列，每条 Finding 格式如下：

### [SEVERITY] F001 — 漏洞标题

| 字段 | 内容 |
|------|------|
| 目标 | target |
| 类型 | type |
| 阶段 | phase |
| MITRE TTP | mitre_ttp |
| CVE | cve |
| 状态 | status |
| 发现时间 | timestamp |

**描述：**
[description]

**Proof of Concept：**
\`\`\`
[poc]
\`\`\`

**截图：** [screenshot_path 或 N/A]

---

## 攻击路径回顾

按攻击阶段梳理完整攻击链：

### 侦察 (Recon)
[列出 phase=recon 的 findings 摘要]

### 初始访问 (Initial Access)
[列出 phase=initial-access 的 findings 摘要]

### 横向移动 (Lateral Movement)
[列出 phase=lateral-movement 的 findings 摘要]

### 后渗透 (Post-Exploitation)
[列出 phase=post-exploitation 的 findings 摘要]

---

## 修复建议

按优先级列出修复建议，critical/high 问题优先。

---

## 附录：测试工具

- nmap / naabu — 端口扫描
- nuclei / httpx — Web 漏洞扫描
- subfinder / dnsx — 子域名枚举
- [其他使用工具]
```

---

将生成的报告文件路径输出给用户，并给出关键统计摘要。
