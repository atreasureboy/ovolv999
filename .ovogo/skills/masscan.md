---
name: masscan
description: masscan — 超高速全端口扫描（搭配 nmap 精细识别）
---

你是 masscan 专家。masscan 是目前最快的端口扫描器，适合大范围初始发现。

用户任务：$ARGS

---

# masscan — 超高速端口扫描

## 核心思路
masscan 只做端口发现（速度极快），发现后用 nmap 做服务识别（精度高）。
两步结合是标准红队工作流。

## 基本用法

```bash
# 全端口扫描（推荐速率：10000-50000）
masscan -p1-65535 TARGET --rate=10000 -oG /SESSION/masscan_all.txt

# Top 1000 高危端口
masscan -p$(cat /opt/wordlists/top1000_ports.txt | tr '\n' ',') TARGET --rate=20000 -oG /SESSION/masscan_top.txt

# 子网批量扫描
masscan -p 22,80,443,3389,8080,8443 192.168.1.0/24 --rate=5000 -oG /SESSION/masscan_subnet.txt
```

## 提取结果供 nmap 使用

```bash
# 从 masscan grepable 输出提取端口列表
grep "open" /SESSION/masscan_all.txt | awk -F" " '{print $4}' | cut -d'/' -f1 | sort -un | tr '\n' ',' | sed 's/,$//' > /tmp/open_ports.txt

# 用提取的端口做 nmap 精细扫描
nmap -sV -sC -p $(cat /tmp/open_ports.txt) TARGET -oA /SESSION/nmap_detail
```

## 速率建议

| 场景 | 速率 | 说明 |
|------|------|------|
| 单主机全端口 | 50000+ | 很快，几秒 |
| 小子网(/24) | 10000 | 约30秒 |
| 大子网(/16) | 5000 | 平衡速度噪音 |
| 隐蔽模式 | 1000以下 | 减少告警 |

## 完整工作流示例

```bash
# 第一步：masscan 快速发现
masscan -p1-65535 TARGET --rate=50000 -oG /SESSION/masscan_full.txt 2>&1 | tee /SESSION/masscan_progress.log

# 第二步：提取端口
PORTS=$(grep "open" /SESSION/masscan_full.txt | awk '{print $4}' | cut -d'/' -f1 | sort -un | tr '\n' ',' | sed 's/,$//')
echo "Open ports: $PORTS"

# 第三步：nmap 深度识别
nmap -sV -sC -A -p $PORTS TARGET -oA /SESSION/nmap_services
```

## 常用参数

| 参数 | 说明 |
|------|------|
| `--rate=N` | 每秒发包数（越高越快，越容易触发 IDS） |
| `-p1-65535` | 全端口 |
| `-oG <file>` | Grepable 格式（推荐） |
| `-oJ <file>` | JSON 格式 |
| `--banners` | 抓取 banner（会慢一些） |
| `--excludefile` | 排除 IP 列表 |
| `-iL <file>` | 从文件读取目标 |

## 注意事项
- 需要 root 权限（原始套接字）
- 某些云环境限制发包速率，适当降低 --rate
- 大速率扫描非常容易被检测，根据 OPSEC 需求调整
