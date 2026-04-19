---
name: feroxbuster
description: feroxbuster — 递归 Web 目录暴力枚举（比 gobuster 更强）
---

你是 feroxbuster 专家。feroxbuster 支持递归扫描、自动过滤、并发高，是目录枚举首选。

用户任务：$ARGS

---

# feroxbuster — 递归 Web 内容发现

## 核心优势 vs gobuster
- 自动递归：发现目录后自动深入扫描
- 智能过滤：自动识别并过滤"软404"
- 高并发：默认50线程
- 实时输出：发现即显示

## 快速上手

```bash
# 基础扫描（推荐起手式）
feroxbuster -u https://TARGET -w /opt/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -o /SESSION/ferox_dirs.txt

# 带扩展名扫描（PHP/ASP站点）
feroxbuster -u https://TARGET \
    -w /opt/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt \
    -x php,html,txt,bak,zip,sql,json,config \
    -o /SESSION/ferox_full.txt

# 快速扫描（Common.txt + 高并发）
feroxbuster -u https://TARGET \
    -w /opt/wordlists/seclists/Discovery/Web-Content/common.txt \
    -t 100 --depth 3 -o /SESSION/ferox_quick.txt
```

## 典型场景

### WordPress 站点
```bash
feroxbuster -u https://TARGET \
    -w /opt/wordlists/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt \
    -x php -t 50 -o /SESSION/ferox_wp.txt
```

### API 端点发现
```bash
feroxbuster -u https://TARGET/api \
    -w /opt/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    -m GET,POST -t 30 -o /SESSION/ferox_api.txt
```

### 低噪音模式（有 WAF）
```bash
feroxbuster -u https://TARGET \
    -w /opt/wordlists/seclists/Discovery/Web-Content/common.txt \
    -t 10 --rate-limit 50 \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
    -o /SESSION/ferox_slow.txt
```

### 过滤无用结果
```bash
# 过滤特定状态码
feroxbuster -u https://TARGET -w /wordlist.txt \
    --filter-status 404,403,500 -o /SESSION/ferox_filtered.txt

# 过滤特定响应大小（过滤同类软404）
feroxbuster -u https://TARGET -w /wordlist.txt \
    --filter-size 1234 -o /SESSION/ferox_nodup.txt
```

## 常用参数

| 参数 | 说明 |
|------|------|
| `-u` | 目标 URL |
| `-w` | 字典文件 |
| `-x` | 扩展名（php,html,jsp...） |
| `-t` | 线程数（默认50） |
| `--depth` | 递归深度（默认4） |
| `-o` | 输出文件 |
| `-m` | HTTP 方法（GET,POST） |
| `--filter-status` | 过滤状态码 |
| `--filter-size` | 过滤响应大小 |
| `--rate-limit` | 每秒请求数限制 |
| `-H` | 自定义 Header |
| `-C` | Cookie |
| `--no-recursion` | 禁用递归 |
| `--scan-limit` | 并发扫描目录数上限 |

## 字典推荐

| 场景 | 字典 |
|------|------|
| 通用目录 | `seclists/Discovery/Web-Content/raft-medium-directories.txt` |
| 通用文件 | `seclists/Discovery/Web-Content/raft-medium-files.txt` |
| 快速扫描 | `seclists/Discovery/Web-Content/common.txt` |
| API | `seclists/Discovery/Web-Content/api/objects.txt` |
| 备份文件 | `seclists/Discovery/Web-Content/web-extensions.txt` |
