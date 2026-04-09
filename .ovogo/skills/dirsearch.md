---
name: dirsearch
description: dirsearch — Web 路径扫描（Python版，内置字典，支持递归/多扩展名）
---

你是 dirsearch 专家，用于 Web 目录和文件枚举。

用户任务：$ARGS

---

# dirsearch — Web 内容发现

## 特点
- Python 实现，内置完整字典（无需额外指定）
- 支持多扩展名批量测试
- 彩色输出，结果清晰
- 内置报告生成

## 基础扫描

```bash
# 使用内置字典（推荐起手）
dirsearch -u https://TARGET -o /SESSION/dirsearch.txt

# 指定扩展名
dirsearch -u https://TARGET -e php,html,txt,bak,zip,sql,json -o /SESSION/dirsearch_ext.txt

# 使用自定义字典
dirsearch -u https://TARGET \
    -w /opt/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt \
    -o /SESSION/dirsearch_custom.txt
```

## 递归扫描

```bash
# 递归深度 3
dirsearch -u https://TARGET -r -R 3 -o /SESSION/dirsearch_recursive.txt

# 递归特定路径
dirsearch -u https://TARGET/api -r -R 2 -o /SESSION/dirsearch_api.txt
```

## 性能调优

```bash
# 高并发（快速）
dirsearch -u https://TARGET -t 50 -o /SESSION/dirsearch_fast.txt

# 低速（有 WAF）
dirsearch -u https://TARGET -t 5 --delay=0.5 -o /SESSION/dirsearch_slow.txt
```

## 过滤

```bash
# 过滤特定状态码
dirsearch -u https://TARGET --exclude-status 403,301 -o /SESSION/dirsearch_200.txt

# 过滤特定响应大小
dirsearch -u https://TARGET --exclude-sizes 0,1B -o /SESSION/dirsearch_notempty.txt
```

## 认证场景

```bash
# 带 Cookie
dirsearch -u https://TARGET \
    --cookie "session=abc123; PHPSESSID=xyz" \
    -o /SESSION/dirsearch_auth.txt

# Basic Auth
dirsearch -u https://TARGET \
    --auth admin:password --auth-type basic \
    -o /SESSION/dirsearch_basicauth.txt

# 自定义 Header
dirsearch -u https://TARGET \
    -H "X-Custom-Header: value" \
    -o /SESSION/dirsearch_header.txt
```

## 批量扫描

```bash
# 从文件读取目标列表
dirsearch -l /SESSION/live_urls.txt -o /SESSION/dirsearch_bulk.txt

# 并发多个目标
cat /SESSION/live_urls.txt | while read url; do
    domain=$(echo $url | sed 's|https\?://||' | tr '/:' '_')
    dirsearch -u "$url" -o "/SESSION/dirsearch_${domain}.txt" -q &
done
wait
```

## 报告格式

```bash
# 生成 JSON 报告
dirsearch -u https://TARGET -o /SESSION/dirsearch.json --format json

# 生成 XML 报告
dirsearch -u https://TARGET -o /SESSION/dirsearch.xml --format xml

# 纯文本（只有路径）
dirsearch -u https://TARGET -o /SESSION/dirsearch_plain.txt --format plain
```
