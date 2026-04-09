---
name: gau
description: gau/waybackurls — 历史 URL 收集（发现隐藏端点/参数/旧版本功能）
---

你是历史 URL 收集专家，使用 gau、waybackurls、hakrawler 等工具挖掘目标的历史和隐藏 URL。

用户任务：$ARGS

---

# 历史 URL 收集

## 为什么重要
历史 URL 可以发现：
- 已删除但未清理的敏感端点（/api/admin、/backup.zip）
- 带参数的 URL（SQL注入/XSS的攻击面）
- 旧版本功能（可能有已知漏洞）
- 内部路径泄露

## gau — GetAllUrls

```bash
# 收集单域名（所有来源）
gau TARGET.com | tee /SESSION/gau_urls.txt

# 包含子域名
gau --subs TARGET.com | tee /SESSION/gau_all.txt

# 指定来源
gau --providers wayback,otx,commoncrawl TARGET.com | tee /SESSION/gau_sources.txt

# 过滤特定扩展
gau TARGET.com | grep -v '\.png\|\.jpg\|\.gif\|\.css\|\.woff' | tee /SESSION/gau_filtered.txt

# 只保留带参数的 URL
gau TARGET.com | grep '?' | tee /SESSION/gau_params.txt
```

## waybackurls

```bash
# 单域名
waybackurls TARGET.com | tee /SESSION/wayback_urls.txt

# 包含子域名
echo TARGET.com | waybackurls | tee /SESSION/wayback_urls.txt

# 去重
echo TARGET.com | waybackurls | sort -u | tee /SESSION/wayback_dedup.txt
```

## 聚合多来源

```bash
# 组合 gau + waybackurls（推荐）
(gau TARGET.com; waybackurls TARGET.com) | sort -u | tee /SESSION/all_history_urls.txt
echo "[*] Total URLs: $(wc -l < /SESSION/all_history_urls.txt)"
```

## URL 处理与过滤

```bash
# 过滤静态资源（图片/CSS/字体等）
cat /SESSION/all_history_urls.txt | \
    grep -vE '\.(png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|css|pdf)(\?|$)' | \
    tee /SESSION/dynamic_urls.txt

# 只保留带参数的 URL（参数挖掘）
cat /SESSION/dynamic_urls.txt | grep '=' | tee /SESSION/param_urls.txt

# 提取唯一参数名
cat /SESSION/param_urls.txt | grep -oP '[?&][^=]+(?==)' | sort -u | tee /SESSION/param_names.txt

# 提取所有 JS 文件（寻找 API 端点和密钥）
cat /SESSION/all_history_urls.txt | grep '\.js$' | sort -u | tee /SESSION/js_files.txt

# 提取唯一路径（去掉参数）
cat /SESSION/all_history_urls.txt | sed 's/?.*//' | sort -u | tee /SESSION/unique_paths.txt
```

## 后续利用

```bash
# 对带参数 URL 跑 XSS
cat /SESSION/param_urls.txt | dalfox pipe --worker 20 -o /SESSION/xss_results.txt

# 对带参数 URL 跑 SQLi
cat /SESSION/param_urls.txt | head -50 | while read url; do
    sqlmap -u "$url" --batch --level 1 --quiet 2>/dev/null
done

# JS 文件分析（找 API key、端点、secrets）
cat /SESSION/js_files.txt | while read jsurl; do
    curl -s "$jsurl" | grep -oE '(api[_-]?key|secret|token|password|auth)[^"]*' | head -5
done | tee /SESSION/js_secrets.txt

# 发现的旧路径批量探测存活
cat /SESSION/unique_paths.txt | httpx -sc -title -silent | tee /SESSION/old_paths_alive.txt
```

## 利用 hakrawler 补充爬取

```bash
# 主动爬取（gau 是被动历史，hakrawler 是主动）
echo "https://TARGET.com" | hakrawler -depth 3 -plain | tee /SESSION/hakrawler_urls.txt

# 组合被动+主动
(gau TARGET.com; echo "https://TARGET.com" | hakrawler -plain) | sort -u | tee /SESSION/all_urls_combined.txt
```
