---
name: nikto
description: nikto — Web 服务器漏洞扫描（配置缺陷/已知漏洞/信息泄露）
---

你是 nikto 专家。nikto 专注于发现服务器配置缺陷、危险文件、已知漏洞。

用户任务：$ARGS

---

# nikto — Web 服务器扫描

## 定位
nikto 不是漏洞利用工具，而是快速发现：
- 危险默认文件（phpinfo.php、.git、.env 等）
- 服务器配置缺陷（目录列举、不安全 HTTP 方法）
- 过时软件版本
- 常见 Web 漏洞特征

## 基础扫描

```bash
# 标准扫描
nikto -h https://TARGET -o /SESSION/nikto.txt -Format txt

# SSL 站点
nikto -h TARGET -ssl -port 443 -o /SESSION/nikto_ssl.txt

# 指定端口
nikto -h TARGET -port 8080,8443 -o /SESSION/nikto_8080.txt

# 保存 HTML 报告
nikto -h https://TARGET -o /SESSION/nikto_report.html -Format html
```

## 提高覆盖度

```bash
# 完整扫描（所有插件）
nikto -h https://TARGET -Tuning x -o /SESSION/nikto_full.txt

# 只扫描特定类型
nikto -h https://TARGET -Tuning 1,2,3,4,b -o /SESSION/nikto_targeted.txt
```

## Tuning 参数详解

| 值 | 类型 |
|-----|------|
| 1 | 有趣的文件/可见内容 |
| 2 | 配置问题 |
| 3 | 信息泄露 |
| 4 | 注入类（XSS/Script/HTML） |
| 5 | 远程文件检索 |
| 6 | 拒绝服务 |
| 7 | 远程文件检索（服务器级别） |
| 8 | 命令执行/远程shell |
| 9 | SQL注入 |
| 0 | 文件上传 |
| a | 认证绕过 |
| b | 软件识别 |

## 结合代理绕过 WAF

```bash
# 通过 Burp 代理（用于分析/绕过）
nikto -h https://TARGET -useproxy http://127.0.0.1:8080 -o /SESSION/nikto_burp.txt

# 自定义 User-Agent
nikto -h https://TARGET -useragent "Mozilla/5.0 (compatible; Googlebot/2.1)" -o /SESSION/nikto_ua.txt
```

## 输出解读

```
+ OSVDB-3233: /icons/README: Apache default file found.
  ^^^^         ^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  数据库ID    发现的路径      漏洞描述

+ Server: Apache/2.4.41 (Ubuntu)    ← 版本信息泄露
+ /phpinfo.php: PHP info page found  ← 危险文件暴露
+ /admin/: This might be interesting ← 敏感目录
```

## 组合工作流

```bash
# httpx 先确认存活，nikto 扫描全部
cat /SESSION/live_urls.txt | while read url; do
    domain=$(echo $url | sed 's|https\?://||' | tr '/:' '_')
    nikto -h $url -o "/SESSION/nikto_${domain}.txt" -Format txt &
done
wait
echo "All nikto scans done"
grep -h "+" /SESSION/nikto_*.txt | sort -u > /SESSION/nikto_all_findings.txt
```
