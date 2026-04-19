---
name: sslscan
description: sslscan/testssl — SSL/TLS 配置扫描（弱密码/证书/协议缺陷）
---

你是 SSL/TLS 安全评估专家，使用 sslscan 和 testssl.sh 发现 HTTPS 配置缺陷。

用户任务：$ARGS

---

# SSL/TLS 安全扫描

## 为什么重要
SSL/TLS 配置缺陷是高频发现：
- 过时协议：SSLv2/SSLv3/TLS1.0/1.1（POODLE、BEAST 攻击）
- 弱密码套件：RC4、DES、NULL 密码
- 证书问题：过期、自签名、域名不匹配、弱密钥
- Heartbleed（CVE-2014-0160）
- ROBOT 攻击、CRIME/BREACH 压缩攻击

---

## sslscan

```bash
# 基础扫描
sslscan TARGET:443 | tee /SESSION/sslscan.txt

# HTTP 和 HTTPS 都扫
sslscan --no-failed TARGET:443 | tee /SESSION/sslscan_443.txt
sslscan --no-failed TARGET:8443 | tee /SESSION/sslscan_8443.txt

# 显示全部（包括支持的密码）
sslscan --show-ciphers TARGET:443 | tee /SESSION/sslscan_full.txt

# STARTTLS（SMTP/FTP/IMAP）
sslscan --starttls-smtp TARGET:25
sslscan --starttls-ftp  TARGET:21
sslscan --starttls-imap TARGET:143
```

---

## testssl.sh（更全面，推荐）

```bash
# 检查是否安装
which testssl.sh || which testssl

# 完整扫描（所有检测项）
testssl.sh https://TARGET | tee /SESSION/testssl_full.txt

# 只扫漏洞（快速）
testssl.sh --vulnerable https://TARGET | tee /SESSION/testssl_vulns.txt

# 批量扫描（从文件读取）
testssl.sh --file /SESSION/https_targets.txt | tee /SESSION/testssl_bulk.txt

# 只看协议版本
testssl.sh --protocols https://TARGET

# 只看证书信息
testssl.sh --certs https://TARGET

# JSON 输出（便于解析）
testssl.sh --jsonfile /SESSION/testssl.json https://TARGET
```

---

## nmap SSL 脚本（快速检测）

```bash
# SSL 综合扫描
nmap --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle -p 443 TARGET \
    -oN /SESSION/nmap_ssl.txt

# 只检测 Heartbleed
nmap --script ssl-heartbleed -p 443 TARGET

# 证书信息
nmap --script ssl-cert -p 443 TARGET | grep -A20 "ssl-cert"
```

---

## 手动 OpenSSL 检测

```bash
# 查看证书详情
openssl s_client -connect TARGET:443 </dev/null 2>/dev/null | \
    openssl x509 -noout -text | grep -E "Subject|Issuer|Not After|Not Before|Public-Key"

# 测试弱协议
openssl s_client -connect TARGET:443 -ssl3 2>&1 | grep -E "CONNECTED|error"   # SSLv3
openssl s_client -connect TARGET:443 -tls1 2>&1 | grep -E "CONNECTED|error"   # TLS 1.0
openssl s_client -connect TARGET:443 -tls1_1 2>&1 | grep -E "CONNECTED|error" # TLS 1.1

# 获取完整证书链
openssl s_client -showcerts -connect TARGET:443 </dev/null 2>/dev/null | tee /SESSION/cert_chain.txt

# 提取 SAN（Subject Alternative Names）—— 发现更多关联域名
openssl s_client -connect TARGET:443 </dev/null 2>/dev/null | \
    openssl x509 -noout -text | grep -A2 "Subject Alternative Name"
```

---

## 结果分析重点

```
[!] SSLv3 supported          → POODLE 漏洞
[!] TLS 1.0 supported        → BEAST 漏洞（高危内网）
[!] RC4 cipher supported     → 弱密码
[!] Heartbleed vulnerable    → 严重！可内存泄漏读取私钥
[!] Self-signed cert         → 中间人风险
[!] Cert expired             → 信息
[!] Weak key (1024 bit)      → 密钥强度不足
```
