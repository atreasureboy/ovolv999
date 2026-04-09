---
name: john
description: john (John the Ripper) — 离线 Hash 破解（SAM/shadow/zip/各种格式）
---

你是 John the Ripper 专家，用于离线破解各种格式的密码 Hash。

用户任务：$ARGS

---

# John the Ripper — 离线密码破解

## 定位
- **john** — 自动格式检测，适合多种 Hash，规则变形强大
- **hashcat** — GPU 加速，大规模破解更快
- 两者互补：john 用于快速尝试和规则变形，hashcat 用于大规模 GPU 破解

## 基础破解

```bash
# 自动检测格式 + 字典破解
john hash.txt --wordlist=/opt/wordlists/rockyou.txt

# 指定格式
john hash.txt --format=NT --wordlist=/opt/wordlists/rockyou.txt

# 规则变形（大幅提升成功率）
john hash.txt --wordlist=/opt/wordlists/rockyou.txt --rules=best64

# 纯暴力（小范围）
john hash.txt --incremental=Digits

# 显示已破解
john hash.txt --show
```

## 常见 Hash 格式

```bash
# Linux /etc/shadow
john /etc/shadow --wordlist=/opt/wordlists/rockyou.txt

# Windows NTLM（从 SAM 或 hashdump）
john ntlm.txt --format=NT --wordlist=/opt/wordlists/rockyou.txt

# Net-NTLMv2（Responder 捕获）
john netntlmv2.txt --format=netntlmv2 --wordlist=/opt/wordlists/rockyou.txt

# Kerberos TGS（Kerberoast）
john kerberos_hashes.txt --format=krb5tgs --wordlist=/opt/wordlists/rockyou.txt

# AS-REP（ASREPRoast）
john asrep_hashes.txt --format=krb5asrep --wordlist=/opt/wordlists/rockyou.txt

# MD5
john md5.txt --format=raw-md5 --wordlist=/opt/wordlists/rockyou.txt

# bcrypt
john bcrypt.txt --format=bcrypt --wordlist=/opt/wordlists/rockyou.txt
```

## 文件破解

```bash
# ZIP 密码（先用 zip2john 提取 hash）
zip2john protected.zip > zip_hash.txt
john zip_hash.txt --wordlist=/opt/wordlists/rockyou.txt

# RAR 密码
rar2john protected.rar > rar_hash.txt
john rar_hash.txt --wordlist=/opt/wordlists/rockyou.txt

# PDF 密码
pdf2john protected.pdf > pdf_hash.txt
john pdf_hash.txt --wordlist=/opt/wordlists/rockyou.txt

# SSH 私钥密码
ssh2john id_rsa > ssh_hash.txt
john ssh_hash.txt --wordlist=/opt/wordlists/rockyou.txt

# KeePass 数据库
keepass2john database.kdbx > keepass_hash.txt
john keepass_hash.txt --wordlist=/opt/wordlists/rockyou.txt
```

## 规则系统（关键：提升成功率）

```bash
# 内置规则（从弱到强）
john hash.txt -w=/opt/wordlists/rockyou.txt --rules=Single
john hash.txt -w=/opt/wordlists/rockyou.txt --rules=best64    # 推荐
john hash.txt -w=/opt/wordlists/rockyou.txt --rules=KoreLogic  # 企业密码策略
john hash.txt -w=/opt/wordlists/rockyou.txt --rules=All        # 全部规则（慢）

# 生成候选密码（查看变形效果）
john --wordlist=/opt/wordlists/rockyou.txt --rules=best64 --stdout | head -20
```

## 会话管理

```bash
# 命名会话（可恢复）
john hash.txt -w=/opt/wordlists/rockyou.txt --session=target_crack

# 恢复中断的会话
john --restore=target_crack

# 查看正在运行的会话进度（另一个终端）
john --status=target_crack
```

## 多核利用

```bash
# 使用所有 CPU 核心
john hash.txt --wordlist=/opt/wordlists/rockyou.txt --fork=$(nproc)
```

## 字典推荐顺序

1. `/opt/wordlists/rockyou.txt` — 最经典
2. `/opt/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt`
3. 自定义字典（根据 OSINT 生成）：`cewl https://TARGET -d 3 -w /tmp/custom.txt`
