---
name: searchsploit
description: searchsploit — Exploit-DB 本地搜索 + exploit 定位与使用
---

你是 searchsploit 专家，用于根据服务版本快速查找公开 exploit。

用户任务：$ARGS

---

# searchsploit — Exploit-DB 离线搜索

## 基础搜索

```bash
# 按软件名搜索
searchsploit apache 2.4

# 按关键词
searchsploit wordpress 5.9

# 搜索特定 CVE
searchsploit CVE-2021-44228

# 只看 Web 应用漏洞
searchsploit -t "wordpress" --www

# 精确匹配（减少误报）
searchsploit --exact "Apache 2.4.49"
```

## 查看和使用 Exploit

```bash
# 查看 exploit 详情（不复制）
searchsploit -x exploits/php/webapps/12345.py

# 复制 exploit 到当前目录
searchsploit -m exploits/php/webapps/12345.py

# 复制到指定目录
searchsploit -m 12345 -o /SESSION/exploits/
```

## 结合 nmap 结果自动搜索

```bash
# 从 nmap XML 提取版本并自动搜索
searchsploit --nmap /SESSION/nmap_services.xml | tee /SESSION/exploits_found.txt

# 手动根据 nmap 结果搜索
# 示例：发现 vsftpd 2.3.4
searchsploit vsftpd 2.3.4

# 示例：发现 OpenSSH 7.2
searchsploit openssh 7.2
```

## 典型工作流

```bash
# 第一步：nmap 获取版本信息
nmap -sV TARGET -oA /SESSION/nmap_versions

# 第二步：批量搜索版本漏洞
grep -E "open.*[0-9]+\.[0-9]" /SESSION/nmap_versions.nmap | while read line; do
    service=$(echo $line | awk '{print $3}')
    version=$(echo $line | awk '{print $4,$5}')
    echo "=== $service $version ==="
    searchsploit "$service $version" 2>/dev/null | head -10
done | tee /SESSION/searchsploit_results.txt

# 第三步：下载有价值的 exploit
searchsploit -m 12345 -o /SESSION/exploits/
```

## 更新数据库

```bash
searchsploit -u
```

## 结果格式

```
---------- ------------------------------- ---------
 EDB-ID   | Title                         | Path
---------- ------------------------------- ---------
 47887    | Apache 2.4.49 - RCE           | exploits/linux/remote/47887.py
 47890    | Apache 2.4.49 - LFI           | exploits/linux/webapps/47890.sh
---------- ------------------------------- ---------
```
- EDB-ID：Exploit-DB 编号，可在 https://www.exploit-db.com/exploits/47887 查看详情
- Path：`/usr/share/exploitdb/` 下的相对路径

## 配合 Metasploit

```bash
# searchsploit 找到 exploit 后检查是否有 MSF 模块
searchsploit -m 47887
cat 47887.py | grep -i "metasploit\|msf"

# 或直接在 msfconsole 搜索
# search type:exploit name:apache 2.4.49
```
