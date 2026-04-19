---
name: snmp
description: SNMP 枚举 — onesixtyone/snmpwalk/snmp-check（发现网络设备/系统信息）
---

你是网络协议枚举专家，使用 SNMP 工具发现目标网络设备和系统信息。

用户任务：$ARGS

---

# SNMP 枚举

## 为什么重要
SNMP（简单网络管理协议，UDP/161）配置不当时可泄露：
- 系统信息（OS 版本、主机名）
- 网络接口和路由表
- 运行中的进程列表
- 已安装软件
- 用户账户（Windows）

## 快速发现：onesixtyone（community string 爆破）

```bash
# 常见 community string 爆破（发现有效凭证）
onesixtyone -c /opt/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings.txt \
    TARGET -o /SESSION/snmp_communities.txt

# 子网批量扫描
onesixtyone -c /opt/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings.txt \
    -i /SESSION/live_ips.txt -o /SESSION/snmp_bulk.txt

# 只试 public/private（快速）
for cs in public private community manager; do
    snmpwalk -v2c -c $cs TARGET sysInfo 2>/dev/null | head -3 && echo "[+] community: $cs"
done
```

## snmpwalk — 完整信息提取

```bash
# 基础系统信息（OID: 1.3.6.1.2.1.1）
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.1 | tee /SESSION/snmp_sysinfo.txt

# 所有信息（完整 MIB）
snmpwalk -v2c -c public TARGET . | tee /SESSION/snmp_all.txt

# 网络接口
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.2 | tee /SESSION/snmp_interfaces.txt

# 路由表
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.4.21 | tee /SESSION/snmp_routes.txt

# 运行进程（Windows/Linux）
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.4.2 | tee /SESSION/snmp_processes.txt

# 已安装软件（Windows）
snmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.6.3 | tee /SESSION/snmp_software.txt

# 用户账户（Windows，hrSWRunParameters）
snmpwalk -v2c -c public TARGET 1.3.6.1.4.1.77.1.2.25 | tee /SESSION/snmp_users.txt

# SNMPv3（需要用户名和密码）
snmpwalk -v3 -l authPriv -u username -a MD5 -A authpass -x DES -X privpass TARGET .
```

## snmp-check（更友好的输出）

```bash
# 完整信息收集
snmp-check TARGET -c public | tee /SESSION/snmp_check.txt

# 只看进程
snmp-check TARGET -c public -o | grep "Running processes" -A 50 | head -60
```

## nmap SNMP 脚本

```bash
# SNMP 枚举（所有脚本）
nmap -sU -p 161 --script snmp-* TARGET -oN /SESSION/nmap_snmp.txt

# 常用脚本组合
nmap -sU -p 161 \
    --script snmp-info,snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-users \
    TARGET -oN /SESSION/nmap_snmp_detail.txt
```

## OID 速查

| OID | 内容 |
|-----|------|
| `1.3.6.1.2.1.1` | 系统信息 |
| `1.3.6.1.2.1.2` | 网络接口 |
| `1.3.6.1.2.1.4.21` | IP 路由表 |
| `1.3.6.1.2.1.25.4.2` | 运行进程 |
| `1.3.6.1.2.1.25.6.3` | 安装软件 |
| `1.3.6.1.4.1.77.1.2.25` | Windows 用户 |
