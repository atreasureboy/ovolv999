---
name: enum4linux
description: enum4linux-ng — SMB/NetBIOS/RPC 枚举（Windows 内网信息收集）
---

你是 SMB 枚举专家，使用 enum4linux-ng、smbclient、rpcclient 进行 Windows 系统信息收集。

用户任务：$ARGS

---

# enum4linux-ng — Windows/SMB 枚举

## 定位
内网渗透初始阶段，对 Windows 目标进行：
- 用户名枚举
- 共享目录列举
- 系统信息/域信息
- 密码策略
- RPC 信息

## 基础用法

```bash
# 完整枚举（推荐）
enum4linux-ng TARGET -A -oA /SESSION/enum4linux_TARGET

# 无认证枚举
enum4linux-ng TARGET -A

# 带凭证枚举（获取到凭证后使用）
enum4linux-ng TARGET -u 'username' -p 'password' -A -oA /SESSION/enum4linux_auth
```

## 分项枚举

```bash
# 只枚举用户
enum4linux-ng TARGET -U

# 只枚举共享
enum4linux-ng TARGET -S

# 只枚举组
enum4linux-ng TARGET -G

# 系统信息
enum4linux-ng TARGET -O

# 密码策略
enum4linux-ng TARGET -P
```

## smbclient 手动探测

```bash
# 列出共享（匿名）
smbclient -L //TARGET -N

# 列出共享（带凭证）
smbclient -L //TARGET -U 'domain\user%password'

# 连接共享
smbclient //TARGET/share -U 'user%password'

# 递归下载共享内容
smbclient //TARGET/share -U 'user%password' -c "prompt;recurse;mget *"
```

## rpcclient 用户/域枚举

```bash
# 匿名登录
rpcclient -U "" -N TARGET

# 枚举命令（在 rpcclient 交互界面）
# enumdomusers          — 枚举域用户
# enumdomgroups         — 枚举域组
# querydominfo          — 域信息
# getdompwinfo          — 密码策略
# lsaquery              — LSA 信息
# lookupnames admin     — 查找特定用户SID

# 非交互式批量执行
rpcclient -U "user%pass" TARGET -c "enumdomusers" | tee /SESSION/rpc_users.txt
```

## crackmapexec/netexec SMB 扫描（配合使用）

```bash
# 扫描整个子网的 SMB
nxc smb 192.168.1.0/24 --gen-relay-list /SESSION/smb_hosts.txt

# 空口令测试
nxc smb TARGET -u '' -p ''

# 共享枚举
nxc smb TARGET -u 'user' -p 'pass' --shares
```

## 结果分析重点

```
Users found:      → 用于密码喷洒/暴破
Password policy:  → 确定爆破策略（锁定次数、复杂度）
Shares found:     → 寻找可读写的敏感共享
Domain info:      → 确认域名，为 BloodHound 做准备
```
