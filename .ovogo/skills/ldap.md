---
name: ldap
description: LDAP 枚举 — ldapsearch/ldap3/windapsearch（AD 用户/组/策略信息收集）
---

你是 LDAP 枚举专家，使用 ldap 工具从 Active Directory 提取用户、组、策略等关键信息。

用户任务：$ARGS

---

# LDAP 枚举（Active Directory）

## 前提
- 目标开放 LDAP（389/TCP）或 LDAPS（636/TCP）
- 有效域凭证（或匿名/Guest 访问）

## ldapsearch — 基础枚举

```bash
# 匿名访问测试
ldapsearch -x -H ldap://DC_IP -b "" -s base "(objectclass=*)" \
    namingContexts 2>&1 | tee /SESSION/ldap_namingctx.txt

# 获取 Base DN
ldapsearch -x -H ldap://DC_IP -b "" -s base "(objectclass=*)" | grep namingContexts

# 认证查询（用户名密码）
BASEDN="DC=corp,DC=local"
ldapsearch -x -H ldap://DC_IP -D "user@corp.local" -w "Password123" \
    -b "$BASEDN" "(objectClass=user)" cn sAMAccountName mail \
    | tee /SESSION/ldap_users.txt

# 枚举所有用户
ldapsearch -x -H ldap://DC_IP -D "user@corp.local" -w "Password123" \
    -b "$BASEDN" "(objectClass=person)" \
    cn sAMAccountName userPrincipalName mail memberOf pwdLastSet \
    | tee /SESSION/ldap_all_users.txt

# 枚举所有组
ldapsearch -x -H ldap://DC_IP -D "user@corp.local" -w "Password123" \
    -b "$BASEDN" "(objectClass=group)" \
    cn member description \
    | tee /SESSION/ldap_groups.txt

# 枚举管理员组成员
ldapsearch -x -H ldap://DC_IP -D "user@corp.local" -w "Password123" \
    -b "$BASEDN" "(memberOf=CN=Domain Admins,CN=Users,$BASEDN)" \
    cn sAMAccountName \
    | tee /SESSION/ldap_domain_admins.txt

# 枚举域控制器
ldapsearch -x -H ldap://DC_IP -D "user@corp.local" -w "Password123" \
    -b "$BASEDN" "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" \
    cn dNSHostName \
    | tee /SESSION/ldap_dcs.txt

# 找密码永不过期的账户
ldapsearch -x -H ldap://DC_IP -D "user@corp.local" -w "Password123" \
    -b "$BASEDN" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" \
    cn sAMAccountName \
    | tee /SESSION/ldap_no_expire.txt

# 找不需要预认证的账户（ASREPRoasting）
ldapsearch -x -H ldap://DC_IP -D "user@corp.local" -w "Password123" \
    -b "$BASEDN" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
    cn sAMAccountName \
    | tee /SESSION/ldap_asrep.txt
```

## windapsearch（更简单的 Python 工具）

```bash
# 安装检测
which windapsearch || pip3 install windapsearch

# 匿名枚举
windapsearch -d DOMAIN.LOCAL --dc DC_IP -m users --full

# 带凭证
windapsearch -d DOMAIN.LOCAL --dc DC_IP -u "user@DOMAIN.LOCAL" -p "Password123" \
    -m users -o /SESSION/windap_users.txt

# 枚举域管
windapsearch -d DOMAIN.LOCAL --dc DC_IP -u "user@corp.local" -p "pass" \
    -m domain-admins

# 枚举所有组
windapsearch -d DOMAIN.LOCAL --dc DC_IP -u "user@corp.local" -p "pass" \
    -m groups -o /SESSION/windap_groups.txt

# 找有 SPN 的账户（Kerberoasting）
windapsearch -d DOMAIN.LOCAL --dc DC_IP -u "user@corp.local" -p "pass" \
    -m unconstrained-users
```

## ldap3（Python 脚本方式）

```python
# 快速枚举脚本
python3 << 'EOF'
from ldap3 import Server, Connection, ALL, SUBTREE

DC_IP = "DC_IP"
DOMAIN = "corp.local"
USER = f"user@{DOMAIN}"
PASS = "Password123"
BASE_DN = "DC=corp,DC=local"

server = Server(DC_IP, get_info=ALL)
conn = Connection(server, USER, PASS, auto_bind=True)

# 枚举用户
conn.search(BASE_DN, "(objectClass=person)",
            attributes=["cn", "sAMAccountName", "mail", "memberOf"])
for entry in conn.entries:
    print(entry)
EOF
```

## Hash 传递 LDAP 认证

```bash
# 用 NTLM Hash 认证 LDAP
ldapsearch -x -H ldap://DC_IP \
    -D "user@corp.local" \
    -Y DIGEST-MD5 \
    -b "DC=corp,DC=local" "(objectClass=user)" cn 2>/dev/null
```
