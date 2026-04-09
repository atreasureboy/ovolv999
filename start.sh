#!/bin/bash
# ovogogogo 启动脚本
# 用法: ./start.sh

set -e
cd "$(dirname "$0")"

# ── 环境变量检查 ──────────────────────────────────────────────
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi

if [ -z "$OPENAI_API_KEY" ]; then
  echo "[错误] 请设置 OPENAI_API_KEY"
  echo "  方式1: export OPENAI_API_KEY=xxx && ./start.sh"
  echo "  方式2: 在项目根目录创建 .env 文件写入 OPENAI_API_KEY=xxx"
  exit 1
fi

if [ -z "$OPENAI_BASE_URL" ]; then
  echo "[错误] 请设置 OPENAI_BASE_URL（OpenAI 兼容 API 地址）"
  exit 1
fi

# 武器库 API 默认指向本机，VPS 上需要改成服务器地址
export WEAPON_RADAR_URL="${WEAPON_RADAR_URL:-http://127.0.0.1:8765}"

# ── 编译检查 ──────────────────────────────────────────────────
if [ ! -f dist/bin/ovogogogo.js ]; then
  echo "[*] 未找到编译产物，正在编译..."
  npm install && npm run build
fi

# ── 启动 ──────────────────────────────────────────────────────
echo "[*] OPENAI_BASE_URL = $OPENAI_BASE_URL"
echo "[*] WEAPON_RADAR_URL = $WEAPON_RADAR_URL"
echo ""
node dist/bin/ovogogogo.js
