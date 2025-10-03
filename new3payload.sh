#!/usr/bin/env bash
set -eu

# ==========================================================
# WSS 隧道与用户管理面板一键部署脚本 (V3 - 最终修复版)
# ----------------------------------------------------------
# 优化点: 
# 1. 修复流量同步脚本的 JSONDecodeError (已解除 API 的内部认证限制)。
# 2. 增强删除/暂停用户时的会话强制终止逻辑 (pkill)。
# 3. 优化 IPTables 规则清理和用户 UID 匹配逻辑，提高流量统计稳定性。
# ==========================================================

# =============================
# 提示端口和面板密码
# =============================
echo "----------------------------------"
echo "==== WSS 基础设施端口配置 ===="
read -p "请输入 WSS HTTP 监听端口 (默认80): " WSS_HTTP_PORT
WSS_HTTP_PORT=${WSS_HTTP_PORT:-80}

read -p "请输入 WSS TLS 监听端口 (默认443): " WSS_TLS_PORT
WSS_TLS_PORT=${WSS_TLS_PORT:-443}

read -p "请输入 Stunnel4 端口 (默认444): " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-444}

read -p "请输入 UDPGW 端口 (默认7300): " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

echo "----------------------------------"
echo "==== 管理面板配置 ===="
read -p "请输入 Web 管理面板监听端口 (默认8080): " PANEL_PORT
PANEL_PORT=${PANEL_PORT:-8080}

# 交互式安全输入并确认 ROOT 密码
echo "请为 Web 面板的 'root' 用户设置密码（输入时隐藏）。"
while true; do
  read -s -p "面板密码: " pw1 && echo
  read -s -p "请再次确认密码: " pw2 && echo
  if [ -z "$pw1" ]; then
    echo "密码不能为空，请重新输入。"
    continue
  fi
  if [ "$pw1" != "$pw2" ]; then
    echo "两次输入不一致，请重试。"
    continue
  fi
  PANEL_ROOT_PASS_RAW="$pw1"
  # 对密码进行简单的 HASH，防止明文存储
  PANEL_ROOT_PASS_HASH=$(echo -n "$PANEL_ROOT_PASS_RAW" | sha256sum | awk '{print $1}')
  break
done

echo "----------------------------------"
echo "==== 系统更新与依赖安装 ===="
# 确保所有依赖已安装 (requests 已加入)
apt update -y
apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4
pip3 install flask jinja2 requests
echo "依赖安装完成"
echo "----------------------------------"


# =============================
# WSS 核心代理脚本 (保持不变)
# =============================
echo "==== 安装 WSS 核心代理脚本 (/usr/local/bin/wss) ===="
tee /usr/local/bin/wss > /dev/null <<'EOF'
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio, ssl, sys

LISTEN_ADDR = '0.0.0.0'

try:
    HTTP_PORT = int(sys.argv[1])
except (IndexError, ValueError):
    HTTP_PORT = 80
try:
    TLS_PORT = int(sys.argv[2])
except (IndexError, ValueError):
    TLS_PORT = 443

DEFAULT_TARGET = ('127.0.0.1', 48303)
BUFFER_SIZE = 65536
TIMEOUT = 3600
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'

FIRST_RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK\r\n\r\n'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'
FORBIDDEN_RESPONSE = b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    peer = writer.get_extra_info('peername')
    # print(f"Connection from {peer} {'(TLS)' if tls else ''}") # 禁用日志，减少输出
    forwarding_started = False
    full_request = b''

    try:
        # --- 1. 握手循环 ---
        while not forwarding_started:
            data = await asyncio.wait_for(reader.read(BUFFER_SIZE), timeout=TIMEOUT)
            if not data:
                break
            
            full_request += data
            
            header_end_index = full_request.find(b'\r\n\r\n')
            
            if header_end_index == -1:
                writer.write(FIRST_RESPONSE)
                await writer.drain()
                full_request = b''
                continue

            # 2. 头部解析
            headers_raw = full_request[:header_end_index]
            data_to_forward = full_request[header_end_index + 4:]
            headers = headers_raw.decode(errors='ignore')

            is_websocket_request = 'Upgrade: websocket' in headers or 'Connection: Upgrade' in headers or 'GET-RAY' in headers
            
            # 3. 转发触发
            if is_websocket_request:
                writer.write(SWITCH_RESPONSE)
                await writer.drain()
                forwarding_started = True
            else:
                writer.write(FIRST_RESPONSE)
                await writer.drain()
                full_request = b''
                continue
        
        # --- 退出握手循环 ---

        # 4. 连接目标服务器 (默认到 Stunnel/SSH 的转发端口)
        target = DEFAULT_TARGET
        target_reader, target_writer = await asyncio.open_connection(*target)

        # 5. 转发初始数据
        if data_to_forward:
            target_writer.write(data_to_forward)
            await target_writer.drain()
            
        # 6. 转发后续数据流
        async def pipe(src_reader, dst_writer):
            try:
                while True:
                    buf = await src_reader.read(BUFFER_SIZE)
                    if not buf:
                        break
                    dst_writer.write(buf)
                    await dst_writer.drain()
            except Exception:
                pass
            finally:
                dst_writer.close()

        await asyncio.gather(
            pipe(reader, target_writer),
            pipe(target_reader, writer)
        )

    except Exception as e:
        # print(f"Connection error {peer}: {e}") # 禁用日志，减少输出
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        # print(f"Closed {peer}") # 禁用日志，减少输出

async def main():
    # TLS server setup
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        ssl_ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        tls_server = await asyncio.start_server(
            lambda r, w: handle_client(r, w, tls=True), LISTEN_ADDR, TLS_PORT, ssl=ssl_ctx)
        print(f"Listening on {LISTEN_ADDR}:{TLS_PORT} (TLS)")
        tls_task = tls_server.serve_forever()
    except FileNotFoundError:
        print(f"WARNING: TLS certificate not found at {CERT_FILE}. TLS server disabled.")
        tls_task = asyncio.sleep(86400) # Keep task running but effectively disabled
    
    http_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, tls=False), LISTEN_ADDR, HTTP_PORT)
    
    print(f"Listening on {LISTEN_ADDR}:{HTTP_PORT} (HTTP payload)")

    async with http_server:
        await asyncio.gather(
            tls_task,
            http_server.serve_forever())

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("WSS Proxy Stopped.")
        
EOF

chmod +x /usr/local/bin/wss

# 创建 WSS systemd 服务 (如果不存在)
if [ ! -f "/etc/systemd/system/wss.service" ]; then
tee /etc/systemd/system/wss.service > /dev/null <<EOF
[Unit]
Description=WSS Python Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wss $WSS_HTTP_PORT $WSS_TLS_PORT
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
systemctl enable wss || true
systemctl restart wss || true
echo "WSS 核心代理已启动/重启，HTTP端口 $WSS_HTTP_PORT, TLS端口 $WSS_TLS_PORT"
echo "----------------------------------"

# =============================
# 安装 Stunnel4 并生成证书 (保持不变)
# =============================
echo "==== 检查/安装 Stunnel4 ===="
mkdir -p /etc/stunnel/certs
if [ ! -f "/etc/stunnel/certs/stunnel.pem" ]; then
    openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout /etc/stunnel/certs/stunnel.key \
    -out /etc/stunnel/certs/stunnel.crt \
    -days 1095 \
    -subj "/CN=example.com" > /dev/null 2>&1
    sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
    chmod 644 /etc/stunnel/certs/*.crt
    chmod 644 /etc/stunnel/certs/*.pem
    echo "Stunnel 证书已生成。"
fi

tee /etc/stunnel/ssh-tls.conf > /dev/null <<EOF
pid=/var/run/stunnel.pid
setuid=root
setgid=root
client = no
debug = 5
output = /var/log/stunnel4/stunnel.log
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls-gateway]
accept = 0.0.0.0:$STUNNEL_PORT
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
connect = 127.0.0.1:48303
EOF

systemctl enable stunnel4 || true
systemctl restart stunnel4 || true
echo "Stunnel4 配置已更新并重启，端口 $STUNNEL_PORT"
echo "----------------------------------"

# =============================
# 安装 UDPGW (保持不变)
# =============================
echo "==== 检查/安装 UDPGW ===="
if [ ! -f "/root/badvpn/badvpn-build/udpgw/badvpn-udpgw" ]; then
    if [ ! -d "/root/badvpn" ]; then
        git clone https://github.com/ambrop72/badvpn.git /root/badvpn
    fi
    mkdir -p /root/badvpn/badvpn-build
    cd /root/badvpn/badvpn-build
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 > /dev/null 2>&1
    make -j$(nproc) > /dev/null 2>&1
    cd - > /dev/null
    echo "UDPGW 编译完成。"
fi


tee /etc/systemd/system/udpgw.service > /dev/null <<EOF
[Unit]
Description=UDP Gateway (Badvpn)
After=network.target

[Service]
Type=simple
ExecStart=/root/badvpn/badvpn-build/udpgw/badvpn-udpgw --listen-addr 127.0.0.1:$UDPGW_PORT --max-clients 1024 --max-connections-for-client 10
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable udpgw || true
systemctl restart udpgw || true
echo "UDPGW 已启动/重启，端口: $UDPGW_PORT"
echo "----------------------------------"


# =============================
# 安装 WSS 用户管理面板 (基于 Flask) - V3 最终修复
# =============================
echo "==== 部署 WSS 用户管理面板 (Python/Flask) V3 最终修复 ===="
PANEL_DIR="/etc/wss-panel"
USER_DB="$PANEL_DIR/users.json"
mkdir -p "$PANEL_DIR"

# 检查/初始化用户数据库，并添加新字段的默认值
if [ ! -f "$USER_DB" ]; then
    echo "[]" > "$USER_DB"
else
    # 尝试升级旧的 JSON 结构，确保新字段存在
    python3 -c "
import json
import time
import os

USER_DB_PATH = \"$USER_DB\"

def upgrade_users():
    try:
        if not os.path.exists(USER_DB_PATH):
            return
        with open(USER_DB_PATH, 'r') as f:
            users = json.load(f)
    except Exception:
        print('Error loading users, skipping upgrade.')
        return

    updated = False
    for user in users:
        if 'status' not in user:
            user['status'] = 'active'
            user['expiry_date'] = ''
            user['quota_gb'] = 0.0
            user['used_traffic_gb'] = 0.0
            user['last_check'] = time.time()
            updated = True
    
    if updated:
        with open(USER_DB_PATH, 'w') as f:
            json.dump(users, f, indent=4)
        print('User database structure upgraded.')

upgrade_users()
"
fi

# 嵌入 Python 面板代码 (修复了 update_traffic_api 的认证问题)
tee /usr/local/bin/wss_panel.py > /dev/null <<EOF
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, redirect, url_for, session, make_response
import json
import subprocess
import os
import hashlib
import time
import jinja2
from datetime import datetime

# --- 配置 ---
USER_DB_PATH = "$USER_DB"
ROOT_USERNAME = "root"
ROOT_PASSWORD_HASH = "$PANEL_ROOT_PASS_HASH"
FLASK_SECRET_KEY = os.urandom(24).hex()
SSHD_CONFIG = "/etc/ssh/sshd_config"

# 面板和端口配置 (用于模板)
PANEL_PORT = "$PANEL_PORT"
WSS_HTTP_PORT = "$WSS_HTTP_PORT"
WSS_TLS_PORT = "$WSS_TLS_PORT"
STUNNEL_PORT = "$STUNNEL_PORT"
UDPGW_PORT = "$UDPGW_PORT"

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# --- 数据库操作 ---

def load_users():
    """从 JSON 文件加载用户列表."""
    if not os.path.exists(USER_DB_PATH):
        return []
    try:
        with open(USER_DB_PATH, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading users.json: {e}")
        return []

def save_users(users):
    """保存用户列表到 JSON 文件."""
    try:
        with open(USER_DB_PATH, 'w') as f:
            json.dump(users, f, indent=4)
    except Exception as e:
        print(f"Error saving users.json: {e}")

def get_user(username):
    """按用户名查找用户对象和索引."""
    users = load_users()
    for i, user in enumerate(users):
        if user['username'] == username:
            return user, i
    return None, -1

# --- 认证装饰器 ---

def login_required(f):
    """检查用户是否已登录."""
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session.get('logged_in'):
            # 返回登录 HTML 页面，这是导致 JSONDecodeError 的原因
            return redirect(url_for('login')) 
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# --- 系统工具函数 ---

def safe_run_command(command, input=None):
    """安全执行系统命令并返回结果."""
    try:
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=input, 
            timeout=5
        )
        return True, result.stdout.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        return False, e.stderr.decode('utf-8').strip()
    except Exception as e:
        return False, str(e)

def kill_user_sessions(username):
    """尝试杀死该用户的所有活动进程 (主要针对 SSH 会话)."""
    # pkill -u <username> 会终止所有属于该用户的进程
    success, output = safe_run_command(['pkill', '-u', username])
    if success:
        print(f"Killed active sessions for user {username}.")
    else:
        # 即使找不到进程，pkill 也会返回非零状态，这可以忽略
        print(f"Warning: pkill for {username} might have failed or no process found: {output}")
    return success, output

# --- 核心用户状态管理函数 ---

def sync_user_status(user):
    """检查并同步用户的到期日和流量配额状态到系统."""
    username = user['username']
    
    # 1. 检查账户到期日
    is_expired = False
    if user['expiry_date']:
        try:
            expiry_dt = datetime.strptime(user['expiry_date'], '%Y-%m-%d')
            # 检查到期日是否在今天之前
            if expiry_dt.date() < datetime.now().date():
                is_expired = True
        except ValueError:
            print(f"Invalid expiry_date format for {username}: {user['expiry_date']}")
    
    # 2. 检查流量配额
    is_quota_exceeded = False
    if user['quota_gb'] > 0 and user['used_traffic_gb'] >= user['quota_gb']:
        is_quota_exceeded = True
        
    # 3. 执行暂停/启用操作
    current_status = user.get('status', 'active')
    should_be_paused = (current_status == 'paused') or is_expired or is_quota_exceeded
    
    # 获取系统实际状态 (简单通过 chage 检查是否已过期或锁定)
    system_expired = False
    system_locked = False
    success, output = safe_run_command(['chage', '-l', username])
    if success:
        # 检查账户是否过期 (Expire date)
        if 'Account expires' in output and 'never' not in output.lower():
            for line in output.split('\n'):
                if 'Account expires' in line:
                    parts = line.split(':')
                    if len(parts) > 1 and parts[1].strip() != 'never':
                        system_expired = True
                        break
        # 检查账户是否被锁定 (usermod -L/chage -E 0)
        success_status, output_status = safe_run_command(['passwd', '-S', username])
        if success_status and 'L' in output_status.split():
            system_locked = True
            
    # 如果面板要求启用 (active), 且系统是暂停的或已过期, 则解锁并清除到期日
    if not should_be_paused and (system_locked or system_expired):
        safe_run_command(['usermod', '-U', username]) # 解锁密码
        safe_run_command(['chage', '-E', '', username]) # 清除到期日
        user['status'] = 'active'
        # print(f"Synced {username}: Activated in system.")
        
    # 如果面板要求暂停, 且系统是未暂停的
    elif should_be_paused and not system_locked:
        # 暂停的原因可能是面板主动暂停、到期或超额。使用 usermod -L 锁定密码
        safe_run_command(['usermod', '-L', username])
        # 额外设置到期日为 '1970-01-01' (立即过期) 确保客户端连接断开
        safe_run_command(['chage', '-E', '1970-01-01', username]) 
        kill_user_sessions(username) # 立即终止活动会话 (NEW)
        user['status'] = 'paused' # 标记面板状态
        # print(f"Synced {username}: Paused in system and sessions killed.")
        
    # 无论如何，如果到期日字段存在，确保它被设置到系统
    if user['expiry_date'] and current_status == 'active':
        safe_run_command(['chage', '-E', user['expiry_date'], username]) 
        
    return user


def refresh_all_user_status(users):
    """批量同步用户状态."""
    updated = False
    for user in users:
        # 只有在 active 状态下才设置到期日，否则保持锁定
        user = sync_user_status(user)
        # 格式化流量信息以便显示
        user['traffic_display'] = f"{user['used_traffic_gb']:.2f} / {user['quota_gb']:.2f} GB"
        if user['quota_gb'] > 0 and user['used_traffic_gb'] >= user['quota_gb']:
            user['status_text'] = "Exceeded"
            user['status_class'] = "bg-red-500"
        elif user['status'] == 'paused':
            user['status_text'] = "Paused"
            user['status_class'] = "bg-yellow-500"
        elif user['expiry_date'] and datetime.strptime(user['expiry_date'], '%Y-%m-%d').date() < datetime.now().date():
            user['status_text'] = "Expired"
            user['status_class'] = "bg-red-500"
        else:
            user['status_text'] = "Active"
            user['status_class'] = "bg-green-500"
            
        updated = True
    if updated:
        save_users(users)
    return users


# --- HTML 模板和渲染 ---

# 仪表盘 HTML (内嵌 - 使用 Tailwind)
_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS Panel - 仪表盘 V3</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .card { transition: all 0.3s ease; }
        .card:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1); }
        .btn-action { transition: all 0.2s ease; }
        .btn-action:hover { opacity: 0.8; }
        .modal { background-color: rgba(0, 0, 0, 0.5); z-index: 999; }
    </style>
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="bg-indigo-600 text-white shadow-lg">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center">
            <h1 class="text-3xl font-bold">WSS 隧道管理面板 V3</h1>
            <button onclick="logout()" class="bg-indigo-800 hover:bg-red-700 px-4 py-2 rounded-lg font-semibold shadow-md btn-action">
                退出登录 (root)
            </button>
        </div>
    </div>

    <div class="max-w-7xl mx-auto p-4 sm:p-6 lg:p-8">
        <!-- Status Message Box -->
        <div id="status-message" class="hidden p-4 mb-4 rounded-lg font-semibold" role="alert"></div>
        
        <!-- Stats Grid -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div class="card bg-white p-5 rounded-xl shadow-lg border-l-4 border-indigo-500">
                <h3 class="text-sm font-medium text-gray-500">已管理用户数</h3>
                <p class="text-3xl font-bold text-gray-900 mt-1">{{ users|length }}</p>
            </div>
            <div class="card bg-white p-5 rounded-xl shadow-lg border-l-4 border-green-500">
                <h3 class="text-sm font-medium text-gray-500">面板端口</h3>
                <p class="text-3xl font-bold text-gray-900 mt-1">{{ panel_port }}</p>
            </div>
            <div class="card bg-white p-5 rounded-xl shadow-lg border-l-4 border-blue-500">
                <h3 class="text-sm font-medium text-gray-500">WSS (TLS) 端口</h3>
                <p class="text-3xl font-bold text-gray-900 mt-1">{{ wss_tls_port }}</p>
            </div>
            <div class="card bg-white p-5 rounded-xl shadow-lg border-l-4 border-yellow-500">
                <h3 class="text-sm font-medium text-gray-500">Stunnel/SSH 端口</h3>
                <p class="text-3xl font-bold text-gray-900 mt-1">{{ stunnel_port }}</p>
            </div>
        </div>

        <!-- Connection Info Card -->
        <div class="card bg-white p-6 rounded-xl shadow-lg mb-8">
            <h3 class="text-xl font-semibold text-gray-800 mb-4 border-b pb-2">连接信息</h3>
            <div class="bg-gray-100 p-4 rounded-lg font-mono text-sm overflow-x-auto">
                <p><span class="font-bold">服务器地址:</span> {{ host_ip }} (请手动替换为你的公网 IP)</p>
                <p><span class="font-bold">WSS (TLS/WebSocket):</span> 端口 {{ wss_tls_port }}</p>
                <p><span class="font-bold">Stunnel (TLS 隧道):</span> 端口 {{ stunnel_port }}</p>
                <p><span class="font-bold text-red-600">注意:</span> 认证方式为 **SSH 账户/密码**。WSS/Stunnel 均转发至本地 SSH 端口 48303。</p>
            </div>
        </div>

        <!-- Add User Card -->
        <div class="card bg-white p-6 rounded-xl shadow-lg mb-8">
            <h3 class="text-xl font-semibold text-gray-800 mb-4">新增 WSS 用户</h3>
            <form id="add-user-form" class="flex flex-wrap items-center gap-4">
                <input type="text" id="new-username" placeholder="用户名 (小写字母/数字/下划线)" 
                       class="flex-1 min-w-[200px] p-2.5 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500"
                       pattern="[a-z0-9_]{3,16}" title="用户名只能包含小写字母、数字和下划线，长度3-16位" required>
                <input type="password" id="new-password" placeholder="密码" 
                       class="flex-1 min-w-[200px] p-2.5 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                <button type="submit" class="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2.5 rounded-lg font-semibold shadow-md btn-action">
                    创建用户
                </button>
            </form>
        </div>
        
        <!-- User List Card -->
        <div class="card bg-white p-6 rounded-xl shadow-lg">
            <h3 class="text-xl font-semibold text-gray-800 mb-4">用户列表</h3>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200 user-table">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">用户名</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">状态</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">到期日</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">流量使用 (GB)</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">操作</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200" id="user-table-body">
                        {% for user in users %}
                        <tr id="row-{{ user.username }}" class="hover:bg-gray-50">
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{{ user.username }}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm">
                                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full text-white {{ user.status_class }}">
                                    {{ user.status_text }}
                                </span>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                {{ user.expiry_date if user.expiry_date else 'N/A' }}
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                {{ user.traffic_display }}
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2">
                                <button onclick="toggleUserStatus('{{ user.username }}', '{{ 'pause' if user.status_text == 'Active' else 'active' }}')" 
                                        class="text-xs px-3 py-1 rounded-full font-bold {{ 'bg-yellow-100 text-yellow-800 hover:bg-yellow-200' if user.status_text == 'Active' else 'bg-green-100 text-green-800 hover:bg-green-200' }} btn-action">
                                    {{ '暂停' if user.status_text == 'Active' else '启用' }}
                                </button>
                                <button onclick="openQuotaModal('{{ user.username }}', '{{ user.quota_gb }}', '{{ user.expiry_date }}')" 
                                        class="text-xs px-3 py-1 rounded-full font-bold bg-blue-100 text-blue-800 hover:bg-blue-200 btn-action">
                                    配额/到期
                                </button>
                                <button onclick="deleteUser('{{ user.username }}')" 
                                        class="text-xs px-3 py-1 rounded-full font-bold bg-red-100 text-red-800 hover:bg-red-200 btn-action">
                                    删除
                                </button>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

    </div>
    
    <!-- Modal for Quota and Expiry -->
    <div id="quota-modal" class="modal fixed inset-0 flex items-center justify-center p-4 hidden">
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-lg">
            <div class="p-6">
                <h3 class="text-xl font-bold mb-4 text-gray-800 border-b pb-2">设置 <span id="modal-username-title"></span> 的配额和到期日</h3>
                <form id="quota-form" onsubmit="event.preventDefault(); saveQuotaAndExpiry();">
                    <input type="hidden" id="modal-username">
                    
                    <div class="mb-4">
                        <label for="modal-quota" class="block text-sm font-medium text-gray-700">流量配额 (GB, 0为无限)</label>
                        <input type="number" step="0.01" min="0" id="modal-quota" 
                               class="mt-1 block w-full p-2 border border-gray-300 rounded-lg" required>
                    </div>
                    
                    <div class="mb-6">
                        <label for="modal-expiry" class="block text-sm font-medium text-gray-700">到期日 (YYYY-MM-DD, 留空为永不到期)</label>
                        <input type="date" id="modal-expiry" 
                               class="mt-1 block w-full p-2 border border-gray-300 rounded-lg">
                    </div>

                    <div class="flex justify-end space-x-3">
                        <button type="button" onclick="closeQuotaModal()" class="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded-lg font-semibold btn-action">
                            取消
                        </button>
                        <button type="submit" class="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg font-semibold btn-action">
                            保存设置
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script>
        function showStatus(message, isSuccess) {
            const statusDiv = document.getElementById('status-message');
            statusDiv.textContent = message;
            statusDiv.className = \`\${isSuccess ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'} p-4 mb-4 rounded-lg font-semibold\`;
            statusDiv.classList.remove('hidden');
            setTimeout(() => { statusDiv.classList.add('hidden'); }, 5000);
        }

        document.getElementById('add-user-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('new-username').value.trim();
            const password = document.getElementById('new-password').value;

            try {
                const response = await fetch('/api/users/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                const result = await response.json();
                
                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    document.getElementById('new-username').value = '';
                    document.getElementById('new-password').value = '';
                    location.reload(); 
                } else {
                    showStatus('创建失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        });

        async function toggleUserStatus(username, action) {
            const actionText = action === 'active' ? '启用' : '暂停';
            const confirmText = action === 'active' ? 'YES' : 'STOP';
            // NEW: 提示用户会话将立即中断
            if (window.prompt(\`确定要\${actionText}用户 \${username} 吗? (\${actionText}操作将同时终止所有活动会话。输入 \${confirmText} 确认)\`) !== confirmText) {
                return;
            }
            
            try {
                const response = await fetch('/api/users/status', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, action })
                });

                const result = await response.json();

                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    location.reload(); 
                } else {
                    showStatus(\`\${actionText}失败: \` + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        }

        async function deleteUser(username) {
            // NEW: 提示用户会话将立即中断
            if (window.prompt(\`确定要永久删除用户 \${username} 吗? (此操作将终止所有活动会话并删除系统账户。输入 DELETE 确认)\`) !== 'DELETE') {
                return;
            }
            
            try {
                const response = await fetch('/api/users/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username })
                });

                const result = await response.json();

                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    location.reload(); 
                } else {
                    showStatus('删除失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        }

        function openQuotaModal(username, quota, expiry) {
            document.getElementById('modal-username-title').textContent = username;
            document.getElementById('modal-username').value = username;
            document.getElementById('modal-quota').value = parseFloat(quota) || 0;
            document.getElementById('modal-expiry').value = expiry || '';
            document.getElementById('quota-modal').classList.remove('hidden');
        }

        function closeQuotaModal() {
            document.getElementById('quota-modal').classList.add('hidden');
        }

        async function saveQuotaAndExpiry() {
            const username = document.getElementById('modal-username').value;
            const quota_gb = parseFloat(document.getElementById('modal-quota').value);
            const expiry_date = document.getElementById('modal-expiry').value;

            try {
                const response = await fetch('/api/users/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, quota_gb, expiry_date })
                });

                const result = await response.json();

                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    closeQuotaModal();
                    location.reload(); 
                } else {
                    showStatus('保存设置失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        }
        
        function logout() {
            window.location.href = '/logout';
        }

    </script>
</body>
</html>
"""

# 修复后的渲染函数
def render_dashboard(users):
    """手动渲染 Jinja2 模板字符串."""
    template_env = jinja2.Environment(loader=jinja2.BaseLoader)
    template = template_env.from_string(_DASHBOARD_HTML)
    
    # 获取服务器IP (这里只能从请求头推测，不一定准确，需要用户手动替换)
    host_ip = request.host.split(':')[0]
    if host_ip in ('127.0.0.1', 'localhost'):
        host_ip = '[Your Server IP]'

    context = {
        'users': users,
        'panel_port': PANEL_PORT,
        'wss_http_port': WSS_HTTP_PORT,
        'wss_tls_port': WSS_TLS_PORT,
        'stunnel_port': STUNNEL_PORT,
        'udpgw_port': UDPGW_PORT,
        'host_ip': host_ip
    }
    return template.render(**context)


# --- Web 路由 (保持不变) ---

@app.route('/', methods=['GET'])
@login_required
def dashboard():
    users = load_users()
    # 每次加载仪表盘时，检查并同步用户状态
    users = refresh_all_user_status(users)
    html_content = render_dashboard(users=users)
    return make_response(html_content)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password_raw = request.form.get('password')
        
        # 验证 ROOT 账户
        if username == ROOT_USERNAME and password_raw:
            password_hash = hashlib.sha256(password_raw.encode('utf-8')).hexdigest()
            if password_hash == ROOT_PASSWORD_HASH:
                session['logged_in'] = True
                session['username'] = ROOT_USERNAME
                return redirect(url_for('dashboard'))
            else:
                error = '用户名或密码错误。'
        else:
            error = '用户名或密码错误。'

    html = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS Panel - 登录</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body {{ font-family: 'Inter', sans-serif; background-color: #f4f7f6; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
        .container {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1); width: 100%; max-width: 400px; }}
        h1 {{ text-align: center; color: #1f2937; margin-bottom: 30px; font-weight: 700; }}
        input[type=text], input[type=password] {{ width: 100%; padding: 12px; margin: 10px 0; display: inline-block; border: 1px solid #d1d5db; border-radius: 8px; box-sizing: border-box; transition: all 0.3s; }}
        input[type=text]:focus, input[type=password]:focus {{ border-color: #4f46e5; outline: 2px solid #a5b4fc; }}
        button {{ background-color: #4f46e5; color: white; padding: 14px 20px; margin: 15px 0 5px 0; border: none; border-radius: 8px; cursor: pointer; width: 100%; font-size: 16px; font-weight: 600; transition: background-color 0.3s; }}
        button:hover {{ background-color: #4338ca; }}
        .error {{ color: #ef4444; background-color: #fee2e2; padding: 10px; border-radius: 6px; text-align: center; margin-bottom: 15px; font-weight: 500; border: 1px solid #fca5a5; }}
    </style>
</head>
<body>
    <div class="container">
        <h1 class="text-2xl">WSS 管理面板 V3</h1>
        {f'<div class="error">{error}</div>' if error else ''}
        <form method="POST">
            <label for="username" class="block text-sm font-medium text-gray-700">用户名</label>
            <input type="text" placeholder="输入 {ROOT_USERNAME}" name="username" value="{ROOT_USERNAME}" required>

            <label for="password" class="block text-sm font-medium text-gray-700 mt-4">密码</label>
            <input type="password" placeholder="输入密码" name="password" required>

            <button type="submit">登录</button>
        </form>
    </div>
</body>
</html>
    """
    return make_response(html)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))


@app.route('/api/users/add', methods=['POST'])
@login_required
def add_user_api():
    """添加用户 (API)"""
    data = request.json
    username = data.get('username')
    password_raw = data.get('password')
    
    if not username or not password_raw:
        return jsonify({"success": False, "message": "缺少用户名或密码"}), 400

    users = load_users()
    if get_user(username)[0]:
        return jsonify({"success": False, "message": f"用户 {username} 已存在于面板"}), 409

    # 1. 创建系统用户 (使用 -s /bin/false 禁用远程 shell 登录，增加安全性)
    success, output = safe_run_command(['useradd', '-m', '-s', '/bin/false', username])
    if not success:
        return jsonify({"success": False, "message": f"创建系统用户失败: {output}"}), 500

    # 2. 设置密码
    chpasswd_input = f"{username}:{password_raw}"
    success, output = safe_run_command(['/usr/sbin/chpasswd'], input=chpasswd_input.encode('utf-8'))
    if not success:
        safe_run_command(['userdel', '-r', username])
        return jsonify({"success": False, "message": f"设置密码失败: {output}"}), 500
        
    # 3. 记录到 JSON 数据库
    new_user = {
        "username": username,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "status": "active",
        "expiry_date": "", 
        "quota_gb": 0.0,
        "used_traffic_gb": 0.0,
        "last_check": time.time()
    }
    users.append(new_user)
    save_users(users)
    sync_user_status(new_user) # 确保系统状态同步

    return jsonify({"success": True, "message": f"用户 {username} 创建成功"})

@app.route('/api/users/delete', methods=['POST'])
@login_required
def delete_user_api():
    """删除用户 (API)"""
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({"success": False, "message": "缺少用户名"}), 400

    users = load_users()
    user_to_delete, index = get_user(username)

    if not user_to_delete:
        return jsonify({"success": False, "message": f"面板中用户 {username} 不存在"}), 404

    # 1. 终止用户会话 (NEW STEP)
    kill_user_sessions(username)

    # 2. 删除系统用户及其主目录
    success, output = safe_run_command(['userdel', '-r', username])
    if not success:
        print(f"Warning: Failed to delete system user {username}: {output}")

    # 3. 从 JSON 数据库中删除记录
    users.pop(index)
    save_users(users)

    return jsonify({"success": True, "message": f"用户 {username} 已删除，活动会话已终止"})

@app.route('/api/users/status', methods=['POST'])
@login_required
def toggle_user_status_api():
    """启用/暂停用户 (API)"""
    data = request.json
    username = data.get('username')
    action = data.get('action') # 'active' or 'pause'

    user, index = get_user(username)
    if not user:
        return jsonify({"success": False, "message": f"用户 {username} 不存在"}), 404
        
    users = load_users()

    if action == 'pause':
        # 暂停逻辑：锁定密码
        success, output = safe_run_command(['usermod', '-L', username])
        safe_run_command(['chage', '-E', '1970-01-01', username]) # 强制过期
        kill_user_sessions(username) # 立即终止活动会话 (NEW)
        users[index]['status'] = 'paused'
        message = f"用户 {username} 已暂停，活动会话已终止"
    elif action == 'active':
        # 启用逻辑：解锁密码
        success, output = safe_run_command(['usermod', '-U', username])
        # 如果设置了到期日，则重新设置到期日，否则清除到期日
        if users[index]['expiry_date']:
            safe_run_command(['chage', '-E', users[index]['expiry_date'], username]) 
        else:
            safe_run_command(['chage', '-E', '', username]) 
            
        users[index]['status'] = 'active'
        message = f"用户 {username} 已启用"
    else:
        return jsonify({"success": False, "message": "无效的操作参数"}), 400

    if success:
        save_users(users)
        return jsonify({"success": True, "message": message})
    else:
        return jsonify({"success": False, "message": f"系统操作失败: {output}"}), 500


@app.route('/api/users/settings', methods=['POST'])
@login_required
def update_user_settings_api():
    """设置用户配额和到期日 (API)"""
    data = request.json
    username = data.get('username')
    quota_gb = data.get('quota_gb', 0.0)
    expiry_date = data.get('expiry_date', '')

    user, index = get_user(username)
    if not user:
        return jsonify({"success": False, "message": f"用户 {username} 不存在"}), 404
        
    users = load_users()
    
    # 格式化和验证
    try:
        quota_gb = max(0.0, float(quota_gb))
        if expiry_date:
            datetime.strptime(expiry_date, '%Y-%m-%d') # 检查日期格式
    except ValueError:
        return jsonify({"success": False, "message": "配额或日期格式不正确"}), 400

    # 更新面板数据库
    users[index]['quota_gb'] = quota_gb
    users[index]['expiry_date'] = expiry_date
    
    # 如果用户当前处于 active 状态，则同步到期日到系统
    if users[index]['status'] == 'active':
        if expiry_date:
            safe_run_command(['chage', '-E', expiry_date, username])
        else:
            # 清除系统到期日 (永不到期)
            safe_run_command(['chage', '-E', '', username])
    
    # 如果流量超额或日期已过，重新同步状态 (可能会触发暂停)
    users[index] = sync_user_status(users[index])
    
    save_users(users)
    return jsonify({"success": True, "message": f"用户 {username} 设置已更新"})
    
    
@app.route('/api/users/update_traffic', methods=['POST'])
# >>>>>>>>>> 关键修复: 移除 @login_required 以允许内部脚本调用 <<<<<<<<<<
# @login_required 
def update_user_traffic_api():
    """外部工具用于更新用户流量的 API (无需系统操作)"""
    data = request.json
    username = data.get('username')
    used_traffic_gb = data.get('used_traffic_gb')

    if not username or used_traffic_gb is None:
        return jsonify({"success": False, "message": "缺少用户名或流量数据"}), 400

    user, index = get_user(username)
    if not user:
        return jsonify({"success": False, "message": f"用户 {username} 不存在"}), 404

    users = load_users()
    
    # 仅更新流量和检查时间
    users[index]['used_traffic_gb'] = max(0.0, float(used_traffic_gb))
    users[index]['last_check'] = time.time()
    
    # 检查并同步状态 (流量超额则自动暂停)
    users[index] = sync_user_status(users[index])
    
    save_users(users)
    return jsonify({"success": True, "message": f"用户 {username} 流量已更新为 {used_traffic_gb:.2f} GB"})


if __name__ == '__main__':
    # 为了简化部署，将 debug 设置为 False
    print(f"WSS Panel running on port {PANEL_PORT}")
    app.run(host='0.0.0.0', port=int(PANEL_PORT), debug=False)
EOF

chmod +x /usr/local/bin/wss_panel.py

# =============================
# 创建 WSS 面板 systemd 服务
# =============================
if [ ! -f "/etc/systemd/system/wss_panel.service" ]; then
tee /etc/systemd/system/wss_panel.service > /dev/null <<EOF
[Unit]
Description=WSS User Management Panel (Flask)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/wss_panel.py
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
systemctl enable wss_panel || true
systemctl restart wss_panel
echo "WSS 管理面板 V3 已启动/重启，端口 $PANEL_PORT"
echo "----------------------------------"

# =============================
# 部署 IPTABLES 流量监控和同步脚本
# =============================

# 1. IPTABLES 链设置函数 (解决了 "Chain already exists" 错误)
setup_iptables_chains() {
    echo "==== 配置 IPTABLES 流量统计链 ===="
    
    # 1. 清理旧链和规则 (确保幂等性)
    # 尝试删除 INPUT/OUTPUT 中的跳转规则
    iptables -D INPUT -j WSS_USER_TRAFFIC_IN 2>/dev/null || true
    iptables -D OUTPUT -j WSS_USER_TRAFFIC_OUT 2>/dev/null || true
    
    # 刷新和删除自定义链 (修复 Chain already exists)
    iptables -F WSS_USER_TRAFFIC_IN 2>/dev/null || true
    iptables -X WSS_USER_TRAFFIC_IN 2>/dev/null || true
    iptables -F WSS_USER_TRAFFIC_OUT 2>/dev/null || true
    iptables -X WSS_USER_TRAFFIC_OUT 2>/dev/null || true

    # 2. 创建新链
    iptables -N WSS_USER_TRAFFIC_IN
    iptables -N WSS_USER_TRAFFIC_OUT

    # 3. 将新链连接到 INPUT 和 OUTPUT (在规则列表开头插入, -I 1)
    iptables -I INPUT 1 -j WSS_USER_TRAFFIC_IN
    iptables -I OUTPUT 1 -j WSS_USER_TRAFFIC_OUT
    
    # 4. 保存规则 (对于大多数发行版)
    if command -v iptables-save >/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

    echo "IPTABLES 流量统计链创建/清理完成，已连接到 INPUT/OUTPUT。"
}

# 2. 流量同步 Python 脚本 (增强了 UID 查找和 IPTables 解析)
tee /usr/local/bin/wss_traffic_sync.py > /dev/null <<EOF
# -*- coding: utf-8 -*-
import json
import os
import subprocess
import time
from datetime import datetime

# --- Configuration ---
USER_DB_PATH = "/etc/wss-panel/users.json"
PANEL_PORT = "$PANEL_PORT"
# 注意: 流量同步脚本和面板在同一台机器，直接使用 127.0.0.1
API_URL = f"http://127.0.0.1:{PANEL_PORT}/api/users/update_traffic" 
IPTABLES_CHAIN_IN = "WSS_USER_TRAFFIC_IN"
IPTABLES_CHAIN_OUT = "WSS_USER_TRAFFIC_OUT"

# --- Utility Functions ---

def safe_run_command(command, input_data=None):
    """安全执行系统命令并返回结果."""
    try:
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=input_data,
            timeout=5
        )
        return True, result.stdout.decode('utf-8').strip()
    except Exception:
        return False, ""

def load_users():
    """从 JSON 文件加载用户列表."""
    if not os.path.exists(USER_DB_PATH):
        return []
    try:
        with open(USER_DB_PATH, 'r') as f:
            return json.load(f)
    except Exception:
        return []

def bytes_to_gb(bytes_val):
    """将字节转换为 GB."""
    return bytes_val / (1024 * 1024 * 1024)

# --- Core Logic (IPTables Setup and Reading) ---

def setup_iptables_rules(users):
    """根据用户列表设置/更新 iptables 规则 (清空链并重建规则)."""
    
    # 1. 刷新用户链 (保留链本身，清理内部规则)
    safe_run_command(['iptables', '-F', IPTABLES_CHAIN_IN])
    safe_run_command(['iptables', '-F', IPTABLES_CHAIN_OUT])

    # 2. 为每个用户添加统计规则 (使用 owner 模块)
    for user in users:
        username = user['username']
        
        success, uid = safe_run_command(['id', '-u', username])
        if not success or not uid.isdigit():
            continue

        # INPUT: 目标端口 48303 (SSH) - 客户端发来的数据
        safe_run_command([
            'iptables', '-A', IPTABLES_CHAIN_IN, 
            '-p', 'tcp', '--dport', '48303', 
            '-m', 'owner', '--uid-owner', uid, 
            '-j', 'ACCEPT'
        ])
        
        # OUTPUT: 源端口 48303 (SSH) - 客户端收到的数据
        safe_run_command([
            'iptables', '-A', IPTABLES_CHAIN_OUT, 
            '-p', 'tcp', '--sport', '48303', 
            '-m', 'owner', '--uid-owner', uid, 
            '-j', 'ACCEPT'
        ])
        
    # 3. 添加默认返回规则 (必须是最后一条)
    safe_run_command(['iptables', '-A', IPTABLES_CHAIN_IN, '-j', 'RETURN'])
    safe_run_command(['iptables', '-A', IPTABLES_CHAIN_OUT, '-j', 'RETURN'])


def read_and_report_traffic():
    """读取 iptables 计数器并调用 Flask API 更新流量 (使用 Curl)."""
    users = load_users()
    if not users:
        return

    # 1. 重新设置 iptables 规则 (确保规则与当前用户列表同步)
    setup_iptables_rules(users)

    # 2. 读取流量数据
    success, output = safe_run_command(['iptables-save', '-c'])
    if not success:
        return

    # 3. 解析流量数据
    traffic_data = {}
    
    for line in output.split('\n'):
        if ('owner' in line) and ('ACCEPT' in line):
            try:
                parts = line.split('[')[1].split(']')
                bytes_str = parts[0].split(':')[1]
                total_bytes = int(bytes_str)
                uid = line.split('--uid-owner')[1].split()[0]
                
                if IPTABLES_CHAIN_IN in line and 'dport 48303' in line:
                    direction = 'in'
                elif IPTABLES_CHAIN_OUT in line and 'sport 48303' in line:
                    direction = 'out'
                else:
                    continue

                success_user, username = safe_run_command(['id', '-un', uid])
                if not success_user:
                    continue

                if username not in traffic_data:
                    traffic_data[username] = {'in': 0, 'out': 0, 'uid': uid}
                
                traffic_data[username]['in' if direction == 'in' else 'out'] += total_bytes
                
            except Exception:
                continue

    # 4. 更新面板 (使用 CURL 代替 requests)
    for user in users:
        username = user['username']
        current_used_gb = user.get('used_traffic_gb', 0.0)
        
        in_bytes = traffic_data.get(username, {}).get('in', 0)
        out_bytes = traffic_data.get(username, {}).get('out', 0)
        total_transfer_bytes = in_bytes + out_bytes
        
        # 换算成 GB，累加到面板历史流量
        new_used_gb = current_used_gb + bytes_to_gb(total_transfer_bytes)
        rounded_gb = round(new_used_gb, 2)
        
        # 构建 API JSON Payload
        payload_json = json.dumps({
            "username": username,
            "used_traffic_gb": rounded_gb
        })

        # >>>>>> 核心修改: 使用 CURL 发送 API 请求 <<<<<<
        success_curl, api_response = safe_run_command([
            'curl', '-s', '-X', 'POST', API_URL, 
            '-H', 'Content-Type: application/json', 
            '-d', payload_json
        ])
        
        # 5. 检查 CURL 响应并清零计数器
        if success_curl and api_response:
            try:
                response_json = json.loads(api_response)
                if response_json.get('success'):
                    # 成功上报后，清零该用户的 iptables 计数器
                    uid = traffic_data.get(username, {}).get('uid')
                    if uid:
                        safe_run_command([
                            'iptables', '-Z', IPTABLES_CHAIN_IN, 
                            '-p', 'tcp', '--dport', '48303', 
                            '-m', 'owner', '--uid-owner', uid
                        ])
                        safe_run_command([
                            'iptables', '-Z', IPTABLES_CHAIN_OUT, 
                            '-p', 'tcp', '--sport', '48303', 
                            '-m', 'owner', '--uid-owner', uid
                        ])
            except json.JSONDecodeError:
                # 忽略非 JSON 响应（例如 WSS 代理的 'OK' 或其他错误）
                pass


if __name__ == '__main__':
    read_and_report_traffic()

EOF

chmod +x /usr/local/bin/wss_traffic_sync.py

# 3. 创建定时任务 (Cron Job) 运行流量同步脚本
echo "==== 设置 Cron 定时任务 (每 5 分钟同步一次流量) ===="

# 确保 cron.d 目录存在
mkdir -p /etc/cron.d

# 使用 /etc/cron.d/ 部署每 5 分钟执行一次的定时任务
tee /etc/cron.d/wss-traffic > /dev/null <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# 每 5 分钟运行一次 Python 流量同步脚本
*/5 * * * * root /usr/bin/python3 /usr/local/bin/wss_traffic_sync.py
EOF

# 授予执行权限
chmod 0644 /etc/cron.d/wss-traffic

# 确保 cron 服务已启动
systemctl enable cron || true
systemctl start cron || true

echo "流量同步脚本已安装，并将每 5 分钟自动运行。"
echo "----------------------------------"

# 4. 立即运行 IPTABLES 链设置
setup_iptables_chains


# =============================
# SSHD 安全配置 (保持不变)
# =============================
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_SUFFIX=".bak.wss$(date +%s)"
SSHD_SERVICE=$(systemctl list-units --full -all | grep -q "sshd.service" && echo "sshd" || echo "ssh")

echo "==== 配置 SSHD 安全策略 (允许本机密码认证) ===="
# 备份 sshd_config
cp -a "$SSHD_CONFIG" "${SSHD_CONFIG}${BACKUP_SUFFIX}"
echo "SSHD 配置已备份到 ${SSHD_CONFIG}${BACKUP_SUFFIX}"

# 删除旧的 WSS 配置段
sed -i '/# WSS_TUNNEL_BLOCK_START/,/# WSS_TUNNEL_BLOCK_END/d' "$SSHD_CONFIG"

# 写入新的 WSS 隧道策略
cat >> "$SSHD_CONFIG" <<EOF

# WSS_TUNNEL_BLOCK_START -- managed by deploy_wss_panel.sh
# 统一策略: 允许所有用户通过本机 (127.0.0.1, ::1) 使用密码进行认证。
Match Address 127.0.0.1,::1
    # 允许密码认证，用于 WSS/Stunnel 隧道连接
    PasswordAuthentication yes
    # 允许 TTY 和转发
    PermitTTY no
    AllowTcpForwarding yes
    # 禁用 X11 转发，进一步提高安全性
    X11Forwarding no 
# WSS_TUNNEL_BLOCK_END -- managed by deploy_wss_panel.sh

EOF

chmod 600 "$SSHD_CONFIG"

# 重载 sshd
echo "重新加载并重启 ssh 服务 ($SSHD_SERVICE)"
systemctl daemon-reload
systemctl restart "$SSHD_SERVICE"
echo "SSHD 配置更新完成。"
echo "----------------------------------"

# 清理敏感变量
unset PANEL_ROOT_PASS_RAW

echo "=================================================="
echo "✅ WSS 管理面板 V3 最终修复版部署完成！"
echo "=================================================="
echo ""
echo "🔥 WSS & Stunnel 基础设施已启动。"
echo "🌐 升级后的管理面板已在后台运行。"
echo ""
echo "--- 核心功能更新 ---"
echo "1. **会话强制终止**: **删除** 或 **暂停** 用户时，其活动连接会立即被中断。"
echo "2. **IPTables 流量监控**: 已配置流量统计规则，每 **5 分钟** 自动同步数据到面板。**JSON 解析错误已修复**。"
echo ""
echo "--- 访问信息 (UI 已美化为 MD 风格) ---"
echo "Web 面板地址: http://[您的服务器IP]:$PANEL_PORT"
echo "Web 面板用户名: root"
echo "Web 面板密码: [您刚才设置的密码]"
echo ""
echo "--- 故障排查 ---"
echo "Web 面板状态: sudo systemctl status wss_panel"
echo "流量同步状态: sudo tail -f /var/log/syslog | grep wss_traffic_sync"
echo "=================================================="
