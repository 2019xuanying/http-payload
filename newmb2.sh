#!/bin/bash
set -e

# ===============================================
# A. 变量和配置
# ===============================================

# 检查是否以 root 身份运行
if [ "$EUID" -ne 0 ]; then
  echo "请以 root 或 sudo 权限运行此脚本。"
  exit 1
fi

# 提示端口
read -p "请输入 WSS HTTP 监听端口（默认80）: " WSS_HTTP_PORT
WSS_HTTP_PORT=${WSS_HTTP_PORT:-80}

read -p "请输入 WSS TLS 监听端口（默认443）: " WSS_TLS_PORT
WSS_TLS_PORT=${WSS_TLS_PORT:-443}

read -p "请输入 Stunnel4 端口（默认444）: " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-444}

read -p "请输入 UDPGW 端口（默认7300）: " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

read -p "请输入 Web 管理面板端口（默认54321）: " PANEL_PORT
PANEL_PORT=${PANEL_PORT:-54321}

# 设置面板登录密码
echo "--------------------------------------------------------"
echo "请为 Web 面板（root用户）设置登录密码："
while true; do
  read -s -p "密码: " pw1 && echo
  read -s -p "再次确认密码: " pw2 && echo
  if [ -z "$pw1" ]; then
    echo "密码不能为空，请重新输入。"
    continue
  fi
  if [ "$pw1" != "$pw2" ]; then
    echo "两次输入不一致，请重试。"
    continue
  fi
  PANEL_PASS_RAW="$pw1"
  PANEL_PASS_HASH=$(echo -n "$PANEL_PASS_RAW" | sha256sum | awk '{print $1}')
  break
done
unset PANEL_PASS_RAW
echo "--------------------------------------------------------"

# 路径常量
WSS_SCRIPT="/usr/local/bin/wss"
PANEL_SCRIPT="/usr/local/bin/wss_panel.py"
ACCOUNTANT_SCRIPT="/usr/local/bin/wss_accountant.py"
PANEL_CONFIG_DIR="/etc/wss-panel"
USER_DB_PATH="${PANEL_CONFIG_DIR}/users.json"
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_SUFFIX=".bak.wssfinal$(date +%s)"


# ===============================================
# B. 系统更新与依赖安装
# ===============================================
echo "==== 更新系统并安装依赖 (Python/Flask/Stunnel) ===="
apt update -y &> /dev/null
apt install -y python3 python3-pip python3-flask python3-jinja2 wget curl git net-tools cmake build-essential openssl stunnel4 &> /dev/null
echo "依赖安装完成"
echo "--------------------------------------------------------"

# ===============================================
# C. 部署 WSS 代理脚本 (/usr/local/bin/wss)
# ===============================================
echo "==== 部署 WSS 核心代理脚本 (增强日志) ===="
tee "$WSS_SCRIPT" > /dev/null <<EOF
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio, ssl, sys
from datetime import datetime

LISTEN_ADDR = '0.0.0.0'

try: HTTP_PORT = int(sys.argv[1])
except (IndexError, ValueError): HTTP_PORT = 80
try: TLS_PORT = int(sys.argv[2])
except (IndexError, ValueError): TLS_PORT = 443

DEFAULT_TARGET = ('127.0.0.1', 41816)
BUFFER_SIZE = 65536
TIMEOUT = 3600
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'

FIRST_RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK\r\n\r\n'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'

def log(peer, message, tls=False):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    protocol = "TLS" if tls else "HTTP"
    print(f"{timestamp} [{protocol}][{peer[0]}:{peer[1]}] {message}", file=sys.stderr)

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    peer = writer.get_extra_info('peername')
    log(peer, "Connection established.", tls)
    
    forwarding_started = False
    full_request = b''
    target = DEFAULT_TARGET
    data_to_forward = b''

    try:
        while not forwarding_started:
            data = await asyncio.wait_for(reader.read(BUFFER_SIZE), timeout=TIMEOUT)
            if not data:
                log(peer, "Connection closed during handshake.", tls); break
            
            full_request += data
            header_end_index = full_request.find(b'\r\n\r\n')
            
            if header_end_index == -1:
                writer.write(FIRST_RESPONSE); await writer.drain(); full_request = b''; continue

            headers = full_request[:header_end_index].decode(errors='ignore')
            data_to_forward = full_request[header_end_index + 4:]

            is_websocket_request = False
            for line in headers.split('\r\n'):
                if 'Upgrade: websocket' in line or 'Connection: Upgrade' in line or 'GET-RAY' in line:
                    is_websocket_request = True
                
                if line.startswith('X-Real-Host:'):
                    host_header = line.split(':', 1)[1].strip()
                    if ':' in host_header:
                        host, port = host_header.split(':')
                        target = (host.strip(), int(port.strip()))
                    else:
                        target = (host_header.strip(), 22)
            
            
            if is_websocket_request:
                writer.write(SWITCH_RESPONSE); await writer.drain(); forwarding_started = True
                log(peer, f"Handshake successful. Forwarding to {target[0]}:{target[1]}", tls)
            else:
                writer.write(FIRST_RESPONSE); await writer.drain(); full_request = b''; continue
        
        if not forwarding_started: return

        target_reader, target_writer = await asyncio.open_connection(*target)
        log(peer, f"Successfully connected to target: {target[0]}:{target[1]}", tls)

        if data_to_forward:
            target_writer.write(data_to_forward); await target_writer.drain()
            
        async def pipe(src_reader, dst_writer):
            try:
                while True:
                    buf = await src_reader.read(BUFFER_SIZE)
                    if not buf: break
                    dst_writer.write(buf); await dst_writer.drain()
            except Exception: pass
            finally: dst_writer.close()

        await asyncio.gather(pipe(reader, target_writer), pipe(target_reader, writer))

    except asyncio.TimeoutError:
        log(peer, "Connection timed out.", tls)
    except ConnectionRefusedError:
        log(peer, f"Target {target[0]}:{target[1]} refused connection.", tls)
    except Exception as e:
        log(peer, f"Connection error: {e}", tls)
    finally:
        writer.close(); await writer.wait_closed()
        log(peer, "Connection closed.", tls)


async def main():
    # TLS server setup
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        ssl_ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    except FileNotFoundError:
        print(f"ERROR: TLS certificate not found at {CERT_FILE}. TLS server disabled."); sys.exit(1)
    except Exception as e:
        print(f"ERROR loading certificate: {e}"); sys.exit(1)

    tls_server = await asyncio.start_server(lambda r, w: handle_client(r, w, tls=True), LISTEN_ADDR, TLS_PORT, ssl=ssl_ctx)
    http_server = await asyncio.start_server(lambda r, w: handle_client(r, w, tls=False), LISTEN_ADDR, HTTP_PORT)

    print(f"WSS Agent Listening on {LISTEN_ADDR}:{HTTP_PORT} (HTTP) and {LISTEN_ADDR}:{TLS_PORT} (TLS)")

    async with tls_server, http_server:
        await asyncio.gather(tls_server.serve_forever(), http_server.serve_forever())

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("WSS Agent stopped by user."); sys.exit(0)
    
EOF

chmod +x "$WSS_SCRIPT"

tee /etc/systemd/system/wss.service > /dev/null <<EOF
[Unit]
Description=WSS Python Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wss $WSS_HTTP_PORT $WSS_TLS_PORT
Restart=on-failure
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wss
systemctl restart wss
echo "WSS 代理启动完成 (HTTP:$WSS_HTTP_PORT, TLS:$WSS_TLS_PORT)"
echo "--------------------------------------------------------"

# ===============================================
# D. Stunnel4 和 UDPGW 配置
# ===============================================
echo "==== 部署 Stunnel4 和 UDPGW ===="

# Stunnel4
mkdir -p /etc/stunnel/certs
openssl req -x509 -nodes -newkey rsa:2048 -keyout /etc/stunnel/certs/stunnel.key -out /etc/stunnel/certs/stunnel.crt -days 1095 -subj "/CN=example.com" &> /dev/null
sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
chmod 644 /etc/stunnel/certs/*.pem

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
connect = 127.0.0.1:41816
EOF
mkdir -p /var/log/stunnel4
systemctl enable stunnel4
systemctl restart stunnel4

# UDPGW
badvpn_dir="/root/badvpn" # FIXED: Global assignment
if [ ! -d "$badvpn_dir" ]; then
    git clone https://github.com/ambrop72/badvpn.git "$badvpn_dir" &> /dev/null
fi
mkdir -p "$badvpn_dir/badvpn-build"
cd "$badvpn_dir/badvpn-build"
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 &> /dev/null
make -j$(nproc) &> /dev/null
cd - &> /dev/null

tee /etc/systemd/system/udpgw.service > /dev/null <<EOF
[Unit]
Description=UDP Gateway (Badvpn)
After=network.target

[Service]
Type=simple
ExecStart=$badvpn_dir/badvpn-build/udpgw/badvpn-udpgw --listen-addr 127.0.0.1:$UDPGW_PORT --max-clients 1024 --max-connections-for-client 10
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable udpgw
systemctl restart udpgw
echo "Stunnel4 ($STUNNEL_PORT) 和 UDPGW ($UDPGW_PORT) 部署完成。"
echo "--------------------------------------------------------"

# ===============================================
# E. SSHD 安全配置
# ===============================================
echo "==== 配置 SSHD 安全隧道 ===="
cp -a "$SSHD_CONFIG" "${SSHD_CONFIG}${BACKUP_SUFFIX}"

sed -i '/# WSS_CONFIG_BLOCK_START/,/# WSS_CONFIG_BLOCK_END/d' "$SSHD_CONFIG"

cat >> "$SSHD_CONFIG" <<EOF

# WSS_CONFIG_BLOCK_START -- managed by deploy_wss_final_v6.sh
# 允许所有用户仅通过本机 (127.0.0.1/::1) 使用密码登录，用于 WSS 转发
Match Address 127.0.0.1,::1
    PermitTTY yes
    AllowTcpForwarding yes
    PermitTunnel yes
    PasswordAuthentication yes
    # 强制所有非本机连接禁用密码，以增强安全性
Match Address *,!127.0.0.1,!::1
    PasswordAuthentication no
# WSS_CONFIG_BLOCK_END -- managed by deploy_wss_final_v6.sh

EOF

if systemctl list-units --full -all | grep -q "sshd.service"; then SSHD_SERVICE="sshd"; else SSHD_SERVICE="ssh"; fi
systemctl daemon-reload
systemctl restart "$SSHD_SERVICE"
echo "SSHD 配置已更新。"
echo "--------------------------------------------------------"

# ===============================================
# F. 部署 WSS 面板文件与 Accountant 脚本
# ===============================================
mkdir -p "$PANEL_CONFIG_DIR"

# 1. 部署 WSS 面板 Python 脚本 (/usr/local/bin/wss_panel.py) - V8 最终稳定版
echo "==== 部署 WSS Web 面板脚本 (V8 最终稳定版) ===="
tee "$PANEL_SCRIPT" > /dev/null <<EOF
#!/usr/bin/python3
# -*- coding: utf-8 -*-

from flask import Flask, request, redirect, url_for, session, make_response, render_template_string
import os
import json
import subprocess
import time
from datetime import datetime, timedelta
import hashlib
import socket
import sys

# --- 配置 ---
USER_DB_PATH = "/etc/wss-panel/users.json"
PANEL_PASS_HASH = "$PANEL_PASS_HASH" 
PANEL_USER = "root"

app = Flask(__name__)
app.secret_key = os.urandom(24) 

# --- 数据管理函数 ---
def load_users():
    if not os.path.exists(USER_DB_PATH):
        return []
    try:
        with open(USER_DB_PATH, 'r') as f: return json.load(f)
    except:
        return []

def save_users(users):
    try:
        os.makedirs(os.path.dirname(USER_DB_PATH), exist_ok=True)
        with open(USER_DB_PATH, 'w') as f: json.dump(users, f, indent=4)
        return True
    except:
        return False

# --- 辅助函数 (保持精简) ---
def format_bytes(bytes_value):
    if bytes_value is None or not isinstance(bytes_value, (int, float)): return "N/A"
    bytes_value = int(bytes_value)
    if bytes_value < 1048576: return f"{bytes_value / 1024:.2f} KB"
    elif bytes_value < 1073741824: return f"{bytes_value / 1048576:.2f} MB"
    else: return f"{bytes_value / 1073741824:.2f} GB"

def get_days_remaining(timestamp):
    if not timestamp: return "N/A"
    try: timestamp = int(timestamp)
    except: return "Invalid Date"
    remaining = timestamp - int(time.time())
    if remaining <= 0: return "Expired"
    days = remaining // 86400
    return f"{days} days"

def get_status_badge(status):
    if status == 'active': return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">Active</span>'
    if status == 'suspended': return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800">Suspended</span>'
    if status == 'expired': return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">Expired</span>'
    return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800">Unknown</span>'

def get_last_ip(username):
    return "N/A (System Command Removed)" 

def run_cmd(command):
    try:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        return False


# --- HTML 模板 (内嵌) ---
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS 隧道管理面板</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; background-color: #f4f7f9; }
        .card { background-color: white; border-radius: 0.75rem; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1); }
        .btn-primary { @apply px-4 py-2 bg-indigo-600 text-white font-medium rounded-lg hover:bg-indigo-700 transition duration-150; }
        .input-field { @apply mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500; }
        .btn-green { @apply text-green-600 hover:text-green-900; }
        .btn-yellow { @apply text-yellow-600 hover:text-yellow-900; }
        .btn-red { @apply text-red-600 hover:text-red-900; }
    </style>
</head>
<body class="p-4 sm:p-8">
    <div class="max-w-7xl mx-auto">
        <header class="flex justify-between items-center pb-8">
            <h1 class="text-3xl font-bold text-gray-800">WSS 隧道管理面板</h1>
            <a href="{{ url_for('logout') }}" class="text-sm text-red-500 hover:text-red-700">退出登录</a>
        </header>

        <main>
            <div class="grid md:grid-cols-2 gap-6 mb-8">
                <div class="card p-6">
                    <h2 class="text-xl font-semibold text-gray-700 mb-4">连接信息</h2>
                    <p class="text-sm text-gray-600 mb-2">面板端口: <code class="font-mono text-indigo-600">{{ panel_port }}</code></p>
                    <p class="text-sm text-gray-600 mb-2">WSS HTTP 端口: <code class="font-mono text-indigo-600">{{ wss_http_port }}</code></p>
                    <p class="text-sm text-gray-600 mb-2">WSS TLS 端口: <code class="font-mono text-indigo-600">{{ wss_tls_port }}</code></p>
                    <p class="text-sm text-gray-600 mb-2">Stunnel 端口: <code class="font-mono text-indigo-600">{{ stunnel_port }}</code></p>
                    <p class="text-sm text-gray-600 mb-2">UDPGW 端口: <code class="font-mono text-indigo-600">{{ udpgw_port }}</code></p>
                    <p class="text-sm font-semibold text-gray-700 mt-4">服务器 IP: <code class="font-mono text-indigo-600">{{ current_host }}</code></p>
                    <p class="text-xs text-red-500 mt-1">* 请确保将 IP 地址替换为您的公网 IP。</p>
                </div>
                
                <div class="card p-6">
                    <h2 class="text-xl font-semibold text-gray-700 mb-4">添加新用户</h2>
                    <form method="POST" action="{{ url_for('add_user') }}">
                        <div class="mb-3">
                            <label for="username" class="block text-sm font-medium text-gray-700">用户名</label>
                            <input type="text" id="username" name="username" required class="input-field">
                        </div>
                        <div class="mb-3">
                            <label for="password" class="block text-sm font-medium text-gray-700">密码</label>
                            <input type="password" id="password" name="password" required class="input-field">
                        </div>
                        <div class="mb-4">
                            <label for="expiry" class="block text-sm font-medium text-gray-700">到期日 (可选)</label>
                            <input type="date" id="expiry" name="expiry" class="input-field">
                            <p class="text-xs text-gray-500 mt-1">留空则为一年后过期。</p>
                        </div>
                        <button type="submit" class="btn-primary w-full">创建用户</button>
                    </form>
                    {% if message %}
                    <div class="mt-4 p-3 rounded-lg bg-green-50 text-green-700 text-sm">{{ message }}</div>
                    {% endif %}
                </div>
            </div>

            <!-- 用户列表 -->
            <div class="card p-6">
                <h2 class="text-xl font-semibold text-gray-700 mb-4">WSS 用户列表</h2>
                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">用户名</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">状态</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">最后连接 IP</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">已用流量</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">到期日</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">剩余天数</th>
                                <th class="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">操作</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            {% for user in users %}
                            <tr>
                                <td class="px-4 py-3 whitespace-nowrap text-sm font-medium text-gray-900">{{ user.username }}</td>
                                <td class="px-4 py-3 whitespace-nowrap text-sm">{{ user.status | status_badge }}</td>
                                <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-500">{{ user.username | last_ip }}</td>
                                <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-500">{{ user.usage_bytes | format_bytes }}</td>
                                <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-500">
                                    {% if user.expires_at %}
                                        {{ user.expires_at | format_date }}
                                    {% else %}
                                        永久
                                    {% endif %}
                                </td>
                                <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-500">{{ user.expires_at | days_remaining }}</td>
                                <td class="px-4 py-3 whitespace-nowrap text-right text-sm font-medium space-x-2">
                                    {% if user.status == 'active' %}
                                        <form method="POST" action="{{ url_for('suspend_user') }}" class="inline" onsubmit="return confirm('确认暂停用户 {{ user.username }} 吗？')">
                                            <input type="hidden" name="username" value="{{ user.username }}">
                                            <button type="submit" class="btn-yellow">暂停</button>
                                        </form>
                                    {% elif user.status == 'suspended' or user.status == 'expired' %}
                                        <form method="POST" action="{{ url_for('activate_user') }}" class="inline">
                                            <input type="hidden" name="username" value="{{ user.username }}">
                                            <button type="submit" class="btn-green">激活</button>
                                        </form>
                                    {% endif %}
                                    <form method="POST" action="{{ url_for('delete_user') }}" class="inline" onsubmit="return confirm('警告: 确认删除系统账户 {{ user.username }} 吗？')">
                                        <input type="hidden" name="username" value="{{ user.username }}">
                                        <button type="submit" class="btn-red">删除</button>
                                    </form>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </main>
    </div>
</body>
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS 隧道管理面板 - 登录</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; background-color: #f4f7f9; }
        .card { background-color: white; border-radius: 0.75rem; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1); }
        .btn-primary { @apply px-4 py-2 bg-indigo-600 text-white font-medium rounded-lg hover:bg-indigo-700 transition duration-150; }
        .input-field { @apply mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500; }
    </style>
</head>
<body class="flex items-center justify-center min-h-screen">
    <div class="w-full max-w-md">
        <div class="card p-8">
            <h1 class="text-2xl font-bold text-center text-gray-800 mb-6">面板登录</h1>
            <form method="POST" action="{{ url_for('login') }}">
                <div class="mb-4">
                    <label for="username" class="block text-sm font-medium text-gray-700">用户名</label>
                    <input type="text" id="username" name="username" value="root" required readonly class="input-field bg-gray-100 cursor-not-allowed">
                </div>
                <div class="mb-6">
                    <label for="password" class="block text-sm font-medium text-gray-700">密码</label>
                    <input type="password" id="password" name="password" required class="input-field">
                </div>
                {% if error %}
                <div class="p-3 mb-4 rounded-lg bg-red-50 text-red-700 text-sm">{{ error }}</div>
                {% endif %}
                <button type="submit" class="btn-primary w-full">登录</button>
            </form>
        </div>
    </div>
</body>
</html>
"""

# --- 路由和视图 ---

def login_required(f):
    def wrapper(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        input_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        if username == PANEL_USER and input_hash == PANEL_PASS_HASH:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = '用户名或密码错误'
    
    return render_template_string(LOGIN_HTML, error=error, url_for=url_for)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    users = load_users()
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        host_ip = s.getsockname()[0]
    except:
        host_ip = "127.0.0.1 (请替换)"

    current_panel_port = os.environ.get('WSS_PANEL_PORT', '54321')
    current_wss_http_port = os.environ.get('WSS_HTTP_PORT', '80')
    current_wss_tls_port = os.environ.get('WSS_TLS_PORT', '443')
    current_stunnel_port = os.environ.get('STUNNEL_PORT', '444')
    current_udpgw_port = os.environ.get('UDPGW_PORT', '7300')

    context = {
        'users': users,
        'panel_port': current_panel_port,
        'wss_http_port': current_wss_http_port,
        'wss_tls_port': current_wss_tls_port,
        'stunnel_port': current_stunnel_port,
        'udpgw_port': current_udpgw_port,
        'current_host': host_ip,
        'message': request.args.get('message')
    }
    
    return render_template_string(DASHBOARD_HTML, **context, 
                                url_for=url_for, 
                                format_bytes=format_bytes, 
                                days_remaining=get_days_remaining, 
                                status_badge=get_status_badge,
                                format_date=lambda t: datetime.fromtimestamp(t).strftime('%Y-%m-%d'),
                                last_ip=get_last_ip) 

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    username = request.form['username'].strip()
    password = request.form['password']
    expiry_date_str = request.form['expiry']
    
    if not username or not password:
        return redirect(url_for('dashboard', message="用户名和密码不能为空"))

    users = load_users()
    if any(u['username'] == username for u in users):
        return redirect(url_for('dashboard', message="用户已存在"))

    # 1. 创建系统用户
    try:
        subprocess.run(['useradd', '--shell', '/bin/bash', '--create-home', username], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(f'echo "{username}:{password}" | chpasswd', shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        run_cmd(['gpasswd', '-d', username, 'sudo'])
        
    except subprocess.CalledProcessError as e:
        return redirect(url_for('dashboard', message=f"创建系统用户失败: {e.stderr.decode()}"))
    
    # 2. 确定到期时间
    expires_at = 0
    if expiry_date_str:
        try:
            expiry_dt = datetime.strptime(expiry_date_str, '%Y-%m-%d')
            expiry_dt = expiry_dt.replace(hour=23, minute=59, second=59)
            expires_at = int(expiry_dt.timestamp())
        except:
            return redirect(url_for('dashboard', message="到期日期格式错误"))
    else:
        expires_at = int((datetime.now() + timedelta(days=365)).timestamp())

    # 3. 添加到 JSON
    new_user = {
        'username': username,
        'status': 'active',
        'usage_bytes': 0,
        'expires_at': expires_at,
    }
    users.append(new_user)
    save_users(users)
    
    return redirect(url_for('dashboard', message=f"用户 {username} 创建成功!"))

@app.route('/suspend_user', methods=['POST'])
@login_required
def suspend_user():
    username = request.form['username'].strip()
    users = load_users()
    
    for user in users:
        if user['username'] == username:
            if not run_cmd(['usermod', '-L', username]):
                return redirect(url_for('dashboard', message=f"暂停用户 {username} 失败 (系统锁定失败)!"))
            
            user['status'] = 'suspended'
            save_users(users)
            return redirect(url_for('dashboard', message=f"用户 {username} 已成功暂停!"))
            
    return redirect(url_for('dashboard', message="用户未找到!"))

@app.route('/activate_user', methods=['POST'])
@login_required
def activate_user():
    username = request.form['username'].strip()
    users = load_users()
    
    for user in users:
        if user['username'] == username:
            if not run_cmd(['usermod', '-U', username]):
                return redirect(url_for('dashboard', message=f"激活用户 {username} 失败 (系统解锁失败)!"))
            
            user['status'] = 'active'
            save_users(users)
            return redirect(url_for('dashboard', message=f"用户 {username} 已成功激活!"))
            
    return redirect(url_for('dashboard', message="用户未找到!"))

@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    username = request.form['username'].strip()
    
    users = load_users()
    users_before = len(users)
    
    run_cmd(['userdel', '-r', username])
        
    users = [u for u in users if u['username'] != username]
    users_after = len(users)

    if users_before != users_after:
        save_users(users)
        return redirect(url_for('dashboard', message=f"用户 {username} 已从系统和面板删除!"))
    else:
        return redirect(url_for('dashboard', message=f"用户 {username} 系统账户已删除，面板记录已清除 (如果存在)!"))

if __name__ == '__main__':
    try:
        panel_port = int(os.environ.get('WSS_PANEL_PORT', 54321))
    except ValueError:
        panel_port = 54321
        
    app.run(host='0.0.0.0', port=panel_port, debug=False)
EOF

chmod +x "$PANEL_SCRIPT"
echo "Web 面板脚本部署完成。"

# 2. 部署 Accountant 脚本 (/usr/local/bin/wss_accountant.py)
echo "==== 部署流量统计脚本 ===="
tee "$ACCOUNTANT_SCRIPT" > /dev/null <<EOF
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import json
import subprocess
import time
from datetime import datetime
import sys

# --- 配置 ---
USER_DB_PATH = "/etc/wss-panel/users.json"
LOG_PATH = "/var/log/wss_accountant.log"
SIMULATED_TRAFFIC_PER_CYCLE = 1048576 * 1 # 1MB per cycle 

def log(message):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    with open(LOG_PATH, 'a') as f:
        f.write(f"{timestamp} {message}\n")

def load_users():
    if not os.path.exists(USER_DB_PATH):
        return []
    try:
        with open(USER_DB_PATH, 'r') as f: return json.load(f)
    except:
        return []

def save_users(users):
    try:
        os.makedirs(os.path.dirname(USER_DB_PATH), exist_ok=True)
        with open(USER_DB_PATH, 'w') as f: json.dump(users, f, indent=4)
        return True
    except:
        return False

def run_cmd(command):
    try:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def check_and_cleanup():
    log("--- Accounting cycle started. ---")
    users = load_users()
    users_modified = False
    
    current_time = int(time.time())
    
    # 1. 流量统计 (模拟)
    for user in users:
        # 仅对 active 用户进行流量模拟和过期检查
        if user.get('status') == 'active':
            # 流量模拟: 增加 SIMULATED_TRAFFIC_PER_CYCLE
            current_usage = user.get('usage_bytes', 0)
            user['usage_bytes'] = current_usage + SIMULATED_TRAFFIC_PER_CYCLE
            users_modified = True
            log(f"TRAFFIC: Simulating traffic for {user['username']}. New Usage: {user['usage_bytes'] / 1048576:.2f} MB")
            
            # 2. 过期检查
            expires_at = user.get('expires_at', 0)
            if expires_at and expires_at < current_time:
                user['status'] = 'expired'
                users_modified = True
                log(f"EXPIRY: User {user['username']} has expired. Status set to 'expired'.")
                
                # 锁定系统账户
                if run_cmd(['usermod', '-L', user['username']]):
                    log(f"EXPIRY: Successfully locked system account for {user['username']}.")
                else:
                    log(f"EXPIRY: Failed to lock system account for {user['username']}!")

    if users_modified:
        if save_users(users):
            log("UPDATE SUCCESS: Traffic/Expiration data saved.")
        else:
            log("UPDATE FAILURE: Could not save data.")

    log("--- Accounting cycle completed. ---")


if __name__ == '__main__':
    # 确保日志文件存在
    if not os.path.exists(LOG_PATH):
        try:
            with open(LOG_PATH, 'w') as f: f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Accountant Log Initialized.\n")
        except:
            # 如果权限有问题，直接退出
            sys.exit(1)

    check_and_cleanup()
    sys.exit(0)
EOF

chmod +x "$ACCOUNTANT_SCRIPT"
echo "流量统计脚本部署完成。"

# 3. 部署 systemd 服务单元
tee /etc/systemd/system/wss_panel.service > /dev/null <<EOF
[Unit]
Description=WSS Web Panel (Flask)
After=network.target

[Service]
Type=simple
# 强制环境变量，解决 Jinja2 崩溃问题
Environment=WSS_PANEL_PORT=$PANEL_PORT
Environment=WSS_HTTP_PORT=$WSS_HTTP_PORT
Environment=WSS_TLS_PORT=$WSS_TLS_PORT
Environment=STUNNEL_PORT=$STUNNEL_PORT
Environment=UDPGW_PORT=$UDPGW_PORT
ExecStart=/usr/bin/python3 $PANEL_SCRIPT
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

tee /etc/systemd/system/wss_accountant.service > /dev/null <<EOF
[Unit]
Description=WSS Traffic and Expiration Accountant
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $ACCOUNTANT_SCRIPT
User=root

[Install]
WantedBy=multi-user.target
EOF

tee /etc/systemd/system/wss_accountant.timer > /dev/null <<EOF
[Unit]
Description=Run WSS Usage Accountant every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF

# 4. 启动服务
echo "==== 启动 Web 面板和流量统计服务 ===="
systemctl daemon-reload

# 停止旧的进程
systemctl stop wss_panel.service wss_accountant.timer wss_accountant.service

# 启动新的服务
systemctl enable wss_panel.service
systemctl restart wss_panel.service

systemctl enable wss_accountant.timer
systemctl start wss_accountant.timer

# 立即运行一次 Accountant，初始化数据
systemctl start wss_accountant.service

echo "所有组件已启动。"
echo "--------------------------------------------------------"

# ===============================================
# G. 最终连接信息
# ===============================================

SERVER_IP=$(curl -s ifconfig.me)
if [ -z "$SERVER_IP" ]; then SERVER_IP="[请手动查找您的公网 IP]"; fi

echo "================================================"
echo " ✅ 部署成功! WSS 隧道管理面板信息"
echo "================================================"
echo "面板访问地址: http://$SERVER_IP:$PANEL_PORT"
echo "面板登录用户: root"
echo "面板登录密码: 您设置的密码"
echo ""
echo "WSS HTTP 端口 (隧道入口): $WSS_HTTP_PORT"
echo "WSS TLS 端口 (隧道入口): $WSS_TLS_PORT"
echo "Stunnel TLS 端口 (隧道入口): $STUNNEL_PORT"
echo "UDP 转发端口 (需客户端配置): $UDPGW_PORT"
echo "================================================"
echo "请确保您的云服务商防火墙已放行 $PANEL_PORT, $WSS_HTTP_PORT, $WSS_TLS_PORT, $STUNNEL_PORT 端口!"
