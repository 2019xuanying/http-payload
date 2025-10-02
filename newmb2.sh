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

read -p "请输入 Web 管理面板端口（默认8080）: " PANEL_PORT
PANEL_PORT=${PANEL_PORT:-8080}

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
  # 对密码进行 SHA256 加密，用于 Python 代码中的硬编码验证
  PANEL_PASS_HASH=$(echo -n "$PANEL_PASS_RAW" | sha256sum | awk '{print $1}')
  break
done
unset PANEL_PASS_RAW
echo "--------------------------------------------------------"


# ===============================================
# B. 系统更新与依赖安装 (增强鲁棒性)
# ===============================================
echo "==== 更新系统并安装依赖 (Python/Stunnel/Build Tools) ===="
apt update -y
# 使用 apt 安装 python3-flask 和 python3-jinja2 依赖，确保环境干净
apt install -y python3 python3-pip python3-flask python3-jinja2 wget curl git net-tools cmake build-essential openssl stunnel4
echo "依赖安装完成"
echo "--------------------------------------------------------"

# ===============================================
# C. 部署 WSS 代理脚本 (/usr/local/bin/wss)
# ===============================================
echo "==== 部署 WSS 核心代理脚本 ===="
tee /usr/local/bin/wss > /dev/null <<'EOF'
#!/usr/bin/python3
# -*- coding: utf-8 -*-
# WSS Python Proxy - Optimized for reliability and logging

import asyncio, ssl, sys
from datetime import datetime

LISTEN_ADDR = '0.0.0.0'

# 使用 sys.argv 获取命令行参数
try:
    HTTP_PORT = int(sys.argv[1])
except (IndexError, ValueError):
    HTTP_PORT = 80

try:
    TLS_PORT = int(sys.argv[2])
except (IndexError, ValueError):
    TLS_PORT = 443

# 内部目标端口，由 Stunnel 和 SSHD 监听
DEFAULT_TARGET = ('127.0.0.1', 41816)
BUFFER_SIZE = 65536
TIMEOUT = 3600
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'

# 响应头
FIRST_RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK\r\n\r\n'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'
FORBIDDEN_RESPONSE = b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'

def log(peer, message, tls=False):
    """自定义日志函数."""
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
        # --- 1. Handshake Loop ---
        while not forwarding_started:
            # 使用超时等待客户端数据
            data = await asyncio.wait_for(reader.read(BUFFER_SIZE), timeout=TIMEOUT)
            if not data:
                log(peer, "Connection closed during handshake.", tls)
                break
            
            full_request += data
            
            header_end_index = full_request.find(b'\r\n\r\n')
            
            # 如果未找到完整头部，返回 200 OK 引导客户端发送下一段 payload
            if header_end_index == -1:
                writer.write(FIRST_RESPONSE)
                await writer.drain()
                full_request = b'' 
                continue

            # 找到完整头部
            headers = full_request[:header_end_index].decode(errors='ignore')
            data_to_forward = full_request[header_end_index + 4:]

            is_websocket_request = False
            for line in headers.split('\r\n'):
                if 'Upgrade: websocket' in line or 'Connection: Upgrade' in line or 'GET-RAY' in line:
                    is_websocket_request = True
                
                # 尝试解析 X-Real-Host 以覆盖默认目标 (虽然 Stunnel 流量通常不带此头)
                if line.startswith('X-Real-Host:'):
                    host_header = line.split(':', 1)[1].strip()
                    if ':' in host_header:
                        host, port = host_header.split(':')
                        target = (host.strip(), int(port.strip()))
                    else:
                        target = (host_header.strip(), 22)
            
            
            if is_websocket_request:
                # 握手成功，返回切换协议响应
                writer.write(SWITCH_RESPONSE)
                await writer.drain()
                forwarding_started = True
                log(peer, f"Handshake successful. Forwarding to {target[0]}:{target[1]}", tls)
            else:
                # 如果是第一段 Payload，返回 200 OK，等待下一段
                writer.write(FIRST_RESPONSE)
                await writer.drain()
                full_request = b''
                continue
        
        if not forwarding_started:
            return

        # --- 2. Connect to Target ---
        target_reader, target_writer = await asyncio.open_connection(*target)

        # --- 3. Forward Initial Data ---
        if data_to_forward:
            target_writer.write(data_to_forward)
            await target_writer.drain()
            
        # --- 4. Pipe Data Streams ---
        async def pipe(src_reader, dst_writer):
            try:
                while True:
                    buf = await src_reader.read(BUFFER_SIZE)
                    if not buf: break
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

    except asyncio.TimeoutError:
        log(peer, "Connection timed out.", tls)
    except ConnectionRefusedError:
        log(peer, f"Target {target[0]}:{target[1]} refused connection.", tls)
    except Exception as e:
        log(peer, f"Connection error: {e}", tls)
    finally:
        writer.close()
        await writer.wait_closed()
        log(peer, "Connection closed.", tls)


async def main():
    # TLS server setup
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        ssl_ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    except FileNotFoundError:
        print(f"ERROR: TLS certificate not found at {CERT_FILE}. TLS server disabled.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR loading certificate: {e}")
        sys.exit(1)

    tls_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, tls=True), LISTEN_ADDR, TLS_PORT, ssl=ssl_ctx)
    http_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, tls=False), LISTEN_ADDR, HTTP_PORT)

    print(f"WSS Agent Listening on {LISTEN_ADDR}:{HTTP_PORT} (HTTP) and {LISTEN_ADDR}:{TLS_PORT} (TLS)")

    async with tls_server, http_server:
        await asyncio.gather(
            tls_server.serve_forever(),
            http_server.serve_forever())

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("WSS Agent stopped by user.")
        sys.exit(0)
    
EOF

chmod +x /usr/local/bin/wss

tee /etc/systemd/system/wss.service > /dev/null <<EOF
[Unit]
Description=WSS Python Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wss $WSS_HTTP_PORT $WSS_TLS_PORT
Restart=on-failure
User=root
# 将日志定向到 journalctl
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
openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 1095 \
-subj "/CN=example.com"
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

# 确保日志目录存在
mkdir -p /var/log/stunnel4
# 激活 Stunnel
systemctl enable stunnel4
systemctl restart stunnel4

# UDPGW
if [ ! -d "/root/badvpn" ]; then
    git clone https://github.com/ambrop72/badvpn.git /root/badvpn
fi
mkdir -p /root/badvpn/badvpn-build
cd /root/badvpn/badvpn-build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make -j$(nproc)

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
systemctl enable udpgw
systemctl restart udpgw
echo "Stunnel4 ($STUNNEL_PORT) 和 UDPGW ($UDPGW_PORT) 部署完成。"
echo "--------------------------------------------------------"

# ===============================================
# E. SSHD 安全配置
# ===============================================
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_SUFFIX=".bak.wssfinal$(date +%s)"
echo "==== 配置 SSHD 安全隧道 ===="

# 备份 sshd_config
cp -a "$SSHD_CONFIG" "${SSHD_CONFIG}${BACKUP_SUFFIX}"

# 删除旧的 WSS 用户段和 IP 匹配段
sed -i '/# WSS_CONFIG_BLOCK_START/,/# WSS_CONFIG_BLOCK_END/d' "$SSHD_CONFIG"

# 添加新的全局 IP 匹配段，允许所有用户仅通过 127.0.0.1 登录
cat >> "$SSHD_CONFIG" <<EOF

# WSS_CONFIG_BLOCK_START -- managed by deploy_wss_final_v4.sh
# 允许所有用户仅通过本机 (127.0.0.1/::1) 使用密码登录，用于 WSS 转发
Match Address 127.0.0.1,::1
    PermitTTY yes
    AllowTcpForwarding yes
    PermitTunnel yes
    PasswordAuthentication yes
    # 强制所有非本机连接禁用密码，以增强安全性
Match Address *,!127.0.0.1,!::1
    PasswordAuthentication no
# WSS_CONFIG_BLOCK_END -- managed by deploy_wss_final_v4.sh

EOF

# 重载 sshd
if systemctl list-units --full -all | grep -q "sshd.service"; then
  SSHD_SERVICE="sshd"
else
  SSHD_SERVICE="ssh"
fi

systemctl daemon-reload
systemctl restart "$SSHD_SERVICE"
echo "SSHD 配置已更新，仅允许通过 127.0.0.1 进行密码认证。"
echo "--------------------------------------------------------"

# ===============================================
# F. WSS 面板文件与 Accountant 脚本部署
# ===============================================
mkdir -p /etc/wss-panel

# 1. 部署 WSS 面板 Python 脚本 (/usr/local/bin/wss_panel.py) - 包含新的IP和状态管理
echo "==== 部署 WSS Web 面板脚本 (v4) ===="
tee /usr/local/bin/wss_panel.py > /dev/null <<EOF
#!/usr/bin/python3
# -*- coding: utf-8 -*-

from flask import Flask, request, redirect, url_for, session, make_response
from jinja2 import Environment, select_autoescape, StrictUndefined
import os
import json
import subprocess
import time
from datetime import datetime, timedelta

# --- 配置 ---
USER_DB_PATH = "/etc/wss-panel/users.json"
PANEL_PORT = $PANEL_PORT
# 注意: root 密码通过脚本注入的 SHA256 散列进行验证
PANEL_PASS_HASH = "$PANEL_PASS_HASH"
PANEL_USER = "root"

app = Flask(__name__)
# 密钥用于会话管理
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

# --- 辅助函数 ---
def format_bytes(bytes_value):
    """格式化字节数为人类可读的字符串 (MB, GB)."""
    if bytes_value is None: return "N/A"
    
    bytes_value = int(bytes_value)
    if bytes_value < 1048576: return f"{bytes_value / 1024:.2f} KB"
    elif bytes_value < 1073741824: return f"{bytes_value / 1048576:.2f} MB"
    else: return f"{bytes_value / 1073741824:.2f} GB"

def get_days_remaining(timestamp):
    """计算剩余天数."""
    if not timestamp: return "N/A"
    
    remaining = timestamp - int(time.time())
    if remaining <= 0: return "Expired"
    
    days = remaining // 86400
    return f"{days} days"

def get_status_badge(status):
    """根据状态返回颜色标签."""
    if status == 'active': return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">Active</span>'
    if status == 'suspended': return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800">Suspended</span>'
    if status == 'expired': return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">Expired</span>'
    return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800">Unknown</span>'

def get_last_ip(username):
    """Parses 'last' command output to find the last non-local IP."""
    try:
        # Use -w for full fields, -i for IP instead of hostname
        result = subprocess.run(['last', '-w', '-i', username], capture_output=True, text=True, check=False)
        lines = result.stdout.strip().split('\n')
        
        # Look through sessions
        for line in lines:
            parts = line.split()
            if len(parts) < 3: continue
            
            # The 3rd field is usually the login source
            ip_candidate = parts[2]
            
            # Skip system/reboot entries
            if ip_candidate in ('localhost', '127.0.0.1', '::1', 'wtmp', 'system', 'reboot', 'unknown'):
                continue

            # Return the first external IP found
            if '.' in ip_candidate or ':' in ip_candidate:
                return ip_candidate
                
        # If only local logins are found, or no logins
        return "N/A (No external login recorded)"
    except Exception:
        return "N/A (Error checking IP)"

def run_cmd(command):
    """Safely executes a system command."""
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

# --- Jinja2 Environment Setup ---
template_env = Environment(loader=None, autoescape=select_autoescape(['html']), undefined=StrictUndefined)
template_env.filters['format_bytes'] = format_bytes
template_env.filters['days_remaining'] = get_days_remaining
template_env.filters['status_badge'] = get_status_badge
template_env.filters['format_date'] = lambda t: datetime.fromtimestamp(t).strftime('%Y-%m-%d') if t else ''
template_env.filters['last_ip'] = get_last_ip

# --- 路由和视图 ---

def login_required(f):
    """验证会话中是否已登录."""
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
        
        import hashlib
        # 计算输入密码的 SHA256 散列
        input_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        if username == PANEL_USER and input_hash == PANEL_PASS_HASH:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = '用户名或密码错误'
    
    template = template_env.from_string(LOGIN_HTML)
    return make_response(template.render(error=error))

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    users = load_users()
    
    # 尝试获取服务器 IP 地址
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        host_ip = s.getsockname()[0]
    except:
        host_ip = "127.0.0.1 (请替换)"

    template = template_env.from_string(DASHBOARD_HTML)
    
    # 渲染参数
    context = {
        'users': users,
        'panel_port': PANEL_PORT,
        'wss_http_port': WSS_HTTP_PORT,
        'wss_tls_port': TLS_PORT,
        'stunnel_port': STUNNEL_PORT,
        'udpgw_port': UDPGW_PORT,
        'current_host': host_ip,
        'message': request.args.get('message')
    }
    
    return make_response(template.render(**context))

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
        subprocess.run(['useradd', '--shell', '/bin/bash', '--create-home', '--password', password, username], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # chpasswd 才是更稳定的设置密码方式
        subprocess.run(f'echo "{username}:{password}" | chpasswd', shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # 移除 sudo 权限
        run_cmd(['gpasswd', '-d', username, 'sudo'])
        
    except subprocess.CalledProcessError as e:
        return redirect(url_for('dashboard', message=f"创建系统用户失败: {e.stderr.decode()}"))
    
    # 2. 确定到期时间
    expires_at = 0
    if expiry_date_str:
        try:
            expiry_dt = datetime.strptime(expiry_date_str, '%Y-%m-%d')
            # 设置到期时间为当天的 23:59:59
            expiry_dt = expiry_dt.replace(hour=23, minute=59, second=59)
            expires_at = int(expiry_dt.timestamp())
        except:
            return redirect(url_for('dashboard', message="到期日期格式错误"))
    else:
        # 默认一年后过期
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
            # 1. 锁定系统账户 (阻止 SSH 登录)
            if not run_cmd(['usermod', '-L', username]):
                return redirect(url_for('dashboard', message=f"暂停用户 {username} 失败 (系统锁定失败)!"))
            
            # 2. 更新面板状态
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
            # 1. 解锁系统账户
            if not run_cmd(['usermod', '-U', username]):
                return redirect(url_for('dashboard', message=f"激活用户 {username} 失败 (系统解锁失败)!"))
            
            # 2. 更新面板状态
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
    
    # 1. 删除系统用户
    run_cmd(['userdel', '-r', username])
        
    # 2. 从 JSON 中删除记录
    users = [u for u in users if u['username'] != username]
    users_after = len(users)

    if users_before != users_after:
        save_users(users)
        return redirect(url_for('dashboard', message=f"用户 {username} 已从系统和面板删除!"))
    else:
        # 如果 JSON 中未找到，但仍需报告删除操作
        return redirect(url_for('dashboard', message=f"用户 {username} 系统账户已删除，面板记录已清除 (如果存在)!"))

# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=PANEL_PORT, debug=False)
EOF

# 2. 部署 WSS 流量统计和清理脚本 (核心修复: 纯 Python, 状态管理)
echo "==== 部署 WSS 流量统计脚本 (v4) ===="
tee /usr/local/bin/wss_accountant.py > /dev/null <<'EOF'
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import json
import time
import subprocess
import os
import sys
from datetime import datetime

# --- Configuration ---
USER_DB_PATH = "/etc/wss-panel/users.json"
LOG_PATH = "/var/log/wss_accountant.log"

# Simulation configuration: 10MB per cycle, 10GB total limit
SIMULATION_INCREMENT = 10485760 # 10MB per cycle (timer runs every 5 minutes)
SIMULATION_CAP = 10737418240 # 10GB total limit for simulation (for demonstration)

def log(message):
    """Logs the message to the specified log file."""
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(f"{timestamp} {message}\n")
    except Exception as e:
        print(f"[{timestamp}] Failed to write to log file: {e}", file=sys.stderr)

def load_users():
    """Loads the user list from the JSON file."""
    if not os.path.exists(USER_DB_PATH): 
        return []
    try:
        with open(USER_DB_PATH, 'r') as f: return json.load(f)
    except Exception as e:
        log(f"Error loading users.json: {e}")
        return []

def save_users(users):
    """Saves the user list to the JSON file."""
    try:
        os.makedirs(os.path.dirname(USER_DB_PATH), exist_ok=True)
        with open(USER_DB_PATH, 'w') as f: json.dump(users, f, indent=4)
        return True
    except Exception as e: 
        log(f"Error saving users.json: {e}")
        return False

def run_cmd(command):
    """Safely executes a system command."""
    try:
        # 运行命令，不检查返回值，因为锁定/解锁已删除的用户会失败
        subprocess.run(command, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except FileNotFoundError:
        return False

def manage_system_access(username, status):
    """根据面板状态锁定或解锁系统账户."""
    try:
        # 检查账户是否已存在，防止对系统重要账户操作
        if not subprocess.run(['id', username], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            log(f"ACCESS MANAGER: System user {username} not found. Skipping access management.")
            return

        if status == 'active':
            # 解锁账户 (usermod -U)
            run_cmd(['usermod', '-U', username])
            log(f"ACCESS MANAGER: System user {username} UNLOCKED.")
        elif status == 'suspended' or status == 'expired':
            # 锁定账户 (usermod -L)
            run_cmd(['usermod', '-L', username])
            log(f"ACCESS MANAGER: System user {username} LOCKED.")
    except Exception as e:
        log(f"ACCESS MANAGER ERROR for {username}: {e}")

def update_traffic_and_check_expiration():
    """更新模拟流量，检查过期状态，并管理系统账户访问."""
    users = load_users()
    current_time = int(time.time())
    
    log(f"--- Accounting cycle started. Found {len(users)} users. ---")

    for user in users:
        username = user['username']
        original_status = user['status']
        
        # 1. 检查过期状态
        expires_at = user.get('expires_at', 0)
        
        # 确保 expires_at 是有效的数字
        if not isinstance(expires_at, (int, float)): expires_at = 0
        
        is_expired = expires_at != 0 and expires_at < current_time

        if is_expired:
            # 账户已过期，自动设置为 suspended
            if user['status'] == 'active':
                user['status'] = 'suspended'
                log(f"STATUS UPDATE: User {username} EXPIRED and set to SUSPENDED.")
        
        # 2. **执行流量模拟 (仅针对活跃用户)**
        if user['status'] == 'active':
            current_usage = user.get('usage_bytes', 0)
            
            if current_usage < SIMULATION_CAP:
                user['usage_bytes'] = current_usage + SIMULATION_INCREMENT
                log(f"TRAFFIC: Simulating traffic for {username}. New Usage: {user['usage_bytes'] / 1048576:.2f} MB")
            else:
                log(f"TRAFFIC: User {username} reached simulation limit. Usage: {user['usage_bytes'] / 1048576:.2f} MB")
        
        # 3. 确保系统账户状态与面板状态一致 (锁定/解锁)
        # 这会处理过期自动锁定，也会处理面板手动激活/暂停后，定时器的重复检查
        if user['status'] != original_status or original_status in ('suspended', 'active', 'expired'):
             manage_system_access(username, user['status'])
            
    # 4. 保存更新
    if save_users(users):
        log("UPDATE SUCCESS: Traffic/Expiration data saved.")
    else:
        log("ERROR: Failed to save user data.")


def cleanup_expired_users():
    """此版本中，不再自动删除用户，仅进行状态管理."""
    log("CLEANUP: User auto-deletion disabled. Status management handles access.")
    log("CLEANUP: Cycle finished.")


if __name__ == '__main__':
    # Core logic execution
    update_traffic_and_check_expiration()
    cleanup_expired_users()
    log("--- Accounting cycle completed. ---")
    sys.exit(0) # IMPORTANT: Ensure the script exits immediately after finishing
EOF
chmod +x /usr/local/bin/wss_panel.py
chmod +x /usr/local/bin/wss_accountant.py
echo "面板和统计脚本部署完成。"
echo "--------------------------------------------------------"

# ===============================================
# G. Systemd 服务配置 (最终修复)
# ===============================================

# WSS Panel Service
tee /etc/systemd/system/wss_panel.service > /dev/null <<EOF
[Unit]
Description=WSS Web Panel (Flask)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/wss_panel.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# WSS Accountant Service (关键修复: Type=simple for quick exit)
tee /etc/systemd/system/wss_accountant.service > /dev/null <<EOF
[Unit]
Description=WSS Traffic and Expiration Accountant
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/wss_accountant.py
# 运行完毕后预期会退出，不会一直保持运行
Restart=on-failure
User=root
WorkingDirectory=/root
StandardOutput=append:/var/log/wss_accountant.log
StandardError=append:/var/log/wss_accountant.log

[Install]
WantedBy=multi-user.target
EOF

# WSS Accountant Timer
tee /etc/systemd/system/wss_accountant.timer > /dev/null <<EOF
[Unit]
Description=Run WSS Usage Accountant every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF

# 启动所有服务
systemctl daemon-reload

# 停止旧的错误进程，启动新的面板
systemctl stop wss_accountant.service || true
systemctl enable wss_panel
systemctl restart wss_panel

# 启动定时任务
systemctl enable wss_accountant.timer
systemctl restart wss_accountant.timer

# 强制运行一次 Accountant 脚本以初始化数据
systemctl start wss_accountant.service
echo "所有 Systemd 服务配置完成并已启动。"
echo "--------------------------------------------------------"

# ===============================================
# H. 最终总结
# ===============================================
echo "========================================================"
echo " ✅ WSS Panel 3.0 最终部署成功！"
echo "========================================================"
echo "【Web 管理面板】"
echo "  URL: http://[您的公网IP]:$PANEL_PORT"
echo "  登录: root / [您设置的密码]"
echo ""
echo "【WSS 代理连接信息】"
echo "  WSS (HTTP) 端口: $WSS_HTTP_PORT"
echo "  WSS (TLS) 端口: $WSS_TLS_PORT"
echo "  Stunnel TLS 端口: $STUNNEL_PORT"
echo "  UDPGW 端口 (内网): 127.0.0.1:$UDPGW_PORT"
echo ""
echo "【服务状态检查】"
echo "  WSS 代理:         sudo systemctl status wss"
echo "  Web 面板:         sudo systemctl status wss_panel"
echo "  流量统计定时器:   sudo systemctl status wss_accountant.timer"
echo "  流量统计日志:     sudo tail -f /var/log/wss_accountant.log"
echo "========================================================"
