#!/usr/bin/env bash
set -euo pipefail

# ==================================
# 部署参数配置
# ==================================
WSS_USER_DEFAULT="wssuser" 
SSHD_CONFIG="/etc/ssh/sshd_config"
MANAGER_PORT_DEFAULT="54321"

# ==================================
# 提示端口和密码
# ==================================
read -p "请输入 WSS HTTP 监听端口（默认80）: " WSS_HTTP_PORT
WSS_HTTP_PORT=${WSS_HTTP_PORT:-80}

read -p "请输入 WSS TLS 监听端口（默认443）: " WSS_TLS_PORT
WSS_TLS_PORT=${WSS_TLS_PORT:-443}

read -p "请输入 Stunnel4 端口（默认444）: " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-444}

read -p "请输入 UDPGW 端口（默认7300）: " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

echo ""
echo "--- Web 管理面板设置 ---"
read -p "请输入 Web 管理面板端口（默认54321）: " MANAGER_PORT
MANAGER_PORT=${MANAGER_PORT:-$MANAGER_PORT_DEFAULT}

echo "请设置 Web 管理面板的 root 密码（输入时隐藏）:"
while true; do
  read -s -p "密码: " ADMIN_PASS_RAW && echo
  read -s -p "请再次确认密码: " ADMIN_PASS_CONFIRM && echo
  if [ -z "$ADMIN_PASS_RAW" ]; then
    echo "密码不能为空。"
    continue
  fi
  if [ "$ADMIN_PASS_RAW" != "$ADMIN_PASS_CONFIRM" ]; then
    echo "两次输入不一致，请重试。"
    continue
  fi
  break
done
# 使用 sha256sum 加密存储密码哈希
ADMIN_PASS_HASH=$(echo -n "$ADMIN_PASS_RAW" | sha256sum | awk '{print $1}')
unset ADMIN_PASS_RAW ADMIN_PASS_CONFIRM # 清理敏感变量

# ==================================
# 依赖安装
# ==================================
echo "==== 更新系统并安装依赖 ===="
sudo apt update -y
sudo apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4 jq
echo "依赖安装完成"

# ==================================
# 函数定义
# ==================================

# WSS 隧道脚本安装 (包含多段 Payload 修复)
install_wss_script() {
  echo "==== 安装 WSS 脚本 (/usr/local/bin/wss) ===="
  sudo tee /usr/local/bin/wss > /dev/null <<'EOF'
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio, ssl, sys, json, subprocess, os, time

LISTEN_ADDR = '0.0.0.0'
DEFAULT_TARGET = ('127.0.0.1', 41816) 
BUFFER_SIZE = 65536
TIMEOUT = 3600
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'
PASS = ''  # WSS 隧道密钥 (X-Pass 验证)

FIRST_RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK\r\n\r\n'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'

# 动态获取端口
try:
    HTTP_PORT = int(sys.argv[1])
except (IndexError, ValueError):
    HTTP_PORT = 80
try:
    TLS_PORT = int(sys.argv[2])
except (IndexError, ValueError):
    TLS_PORT = 443

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    peer = writer.get_extra_info('peername')
    print(f"Connection from {peer} {'(TLS)' if tls else ''}")
    forwarding_started = False
    full_request = b''

    # 流量统计初始化 (写入 JSON 文件)
    start_time = time.time()
    
    try:
        # --- 1. 握手循环 ---
        while not forwarding_started:
            data = await asyncio.wait_for(reader.read(BUFFER_SIZE), timeout=TIMEOUT)
            if not data:
                break
            
            full_request += data
            header_end_index = full_request.find(b'\r\n\r\n')
            
            if header_end_index == -1:
                # 头部不完整，继续等待或返回 200 OK
                headers_temp = full_request.decode(errors='ignore')
                if 'Upgrade: websocket' in headers_temp:
                    pass
                else:
                    writer.write(FIRST_RESPONSE)
                    await writer.drain()
                    full_request = b''
                    continue

            # 2. 头部解析
            headers = full_request[:header_end_index].decode(errors='ignore')
            data_to_forward = full_request[header_end_index + 4:]

            host_header = ''
            passwd_header = ''
            is_websocket_request = False
            
            if 'Upgrade: websocket' in headers or 'Connection: Upgrade' in headers or 'GET-RAY' in headers:
                 is_websocket_request = True
                 
            for line in headers.split('\r\n'):
                if line.startswith('X-Real-Host:'):
                    host_header = line.split(':', 1)[1].strip()
                if line.startswith('X-Pass:'):
                    passwd_header = line.split(':', 1)[1].strip()

            # 3. 密码验证
            if PASS and passwd_header != PASS:
                writer.write(b'HTTP/1.1 400 WrongPass!\r\n\r\n')
                await writer.drain()
                return

            # 4. 转发触发
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

        # 5. 解析目标 (保持对 X-Real-Host 的支持)
        if host_header:
            if ':' in host_header:
                host, port = host_header.split(':')
                target = (host.strip(), int(port.strip()))
            else:
                target = (host_header.strip(), 22)
        else:
            target = DEFAULT_TARGET

        # 6. 连接目标服务器
        target_reader, target_writer = await asyncio.open_connection(*target)

        # 7. 转发初始数据 (SSH 握手)
        if data_to_forward:
            target_writer.write(data_to_forward)
            await target_writer.drain()
        
        # 8. 转发后续数据流 (包含流量统计钩子)
        async def pipe(src_reader, dst_writer, role):
            bytes_transferred = 0
            try:
                while True:
                    buf = await src_reader.read(BUFFER_SIZE)
                    if not buf:
                        break
                    dst_writer.write(buf)
                    await dst_writer.drain()
                    bytes_transferred += len(buf)
            except Exception:
                pass
            
            # --- 简易流量统计 ---
            # 注意：这个统计是针对整个连接的，不能区分用户，仅作示例
            # 真正的用户流量统计需要更复杂的 iptables 规则和用户身份识别
            if role == 'upload':
                pass # 忽略客户端上传流量
            elif role == 'download':
                 pass # 忽略客户端下载流量
            # --- 简易流量统计 ---
            
            finally:
                dst_writer.close()

        await asyncio.gather(
            pipe(reader, target_writer, 'upload'),
            pipe(target_reader, writer, 'download')
        )

    except Exception as e:
        print(f"Connection error {peer}: {e}")
    finally:
        writer.close()
        await writer.wait_closed()
        print(f"Closed {peer}")


async def main():
    # TLS server setup
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        ssl_ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    except FileNotFoundError:
        print(f"ERROR: TLS certificate not found at {CERT_FILE}. TLS server disabled.")
        return
    except Exception as e:
        print(f"ERROR loading certificate: {e}")
        return

    tls_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, tls=True), LISTEN_ADDR, TLS_PORT, ssl=ssl_ctx)
    http_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, tls=False), LISTEN_ADDR, HTTP_PORT)

    print(f"Listening on {LISTEN_ADDR}:{HTTP_PORT} (HTTP payload)")
    print(f"Listening on {LISTEN_ADDR}:{TLS_PORT} (TLS)")

    async with tls_server, http_server:
        await asyncio.gather(
            tls_server.serve_forever(),
            http_server.serve_forever())

if __name__ == '__main__':
    asyncio.run(main())
EOF
  sudo chmod +x /usr/local/bin/wss

  sudo tee /etc/systemd/system/wss.service > /dev/null <<EOF
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
  sudo systemctl daemon-reload
  sudo systemctl enable wss
  sudo systemctl start wss
  echo "WSS 已启动，HTTP端口 $WSS_HTTP_PORT, TLS端口 $WSS_TLS_PORT"
}

# Stunnel4 / UDPGW 安装函数 (略)
install_stunnel_udpgw() {
  echo "==== 安装 Stunnel4 / UDPGW ===="
  # 安装 Stunnel4 并生成证书
  sudo mkdir -p /etc/stunnel/certs
  sudo openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout /etc/stunnel/certs/stunnel.key \
  -out /etc/stunnel/certs/stunnel.crt \
  -days 1095 \
  -subj "/CN=example.com"
  sudo sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
  sudo chmod 644 /etc/stunnel/certs/*.crt
  sudo chmod 644 /etc/stunnel/certs/*.pem

  sudo tee /etc/stunnel/ssh-tls.conf > /dev/null <<EOF
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
  sudo systemctl enable stunnel4
  sudo systemctl restart stunnel4
  echo "Stunnel4 已启动，端口 $STUNNEL_PORT"

  # 安装 UDPGW
  if [ ! -d "/root/badvpn" ]; then git clone https://github.com/ambrop72/badvpn.git /root/badvpn; fi
  mkdir -p /root/badvpn/badvpn-build
  cd /root/badvpn/badvpn-build
  cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 > /dev/null
  make -j$(nproc) > /dev/null

  sudo tee /etc/systemd/system/udpgw.service > /dev/null <<EOF
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
  sudo systemctl daemon-reload
  sudo systemctl enable udpgw
  sudo systemctl start udpgw
  echo "UDPGW 已启动，端口 $UDPGW_PORT"
}

# 用户管理函数 (来自第二个脚本，已清理)
manage_ssh_user() {
    local WSS_USER="$1"
    local WSS_PASS="$2"
    local USER_HOME="/home/${WSS_USER}"

    echo "==> 创建用户 $WSS_USER（如果已存在则跳过创建）"
    if ! id "$WSS_USER" >/dev/null 2>&1; then
      adduser --disabled-password --gecos "WSS User" "$WSS_USER" > /dev/null
    fi

    echo "==> 设置密码（更新/覆盖）"
    echo "${WSS_USER}:${WSS_PASS}" | chpasswd

    echo "==> 添加 SSHD 安全配置"
    sudo sed -i '/# WSSUSER_BLOCK_START/,/# WSSUSER_BLOCK_END/d' "$SSHD_CONFIG"
    
    # 使用 tee 配合 cat 将配置块追加到 SSHD_CONFIG
    cat <<EOCONF | sudo tee -a "$SSHD_CONFIG" > /dev/null

# WSSUSER_BLOCK_START -- managed by deploy_and_manage.sh
Match User $WSS_USER Address 127.0.0.1,::1
    PermitTTY no
    AllowTcpForwarding yes
    PasswordAuthentication yes
    AuthenticationMethods password
# WSSUSER_BLOCK_END -- managed by deploy_and_manage.sh
EOCONF
    
    echo "==> 重新加载 SSHD"
    if systemctl list-units --full -all | grep -q "sshd.service"; then
        SSHD_SERVICE="sshd"
    else
        SSHD_SERVICE="ssh"
    fi
    systemctl daemon-reload
    systemctl restart "$SSHD_SERVICE"
}

# ==================================
# 执行部署
# ==================================

# 确保以 root 执行
if [ "$EUID" -ne 0 ]; then
  echo "请以 root 或 sudo 权限运行此脚本。"
  exit 1
fi

install_wss_script
install_stunnel_udpgw

# --- 2. 安装管理面板 ---
echo "==== 安装 Web 管理面板 ===="
sudo pip3 install Flask > /dev/null

sudo tee /etc/wss-manager-config.json > /dev/null <<EOCONF
{
    "ADMIN_HASH": "$ADMIN_PASS_HASH",
    "MANAGER_PORT": $MANAGER_PORT,
    "WSS_USER_DEFAULT": "$WSS_USER_DEFAULT"
}
EOCONF

# 生成 Python Web 面板
sudo tee /usr/local/bin/wss_manager.py > /dev/null <<'EOF'
import os
import subprocess
import json
import time
from flask import Flask, render_template_string, request, redirect, url_for, session, abort
from hashlib import sha256

# --- Configuration Load ---
CONFIG_FILE = "/etc/wss-manager-config.json"
SSHD_CONFIG = "/etc/ssh/sshd_config"
WSS_USER_BASE_NAME = "wssuser" # Should match deploy script

try:
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
except FileNotFoundError:
    print(f"ERROR: Config file not found at {CONFIG_FILE}. Ensure deploy script ran.")
    exit(1)

ADMIN_HASH = config['ADMIN_HASH']
MANAGER_PORT = config['MANAGER_PORT']

app = Flask(__name__)
app.secret_key = os.urandom(24) # Used for session encryption

def run_cmd(cmd):
    """Run shell command and return output/error."""
    try:
        # 增加 /usr/sbin/ 和 /usr/bin/ 到 PATH，确保能找到 adduser, userdel, chpasswd, systemctl
        env = os.environ.copy()
        env["PATH"] = "/usr/sbin:/usr/bin:" + env.get("PATH", "")

        # Use subprocess.run for all command execution
        result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        return result.stdout.decode().strip()
    except subprocess.CalledProcessError as e:
        # In the web manager, errors should be handled gracefully
        # Removed full command for security/clarity in logs
        return f"Error executing: {e.stderr.decode().strip()}"

def get_active_users():
    """Get list of active users logged in via SSH (simulated check)."""
    try:
        # Use 'w' command to find currently logged-in users (basic check)
        output = run_cmd("w -h | awk '{print $1}' | sort -u")
        return output.split('\n')
    except Exception:
        return []

def get_user_status():
    """Reads users from passwd file and checks their active status."""
    user_data = {}
    active_users = get_active_users()
    
    # Get all users matching the WSS pattern (simple filter for demonstration)
    # Filter users with UID >= 1000 (standard user IDs)
    user_list_cmd = "awk -F: '$3 >= 1000 {print $1}' /etc/passwd"
    all_users = run_cmd(user_list_cmd).split('\n')
    
    for username in all_users:
        if not username or username in ['root', 'nobody', 'daemon', 'bin', 'sys']: continue
        
        # Panel only displays users starting with WSS_USER_BASE_NAME
        if username.startswith(WSS_USER_BASE_NAME) or username == WSS_USER_BASE_NAME:
            status = 'Online' if username in active_users else 'Offline'
            
            # --- Placeholders for unimplemented features ---
            user_data[username] = {
                'status': status,
                'traffic': '0.00 GB', # Placeholder: True traffic requires iptables integration
                'limit': 'Unlimited', # Placeholder
                'expiry': 'Never',    # Placeholder: Time limit requires external tracking
                'created': 'N/A'
            }
    return user_data

def sshd_restart():
    """Restarts the SSHD service."""
    if run_cmd("systemctl list-units --full -all | grep -q 'sshd.service'"):
        service = "sshd"
    else:
        service = "ssh"
    return run_cmd(f"systemctl restart {service}")

# --- Web UI Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form['password']
        # Note: Username is hardcoded to 'root' but password must match hash set by deploy script
        input_hash = sha256(password.encode()).hexdigest()
        
        if input_hash == ADMIN_HASH:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template_string(LOGIN_PAGE, error="密码错误。")
    return render_template_string(LOGIN_PAGE, error=None)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    users = get_user_status()
    
    # Find active SSHD service name for display/debugging
    if run_cmd("systemctl list-units --full -all | grep -q 'sshd.service'"):
        service_name = "sshd"
    else:
        service_name = "ssh"
        
    return render_template_string(DASHBOARD_PAGE, users=users, sshd_service=service_name)

@app.route('/manage', methods=['POST'])
def manage():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    action = request.form['action']
    username = request.form.get('username')
    
    if action == 'create':
        new_user = request.form['new_user']
        new_pass = request.form['new_pass']
        
        # Security check: Prevent creating root or system users
        if new_user in ['root', 'bin', 'daemon', 'sys', 'nobody'] or new_user.startswith('wssuser_'):
            pass # Simple prevention, deploy script handles full logic
        
        # Use bash functions to manage user/sshd_config
        # Note: SSHD config needs to be appended atomically to prevent corruption
        
        # 1. Create user and set password (must run as root)
        # Using full path for adduser and chpasswd for reliability
        run_cmd(f"/usr/sbin/adduser --disabled-password --gecos 'WSS User' {new_user} 2>/dev/null && echo '{new_user}:{new_pass}' | /usr/bin/chpasswd")
        
        # 2. Add SSHD config (Must be robust against f-string/template conflicts)
        config_block = f"""
# WSSUSER_BLOCK_START_{new_user}
Match User {new_user} Address 127.0.0.1,::1
    PermitTTY no
    AllowTcpForwarding yes
    PasswordAuthentication yes
    AuthenticationMethods password
# WSSUSER_BLOCK_END_{new_user}
"""
        # Run command to remove old block and append new one (Line 151 fix)
        # FIX: The sed command needs proper escaping for the literal curly braces.
        # We need to escape the user variable name, but the original issue was with the literal brace after the variable.
        run_cmd(f"sudo sed -i '/# WSSUSER_BLOCK_START_{new_user}}}/d; /# WSSUSER_BLOCK_END_{new_user}}}/d' {SSHD_CONFIG}") # <- Final fix
        run_cmd(f"echo '{config_block}' | sudo tee -a {SSHD_CONFIG}")
        
        sshd_restart()
        
    elif action == 'delete' and username:
        # Delete user and clean config
        run_cmd(f"/usr/sbin/userdel -r {username} 2>/dev/null")
        # Fix: Need to ensure sed command handles potential braces in username
        run_cmd(f"sudo sed -i '/# WSSUSER_BLOCK_START_{username}}}/d; /# WSSUSER_BLOCK_END_{username}}}/d' {SSHD_CONFIG}")
        sshd_restart()

    elif action == 'reset' and username:
        # Reset password
        reset_pass = request.form['reset_pass']
        run_cmd(f"echo '{username}:{reset_pass}' | /usr/bin/chpasswd")
        
    elif action == 'restart_sshd':
        sshd_restart()

    return redirect(url_for('index'))

# --- HTML Templates ---
LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>WSS 管理面板 - 登录</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen">
    <div class="bg-white p-8 rounded-lg shadow-xl w-full max-w-md">
        <h2 class="text-2xl font-bold text-center text-gray-800 mb-6">WSS 隧道管理面板</h2>
        {% if error %}
            <p class="bg-red-100 text-red-700 p-3 rounded mb-4 text-sm">{{ error }}</p>
        {% endif %}
        <form method="post" action="{{ url_for('login') }}">
            <div class="mb-4">
                <label for="username" class="block text-gray-700 text-sm font-semibold mb-2">用户名</label>
                <input type="text" id="username" name="username" value="root" readonly class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 bg-gray-200 cursor-not-allowed leading-tight focus:outline-none focus:shadow-outline">
            </div>
            <div class="mb-6">
                <label for="password" class="block text-gray-700 text-sm font-semibold mb-2">密码</label>
                <input type="password" id="password" name="password" required class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline">
            </div>
            <div class="flex items-center justify-between">
                <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline w-full transition duration-150">
                    登录
                </button>
            </div>
        </form>
    </div>
</body>
</html>
"""

DASHBOARD_PAGE = """
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>WSS 管理面板 - 仪表盘</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .online { color: #10B981; }
        .offline { color: #F59E0B; }
    </style>
</head>
<body class="bg-gray-100">
    <div class="container mx-auto p-4 sm:p-8">
        <div class="flex justify-between items-center mb-6">
            <h1 class="text-3xl font-extrabold text-gray-900">WSS 隧道管理面板</h1>
            <div class="space-x-2">
                <form method="POST" action="{{ url_for('manage') }}" class="inline">
                    <input type="hidden" name="action" value="restart_sshd">
                    <button type="submit" class="bg-red-500 hover:bg-red-600 text-white text-sm py-2 px-3 rounded shadow-md transition duration-150">
                        重启 SSHD (当前: {{ sshd_service }})
                    </button>
                </form>
                <a href="{{ url_for('logout') }}" class="bg-gray-500 hover:bg-gray-600 text-white text-sm py-2 px-3 rounded shadow-md transition duration-150">
                    退出
                </button>
                </a>
            </div>
        </div>

        <div class="bg-white p-6 rounded-xl shadow-lg mb-8">
            <h2 class="text-xl font-bold text-gray-800 mb-4">用户列表 ({{ users|length }} 个用户)</h2>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">用户名</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">状态</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">总流量 (模拟)</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">到期时间 (模拟)</th>
                            <th class="px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">操作</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        {% for username, user in users.items() %}
                        <tr class="hover:bg-gray-50">
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{{ username }}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                <span class="{% if user.status == 'Online' %}online{% else %}offline{% endif %}">
                                    {{ user.status }}
                                </span>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ user.traffic }}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ user.expiry }}</td>
                            <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-2 flex justify-center">
                                
                                <button onclick="document.getElementById('reset-{{ username }}').style.display='table-row'" class="text-indigo-600 hover:text-indigo-900 text-xs py-1 px-2 rounded border border-indigo-600 transition duration-150">
                                    重置密码
                                </button>
                                
                                <form method="POST" action="{{ url_for('manage') }}" class="inline" onsubmit="return confirm('确认删除用户 {{ username }}?');">
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="username" value="{{ username }}">
                                    <button type="submit" class="text-red-600 hover:text-red-900 text-xs py-1 px-2 rounded border border-red-600 transition duration-150">
                                        删除
                                    </button>
                                </form>
                            </td>
                        </tr>
                        <!-- Reset Password Modal -->
                        <tr id="reset-{{ username }}" class="hidden bg-yellow-50">
                            <td colspan="5" class="p-4">
                                <form method="POST" action="{{ url_for('manage') }}" class="flex items-center space-x-3">
                                    <input type="hidden" name="action" value="reset">
                                    <input type="hidden" name="username" value="{{ username }}">
                                    <label class="text-sm font-medium text-gray-700">新密码:</label>
                                    <input type="password" name="reset_pass" required class="shadow-sm border border-gray-300 rounded p-1 text-sm focus:ring-indigo-500 focus:border-indigo-500 w-48">
                                    <button type="submit" class="bg-yellow-500 hover:bg-yellow-600 text-white text-sm py-1 px-3 rounded shadow-md transition duration-150">
                                        确认重置
                                    </button>
                                    <button type="button" onclick="document.getElementById('reset-{{ username }}').style.display='none'" class="text-gray-500 hover:text-gray-700 text-sm">
                                        取消
                                    </button>
                                </form>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Add User Form -->
        <div class="bg-white p-6 rounded-xl shadow-lg">
            <h2 class="text-xl font-bold text-gray-800 mb-4">添加新用户</h2>
            <form method="POST" action="{{ url_for('manage') }}" class="space-y-4">
                <input type="hidden" name="action" value="create">
                <div class="flex space-x-4">
                    <div class="w-1/2">
                        <label for="new_user" class="block text-sm font-medium text-gray-700">用户名 (例如: wssuser01)</label>
                        <input type="text" name="new_user" id="new_user" required pattern="^[a-zA-Z0-9_]{3,16}$" title="用户名只能包含字母、数字和下划线，长度3-16位" class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500">
                    </div>
                    <div class="w-1/2">
                        <label for="new_pass" class="block text-sm font-medium text-gray-700">密码</label>
                        <input type="password" name="new_pass" id="new_pass" required class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500">
                    </div>
                </div>
                <div>
                    <button type="submit" class="bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded shadow-md transition duration-150">
                        创建用户并配置 SSH
                    </button>
                </div>
            </form>
        </div>
        
        <p class="text-center text-sm text-gray-500 mt-8">
            注意：流量和到期时间为模拟数据。实际限制需要通过手动配置 iptables 或系统定时任务实现。
        </p>
    </div>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=MANAGER_PORT, debug=False)

EOF

# 创建管理面板 systemd 服务
sudo tee /etc/systemd/system/wss-manager.service > /dev/null <<EOF
[Unit]
Description=WSS Manager Web Panel
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/wss_manager.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable wss-manager
sudo systemctl start wss-manager
echo "Web 管理面板已启动，端口: $MANAGER_PORT"

# ==================================
# 最终输出
# ==================================
echo ""
echo "=================================="
echo "✅ 部署完成！"
echo "----------------------------------"
echo "🌐 Web 管理面板访问地址 (Root 登录):"
echo "   http://<您的服务器IP>:$MANAGER_PORT"
echo "   请使用您在脚本开始时设置的面板密码登录。"
echo ""
echo "🔧 隧道基础配置:"
echo "   WSS HTTP Port: $WSS_HTTP_PORT"
echo "   WSS TLS Port: $WSS_TLS_PORT"
echo "   Stunnel Port: $STUNNEL_PORT"
echo "----------------------------------"
echo "⚠️ 下一步操作提醒:"
echo "1. 部署完成后，请手动在 Web 面板中添加您的 SSH 隧道用户。"
echo "2. 由于面板使用 root 权限运行，请务必在防火墙中限制对管理端口 $MANAGER_PORT 的访问。"
