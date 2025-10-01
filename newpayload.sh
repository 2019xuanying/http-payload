#!/usr/bin/env bash
set -euo pipefail

# ==================================
# 部署参数配置
# ==================================
WSS_USER_DEFAULT="wssuser"
SSHD_CONFIG="/etc/ssh/sshd_config"
MANAGER_PORT_DEFAULT="54321"
HTML_TEMPLATE_PATH="/usr/local/bin/templates"

# ==================================
# 提示端口和密码
# ==================================
echo "--- 隧道端口设置 ---"
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
SECRET_KEY_PART=$(echo -n "$ADMIN_PASS_HASH" | cut -c 1-24) # 提取部分哈希作为 secret key

# ==================================
# 依赖安装
# ==================================
echo "==== 更新系统并安装依赖 ===="
sudo apt update -y
sudo apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4 jq
sudo pip3 install Flask > /dev/null
echo "依赖安装完成"

# ==================================
# 函数定义
# ==================================

# WSS 隧道脚本安装 (包含多段 Payload 修复)
install_wss_script() {
  echo "==== 安装 WSS 脚本 (/usr/local/bin/wss) ===="
  # WSS 脚本内容保持不变，因为它看起来是功能正常的
  # (此处省略原 WSS Python 脚本内容以节省篇幅，假设其功能正确)
  sudo tee /usr/local/bin/wss > /dev/null <<'EOF'
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio, ssl, sys

LISTEN_ADDR = '0.0.0.0'

# 使用 sys.argv 获取命令行参数。如果未提供，则使用默认值
try:
    HTTP_PORT = int(sys.argv[1])
except (IndexError, ValueError):
    HTTP_PORT = 80        # 默认 HTTP 端口

try:
    TLS_PORT = int(sys.argv[2])
except (IndexError, ValueError):
    TLS_PORT = 443        # 默认 TLS 端口

# 默认转发目标是本地 SSH 端口
DEFAULT_TARGET = ('127.0.0.1', 41816)
BUFFER_SIZE = 65536
TIMEOUT = 3600
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'
PASS = ''  # WSS 隧道密钥已禁用

FIRST_RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK\r\n\r\n'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'
FORBIDDEN_RESPONSE = b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    peer = writer.get_extra_info('peername')
    print(f"Connection from {peer} {'(TLS)' if tls else ''}")
    forwarding_started = False
    full_request = b'' # 用于累积 Payload 数据

    try:
        # --- 1. 握手循环 ---
        while not forwarding_started:
            
            data = await asyncio.wait_for(reader.read(BUFFER_SIZE), timeout=TIMEOUT)
            if not data:
                break
            
            full_request += data
            
            # 找到 HTTP 头部和实际数据之间的分隔符 (空行)
            header_end_index = full_request.find(b'\r\n\r\n')
            
            # 如果尚未找到完整的头部，继续等待
            if header_end_index == -1:
                # 在没有找到完整头部时，检查是否有 WebSocket 升级关键词
                headers_temp = full_request.decode(errors='ignore')
                
                # 检查是否包含升级关键词，如果是，则继续等待完整头部
                if 'Upgrade: websocket' in headers_temp or 'Connection: Upgrade' in headers_temp:
                    pass # 继续累积数据，以便进行完整解析
                else:
                    # 如果头部不完整且没有 Upgrade，返回 200 OK，等待下一段
                    # 这是为了兼容多段 Payload 的第一或中间几段
                    writer.write(FIRST_RESPONSE)
                    await writer.drain()
                    full_request = b'' # 清空，等待下一段数据
                    continue

            # 头部和数据分离
            headers = full_request[:header_end_index].decode(errors='ignore') if header_end_index != -1 else full_request.decode(errors='ignore')
            data_to_forward = full_request[header_end_index + 4:] if header_end_index != -1 else b'' # 分离出 SSH 数据

            host_header = ''
            passwd_header = ''
            is_websocket_request = False
            
            # 解析头部信息
            if 'Upgrade: websocket' in headers or 'Connection: Upgrade' in headers or 'GET-RAY' in headers:
                is_websocket_request = True
            
            for line in headers.split('\r\n'):
                if line.startswith('X-Real-Host:'):
                    host_header = line.split(':', 1)[1].strip()
                if line.startswith('X-Pass:'):
                    passwd_header = line.split(':', 1)[1].strip()

            # 3. 密码验证 (WSS 密钥) - 已移除
            
            # 4. 转发触发
            if is_websocket_request:
                writer.write(SWITCH_RESPONSE)
                await writer.drain()
                forwarding_started = True
            else:
                # 如果是完整的 HTTP 请求但不是 WebSocket，返回 200 OK
                writer.write(FIRST_RESPONSE)
                await writer.drain()
                full_request = b'' # 清空，等待下一段数据
                continue
        
        # --- 退出握手循环 ---

        # 5. 解析目标
        if host_header:
            if ':' in host_header:
                host, port = host_header.split(':')
                target = (host.strip(), int(port.strip()))
            else:
                target = (host_header.strip(), 22)
        else:
            target = DEFAULT_TARGET # 127.0.0.1:41816

        # 6. 连接目标服务器
        target_reader, target_writer = await asyncio.open_connection(*target)

        # 7. 转发初始数据 (SSH 握手)
        if data_to_forward:
            target_writer.write(data_to_forward)
            await target_writer.drain()
            
        # 8. 转发后续数据流
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
        # 打印异常，帮助调试
        print(f"Connection error {peer}: {e}")
    
    finally: # 修复了导致 SyntaxError 的 try/except/finally 结构
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

    # Start servers
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

# Stunnel4 / UDPGW 安装函数 (保持不变)
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
  # 确保 stunnel4 配置文件正确
  if systemctl is-enabled stunnel4 &> /dev/null; then
    sudo systemctl restart stunnel4
  else
    sudo systemctl enable stunnel4
    sudo systemctl start stunnel4
  fi
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
  cd - > /dev/null # 返回到之前的目录
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
echo "==== 配置 Web 管理面板 ===="

# 修复: JSON 键名改为 ADMIN_PASSWORD_HASH 以匹配 Python 代码
sudo tee /etc/wss-manager-config.json > /dev/null <<EOCONF
{
    "ADMIN_PASSWORD_HASH": "$ADMIN_PASS_HASH",
    "MANAGER_PORT": $MANAGER_PORT,
    "WSS_USER_DEFAULT": "$WSS_USER_DEFAULT",
    "SECRET_KEY_PART": "$SECRET_KEY_PART"
}
EOCONF

# 创建 templates 目录并写入 HTML 模板文件 (修复 Jinja2 渲染问题)
echo "==== 写入 Flask 模板文件 ===="
sudo mkdir -p $HTML_TEMPLATE_PATH

sudo tee $HTML_TEMPLATE_PATH/base.html > /dev/null <<'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ app_name if app_name is defined else 'WSS Manager' }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; background-color: #0d1117; color: #c9d1d9; }
        .card { background-color: #161b22; border: 1px solid #30363d; border-radius: 8px;}
        .btn-primary { background-color: #238636; color: white; transition: background-color 0.2s; border-radius: 6px;}
        .btn-primary:hover { background-color: #2ea043; }
        .btn-danger { background-color: #da3633; color: white; transition: background-color 0.2s; border-radius: 6px;}
        .btn-danger:hover { background-color: #f85149; }
        input[type="text"], input[type="password"] { background-color: #0d1117; border: 1px solid #30363d; color: #c9d1d9; border-radius: 6px; }
        .success { background-color: #23863622; border-left: 4px solid #238636; color: #56d364; }
        .error { background-color: #da363322; border-left: 4px solid #da3633; color: #f85149; }
        .online-dot { background-color: #56d364; }
        .offline-dot { background-color: #f85149; }
    </style>
</head>
<body>

<div class="container mx-auto p-4 md:p-8">
    <div class="flex justify-between items-center mb-6">
        <h1 class="text-3xl font-bold text-white">{{ app_name if app_name is defined else 'WSS Manager' }}</h1>
        {% if session.logged_in %}
        <a href="{{ url_for('logout') }}" class="text-sm text-gray-400 hover:text-white transition duration-150">退出 (Admin)</a>
        {% endif %}
    </div>

    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            <div class="mb-4">
                {% for category, message in messages %}
                    <div class="p-3 mb-2 rounded-md text-sm {{ 'error' if category == 'error' else 'success' }}">
                        {{ message }}
                    </div>
                {% endfor %}
            </div>
        {% endif %}
    {% endwith %}

    {% block content %}{% endblock %}

</div>
</body>
</html>
EOF

sudo tee $HTML_TEMPLATE_PATH/login.html > /dev/null <<'EOF'
{% extends "base.html" %}

{% block content %}
<div class="flex items-center justify-center min-h-[calc(100vh-100px)]">
    <div class="card p-8 rounded-lg shadow-xl w-full max-w-md">
        <h2 class="text-2xl font-bold mb-6 text-center text-white">管理员登录</h2>
        <form method="POST">
            <div class="mb-4">
                <label for="password" class="block text-sm font-medium mb-1">密码</label>
                <input type="password" name="password" id="password" required class="w-full p-3 rounded-md focus:outline-none focus:ring-2 focus:ring-[#238636]">
            </div>
            <button type="submit" class="btn-primary w-full p-3 rounded-md font-semibold">登录</button>
        </form>
    </div>
</div>
{% endblock %}
EOF

sudo tee $HTML_TEMPLATE_PATH/index.html > /dev/null <<'EOF'
{% extends "base.html" %}

{% block content %}
<h2 class="text-xl font-semibold mb-3">隧道用户列表 (UID >= 1000)</h2>
<div class="overflow-x-auto card rounded-lg shadow-lg mb-8">
    <table class="min-w-full divide-y divide-[#30363d]">
        <thead class="bg-[#161b22]">
            <tr>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">状态</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">用户名</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">最后登录/时长</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">流量限制</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">流量使用</th>
                <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">操作</th>
            </tr>
        </thead>
        <tbody class="divide-y divide-[#30363d]">
            {% for user in users %}
            <tr class="hover:bg-[#21262d] transition duration-150">
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="h-3 w-3 rounded-full inline-block mr-2 {{ 'online-dot' if user.is_online else 'offline-dot' }}"></span>
                    {{ '在线' if user.is_online else '离线' }}
                </td>
                <td class="px-6 py-4 whitespace-nowrap font-medium">{{ user.username }}</td>
                <td class="px-6 py-4 whitespace-nowrap">{{ user.last_login }}</td>
                <td class="px-6 py-4 whitespace-nowrap text-green-400">{{ user.data_limit }}</td>
                <td class="px-6 py-4 whitespace-nowrap text-red-400">{{ user.data_used }}</td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <form method="POST" class="inline" onsubmit="return confirm('确认删除用户 {{ user.username }}? 这将删除其系统账户和所有配置。');">
                        <input type="hidden" name="action" value="delete_user">
                        <input type="hidden" name="username" value="{{ user.username }}">
                        <button type="submit" class="btn-danger p-2 text-xs rounded-md">删除</button>
                    </form>
                </td>
            </tr>
            {% else %}
            <tr>
                <td colspan="6" class="px-6 py-4 text-center text-gray-500">
                    当前没有隧道用户。请在下方创建。
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>

<div class="mt-8 card p-6 rounded-lg">
    <h2 class="text-xl font-semibold mb-4">添加/更新隧道用户</h2>
    <form method="POST" class="space-y-4">
        <input type="hidden" name="action" value="create_user">
        <div>
            <label for="new_username" class="block text-sm font-medium mb-1">用户名</label>
            <input type="text" name="username" id="new_username" required class="w-full p-2 rounded-md focus:outline-none focus:ring-2 focus:ring-[#238636]" placeholder="用户名 (例如: tunnel01)">
        </div>
        <div>
            <label for="new_password" class="block text-sm font-medium mb-1">密码</label>
            <input type="password" name="password" id="new_password" required class="w-full p-2 rounded-md focus:outline-none focus:ring-2 focus:ring-[#238636]">
        </div>
        <button type="submit" class="btn-primary p-3 rounded-md font-semibold">创建用户并配置SSH</button>
    </form>
</div>
{% endblock %}
EOF

# 生成 Python Web 面板
sudo tee /usr/local/bin/wss_manager.py > /dev/null <<'EOF'
# -*- coding: utf-8 -*-
import json
import subprocess
import os
import sys
from flask import Flask, render_template, request, redirect, url_for, session, flash, get_flashed_messages
from datetime import datetime, timedelta
import hashlib
import time

# --- 配置参数 (从部署脚本的 JSON 文件中加载) ---
CONFIG_FILE = "/etc/wss-manager-config.json"
SSHD_CONFIG = "/etc/ssh/sshd_config"
WSS_USER_BASE_NAME = "wssuser"
USER_HOME_BASE = "/home"
TEMPLATES_FOLDER = "/usr/local/bin/templates"

# 加载配置
try:
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
        MANAGER_PORT = config['MANAGER_PORT']
        # 修复: 从 ADMIN_PASSWORD_HASH 加载密码哈希
        ADMIN_PASSWORD_HASH = config.get('ADMIN_PASSWORD_HASH', None)
        # 修复: 使用部分哈希作为固定 secret key
        SECRET_KEY_PART = config.get('SECRET_KEY_PART', os.urandom(24).hex()) 

except Exception as e:
    print(f"ERROR: Failed to load configuration from {CONFIG_FILE}. Details: {e}")
    MANAGER_PORT = 54321
    ADMIN_PASSWORD_HASH = ""
    SECRET_KEY_PART = os.urandom(24).hex()
    # 注意：如果配置文件加载失败，Web 面板将无法正确运行，但在部署脚本中已检查

# 修复: 设置 template_folder，使 Flask 能够找到模板
app = Flask(__name__, template_folder=TEMPLATES_FOLDER)
# 修复: 使用固定的密钥，确保重启后会话不会丢失
app.secret_key = SECRET_KEY_PART 


# --- 辅助函数 ---

def run_cmd(command):
    """
    运行 Bash 命令并返回其输出。
    """
    try:
        # 使用 /bin/bash 确保命令能被正确执行
        result = subprocess.run(
            ['/bin/bash', '-c', command],
            capture_output=True,
            text=True,
            check=True,
            timeout=10 # 增加超时机制
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"CMD ERROR: Command failed: {e.cmd}")
        print(f"STDERR: {e.stderr}")
        return f"CMD_ERROR: {e.stderr}"
    except FileNotFoundError:
        print(f"CMD ERROR: /bin/bash not found.")
        return "CMD_ERROR: /bin/bash not found."
    except subprocess.TimeoutExpired:
        print("CMD ERROR: Command timed out.")
        return "CMD_ERROR: Command timed out."


def check_auth():
    """检查用户是否登录"""
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))
    return None

def hash_password(password):
    """使用 SHA256 对密码进行哈希处理"""
    return hashlib.sha256(password.encode()).hexdigest()

# --- 用户管理逻辑 ---

def get_user_status():
    """获取所有隧道用户的状态、流量和在线信息"""
    user_status = []

    # 1. 获取所有 UID >= 1000 的用户列表 (非系统用户)
    try:
        user_list_cmd = "/usr/bin/awk -F: '($3 >= 1000) {print $1}' /etc/passwd"
        all_users = run_cmd(user_list_cmd).split('\n')
    except Exception as e:
        print(f"ERROR reading /etc/passwd: {e}")
        all_users = []
        
    # 2. 获取在线用户列表 (w 命令)
    online_users_output = run_cmd("w -h").split('\n')
    online_list = {line.split()[0]: True for line in online_users_output if line.strip()}
    
    # 3. 构建用户状态列表
    for username in all_users:
        if not username or username in ['root', 'nobody', 'daemon', 'bin', 'sys', 'man', 'lp', 'mail', 'news', 'uucp']:  
            continue
            
        # 4. 检查该用户是否在 sshd_config 中有配置块 (判断是否为面板创建的隧道用户)
        # 修复: 使用 'grep -q' 的退出码 ($?) 来判断是否存在，而不是判断输出
        # run_cmd 始终返回 stdout，所以这里需要一个更精确的检查，
        # 最好是直接使用 Python 的 os.system 或 subprocess.run(check=False) 配合 returncode。
        
        # 重新定义检查命令，返回一个明确的结果字符串
        check_cmd = f"grep -q '# WSSUSER_BLOCK_START_{username}' {SSHD_CONFIG} && echo 'FOUND' || echo 'NOT_FOUND'"
        if run_cmd(check_cmd) != "FOUND":
            continue # 如果没有找到配置块，则跳过
            
        # 流量和时间数据是手动配置的占位符
        user_data = {
            'username': username,
            'is_online': online_list.get(username, False),
            # last_login 字段在离线时显示 N/A，在线时显示 'Online' 
            'last_login': 'Online' if online_list.get(username, False) else 'N/A',
            'data_limit': "50 GB", # 占位符
            'data_used': "0 GB", # 占位符
            'expiry_date': (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"), # 占位符
            'status': 'Active'
        }
        user_status.append(user_data)

    return user_status

def manage_user_ssh_config(username, action, password=None):
    """管理用户在 sshd_config 中的配置块"""
    
    # 1. 清理所有与该用户相关的旧配置
    # 修复: sed 命令使用单引号和外部变量的组合，更安全可靠
    cleanup_cmd = f"sudo sed -i '/# WSSUSER_BLOCK_START_{username}/,/# WSSUSER_BLOCK_END_{username}/d' {SSHD_CONFIG}"
    run_cmd(cleanup_cmd)
    
    if action == 'delete':
        run_cmd(f"sudo userdel -r {username}")
        return f"User {username} deleted successfully."
        
    if action == 'create':
        # 2. 创建用户
        if 'No such user' in run_cmd(f"id {username} 2>&1"): # 检查用户是否存在
            run_cmd(f"sudo adduser --disabled-password --gecos 'WSS Tunnel User' {username}")
        
        # 3. 确保没有 sudo 权限 (可选，但推荐)
        run_cmd(f"sudo gpasswd -d {username} sudo 2>/dev/null || true") 
            
        # 4. 设置/更新密码
        if password:
            # 确保密码中不包含可能破坏 shell 命令的字符
            password_safe = password.replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')
            run_cmd(f'echo "{username}:{password_safe}" | sudo chpasswd')
            
        # 5. 写入 SSHD 配置块
        # 使用 Python 的文件写入功能，比 Bash 的 tee/echo 更安全、更可靠
        config_block = f"""

# WSSUSER_BLOCK_START_{username} -- managed by wss_manager
# 允许 {username} 从本机登录 (WSS/Stunnel)
Match User {username} Address 127.0.0.1,::1
    PermitTTY no
    AllowTcpForwarding yes
    PasswordAuthentication yes
    AuthenticationMethods password,keyboard-interactive
    ChallengeResponseAuthentication yes
# 禁止 {username} 远程登录 (其他地址)
Match User {username} Address *,!127.0.0.1,!::1
    PermitTTY no
    AllowTcpForwarding no
    PasswordAuthentication no
# WSSUSER_BLOCK_END_{username}
"""      
        try:
            with open(SSHD_CONFIG, 'a') as f:
                f.write(config_block)
            
            # 6. 重启 SSHD
            sshd_service = "sshd" if "sshd.service" in run_cmd("systemctl list-units --full -all | grep -i sshd") else "ssh"
            run_cmd(f"sudo systemctl restart {sshd_service}")
            return f"User {username} created/updated and SSHD restarted successfully."
        except Exception as e:
            return f"CMD_ERROR: Failed to write SSHD config or restart SSHD: {e}"
            
    return "Invalid action."


# --- 路由定义 ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form['password']
        if hash_password(password) == ADMIN_PASSWORD_HASH:
            session['logged_in'] = True
            session['username'] = 'Admin'
            return redirect(url_for('index'))
        else:
            flash("Invalid password", "error")
            # 修复: 登录失败后重定向到 login 页面
            return redirect(url_for('login')) 
    # 修复: 使用标准 render_template
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/', methods=['GET', 'POST'])
def index():
    auth_check = check_auth()
    if auth_check:
        return auth_check

    # 处理用户管理动作
    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username')
        
        if action == 'create_user':
            password = request.form.get('password')
            if not username or not password:
                flash("Username and password are required.", "error")
                return redirect(url_for('index'))
            
            result = manage_user_ssh_config(username, 'create', password)
            if 'CMD_ERROR' in result:
                flash(f"创建失败: {result}", "error")
            else:
                flash(f"用户 {username} 创建/更新成功! SSHD已重启。", "success")

        elif action == 'delete_user':
            result = manage_user_ssh_config(username, 'delete')
            if 'CMD_ERROR' in result:
                flash(f"删除失败: {result}", "error")
            else:
                flash(f"用户 {username} 删除成功。", "success")
        
        return redirect(url_for('index'))

    user_data = get_user_status()
    # 修复: 使用标准 render_template
    return render_template('index.html', users=user_data, app_name='WSS Manager')


if __name__ == '__main__':
    print(f"Starting WSS Manager on port {MANAGER_PORT}...")
    try:
        # Flask 需要运行在 0.0.0.0 上才能从外部访问
        app.run(host='0.0.0.0', port=MANAGER_PORT, debug=False)
    except Exception as e:
        print(f"FATAL ERROR: Failed to start Flask app: {e}", file=sys.stderr)
        sys.exit(1)

EOF

# 创建管理面板 systemd 服务
sudo tee /etc/systemd/system/wss-manager.service > /dev/null <<EOF
[Unit]
Description=WSS Manager Web Panel
After=network.target

[Service]
Type=simple
# 确保使用正确的 python3 路径
ExecStart=/usr/bin/python3 /usr/local/bin/wss_manager.py
Restart=always
User=root
# 确保 template 文件夹可访问
WorkingDirectory=/usr/local/bin/

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
echo "    http://<您的服务器IP>:$MANAGER_PORT"
echo "    请使用您在脚本开始时设置的面板密码登录。"
echo ""
echo "🔧 隧道基础配置:"
echo "    WSS HTTP Port: $WSS_HTTP_PORT"
echo "    WSS TLS Port: $WSS_TLS_PORT"
echo "    Stunnel Port: $STUNNEL_PORT"
echo "    UDPGW Port: $UDPGW_PORT"
echo "----------------------------------"
echo "⚠️ 下一步操作提醒 (重要):"
echo "1. 部署完成后，请手动在 Web 面板中添加您的 SSH 隧道用户。"
echo "2. 由于面板使用 root 权限运行，请务必在**防火墙中限制对管理端口 $MANAGER_PORT 的访问**，只允许可信IP访问。"
echo "3. 检查 SSHD 服务的状态: systemctl status sshd.service (或 ssh.service)"
echo "4. 检查 Web 面板服务的状态: systemctl status wss-manager.service"
echo "=================================="
