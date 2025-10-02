#!/usr/bin/env bash
set -eu

# ==========================================================
# WSS 隧道与用户管理面板一键部署脚本 (V2 - 增强版)
# ----------------------------------------------------------
# 新增功能: 流量统计, 到期日, 账户状态 (在线/离线/暂停), 优化 UI。
# Panel 默认端口: 8080 (可修改)
# WSS 默认端口: HTTP 80, TLS 443
# Stunnel 默认端口: 444
# UDPGW 默认端口: 7300
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
apt update -y
# 确保安装 `dateutils` 用于日期计算（虽然 Python 内部会处理，但这里可以作为备选）
apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4 procps
pip3 install flask jinja2
echo "依赖安装完成"
echo "----------------------------------"

# =============================
# WSS 核心代理脚本 (保持不变)
# =============================
echo "==== 安装 WSS 核心代理脚本 (/usr/local/bin/wss) ===="
tee /usr/local/bin/wss > /dev/null <<'EOF'
#!/usr/bin/python3
# -*- coding: utf-8 -*-

# WSS 核心代理脚本 V1 (保持原样，负责 WSS/HTTP Payload 转发至 127.0.0.1:41816)

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

DEFAULT_TARGET = ('127.0.0.1', 41816) # 转发目标：SSHD 端口
BUFFER_SIZE = 65536
TIMEOUT = 3600
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'

# HTTP/WebSocket 握手响应
FIRST_RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK\r\n\r\n'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'
FORBIDDEN_RESPONSE = b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    peer = writer.get_extra_info('peername')
    print(f"Connection from {peer} {'(TLS)' if tls else ''}")
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
                # 如果头部不完整，发送 OK 响应以等待更多数据 (HTTP Payload 伪装)
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
        print(f"Connection error {peer}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        print(f"Closed {peer}")

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

# 创建 WSS systemd 服务
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

systemctl daemon-reload
systemctl enable wss
systemctl restart wss
echo "WSS 已启动，HTTP端口 $WSS_HTTP_PORT, TLS端口 $WSS_TLS_PORT"
echo "----------------------------------"

# =============================
# 安装 Stunnel4 并生成证书 (保持不变)
# =============================
echo "==== 安装 Stunnel4 ===="
mkdir -p /etc/stunnel/certs
openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 1095 \
-subj "/CN=example.com" > /dev/null 2>&1
sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
chmod 644 /etc/stunnel/certs/*.crt
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

systemctl enable stunnel4
systemctl restart stunnel4
echo "Stunnel4 安装完成，端口 $STUNNEL_PORT"
echo "----------------------------------"

# =============================
# 安装 UDPGW (保持不变)
# =============================
echo "==== 安装 UDPGW ===="
if [ ! -d "/root/badvpn" ]; then
    git clone https://github.com/ambrop72/badvpn.git /root/badvpn
fi
mkdir -p /root/badvpn/badvpn-build
cd /root/badvpn/badvpn-build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 > /dev/null 2>&1
make -j$(nproc) > /dev/null 2>&1
cd - > /dev/null

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
systemctl start udpgw
echo "UDPGW 已安装并启动，端口: $UDPGW_PORT"
echo "----------------------------------"


# =============================
# 安装 WSS 用户管理面板 (基于 Flask) - 升级版
# =============================
echo "==== 部署 WSS 用户管理面板 (Python/Flask) - 升级版 ===="
PANEL_DIR="/etc/wss-panel"
USER_DB="$PANEL_DIR/users.json"
mkdir -p "$PANEL_DIR"

# 创建或初始化用户数据库
if [ ! -f "$USER_DB" ]; then
    # 初始化时添加新的字段
    echo "[]" > "$USER_DB"
fi

# 嵌入 Python 面板代码 (修复了模板渲染问题，并加入新逻辑)
tee /usr/local/bin/wss_panel.py > /dev/null <<'EOF'
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, redirect, url_for, session, make_response
import json
import subprocess
import os
import hashlib
import time
from datetime import datetime, timedelta, timezone
import jinja2

# --- 配置 ---
USER_DB_PATH = "$USER_DB"
ROOT_USERNAME = "root"
ROOT_PASSWORD_HASH = "$PANEL_ROOT_PASS_HASH"
FLASK_SECRET_KEY = os.urandom(24).hex()
# Panel and Port config (used for templates)
PANEL_PORT = "$PANEL_PORT"
WSS_HTTP_PORT = "$WSS_HTTP_PORT"
WSS_TLS_PORT = "$WSS_TLS_PORT"
STUNNEL_PORT = "$STUNNEL_PORT"
UDPGW_PORT = "$UDPGW_PORT"

# 默认时区设为 UTC，并获取当前日期
TZ = timezone(timedelta(hours=8)) # 假设您偏好东八区时间
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# --- 数据库操作 ---

def load_users():
    """从 JSON 文件加载用户列表，并确保数据结构完整性."""
    if not os.path.exists(USER_DB_PATH):
        return []
    try:
        with open(USER_DB_PATH, 'r') as f:
            users = json.load(f)
            # 确保新字段存在，并提供默认值
            for user in users:
                if 'expiry_date' not in user:
                    user['expiry_date'] = (datetime.now(TZ) + timedelta(days=3650)).strftime('%Y-%m-%d') # 默认十年
                if 'traffic_used_gb' not in user:
                    user['traffic_used_gb'] = 0.0
            return users
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
    """按用户名查找用户."""
    users = load_users()
    for user in users:
        if user['username'] == username:
            return user
    return None

# --- 状态检查和系统工具函数 ---

def safe_run_command(command, input=None):
    """安全执行系统命令并返回结果."""
    try:
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=input,
            timeout=5 # 避免长时间阻塞
        )
        return True, result.stdout.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        return False, e.stderr.decode('utf-8').strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, f"Command error: {e}"

def check_user_status(user):
    """检查用户状态: 在线/离线/暂停.  
        Note: 无法获取客户端真实 IP, 因为 SSH 连接来自 127.0.0.1。
    """
    now = datetime.now(TZ).date()
    expiry_date = datetime.strptime(user.get('expiry_date', '2099-12-31'), '%Y-%m-%d').date()
    
    # 1. 检查到期日 (暂停状态优先级最高)
    if now > expiry_date:
        return {"status": "Paused", "details": "已到期", "pid": None}

    # 2. 检查在线状态 (通过检查 SSHD 进程)
    username = user['username']
    # 搜索由本机发起的 SSH 进程
    success, output = safe_run_command(['pgrep', '-f', f'sshd: {username}@notty'])
    
    if success and output:
        pids = output.split('\n')
        # 找到第一个 PID
        pid = pids[0]
        # 检查 SSH 连接的 IP (由于隧道，IP 总是 127.0.0.1)
        # 实际客户端 IP 无法获取，这里返回 PID 作为追溯信息
        return {"status": "Online", "details": f"PID: {pid}", "pid": pid}
        
    return {"status": "Offline", "details": "离线", "pid": None}


# --- 认证装饰器 ---

def login_required(f):
    """检查用户是否已登录."""
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return login_required.__name__

# --- HTML 模板和渲染 (Material Design 风格) ---

# 仪表盘 HTML (内嵌)
_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS Panel - 仪表盘</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; background-color: #f5f5f5; margin: 0; padding: 0; }
        .header { background-color: #0d47a1; color: white; padding: 16px 24px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; font-size: 20px; font-weight: 600; }
        .header button { background-color: #d32f2f; border: none; padding: 8px 15px; border-radius: 4px; cursor: pointer; color: white; transition: background-color 0.3s; box-shadow: 0 2px 4px rgba(0,0,0,0.2); }
        .header button:hover { background-color: #c62828; }
        .container { padding: 20px; max-width: 1400px; margin: 20px auto; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24); margin-bottom: 25px; transition: all 0.3s cubic-bezier(.25,.8,.25,1); }
        .card:hover { box-shadow: 0 10px 20px rgba(0,0,0,0.19), 0 6px 6px rgba(0,0,0,0.23); }

        /* Grid & Stats */
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-box { background-color: #e3f2fd; border-radius: 6px; padding: 15px; text-align: center; border-left: 5px solid #2196f3; }
        .stat-box h3 { margin: 0 0 5px 0; color: #424242; font-size: 14px; font-weight: 400; }
        .stat-box p { margin: 0; font-size: 20px; font-weight: 700; color: #1565c0; }
        
        /* Form */
        .user-form input, .user-form button { padding: 10px; margin-right: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        .user-form input:focus { border-color: #1565c0; outline: none; box-shadow: 0 0 0 2px rgba(21, 101, 192, 0.2); }
        .user-form button { background-color: #43a047; color: white; border: none; cursor: pointer; transition: background-color 0.3s; box-shadow: 0 2px 4px rgba(0,0,0,0.2); }
        .user-form button:hover { background-color: #388e3c; }

        /* Table */
        .user-table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .user-table th, .user-table td { border-bottom: 1px solid #eee; padding: 12px; text-align: left; }
        .user-table th { background-color: #f5f5f5; color: #424242; font-weight: 600; text-transform: uppercase; font-size: 12px; }
        .user-table tr:hover { background-color: #f9f9f9; }
        .user-table .delete-btn, .user-table .reset-btn { background-color: #f44336; color: white; border: none; padding: 6px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; margin-right: 5px; }
        .user-table .reset-btn { background-color: #ff9800; }
        .user-table .delete-btn:hover { background-color: #d32f2f; }
        .user-table .reset-btn:hover { background-color: #fb8c00; }

        /* Status Tags */
        .status { padding: 4px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; display: inline-block; }
        .status-online { background-color: #e8f5e9; color: #4caf50; } /* Green */
        .status-offline { background-color: #fbe9e7; color: #ff5722; } /* Orange/Deep-Orange */
        .status-paused { background-color: #fff3e0; color: #ff9800; } /* Amber */
        .status-active { background-color: #e3f2fd; color: #2196f3; } /* Blue */

        /* Alert */
        .alert { padding: 15px; border-radius: 4px; margin-bottom: 20px; font-weight: 600; }
        .alert-success { background-color: #e8f5e9; color: #2e7d32; border: 1px solid #a5d6a7; }
        .alert-error { background-color: #ffebee; color: #c62828; border: 1px solid #ef9a9a; }

        /* Connection Info */
        .connection-info h3 { margin-top: 0; color: #2c3e50; }
        .connection-info pre { background-color: #eceff1; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 14px; color: #37474f; }
        .note { color: #757575; font-size: 13px; margin-top: 15px; border-left: 3px solid #ffb300; padding-left: 10px; background-color: #fffde7; padding: 8px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>WSS Panel - 仪表盘</h1>
        <button onclick="logout()">退出登录 (root)</button>
    </div>

    <div class="container">
        <div id="status-message" class="alert" style="display:none;"></div>
        
        <div class="grid">
            <div class="stat-box"><h3>用户总数</h3><p id="user-count">{{ users|length }}</p></div>
            <div class="stat-box"><h3>面板端口</h3><p>{{ panel_port }}</p></div>
            <div class="stat-box"><h3>WSS HTTP 端口</h3><p>{{ wss_http_port }}</p></div>
            <div class="stat-box"><h3>Stunnel TLS 端口</h3><p>{{ stunnel_port }}</p></div>
        </div>

        <div class="card connection-info">
            <h3>连接信息 (请替换 [Your Server IP])</h3>
            <pre>
服务器地址: [Your Server IP]
WSS HTTP 端口: {{ wss_http_port }}
WSS TLS 端口: {{ wss_tls_port }}
Stunnel 端口: {{ stunnel_port }}
</pre>
            <p class="note">注意：所有隧道连接（WSS/Stunnel）都使用面板创建的 SSH 账户和密码进行认证。</p>
        </div>

        <div class="card">
            <h3>新增 WSS 用户</h3>
            <form id="add-user-form" class="user-form" onsubmit="addUser(event)">
                <input type="text" id="new-username" placeholder="用户名 (a-z0-9_)" pattern="[a-z0-9_]{3,16}" title="用户名只能包含小写字母、数字和下划线，长度3-16位" required>
                <input type="password" id="new-password" placeholder="密码" required>
                <input type="number" id="default-days" value="30" min="1" max="3650" placeholder="默认有效期 (天)">
                <button type="submit">创建用户</button>
            </form>
        </div>

        <div class="card">
            <h3>用户列表</h3>
            <table class="user-table" id="user-table">
                <thead>
                    <tr>
                        <th>用户名</th>
                        <th>状态</th>
                        <th>连接信息</th>
                        <th>创建时间</th>
                        <th>到期日</th>
                        <th>已用流量 (GB)</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr id="row-{{ user.username }}">
                        <td>{{ user.username }}</td>
                        <td><span class="status status-{{ user.runtime_status|lower }}">{{ user.runtime_status }}</span></td>
                        <td>{{ user.runtime_details }}</td>
                        <td>{{ user.created_at.split(' ')[0] }}</td>
                        <td>{{ user.expiry_date }}</td>
                        <td><span id="traffic-{{ user.username }}">{{ user.traffic_used_gb|round(2) }}</span></td>
                        <td>
                            <button class="reset-btn" onclick="resetTraffic('{{ user.username }}')">重置流量</button>
                            <button class="delete-btn" onclick="deleteUser('{{ user.username }}')">删除</button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        function showStatus(message, isSuccess) {
            const statusDiv = document.getElementById('status-message');
            statusDiv.textContent = message;
            statusDiv.className = isSuccess ? 'alert alert-success' : 'alert alert-error';
            statusDiv.style.display = 'block';
            setTimeout(() => { statusDiv.style.display = 'none'; }, 5000);
        }

        async function addUser(e) {
            e.preventDefault();
            const username = document.getElementById('new-username').value.trim();
            const password = document.getElementById('new-password').value;
            const defaultDays = parseInt(document.getElementById('default-days').value) || 30;

            if (!username || !password) {
                showStatus('用户名和密码不能为空。', false);
                return;
            }

            try {
                const response = await fetch('/api/users/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password, default_days: defaultDays })
                });

                const result = await response.json();
                
                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    // 清空字段并刷新
                    document.getElementById('new-username').value = '';
                    document.getElementById('new-password').value = '';
                    document.getElementById('default-days').value = '30';
                    location.reload();
                } else {
                    showStatus('创建失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        }

        async function deleteUser(username) {
            if (!window.confirm(\`确定要删除用户 \${username} 吗？这将从系统中永久删除该用户。\`)) {
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
                    const row = document.getElementById(\`row-\${username}\`);
                    if (row) row.remove();
                    
                    const countEl = document.getElementById('user-count');
                    countEl.textContent = parseInt(countEl.textContent) - 1;
                } else {
                    showStatus('删除失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        }

        async function resetTraffic(username) {
            if (!window.confirm(\`确定要重置用户 \${username} 的已用流量吗？\`)) {
                return;
            }
            
            try {
                const response = await fetch('/api/traffic/reset', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username })
                });
                const result = await response.json();
                
                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    document.getElementById(\`traffic-\${username}\`).textContent = '0.00';
                } else {
                    showStatus('重置失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        }
        
        function logout() {
            window.location.href = '/logout';
        }
        
        // 使用 window.confirm 替代 alert/prompt，简化 iframe 兼容性问题
        window.confirm = function(message) {
          return window.prompt(message + ' (输入 Y 确认)') === 'Y';
        }
    </script>
</body>
</html>
"""

# 修复后的渲染函数
def render_dashboard(users):
    """手动渲染 Jinja2 模板字符串."""
    # 遍历用户，添加运行时状态
    for user in users:
        status_info = check_user_status(user)
        user['runtime_status'] = status_info['status']
        user['runtime_details'] = status_info['details']
        # 流量显示格式化
        try:
            user['traffic_used_gb'] = float(user.get('traffic_used_gb', 0.0))
        except ValueError:
            user['traffic_used_gb'] = 0.0 # 避免因数据格式错误导致渲染失败

    template_env = jinja2.Environment(loader=jinja2.BaseLoader, autoescape=jinja2.select_autoescape(['html', 'xml']))
    template = template_env.from_string(_DASHBOARD_HTML)
    
    context = {
        'users': users,
        'panel_port': PANEL_PORT,
        'wss_http_port': WSS_HTTP_PORT,
        'wss_tls_port': WSS_TLS_PORT,
        'stunnel_port': STUNNEL_PORT,
        'udpgw_port': UDPGW_PORT
    }
    return template.render(**context)


# --- Web 路由 ---

@app.route('/', methods=['GET'])
@login_required
def dashboard():
    users = load_users()
    html_content = render_dashboard(users=users)
    return make_response(html_content)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    # ... (Login HTML/Logic remains the same) ...
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
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        body {{ font-family: 'Inter', sans-serif; background-color: #e3f2fd; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
        .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1); width: 100%; max-width: 350px; }}
        h1 {{ text-align: center; color: #1565c0; margin-bottom: 25px; font-weight: 700; font-size: 24px; }}
        label {{ display: block; margin-bottom: 5px; font-weight: 600; color: #333; font-size: 14px; }}
        input[type=text], input[type=password] {{ width: 100%; padding: 12px; margin-bottom: 15px; display: inline-block; border: 1px solid #cfd8dc; border-radius: 4px; box-sizing: border-box; transition: border-color 0.3s, box-shadow 0.3s; }}
        input[type=text]:focus, input[type=password]:focus {{ border-color: #2196f3; outline: none; box-shadow: 0 0 0 2px rgba(33, 150, 243, 0.2); }}
        button {{ background-color: #4CAF50; color: white; padding: 12px 20px; margin: 15px 0 5px 0; border: none; border-radius: 4px; cursor: pointer; width: 100%; font-size: 16px; font-weight: 600; transition: background-color 0.3s, box-shadow 0.3s; box-shadow: 0 2px 4px rgba(0,0,0,0.2); }}
        button:hover {{ background-color: #43a047; box-shadow: 0 4px 8px rgba(0,0,0,0.2); }}
        .error {{ color: #d32f2f; background-color: #ffcdd2; padding: 10px; border-radius: 4px; text-align: center; margin-bottom: 15px; font-weight: 600; border: 1px solid #ef9a9a; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>WSS 管理面板</h1>
        {f'<div class="error">{error}</div>' if error else ''}
        <form method="POST">
            <label for="username"><b>用户名</b></label>
            <input type="text" placeholder="输入 {ROOT_USERNAME}" name="username" value="{ROOT_USERNAME}" required>

            <label for="password"><b>密码</b></label>
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
    default_days = int(data.get('default_days', 30))
    
    if not username or not password_raw or default_days <= 0:
        return jsonify({"success": False, "message": "缺少用户名、密码或有效期无效"}), 400

    users = load_users()
    if get_user(username):
        return jsonify({"success": False, "message": f"用户 {username} 已存在于面板"}), 409

    # 1. 创建系统用户 (使用 -s /bin/false 禁用远程 shell 登录)
    success, output = safe_run_command(['useradd', '-m', '-s', '/bin/false', username])
    if not success:
        return jsonify({"success": False, "message": f"创建系统用户失败: {output}"}), 500

    # 2. 设置密码
    chpasswd_input = f"{username}:{password_raw}"
    success, output = safe_run_command(['/usr/sbin/chpasswd'], input=chpasswd_input.encode('utf-8'))
    if not success:
        safe_run_command(['userdel', '-r', username])
        return jsonify({"success": False, "message": f"设置密码失败: {output}"}), 500
        
    # 3. 计算到期日并记录到 JSON 数据库
    expiry_date = (datetime.now(TZ) + timedelta(days=default_days)).strftime('%Y-%m-%d')
    
    new_user = {
        "username": username,
        "created_at": datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S"),
        "expiry_date": expiry_date, # 新增到期日
        "traffic_used_gb": 0.0,     # 新增已用流量 (手动维护)
        "status": "active"
    }
    users.append(new_user)
    save_users(users)

    return jsonify({"success": True, "message": f"用户 {username} 创建成功，到期日: {expiry_date}"})

@app.route('/api/users/delete', methods=['POST'])
@login_required
def delete_user_api():
    """删除用户 (API)"""
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({"success": False, "message": "缺少用户名"}), 400

    users = load_users()
    user_to_delete = get_user(username)

    if not user_to_delete:
        # 即使面板中没有记录，也要尝试删除系统用户，防止幽灵账户
        safe_run_command(['userdel', '-r', username])
        return jsonify({"success": False, "message": f"面板中用户 {username} 不存在 (但尝试删除系统用户)"}), 404

    # 1. 删除系统用户及其主目录
    success, output = safe_run_command(['userdel', '-r', username])
    if not success:
        # 警告而非失败，因为可能用户已不存在
        print(f"Warning: Failed to delete system user {username}: {output}")

    # 2. 从 JSON 数据库中删除记录
    users = [user for user in users if user['username'] != username]
    save_users(users)

    return jsonify({"success": True, "message": f"用户 {username} 已删除"})

@app.route('/api/traffic/reset', methods=['POST'])
@login_required
def reset_traffic_api():
    """重置用户流量 (API)"""
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({"success": False, "message": "缺少用户名"}), 400

    users = load_users()
    user_found = False
    for user in users:
        if user['username'] == username:
            user['traffic_used_gb'] = 0.0
            user_found = True
            break

    if user_found:
        save_users(users)
        return jsonify({"success": True, "message": f"用户 {username} 流量已重置为 0.0 GB"})
    else:
        return jsonify({"success": False, "message": f"用户 {username} 不存在"}), 404


if __name__ == '__main__':
    print(f"WSS Panel running on port {PANEL_PORT}")
    # 由于我们使用 systemd 托管，debug 保持为 False
    app.run(host='0.0.0.0', port=int(PANEL_PORT), debug=False)

EOF

chmod +x /usr/local/bin/wss_panel.py

# =============================
# 创建 WSS 面板 systemd 服务 (保持不变)
# =============================
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

systemctl daemon-reload
systemctl enable wss_panel
systemctl restart wss_panel
echo "WSS 管理面板已启动，端口 $PANEL_PORT"
echo "----------------------------------"

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
    PermitTTY no # 明确禁止 TTY 以提高安全性，仅允许转发
    AllowTcpForwarding yes
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
echo "✅ 部署完成！"
echo "=================================================="
echo ""
echo "🔥 WSS & Stunnel 基础设施已启动。"
echo "🌐 WSS 用户管理面板已在后台运行 (Material Design 风格 UI)。"
echo ""
echo "--- 访问信息 ---"
echo "Web 面板地址: http://[您的服务器IP]:$PANEL_PORT"
echo "Web 面板用户名: root"
echo "Web 面板密码: [您刚才设置的密码]"
echo ""
echo "--- 重要说明 ---"
echo "1. **在线状态**：通过检查 **sshd 进程**确定用户是否连接。"
echo "2. **连接信息**：由于隧道设计，SSH 连接源 IP 始终是 127.0.0.1。面板显示的是 **sshd 进程 ID (PID)**，您可以利用 PID 在系统层面 (如用 'netstat -antp | grep PID') 追溯连接详情。"
echo "3. **流量统计**：面板目前提供 **手动重置** 功能。要实现精确的实时流量统计，需要更复杂的系统级集成，超出当前简易 Flask 架构范围。请在面板中 **手动更新或重置** 用户的流量数据。"
echo "=================================================="
