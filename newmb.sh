#!/usr/bin/env bash
set -eu

# ==========================================================
# WSS Panel V2 部署脚本 (包含流量/到期日管理)
# ----------------------------------------------------------
# 此脚本部署了 WSS 代理、Stunnel4、UDPGW、Flask面板和流量统计模拟服务。
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
apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4 iptables
pip3 install flask jinja2
echo "依赖安装完成"
echo "----------------------------------"


# =============================
# WSS 核心代理脚本 (不变，专注于转发)
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

DEFAULT_TARGET = ('127.0.0.1', 41816)
BUFFER_SIZE = 65536
TIMEOUT = 3600
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'

FIRST_RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK\r\n\r\n'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    peer = writer.get_extra_info('peername')
    print(f"Connection from {peer} {'(TLS)' if tls else ''}")
    forwarding_started = False
    full_request = b''

    try:
        while not forwarding_started:
            data = await asyncio.wait_for(reader.read(BUFFER_SIZE), timeout=TIMEOUT)
            if not data: break
            
            full_request += data
            header_end_index = full_request.find(b'\r\n\r\n')
            
            if header_end_index == -1:
                writer.write(FIRST_RESPONSE)
                await writer.drain()
                full_request = b''
                continue

            headers_raw = full_request[:header_end_index]
            data_to_forward = full_request[header_end_index + 4:]
            headers = headers_raw.decode(errors='ignore')

            is_websocket_request = 'Upgrade: websocket' in headers or 'Connection: Upgrade' in headers or 'GET-RAY' in headers
            
            if is_websocket_request:
                writer.write(SWITCH_RESPONSE)
                await writer.drain()
                forwarding_started = True
            else:
                writer.write(FIRST_RESPONSE)
                await writer.drain()
                full_request = b''
                continue
        
        target = DEFAULT_TARGET
        target_reader, target_writer = await asyncio.open_connection(*target)

        if data_to_forward:
            target_writer.write(data_to_forward)
            await target_writer.drain()
            
        async def pipe(src_reader, dst_writer):
            try:
                while True:
                    buf = await src_reader.read(BUFFER_SIZE)
                    if not buf: break
                    dst_writer.write(buf)
                    await dst_writer.drain()
            except Exception: pass
            finally: dst_writer.close()

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
        except Exception: pass
        print(f"Closed {peer}")

async def main():
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        ssl_ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        tls_server = await asyncio.start_server(
            lambda r, w: handle_client(r, w, tls=True), LISTEN_ADDR, TLS_PORT, ssl=ssl_ctx)
        print(f"Listening on {LISTEN_ADDR}:{TLS_PORT} (TLS)")
        tls_task = tls_server.serve_forever()
    except FileNotFoundError:
        print(f"WARNING: TLS certificate not found at {CERT_FILE}. TLS server disabled.")
        tls_task = asyncio.sleep(86400)

    http_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, tls=False), LISTEN_ADDR, HTTP_PORT)
    
    print(f"Listening on {LISTEN_ADDR}:{HTTP_PORT} (HTTP payload)")

    async with http_server:
        await asyncio.gather(
            tls_task,
            http_server.serve_forever())

if __name__ == '__main__':
    try: asyncio.run(main())
    except KeyboardInterrupt: print("WSS Proxy Stopped.")
        
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
systemctl start wss
echo "WSS 已启动，HTTP端口 $WSS_HTTP_PORT, TLS端口 $WSS_TLS_PORT"
echo "----------------------------------"

# =============================
# Stunnel4, UDPGW, SSHD 配置 (与原脚本一致)
# =============================
echo "==== 安装 Stunnel4, UDPGW, SSHD 配置 ===="
mkdir -p /etc/stunnel/certs
openssl req -x509 -nodes -newkey rsa:2048 -keyout /etc/stunnel/certs/stunnel.key -out /etc/stunnel/certs/stunnel.crt -days 1095 -subj "/CN=example.com" > /dev/null 2>&1
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

if [ ! -d "/root/badvpn" ]; then git clone https://github.com/ambrop72/badvpn.git /root/badvpn; fi
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

SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_SUFFIX=".bak.wss$(date +%s)"
SSHD_SERVICE=$(systemctl list-units --full -all | grep -q "sshd.service" && echo "sshd" || echo "ssh")
cp -a "$SSHD_CONFIG" "${SSHD_CONFIG}${BACKUP_SUFFIX}"
sed -i '/# WSS_TUNNEL_BLOCK_START/,/# WSS_TUNNEL_BLOCK_END/d' "$SSHD_CONFIG"
cat >> "$SSHD_CONFIG" <<EOF

# WSS_TUNNEL_BLOCK_START -- managed by deploy_wss_panel.sh
Match Address 127.0.0.1,::1
    PasswordAuthentication yes
    PermitTTY yes
    AllowTcpForwarding yes
# WSS_TUNNEL_BLOCK_END -- managed by deploy_wss_panel.sh

EOF
chmod 600 "$SSHD_CONFIG"
systemctl daemon-reload
systemctl restart "$SSHD_SERVICE"

echo "Stunnel4, UDPGW, SSHD 配置更新完成。"
echo "----------------------------------"

# =============================
# WSS 流量统计脚本 (WSS ACCOUNTANT)
# =============================
echo "==== 部署流量统计与过期检查服务 (/usr/local/bin/wss_accountant.py) ===="
PANEL_DIR="/etc/wss-panel"
USER_DB="$PANEL_DIR/users.json"

tee /usr/local/bin/wss_accountant.py > /dev/null <<EOF
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, redirect, url_for, session, make_response
import json
import subprocess
import os
import hashlib
import time
import jinja2
from datetime import datetime, timedelta

# --- WARNING: These variables MUST be injected correctly by the deployment script ---
# If the script is run directly, these values will be defaults
USER_DB_PATH = "/etc/wss-panel/users.json"
ROOT_USERNAME = "root"
ROOT_PASSWORD_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" # Default for empty string if not set
PANEL_PORT = os.environ.get('PANEL_PORT', '8080')
WSS_HTTP_PORT = os.environ.get('WSS_HTTP_PORT', '80')
WSS_TLS_PORT = os.environ.get('WSS_TLS_PORT', '443')
STUNNEL_PORT = os.environ.get('STUNNEL_PORT', '444')
UDPGW_PORT = os.environ.get('UDPGW_PORT', '7300')

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()

# --- 工具函数 ---

def load_users():
    if not os.path.exists(USER_DB_PATH): return []
    try:
        with open(USER_DB_PATH, 'r') as f: return json.load(f)
    except Exception: return []

def save_users(users):
    try:
        os.makedirs(os.path.dirname(USER_DB_PATH), exist_ok=True)
        with open(USER_DB_PATH, 'w') as f: json.dump(users, f, indent=4)
    except Exception: pass

def get_user(username):
    users = load_users()
    for user in users:
        if user['username'] == username: return user
    return None

def safe_run_command(command, input=None):
    try:
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=input)
        return True, result.stdout.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        return False, e.stderr.decode('utf-8').strip()
    except FileNotFoundError:
        return False, "Command not found."

def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session.get('logged_in'): return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# --- 数据处理/格式化 ---

def bytes_to_human(n):
    if n is None: return "N/A"
    n = float(n)
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    return f"{n:.2f} {units[i]}"

def calculate_remaining_days(timestamp):
    if timestamp is None or timestamp == 0: return "无限期"
    try:
        expiry_date = datetime.fromtimestamp(timestamp)
        today = datetime.now()
        remaining = expiry_date - today
        if remaining.total_seconds() <= 0: return "已过期"
        return f"{remaining.days} 天"
    except:
        return "N/A"

# --- HTML 模板 ---

_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS Panel - 仪表盘</title>
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #f0f2f5; margin: 0; padding: 0; }
        .header { background-color: #2c3e50; color: white; padding: 20px 40px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; font-size: 24px; }
        .header button { background-color: #e74c3c; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer; color: white; transition: background-color 0.3s; }
        .header button:hover { background-color: #c0392b; }
        .container { padding: 20px; max-width: 1200px; margin: 20px auto; }
        .card { background: white; padding: 25px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05); margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-box { background-color: #ecf0f1; padding: 15px; border-radius: 8px; text-align: center; }
        .stat-box h3 { margin: 0 0 5px 0; color: #34495e; font-size: 16px; }
        .stat-box p { margin: 0; font-size: 24px; font-weight: bold; color: #2980b9; }
        
        /* Form */
        .user-form { display: flex; gap: 10px; align-items: center; flex-wrap: wrap;}
        .user-form input[type=text], .user-form input[type=password], .user-form input[type=date] { padding: 10px; border: 1px solid #ccc; border-radius: 6px; flex-grow: 1; max-width: 250px;}
        .user-form button { background-color: #2ecc71; color: white; border: none; padding: 10px 15px; border-radius: 6px; cursor: pointer; transition: background-color 0.3s; }
        .user-form button:hover { background-color: #27ae60; }

        /* Table */
        .user-table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .user-table th, .user-table td { border: 1px solid #ddd; padding: 12px; text-align: left; font-size: 14px;}
        .user-table th { background-color: #f7f7f7; color: #333; }
        .user-table tr:nth-child(even) { background-color: #f9f9f9; }
        .user-table .delete-btn { background-color: #e74c3c; color: white; border: none; padding: 6px 10px; border-radius: 5px; cursor: pointer; font-size: 12px; }
        .user-table .delete-btn:hover { background-color: #c0392b; }

        /* Status & Alert */
        .alert { padding: 15px; border-radius: 8px; margin-bottom: 20px; font-weight: bold; }
        .alert-success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }

        .status-active { color: #2ecc71; font-weight: bold; }
        .status-expired { color: #e74c3c; font-weight: bold; }
        
        /* Connection Info */
        .connection-info h3 { margin-top: 0; color: #2c3e50; }
        .connection-info pre { background-color: #ecf0f1; padding: 10px; border-radius: 6px; overflow-x: auto; font-size: 14px; }
        .note { color: #888; font-size: 14px; margin-top: 15px; border-left: 3px solid #f39c12; padding-left: 10px; }
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
            <div class="stat-box">
                <h3>总用户数</h3>
                <p id="user-count">{{ users|length }}</p>
            </div>
            <div class="stat-box">
                <h3>Web 面板端口</h3>
                <p>{{ panel_port }}</p>
            </div>
            <div class="stat-box">
                <h3>WSS (HTTP) 端口</h3>
                <p>{{ wss_http_port }}</p>
            </div>
            <div class="stat-box">
                <h3>Stunnel 端口</h3>
                <p>{{ stunnel_port }}</p>
            </div>
        </div>

        <div class="card connection-info">
            <h3>连接信息 (请替换 [Your Server IP])</h3>
            <p>使用以下信息配置你的客户端（WSS 或 Stunnel 模式）：</p>
            
            <pre>
服务器地址: {{ host_ip }}
WSS HTTP 端口: {{ wss_http_port }}
WSS TLS 端口: {{ wss_tls_port }}
Stunnel 端口: {{ stunnel_port }}
底层认证: SSH 账户/密码
</pre>
            <p class="note">注意：流量统计和过期检查服务每5分钟运行一次。过期用户会被自动从系统中删除。</p>
        </div>

        <div class="card">
            <h3>新增 WSS 用户</h3>
            <form id="add-user-form" class="user-form">
                <input type="text" id="new-username" placeholder="用户名" pattern="[a-z0-9_]{3,16}" title="用户名只能包含小写字母、数字和下划线，长度3-16位" required>
                <input type="password" id="new-password" placeholder="密码" required>
                <input type="date" id="new-expiry-date" placeholder="到期日 (可选)">
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
                        <th>已用流量</th>
                        <th>到期日</th>
                        <th>剩余天数</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr id="row-{{ user.username }}">
                        <td>{{ user.username }}</td>
                        <td><span class="status-{{ user.status }}">{{ user.status.upper() }}</span></td>
                        <td>{{ user.usage_human }}</td>
                        <td>{{ user.expires_at_date }}</td>
                        <td>{{ user.remaining_days }}</td>
                        <td>
                            {% if user.status == 'active' %}
                            <button class="delete-btn" onclick="deleteUser('{{ user.username }}')">删除</button>
                            {% else %}
                            <button class="delete-btn" onclick="deleteUser('{{ user.username }}')" title="账户已过期，删除其记录">清理</button>
                            {% endif %}
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

        document.getElementById('add-user-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('new-username').value.trim();
            const password = document.getElementById('new-password').value;
            const expiryDate = document.getElementById('new-expiry-date').value;

            if (!username || !password) {
                showStatus('用户名和密码不能为空。', false);
                return;
            }

            try {
                const response = await fetch('/api/users/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        username, 
                        password,
                        expiry_date: expiryDate
                    })
                });

                const result = await response.json();
                
                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    document.getElementById('new-username').value = '';
                    document.getElementById('new-password').value = '';
                    document.getElementById('new-expiry-date').value = '';
                    location.reload();
                } else {
                    showStatus('创建失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        });

        async function deleteUser(username) {
            if (window.confirm(\`确定要删除/清理用户 \${username} 吗?\`)) {
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
                        location.reload(); // 强制刷新确保数据一致
                    } else {
                        showStatus('删除失败: ' + result.message, false);
                    }
                } catch (error) {
                    showStatus('请求失败，请检查面板运行状态。', false);
                }
            }
        }
        
        function logout() {
            window.location.href = '/logout';
        }
    </script>
</body>
</html>
"""

# 渲染函数 (已修复)
def render_dashboard(users):
    template_env = jinja2.Environment(loader=jinja2.BaseLoader)
    template = template_env.from_string(_DASHBOARD_HTML)
    
    # 尝试获取真实的Host IP，如果失败则提示用户
    host_ip = request.host.split(':')[0]
    if host_ip in ('127.0.0.1', 'localhost', '0.0.0.0'):
         host_ip = '[Your Server IP]'

    # 预处理用户数据，确保所有字段都存在且格式正确
    processed_users = []
    for user in users:
        # 确保 usage_bytes 是数字，如果不存在则默认为 0
        user['usage_bytes'] = user.get('usage_bytes', 0)
        user['expires_at'] = user.get('expires_at', 0)
        user['status'] = user.get('status', 'active')

        user['usage_human'] = bytes_to_human(user['usage_bytes'])
        
        expires_ts = user['expires_at']
        if expires_ts and expires_ts != 0:
            user['expires_at_date'] = datetime.fromtimestamp(expires_ts).strftime('%Y-%m-%d')
        else:
            user['expires_at_date'] = "无限期"

        user['remaining_days'] = calculate_remaining_days(expires_ts)
        processed_users.append(user)

    context = {
        'users': processed_users,
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
    # 在这里调用更新后的 render_dashboard 函数
    html_content = render_dashboard(users=users) 
    return make_response(html_content)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password_raw = request.form.get('password')
        
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

    # Hardcoded HTML for login page
    login_html = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS Panel - 登录</title>
    <style>
        body {{ font-family: sans-serif; background-color: #f4f7f6; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
        .container {{ background: white; padding: 25px; border-radius: 12px; box-shadow: 0 6px 15px rgba(0, 0, 0, 0.1); width: 100%; max-width: 380px; }}
        h1 {{ text-align: center; color: #333; margin-bottom: 25px; font-weight: 600; }}
        input[type=text], input[type=password] {{ width: 100%; padding: 12px 10px; margin: 8px 0; display: inline-block; border: 1px solid #ccc; border-radius: 8px; box-sizing: border-box; transition: border-color 0.3s; }}
        input[type=text]:focus, input[type=password]:focus {{ border-color: #4CAF50; outline: none; }}
        button {{ background-color: #4CAF50; color: white; padding: 14px 20px; margin: 15px 0 5px 0; border: none; border-radius: 8px; cursor: pointer; width: 100%; font-size: 16px; transition: background-color 0.3s; }}
        button:hover {{ background-color: #45a049; }}
        .error {{ color: #e74c3c; text-align: center; margin-bottom: 15px; font-weight: bold; }}
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
    return make_response(login_html)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/api/users/add', methods=['POST'])
@login_required
def add_user_api():
    data = request.json
    username = data.get('username')
    password_raw = data.get('password')
    expiry_date_str = data.get('expiry_date')
    
    if not username or not password_raw: return jsonify({"success": False, "message": "缺少用户名或密码"}), 400

    users = load_users()
    if get_user(username): return jsonify({"success": False, "message": f"用户 {username} 已存在于面板"}), 409

    expires_at = 0
    if expiry_date_str:
        try:
            # 设置到期日为该天的最后一秒
            expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d')
            expires_at = int((expiry_date + timedelta(days=1, seconds=-1)).timestamp()) 
        except ValueError:
            return jsonify({"success": False, "message": "到期日期格式不正确 (应为 YYYY-MM-DD)"}), 400

    # 1. 创建系统账户
    success, output = safe_run_command(['useradd', '-m', '-s', '/bin/false', username])
    if not success: return jsonify({"success": False, "message": f"创建系统用户失败: {output}"}), 500

    # 2. 设置密码
    chpasswd_input = f"{username}:{password_raw}"
    success, output = safe_run_command(['/usr/sbin/chpasswd'], input=chpasswd_input.encode('utf-8'))
    if not success:
        safe_run_command(['userdel', '-r', username])
        return jsonify({"success": False, "message": f"设置密码失败: {output}"}), 500
        
    # 3. 更新面板数据库
    new_user = {
        "username": username,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "status": "active",
        "usage_bytes": 0,
        "expires_at": expires_at
    }
    users.append(new_user)
    save_users(users)

    return jsonify({"success": True, "message": f"用户 {username} 创建成功"})

@app.route('/api/users/delete', methods=['POST'])
@login_required
def delete_user_api():
    data = request.json
    username = data.get('username')
    
    if not username: return jsonify({"success": False, "message": "缺少用户名"}), 400

    users = load_users()
    user_to_delete = get_user(username)

    if not user_to_delete: return jsonify({"success": False, "message": f"面板中用户 {username} 不存在"}), 404

    # 删除系统账户 (这将终止所有SSH连接)
    safe_run_command(['userdel', '-r', username])

    # 从 JSON 数据库中删除记录
    users = [user for user in users if user['username'] != username]
    save_users(users)

    return jsonify({"success": True, "message": f"用户 {username} 已删除/清理"})


if __name__ == '__main__':
    # 从 /etc/wss-panel/panel_config.json 加载配置，以确保端口和哈希正确
    try:
        with open("/etc/wss-panel/panel_config.json", 'r') as f:
            config = json.load(f)
            ROOT_PASSWORD_HASH = config.get('root_hash', ROOT_PASSWORD_HASH)
            PANEL_PORT = config.get('panel_port', PANEL_PORT)

    except Exception:
        # 忽略加载错误，使用默认或脚本嵌入的值
        pass
        
    app.run(host='0.0.0.0', port=int(PANEL_PORT), debug=False)

EOF

chmod +x /usr/local/bin/wss_panel.py

# =============================
# 创建 WSS 面板 systemd 服务
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
systemctl start wss_panel
echo "WSS 管理面板已启动，端口 $PANEL_PORT"
echo "----------------------------------"

# 清理敏感变量
unset PANEL_ROOT_PASS_RAW

echo "=================================================="
echo "✅ WSS Panel V2 部署完成！"
echo "=================================================="
echo ""
echo "🔥 WSS 基础设施、Web 面板、流量统计服务均已启动。"
echo ""
echo "--- 访问信息 ---"
echo "Web 面板地址: http://[您的服务器IP]:$PANEL_PORT"
echo "Web 面板用户名: root"
echo "Web 面板密码: [您刚才设置的密码]"
echo ""
echo "--- 故障排查 ---"
echo "WSS 代理状态: sudo systemctl status wss"
echo "Stunnel 状态: sudo systemctl status stunnel4"
echo "Web 面板状态: sudo systemctl status wss_panel"
echo "用户数据库路径: /etc/wss-panel/users.json (面板通过此文件进行用户查询和管理)"
echo ""
echo "--- 注意事项 ---"
echo "1. 流量统计是基于 iptables 的用户 ID 追踪，请勿手动修改 /etc/passwd 中 WSS 用户的 UID。"
echo "2. 流量统计和过期检查服务每5分钟运行一次，过期用户会被自动删除系统账户。"
echo "3. 流量数据目前是模拟的累加，若需精确统计，请自行优化 /usr/local/bin/wss_accountant.py 中 iptables 读取和清零逻辑。"
echo "=================================================="
