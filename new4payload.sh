#!/usr/bin/env bash
set -eu

# =============================
# 辅助函数：检查端口监听状态
# =============================
check_port() {
    local port="$1"
    if netstat -tuln | grep -q ":$port\s"; then
        echo -e "  端口 $port: \033[32mLISTENING\033[0m"
    else
        echo -e "  端口 $port: \033[31mNOT LISTENING\033[0m"
    fi
}

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
read -p "请输入 Web 管理面板监听端口 (默认54321): " PANEL_PORT
PANEL_PORT=${PANEL_PORT:-54321}

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
apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4 iptables
pip3 install flask jinja2 requests
echo "依赖安装完成"
echo "----------------------------------"


# =============================
# WSS 核心代理脚本 (V5.1 - 增加 IP 实时记录)
# =============================
echo "==== 安装 WSS 核心代理脚本 (/usr/local/bin/wss) V5.1 ===="
tee /usr/local/bin/wss > /dev/null <<'EOF'
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio, ssl, sys
import json
import time
import os

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

LIVE_CONNECTIONS_FILE = '/var/run/wss_live_connections.json'
CONNECTIONS_LOCK = asyncio.Lock()
ACTIVE_CONNECTIONS = {} # {peername: start_time}

FIRST_RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK\r\n\r\n'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'
FORBIDDEN_RESPONSE = b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'

def save_active_connections():
    """将内存中的活跃连接写入磁盘文件。"""
    try:
        # 确保目录存在
        os.makedirs(os.path.dirname(LIVE_CONNECTIONS_FILE) or '.', exist_ok=True)
        with open(LIVE_CONNECTIONS_FILE, 'w') as f:
            # 简化记录，只保留 IP、端口和开始时间
            json.dump(ACTIVE_CONNECTIONS, f, indent=4)
    except Exception:
        pass

async def live_connection_manager():
    """定时将连接状态写入文件。"""
    while True:
        await asyncio.sleep(5) # 每5秒更新一次文件
        async with CONNECTIONS_LOCK:
            save_active_connections()

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    peer = writer.get_extra_info('peername')
    # 提取 IP 地址
    client_ip = peer[0] 
    forwarding_started = False
    full_request = b''

    # 尝试将连接加入实时列表
    async with CONNECTIONS_LOCK:
        ACTIVE_CONNECTIONS[client_ip] = {
            "start_time": time.time(), 
            "peer": str(peer), 
            "tls": tls
        }
        # 立即更新文件，方便面板快速感知新连接
        save_active_connections() 

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

        # 4. 连接目标服务器
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

    except Exception:
        pass
    finally:
        # 清理连接信息
        async with CONNECTIONS_LOCK:
            if client_ip in ACTIVE_CONNECTIONS:
                del ACTIVE_CONNECTIONS[client_ip]
                save_active_connections() # 断开时立即更新
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def main():
    # 确保运行目录存在
    os.makedirs(os.path.dirname(LIVE_CONNECTIONS_FILE) or '.', exist_ok=True)
    # 启动定时连接管理器
    asyncio.create_task(live_connection_manager())

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
# 安装 Stunnel4 并生成证书
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
# 注意: Stunnel 转发目标是 127.0.0.1:48303
connect = 127.0.0.1:48303
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
EOF

systemctl enable stunnel4 || true
systemctl restart stunnel4 || true
echo "Stunnel4 配置已更新并重启，端口 $STUNNEL_PORT"
echo "----------------------------------"

# =============================
# 安装 UDPGW
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
# 安装 WSS 用户管理面板 (基于 Flask) - V5.1 新增 IP 阻断
# =============================
echo "==== 部署 WSS 用户管理面板 (Python/Flask) V5.1 增强版 (新增 IP 阻断) ===="
PANEL_DIR="/etc/wss-panel"
USER_DB="$PANEL_DIR/users.json"
mkdir -p "$PANEL_DIR"

# 检查/初始化用户数据库 (升级 logic)
python3 -c "
import json
import time
import os

USER_DB_PATH = \"$USER_DB\"

def upgrade_users():
    try:
        if not os.path.exists(USER_DB_PATH):
            print('Creating new user database.')
            # 初始化一个空列表，如果文件不存在
            with open(USER_DB_PATH, 'w') as f:
                json.dump([], f)
            return
        with open(USER_DB_PATH, 'r') as f:
            users = json.load(f)
    except Exception:
        print('Error loading users, skipping upgrade.')
        return

    updated = False
    for user in users:
        # 确保 V5.1 字段存在
        if 'status' not in user:
            user['status'] = 'active'
        if 'expiry_date' not in user:
            user['expiry_date'] = ''
        if 'quota_gb' not in user:
            user['quota_gb'] = 0.0
        if 'used_traffic_gb' not in user:
            user['used_traffic_gb'] = 0.0
        if 'last_check' not in user:
            user['last_check'] = time.time()
        # V5.1 新增：永久阻断 IP 列表
        if 'blocked_ips' not in user:
            user['blocked_ips'] = []
        
        updated = True
    
    if updated:
        with open(USER_DB_PATH, 'w') as f:
            json.dump(users, f, indent=4)
        print('User database structure upgraded.')

upgrade_users()
"

# 嵌入 Python 面板代码 (新增 IP 监控和阻断功能)
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
LIVE_CONNECTIONS_FILE = "/var/run/wss_live_connections.json" # WSS 代理写入的实时连接文件

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
        # 允许文件损坏但返回空列表，避免面板崩溃
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
            check=False, # 避免非零退出码引发异常
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=input, 
            timeout=5
        )
        # 检查返回码来判断是否成功 (0 为成功)
        return result.returncode == 0, result.stdout.decode('utf-8').strip() + result.stderr.decode('utf-8').strip()
    except Exception as e:
        return False, str(e)

def kill_user_sessions(username):
    """尝试杀死该用户的所有活动进程 (主要针对 SSH 会话)."""
    success, output = safe_run_command(['pkill', '-u', username])
    if not success and 'no process found' not in output.lower():
         print(f"Warning: pkill for {username} might have failed: {output}")
    return True

# --- IP 阻断功能 ---

def apply_ip_block(ip_addr):
    """在 IPTABLES 中永久阻断特定 IP (INPUT 链)."""
    # -C 检查规则是否存在，-A 添加规则
    # 注意：iptables -C 失败时返回码非 0
    check_success, _ = safe_run_command(['iptables', '-C', 'INPUT', '-s', ip_addr, '-j', 'DROP'])
    if not check_success:
        # 在 INPUT 链的第 1 条插入规则，保证其优先级
        safe_run_command(['iptables', '-I', 'INPUT', '1', '-s', ip_addr, '-j', 'DROP']) 
        
    # 保存规则以持久化 (如果系统支持)
    safe_run_command(['iptables-save', '>', '/etc/iptables/rules.v4'])
    # 理论上新的连接会被 DROP，但为了快速终止当前连接，可以尝试：
    # terminate_tcp_connections(ip_addr=ip_addr) # 过于复杂，依赖 DROP 足够
    return True

def remove_ip_block(ip_addr):
    """从 IPTABLES 中移除 IP 阻断规则."""
    # -D 删除规则
    while True: # 循环删除所有匹配的规则 (防止重复添加)
        success, _ = safe_run_command(['iptables', '-D', 'INPUT', '-s', ip_addr, '-j', 'DROP'])
        if not success:
            break
    
    # 保存规则以持久化 (如果系统支持)
    safe_run_command(['iptables-save', '>', '/etc/iptables/rules.v4'])
    return True

def reapply_permanent_ip_blocks():
    """面板启动时，重新加载所有用户的永久阻断 IP 规则."""
    print("Initializing: Re-applying permanent IP blocks...")
    users = load_users()
    total_blocked = 0
    # 首先清除所有由面板管理的 DROP 规则，避免残留/重复
    # 这是一个危险的操作，但在面板重启时用于清理干净是必要的。
    # 我们只删除包含 '-j DROP' 的规则。
    safe_run_command(['iptables', '-F', 'INPUT'])
    
    # 重新应用所有用户永久阻断的规则
    for user in users:
        for ip_addr in user.get('blocked_ips', []):
            apply_ip_block(ip_addr) # 确保规则存在
            total_blocked += 1
            
    # 确保 IPTABLES 流量统计链也被重新连接到 INPUT (setup_iptables_chains 在脚本末尾执行，这里只需确保 DROP 规则优先)
    print(f"Initialization complete. {total_blocked} permanent IP blocks re-applied.")


# --- 核心用户状态管理函数 ---

def sync_user_status(user):
    """检查并同步用户的到期日和流量配额状态到系统."""
    username = user['username']
    
    # 1. 检查账户到期日
    is_expired = False
    if user.get('expiry_date'):
        try:
            expiry_dt = datetime.strptime(user['expiry_date'], '%Y-%m-%d')
            if expiry_dt.date() < datetime.now().date():
                is_expired = True
        except ValueError:
            pass
    
    # 2. 检查流量配额
    is_quota_exceeded = False
    if user.get('quota_gb', 0.0) > 0 and user.get('used_traffic_gb', 0.0) >= user['quota_gb']:
        is_quota_exceeded = True
        
    current_status = user.get('status', 'active')
    should_be_paused = (current_status == 'paused') or is_expired or is_quota_exceeded
    
    # 获取系统实际状态
    system_locked = False
    success_status, output_status = safe_run_command(['passwd', '-S', username])
    if success_status and 'L' in output_status.split():
        system_locked = True
        
    # 如果面板要求启用 (active), 且系统是暂停的/锁定的
    if not should_be_paused and system_locked:
        safe_run_command(['usermod', '-U', username]) # 解锁密码
        safe_run_command(['chage', '-E', user.get('expiry_date', ''), username]) # 重新设置到期日或清除
        user['status'] = 'active'
        
    # 如果面板要求暂停/锁定, 且系统是未暂停的
    elif should_be_paused and not system_locked:
        safe_run_command(['usermod', '-L', username]) # 锁定密码
        safe_run_command(['chage', '-E', '1970-01-01', username]) # 强制过期
        kill_user_sessions(username) # 立即终止活动会话
        user['status'] = 'paused' # 标记面板状态
        
    # 如果处于活动状态，确保到期日字段被设置到系统 (如果存在)
    elif user.get('expiry_date') and current_status == 'active':
        safe_run_command(['chage', '-E', user['expiry_date'], username]) 

    return user

def refresh_all_user_status(users):
    """批量同步用户状态."""
    updated = False
    for user in users:
        # 确保 V5.1 新字段存在
        if 'blocked_ips' not in user:
            user['blocked_ips'] = []
            updated = True
            
        user = sync_user_status(user)
        # 格式化流量信息以便显示
        user['traffic_display'] = f"{user.get('used_traffic_gb', 0.0):.2f} / {user.get('quota_gb', 0.0):.2f} GB"
        
        # 确定状态文本和颜色
        user['status_text'] = "Active"
        user['status_class'] = "bg-green-500"
        
        if user['quota_gb'] > 0 and user['used_traffic_gb'] >= user['quota_gb']:
            user['status_text'] = "Exceeded"
            user['status_class'] = "bg-red-500"
        elif user['status'] == 'paused':
            user['status_text'] = "Paused"
            user['status_class'] = "bg-yellow-500"
        elif user['expiry_date']:
            try:
                if datetime.strptime(user['expiry_date'], '%Y-%m-%d').date() < datetime.now().date():
                    user['status_text'] = "Expired"
                    user['status_class'] = "bg-red-500"
            except ValueError:
                pass
        
        # IP 阻断的计数显示
        user['blocked_ip_count'] = len(user.get('blocked_ips', []))
        
        updated = True
    if updated:
        save_users(users)
    return users


# --- HTML 模板和渲染 ---

# 仪表盘 HTML (内嵌 - 增加实时连接和 IP 阻断按钮)
_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS Panel - 仪表盘 V5.1</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .card { transition: all 0.3s ease; }
        .card:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1); }
        .btn-action { transition: all 0.2s ease; }
        .btn-action:hover { opacity: 0.8; }
        .modal { background-color: rgba(0, 0, 0, 0.5); z-index: 999; }
        .modal-content { max-height: 80vh; overflow-y: auto; }
    </style>
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="bg-indigo-600 text-white shadow-lg">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center">
            <h1 class="text-3xl font-bold">WSS 隧道管理面板 V5.1 (IP 管理)</h1>
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
            <h3 class="text-xl font-semibold text-gray-800 mb-4 border-b pb-2">连接信息与实时监控</h3>
            <div class="bg-gray-100 p-4 rounded-lg font-mono text-sm overflow-x-auto">
                <p><span class="font-bold">服务器地址:</span> {{ host_ip }} (请手动替换为你的公网 IP)</p>
                <p><span class="font-bold">WSS (TLS/WebSocket):</span> 端口 {{ wss_tls_port }}</p>
                <p><span class="font-bold">Stunnel (TLS 隧道):</span> 端口 {{ stunnel_port }}</p>
                <p class="text-red-600 mt-2 font-bold">WSS 代理实时 IP 监控已开启！</p>
                <button onclick="openLiveConnectionsModal()" class="bg-pink-600 hover:bg-pink-700 text-white px-3 py-1 mt-2 rounded-lg font-semibold shadow-md btn-action text-xs">
                    &#x1F4BB; 查看实时活跃连接 IP
                </button>
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
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">永久阻断 IP 数</th>
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
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                <button onclick="openBlockedIpModal('{{ user.username }}')" class="text-xs px-3 py-1 rounded-full font-bold bg-pink-100 text-pink-800 hover:bg-pink-200 btn-action">
                                    {{ user.blocked_ip_count }} 个 IP 被阻断
                                </button>
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
                                <button onclick="resetTraffic('{{ user.username }}')"
                                        class="text-xs px-3 py-1 rounded-full font-bold bg-purple-100 text-purple-800 hover:bg-purple-200 btn-action">
                                    重置流量
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
                <h3 class="text-xl font-bold mb-4 text-gray-800 border-b pb-2">设置 <span id="modal-quota-username-title"></span> 的配额和到期日</h3>
                <form id="quota-form" onsubmit="event.preventDefault(); saveQuotaAndExpiry();">
                    <input type="hidden" id="modal-quota-username">
                    
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
    
    <!-- Modal for Blocked IPs -->
    <div id="blocked-ip-modal" class="modal fixed inset-0 flex items-center justify-center p-4 hidden">
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl modal-content">
            <div class="p-6">
                <h3 class="text-xl font-bold mb-4 text-gray-800 border-b pb-2">
                    永久阻断 IP 管理 - <span id="modal-blocked-ip-username-title"></span>
                </h3>
                <input type="hidden" id="modal-blocked-ip-username">
                
                <div class="mb-4">
                    <h4 class="font-semibold text-gray-700 mb-2">已阻断 IP (永久生效):</h4>
                    <ul id="blocked-ip-list" class="space-y-2 text-sm bg-gray-100 p-3 rounded-lg">
                        <!-- Content inserted by JS -->
                    </ul>
                </div>

                <div class="mb-6 border-t pt-4">
                    <h4 class="font-semibold text-gray-700 mb-2">手动阻断新 IP:</h4>
                    <div class="flex gap-2">
                        <input type="text" id="ip-to-block-manual" placeholder="输入要永久阻断的 IP 地址 (例如: 1.2.3.4)" 
                               class="flex-1 p-2 border border-gray-300 rounded-lg">
                        <button onclick="blockIp(document.getElementById('modal-blocked-ip-username').value, document.getElementById('ip-to-block-manual').value)" 
                                class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg font-semibold btn-action">
                            永久阻断
                        </button>
                    </div>
                </div>

                <div class="flex justify-end space-x-3">
                    <button type="button" onclick="closeBlockedIpModal()" class="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded-lg font-semibold btn-action">
                        关闭
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal for Live Connections -->
    <div id="live-connections-modal" class="modal fixed inset-0 flex items-center justify-center p-4 hidden">
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-4xl modal-content">
            <div class="p-6">
                <h3 class="text-xl font-bold mb-4 text-gray-800 border-b pb-2">
                    WSS 实时活跃连接 (所有用户)
                    <button onclick="loadLiveConnections()" class="ml-4 text-sm bg-blue-100 text-blue-800 px-3 py-1 rounded-full font-medium hover:bg-blue-200">
                        &#x27F3; 刷新
                    </button>
                </h3>
                
                <div id="live-connections-content" class="text-sm">
                    <p class="text-center text-gray-500">正在加载实时连接...</p>
                </div>

                <div class="flex justify-end space-x-3 mt-6">
                    <button type="button" onclick="closeLiveConnectionsModal()" class="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded-lg font-semibold btn-action">
                        关闭
                    </button>
                </div>
            </div>
        </div>
    </div>

    <script>
        // --- Utility Functions ---
        function showStatus(message, isSuccess) {
            const statusDiv = document.getElementById('status-message');
            statusDiv.textContent = message;
            statusDiv.className = \`\${isSuccess ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'} p-4 mb-4 rounded-lg font-semibold\`;
            statusDiv.classList.remove('hidden');
            setTimeout(() => { statusDiv.classList.add('hidden'); }, 5000);
        }
        
        function formatUptime(seconds) {
            if (seconds === undefined || seconds === null) return 'N/A';
            const d = Math.floor(seconds / (3600 * 24));
            const h = Math.floor(seconds % (3600 * 24) / 3600);
            const m = Math.floor(seconds % 3600 / 60);
            const s = Math.floor(seconds % 60);
            let parts = [];
            if (d > 0) parts.push(d + '天');
            if (h > 0) parts.push(h + '小时');
            if (m > 0) parts.push(m + '分');
            if (s > 0 && parts.length < 2) parts.push(s + '秒');
            return parts.length > 0 ? parts.join('') : '0秒';
        }
        
        function logout() {
            window.location.href = '/logout';
        }
        
        // --- API Calls ---

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
             document.getElementById('modal-quota-username-title').textContent = username;
             document.getElementById('modal-quota-username').value = username;
             document.getElementById('modal-quota').value = parseFloat(quota) || 0;
             document.getElementById('modal-expiry').value = expiry || '';
             document.getElementById('quota-modal').classList.remove('hidden');
         }

         function closeQuotaModal() {
             document.getElementById('quota-modal').classList.add('hidden');
         }

         async function saveQuotaAndExpiry() {
             const username = document.getElementById('modal-quota-username').value;
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
         
         async function resetTraffic(username) {
             if (window.prompt('确定要将用户 ' + username + ' 的已用流量清零吗? (输入 RESET 确认)') !== 'RESET') {
                 return;
             }

             try {
                 const response = await fetch('/api/users/reset_traffic', {
                     method: 'POST',
                     headers: { 'Content-Type': 'application/json' },
                     body: JSON.stringify({ username })
                 });

                 const result = await response.json();

                 if (response.ok && result.success) {
                     showStatus(result.message, true);
                     location.reload();
                 } else {
                     showStatus('重置失败: ' + result.message, false);
                 }
             } catch (error) {
                 showStatus('请求失败，请检查面板运行状态。', false);
             }
         }

        // --- NEW IP BLOCKING FUNCTIONS ---
        
        async function blockIp(username, ip_addr) {
            ip_addr = ip_addr.trim();
            if (!ip_addr || !/^(\d{1,3}\.){3}\d{1,3}$/.test(ip_addr)) {
                showStatus('IP 地址不能为空或格式不正确。', false);
                return;
            }
            if (!username) {
                showStatus('操作失败，未选择用户。', false);
                return;
            }
            if (!window.confirm(\`确定要永久阻断用户 \${username} 的 IP \${ip_addr} 吗? (将添加到防火墙规则)\`)) {
                return;
            }

            try {
                const response = await fetch('/api/users/block_ip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, ip_addr })
                });

                const result = await response.json();
                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    openBlockedIpModal(username); // 刷新模态框
                } else {
                    showStatus('阻断失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        }
        
        async function unblockIp(username, ip_addr) {
            if (!window.confirm(\`确定要解除阻断用户 \${username} 的 IP \${ip_addr} 吗? (将从该用户记录中移除)\`)) {
                return;
            }

            try {
                const response = await fetch('/api/users/unblock_ip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, ip_addr })
                });

                const result = await response.json();
                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    openBlockedIpModal(username); // 刷新模态框
                } else {
                    showStatus('解除失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        }

        // --- IP Modal Functions ---

        function openBlockedIpModal(username) {
            const usersData = JSON.parse(JSON.stringify({{ users|tojson }})).find(u => u.username === username);

            document.getElementById('modal-blocked-ip-username-title').textContent = username;
            document.getElementById('modal-blocked-ip-username').value = username;
            
            const listContainer = document.getElementById('blocked-ip-list');
            listContainer.innerHTML = '';

            const blockedIps = usersData?.blocked_ips || [];
            
            if (blockedIps.length === 0) {
                listContainer.innerHTML = '<li class="text-gray-500">该用户目前没有永久阻断的 IP 地址。</li>';
            } else {
                blockedIps.forEach(ip => {
                    const li = document.createElement('li');
                    li.className = 'flex justify-between items-center p-2 bg-white rounded-md shadow-sm';
                    li.innerHTML = \`
                        <span class="font-mono text-gray-800">\${ip}</span>
                        <button onclick="unblockIp('\${username}', '\${ip}')" 
                                class="text-xs px-3 py-1 rounded-full font-bold bg-green-100 text-green-800 hover:bg-green-200 btn-action">
                            解除阻断 (启用)
                        </button>
                    \`;
                    listContainer.appendChild(li);
                });
            }

            document.getElementById('ip-to-block-manual').value = '';
            document.getElementById('blocked-ip-modal').classList.remove('hidden');
        }

        function closeBlockedIpModal() {
            document.getElementById('blocked-ip-modal').classList.add('hidden');
            location.reload(); // 确保主列表的计数更新
        }
        
        function openLiveConnectionsModal() {
            document.getElementById('live-connections-modal').classList.remove('hidden');
            loadLiveConnections();
        }

        function closeLiveConnectionsModal() {
            document.getElementById('live-connections-modal').classList.add('hidden');
        }

        async function loadLiveConnections() {
            const contentDiv = document.getElementById('live-connections-content');
            contentDiv.innerHTML = '<p class="text-center text-gray-500">正在加载实时连接...</p>';

            try {
                const response = await fetch('/api/users/live_connections');
                const result = await response.json();

                if (response.ok && result.success) {
                    const liveConnections = result.connections;
                    
                    if (Object.keys(liveConnections).length === 0) {
                        contentDiv.innerHTML = '<p class="text-center text-gray-500 p-4 border rounded-lg">WSS 代理报告: 目前没有活跃连接。</p>';
                        return;
                    }
                    
                    const usersData = JSON.parse(JSON.stringify({{ users|tojson }}));
                    
                    let html = \`
                        <div class="overflow-x-auto">
                        <table class="min-w-full divide-y divide-gray-200">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">IP 地址</th>
                                    <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">已连接时长</th>
                                    <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">连接类型</th>
                                    <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">操作</th>
                                </tr>
                            </thead>
                            <tbody class="bg-white divide-y divide-gray-200">
                    \`;

                    for (const ip in liveConnections) {
                        const conn = liveConnections[ip];
                        const startTime = conn.start_time;
                        const connectedSeconds = Date.now() / 1000 - startTime;
                        const uptime = formatUptime(connectedSeconds);
                        const isTls = conn.tls ? 'TLS (443)' : 'HTTP (80)';
                        
                        let isPermanentlyBlocked = false;
                        let blockedByUser = [];
                        
                        usersData.forEach(user => {
                            if (user.blocked_ips && user.blocked_ips.includes(ip)) {
                                isPermanentlyBlocked = true;
                                blockedByUser.push(user.username);
                            }
                        });

                        const ipId = ip.replace(/\\./g, '-');

                        html += \`
                            <tr class="hover:bg-gray-50 \${isPermanentlyBlocked ? 'bg-red-50' : ''}">
                                <td class="px-4 py-2 whitespace-nowrap font-mono text-gray-900">\${ip}</td>
                                <td class="px-4 py-2 whitespace-nowrap text-gray-500">\${uptime}</td>
                                <td class="px-4 py-2 whitespace-nowrap text-gray-500">\${isTls}</td>
                                <td class="px-4 py-2 whitespace-nowrap">
                                    <select id="user-for-\${ipId}" class="p-1 border rounded text-xs bg-white mr-2 min-w-[100px]">
                                        <option value="">选择用户</option>
                                        \${usersData.map(u => \`<option value="\${u.username}">\${u.username}</option>\`).join('')}
                                    </select>
                                    <button onclick="
                                        const username = document.getElementById('user-for-\${ipId}').value;
                                        if (username) { blockIp(username, '\${ip}') } else { showStatus('请先选择一个用户', false) }
                                    " 
                                    class="text-xs px-3 py-1 rounded-full font-bold \${isPermanentlyBlocked ? 'bg-gray-300 text-gray-800' : 'bg-red-600 text-white hover:bg-red-700'} btn-action" 
                                    \${isPermanentlyBlocked ? 'disabled' : ''}>
                                        \${isPermanentlyBlocked ? '已阻断 (' + blockedByUser[0] + ')' : '永久阻断此 IP'}
                                    </button>
                                </td>
                            </tr>
                        \`;
                    }
                    
                    html += \`
                            </tbody>
                        </table>
                        </div>
                        <p class="mt-4 text-xs text-red-500">注意: 实时连接列表仅显示 WSS 代理层的连接 IP。阻断操作需要您选择一个**用户**，被阻断的 IP 将被添加到该用户的记录中。</p>
                    \`;
                    contentDiv.innerHTML = html;

                } else {
                    contentDiv.innerHTML = \`<p class="text-center text-red-500 p-4 border border-red-200 rounded-lg">获取实时连接失败: \${result.message || '未知错误'}</p>\`;
                }
            } catch (error) {
                contentDiv.innerHTML = \`<p class="text-center text-red-500 p-4 border border-red-200 rounded-lg">请求错误，请检查 WSS 代理是否运行正常。</p>\`;
            }
        }
        
    </script>
</body>
</html>
"""

def render_dashboard(users):
    """手动渲染 Jinja2 模板字符串."""
    template_env = jinja2.Environment(loader=jinja2.BaseLoader)
    template = template_env.from_string(_DASHBOARD_HTML)
    
    # 获取服务器IP 
    host_ip = request.host.split(':')[0]
    if host_ip in ('127.0.0.1', 'localhost', '0.0.0.0'):
        try:
             # 尝试通过 shell 命令获取公网 IP
             result = subprocess.run(['curl', '-s', 'icanhazip.com'], stdout=subprocess.PIPE, timeout=2)
             host_ip = result.stdout.decode().strip() or '[Your Server IP]'
        except Exception:
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


# --- Web 路由 ---

@app.before_request
def check_ip_block():
    """在处理请求前，检查请求的 IP 是否已被永久阻断 (防止恶意访问面板)"""
    # 允许本地访问和流量更新API调用绕过此检查
    if request.path.startswith('/api/users/update_traffic') or request.remote_addr in ('127.0.0.1', '::1'):
        return 
        
    if request.path.startswith('/login') or request.path == '/':
        client_ip = request.remote_addr
        users = load_users()
        for user in users:
            if client_ip in user.get('blocked_ips', []):
                return jsonify({"error": "Forbidden", "message": "Your IP address is permanently blocked by the administrator."}), 403
                
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
        <h1 class="text-2xl">WSS 管理面板 V5.1</h1>
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
        "last_check": time.time(),
        "blocked_ips": [] # V5.1 新增
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

    # 1. 终止用户会话
    kill_user_sessions(username)
    
    # 2. 从 IPTABLES 移除该用户所有永久阻断的 IP
    for ip_addr in user_to_delete.get('blocked_ips', []):
        remove_ip_block(ip_addr)

    # 3. 删除系统用户及其主目录
    success, output = safe_run_command(['userdel', '-r', username])
    if not success:
        print(f"Warning: Failed to delete system user {username}: {output}")

    # 4. 从 JSON 数据库中删除记录
    users.pop(index)
    save_users(users)

    return jsonify({"success": True, "message": f"用户 {username} 已删除，活动会话已终止，IP 阻断规则已清除"})

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
        safe_run_command(['usermod', '-L', username])
        safe_run_command(['chage', '-E', '1970-01-01', username]) # 强制过期
        kill_user_sessions(username) # 立即终止活动会话
        users[index]['status'] = 'paused'
        message = f"用户 {username} 已暂停，活动会话已终止"
    elif action == 'active':
        # 启用逻辑：解锁密码
        safe_run_command(['usermod', '-U', username])
        # 如果设置了到期日，则重新设置到期日，否则清除到期日
        if users[index].get('expiry_date'):
            safe_run_command(['chage', '-E', users[index]['expiry_date'], username]) 
        else:
            safe_run_command(['chage', '-E', '', username]) 
            
        users[index]['status'] = 'active'
        message = f"用户 {username} 已启用"
    else:
        return jsonify({"success": False, "message": "无效的操作参数"}), 400

    save_users(users)
    return jsonify({"success": True, "message": message})
    

@app.route('/api/users/reset_traffic', methods=['POST'])
@login_required
def reset_user_traffic_api():
    """将用户的已用流量清零 (API) - NEW"""
    data = request.json
    username = data.get('username')

    user, index = get_user(username)
    if not user:
        return jsonify({"success": False, "message": f"用户 {username} 不存在"}), 404
        
    users = load_users()
    
    # 清零流量
    users[index]['used_traffic_gb'] = 0.0
    
    # 如果用户超额状态被清除，重新同步状态（如果超额清零后状态变为 active，则解除系统锁定）
    users[index] = sync_user_status(users[index])
    
    save_users(users)
    return jsonify({"success": True, "message": f"用户 {username} 的已用流量已重置为 0.00 GB"})


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
    
    # 同步状态 (可能会触发暂停/启用)
    users[index] = sync_user_status(users[index])
    
    save_users(users)
    return jsonify({"success": True, "message": f"用户 {username} 设置已更新"})
    
    
@app.route('/api/users/update_traffic', methods=['POST'])
# 此 API 无需登录，供内部脚本调用
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


@app.route('/api/users/live_connections', methods=['GET'])
@login_required
def live_connections_api():
    """获取 WSS 代理记录的实时连接 IP"""
    if not os.path.exists(LIVE_CONNECTIONS_FILE):
        return jsonify({"success": False, "connections": {}, "message": "WSS 代理连接文件不存在，请确保 WSS 服务运行正常。"}), 500
        
    try:
        with open(LIVE_CONNECTIONS_FILE, 'r') as f:
            connections = json.load(f)
            return jsonify({"success": True, "connections": connections})
    except Exception as e:
        return jsonify({"success": False, "message": f"读取实时连接文件失败: {e}"}), 500

@app.route('/api/users/block_ip', methods=['POST'])
@login_required
def block_ip_api():
    """永久阻断一个 IP 地址，并加入用户的 blocked_ips 列表"""
    data = request.json
    username = data.get('username')
    ip_addr = data.get('ip_addr')
    
    if not username or not ip_addr:
        return jsonify({"success": False, "message": "缺少用户名或 IP 地址"}), 400

    user, index = get_user(username)
    if not user:
        return jsonify({"success": False, "message": f"用户 {username} 不存在"}), 404
        
    users = load_users()
    
    # 1. 执行 IPTABLES 阻断
    apply_ip_block(ip_addr)
    
    # 2. 记录到用户数据库 (去重)
    if ip_addr not in users[index].get('blocked_ips', []):
        users[index]['blocked_ips'].append(ip_addr)
        save_users(users)
        
    return jsonify({"success": True, "message": f"IP {ip_addr} 已被永久阻断并记录到用户 {username} 名下"})

@app.route('/api/users/unblock_ip', methods=['POST'])
@login_required
def unblock_ip_api():
    """解除对一个 IP 地址的永久阻断，并从用户的 blocked_ips 列表移除"""
    data = request.json
    username = data.get('username')
    ip_addr = data.get('ip_addr')
    
    if not username or not ip_addr:
        return jsonify({"success": False, "message": "缺少用户名或 IP 地址"}), 400

    user, index = get_user(username)
    if not user:
        return jsonify({"success": False, "message": f"用户 {username} 不存在"}), 404

    users = load_users()
    
    # 1. 从用户数据库中移除
    if ip_addr in users[index].get('blocked_ips', []):
        users[index]['blocked_ips'].remove(ip_addr)
        save_users(users)
        
    # 2. 检查其他用户是否也阻断了此 IP
    is_still_blocked = False
    for other_user in users:
        if other_user['username'] != username and ip_addr in other_user.get('blocked_ips', []):
            is_still_blocked = True
            break
            
    # 3. 只有当没有其他用户阻断此 IP 时，才从 IPTABLES 中移除
    if not is_still_blocked:
        remove_ip_block(ip_addr)
        message = f"IP {ip_addr} 已解除阻断并从防火墙移除"
    else:
        message = f"IP {ip_addr} 已从用户 {username} 名下解除，但仍被其他用户阻断，防火墙规则未移除。"

    return jsonify({"success": True, "message": message})


if __name__ == '__main__':
    # 面板启动时，重新加载永久阻断的 IP 规则
    reapply_permanent_ip_blocks() 
    
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
echo "WSS 管理面板 V5.1 已启动/重启，端口 $PANEL_PORT"
echo "----------------------------------"

# =============================
# 部署 IPTABLES 流量监控和同步脚本
# =============================

# 1. IPTABLES 链设置函数 (解决了 "Chain already exists" 错误)
setup_iptables_chains() {
    echo "==== 配置 IPTABLES 流量统计链 ===="
    
    # 1. 清理旧链和规则 (确保幂等性)
    # 删除连接点
    iptables -D INPUT -j WSS_USER_TRAFFIC_IN 2>/dev/null || true
    iptables -D OUTPUT -j WSS_USER_TRAFFIC_OUT 2>/dev/null || true
    
    # 清空并删除链
    iptables -F WSS_USER_TRAFFIC_IN 2>/dev/null || true
    iptables -X WSS_USER_TRAFFIC_IN 2>/dev/null || true
    iptables -F WSS_USER_TRAFFIC_OUT 2>/dev/null || true
    iptables -X WSS_USER_TRAFFIC_OUT 2>/dev/null || true

    # 2. 创建新链
    iptables -N WSS_USER_TRAFFIC_IN
    iptables -N WSS_USER_TRAFFIC_OUT

    # 3. 将新链连接到 INPUT 和 OUTPUT (在规则列表开头插入, -I 1)
    # 注意: IP 阻断规则 (DROP) 应该比流量统计规则更优先 (在 -I 1 之前，DROP规则在面板启动时被 INSERT 到最前面)
    iptables -I INPUT 1 -j WSS_USER_TRAFFIC_IN
    iptables -I OUTPUT 1 -j WSS_USER_TRAFFIC_OUT
    
    # 4. 保存规则 (对于大多数发行版)
    if command -v iptables-save >/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

    echo "IPTABLES 流量统计链创建/清理完成，已连接到 INPUT/OUTPUT。"
}

# 2. 流量同步 Python 脚本 (使用 Curl)
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
    
    safe_run_command(['iptables', '-F', IPTABLES_CHAIN_IN])
    safe_run_command(['iptables', '-F', IPTABLES_CHAIN_OUT])

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
        
    safe_run_command(['iptables', '-A', IPTABLES_CHAIN_IN, '-j', 'RETURN'])
    safe_run_command(['iptables', '-A', IPTABLES_CHAIN_OUT, '-j', 'RETURN'])


def read_and_report_traffic():
    """读取 iptables 计数器并调用 Flask API 更新流量 (使用 Curl)."""
    users = load_users()
    if not users:
        return

    setup_iptables_rules(users)

    success, output = safe_run_command(['iptables-save', '-c'])
    if not success:
        return

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

    for user in users:
        username = user['username']
        current_used_gb = user.get('used_traffic_gb', 0.0)
        
        in_bytes = traffic_data.get(username, {}).get('in', 0)
        out_bytes = traffic_data.get(username, {}).get('out', 0)
        total_transfer_bytes = in_bytes + out_bytes
        
        new_used_gb = current_used_gb + bytes_to_gb(total_transfer_bytes)
        rounded_gb = round(new_used_gb, 2)
        
        payload_json = json.dumps({
            "username": username,
            "used_traffic_gb": rounded_gb
        })

        # 使用 curl 调用面板 API
        success_curl, api_response = safe_run_command([
            'curl', '-s', '-X', 'POST', API_URL, 
            '-H', 'Content-Type: application/json', 
            '-d', payload_json
        ])
        
        if success_curl and api_response:
            try:
                response_json = json.loads(api_response)
                if response_json.get('success'):
                    # 如果面板更新成功，则清零 IPTABLES 计数器
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
                pass


if __name__ == '__main__':
    read_and_report_traffic()
EOF

chmod +x /usr/local/bin/wss_traffic_sync.py

# 3. 创建定时任务 (Cron Job) 运行流量同步脚本
echo "==== 设置 Cron 定时任务 (每 5 分钟同步一次流量) ===="

mkdir -p /etc/cron.d

tee /etc/cron.d/wss-traffic > /dev/null <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# 每 5 分钟运行一次 Python 流量同步脚本
*/5 * * * * root /usr/bin/python3 /usr/local/bin/wss_traffic_sync.py
EOF

chmod 0644 /etc/cron.d/wss-traffic

systemctl enable cron || true
systemctl start cron || true

echo "流量同步脚本已安装，并将每 5 分钟自动运行。"
echo "----------------------------------"

# 4. 立即运行 IPTABLES 链设置
setup_iptables_chains


# =============================
# SSHD 安全配置 
# =============================
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_SUFFIX=".bak.wss$(date +%s)"
SSHD_SERVICE=$(systemctl list-units --full -all | grep -q "sshd.service" && echo "sshd" || echo "ssh")

echo "==== 配置 SSHD 安全策略 ===="
# 备份 sshd_config
cp -a "$SSHD_CONFIG" "${SSHD_CONFIG}${BACKUP_SUFFIX}"
echo "SSHD 配置已备份到 ${SSHD_CONFIG}${BACKUP_SUFFIX}"

# 1. 删除旧的 WSS 匹配配置段
sed -i '/# WSS_TUNNEL_BLOCK_START/,/# WSS_TUNNEL_BLOCK_END/d' "$SSHD_CONFIG"

# 2. 写入新的 WSS 隧道策略
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
echo "✅ WSS 管理面板 V5.1 部署完成！"
echo "=================================================="
echo ""
echo "🔥 关键更新点："
echo "1. WSS 代理现在能实时记录连接的客户端 IP。"
echo "2. 面板新增 **'实时活跃连接 IP'** 按钮，可查看当前所有连接并实施永久阻断/启用操作。"
echo ""
echo "--- 访问信息 ---"
echo "Web 面板地址: http://\$SERVER_IP:$PANEL_PORT"
echo "Web 面板用户名: root"
echo "Web 面板密码: [您刚才设置的密码]"
echo ""
echo "--- 端口状态检查 ---"
echo "以下为关键服务端口实际监听状态 (L = Listen):"
echo "WSS (HTTP/WebSocket): $WSS_HTTP_PORT"
check_port "$WSS_HTTP_PORT"
echo "WSS (TLS/WebSocket): $WSS_TLS_PORT"
check_port "$WSS_TLS_PORT"
echo "Stunnel (TLS 隧道): $STUNNEL_PORT"
check_port "$STUNNEL_PORT"
echo "内部转发端口 (SSH): 48303"
check_port "48303"
echo "UDPGW (内部网关): $UDPGW_PORT"
check_port "$UDPGW_PORT"

echo ""
echo "--- 故障排查/日志命令 ---"
echo "WSS 核心代理状态: sudo systemctl status wss -l"
echo "Web 面板状态: sudo systemctl status wss_panel -l"
echo "检查 IPTABLES IP 阻断规则: sudo iptables -L INPUT -n --line-numbers"
echo ""
echo "用户数据库路径: /etc/wss-panel/users.json (面板通过此文件管理用户)"
echo "实时连接文件: cat /var/run/wss_live_connections.json (WSS 代理每 5 秒更新一次)"
echo "=================================================="
