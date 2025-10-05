#!/usr/bin/env bash
set -eu

# =======================================================
# WSS 隧道/Stunnel/管理面板部署脚本 V5.7 - 实时 IP 阻断与 VENV/审计日志
# =======================================================

# --- 全局变量和工具函数 (不变) ---

# 检查端口是否正在监听
check_port() {
    local port="$1"
    if command -v ss >/dev/null; then
        if ss -tuln | grep -q ":$port "; then
            echo -e " \033[32m[LISTEN]\033[0m"
        else
            echo -e " \033[31m[FAIL]\033[0m"
        fi
    elif command -v netstat >/dev/null; then
        if netstat -tuln | grep -q ":$port "; then
            echo -e " \033[32m[LISTEN]\033[0m"
        else
            echo -e " \033[31m[FAIL]\033[0m"
        fi
    else
        echo " (Cannot check status, ss or netstat not found)"
    fi
}
export -f check_port

# 获取服务器IP (增加备用 IP API，提高成功率)
get_server_ip() {
    echo "尝试获取服务器公网 IP..."
    # 尝试使用 ip.sb
    SERVER_IP=$(curl -s --connect-timeout 2 ip.sb 2>/dev/null)
    # 尝试使用 ifconfig.me
    [ -z "$SERVER_IP" ] && SERVER_IP=$(curl -s --connect-timeout 2 ifconfig.me 2>/dev/null)
    # 尝试获取本地非回环 IP
    [ -z "$SERVER_IP" ] && SERVER_IP=$(ip a | grep 'inet ' | grep -v '127.0.0.1' | head -n 1 | awk '{print $2}' | cut -d/ -f1)
    # 最终默认值
    [ -z "$SERVER_IP" ] && SERVER_IP='[SERVER_IP]'
    echo "$SERVER_IP"
}
SERVER_IP=$(get_server_ip)
echo "检测到的服务器 IP: $SERVER_IP"

# --- VENV 配置 (API Key 配置移除) ---
VENV_PATH="/opt/wss_venv"
PYTHON_VENV_PATH="$VENV_PATH/bin/python3"


# --- 1. 提示端口和面板密码 (保留不变) ---
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
    # 对密码进行简单的 HASH
    PANEL_ROOT_PASS_HASH=$(echo -n "$PANEL_ROOT_PASS_RAW" | sha256sum | awk '{print $1}')
    break
done

echo "----------------------------------"
echo "==== 系统更新与依赖安装 (VENV 隔离) ===="
apt update -y
apt install -y python3 python3-pip python3-venv wget curl git net-tools cmake build-essential openssl stunnel4 iptables-persistent

# 1. 创建并安装 Python 虚拟环境
echo "创建 Python 虚拟环境于 $VENV_PATH"
mkdir -p "$VENV_PATH"
python3 -m venv "$VENV_PATH"

# 2. 在 VENV 中安装 python 依赖
echo "在 VENV 中安装 Python 依赖..."
"$PYTHON_VENV_PATH" -m pip install flask jinja2 requests httpx

echo "依赖安装完成，使用隔离环境路径: $VENV_PATH"
echo "----------------------------------"


# --- 2. WSS 核心代理脚本 (保留不变) ---
echo "==== 安装 WSS 核心代理脚本 (/usr/local/bin/wss) ===="
tee /usr/local/bin/wss > /dev/null <<EOF
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio
import ssl
import sys
import os
import json
import httpx # 引入 httpx 用于异步 HTTP 客户端

# --- 配置 ---
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
PANEL_PORT = os.environ.get('WSS_PANEL_PORT', '54321')
API_URL_CHECK = f"http://127.0.0.1:{PANEL_PORT}/api/ips/check"
API_URL_REPORT = f"http://127.0.0.1:{PANEL_PORT}/api/ips/report"

FIRST_RESPONSE = b'HTTP/1.1 200 OK\\r\\nContent-Type: text/plain\\r\\nContent-Length: 2\\r\\n\\r\\nOK\\r\\n\\r\\n'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\n\\r\\n'
FORBIDDEN_RESPONSE = b'HTTP/1.1 403 Forbidden\\r\\nContent-Length: 0\\r\\n\\r\\n'

http_client = httpx.AsyncClient(timeout=3.0) 

async def check_ip_status(client_ip):
    """异步查询 Flask 面板，检查 IP 是否被禁止 (作为二次验证)."""
    try:
        response = await http_client.post(
            API_URL_CHECK,
            json={'ip': client_ip}
        )
        if response.status_code == 200:
            result = response.json()
            return not result.get('is_banned', False)
        return True
    except Exception:
        return True

async def report_ip_activity(client_ip, action):
    """异步报告 IP 活动状态 (connect/disconnect)."""
    try:
        await http_client.post(
            API_URL_REPORT,
            json={'ip': client_ip, 'action': action}
        )
    except Exception:
        pass


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    peer = writer.get_extra_info('peername')
    client_ip = peer[0]
    
    is_allowed = await check_ip_status(client_ip)
    if not is_allowed:
        writer.write(FORBIDDEN_RESPONSE)
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        return

    await report_ip_activity(client_ip, 'connect')
    
    forwarding_started = False
    full_request = b''

    try:
        while not forwarding_started:
            data = await asyncio.wait_for(reader.read(BUFFER_SIZE), timeout=10) 
            if not data:
                break
            
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
        
        if not forwarding_started:
            raise Exception("Handshake failed or connection closed early")

        target = DEFAULT_TARGET
        target_reader, target_writer = await asyncio.open_connection(*target)

        if data_to_forward:
            target_writer.write(data_to_forward)
            await target_writer.drain()
            
        async def pipe(src_reader, dst_writer):
            pipe_timeout = TIMEOUT 
            try:
                while True:
                    buf = await asyncio.wait_for(src_reader.read(BUFFER_SIZE), timeout=pipe_timeout)
                    if not buf:
                        break
                    dst_writer.write(buf)
                    await dst_writer.drain()
            except asyncio.TimeoutError:
                pass
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
        await report_ip_activity(client_ip, 'disconnect')
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

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
    try:
        os.environ['WSS_PANEL_PORT'] = "$PANEL_PORT" 
        asyncio.run(main())
    except KeyboardInterrupt:
        print("WSS Proxy Stopped.")
    except Exception as e:
        print(f"FATAL ERROR: {e}")
        
EOF

chmod +x /usr/local/bin/wss

# 创建 WSS systemd 服务 (ExecStart 更新为 VENV 路径)
tee /etc/systemd/system/wss.service > /dev/null <<EOF
[Unit]
Description=WSS Python Proxy (V5.7 VENV/IP Control)
After=network.target

[Service]
Type=simple
Environment=WSS_PANEL_PORT=$PANEL_PORT
ExecStart=$PYTHON_VENV_PATH /usr/local/bin/wss $WSS_HTTP_PORT $WSS_TLS_PORT
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wss || true
systemctl restart wss || true
echo "WSS 核心代理 (V5.7 VENV隔离版) 已启动/重启，HTTP端口 $WSS_HTTP_PORT, TLS端口 $WSS_TLS_PORT"
echo "----------------------------------"

# --- 3. Stunnel4, UDPGW (保留 V5.5 优化) ---
echo "==== 检查/安装 Stunnel4 ===="
mkdir -p /etc/stunnel/certs
if [ ! -f "/etc/stunnel/certs/stunnel.pem" ]; then
    echo "Stunnel 证书不存在，正在生成..."
    openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout /etc/stunnel/certs/stunnel.key \
    -out /etc/stunnel/certs/stunnel.crt \
    -days 1095 \
    -subj "/CN=example.com"
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
debug = 0
output = /var/log/stunnel4/stunnel.log
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls-gateway]
accept = 0.0.0.0:$STUNNEL_PORT
connect = 127.0.0.1:48303
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
EOF

systemctl enable stunnel4 || true
systemctl restart stunnel4 || true
echo "Stunnel4 配置已更新并重启，端口 $STUNNEL_PORT"
echo "----------------------------------"

echo "==== 检查/安装 UDPGW (编译反馈增强) ===="
if [ ! -f "/root/badvpn/badvpn-build/udpgw/badvpn-udpgw" ]; then
    echo "UDPGW 二进制文件不存在，开始编译..."
    if [ ! -d "/root/badvpn" ]; then
        echo "克隆 badvpn 仓库..."
        git clone https://github.com/ambrop72/badvpn.git /root/badvpn || { echo "ERROR: Git clone failed."; exit 1; }
    fi
    mkdir -p /root/badvpn/badvpn-build
    cd /root/badvpn/badvpn-build
    
    if cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 ; then
        if make -j$(nproc); then
            echo "UDPGW 编译成功。"
        else
            echo "ERROR: UDPGW make failed. Check build-essential is installed."
            exit 1
        fi
    else
        echo "ERROR: UDPGW cmake failed."
        exit 1
    fi
    cd - > /dev/null
else
    echo "UDPGW 二进制文件已存在，跳过编译。"
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


# --- 4. 安装 WSS 用户管理面板 (基于 Flask) - 实时 IP 阻断集成 ---
echo "==== 部署 WSS 用户管理面板 (Python/Flask) V5.7 (审计日志/实时阻断) ===="
PANEL_DIR="/etc/wss-panel"
USER_DB="$PANEL_DIR/users.json"
IP_BANS_DB="$PANEL_DIR/ip_bans.json" 
IP_ACTIVE_DB="$PANEL_DIR/ip_active.json" 
# AUDIT_LOG_PATH 在 Python 脚本内部定义

mkdir -p "$PANEL_DIR"

# 初始化数据库
[ ! -f "$IP_BANS_DB" ] && echo "{}" > "$IP_BANS_DB"
[ ! -f "$IP_ACTIVE_DB" ] && echo "{}" > "$IP_ACTIVE_DB"

# 检查/初始化用户数据库 (保留升级逻辑)
if [ ! -f "$USER_DB" ]; then
    echo "[]" > "$USER_DB"
else
    # 确保旧用户数据结构兼容新字段
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
        if 'banned_ips' not in user:
            user['banned_ips'] = []
            updated = True
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

# 嵌入 Python 面板代码 (移除 API Key 认证，添加审计日志)
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
import re
from functools import wraps

# --- 配置 ---
PANEL_DIR = "/etc/wss-panel"
USER_DB_PATH = os.path.join(PANEL_DIR, "users.json")
IP_BANS_DB_PATH = os.path.join(PANEL_DIR, "ip_bans.json")
IP_ACTIVE_DB_PATH = os.path.join(PANEL_DIR, "ip_active.json")
AUDIT_LOG_PATH = os.path.join(PANEL_DIR, "audit.log") # 审计日志路径

ROOT_USERNAME = "root"
ROOT_PASSWORD_HASH = "$PANEL_ROOT_PASS_HASH"
FLASK_SECRET_KEY = os.urandom(24).hex()

# 面板和端口配置
PANEL_PORT = "$PANEL_PORT"
WSS_HTTP_PORT = "$WSS_HTTP_PORT"
WSS_TLS_PORT = "$WSS_TLS_PORT"
STUNNEL_PORT = "$STUNNEL_PORT"
UDPGW_PORT = "$UDPGW_PORT"

SERVER_IP = os.environ.get('SERVER_IP', '[Your Server IP]')

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# --- 数据库操作 (保留不变) ---
def load_data(path, default_value):
    if not os.path.exists(path):
        return default_value
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {path}: {e}")
        return default_value

def save_data(data, path):
    try:
        with open(path, 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving {path}: {e}")
        return False

def load_users(): return load_data(USER_DB_PATH, [])
def save_users(users): return save_data(users, USER_DB_PATH)
def load_ip_bans(): return load_data(IP_BANS_DB_PATH, {})
def save_ip_bans(ip_bans): return save_data(ip_bans, IP_BANS_DB_PATH)
def load_active_ips(): return load_data(IP_ACTIVE_DB_PATH, {})
def save_active_ips(active_ips): return save_data(active_ips, IP_ACTIVE_DB_PATH)

def get_user(username):
    users = load_users()
    for i, user in enumerate(users):
        if user.get('username') == username:
            return user, i
    return None, -1

# --- 审计日志功能 (新增) ---
def log_action(action_type, username, details=""):
    """记录关键管理操作到审计日志文件."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # 尝试获取操作者的 IP，对于 Web UI 操作，这是客户端 IP
    operator_ip = request.remote_addr if request else "127.0.0.1 (System)"
    
    log_entry = f"[{timestamp}] [USER:{username}] [IP:{operator_ip}] ACTION:{action_type} DETAILS: {details}\n"
    
    try:
        with open(AUDIT_LOG_PATH, 'a') as f:
            f.write(log_entry)
    except Exception as e:
        # 避免日志写入失败影响面板功能
        print(f"Error writing to audit log: {e}")

# --- 认证装饰器 (移除 API Key 认证) ---

def login_required(f):
    """检查用户是否已登录 (用于 Web UI 和所有管理 API)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session.get('logged_in'):
            # 记录尝试访问日志
            log_action("LOGIN_ATTEMPT", "N/A", f"Access denied to {request.path}")
            return redirect(url_for('login'))  
        
        # 记录成功的 UI/API 访问 (可选，但可以显示活跃度)
        # log_action("ACCESS", session.get('username', 'root'), request.path)
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__ + "_decorated"
    return decorated_function


# --- 系统工具函数 (保留不变) ---
def safe_run_command(command, input=None):
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
        
def toggle_iptables_ip_ban(ip, action):
    """实时通过 iptables 封禁或解封 IP，并保存规则."""
    chain = "WSS_IP_BLOCK"
    
    if action == 'block':
        safe_run_command(['iptables', '-D', chain, '-s', ip, '-j', 'DROP'])
        command = ['iptables', '-I', chain, '1', '-s', ip, '-j', 'DROP']
        
    elif action == 'unblock':
        command = ['iptables', '-D', chain, '-s', ip, '-j', 'DROP']
    else:
        return False, "Invalid action"
    
    success, output = safe_run_command(command)
    
    if success:
        try:
            with open('/etc/iptables/rules.v4', 'w') as f:
                subprocess.run(['iptables-save'], stdout=f, check=True, timeout=3)
            return True, "IPTables rule updated and saved."
        except Exception:
            return True, "IPTables rule updated but failed to save persistence file."
    
    if action == 'unblock' and ('No chain/target/match by that name' in output or 'Bad rule' in output):
        return True, f"IP {ip} rule not found, assuming unblocked."
    
    return success, output

def kill_user_sessions(username):
    success, output = safe_run_command(['pkill', '-u', username])
    return success, output 

# --- 核心用户状态管理函数 (保留不变) ---
def sync_user_status(user):
    username = user['username']
    is_expired_or_exceeded = False
    
    if user['expiry_date']:
        try:
            expiry_dt = datetime.strptime(user['expiry_date'], '%Y-%m-%d')
            if expiry_dt.date() < datetime.now().date():
                is_expired_or_exceeded = True
        except ValueError:
            print(f"Invalid expiry_date format for {username}: {user['expiry_date']}")
            
    if user['quota_gb'] > 0 and user['used_traffic_gb'] >= user['quota_gb']:
        is_expired_or_exceeded = True
        
    current_status = user.get('status', 'active')
    should_be_paused = (current_status == 'paused') or is_expired_or_exceeded
    
    system_locked = False
    success_status, output_status = safe_run_command(['passwd', '-S', username])
    if success_status and output_status and ' L ' in output_status:
        system_locked = True
        
    if not should_be_paused and system_locked:
        safe_run_command(['usermod', '-U', username])
        if user['expiry_date']:
            safe_run_command(['chage', '-E', user['expiry_date'], username]) 
        else:
            safe_run_command(['chage', '-E', '', username])
        user['status'] = 'active'
        
    elif should_be_paused and not system_locked:
        safe_run_command(['usermod', '-L', username])
        safe_run_command(['chage', '-E', '1970-01-01', username]) 
        kill_user_sessions(username)
        user['status'] = 'paused'
        
    if current_status == 'active' and user.get('expiry_date'):
        safe_run_command(['chage', '-E', user['expiry_date'], username])  
        
    return user

def refresh_all_user_status(users):
    updated = False
    for user in users:
        user = sync_user_status(user)  
        user['traffic_display'] = f"{user['used_traffic_gb']:.2f} / {user['quota_gb']:.2f} GB"
        user['status_text'] = "Active"
        user['status_class'] = "bg-green-500"

        if user['quota_gb'] > 0 and user['used_traffic_gb'] >= user['quota_gb']:
            user['status_text'] = "Quota Exceeded"
            user['status_class'] = "bg-red-500"
        elif user['status'] == 'paused':
            user['status_text'] = "Paused"
            user['status_class'] = "bg-yellow-500"
        elif user.get('expiry_date'):
             try:
                expiry_dt = datetime.strptime(user['expiry_date'], '%Y-%m-%d')
                if expiry_dt.date() < datetime.now().date():
                    user['status_text'] = "Expired"
                    user['status_class'] = "bg-red-500"
             except ValueError:
                 pass
        
        updated = True
    if updated:
        save_users(users)
    return users


# --- HTML 模板和渲染 (移除 API Key 卡片，更新版本号) ---

# 仪表盘 HTML (内嵌 - 使用 Tailwind, 增加自定义模态框)
_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS Panel - 仪表盘 V5.7</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .card { transition: all 0.3s ease; }
        .btn-action { transition: all 0.2s ease; }
        .modal { background-color: rgba(0, 0, 0, 0.6); z-index: 999; }
        .modal-content { transition: all 0.3s ease-out; transform: translateY(-50px); }
        .modal.open .modal-content { transform: translateY(0); }
        .api-key-container { word-break: break-all; }
    </style>
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="bg-indigo-600 text-white shadow-lg">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center">
            <h1 class="text-3xl font-bold">WSS 隧道管理面板 V5.7 (审计日志/实时阻断)</h1>
            <button onclick="logout()" class="bg-indigo-800 hover:bg-red-700 px-4 py-2 rounded-lg font-semibold shadow-md btn-action">
                退出登录 (root)
            </button>
        </div>
    </div>

    <div class="max-w-7xl mx-auto p-4 sm:p-6 lg:p-8">
        <!-- Status Message Box -->
        <div id="status-message" class="hidden p-4 mb-4 rounded-xl font-semibold shadow-md" role="alert"></div>
        
        <!-- Stats Grid -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div class="card bg-white p-5 rounded-xl shadow-lg border-l-4 border-indigo-500">
                <h3 class="text-sm font-medium text-gray-500">已管理用户组数</h3>
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
        
        <!-- Audit Log Info (新增审计日志提示) -->
        <div class="card bg-white p-6 rounded-xl shadow-lg mb-8">
            <h3 class="text-xl font-semibold text-gray-800 mb-4 border-b pb-2">审计日志信息</h3>
            <div class="bg-gray-100 p-4 rounded-lg font-mono text-sm overflow-x-auto">
                <p><span class="font-bold">日志路径:</span> /etc/wss-panel/audit.log</p>
                <p><span class="font-bold">日志内容:</span> 记录所有管理操作 (登录、增删用户、IP 封禁/解封)。</p>
                <p><span class="font-bold text-red-600">查看命令:</span> cat /etc/wss-panel/audit.log | tail -n 20</p>
            </div>
        </div>

        <!-- Connection Info Card (保留不变) -->
        <div class="card bg-white p-6 rounded-xl shadow-lg mb-8">
            <h3 class="text-xl font-semibold text-gray-800 mb-4 border-b pb-2">连接信息</h3>
            <div class="bg-gray-100 p-4 rounded-lg font-mono text-sm overflow-x-auto">
                <p><span class="font-bold">服务器地址:</span> {{ host_ip }} (请手动替换为你的公网 IP)</p>
                <p><span class="font-bold">WSS/Stunnel 端口:</span> {{ wss_tls_port }} (WSS) / {{ stunnel_port }} (Stunnel)</p>
                <p><span class="font-bold text-red-600">注意:</span> 所有隧道均使用 SSH 账户和密码连接本地端口 48303。</p>
            </div>
        </div>

        <!-- Add User Card / User List Card (保留不变) -->
        <div class="card bg-white p-6 rounded-xl shadow-lg mb-8">
            <h3 class="text-xl font-semibold text-gray-800 mb-4">新增 WSS 用户组 (SSH 账户)</h3>
            <form id="add-user-form" class="flex flex-wrap items-center gap-4">
                <input type="text" id="new-username" placeholder="用户名 (小写字母/数字/下划线)" 
                        class="flex-1 min-w-[200px] p-2.5 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500"
                        pattern="[a-z0-9_]{3,16}" title="用户名只能包含小写字母、数字和下划线，长度3-16位" required>
                <input type="password" id="new-password" placeholder="密码" 
                        class="flex-1 min-w-[200px] p-2.5 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                <button type="submit" class="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2.5 rounded-lg font-semibold shadow-md btn-action">
                    创建用户组
                </button>
            </form>
        </div>
        
        <div class="card bg-white p-6 rounded-xl shadow-lg">
            <h3 class="text-xl font-semibold text-gray-800 mb-4">用户组列表</h3>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200 user-table">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">用户组 (SSH 账户)</th>
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
                                <button onclick="openActiveIPModal('{{ user.username }}')" 
                                        class="text-xs px-3 py-1 rounded-full font-bold bg-purple-100 text-purple-800 hover:bg-purple-200 btn-action">
                                    活跃 IP
                                </button>
                                <button onclick="openQuotaModal('{{ user.username }}', '{{ user.quota_gb }}', '{{ user.expiry_date }}')" 
                                        class="text-xs px-3 py-1 rounded-full font-bold bg-blue-100 text-blue-800 hover:bg-blue-200 btn-action">
                                    配额/到期
                                </button>
                                <button onclick="openConfirmationModal('{{ user.username }}', '{{ 'pause' if user.status_text == 'Active' else 'active' }}', 'toggleStatus', '{{ '暂停' if user.status_text == 'Active' else '启用' }}')" 
                                        class="text-xs px-3 py-1 rounded-full font-bold {{ 'bg-yellow-100 text-yellow-800 hover:bg-yellow-200' if user.status_text == 'Active' else 'bg-green-100 text-green-800 hover:bg-green-200' }} btn-action">
                                    {{ '暂停' if user.status_text == 'Active' else '启用' }}
                                </button>
                                <button onclick="openConfirmationModal('{{ user.username }}', null, 'resetTraffic', '重置流量')"
                                        class="text-xs px-3 py-1 rounded-full font-bold bg-indigo-100 text-indigo-800 hover:bg-indigo-200 btn-action">
                                    重置流量
                                </button>
                                <button onclick="openConfirmationModal('{{ user.username }}', null, 'deleteUser', '删除')" 
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
    
    <!-- Modals (Quota, Active IP, Confirmation) definitions follow (omitted for brevity) -->
    <!-- ... (All modals remain the same as V5.5) ... -->
    <div id="quota-modal" class="modal fixed inset-0 flex items-center justify-center p-4 hidden">
        <div class="modal-content bg-white rounded-xl shadow-2xl w-full max-w-lg transition-all">
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
    
    <div id="active-ip-modal" class="modal fixed inset-0 flex items-center justify-center p-4 hidden">
        <div class="modal-content bg-white rounded-xl shadow-2xl w-full max-w-xl transition-all">
            <div class="p-6">
                <h3 class="text-xl font-bold mb-4 text-gray-800 border-b pb-2">用户组 <span id="active-ip-modal-title"></span> 的活跃 IP</h3>
                <div id="active-ip-list" class="space-y-3 max-h-96 overflow-y-auto">
                    <p class="text-gray-500">正在加载活跃 IP...</p>
                </div>
                <div class="flex justify-end space-x-3 mt-6">
                    <button type="button" onclick="closeActiveIPModal()" class="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded-lg font-semibold btn-action">
                        关闭
                    </button>
                </div>
            </div>
        </div>
    </div>

    <div id="confirmation-modal" class="modal fixed inset-0 flex items-center justify-center p-4 hidden">
        <div class="modal-content bg-white rounded-xl shadow-2xl w-full max-w-md transition-all">
            <div class="p-6">
                <h3 class="text-xl font-bold mb-4 text-gray-800 border-b pb-2" id="confirm-title">操作确认</h3>
                <p id="confirm-message" class="mb-6 text-gray-700"></p>
                
                <input type="hidden" id="confirm-username">
                <input type="hidden" id="confirm-action">
                <input type="hidden" id="confirm-type">

                <div class="flex justify-end space-x-3">
                    <button type="button" onclick="closeConfirmationModal()" class="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded-lg font-semibold btn-action">
                        取消
                    </button>
                    <button type="button" onclick="executeConfirmation()" class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg font-semibold btn-action" id="confirm-button">
                        确认
                    </button>
                </div>
            </div>
        </div>
    </div>


    <script>
        // --- API KEY UI Logic (已移除) ---
        
        // --- 通用 UI 函数 (其余保留不变) ---
        function showStatus(message, isSuccess) {
            const statusDiv = document.getElementById('status-message');
            statusDiv.textContent = message;
            // FIX: Escaping the \${ to prevent Bash "bad substitution" error
            statusDiv.className = \`\${isSuccess ? 'bg-green-100 text-green-800 border-green-400' : 'bg-red-100 text-red-800 border-red-400'} p-4 mb-4 rounded-xl font-semibold shadow-md block border\`;
            setTimeout(() => { statusDiv.classList.add('hidden'); }, 5000);
        }
        
        function logout() {
            window.location.href = '/logout';
        }

        async function openActiveIPModal(username) {
            document.getElementById('active-ip-modal-title').textContent = username;
            const listDiv = document.getElementById('active-ip-list');
            listDiv.innerHTML = '<p class="text-gray-500">正在加载活跃 IP...</p>';
            document.getElementById('active-ip-modal').classList.remove('hidden');

            try {
                const response = await fetch(\`/api/ips/active?username=\${username}\`);
                const result = await response.json();

                if (response.ok && result.success) {
                    const activeIps = result.active_ips;
                    if (activeIps.length === 0) {
                        listDiv.innerHTML = '<p class="text-green-600 font-semibold">当前没有活跃的连接。</p>';
                        return;
                    }

                    listDiv.innerHTML = activeIps.map(ipInfo => {
                        const isBanned = ipInfo.is_banned;
                        const actionText = isBanned ? '解除封禁' : '封禁';
                        const actionClass = isBanned ? 'bg-green-500 hover:bg-green-600' : 'bg-red-500 hover:bg-red-600';
                        const statusText = isBanned ? '已封禁' : '活跃';
                        const statusClass = isBanned ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800';

                        return \`
                            <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg shadow-sm border border-gray-200">
                                <div class="font-mono text-sm text-gray-800">
                                    <strong>\${ipInfo.ip}</strong> 
                                    <span class="ml-2 px-2 text-xs leading-5 font-semibold rounded-full \${statusClass}">\${statusText}</span>
                                    <span class="text-xs text-gray-500 block sm:inline"> | 连接数: \${ipInfo.count} | 最后活动: \${ipInfo.last_seen_display}</span>
                                </div>
                                <button onclick="toggleIPBan('\${username}', '\${ipInfo.ip}', \${isBanned})"
                                        class="text-xs text-white px-3 py-1 rounded-full font-semibold btn-action \${actionClass}">
                                    \${actionText}
                                </button>
                            </div>
                        \`;
                    }).join('');

                } else {
                    listDiv.innerHTML = \`<p class="text-red-500">获取活跃 IP 失败: \${result.message || '未知错误'}</p>\`;
                }

            } catch (error) {
                listDiv.innerHTML = '<p class="text-red-500">请求失败，请检查面板运行状态。</p>';
            }
        }
        
        function closeActiveIPModal() {
            document.getElementById('active-ip-modal').classList.add('hidden');
        }

        async function toggleIPBan(username, ip, isBanned) {
            const action = isBanned ? 'unblock' : 'block';
            const actionText = isBanned ? '解除封禁' : '封禁';

            try {
                const response = await fetch(\`/api/ips/\${action}\`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, ip })
                });

                const result = await response.json();

                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    openActiveIPModal(username); 
                } else {
                    showStatus(\`\${actionText}失败: \` + result.message, false);
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
        
        function openConfirmationModal(username, action, type, typeText) {
            let message = '';
            let confirmButtonText = '确认';

            if (type === 'toggleStatus') {
                const statusText = action === 'active' ? '启用' : '暂停';
                message = \`确定要 \${statusText} 用户组 \${username} 吗? (\${statusText} 操作将立即终止所有活跃连接)\`;
                confirmButtonText = statusText;
            } else if (type === 'resetTraffic') {
                message = \`确定要将用户组 \${username} 的已用流量清零吗?\`;
                confirmButtonText = typeText;
            } else if (type === 'deleteUser') {
                message = \`确定要永久删除用户组 \${username} 吗? (此操作将终止所有连接并删除系统账户!)\`;
                confirmButtonText = typeText;
            }

            document.getElementById('confirm-title').textContent = \`\${typeText} - \${username}\`;
            document.getElementById('confirm-message').textContent = message;
            document.getElementById('confirm-username').value = username;
            document.getElementById('confirm-action').value = action || '';
            document.getElementById('confirm-type').value = type;
            document.getElementById('confirm-button').textContent = confirmButtonText;

            document.getElementById('confirmation-modal').classList.remove('hidden');
        }

        function closeConfirmationModal() {
            document.getElementById('confirmation-modal').classList.add('hidden');
        }

        function executeConfirmation() {
            const username = document.getElementById('confirm-username').value;
            const action = document.getElementById('confirm-action').value;
            const type = document.getElementById('confirm-type').value;

            closeConfirmationModal(); 

            if (type === 'toggleStatus') {
                toggleUserStatus(username, action);
            } else if (type === 'resetTraffic') {
                resetTraffic(username);
            } else if (type === 'deleteUser') {
                deleteUser(username);
            }
        }
        
        document.getElementById('add-user-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('new-username').value.trim();
            const password = document.getElementById('new-password').value;

            if (!/^[a-z0-9_]{3,16}$/.test(username)) {
                showStatus('用户名格式不正确 (3-16位小写字母/数字/下划线)', false);
                return;
            }

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
        
        async function resetTraffic(username) {
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
    </script>
</body>
</html>
"""

# 渲染函数 (移除 API Key 注入)
def render_dashboard(users):
    """手动渲染 Jinja2 模板字符串."""
    template_env = jinja2.Environment(loader=jinja2.BaseLoader)
    template = template_env.from_string(_DASHBOARD_HTML)
    
    host_ip = request.host.split(':')[0]
    if host_ip in ('127.0.0.1', 'localhost'):
        host_ip = SERVER_IP
        
    context = {
        'users': users,
        'panel_port': PANEL_PORT,
        'wss_http_port': WSS_HTTP_PORT,
        'wss_tls_port': WSS_TLS_PORT,
        'stunnel_port': STUNNEL_PORT,
        'udpgw_port': UDPGW_PORT,
        'host_ip': host_ip,
    }
    return template.render(**context)


# --- Web 路由 (保留不变) ---
@app.route('/', methods=['GET'])
@login_required
def dashboard():
    users = load_users()
    users = refresh_all_user_status(users)
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
                # 记录成功登录
                log_action("LOGIN_SUCCESS", ROOT_USERNAME, "Web UI Login")
                return redirect(url_for('dashboard_decorated'))
            else:
                error = '用户名或密码错误。'
                log_action("LOGIN_FAILED", username, "Wrong credentials")
        else:
            error = '用户名或密码错误。'
            log_action("LOGIN_FAILED", username, "Invalid username attempt")

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
        <h1 class="text-2xl">WSS 管理面板 V5.7</h1>
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
    log_action("LOGOUT_SUCCESS", session.get('username', 'root'), "Web UI Logout")
    session.pop('logged_in', None)
    return redirect(url_for('login'))


# ------------------------------------
# --- 用户管理 API (使用 @login_required + 审计日志) ---
# ------------------------------------

@app.route('/api/users/add', methods=['POST'])
@login_required
def add_user_api():
    """添加用户 (API)"""
    data = request.json
    username = data.get('username')
    password_raw = data.get('password')
    
    if not username or not password_raw:
        return jsonify({"success": False, "message": "缺少用户名或密码"}), 400
    
    if not re.match(r'^[a-z0-9_]{3,16}$', username):
        return jsonify({"success": False, "message": "用户名格式不正确 (3-16位小写字母/数字/下划线)"}), 400


    users = load_users()
    if get_user(username)[0]:
        return jsonify({"success": False, "message": f"用户组 {username} 已存在于面板"}), 409

    # 1. 创建系统用户 
    success, output = safe_run_command(['useradd', '-m', '-s', '/bin/false', username])
    if not success:
        log_action("USER_ADD_FAIL", session.get('username', 'root'), f"Failed to create system user {username}: {output}")
        return jsonify({"success": False, "message": f"创建系统用户失败: {output}"}), 500

    # 2. 设置密码
    chpasswd_input = f"{username}:{password_raw}"
    success, output = safe_run_command(['/usr/sbin/chpasswd'], input=chpasswd_input.encode('utf-8'))
    if not success:
        safe_run_command(['userdel', '-r', username])
        log_action("USER_ADD_FAIL", session.get('username', 'root'), f"Failed to set password for {username}: {output}")
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
        "banned_ips": []
    }
    users.append(new_user)
    save_users(users)
    sync_user_status(new_user)
    
    log_action("USER_ADD_SUCCESS", session.get('username', 'root'), f"Created user {username}")

    return jsonify({"success": True, "message": f"用户组 {username} 创建成功"})

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
        return jsonify({"success": False, "message": f"面板中用户组 {username} 不存在"}), 404

    # 1. 终止用户会话
    kill_user_sessions(username)
    
    # 2. 从 IP 封禁规则中清理该用户的所有 IP
    ip_bans = load_ip_bans()
    if username in ip_bans:
        for ip in ip_bans[username]:
             toggle_iptables_ip_ban(ip, 'unblock')
        ip_bans.pop(username)
        save_ip_bans(ip_bans)


    # 3. 删除系统用户及其主目录
    success, output = safe_run_command(['userdel', '-r', username])
    if not success:
        log_action("USER_DELETE_WARNING", session.get('username', 'root'), f"System user {username} deletion failed (non-fatal): {output}")

    # 4. 从 JSON 数据库中删除记录
    users.pop(index)
    save_users(users)
    
    log_action("USER_DELETE_SUCCESS", session.get('username', 'root'), f"Deleted user {username}")

    return jsonify({"success": True, "message": f"用户组 {username} 已删除，活动会话已终止"})

@app.route('/api/users/reset_traffic', methods=['POST'])
@login_required
def reset_user_traffic_api():
    """将用户的已用流量清零 (API)"""
    data = request.json
    username = data.get('username')

    user, index = get_user(username)
    if not user:
        return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
        
    users = load_users()
    
    old_traffic = users[index].get('used_traffic_gb', 0.0)
    users[index]['used_traffic_gb'] = 0.0
    users[index] = sync_user_status(users[index])
    
    save_users(users)
    log_action("TRAFFIC_RESET", session.get('username', 'root'), f"Reset traffic for {username}. Old: {old_traffic:.2f} GB")
    return jsonify({"success": True, "message": f"用户组 {username} 的已用流量已重置为 0.00 GB"})


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
        return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
        
    users = load_users()
    
    try:
        quota_gb = max(0.0, float(quota_gb))
        if expiry_date:
            datetime.strptime(expiry_date, '%Y-%m-%d')
    except ValueError:
        return jsonify({"success": False, "message": "配额或日期格式不正确"}), 400

    old_quota = users[index].get('quota_gb')
    old_expiry = users[index].get('expiry_date')
    
    users[index]['quota_gb'] = quota_gb
    users[index]['expiry_date'] = expiry_date
    
    users[index] = sync_user_status(users[index])
    
    save_users(users)
    log_action("SETTINGS_UPDATE", session.get('username', 'root'), 
               f"Updated {username}: Quota {old_quota:.2f}->{quota_gb:.2f} GB, Expiry {old_expiry}->{expiry_date}")
    return jsonify({"success": True, "message": f"用户组 {username} 设置已更新"})
    
@app.route('/api/users/status', methods=['POST'])
@login_required
def toggle_user_status_api():
    """启用或暂停用户 (API)"""
    data = request.json
    username = data.get('username')
    action = data.get('action') # 'active' or 'pause'

    user, index = get_user(username)
    if not user:
        return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
        
    users = load_users()
    
    if action == 'active':
        users[index]['status'] = 'active'
        log_action("USER_TOGGLE", session.get('username', 'root'), f"Set user {username} to ACTIVE")
    elif action == 'pause':
        users[index]['status'] = 'paused'
        log_action("USER_TOGGLE", session.get('username', 'root'), f"Set user {username} to PAUSED (Locked)")
    else:
        return jsonify({"success": False, "message": "无效的操作"}), 400
        
    users[index] = sync_user_status(users[index])
    save_users(users)
    
    return jsonify({"success": True, "message": f"用户组 {username} 状态已更新为 {action}"})


@app.route('/api/users/update_traffic', methods=['POST'])
# 此 API 无需登录，供本地流量同步脚本调用 (假定其通过 127.0.0.1 访问，且由 root 运行)
def update_user_traffic_api():
    """内部工具用于更新用户流量的 API"""
    # 限制此API只能从本地调用，增加安全性
    if request.remote_addr != '127.0.0.1' and request.remote_addr != '::1':
        return jsonify({"success": False, "message": "Access denied"}), 403
        
    data = request.json
    username = data.get('username')
    used_traffic_gb = data.get('used_traffic_gb')

    if not username or used_traffic_gb is None:
        return jsonify({"success": False, "message": "缺少用户名或流量数据"}), 400

    user, index = get_user(username)
    if not user:
        return jsonify({"success": False, "message": f"用户 {username} 不存在"}), 404

    users = load_users()
    
    users[index]['used_traffic_gb'] = max(0.0, float(used_traffic_gb))
    users[index]['last_check'] = time.time()
    
    users[index] = sync_user_status(users[index])
    
    save_users(users)
    return jsonify({"success": True, "message": f"用户 {username} 流量已更新为 {used_traffic_gb:.2f} GB"})


# ------------------------------------
# --- IP/会话管理 API (使用 @login_required + 审计日志) ---
# ------------------------------------

@app.route('/api/ips/check', methods=['POST'])
# 此 API 无需登录，供 WSS 核心代理调用 (假定其通过 127.0.0.1 访问，且由 root 运行)
def check_ip_api():
    """WSS 代理调用此 API 检查客户端 IP 是否被封禁 (作为二次检查)."""
    # 限制此API只能从本地调用，增加安全性
    if request.remote_addr != '127.0.0.1' and request.remote_addr != '::1':
        return jsonify({"success": False, "message": "Access denied"}), 403
        
    data = request.json
    client_ip = data.get('ip')
    
    if not client_ip:
        return jsonify({"success": False, "message": "缺少 IP"}), 400

    ip_bans = load_ip_bans()
    
    is_banned = False
    for banned_ips in ip_bans.values():
        if client_ip in banned_ips:
            is_banned = True
            break
            
    return jsonify({"success": True, "is_banned": is_banned})

@app.route('/api/ips/report', methods=['POST'])
# 此 API 无需登录，供 WSS 核心代理调用 (假定其通过 127.0.0.1 访问，且由 root 运行)
def report_ip_api():
    """WSS 代理报告 IP 连接/断开活动."""
    # 限制此API只能从本地调用，增加安全性
    if request.remote_addr != '127.0.0.1' and request.remote_addr != '::1':
        return jsonify({"success": False, "message": "Access denied"}), 403
        
    data = request.json
    client_ip = data.get('ip')
    action = data.get('action') # 'connect' or 'disconnect'
    
    if not client_ip or action not in ('connect', 'disconnect'):
        return jsonify({"success": False, "message": "无效的参数"}), 400

    active_ips = load_active_ips()
    now = time.time()
    
    if action == 'connect':
        if client_ip in active_ips:
            active_ips[client_ip]['count'] = active_ips[client_ip].get('count', 0) + 1
            active_ips[client_ip]['last_seen'] = now
        else:
            active_ips[client_ip] = {
                'count': 1, 
                'last_seen': now,
                'user': 'N/A'
            }
            
    elif action == 'disconnect':
        if client_ip in active_ips:
            active_ips[client_ip]['count'] = active_ips[client_ip].get('count', 1) - 1
            active_ips[client_ip]['last_seen'] = now
            if active_ips[client_ip]['count'] <= 0:
                active_ips.pop(client_ip)
                
    save_active_ips(active_ips)
    return jsonify({"success": True})


@app.route('/api/ips/block', methods=['POST'])
@login_required
def block_ip_api():
    """管理员封禁指定用户组下的指定 IP (Web UI 调用)."""
    data = request.json
    username = data.get('username')
    ip = data.get('ip')

    if not username or not ip:
        return jsonify({"success": False, "message": "缺少用户名或 IP"}), 400

    ip_bans = load_ip_bans()
    user, index = get_user(username)
    
    if not user:
        return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
    
    if username not in ip_bans:
        ip_bans[username] = []
        
    if ip not in ip_bans[username]:
        ip_bans[username].append(ip)
        save_ip_bans(ip_bans)
        
    # 1. 实时添加到 IPTABLES (核心改进)
    success_iptables, iptables_output = toggle_iptables_ip_ban(ip, 'block')
    
    # 2. 清理活跃 IP 记录 (用于 UI 显示)
    active_ips = load_active_ips()
    if ip in active_ips:
        active_ips.pop(ip)
        save_active_ips(active_ips)
        
    if success_iptables:
        log_action("IP_BLOCK_SUCCESS", session.get('username', 'root'), f"Blocked IP {ip} for user {username}")
        return jsonify({"success": True, "message": f"IP {ip} 已被封禁 (实时生效)，并从活跃列表中移除。"})
    else:
        log_action("IP_BLOCK_WARNING", session.get('username', 'root'), 
                   f"Blocked IP {ip} in DB for user {username}, but IPTables failed: {iptables_output}")
        return jsonify({"success": True, "message": f"IP {ip} 已被封禁 (面板记录已更新)，但实时防火墙操作失败。"})

@app.route('/api/ips/unblock', methods=['POST'])
@login_required
def unblock_ip_api():
    """管理员解封指定用户组下的指定 IP (Web UI 调用)."""
    data = request.json
    username = data.get('username')
    ip = data.get('ip')

    if not username or not ip:
        return jsonify({"success": False, "message": "缺少用户名或 IP"}), 400

    ip_bans = load_ip_bans()
    
    if username in ip_bans and ip in ip_bans[username]:
        ip_bans[username].remove(ip)
        save_ip_bans(ip_bans)
    
    # 1. 实时从 IPTABLES 移除 (核心改进)
    success_iptables, iptables_output = toggle_iptables_ip_ban(ip, 'unblock')
    
    if success_iptables:
        log_action("IP_UNBLOCK_SUCCESS", session.get('username', 'root'), f"Unblocked IP {ip} for user {username}")
        return jsonify({"success": True, "message": f"IP {ip} 已解除封禁 (实时生效)。"})
    else:
        log_action("IP_UNBLOCK_WARNING", session.get('username', 'root'), 
                   f"Unblocked IP {ip} in DB for user {username}, but IPTables failed: {iptables_output}")
        return jsonify({"success": True, "message": f"IP {ip} 已解除封禁 (面板记录已更新)，但实时防火墙操作失败。"})

@app.route('/api/ips/active', methods=['GET'])
@login_required
def get_active_ips_api():
    """获取指定用户组的活跃 IP 列表."""
    username = request.args.get('username')
    
    if not username:
        return jsonify({"success": False, "message": "缺少用户名"}), 400

    active_ips = load_active_ips()
    ip_bans = load_ip_bans()
    banned_ips_for_user = ip_bans.get(username, [])
    
    filtered_ips = []
    
    all_ips = set(active_ips.keys()) | set(banned_ips_for_user)

    for ip in all_ips:
        data = active_ips.get(ip, {'count': 0, 'last_seen': 0})

        last_seen_display = 'N/A'
        if data['last_seen'] > 0:
             last_seen_dt = datetime.fromtimestamp(data['last_seen'])
             last_seen_display = last_seen_dt.strftime('%H:%M:%S')
        
        is_banned = ip in banned_ips_for_user
        
        filtered_ips.append({
            'ip': ip,
            'count': data['count'],
            'last_seen_display': last_seen_display,
            'is_banned': is_banned
        })
        
    filtered_ips.sort(key=lambda x: (x['count'], x['is_banned']), reverse=True)
    
    return jsonify({"success": True, "active_ips": filtered_ips})


if __name__ == '__main__':
    print(f"WSS Panel running on port {PANEL_PORT}")
    app.run(host='0.0.0.0', port=int(PANEL_PORT), debug=False)
EOF

chmod +x /usr/local/bin/wss_panel.py

# 确保 SERVER_IP 变量在 systemd 服务中可用
export SERVER_IP

# --- 5. 创建 WSS 面板 systemd 服务 (ExecStart 更新为 VENV 路径) ---
if [ ! -f "/etc/systemd/system/wss_panel.service" ]; then
tee /etc/systemd/system/wss_panel.service > /dev/null <<EOF
[Unit]
Description=WSS User Management Panel (Flask V5.7)
After=network.target

[Service]
Type=simple
Environment=SERVER_IP=$SERVER_IP
ExecStart=$PYTHON_VENV_PATH /usr/local/bin/wss_panel.py
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
systemctl enable wss_panel || true
systemctl restart wss_panel
echo "WSS 管理面板 V5.7 已启动/重启，端口 $PANEL_PORT"
echo "----------------------------------"

# --- 6. 部署 IPTABLES 流量监控和同步脚本 ---

# 1. IPTABLES 链设置函数 (保留不变)
setup_iptables_chains() {
    echo "==== 配置 IPTABLES 流量统计和实时阻断链 ===="
    
    BLOCK_CHAIN="WSS_IP_BLOCK"
    
    # 1. 清理旧链和规则 (确保幂等性)
    iptables -D INPUT -j WSS_USER_TRAFFIC_IN 2>/dev/null || true
    iptables -D OUTPUT -j WSS_USER_TRAFFIC_OUT 2>/dev/null || true
    iptables -F WSS_USER_TRAFFIC_IN 2>/dev/null || true
    iptables -X WSS_USER_TRAFFIC_IN 2>/dev/null || true
    iptables -F WSS_USER_TRAFFIC_OUT 2>/dev/null || true
    iptables -X WSS_USER_TRAFFIC_OUT 2>/dev/null || true

    iptables -D INPUT -j $BLOCK_CHAIN 2>/dev/null || true
    iptables -F $BLOCK_CHAIN 2>/dev/null || true
    iptables -X $BLOCK_CHAIN 2>/dev/null || true

    # 2. 创建新链
    iptables -N WSS_USER_TRAFFIC_IN 2>/dev/null || true
    iptables -N WSS_USER_TRAFFIC_OUT 2>/dev/null || true
    iptables -N $BLOCK_CHAIN 2>/dev/null || true

    # 3. 将新链连接到 INPUT 和 OUTPUT
    iptables -I INPUT 1 -j $BLOCK_CHAIN
    iptables -I INPUT 2 -j WSS_USER_TRAFFIC_IN
    iptables -I OUTPUT 1 -j WSS_USER_TRAFFIC_OUT
    
    # 4. 保存规则
    if command -v iptables-save >/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        echo "IPTABLES 规则已保存到 /etc/iptables/rules.v4。"
    fi

    echo "IPTABLES 流量统计和实时阻断链创建/清理完成，已连接到 INPUT/OUTPUT。"
}

# 2. 流量同步 Python 脚本 (新增 IP 清理逻辑)
tee /usr/local/bin/wss_traffic_sync.py > /dev/null <<EOF
# -*- coding: utf-8 -*-
import json
import os
import subprocess
import time
import requests 
from datetime import datetime

# --- Configuration ---
USER_DB_PATH = "/etc/wss-panel/users.json"
IP_ACTIVE_DB_PATH = "/etc/wss-panel/ip_active.json"
PANEL_PORT = "$PANEL_PORT"
API_URL_UPDATE = f"http://127.0.0.1:{PANEL_PORT}/api/users/update_traffic"
IPTABLES_CHAIN_IN = "WSS_USER_TRAFFIC_IN"
IPTABLES_CHAIN_OUT = "WSS_USER_TRAFFIC_OUT"

# IP 不活跃阈值：3600秒 = 1小时
STALE_IP_THRESHOLD = 3600 

# --- Utility Functions ---
def safe_run_command(command, input_data=None):
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

def load_data(path, default_value):
    if not os.path.exists(path):
        return default_value
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return default_value

def save_data(data, path):
    try:
        with open(path, 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except Exception:
        return False

def load_users(): return load_data(USER_DB_PATH, [])
def load_active_ips(): return load_data(IP_ACTIVE_DB_PATH, {})
def save_active_ips(active_ips): return save_data(active_ips, IP_ACTIVE_DB_PATH)

def bytes_to_gb(bytes_val):
    return bytes_val / (1024 * 1024 * 1024)

# --- IP 清理函数 (新增) ---
def clean_stale_ips():
    """清理 ip_active.json 中超过 STALE_IP_THRESHOLD 秒不活跃的 IP 记录."""
    active_ips = load_active_ips()
    now = time.time()
    updated = False
    
    ips_to_delete = []
    for ip, data in active_ips.items():
        if (now - data.get('last_seen', 0)) > STALE_IP_THRESHOLD:
            ips_to_delete.append(ip)
            
    for ip in ips_to_delete:
        del active_ips[ip]
        updated = True
        
    if updated:
        save_active_ips(active_ips)
        # print(f"Cleaned {len(ips_to_delete)} stale IP records.")


# --- Core Logic (IPTables Setup and Reading) ---

def setup_iptables_rules(users):
    """根据用户列表设置/更新 iptables 流量统计规则 (清空链并重建规则)."""
    
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
    """读取 iptables 计数器并调用 Flask API 更新流量."""
    users = load_users()
    if not users:
        return

    # 1. 确保 IPTABLES 流量规则是最新的
    setup_iptables_rules(users)

    # 2. 读取 IPTABLES 计数器
    success, output = safe_run_command(['iptables-save', '-c'])
    if not success:
        return

    traffic_data = {}
    
    uid_to_username = {}
    for user in users:
        success_uid, uid = safe_run_command(['id', '-u', user['username']])
        if success_uid and uid.isdigit():
            uid_to_username[uid] = user['username']

    for line in output.split('\n'):
        if ('owner' in line) and ('ACCEPT' in line):
            try:
                parts = line.split('[')[1].split(']')
                total_bytes = int(parts[0].split(':')[1])
                uid = line.split('--uid-owner')[1].split()[0]
                
                if uid not in uid_to_username:
                    continue

                username = uid_to_username[uid]
                
                if username not in traffic_data:
                    traffic_data[username] = {'in': 0, 'out': 0, 'uid': uid}
                
                if IPTABLES_CHAIN_IN in line and 'dport 48303' in line:
                    traffic_data[username]['in'] += total_bytes
                elif IPTABLES_CHAIN_OUT in line and 'sport 48303' in line:
                    traffic_data[username]['out'] += total_bytes
                    
            except Exception:
                continue

    # 3. 计算并上报流量，然后清零计数器
    for user in users:
        username = user['username']
        current_used_gb = user.get('used_traffic_gb', 0.0)
        
        if username not in traffic_data:
             continue
        
        in_bytes = traffic_data[username].get('in', 0)
        out_bytes = traffic_data[username].get('out', 0)
        total_transfer_bytes = in_bytes + out_bytes
        
        new_used_gb = current_used_gb + bytes_to_gb(total_transfer_bytes)
        rounded_gb = round(new_used_gb, 2)
        uid = traffic_data[username]['uid']
        
        payload_json = {
            "username": username,
            "used_traffic_gb": rounded_gb
        }

        try:
            response = requests.post(API_URL_UPDATE, json=payload_json, timeout=3)
            response_json = response.json()
            
            if response.status_code == 200 and response_json.get('success'):
                # 成功上报后清零计数器
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
            
        except requests.exceptions.RequestException:
            pass


if __name__ == '__main__':
    # 步骤 1: 清理不活跃 IP 记录
    clean_stale_ips()
    # 步骤 2: 读取和报告流量
    read_and_report_traffic()
EOF

chmod +x /usr/local/bin/wss_traffic_sync.py

# 3. 创建定时任务 (Cron Job) 运行流量同步脚本 (ExecStart 更新为 VENV 路径)
echo "==== 设置 Cron 定时任务 (每 5 分钟同步一次流量, 使用 VENV 隔离环境) ===="

mkdir -p /etc/cron.d

tee /etc/cron.d/wss-traffic > /dev/null <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# 每 5 分钟运行一次 Python 流量同步和 IP 清理脚本，使用 VENV 隔离环境
*/5 * * * * root $PYTHON_VENV_PATH /usr/local/bin/wss_traffic_sync.py
EOF

chmod 0644 /etc/cron.d/wss-traffic

systemctl enable cron || true
systemctl start cron || true

echo "流量同步和 IP 清理脚本已安装，并将每 5 分钟自动运行。"
echo "----------------------------------"

# 4. 立即运行 IPTABLES 链设置
setup_iptables_chains


# --- 7. SSHD 安全配置 (保留不变) ---
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_SUFFIX=".bak.wss$(date +%s)"
SSHD_SERVICE=$(systemctl list-units --full -all | grep -E "sshd\.service|ssh\.service" | grep -v "not-found" | head -n 1 | awk '{print $1}' | cut -d'.' -f1 || echo "sshd")

echo "==== 配置 SSHD 安全策略 ===="
cp -a "$SSHD_CONFIG" "${SSHD_CONFIG}${BACKUP_SUFFIX}"
echo "SSHD 配置已备份到 ${SSHD_CONFIG}${BACKUP_SUFFIX}"

sed -i '/# WSS_TUNNEL_BLOCK_START/,/# WSS_TUNNEL_BLOCK_END/d' "$SSHD_CONFIG"

cat >> "$SSHD_CONFIG" <<EOF

# WSS_TUNNEL_BLOCK_START -- managed by deploy_wss_panel.sh
Match Address 127.0.0.1,::1
    PasswordAuthentication yes
    PermitTTY no
    X11Forwarding no
    AllowTcpForwarding yes
    ForceCommand /bin/false
# WSS_TUNNEL_BLOCK_END -- managed by deploy_wss_panel.sh

EOF

chmod 600 "$SSHD_CONFIG"

echo "重新加载并重启 ssh 服务 ($SSHD_SERVICE)"
systemctl daemon-reload
systemctl restart "$SSHD_SERVICE"
echo "SSHD 配置更新完成。"
echo "----------------------------------"

# 清理敏感变量
unset PANEL_ROOT_PASS_RAW

echo "=================================================="
echo "✅ WSS 管理面板部署完成！ (V5.7 审计日志/实时阻断生效)"
echo "=================================================="
echo ""
echo "🔥 基础设施已启动。面板管理操作已启用审计日志。"
echo "🌐 审计日志路径: /etc/wss-panel/audit.log"
echo ""
echo "--- 访问信息 ---"
echo "Web 面板地址: http://$SERVER_IP:$PANEL_PORT"
echo "Web 面板用户名: root"
echo "Web 面板密码: [您刚才设置的密码]"
echo ""
echo "--- 端口状态检查 ---"
echo "WSS (HTTP/WebSocket): $WSS_HTTP_PORT"
check_port "$WSS_HTTP_PORT"
echo "WSS (TLS/WebSocket): $WSS_TLS_PORT"
check_port "$WSS_TLS_PORT"
echo "Stunnel (TLS 隧道): $STUNNEL_PORT"
check_port "$STUNNEL_PORT"
echo "面板端口 (Flask): $PANEL_PORT"
check_port "$PANEL_PORT"

echo ""
echo "--- 故障排查/日志命令 ---"
echo "WSS 核心代理状态: sudo systemctl status wss -l"
echo "Web 面板状态: sudo systemctl status wss_panel -l"
echo "审计日志命令: cat /etc/wss-panel/audit.log | tail -n 20"
echo "=================================================="
