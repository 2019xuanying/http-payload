#!/usr/bin/env bash
set -eu

# =======================================================
# WSS 隧道/Stunnel/管理面板部署脚本 V6.2 - 修复 Payload 阻塞和超时
# 变更: 优化 WSS 核心代理的异步读取循环，增强对分块 Payload 的兼容性。
# =======================================================

# --- 全局变量和工具函数 ---
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
        echo " (Cannot check status, ss or netstat found)"
    fi
}
export -f check_port

get_server_ip() {
    echo "尝试获取服务器公网 IP..."
    SERVER_IP=$(curl -s --connect-timeout 2 ip.sb 2>/dev/null)
    [ -z "$SERVER_IP" ] && SERVER_IP=$(curl -s --connect-timeout 2 ifconfig.me 2>/dev/null)
    [ -z "$SERVER_IP" ] && SERVER_IP=$(ip a | grep 'inet ' | grep -v '127.0.0.1' | head -n 1 | awk '{print $2}' | cut -d/ -f1)
    [ -z "$SERVER_IP" ] && SERVER_IP='[SERVER_IP]'
    echo "$SERVER_IP"
}
SERVER_IP=$(get_server_ip)
echo "检测到的服务器 IP: $SERVER_IP"

VENV_PATH="/opt/wss_venv"
PYTHON_VENV_PATH="$VENV_PATH/bin/python3"


# --- 1. 端口和面板密码配置 ---
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
    PANEL_ROOT_PASS_HASH=$(echo -n "$PANEL_ROOT_PASS_RAW" | sha256sum | awk '{print $1}')
    break
done

echo "----------------------------------"
echo "==== 系统更新与依赖安装 (VENV 隔离) ===="
apt update -y
# 移除了编译依赖
apt install -y python3 python3-pip python3-venv wget curl git net-tools openssl stunnel4 iptables-persistent procps cmake build-essential # 确保编译环境存在

echo "创建 Python 虚拟环境于 $VENV_PATH"
mkdir -p "$VENV_PATH"
python3 -m venv "$VENV_PATH"

echo "在 VENV 中安装 Python 依赖..."
"$PYTHON_VENV_PATH" -m pip install flask jinja2 requests httpx psutil

echo "依赖安装完成，使用隔离环境路径: $VENV_PATH"
echo "----------------------------------"


# --- 2. WSS 核心代理脚本 (目标端口 24355) ---
echo "==== 安装 WSS 核心代理脚本 (/usr/local/bin/wss) ===="
tee /usr/local/bin/wss > /dev/null <<EOF
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio
import ssl
import sys
import os
import httpx 

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

DEFAULT_TARGET = ('127.0.0.1', 24355) # **已统一为 24355**
BUFFER_SIZE = 65536
TIMEOUT = 3600
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'
PANEL_PORT = os.environ.get('WSS_PANEL_PORT', '54321')
API_URL_CHECK = f"http://127.0.0.1:{PANEL_PORT}/api/ips/check"

FIRST_RESPONSE = b'HTTP/1.1 200 OK\\r\\nContent-Type: text/plain\\r\\nContent-Length: 2\\r\\n\\r\\nOK\\r\\n\\r\\n'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\n\\r\\n'
FORBIDDEN_RESPONSE = b'HTTP/1.1 403 Forbidden\\r\\nContent-Length: 0\\r\\n\\r\\n'

http_client = httpx.AsyncClient(timeout=3.0) 

async def check_ip_status(client_ip):
    """检查 IP 是否被面板封禁."""
    try:
        response = await http_client.post(
            API_URL_CHECK,
            json={'ip': client_ip}
        )
        if response.status_code == 200:
            result = response.json()
            return not result.get('is_banned', False)
        # 如果 API 失败，为安全起见默认允许
        return True
    except Exception:
        return True

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    peer = writer.get_extra_info('peername')
    client_ip = peer[0]
    
    is_allowed = await check_ip_status(client_ip)
    if not is_allowed:
        writer.write(FORBIDDEN_RESPONSE)
        await writer.drain()
        writer.close()
        # await writer.wait_closed() # 移除可能导致阻塞的调用
        return

    forwarding_started = False
    full_request = b''

    try:
        while not forwarding_started:
            # 缩短读取超时，避免在等待下一个分块时长时间阻塞
            data = await asyncio.wait_for(reader.read(BUFFER_SIZE), timeout=5) 
            if not data:
                break
            
            full_request += data
            
            header_end_index = full_request.find(b'\r\n\r\n')
            
            if header_end_index == -1:
                # 收到不完整的头部，发送 200 OK 后清除缓冲区，继续读取
                writer.write(FIRST_RESPONSE) 
                await writer.drain()
                full_request = b''
                continue

            headers_raw = full_request[:header_end_index]
            data_to_forward = full_request[header_end_index + 4:]
            
            headers = headers_raw.decode(errors='ignore') 

            is_websocket_request = 'Upgrade: websocket' in headers or 'Connection: Upgrade' in headers or 'GET-RAY' in headers
            
            if is_websocket_request:
                # 握手成功
                writer.write(SWITCH_RESPONSE)
                await writer.drain()
                forwarding_started = True
            else:
                # 非 WebSocket 请求，发送 200 OK 并关闭连接（或者继续尝试下一个分块，这里选择继续读取）
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
                    # 使用较长的 PIPE 超时
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
        try:
            # 确保客户端连接关闭
            writer.close()
            # await writer.wait_closed() # 移除可能导致阻塞的调用
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

# 创建 WSS systemd 服务
tee /etc/systemd/system/wss.service > /dev/null <<EOF
[Unit]
Description=WSS Python Proxy (V6.2 Payload Fix)
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
echo "WSS 核心代理 (V6.2 Payload Fix) 已启动/重启，HTTP端口 $WSS_HTTP_PORT, TLS端口 $WSS_TLS_PORT"
echo "----------------------------------"


# --- 3. Stunnel4, UDPGW (统一目标端口 24355) ---
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
connect = 127.0.0.1:24355 # **已统一为 24355**
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
EOF

systemctl enable stunnel4 || true
systemctl restart stunnel4 || true
echo "Stunnel4 配置已更新并重启，端口 $STUNNEL_PORT"
echo "----------------------------------"

echo "==== 检查/安装 UDPGW ===="
if [ ! -f "/root/badvpn/badvpn-build/udpgw/badvpn-udpgw" ]; then
    echo "UDPGW 二进制文件不存在，开始编译..."
    if [ ! -d "/root/badvpn" ]; then
        echo "克隆 badvpn 仓库..."
        # 注意: 依赖于 cmake/build-essential 已经安装
        apt install -y cmake build-essential || true 
        git clone https://github.com/ambrop72/badvpn.git /root/badvpn || { echo "ERROR: Git clone failed."; exit 1; }
    fi
    mkdir -p /root/badvpn/badvpn-build
    cd /root/badvpn/badvpn-build
    
    if cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 ; then
        if make -j$(nproc); then
            echo "UDPGW 编译成功。"
        else
            echo "ERROR: UDPGW make failed."
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


# --- 4. 安装 WSS 用户管理面板 (V6.2) ---
echo "==== 部署 WSS 用户管理面板 (Python/Flask) V6.2 ===="
PANEL_DIR="/etc/wss-panel"
USER_DB="$PANEL_DIR/users.json"
IP_BANS_DB="$PANEL_DIR/ip_bans.json" 
IP_ACTIVE_DB="$PANEL_DIR/ip_active.json" 
ROOT_HASH_FILE="$PANEL_DIR/root_hash.txt" 

mkdir -p "$PANEL_DIR"

[ ! -f "$IP_BANS_DB" ] && echo "{}" > "$IP_BANS_DB"
[ ! -f "$IP_ACTIVE_DB" ] && echo "{}" > "$IP_ACTIVE_DB"
# 面板密码哈希文件：如果不存在，则写入初始哈希
if [ ! -f "$ROOT_HASH_FILE" ]; then
    echo "$PANEL_ROOT_PASS_HASH" > "$ROOT_HASH_FILE"
fi

if [ ! -f "$USER_DB" ]; then
    echo "[]" > "$USER_DB"
else
    # 简化升级逻辑，只保留并发限制和过期日期
    python3 -c "
import json
import time
import os
USER_DB_PATH = \"$USER_DB\"
def upgrade_users():
    try:
        if not os.path.exists(USER_DB_PATH): return
        with open(USER_DB_PATH, 'r') as f: users = json.load(f)
    except Exception:
        print('Error loading users, skipping upgrade.')
        return
    updated = False
    for user in users:
        if 'banned_ips' not in user: user['banned_ips'] = []; updated = True
        if 'status' not in user: 
            user['status'] = 'active'; user['expiry_date'] = ''
            updated = True
        # 移除流量相关的字段
        for field in ['quota_gb', 'used_traffic_gb', 'last_check']:
            if field in user: del user[field]; updated = True
        if 'max_connections' not in user:
            user['max_connections'] = 3
            updated = True
    if updated:
        with open(USER_DB_PATH, 'w') as f: json.dump(users, f, indent=4)
        print('User database structure upgraded.')
upgrade_users()
"
fi

# 嵌入 Python 面板代码
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
import psutil 

# --- 配置 ---
PANEL_DIR = "/etc/wss-panel"
USER_DB_PATH = os.path.join(PANEL_DIR, "users.json")
IP_BANS_DB_PATH = os.path.join(PANEL_DIR, "ip_bans.json")
IP_ACTIVE_DB_PATH = os.path.join(PANEL_DIR, "ip_active.json")
AUDIT_LOG_PATH = os.path.join(PANEL_DIR, "audit.log")
ROOT_HASH_FILE = os.path.join(PANEL_DIR, "root_hash.txt")

ROOT_USERNAME = "root"
MAX_CONN_DEFAULT = 3 
SSH_TARGET_PORT = 24355 # **已统一为 24355**

PANEL_PORT = "$PANEL_PORT"
WSS_HTTP_PORT = "$WSS_HTTP_PORT"
WSS_TLS_PORT = "$WSS_TLS_PORT"
STUNNEL_PORT = "$STUNNEL_PORT"
UDPGW_PORT = "$UDPGW_PORT"

SERVER_IP = os.environ.get('SERVER_IP', '[Your Server IP]')

app = Flask(__name__)
app.secret_key = os.urandom(24).hex() # 每次重启会变化，但无碍

# --- 数据库操作 / 日志 / 认证 / 系统工具函数 ---
def load_data(path, default_value):
    if not os.path.exists(path): return default_value
    try:
        with open(path, 'r') as f: return json.load(f)
    except Exception as e:
        print(f"Error loading {path}: {e}")
        return default_value

def load_root_hash():
    if not os.path.exists(ROOT_HASH_FILE):
        return None
    try:
        with open(ROOT_HASH_FILE, 'r') as f:
            return f.read().strip()
    except Exception:
        return None

def save_root_hash(new_hash):
    try:
        with open(ROOT_HASH_FILE, 'w') as f:
            f.write(new_hash + '\n')
        return True
    except Exception as e:
        print(f"Error saving root hash: {e}")
        return False

def save_data(data, path):
    try:
        with open(path, 'w') as f: json.dump(data, f, indent=4)
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
        if user.get('username') == username: return user, i
    return None, -1

def log_action(action_type, username, details=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    operator_ip = request.remote_addr if request else "127.0.0.1 (System)"
    log_entry = f"[{timestamp}] [USER:{username}] [IP:{operator_ip}] ACTION:{action_type} DETAILS: {details}\n"
    try:
        with open(AUDIT_LOG_PATH, 'a') as f: f.write(log_entry)
    except Exception as e:
        print(f"Error writing to audit log: {e}")

def get_recent_logs(n=20):
    try:
        if not os.path.exists(AUDIT_LOG_PATH):
            return ["日志文件不存在。"]
        # 使用 tail -n 命令获取最后 n 行
        command = ['tail', '-n', str(n), AUDIT_LOG_PATH]
        # 注意: 如果日志文件不存在，subprocess.run 可能会失败。try/except block 应该能处理。
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
        return result.stdout.decode('utf-8').strip().split('\n')
    except Exception:
        return ["读取日志失败或日志文件为空。"]

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session.get('logged_in'):
            log_action("LOGIN_ATTEMPT", "N/A", f"Access denied to {request.path}")
            return redirect(url_for('login'))  
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__ + "_decorated"
    return decorated_function

def safe_run_command(command, input_data=None):
    """
    安全运行系统命令。
    FIX: 使用 input 关键字参数来传递标准输入数据，以避免 TypeError。
    """
    try:
        result = subprocess.run(
            command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            input=input_data, 
            timeout=5
        )
        return True, result.stdout.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        return False, e.stderr.decode('utf-8').strip()
    except Exception as e:
        return False, str(e)
        
def toggle_iptables_ip_ban(ip, action):
    """在 filter 表的 WSS_IP_BLOCK 链中添加或移除 IP 阻断规则，并保存规则。"""
    chain = "WSS_IP_BLOCK"
    if action == 'block':
        safe_run_command(['iptables', '-D', chain, '-s', ip, '-j', 'DROP']) # 先删除可能存在的，防止重复
        command = ['iptables', '-I', chain, '1', '-s', ip, '-j', 'DROP']
    elif action == 'unblock':
        command = ['iptables', '-D', chain, '-s', ip, '-j', 'DROP']
    else: return False, "Invalid action"
    
    success, output = safe_run_command(command)
    
    if success or 'Bad rule' in output or 'No chain/target/match by that name' in output:
        try:
            # 尝试保存规则
            with open('/etc/iptables/rules.v4', 'w') as f:
                subprocess.run(['iptables-save'], stdout=f, check=True, timeout=3)
            return True, "IPTables rule updated and saved."
        except Exception:
            return True, "IPTables rule updated but failed to save persistence file."
    
    return success, output

def kill_user_sessions(username):
    """终止给定用户名的所有活跃 SSH 会话."""
    safe_run_command(['pkill', '-u', username])

# --- 核心用户状态管理函数 ---

def sync_user_status(user):
    """根据到期日和并发限制同步系统账户状态 (usermod -L/-U, chage -E)."""
    username = user['username']
    
    is_expired_or_exceeded = False
    
    # 检查到期日
    if user['expiry_date']:
        try:
            expiry_dt = datetime.strptime(user['expiry_date'], '%Y-%m-%d')
            if expiry_dt.date() < datetime.now().date(): is_expired_or_exceeded = True
        except ValueError: print(f"Invalid expiry_date format for {username}: {user['expiry_date']}")
            
    # 检查并发限制
    current_conn_count = 0
    max_connections = user.get('max_connections', MAX_CONN_DEFAULT)
    is_over_limit = False
    
    try:
        success, uid = safe_run_command(['id', '-u', username])
        if success and uid.isdigit():
            # 检查用户 uid 拥有的所有到 24355 的 established TCP 连接
            result = subprocess.run(['ss', '-t', '-n', '-o', 'state', 'established', 'dport', str(SSH_TARGET_PORT), 'user', str(uid)], capture_output=True, text=True, timeout=2)
            # ss 命令输出的第一行是标题，所以要减去 1
            current_conn_count = len(result.stdout.strip().split('\n')) - 1 if result.stdout.strip() and len(result.stdout.strip().split('\n')) > 1 else 0
    except Exception:
        current_conn_count = 0

    if max_connections > 0 and current_conn_count > max_connections:
        is_over_limit = True

    should_be_paused = (user.get('status') == 'paused') or is_expired_or_exceeded or is_over_limit
    
    system_locked = False
    success_status, output_status = safe_run_command(['passwd', '-S', username])
    # ' L ' 表示 Locked (锁定)
    if success_status and output_status and ' L ' in output_status: system_locked = True
        
    if not should_be_paused and system_locked:
        # 启用用户 (解锁)
        safe_run_command(['usermod', '-U', username])
        if user['expiry_date']: safe_run_command(['chage', '-E', user['expiry_date'], username]) 
        else: safe_run_command(['chage', '-E', '', username])
        user['status'] = 'active'
        
    elif should_be_paused and not system_locked:
        # 暂停用户 (锁定)
        safe_run_command(['usermod', '-L', username])
        safe_run_command(['chage', '-E', '1970-01-01', username]) # 强制设置为过期
        kill_user_sessions(username)
        user['status'] = 'paused'
        
    user['current_conn_count'] = current_conn_count
    user['max_conn'] = max_connections
    user['is_over_limit'] = is_over_limit
        
    return user

def refresh_all_user_status(users):
    """更新所有用户状态并生成显示所需的字段."""
    updated = False
    for user in users:
        user = sync_user_status(user)  # 刷新系统状态
        
        # 移除 traffic_display
        
        user['status_text'] = "Active"
        user['status_class'] = "bg-green-500"

        if user.get('is_over_limit'):
            user['status_text'] = f"Limit Exceeded ({user['current_conn_count']}/{user['max_conn']})"
            user['status_class'] = "bg-red-500"
        elif user['status'] == 'paused':
            user['status_text'] = "Paused"
            user['status_class'] = "bg-yellow-500"
        elif user.get('expiry_date') and datetime.strptime(user['expiry_date'], '%Y-%m-%d').date() < datetime.now().date():
            user['status_text'] = "Expired"
            user['status_class'] = "bg-red-500"
        else:
             user['status_text'] = f"Active ({user['current_conn_count']}/{user['max_conn']})"
            
        updated = True
    if updated: save_users(users)
    return users

def get_service_status(service):
    """检查 systemd 服务的状态."""
    try:
        success, output = safe_run_command(['systemctl', 'is-active', service])
        return 'running' if success and output == 'active' else 'failed'
    except Exception:
        return 'failed'

# --- Web 路由所需的渲染函数 ---

_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS Panel - 仪表盘 V6.2</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .card { transition: all 0.3s ease; }
        .btn-action { transition: all 0.2s ease; }
        .modal { background-color: rgba(0, 0, 0, 0.6); z-index: 999; }
        .modal-content { transition: all 0.3s ease-out; transform: translateY(-50px); }
        .modal.open .modal-content { transform: translateY(0); }
        .service-status-icon { height: 10px; width: 10px; display: inline-block; border-radius: 50%; margin-right: 5px; }
        .status-running { background-color: #10B981; }
        .status-failed { background-color: #EF4444; }
        .log-entry { font-family: monospace; font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; }
    </style>
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="bg-indigo-600 text-white shadow-lg">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center">
            <h1 class="text-3xl font-bold">WSS 隧道管理面板 V6.2 (纯 IP/并发控制)</h1>
            <div class="flex space-x-3">
                <button onclick="openRootPasswordModal()" class="bg-indigo-700 hover:bg-indigo-800 px-4 py-2 rounded-lg font-semibold shadow-md btn-action">
                    修改 Root 密码
                </button>
                <button onclick="logout()" class="bg-red-600 hover:bg-red-700 px-4 py-2 rounded-lg font-semibold shadow-md btn-action">
                    退出登录 (root)
                </button>
            </div>
        </div>
    </div>

    <div class="max-w-7xl mx-auto p-4 sm:p-6 lg:p-8">
        <!-- Status Message Box -->
        <div id="status-message" class="hidden p-4 mb-4 rounded-xl font-semibold shadow-md" role="alert"></div>
        
        <!-- System Status Card -->
        <div class="card bg-white p-6 rounded-xl shadow-lg mb-8">
            <h3 class="text-xl font-semibold text-gray-800 mb-4 border-b pb-2">实时系统状态</h3>
            <div id="system-status-data" class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <!-- Data populated by JS -->
                <p class="text-gray-500 col-span-4">正在加载系统状态...</p>
            </div>
        </div>

        <!-- Stats Grid (精简) -->
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
                <h3 class="text-sm font-medium text-gray-500">WSS/TLS 端口</h3>
                <p class="text-3xl font-bold text-gray-900 mt-1">{{ wss_tls_port }}</p>
            </div>
            <div class="card bg-white p-5 rounded-xl shadow-lg border-l-4 border-yellow-500">
                <h3 class="text-sm font-medium text-gray-500">Stunnel/UDPGW 端口</h3>
                <p class="text-3xl font-bold text-gray-900 mt-1">{{ stunnel_port }} / {{ udpgw_port }}</p>
            </div>
        </div>
        
        <!-- 服务诊断与控制 (NEW FEATURE) -->
        <div class="card bg-white p-6 rounded-xl shadow-lg mb-8">
            <h3 class="text-xl font-semibold text-gray-800 mb-4 border-b pb-2">服务诊断与控制</h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="bg-gray-100 p-4 rounded-lg font-mono text-sm overflow-x-auto">
                    <p><span class="font-bold">服务器 IP 地址:</span> <span class="text-indigo-600">{{ host_ip }}</span></p>
                    <p class="mt-2 font-bold text-gray-700">关键端口监听状态:</p>
                    <div id="port-status-data" class="mt-2 space-y-1">
                        <!-- Port status populated by JS -->
                        <p class="text-gray-500">正在检查端口...</p>
                    </div>
                </div>
                <div class="bg-gray-100 p-4 rounded-lg">
                    <p class="font-bold text-gray-700 mb-3">核心服务操作:</p>
                    <div class="space-y-3">
                        <button onclick="controlService('wss', 'restart')" class="w-full bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-semibold shadow-md btn-action">
                            重启 WSS Proxy ({{ wss_tls_port }}/{{ wss_http_port }})
                        </button>
                        <button onclick="controlService('stunnel4', 'restart')" class="w-full bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-semibold shadow-md btn-action">
                            重启 Stunnel4 ({{ stunnel_port }})
                        </button>
                        <button onclick="controlService('udpgw', 'restart')" class="w-full bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-semibold shadow-md btn-action">
                            重启 UDPGW ({{ udpgw_port }})
                        </button>
                        <button onclick="controlService('wss_panel', 'restart')" class="w-full bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg font-semibold shadow-md btn-action">
                            重启 Web 面板 (谨慎操作)
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- 近期管理活动 (NEW FEATURE) -->
        <div class="card bg-white p-6 rounded-xl shadow-lg mb-8">
            <h3 class="text-xl font-semibold text-gray-800 mb-4 border-b pb-2">近期管理活动 (最新 20 条)</h3>
            <div class="bg-gray-100 p-4 rounded-lg max-h-96 overflow-y-auto">
                <div id="audit-log-content">
                    <p class="text-gray-500">正在加载日志...</p>
                </div>
            </div>
        </div>

        <!-- Add User Card / User List Card (REMOVED TRAFFIC CONTROLS) -->
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
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">状态 (并发/限制)</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">到期日</th>
                            <!-- 移除流量列 -->
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
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2 flex items-center">
                                <button onclick="openActiveIPModal('{{ user.username }}')" 
                                        class="text-xs px-3 py-1 rounded-full font-bold bg-purple-100 text-purple-800 hover:bg-purple-200 btn-action">
                                    活跃 IP
                                </button>
                                <button onclick="openSettingsModal('{{ user.username }}', '{{ user.expiry_date }}', '{{ user.max_conn }}')" 
                                        class="text-xs px-3 py-1 rounded-full font-bold bg-blue-100 text-blue-800 hover:bg-blue-200 btn-action">
                                    设置
                                </button>
                                <button onclick="openConfirmationModal('{{ user.username }}', '{{ 'pause' if user.status == 'active' else 'active' }}', 'toggleStatus', '{{ '暂停' if user.status == 'active' else '启用' }}')" 
                                        class="text-xs px-3 py-1 rounded-full font-bold {{ 'bg-yellow-100 text-yellow-800 hover:bg-yellow-200' if user.status == 'active' else 'bg-green-100 text-green-800 hover:bg-green-200' }} btn-action">
                                    {{ '暂停' if user.status == 'active' else '启用' }}
                                </button>
                                <!-- 移除重置流量按钮 -->
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
    
    <!-- Modal for Root Password Change (NEW FEATURE) -->
    <div id="root-password-modal" class="modal fixed inset-0 flex items-center justify-center p-4 hidden">
        <div class="modal-content bg-white rounded-xl shadow-2xl w-full max-w-lg transition-all">
            <div class="p-6">
                <h3 class="text-xl font-bold mb-4 text-gray-800 border-b pb-2">修改面板 Root 密码</h3>
                <form id="root-password-form" onsubmit="event.preventDefault(); saveRootPassword();">
                    <div class="mb-4">
                        <label for="current-password-root" class="block text-sm font-medium text-gray-700">当前密码</label>
                        <input type="password" id="current-password-root" class="mt-1 block w-full p-2 border border-gray-300 rounded-lg" required>
                    </div>
                    <div class="mb-4">
                        <label for="new-password-root" class="block text-sm font-medium text-gray-700">新密码</label>
                        <input type="password" id="new-password-root" class="mt-1 block w-full p-2 border border-gray-300 rounded-lg" required>
                    </div>
                    <div class="mb-6">
                        <label for="confirm-password-root" class="block text-sm font-medium text-gray-700">确认新密码</label>
                        <input type="password" id="confirm-password-root" class="mt-1 block w-full p-2 border border-gray-300 rounded-lg" required>
                    </div>

                    <div class="flex justify-end space-x-3">
                        <button type="button" onclick="closeRootPasswordModal()" class="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded-lg font-semibold btn-action">
                            取消
                        </button>
                        <button type="submit" class="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg font-semibold btn-action">
                            保存新密码
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Modal for User Settings (REVISED) -->
    <div id="settings-modal" class="modal fixed inset-0 flex items-center justify-center p-4 hidden">
        <div class="modal-content bg-white rounded-xl shadow-2xl w-full max-w-lg transition-all">
            <div class="p-6">
                <h3 class="text-xl font-bold mb-4 text-gray-800 border-b pb-2">设置 <span id="modal-username-title-settings"></span> 的参数</h3>
                <form id="settings-form" onsubmit="event.preventDefault(); saveSettings();">
                    <input type="hidden" id="modal-username-settings">
                    
                    <!-- 移除流量配额 -->
                    
                    <div class="mb-4">
                        <label for="modal-max-conn" class="block text-sm font-medium text-gray-700">最大并发连接数 (0为无限)</label>
                        <input type="number" step="1" min="0" id="modal-max-conn" class="mt-1 block w-full p-2 border border-gray-300 rounded-lg" required>
                    </div>

                    <div class="mb-6">
                        <label for="modal-expiry" class="block text-sm font-medium text-gray-700">到期日 (YYYY-MM-DD, 留空为永不到期)</label>
                        <input type="date" id="modal-expiry" class="mt-1 block w-full p-2 border border-gray-300 rounded-lg">
                    </div>
                    
                    <!-- 新增修改 SSH 密码 -->
                    <h4 class="font-bold text-gray-800 mt-6 mb-3 border-t pt-3">修改 SSH 密码 (可选)</h4>
                    <div class="mb-4">
                        <label for="modal-new-password" class="block text-sm font-medium text-gray-700">新 SSH 密码 (留空则不修改)</label>
                        <input type="password" id="modal-new-password" class="mt-1 block w-full p-2 border border-gray-300 rounded-lg">
                    </div>

                    <div class="flex justify-end space-x-3 mt-6">
                        <button type="button" onclick="closeSettingsModal()" class="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded-lg font-semibold btn-action">
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
    
    <!-- Active IP / Confirmation Modals (保留并精简) -->
    <div id="active-ip-modal" class="modal fixed inset-0 flex items-center justify-center p-4 hidden">
        <div class="modal-content bg-white rounded-xl shadow-2xl w-full max-w-xl transition-all">
            <div class="p-6">
                <h3 class="text-xl font-bold mb-4 text-gray-800 border-b pb-2">用户组 <span id="active-ip-modal-title"></span> 的活跃 IP (IP 封禁)</h3>
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
        // --- Utility Functions ---
        function showStatus(message, isSuccess) {
            const statusDiv = document.getElementById('status-message');
            statusDiv.textContent = message;
            statusDiv.className = \`\${isSuccess ? 'bg-green-100 text-green-800 border-green-400' : 'bg-red-100 text-red-800 border-red-400'} p-4 mb-4 rounded-xl font-semibold shadow-md block border\`;
            setTimeout(() => { statusDiv.classList.add('hidden'); }, 5000);
        }
        
        function logout() {
            window.location.href = '/logout';
        }

        // --- System Status & Port Check Logic (NEW FEATURE) ---
        const PORT_SERVICES = {
            '{{ wss_http_port }}': 'WSS HTTP/Payload',
            '{{ wss_tls_port }}': 'WSS TLS',
            '{{ stunnel_port }}': 'Stunnel4 TLS',
            '{{ udpgw_port }}': 'UDPGW UDP',
            '{{ panel_port }}': 'Web Panel (TCP)'
        };

        function updateSystemStatus(data) {
            const container = document.getElementById('system-status-data');
            
            const formatService = (service, status) => {
                const className = status === 'running' ? 'status-running' : 'status-failed';
                const text = status === 'running' ? '运行中' : '失败';
                return \`
                    <div class="flex items-center p-2 bg-gray-100 rounded-lg shadow-sm">
                        <span class="service-status-icon \${className}"></span>
                        <span class="font-semibold">\${service}:</span>
                        <span class="ml-auto font-medium \${className === 'status-failed' ? 'text-red-600' : 'text-green-600'}">\${text}</span>
                    </div>
                \`;
            };

            const formatResource = (label, value) => \`
                <div class="p-2 bg-gray-100 rounded-lg shadow-sm">
                    <span class="font-semibold">\${label}:</span>
                    <span class="ml-auto font-medium text-gray-700">\${value}</span>
                </div>
            \`;

            let html = formatResource("CPU 使用率", \`\${data.cpu_percent.toFixed(1)}%\`);
            html += formatResource("内存 (用/总)", \`\${data.memory_used_gb.toFixed(2)} / \${data.memory_total_gb.toFixed(2)} GB\`);
            html += formatResource("磁盘使用率", \`\${data.disk_used_percent.toFixed(1)}%\`);
            html += formatResource("面板 API", '<span class="text-green-600 font-semibold">正常</span>');

            // Service statuses
            html += formatService("WSS Proxy", data.services.wss);
            html += formatService("Panel Service", data.services.wss_panel);
            html += formatService("Stunnel4", data.services.stunnel4);
            html += formatService("UDPGW", data.services.udpgw);

            container.innerHTML = html;
            updatePortStatus(data.ports);
        }
        
        function updatePortStatus(ports) {
            const container = document.getElementById('port-status-data');
            let html = '';
            
            for (const port in ports) {
                const status = ports[port];
                const serviceName = PORT_SERVICES[port] || '未知服务';
                const className = status === 'LISTEN' ? 'text-green-600' : 'text-red-600';
                const iconClass = status === 'LISTEN' ? 'status-running' : 'status-failed';
                
                html += \`
                    <div class="flex justify-between items-center text-gray-700">
                        <span class="font-medium">\${port} (\${serviceName}):</span>
                        <span class="font-bold \${className}">
                            <span class="service-status-icon \${iconClass}"></span>
                            \${status}
                        </span>
                    </div>
                \`;
            }
            container.innerHTML = html;
        }

        async function fetchSystemStatus() {
            const API_URL = '/api/system/status'; 
            
            try {
                const response = await fetch(API_URL, { method: 'GET' });

                if (response.status === 403) {
                    document.getElementById('system-status-data').innerHTML = '<p class="text-red-500 col-span-4">权限不足，请确保已登录。</p>';
                    return;
                }
                
                const data = await response.json();

                if (data.success) {
                    updateSystemStatus(data);
                } else {
                    document.getElementById('system-status-data').innerHTML = \`<p class="text-red-500 col-span-4">无法获取系统状态: \${data.message}</p>\`;
                }
            } catch (error) {
                document.getElementById('system-status-data').innerHTML = '<p class="text-red-500 col-span-4">连接错误，请检查防火墙和面板服务。</p>';
            }
        }
        
        async function fetchAuditLogs() {
            const API_URL = '/api/logs'; 
            try {
                const response = await fetch(API_URL, { method: 'GET' });
                const data = await response.json();
                const logContainer = document.getElementById('audit-log-content');
                
                if (response.ok && data.success) {
                    if (data.logs.length === 0) {
                        logContainer.innerHTML = '<p class="text-gray-500">目前没有管理活动日志。</p>';
                        return;
                    }
                    
                    logContainer.innerHTML = data.logs.map(log => {
                        // 简单的格式化，加粗用户名
                        const formattedLog = log.replace(/\[USER:([^\]]+)\]/, (match, p1) => 
                            p1 !== 'N/A' ? \`[USER:<strong>\${p1}</strong>]\` : match
                        );
                        return \`<div class="log-entry p-1 rounded hover:bg-gray-200">\${formattedLog}</div>\`;
                    }).join('');
                } else {
                    logContainer.innerHTML = \`<p class="text-red-500">无法加载日志: \${data.message || '未知错误'}</p>\`;
                }
            } catch (error) {
                document.getElementById('audit-log-content').innerHTML = '<p class="text-red-500">连接错误，无法获取日志。</p>';
            }
        }
        
        async function controlService(service, action) {
            showStatus(\`正在执行操作: \${action} \${service}...\`, true);
            
            try {
                const response = await fetch('/api/system/control', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ service, action })
                });

                const result = await response.json();

                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    // 延迟刷新状态，等待服务启动
                    setTimeout(() => { fetchSystemStatus(); }, 5000); 
                } else {
                    showStatus(\`服务操作失败: \${result.message}\`, false);
                }
            } catch (error) {
                showStatus('请求失败，无法控制服务。', false);
            }
        }

        window.onload = function() {
            fetchSystemStatus();
            fetchAuditLogs();
            setInterval(fetchSystemStatus, 15000); 
            setInterval(fetchAuditLogs, 30000);
        };

        // --- Settings Modal Logic ---
        
        function openSettingsModal(username, expiry, maxConn) {
            document.getElementById('modal-username-title-settings').textContent = username;
            document.getElementById('modal-username-settings').value = username;
            
            document.getElementById('modal-expiry').value = expiry || '';
            document.getElementById('modal-max-conn').value = parseInt(maxConn) || {{ MAX_CONN_DEFAULT }};
            document.getElementById('modal-new-password').value = '';
            
            document.getElementById('settings-modal').classList.remove('hidden');
        }

        function closeSettingsModal() {
            document.getElementById('settings-modal').classList.add('hidden');
        }

        async function saveSettings() {
            const username = document.getElementById('modal-username-settings').value;
            const expiry_date = document.getElementById('modal-expiry').value;
            const max_connections = parseInt(document.getElementById('modal-max-conn').value);
            const new_ssh_password = document.getElementById('modal-new-password').value;

            if (max_connections < 0) {
                 showStatus('最大并发连接数不能为负数。', false);
                 return;
            }

            try {
                const response = await fetch('/api/users/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, expiry_date, max_connections, new_ssh_password })
                });

                const result = await response.json();

                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    closeSettingsModal();
                    location.reload(); 
                } else {
                    showStatus('保存设置失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        }
        
        // --- Root Password Modal Logic (NEW FEATURE) ---
        
        function openRootPasswordModal() {
            document.getElementById('current-password-root').value = '';
            document.getElementById('new-password-root').value = '';
            document.getElementById('confirm-password-root').value = '';
            document.getElementById('root-password-modal').classList.remove('hidden');
        }
        
        function closeRootPasswordModal() {
            document.getElementById('root-password-modal').classList.add('hidden');
        }
        
        async function saveRootPassword() {
            const currentPass = document.getElementById('current-password-root').value;
            const newPass = document.getElementById('new-password-root').value;
            const confirmPass = document.getElementById('confirm-password-root').value;
            
            if (newPass !== confirmPass) {
                showStatus('两次输入的新密码不一致。', false);
                return;
            }
            if (newPass.length < 6) {
                showStatus('新密码长度至少需要 6 位。', false);
                return;
            }
            
            try {
                const response = await fetch('/api/root/change_password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ current_password: currentPass, new_password: newPass })
                });

                const result = await response.json();

                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    closeRootPasswordModal();
                    // 强制退出重新登录
                    setTimeout(() => { logout(); }, 1500); 
                } else {
                    showStatus('修改密码失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        }

        // --- Existing User/IP Management Functions ---

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
                        listDiv.innerHTML = '<p class="text-green-600 font-semibold">当前没有活跃的连接和封禁记录。</p>';
                        return;
                    }

                    listDiv.innerHTML = activeIps.map(ipInfo => {
                        const isBanned = ipInfo.is_banned;
                        const actionText = isBanned ? '解除封禁' : '封禁';
                        const actionClass = isBanned ? 'bg-green-500 hover:bg-green-600' : 'bg-red-500 hover:bg-red-600';
                        const statusText = isBanned ? '已封禁' : (ipInfo.count > 0 ? '活跃' : '已记录');
                        const statusClass = isBanned ? 'bg-red-100 text-red-800' : (ipInfo.count > 0 ? 'bg-green-100 text-green-800' : 'bg-gray-200 text-gray-800');

                        return \`
                            <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between p-3 bg-gray-50 rounded-lg shadow-sm border border-gray-200">
                                <div class="font-mono text-sm text-gray-800 mb-2 sm:mb-0">
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
                    listDiv.innerHTML = \`<p class="text-red-500">获取 IP 失败: \${result.message || '未知错误'}</p>\`;
                }

            } catch (error) {
                document.getElementById('active-ip-modal').classList.add('hidden');
                showStatus('请求失败，请检查面板运行状态。', false);
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
        
        function openConfirmationModal(username, action, type, typeText) {
            let message = '';
            let confirmButtonText = '确认';

            if (type === 'toggleStatus') {
                const statusText = action === 'active' ? '启用' : '暂停';
                message = \`确定要 \${statusText} 用户组 \${username} 吗? (\${statusText} 操作将立即终止所有活跃连接)\`;
                confirmButtonText = statusText;
            } else if (type === 'deleteUser') {
                message = \`确定要永久删除用户组 \${username} 吗? (此操作将终止所有连接并删除系统账户!)\`;
                confirmButtonText = typeText;
            }
            // 移除了 resetTraffic 选项

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
        
    </script>
</body>
</html>
"""

def render_dashboard(users):
    """手动渲染 Jinja2 模板字符串."""
    template_env = jinja2.Environment(loader=jinja2.BaseLoader)
    # 更新模板版本号
    template = template_env.from_string(_DASHBOARD_HTML)
    
    host_ip = request.host.split(':')[0]
    if host_ip in ('127.0.0.1', 'localhost', '0.0.0.0'):
        host_ip = SERVER_IP
        
    context = {
        'users': users,
        'panel_port': PANEL_PORT,
        'wss_http_port': WSS_HTTP_PORT,
        'wss_tls_port': WSS_TLS_PORT,
        'stunnel_port': STUNNEL_PORT,
        'udpgw_port': UDPGW_PORT,
        'host_ip': host_ip,
        'MAX_CONN_DEFAULT': MAX_CONN_DEFAULT
    }
    return template.render(**context)


# --- Web 路由 ---

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
        root_hash = load_root_hash()
        
        if not root_hash: 
            error = '面板配置错误，Root Hash丢失。'
        elif username == ROOT_USERNAME and password_raw:
            password_hash = hashlib.sha256(password_raw.encode('utf-8')).hexdigest()
            if password_hash == root_hash:
                session['logged_in'] = True
                session['username'] = ROOT_USERNAME
                log_action("LOGIN_SUCCESS", ROOT_USERNAME, "Web UI Login")
                # Flask 装饰器修改了函数名，需要使用 'dashboard_decorated'
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
        <h1 class="text-2xl">WSS 管理面板 V6.2</h1>
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

# --- 新增 Root 密码修改 API ---
@app.route('/api/root/change_password', methods=['POST'])
@login_required
def change_root_password_api():
    data = request.json
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({"success": False, "message": "缺少当前密码或新密码"}), 400
        
    root_hash = load_root_hash()
    current_hash = hashlib.sha256(current_password.encode('utf-8')).hexdigest()
    
    if current_hash != root_hash:
        log_action("ROOT_PASS_FAIL", session.get('username', 'root'), "Incorrect current password for root change")
        return jsonify({"success": False, "message": "当前密码不正确"}), 403
        
    new_hash = hashlib.sha256(new_password.encode('utf-8')).hexdigest()
    if not save_root_hash(new_hash):
        log_action("ROOT_PASS_FAIL", session.get('username', 'root'), "Failed to save new root hash to file")
        return jsonify({"success": False, "message": "保存新密码失败，请检查文件权限"}), 500
        
    log_action("ROOT_PASS_SUCCESS", session.get('username', 'root'), "Root panel password successfully changed")
    return jsonify({"success": True, "message": "Root 面板密码修改成功"})


@app.route('/api/users/add', methods=['POST'])
@login_required
def add_user_api():
    data = request.json
    username = data.get('username')
    password_raw = data.get('password')
    
    if not username or not password_raw: return jsonify({"success": False, "message": "缺少用户名或密码"}), 400
    if not re.match(r'^[a-z0-9_]{3,16}$', username): return jsonify({"success": False, "message": "用户名格式不正确 (3-16位小写字母/数字/下划线)"}), 400

    users = load_users()
    if get_user(username)[0]: return jsonify({"success": False, "message": f"用户组 {username} 已存在于面板"}), 409

    # --- START OF FIX for Issue 1: Handle pre-existing system user ---
    user_exists_on_system = False
    
    # 尝试创建系统用户
    success, output = safe_run_command(['useradd', '-m', '-s', '/bin/false', username])
    if not success:
        if "already exists" in output:
            user_exists_on_system = True
            # 检查 /etc/passwd 确认用户确实存在且可被接管
            success_check, _ = safe_run_command(['id', username])
            if not success_check:
                 log_action("USER_ADD_FAIL", session.get('username', 'root'), f"User {username} exists but ID failed: {output}")
                 return jsonify({"success": False, "message": f"系统用户 {username} 已存在，但无法验证其身份。"}), 500
            
            log_action("USER_ADD_WARN", session.get('username', 'root'), f"System user {username} already exists, attempting to adopt.")
        else:
            log_action("USER_ADD_FAIL", session.get('username', 'root'), f"Failed to create system user {username}: {output}")
            return jsonify({"success": False, "message": f"创建系统用户失败: {output}"}), 500
    # --- END OF FIX ---
    
    # 设置密码（无论用户是新创建还是被接管）
    chpasswd_input = f"{username}:{password_raw}"
    # FIX: safe_run_command 已经修复，使用正确的 input_data=...
    success, output = safe_run_command(['/usr/sbin/chpasswd'], input_data=chpasswd_input.encode('utf-8'))
    if not success:
        # 如果是新创建的用户，需要回滚删除它
        if not user_exists_on_system: safe_run_command(['userdel', '-r', username])
        log_action("USER_ADD_FAIL", session.get('username', 'root'), f"Failed to set password for {username}: {output}")
        return jsonify({"success": False, "message": f"设置密码失败: {output}"}), 500
        
    new_user = {
        "username": username, "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "status": "active", "expiry_date": "", 
        "banned_ips": [], "max_connections": MAX_CONN_DEFAULT
    }
    users.append(new_user)
    save_users(users)
    sync_user_status(new_user)
    
    status_msg = "创建成功" if not user_exists_on_system else "已成功接管并配置密码"
    log_action("USER_ADD_SUCCESS", session.get('username', 'root'), f"User {username} {status_msg}")
    return jsonify({"success": True, "message": f"用户组 {username} {status_msg}"})

@app.route('/api/users/delete', methods=['POST'])
@login_required
def delete_user_api():
    data = request.json
    username = data.get('username')
    
    if not username: return jsonify({"success": False, "message": "缺少用户名"}), 400

    users = load_users()
    user_to_delete, index = get_user(username)

    if not user_to_delete: return jsonify({"success": False, "message": f"面板中用户组 {username} 不存在"}), 404

    kill_user_sessions(username)
    
    ip_bans = load_ip_bans()
    if username in ip_bans:
        for ip in ip_bans[username]: toggle_iptables_ip_ban(ip, 'unblock')
        ip_bans.pop(username)
        save_ip_bans(ip_bans)

    success, output = safe_run_command(['userdel', '-r', username])
    if not success:
        log_action("USER_DELETE_WARNING", session.get('username', 'root'), f"System user {username} deletion failed (non-fatal): {output}")

    users.pop(index)
    save_users(users)
    
    log_action("USER_DELETE_SUCCESS", session.get('username', 'root'), f"Deleted user {username}")
    return jsonify({"success": True, "message": f"用户组 {username} 已删除，活动会话已终止"})


@app.route('/api/users/settings', methods=['POST'])
@login_required
def update_user_settings_api():
    data = request.json
    username = data.get('username')
    expiry_date = data.get('expiry_date', '')
    max_connections = data.get('max_connections', MAX_CONN_DEFAULT)
    new_ssh_password = data.get('new_ssh_password', '') # 新增字段

    user, index = get_user(username)
    if not user: return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
        
    users = load_users()
    
    try:
        max_connections = int(max_connections)
        if max_connections < 0: raise ValueError("Max connections cannot be negative")
        if expiry_date: datetime.strptime(expiry_date, '%Y-%m-%d')
    except ValueError: return jsonify({"success": False, "message": "日期或连接数格式不正确"}), 400

    old_expiry = users[index].get('expiry_date')
    old_max_conn = users[index].get('max_connections')
    
    users[index]['expiry_date'] = expiry_date
    users[index]['max_connections'] = max_connections
    
    # --- SSH 密码修改逻辑 (NEW FEATURE) ---
    password_log = ""
    if new_ssh_password:
        chpasswd_input = f"{username}:{new_ssh_password}"
        # FIX: safe_run_command 已经修复，使用正确的 input_data=...
        success, output = safe_run_command(['/usr/sbin/chpasswd'], input_data=chpasswd_input.encode('utf-8'))
        if success:
            password_log = ", SSH password changed"
        else:
            log_action("USER_PASS_FAIL", session.get('username', 'root'), f"Failed to set password for {username}: {output}")
            return jsonify({"success": False, "message": f"设置 SSH 密码失败: {output}"}), 500
    
    users[index] = sync_user_status(users[index])
    
    save_users(users)
    log_action("SETTINGS_UPDATE", session.get('username', 'root'), 
               f"Updated {username}: Expiry {old_expiry}->{expiry_date}, MaxConn {old_max_conn}->{max_connections}{password_log}")
    return jsonify({"success": True, "message": f"用户组 {username} 设置已更新{password_log}"})
    
@app.route('/api/users/status', methods=['POST'])
@login_required
def toggle_user_status_api():
    data = request.json
    username = data.get('username')
    action = data.get('action')

    user, index = get_user(username)
    if not user: return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
        
    users = load_users()
    
    if action == 'active':
        users[index]['status'] = 'active'
        log_action("USER_TOGGLE", session.get('username', 'root'), f"Set user {username} to ACTIVE")
    elif action == 'pause':
        users[index]['status'] = 'paused'
        log_action("USER_TOGGLE", session.get('username', 'root'), f"Set user {username} to PAUSED (Locked)")
    else: return jsonify({"success": False, "message": "无效的操作"}), 400
        
    users[index] = sync_user_status(users[index])
    save_users(users)
    
    return jsonify({"success": True, "message": f"用户组 {username} 状态已更新为 {action}"})

# 移除了 /api/users/reset_traffic 和 /api/users/update_traffic

# --- 实时系统状态 & 服务控制 API (NEW/REFINED) ---
@app.route('/api/system/status', methods=['GET'])
@login_required 
def get_system_status():
    """获取服务器 CPU/内存/服务状态."""
    
    def get_port_status(port):
        """检查端口是否处于 LISTEN 状态 (使用 ss 命令)"""
        try:
            success, output = safe_run_command(['ss', '-tuln'], input_data=None)
            if success and f":{port} " in output:
                return 'LISTEN'
            return 'FAIL'
        except Exception:
            return 'FAIL'

    try:
        cpu_percent = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        services = {
            'wss': get_service_status('wss'),
            'wss_panel': get_service_status('wss_panel'),
            'stunnel4': get_service_status('stunnel4'),
            'udpgw': get_service_status('udpgw'),
        }
        
        ports = {
            WSS_HTTP_PORT: get_port_status(WSS_HTTP_PORT),
            WSS_TLS_PORT: get_port_status(WSS_TLS_PORT),
            STUNNEL_PORT: get_port_status(STUNNEL_PORT),
            UDPGW_PORT: get_port_status(UDPGW_PORT),
            PANEL_PORT: get_port_status(PANEL_PORT),
        }

        return jsonify({
            "success": True,
            "cpu_percent": cpu_percent,
            "memory_used_gb": round(mem.used / (1024 ** 3), 2),
            "memory_total_gb": round(mem.total / (1024 ** 3), 2),
            "disk_used_percent": disk.percent,
            "services": services,
            "ports": ports
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"System status check failed: {str(e)}"}), 500

@app.route('/api/system/control', methods=['POST'])
@login_required
def control_system_service():
    """重启/停止核心服务."""
    data = request.json
    service = data.get('service')
    action = data.get('action') # restart

    allowed_services = ['wss', 'wss_panel', 'stunnel4', 'udpgw']
    if service not in allowed_services or action != 'restart':
        log_action("SERVICE_CONTROL_FAIL", session.get('username', 'root'), f"Attempted illegal action/service: {action}/{service}")
        return jsonify({"success": False, "message": "无效的服务或操作"}), 400
        
    # 特殊处理 wss_panel，重启后可能导致当前连接断开
    if service == 'wss_panel':
        log_action("SERVICE_CONTROL_WARN", session.get('username', 'root'), "Panel restart requested. Connection may drop.")

    command = ['systemctl', action, service]
    success, output = safe_run_command(command)
    
    if success:
        log_action("SERVICE_CONTROL_SUCCESS", session.get('username', 'root'), f"Successfully executed {action} on {service}")
        return jsonify({"success": True, "message": f"服务 {service} 已成功执行 {action} 操作。请等待 5 秒后刷新状态。"}), 200
    else:
        log_action("SERVICE_CONTROL_FAIL", session.get('username', 'root'), f"Failed to {action} {service}: {output}")
        return jsonify({"success": False, "message": f"服务 {service} 操作失败: {output}"}), 500

@app.route('/api/logs', methods=['GET'])
@login_required
def get_logs_api():
    """获取最新的审计日志."""
    logs = get_recent_logs(20)
    return jsonify({"success": True, "logs": logs})

@app.route('/api/ips/check', methods=['POST'])
def check_ip_api():
    if request.remote_addr != '127.0.0.1' and request.remote_addr != '::1': return jsonify({"success": False, "message": "Access denied"}), 403
        
    data = request.json
    client_ip = data.get('ip')
    
    if not client_ip: return jsonify({"success": False, "message": "缺少 IP"}), 400

    ip_bans = load_ip_bans()
    
    is_banned = False
    for banned_ips in ip_bans.values():
        if client_ip in banned_ips:
            is_banned = True
            break
            
    return jsonify({"success": True, "is_banned": is_banned})

# 移除了 /api/ips/report

@app.route('/api/ips/block', methods=['POST'])
@login_required
def block_ip_api():
    data = request.json
    username = data.get('username')
    ip = data.get('ip')

    if not username or not ip: return jsonify({"success": False, "message": "缺少用户名或 IP"}), 400

    ip_bans = load_ip_bans()
    user, index = get_user(username)
    
    if not user: return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
    
    if username not in ip_bans: ip_bans[username] = []
        
    if ip not in ip_bans[username]:
        ip_bans[username].append(ip)
        save_ip_bans(ip_bans)
        
    success_iptables, iptables_output = toggle_iptables_ip_ban(ip, 'block')
    
    # 移除活跃 IP 记录 (仅作为UI优化，核心是IPTables)
    active_ips = load_active_ips()
    if ip in active_ips:
        active_ips.pop(ip)
        save_active_ips(active_ips)
        
    if success_iptables:
        log_action("IP_BLOCK_SUCCESS", session.get('username', 'root'), f"Blocked IP {ip} for user {username}")
        return jsonify({"success": True, "message": f"IP {ip} 已被封禁 (实时生效)。"})
    else:
        log_action("IP_BLOCK_WARNING", session.get('username', 'root'), 
                   f"Blocked IP {ip} in DB for user {username}, but IPTables failed: {iptables_output}")
        return jsonify({"success": True, "message": f"IP {ip} 已被封禁 (面板记录已更新)，但实时防火墙操作失败。"})

@app.route('/api/ips/unblock', methods=['POST'])
@login_required
def unblock_ip_api():
    data = request.json
    username = data.get('username')
    ip = data.get('ip')

    if not username or not ip: return jsonify({"success": False, "message": "缺少用户名或 IP"}), 400

    ip_bans = load_ip_bans()
    
    if username in ip_bans and ip in ip_bans[username]:
        ip_bans[username].remove(ip)
        save_ip_bans(ip_bans)
    
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
    username = request.args.get('username')
    
    if not username: return jsonify({"success": False, "message": "缺少用户名"}), 400

    active_ips = load_active_ips()
    ip_bans = load_ip_bans()
    banned_ips_for_user = ip_bans.get(username, [])
    
    filtered_ips = []
    
    # 合并活跃 IP 和被封禁 IP 列表，确保显示所有相关 IP
    all_ips = set(active_ips.keys()) | set(banned_ips_for_user)

    for ip in all_ips:
        data = active_ips.get(ip, {'count': 0, 'last_seen': 0})
        last_seen_display = 'N/A'
        if data['last_seen'] > 0:
             last_seen_dt = datetime.fromtimestamp(data['last_seen'])
             last_seen_display = last_seen_dt.strftime('%H:%M:%S')
        
        is_banned = ip in banned_ips_for_user
        
        filtered_ips.append({
            'ip': ip, 'count': data['count'], 'last_seen_display': last_seen_display,
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

# --- 5. 创建 WSS 面板 systemd 服务 ---
if [ ! -f "/etc/systemd/system/wss_panel.service" ]; then
tee /etc/systemd/system/wss_panel.service > /dev/null <<EOF
[Unit]
Description=WSS User Management Panel (Flask V6.2)
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
# FIX: 如果 service 文件存在，只更新 ExecStart
if [ -f "/etc/systemd/system/wss_panel.service" ]; then
    # 更新服务描述的版本号
    sudo sed -i "s|Description=WSS User Management Panel (Flask V6.1)|Description=WSS User Management Panel (Flask V6.2)|" /etc/systemd/system/wss_panel.service
    sudo sed -i "s|^ExecStart=.*|ExecStart=$PYTHON_VENV_PATH /usr/local/bin/wss_panel.py|" /etc/systemd/system/wss_panel.service
fi

systemctl daemon-reload
systemctl enable wss_panel || true
systemctl restart wss_panel
echo "WSS 管理面板 V6.2 已启动/重启，端口 $PANEL_PORT"
echo "----------------------------------"

# --- 6. 部署 IPTABLES 阻断链设置 (移除流量统计链) ---

setup_iptables_chains() {
    echo "==== 配置 IPTABLES IP 实时阻断链 (仅保留 filter 表) ===="
    
    BLOCK_CHAIN="WSS_IP_BLOCK"
    
    # 彻底清理 BLOCK 链 (它在 filter 表)
    iptables -D INPUT -j $BLOCK_CHAIN 2>/dev/null || true
    iptables -F $BLOCK_CHAIN 2>/dev/null || true
    iptables -X $BLOCK_CHAIN 2>/dev/null || true

    # 1. 创建新的阻断链
    iptables -N $BLOCK_CHAIN 2>/dev/null || true 

    # 2. 将新链连接到 INPUT 主链 (必须在最前面)
    iptables -I INPUT 1 -j $BLOCK_CHAIN
    
    # 3. 保存规则
    if command -v iptables-save >/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        echo "IPTABLES 规则已保存到 /etc/iptables/rules.v4。"
    fi

    echo "IPTABLES IP 阻断功能已启用，流量统计功能已移除。"
}

# 立即运行 IPTABLES 链设置
setup_iptables_chains


# --- 7. 移除流量同步 Cron Job ---
echo "==== 移除流量同步 Cron Job ===="
rm -f /etc/cron.d/wss-traffic || true
echo "流量同步 Cron Job 已移除。"
echo "----------------------------------"

# --- 8. SSHD 安全配置 (保留不变) ---
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_SUFFIX=".bak.wss$(date +%s)"
SSHD_SERVICE=$(systemctl list-units --full -all | grep -E "sshd\.service|ssh\.service" | grep -v "not-found" | head -n 1 | awk '{print $1}' | cut -d'.' -f1 || echo "sshd")

echo "==== 配置 SSHD 安全策略 (增强连接稳定性) ===="
cp -a "$SSHD_CONFIG" "${SSHD_CONFIG}${BACKUP_SUFFIX}"
echo "SSHD 配置已备份到 ${SSHD_CONFIG}${BACKUP_SUFFIX}"

# 1. 删除旧的 WSS 匹配配置段
sed -i '/# WSS_TUNNEL_BLOCK_START/,/# WSS_TUNNEL_BLOCK_END/d' "$SSHD_CONFIG"

# 2. 写入新的 WSS 隧道策略 (增加 ClientAliveInterval)
cat >> "$SSHD_CONFIG" <<EOF

# WSS_TUNNEL_BLOCK_START -- managed by deploy_wss_panel.sh (V6.2)
# 统一策略: 允许所有用户通过本机 (127.0.0.1, ::1) 使用密码进行认证。
Match Address 127.0.0.1,::1
    PasswordAuthentication yes
    PermitTTY no
    X11Forwarding no
    AllowTcpForwarding yes
    ForceCommand /bin/false
    # 增加连接活跃检查，防止连接因闲置被断开
    ClientAliveInterval 30
    ClientAliveCountMax 120
# WSS_TUNNEL_BLOCK_END -- managed by deploy_wss_panel.sh (V6.2)

EOF

chmod 600 "$SSHD_CONFIG"

echo "重新加载并重启 ssh 服务 ($SSHD_SERVICE)"
systemctl daemon-reload
systemctl restart "$SSHD_SERVICE"
echo "SSHD 配置更新完成，连接稳定性已增强。"
echo "----------------------------------"

# 清理敏感变量
unset PANEL_ROOT_PASS_RAW

echo "=================================================="
echo "✅ WSS 管理面板部署完成！ (V6.2 Payload 修复/端口统一)"
echo "=================================================="
echo ""
echo "核心代理的 Payload 异步读取逻辑已优化，请再次尝试连接客户端。"
echo "=================================================="
