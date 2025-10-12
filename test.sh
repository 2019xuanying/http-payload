#!/usr/bin/env bash
set -eu

# =======================================================
# WSS 隧道/Stunnel/管理面板部署脚本 V6.6 - IP 修复与并发清理版
# 变更: 
# 1. 核心修复: WSS 代理新增自定义日志 (/var/log/wss.log) 记录真实客户端 IP。
# 2. 核心清理: 彻底移除所有并发连接数限制的代码和字段。
# 3. 健壮性: 优化 stunnel 证书权限 (600)，并增加 wss 日志旋转配置。
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
    [ -z "$SERVER_IP" ] && SERVER_IP=$(/sbin/ip a | grep 'inet ' | grep -v '127.0.0.1' | head -n 1 | awk '{print $2}' | cut -d/ -f1)
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
read -p "请输入 SSH 目标端口 (WSS/Stunnel 转发到此, 默认22): " SSH_TARGET_PORT
SSH_TARGET_PORT=${SSH_TARGET_PORT:-22}
echo "内部 SSH 目标端口: $SSH_TARGET_PORT"

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
    PANEL_ROOT_PASS_HASH=$(echo -n "$PANEL_ROOT_PASS_RAW" | /usr/bin/sha256sum | awk '{print $1}')
    break
done

echo "----------------------------------"
echo "==== 系统更新与依赖安装 (VENV 隔离) ===="
/usr/bin/apt update -y
/usr/bin/apt install -y python3 python3-pip python3-venv wget curl git net-tools openssl stunnel4 iptables-persistent procps cmake build-essential logrotate

echo "创建 Python 虚拟环境于 $VENV_PATH"
/usr/bin/mkdir -p "$VENV_PATH"
/usr/bin/python3 -m venv "$VENV_PATH"

echo "在 VENV 中安装 Python 依赖..."
"$PYTHON_VENV_PATH" -m pip install flask jinja2 requests httpx psutil uvloop

echo "依赖安装完成，使用隔离环境路径: $VENV_PATH"
echo "----------------------------------"


# --- 2. WSS 核心代理脚本 (目标端口 $SSH_TARGET_PORT) ---
echo "==== 安装 WSS 核心代理脚本 (/usr/local/bin/wss) ===="
/usr/bin/tee /usr/local/bin/wss > /dev/null <<EOF
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio
import ssl
import sys
import os
import httpx
import time
import datetime # 导入 datetime 用于日志时间戳
try:
    import uvloop
    UVLOOP_AVAILABLE = True
except ImportError:
    UVLOOP_AVAILABLE = False

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
try:
    SSH_TARGET_PORT = int(sys.argv[3])
except (IndexError, ValueError):
    SSH_TARGET_PORT = 22

DEFAULT_TARGET = ('127.0.0.1', SSH_TARGET_PORT)
BUFFER_SIZE = 65536
TIMEOUT = 3600
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'
PANEL_PORT = os.environ.get('WSS_PANEL_PORT', '54321')
API_URL_CHECK = f"http://127.0.0.1:{PANEL_PORT}/api/ips/check"
WSS_LOG_FILE = '/var/log/wss.log' # WSS 代理自定义日志文件

FIRST_RESPONSE = b'HTTP/1.1 200 OK\\r\\nContent-Type: text/plain\\r\\nContent-Length: 2\\r\\n\\r\\nOK\\r\\n\\r\\n'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\n\\r\\n'
FORBIDDEN_RESPONSE = b'HTTP/1.1 403 Forbidden\\r\\nContent-Length: 0\\r\\n\\r\\n'

http_client = httpx.AsyncClient(timeout=3.0)

# 全局内存缓存
BAN_CACHE = {}
BAN_CACHE_TTL = 60 # 缓存 60 秒

def write_wss_log(client_ip, message):
    """记录 WSS 代理连接事件，包含真实客户端 IP。"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [WSS_CONN] [IP:{client_ip}] {message}\n"
    try:
        # 使用 os.O_APPEND 和 os.O_CREAT 确保文件存在且只追加
        with open(WSS_LOG_FILE, 'a') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Error writing to WSS log: {e}")

async def check_ip_status(client_ip):
    """检查 IP 是否被面板封禁 (新增本地缓存)."""
    global BAN_CACHE
    
    # 1. 检查缓存
    cache_entry = BAN_CACHE.get(client_ip)
    if cache_entry and time.time() < cache_entry['expiry']:
        return cache_entry['is_allowed']

    # 2. 如果缓存失效，异步查询 API
    try:
        response = await http_client.post(
            API_URL_CHECK,
            json={'ip': client_ip}
        )
        
        if response.status_code == 200:
            result = response.json()
            is_allowed = not result.get('is_banned', False)
        else:
            is_allowed = True # API response error, default to allowed

        # 3. 更新缓存
        BAN_CACHE[client_ip] = {
            'is_allowed': is_allowed,
            'expiry': time.time() + BAN_CACHE_TTL
        }
        return is_allowed

    except Exception:
        # 如果面板 API 宕机，为安全起见，暂时允许连接
        return True

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    peer = writer.get_extra_info('peername')
    client_ip = peer[0]
    protocol = "TLS" if tls else "HTTP"
    
    write_wss_log(client_ip, f"Connection received via {protocol}.")

    is_allowed = await check_ip_status(client_ip)
    if not is_allowed:
        writer.write(FORBIDDEN_RESPONSE)
        await writer.drain()
        writer.close()
        write_wss_log(client_ip, "Connection blocked by IP ban list.")
        return

    forwarding_started = False
    full_request = b''

    try:
        while not forwarding_started:
            data = await asyncio.wait_for(reader.read(BUFFER_SIZE), timeout=5)
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
        
        write_wss_log(client_ip, "Handshake SUCCESS. Forwarding to SSHD.")

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
        write_wss_log(client_ip, "Forwarding ERROR or client disconnected.")
        pass
    finally:
        try:
            writer.close()
            write_wss_log(client_ip, "Connection closed.")
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
        
        # --- 集成 uvloop 提升性能 ---
        if UVLOOP_AVAILABLE:
            uvloop.install()
            print("INFO: uvloop event loop installed for high performance.")
        # ------------------------------
        
        asyncio.run(main())
    except KeyboardInterrupt:
        print("WSS Proxy Stopped.")
    except Exception as e:
        print(f"FATAL ERROR: {e}")

EOF

/bin/chmod +x /usr/local/bin/wss
/usr/bin/touch /var/log/wss.log
/usr/bin/chmod 640 /var/log/wss.log # 确保只有 root 和 adm/syslog 组可读

# 创建 WSS systemd 服务 (新增 SSH_TARGET_PORT 参数)
/usr/bin/tee /etc/systemd/system/wss.service > /dev/null <<EOF
[Unit]
Description=WSS Python Proxy (V6.6 IP Fix)
After=network.target

[Service]
Type=simple
Environment=WSS_PANEL_PORT=$PANEL_PORT
ExecStart=$PYTHON_VENV_PATH /usr/local/bin/wss $WSS_HTTP_PORT $WSS_TLS_PORT $SSH_TARGET_PORT
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

/bin/systemctl daemon-reload
/bin/systemctl enable wss || true
/bin/systemctl restart wss || true
echo "WSS 核心代理 (V6.6 IP 修复版) 已启动/重启，HTTP端口 $WSS_HTTP_PORT, TLS端口 $WSS_TLS_PORT"
echo "转发目标端口: $SSH_TARGET_PORT"
echo "----------------------------------"

# --- 2.5. 配置 WSS 日志旋转 ---
/usr/bin/tee /etc/logrotate.d/wss > /dev/null <<EOF
/var/log/wss.log {
    daily
    missingok
    rotate 7
    compress
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        /bin/systemctl reload wss > /dev/null 2>&1 || true
    endscript
}
EOF
echo "WSS 日志旋转配置已创建。"
echo "----------------------------------"


# --- 3. Stunnel4, UDPGW (统一目标端口 $SSH_TARGET_PORT) ---
echo "==== 检查/安装 Stunnel4 ===="
/usr/bin/mkdir -p /etc/stunnel/certs
if [ ! -f "/etc/stunnel/certs/stunnel.pem" ]; then
    echo "Stunnel 证书不存在，正在生成..."
    /usr/bin/openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout /etc/stunnel/certs/stunnel.key \
    -out /etc/stunnel/certs/stunnel.crt \
    -days 1095 \
    -subj "/CN=example.com"
    # 证书文件合并
    /bin/sh -c '/bin/cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
    # 严格设置权限
    /bin/chmod 600 /etc/stunnel/certs/*.key
    /bin/chmod 600 /etc/stunnel/certs/*.pem
    /bin/chmod 644 /etc/stunnel/certs/*.crt
    echo "Stunnel 证书已生成并设置严格权限 (600)。"
fi

/usr/bin/tee /etc/stunnel/ssh-tls.conf > /dev/null <<EOF
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
connect = 127.0.0.1:$SSH_TARGET_PORT 
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
EOF

/bin/systemctl enable stunnel4 || true
/bin/systemctl restart stunnel4 || true
echo "Stunnel4 配置已更新并重启，端口 $STUNNEL_PORT (转发至 $SSH_TARGET_PORT)"
echo "----------------------------------"

echo "==== 检查/安装 UDPGW ===="
if [ ! -f "/root/badvpn/badvpn-build/udpgw/badvpn-udpgw" ]; then
    echo "UDPGW 二进制文件不存在，开始编译..."
    if [ ! -d "/root/badvpn" ]; then
        echo "克隆 badvpn 仓库..."
        /usr/bin/apt install -y cmake build-essential || true
        /usr/bin/git clone https://github.com/ambrop72/badvpn.git /root/badvpn || { echo "ERROR: Git clone failed."; exit 1; }
    fi
    /usr/bin/mkdir -p /root/badvpn/badvpn-build
    
    # 使用子shell隔离工作目录，避免使用易出错的 'cd -'
    (
        # 确保使用 shell 内建命令 'cd'
        cd /root/badvpn/badvpn-build || { echo "ERROR: 无法进入编译目录 /root/badvpn/badvpn-build。"; exit 1; }
        
        echo "开始配置和编译 UDPGW..."
        # 显式使用 /usr/bin/cmake 和 /usr/bin/make 确保路径正确
        if /usr/bin/cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 ; then
            if /usr/bin/make -j$(/usr/bin/nproc); then
                echo "UDPGW 编译成功。"
            else
                echo "ERROR: UDPGW make failed."
                exit 1
            fi
        else
            echo "ERROR: UDPGW cmake failed."
            exit 1
        fi
    ) || { echo "ERROR: UDPGW 编译子进程失败。"; exit 1; }
    
else
    echo "UDPGW 二进制文件已存在，跳过编译。"
fi

/usr/bin/tee /etc/systemd/system/udpgw.service > /dev/null <<EOF
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

/bin/systemctl daemon-reload
/bin/systemctl enable udpgw || true
/bin/systemctl restart udpgw || true
echo "UDPGW 已启动/重启，端口: $UDPGW_PORT"
echo "----------------------------------"


# --- 4. 安装 WSS 用户管理面板 (V6.6 IP修复与清理版) ---
echo "==== 部署 WSS 用户管理面板 (Python/Flask) V6.6 IP修复与清理版 ===="
PANEL_DIR="/etc/wss-panel"
USER_DB="$PANEL_DIR/users.json"
IP_BANS_DB="$PANEL_DIR/ip_bans.json"
ROOT_HASH_FILE="$PANEL_DIR/root_hash.txt"

/usr/bin/mkdir -p "$PANEL_DIR"

[ ! -f "$IP_BANS_DB" ] && echo "{}" > "$IP_BANS_DB"

if [ ! -f "$ROOT_HASH_FILE" ]; then
    echo "$PANEL_ROOT_PASS_HASH" > "$ROOT_HASH_FILE"
fi

if [ ! -f "$USER_DB" ]; then
    echo "[]" > "$USER_DB"
else
    # 清理所有已移除的流量和并发字段
    /usr/bin/python3 -c "
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
        # 彻底清除所有与流量和并发相关的字段 (max_connections, max_conn等)
        for field in ['quota_gb', 'used_traffic_gb', 'last_check', 'max_connections', 'max_conn', 'current_conn_count', 'is_over_limit']:
            if field in user: del user[field]; updated = True
    if updated:
        with open(USER_DB_PATH, 'w') as f: json.dump(users, f, indent=4)
        print('User database structure upgraded and cleaned (V6.6).')
upgrade_users()
"
fi

# 嵌入 Python 面板代码
/usr/bin/tee /usr/local/bin/wss_panel.py > /dev/null <<EOF
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
import shutil 
import logging # 导入 logging

# 设置日志级别
# logging.basicConfig(level=logging.DEBUG)

# --- 配置 ---
PANEL_DIR = "/etc/wss-panel"
USER_DB_PATH = os.path.join(PANEL_DIR, "users.json")
IP_BANS_DB_PATH = os.path.join(PANEL_DIR, "ip_bans.json")
AUDIT_LOG_PATH = os.path.join(PANEL_DIR, "audit.log")
ROOT_HASH_FILE = os.path.join(PANEL_DIR, "root_hash.txt")
WSS_LOG_FILE = '/var/log/wss.log' # 读取 WSS 代理自定义日志

ROOT_USERNAME = "root"
SSH_TARGET_PORT = $SSH_TARGET_PORT

PANEL_PORT = "$PANEL_PORT"
WSS_HTTP_PORT = "$WSS_HTTP_PORT"
WSS_TLS_PORT = "$WSS_TLS_PORT"
STUNNEL_PORT = "$STUNNEL_PORT"
UDPGW_PORT = "$UDPGW_PORT"

SERVER_IP = os.environ.get('SERVER_IP', '[Your Server IP]')

app = Flask(__name__)
# 警告: 生产环境应将 SECRET_KEY 写入配置文件以保证持久性，这里使用随机生成以简化部署
app.secret_key = os.urandom(24).hex()

# --- 数据库操作 / 日志 / 认证 / 系统工具函数 ---
def load_data(path, default_value):
    if not os.path.exists(path): return default_value
    try:
        with open(path, 'r') as f: return json.load(f)
    except Exception as e:
        # logging.error(f"Error loading {path}: {e}")
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
        # logging.error(f"Error saving root hash: {e}")
        return False

def save_data(data, path):
    try:
        with open(path, 'w') as f: json.dump(data, f, indent=4)
        return True
    except Exception as e:
        # logging.error(f"Error saving {path}: {e}")
        return False

def load_users(): return load_data(USER_DB_PATH, [])
def save_users(users): return save_data(users, USER_DB_PATH)
def load_ip_bans(): return load_data(IP_BANS_DB_PATH, {})
def save_ip_bans(ip_bans): return save_data(ip_bans, IP_BANS_DB_PATH)
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
        print(f"Error writing to audit log: {e}") # 无法使用 logging，因为可能在 Flask context 之外
        # logging.error(f"Error writing to audit log: {e}")

def get_recent_logs(n=20):
    try:
        if not os.path.exists(AUDIT_LOG_PATH):
            return ["日志文件不存在。"]
        command = [shutil.which('tail') or '/usr/bin/tail', '-n', str(n), AUDIT_LOG_PATH]
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
    """安全运行系统命令。"""
    try:
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if input_data is not None else None,
            text=True, 
            encoding='utf-8'
        )
        stdout, stderr = process.communicate(input=input_data, timeout=5)
        
        if process.returncode != 0:
             return False, stderr.strip() if stderr else f"Command failed with code {process.returncode}"

        return True, stdout.strip()
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        return False, "Command timed out"
    except FileNotFoundError as e:
        return False, f"Command not found: {command[0]}"
    except Exception as e:
        return False, f"Execution error: {str(e)}"

def toggle_iptables_ip_ban(ip, action):
    """在 WSS_IP_BLOCK 链中添加或移除 IP 阻断规则，并保存规则。"""
    chain = "WSS_IP_BLOCK"
    
    # 简单的 IP 地址校验
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$', ip):
        return False, "Invalid IP address format."

    if action == 'block':
        # 尝试删除旧规则 (避免重复)
        safe_run_command([shutil.which('iptables') or '/sbin/iptables', '-D', chain, '-s', ip, '-j', 'DROP'])
        # 插入新规则
        command = [shutil.which('iptables') or '/sbin/iptables', '-I', chain, '1', '-s', ip, '-j', 'DROP']
    elif action == 'unblock':
        command = [shutil.which('iptables') or '/sbin/iptables', '-D', chain, '-s', ip, '-j', 'DROP']
    else: return False, "Invalid action"

    success, output = safe_run_command(command)

    # 忽略非致命错误，例如规则不存在时的删除操作
    if success or 'Bad rule' in output or 'No chain/target/match by that name' in output:
        try:
            # 使用绝对路径确保 iptables-save 找到
            subprocess.run([shutil.which('iptables-save') or '/sbin/iptables-save'], stdout=open('/etc/iptables/rules.v4', 'w'), check=True, timeout=3)
            return True, "IPTables rule updated and saved."
        except Exception:
            return True, "IPTables rule updated but failed to save persistence file."

    return success, output

def kill_user_sessions(username):
    """终止给定用户名的所有活跃 SSH 会话."""
    safe_run_command([shutil.which('pkill') or '/usr/bin/pkill', '-u', username])

# --- 核心用户状态管理函数 (简化版: 仅检查到期日和手动暂停) ---

def sync_user_status(user):
    """根据到期日和手动状态同步系统账户状态。"""
    username = user['username']

    is_expired = False

    # 检查到期日
    if user['expiry_date']:
        try:
            expiry_dt = datetime.strptime(user['expiry_date'], '%Y-%m-%d')
            if expiry_dt.date() < datetime.now().date(): is_expired = True
        except ValueError: 
            print(f"Invalid expiry_date format for {username}: {user['expiry_date']}")
            # 设为非过期，等待管理员修正
            is_expired = False 

    should_be_paused = (user.get('status') == 'paused') or is_expired

    system_locked = False
    success_status, output_status = safe_run_command([shutil.which('passwd') or '/usr/bin/passwd', '-S', username])
    if success_status and output_status and ' L ' in output_status: system_locked = True

    if not should_be_paused and system_locked:
        safe_run_command([shutil.which('usermod') or '/usr/sbin/usermod', '-U', username])
        if user['expiry_date']: safe_run_command([shutil.which('chage') or '/usr/bin/chage', '-E', user['expiry_date'], username])
        else: safe_run_command([shutil.which('chage') or '/usr/bin/chage', '-E', '', username])
        user['status'] = 'active'

    elif should_be_paused and not system_locked:
        safe_run_command([shutil.which('usermod') or '/usr/sbin/usermod', '-L', username])
        safe_run_command([shutil.which('chage') or '/usr/bin/chage', '-E', '1970-01-01', username])
        kill_user_sessions(username)
        user['status'] = 'paused'
    
    # 清理所有与连接数相关的字段（V6.6 清理）
    user.pop('current_conn_count', None)
    user.pop('max_conn', None)
    user.pop('is_over_limit', None)
    user.pop('max_connections', None) 

    return user

def refresh_all_user_status(users):
    """更新所有用户状态并生成显示所需的字段。"""
    updated = False
    for user in users:
        user = sync_user_status(user)

        user['status_text'] = "Active"
        user['status_class'] = "bg-green-500"

        if user['status'] == 'paused':
            user['status_text'] = "Paused (Manual)"
            user['status_class'] = "bg-yellow-500"
        elif user.get('expiry_date') and datetime.strptime(user['expiry_date'], '%Y-%m-%d').date() < datetime.now().date():
            user['status_text'] = "Expired"
            user['status_class'] = "bg-red-500"
        
        # 移除已弃用的并发字段以防模板报错
        user.pop('max_conn', None) 
        user.pop('current_conn_count', None) 

        updated = True
    if updated: save_users(users)
    return users

def get_service_status(service):
    """检查 systemd 服务的状态."""
    try:
        success, output = safe_run_command([shutil.which('systemctl') or '/bin/systemctl', 'is-active', service])
        return 'running' if success and output == 'active' else 'failed'
    except Exception:
        return 'failed'

# --- 新增：活动日志解析函数 (读取 WSS 自定义日志) ---
def get_user_activity_ips(username, n_lines=1000):
    """从 WSS 自定义日志中获取客户端真实 IP 和连接事件。"""
    
    if not os.path.exists(WSS_LOG_FILE):
        # 尝试从系统日志获取，作为回退或辅助（但不依赖其 IP）
        return {"error": "找不到 WSS 自定义日志文件。请确认 WSS 代理已启动并运行。"}
    
    ip_records = {} # {ip: {last_attempt: timestamp, last_status: 'SUCCESS'/'CLOSED'/'BLOCKED', log_count: N}}
    raw_logs = []

    try:
        tail_command = [shutil.which('tail') or '/usr/bin/tail', '-n', str(n_lines), WSS_LOG_FILE]
        success, tail_output = safe_run_command(tail_command)
        if not success:
            return {"error": f"无法读取 WSS 日志文件: {tail_output}"}
            
        # 1. 解析 WSS 代理日志
        # 日志格式: [YYYY-MM-DD HH:MM:SS] [WSS_CONN] [IP:xxx.xxx.xxx.xxx] Message
        for line in tail_output.split('\n'):
            line = line.strip()
            if not line: continue
            
            # 提取 IP
            ip_match = re.search(r'\[IP:([\d.:a-fA-F]+)\]', line)
            if not ip_match: continue
            ip = ip_match.group(1)
            
            # 提取时间戳
            time_match = re.match(r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]', line)
            log_timestamp = int(time.time())
            if time_match:
                try:
                    log_timestamp = int(datetime.strptime(time_match.group(1), '%Y-%m-%d %H:%M:%S').timestamp())
                except ValueError:
                    pass

            # 确定状态
            status = 'ACTIVE' # 默认活跃或连接中
            if 'Handshake SUCCESS' in line:
                status = 'SUCCESS'
            elif 'Connection closed' in line:
                status = 'CLOSED'
            elif 'Connection blocked by IP ban list' in line:
                status = 'BLOCKED'
            elif 'ERROR' in line:
                status = 'ERROR'
            
            # 2. 结合 SSHD 日志 (可选，用于判断用户身份)
            # 由于 WSS 代理层无法识别用户身份，我们依赖管理员在面板中对用户进行 IP 封禁。
            # 这里我们只记录 WSS 代理收到的连接 IP。
            
            if ip not in ip_records:
                ip_records[ip] = {
                    'last_attempt': log_timestamp,
                    'last_status': status,
                    'log_count': 0
                }
            
            if log_timestamp > ip_records[ip]['last_attempt']:
                ip_records[ip]['last_attempt'] = log_timestamp
                ip_records[ip]['last_status'] = status
            
            ip_records[ip]['log_count'] += 1
            raw_logs.append(line)

        # 转换为列表并按时间戳排序
        sorted_ip_list = sorted(
            [{'ip': ip, **data} for ip, data in ip_records.items()],
            key=lambda x: x['last_attempt'], reverse=True
        )
        
        return {"ip_data": sorted_ip_list, "raw_logs": raw_logs[-50:][::-1]} # 返回最新的 50 条原始日志

    except Exception as e:
        return {"error": f"处理 WSS 日志时发生异常: {str(e)}"}


# --- Web 路由所需的渲染函数 ---

_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS Panel - 仪表盘 V6.6 IP修复与清理版</title>
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
        .ip-status-success { color: #10B981; }
        .ip-status-fail { color: #EF4444; }
        .ip-status-closed { color: #F59E0B; }
        .ip-status-blocked { color: #DC2626; font-weight: bold; }
        .ip-status-banned-tag { background-color: #FEE2E2; color: #EF4444; font-weight: bold;}
    </style>
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="bg-indigo-600 text-white shadow-lg">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center">
            <h1 class="text-3xl font-bold">WSS 隧道管理面板 V6.6 (IP修复与清理版)</h1>
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
                <p class="text-gray-500 col-span-4">正在加载系统状态...</p>
            </div>
        </div>

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
                <h3 class="text-sm font-medium text-gray-500">WSS/TLS 端口</h3>
                <p class="text-3xl font-bold text-gray-900 mt-1">{{ wss_tls_port }}</p>
            </div>
            <div class="card bg-white p-5 rounded-xl shadow-lg border-l-4 border-yellow-500">
                <h3 class="text-sm font-medium text-gray-500">Stunnel/SSH 目标端口</h3>
                <p class="text-3xl font-bold text-gray-900 mt-1">{{ stunnel_port }} / {{ ssh_target_port }}</p>
            </div>
        </div>
        
        <!-- 服务诊断与控制 -->
        <div class="card bg-white p-6 rounded-xl shadow-lg mb-8">
            <h3 class="text-xl font-semibold text-gray-800 mb-4 border-b pb-2">服务诊断与控制</h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="bg-gray-100 p-4 rounded-lg font-mono text-sm overflow-x-auto">
                    <p><span class="font-bold">服务器 IP 地址:</span> <span class="text-indigo-600">{{ host_ip }}</span></p>
                    <p class="mt-2 font-bold text-gray-700">关键端口监听状态:</p>
                    <div id="port-status-data" class="mt-2 space-y-1">
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

        <!-- 近期管理活动 -->
        <div class="card bg-white p-6 rounded-xl shadow-lg mb-8">
            <h3 class="text-xl font-semibold text-gray-800 mb-4 border-b pb-2">近期管理活动 (最新 20 条)</h3>
            <div class="bg-gray-100 p-4 rounded-lg max-h-96 overflow-y-auto">
                <div id="audit-log-content">
                    <p class="text-gray-500">正在加载日志...</p>
                </div>
            </div>
        </div>

        <!-- Add User Card / User List Card -->
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
                                <button onclick="openIPActivityModal('{{ user.username }}')" 
                                        class="text-xs px-3 py-1 rounded-full font-bold bg-purple-100 text-purple-800 hover:bg-purple-200 btn-action">
                                    IP/活动追踪
                                </button>
                                <button onclick="openSettingsModal('{{ user.username }}', '{{ user.expiry_date }}')" 
                                        class="text-xs px-3 py-1 rounded-full font-bold bg-blue-100 text-blue-800 hover:bg-blue-200 btn-action">
                                    设置
                                </button>
                                <button onclick="openConfirmationModal('{{ user.username }}', '{{ 'pause' if user.status == 'active' else 'active' }}', 'toggleStatus', '{{ '暂停' if user.status == 'active' else '启用' }}')" 
                                        class="text-xs px-3 py-1 rounded-full font-bold {{ 'bg-yellow-100 text-yellow-800 hover:bg-yellow-200' if user.status == 'active' else 'bg-green-100 text-green-800 hover:bg-green-200' }} btn-action">
                                    {{ '暂停' if user.status == 'active' else '启用' }}
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
    
    <!-- Modal for Root Password Change -->
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
    
    <!-- Modal for User Settings -->
    <div id="settings-modal" class="modal fixed inset-0 flex items-center justify-center p-4 hidden">
        <div class="modal-content bg-white rounded-xl shadow-2xl w-full max-w-lg transition-all">
            <div class="p-6">
                <h3 class="text-xl font-bold mb-4 text-gray-800 border-b pb-2">设置 <span id="modal-username-title-settings"></span> 的参数</h3>
                <form id="settings-form" onsubmit="event.preventDefault(); saveSettings();">
                    <input type="hidden" id="modal-username-settings">
                    
                    <div class="mb-6">
                        <label for="modal-expiry" class="block text-sm font-medium text-gray-700">到期日 (YYYY-MM-DD, 留空为永不到期)</label>
                        <input type="date" id="modal-expiry" class="mt-1 block w-full p-2 border border-gray-300 rounded-lg">
                    </div>
                    
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
    
    <!-- IP/Activity Tracking Modal (NEW) -->
    <div id="ip-activity-modal" class="modal fixed inset-0 flex items-center justify-center p-4 hidden">
        <div class="modal-content bg-white rounded-xl shadow-2xl w-full max-w-2xl transition-all">
            <div class="p-6">
                <h3 class="text-xl font-bold mb-4 text-gray-800 border-b pb-2">用户组 <span id="ip-activity-modal-title"></span> 的 IP/活动追踪</h3>
                <div class="text-sm text-gray-600 mb-4">
                    <p>数据来源: WSS 代理自定义日志 (<span class="font-mono text-xs">/var/log/wss.log</span>)。可追踪真实公网 IP。</p>
                </div>
                
                <!-- IP List Section -->
                <h4 class="text-lg font-semibold text-gray-800 mb-2">活跃 IP 列表 (最近连接的公网 IP)</h4>
                <div id="ip-activity-list" class="space-y-3 max-h-80 overflow-y-auto p-3 bg-gray-50 rounded-lg border">
                    <p class="text-gray-500">正在加载 IP 数据...</p>
                </div>
                
                <!-- Raw Log Section -->
                <h4 class="text-lg font-semibold text-gray-800 mt-6 mb-2 border-t pt-3">原始 WSS 活动日志 (最新 50 条)</h4>
                <div id="raw-logs-list" class="space-y-1 max-h-48 overflow-y-auto bg-gray-100 p-3 rounded-lg border">
                    <p class="text-gray-500">正在加载日志...</p>
                </div>
                
                <div class="flex justify-end space-x-3 mt-6">
                    <button type="button" onclick="closeIPActivityModal()" class="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded-lg font-semibold btn-action">
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

        // --- System Status & Port Check Logic (No change) ---
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
            // 每 15 秒更新一次系统状态，每 30 秒更新一次审计日志
            setInterval(fetchSystemStatus, 15000); 
            setInterval(fetchAuditLogs, 30000);
        };

        // --- IP/Activity Tracking Modal Logic (NEW) ---
        
        function openIPActivityModal(username) {
            document.getElementById('ip-activity-modal-title').textContent = username;
            
            document.getElementById('ip-activity-list').innerHTML = '<p class="text-gray-500">正在加载 IP 数据...</p>';
            document.getElementById('raw-logs-list').innerHTML = '<p class="text-gray-500">正在加载日志...</p>';
            document.getElementById('ip-activity-modal').classList.remove('hidden');
            
            fetchIPActivity(username);
        }
        
        function closeIPActivityModal() {
            document.getElementById('ip-activity-modal').classList.add('hidden');
        }

        async function fetchIPActivity(username) {
            const API_URL = \`/api/users/ip_activity?username=\${username}\`;
            const ipListDiv = document.getElementById('ip-activity-list');
            const rawLogsDiv = document.getElementById('raw-logs-list');

            try {
                const response = await fetch(API_URL, { method: 'GET' });
                const result = await response.json();

                if (!response.ok || !result.success) {
                    ipListDiv.innerHTML = \`<p class="text-red-500">获取数据失败: \${result.message || result.error || '未知错误'}</p>\`;
                    rawLogsDiv.innerHTML = '<p class="text-red-500">无法加载原始日志。</p>';
                    return;
                }
                
                // 1. 渲染 IP 列表
                const ipData = result.ip_data;
                const bannedIps = result.banned_ips || [];

                if (ipData.length === 0) {
                    ipListDiv.innerHTML = '<p class="text-green-600 font-semibold">WSS 代理日志中没有找到该用户的连接 IP 记录。</p>';
                } else {
                    ipListDiv.innerHTML = ipData.map(ipInfo => {
                        const isBanned = bannedIps.includes(ipInfo.ip);
                        const banAction = isBanned ? 'unblock' : 'block';
                        const banActionText = isBanned ? '解除封禁' : '封禁 IP';
                        const banBtnClass = isBanned ? 'bg-green-600 hover:bg-green-700' : 'bg-red-600 hover:bg-red-700';
                        
                        let statusText;
                        let statusClass;

                        if (isBanned) {
                            statusText = "已封禁";
                            statusClass = "ip-status-blocked";
                        } else if (ipInfo.last_status === 'SUCCESS') {
                            statusText = "握手成功";
                            statusClass = "ip-status-success";
                        } else if (ipInfo.last_status === 'CLOSED') {
                            statusText = "连接关闭";
                            statusClass = "ip-status-closed";
                        } else if (ipInfo.last_status === 'BLOCKED') {
                            statusText = "代理层被阻断";
                            statusClass = "ip-status-blocked";
                        } else {
                            statusText = "连接中/未知";
                            statusClass = "text-gray-600";
                        }

                        const lastAttempt = new Date(ipInfo.last_attempt * 1000).toLocaleString();

                        return \`
                            <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between p-3 bg-white rounded-lg shadow-sm border border-gray-200">
                                <div class="font-mono text-sm text-gray-800 mb-2 sm:mb-0 flex items-center">
                                    <strong class="\${isBanned ? 'text-red-600' : 'text-indigo-600'}">\${ipInfo.ip}</strong> 
                                    <span class="ml-2 px-2 text-xs leading-5 font-semibold rounded-full text-white \${isBanned ? 'bg-red-500 ip-status-banned-tag' : 'bg-gray-500'}" style="\${isBanned ? 'background-color: #FEE2E2; color: #DC2626;' : ''}">\${statusText}</span>
                                    <span class="text-xs text-gray-500 block sm:inline"> | 最后事件: \${lastAttempt} | 次数: \${ipInfo.log_count}</span>
                                </div>
                                <button onclick="toggleIPBanAction('\${username}', '\${ipInfo.ip}', '\${banAction}')"
                                        class="text-xs text-white px-3 py-1 rounded-lg font-semibold btn-action \${banBtnClass}">
                                    \${banActionText}
                                </button>
                            </div>
                        \`;
                    }).join('');
                }
                
                // 2. 渲染原始日志
                const rawLogs = result.raw_logs;
                if (rawLogs.length === 0) {
                    rawLogsDiv.innerHTML = '<p class="text-gray-500">没有匹配的原始日志记录。</p>';
                } else {
                    rawLogsDiv.innerHTML = rawLogs.map(log => {
                        const statusClass = log.includes('Handshake SUCCESS') ? 'text-green-600' : log.includes('blocked') ? 'text-red-600' : 'text-gray-800';
                        return \`<div class="log-entry p-1 rounded hover:bg-gray-200 \${statusClass}">\${log}</div>\`;
                    }).join('');
                }

            } catch (error) {
                ipListDiv.innerHTML = '<p class="text-red-500">请求失败，请检查面板运行状态。</p>';
                rawLogsDiv.innerHTML = '<p class="text-red-500">请求失败，无法加载日志。</p>';
            }
        }
        
        async function toggleIPBanAction(username, ip, action) {
            const actionText = action === 'block' ? '封禁' : '解除封禁';

            try {
                const response = await fetch(\`/api/ips/\${action}\`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, ip })
                });

                const result = await response.json();

                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    // 刷新 IP 列表
                    fetchIPActivity(username); 
                } else {
                    showStatus(\`\${actionText}失败: \` + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        }


        // --- Settings Modal Logic (CONCURRENCY REMOVED) ---
        
        function openSettingsModal(username, expiry) { // 移除了 maxConn 参数
            document.getElementById('modal-username-title-settings').textContent = username;
            document.getElementById('modal-username-settings').value = username;
            
            document.getElementById('modal-expiry').value = expiry || '';
            document.getElementById('modal-new-password').value = '';
            
            document.getElementById('settings-modal').classList.remove('hidden');
        }

        function closeSettingsModal() {
            document.getElementById('settings-modal').classList.add('hidden');
        }

        async function saveSettings() {
            const username = document.getElementById('modal-username-settings').value;
            const expiry_date = document.getElementById('modal-expiry').value;
            const new_ssh_password = document.getElementById('modal-new-password').value;

            try {
                // max_connections 字段被移除
                const response = await fetch('/api/users/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, expiry_date, new_ssh_password })
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
        
        // --- Root Password Modal Logic / Confirmation Logic (No change) ---
        
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
                    setTimeout(() => { logout(); }, 1500);
                } else {
                    showStatus('修改密码失败: ' + result.message, false);
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
    template = template_env.from_string(_DASHBOARD_HTML)
    
    host_ip = request.host.split(':')[0]
    if host_ip in ('127.0.0.1', 'localhost', '0.0.0.0', '::1'):
        host_ip = SERVER_IP
        
    context = {
        'users': users,
        'panel_port': PANEL_PORT,
        'wss_http_port': WSS_HTTP_PORT,
        'wss_tls_port': WSS_TLS_PORT,
        'stunnel_port': STUNNEL_PORT,
        'udpgw_port': UDPGW_PORT,
        'ssh_target_port': SSH_TARGET_PORT,
        'host_ip': host_ip,
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
        <h1 class="text-2xl">WSS 管理面板 V6.6</h1>
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

# --- Root 密码修改 API (No change) ---
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

    user_exists_on_system = False
    
    success, output = safe_run_command([shutil.which('useradd') or '/usr/sbin/useradd', '-m', '-s', '/bin/false', username])
    if not success:
        if "already exists" in output:
            user_exists_on_system = True
            success_check, _ = safe_run_command([shutil.which('id') or '/usr/bin/id', username])
            if not success_check:
                 log_action("USER_ADD_FAIL", session.get('username', 'root'), f"User {username} exists but ID failed: {output}")
                 return jsonify({"success": False, "message": f"系统用户 {username} 已存在，但无法验证其身份。"}), 500
            
            log_action("USER_ADD_WARN", session.get('username', 'root'), f"System user {username} already exists, attempting to adopt.")
        else:
            log_action("USER_ADD_FAIL", session.get('username', 'root'), f"Failed to create system user {username}: {output}")
            return jsonify({"success": False, "message": f"创建系统用户失败: {output}"}), 500
    
    chpasswd_input = f"{username}:{password_raw}"
    success, output = safe_run_command([shutil.which('chpasswd') or '/usr/sbin/chpasswd'], input_data=chpasswd_input)
    if not success:
        if not user_exists_on_system: safe_run_command([shutil.which('userdel') or '/usr/sbin/userdel', '-r', username])
        log_action("USER_ADD_FAIL", session.get('username', 'root'), f"Failed to set password for {username}: {output}")
        return jsonify({"success": False, "message": f"设置密码失败: {output}"}), 500
        
    new_user = {
        "username": username, "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "status": "active", "expiry_date": "",
        "banned_ips": [], 
        # max_connections 已被移除 (V6.6 清理)
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

    if not user_to_delete: return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404

    kill_user_sessions(username)
    
    ip_bans = load_ip_bans()
    if username in ip_bans:
        # 清除 IPTABLES 规则
        for ip in ip_bans[username]: toggle_iptables_ip_ban(ip, 'unblock')
        ip_bans.pop(username)
        save_ip_bans(ip_bans)

    success, output = safe_run_command([shutil.which('userdel') or '/usr/sbin/userdel', '-r', username])
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
    # max_connections 字段已被移除 (V6.6 清理)
    new_ssh_password = data.get('new_ssh_password', '')

    user, index = get_user(username)
    if not user: return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
        
    users = load_users()
    
    try:
        if expiry_date: datetime.strptime(expiry_date, '%Y-%m-%d')
    except ValueError: return jsonify({"success": False, "message": "日期格式不正确"}), 400

    old_expiry = users[index].get('expiry_date')
    
    users[index]['expiry_date'] = expiry_date
    
    password_log = ""
    if new_ssh_password:
        chpasswd_input = f"{username}:{new_ssh_password}"
        success, output = safe_run_command([shutil.which('chpasswd') or '/usr/sbin/chpasswd'], input_data=chpasswd_input)
        if success:
            password_log = ", SSH password changed"
        else:
            log_action("USER_PASS_FAIL", session.get('username', 'root'), f"Failed to set password for {username}: {output}")
            return jsonify({"success": False, "message": f"设置 SSH 密码失败: {output}"}), 500
    
    users[index] = sync_user_status(users[index])
    
    save_users(users)
    log_action("SETTINGS_UPDATE", session.get('username', 'root'), 
               f"Updated {username}: Expiry {old_expiry}->{expiry_date}{password_log}")
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

# --- IP/活动追踪 API ---
@app.route('/api/users/ip_activity', methods=['GET'])
@login_required
def get_user_ip_activity_api():
    """获取指定用户的 WSS 代理日志中记录的真实客户端 IP。"""
    username = request.args.get('username')
    
    if not username: return jsonify({"success": False, "message": "缺少用户名"}), 400
    
    # 获取 WSS 日志解析结果
    log_result = get_user_activity_ips(username)
    
    if "error" in log_result:
         return jsonify({"success": False, "error": log_result['error']}), 500
         
    # 获取用户的 IP 封禁列表
    ip_bans = load_ip_bans()
    banned_ips = ip_bans.get(username, [])
    
    return jsonify({
        "success": True, 
        "ip_data": log_result['ip_data'],
        "raw_logs": log_result['raw_logs'],
        "banned_ips": banned_ips
    })


# --- 实时系统状态 & 服务控制 API (No change) ---
@app.route('/api/system/status', methods=['GET'])
@login_required 
def get_system_status():
    """获取服务器 CPU/内存/服务状态."""
    
    def get_port_status(port):
        """检查端口是否处于 LISTEN 状态 (使用 ss 命令)"""
        try:
            ss_bin = shutil.which('ss') or '/bin/ss'
            success, output = safe_run_command([ss_bin, '-tuln'], input_data=None)
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
    action = data.get('action')

    allowed_services = ['wss', 'wss_panel', 'stunnel4', 'udpgw']
    if service not in allowed_services or action != 'restart':
        log_action("SERVICE_CONTROL_FAIL", session.get('username', 'root'), f"Attempted illegal action/service: {action}/{service}")
        return jsonify({"success": False, "message": "无效的服务或操作"}), 400
        
    if service == 'wss_panel':
        log_action("SERVICE_CONTROL_WARN", session.get('username', 'root'), "Panel restart requested. Connection may drop.")

    command = [shutil.which('systemctl') or '/bin/systemctl', action, service]
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
    """供 WSS 代理调用的 IP 封禁检查 API (必须来自本地回环)"""
    if request.remote_addr != '127.0.0.1' and request.remote_addr != '::1': return jsonify({"success": False, "message": "Access denied"}), 403
        
    data = request.json
    client_ip = data.get('ip')
    
    if not client_ip: return jsonify({"success": False, "message": "缺少 IP"}), 400

    ip_bans = load_ip_bans()
    
    is_banned = False
    # 遍历所有用户的封禁列表
    for banned_ips in ip_bans.values():
        if client_ip in banned_ips:
            is_banned = True
            break
            
    return jsonify({"success": True, "is_banned": is_banned})

# 此路由已弃用，功能合并到 ip_activity API
@app.route('/api/ips/status', methods=['GET'])
@login_required
def get_ip_ban_status():
    username = request.args.get('username')
    ip_bans = load_ip_bans()
    
    if not username: return jsonify({"success": False, "message": "缺少用户名"}), 400
    
    return jsonify({"success": True, "banned_ips": ip_bans.get(username, [])})


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
        
    if success_iptables:
        log_action("IP_BLOCK_SUCCESS", session.get('username', 'root'), f"Blocked IP {ip} for user {username}")
        return jsonify({"success": True, "message": f"IP {ip} 已被封禁 (实时生效)。"})
    else:
        log_action("IP_BLOCK_WARNING", session.get('username', 'root'), 
                   f"Blocked IP {ip} in DB for user {username}, but IPTables failed: {iptables_output}")
        return jsonify({"success": False, "message": f"IP {ip} 已被封禁 (面板记录已更新)，但实时防火墙操作失败: {iptables_output}"})

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
        return jsonify({"success": False, "message": f"IP {ip} 已解除封禁 (面板记录已更新)，但实时防火墙操作失败: {iptables_output}"})


if __name__ == '__main__':
    print(f"WSS Panel running on port {PANEL_PORT}")
    app.run(host='0.0.0.0', port=int(PANEL_PORT), debug=False)
EOF

/bin/chmod +x /usr/local/bin/wss_panel.py

export SERVER_IP

# --- 5. 创建 WSS 面板 systemd 服务 ---
if [ ! -f "/etc/systemd/system/wss_panel.service" ]; then
/usr/bin/tee /etc/systemd/system/wss_panel.service > /dev/null <<EOF
[Unit]
Description=WSS User Management Panel (Flask V6.6 IP Fix)
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

/bin/systemctl daemon-reload
# 更新服务描述的版本号
/usr/bin/sed -i "s|Description=WSS User Management Panel (Flask V6.*|Description=WSS User Management Panel (Flask V6.6 IP Fix)|" /etc/systemd/system/wss_panel.service
/usr/bin/sed -i "s|^ExecStart=.*|ExecStart=$PYTHON_VENV_PATH /usr/local/bin/wss_panel.py|" /etc/systemd/system/wss_panel.service

/bin/systemctl daemon-reload
/bin/systemctl enable wss || true
/bin/systemctl restart wss_panel
echo "WSS 管理面板 V6.6 IP修复与清理版 已启动/重启，端口 $PANEL_PORT"
echo "----------------------------------"

# --- 6. 部署 IPTABLES 阻断链设置 ---

setup_iptables_chains() {
    echo "==== 配置 IPTABLES 规则 (开放服务端口并设置 IP 阻断链) ===="
    
    BLOCK_CHAIN="WSS_IP_BLOCK"
    
    # 清理旧的 WSS 链和规则
    /sbin/iptables -D INPUT -j $BLOCK_CHAIN 2>/dev/null || true
    /sbin/iptables -F $BLOCK_CHAIN 2>/dev/null || true
    /sbin/iptables -X $BLOCK_CHAIN 2>/dev/null || true
    
    # 允许 loopback 接口
    /sbin/iptables -A INPUT -i lo -j ACCEPT
    # 允许已建立的和相关的连接
    /sbin/iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # 1. 创建并插入 IP 阻断链 (必须在端口开放规则之前，以实现实时封禁)
    /sbin/iptables -N $BLOCK_CHAIN 2>/dev/null || true 
    /sbin/iptables -I INPUT 1 -j $BLOCK_CHAIN # 插入到最前面

    # 2. 开放 TCP 服务端口
    echo "开放 TCP 端口: $WSS_HTTP_PORT(HTTP), $WSS_TLS_PORT(TLS), $STUNNEL_PORT(Stunnel), $PANEL_PORT(Panel)"
    /sbin/iptables -A INPUT -p tcp --dport $WSS_HTTP_PORT -j ACCEPT
    /sbin/iptables -A INPUT -p tcp --dport $WSS_TLS_PORT -j ACCEPT
    /sbin/iptables -A INPUT -p tcp --dport $STUNNEL_PORT -j ACCEPT
    /sbin/iptables -A INPUT -p tcp --dport $PANEL_PORT -j ACCEPT

    # 3. 开放 UDPGW 端口
    echo "开放 UDP 端口: $UDPGW_PORT(UDPGW)"
    /sbin/iptables -A INPUT -p udp --dport $UDPGW_PORT -j ACCEPT
    
    # 4. 保存规则
    if command -v /sbin/iptables-save >/dev/null; then
        /sbin/iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        echo "IPTABLES 规则已保存到 /etc/iptables/rules.v4。"
    fi

    echo "IPTABLES 规则更新完成，所有服务端口已开放。"
}

setup_iptables_chains


# --- 7. 移除流量同步 Cron Job (No change) ---
echo "==== 移除流量同步 Cron Job ===="
/bin/rm -f /etc/cron.d/wss-traffic || true
echo "流量同步 Cron Job 已移除。"
echo "----------------------------------"

# --- 8. SSHD 安全配置 (No change) ---
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_SUFFIX=".bak.wss$(date +%s)"
SSHD_SERVICE=$(/bin/systemctl list-units --full -all | /bin/grep -E "sshd\.service|ssh\.service" | /bin/grep -v "not-found" | /usr/bin/head -n 1 | /usr/bin/awk '{print $1}' | /usr/bin/cut -d'.' -f1 || echo "sshd")

echo "==== 配置 SSHD 安全策略 (增强连接稳定性) ===="
/bin/cp -a "$SSHD_CONFIG" "${SSHD_CONFIG}${BACKUP_SUFFIX}"
echo "SSHD 配置已备份到 ${SSHD_CONFIG}${BACKUP_SUFFIX}"

/bin/sed -i '/# WSS_TUNNEL_BLOCK_START/,/# WSS_TUNNEL_BLOCK_END/d' "$SSHD_CONFIG"

/bin/cat >> "$SSHD_CONFIG" <<EOF

# WSS_TUNNEL_BLOCK_START -- managed by deploy_wss_panel.sh (V6.6 IP Fix)
# 统一策略: 允许所有用户通过本机 (127.0.0.1, ::1) 使用密码进行认证。
Match Address 127.0.0.1,::1
    PasswordAuthentication yes
    PermitTTY no
    X11Forwarding no
    AllowTcpForwarding yes
    ForceCommand /bin/false
    ClientAliveInterval 30
    ClientAliveCountMax 120
# WSS_TUNNEL_BLOCK_END -- managed by deploy_wss_panel.sh (V6.6 IP Fix)

EOF

/bin/chmod 600 "$SSHD_CONFIG"

echo "重新加载并重启 ssh 服务 ($SSHD_SERVICE)"
/bin/systemctl daemon-reload
/bin/systemctl restart "$SSHD_SERVICE"
echo "SSHD 配置更新完成，连接稳定性已增强。"
echo "----------------------------------"

unset PANEL_ROOT_PASS_RAW

echo "=================================================="
echo "✅ WSS 管理面板部署完成！ (V6.6 IP修复与并发清理版)"
echo "=================================================="
echo "核心功能已更新："
echo "1. **公网 IP 追踪修复**: WSS 代理现在会将真实客户端 IP 记录到 `/var/log/wss.log`。"
echo "2. **并发限制清理**: 已彻底移除所有并发连接数相关的代码和字段。"
echo "3. **安全性提升**: Stunnel 证书权限已优化为 600。"
echo "面板访问端口: $PANEL_PORT (请访问该端口登录)"
echo "请确保防火墙已开放 $WSS_HTTP_PORT, $WSS_TLS_PORT, $STUNNEL_PORT, $UDPGW_PORT, $PANEL_PORT 端口。"
echo "=================================================="
