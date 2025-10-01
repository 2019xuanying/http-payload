#!/usr/bin/env bash
set -euo pipefail

# =============================
# WSS Panel 一键部署脚本 
# 集成 WSS 代理, Stunnel, UDPGW, 用户管理面板, 流量/到期日功能
# =============================

# ====== 可修改项 ======
WSS_USER_DEFAULT="wssuser"
SSH_HOME_BASE="/home"
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_SUFFIX=".bak.wss$(date +%s)"
# 默认端口
WSS_HTTP_PORT_DEFAULT=80
WSS_TLS_PORT_DEFAULT=443
STUNNEL_PORT_DEFAULT=444
UDPGW_PORT_DEFAULT=7300
PANEL_PORT_DEFAULT=8080

# 路径常量
WSS_SCRIPT="/usr/local/bin/wss"
PANEL_SCRIPT="/usr/local/bin/wss_panel.py"
ACCOUNTANT_SCRIPT="/usr/local/bin/wss_accountant.py"
PANEL_CONFIG_DIR="/etc/wss-panel"
PANEL_CONFIG_FILE="${PANEL_CONFIG_DIR}/panel_config.json"
USER_DB_PATH="${PANEL_CONFIG_DIR}/users.json"
# ======================

# --- 辅助函数 ---
spinner() {
    local pid=$!
    local delay=0.1
    local spin_chars="/-\|"
    echo -n "..."
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spin_chars#?}
        printf "%c" "$spin_chars"
        spin_chars=$temp${spin_chars:0:1}
        sleep "$delay"
        printf "\b"
    done
    printf " \b"
}

log() {
    echo -e "[\033[1;34mINFO\033[0m] $1"
}

error() {
    echo -e "[\033[1;31mERROR\033[0m] $1" >&2
    exit 1
}

# --- 交互式提示和密码设置 ---
read_user_input() {
    read -p "请输入 WSS HTTP 监听端口（默认${WSS_HTTP_PORT_DEFAULT}）: " WSS_HTTP_PORT
    WSS_HTTP_PORT=${WSS_HTTP_PORT:-$WSS_HTTP_PORT_DEFAULT}

    read -p "请输入 WSS TLS 监听端口（默认${WSS_TLS_PORT_DEFAULT}）: " WSS_TLS_PORT
    WSS_TLS_PORT=${WSS_TLS_PORT:-$WSS_TLS_PORT_DEFAULT}

    read -p "请输入 Stunnel4 端口（默认${STUNNEL_PORT_DEFAULT}）: " STUNNEL_PORT
    STUNNEL_PORT=${STUNNEL_PORT:-$STUNNEL_PORT_DEFAULT}

    read -p "请输入 UDPGW 端口（默认${UDPGW_PORT_DEFAULT}）: " UDPGW_PORT
    UDPGW_PORT=${UDPGW_PORT:-$UDPGW_PORT_DEFAULT}

    read -p "请输入 Web 面板监听端口（默认${PANEL_PORT_DEFAULT}）: " PANEL_PORT
    PANEL_PORT=${PANEL_PORT:-$PANEL_PORT_DEFAULT}
    
    # 交互式安全输入 root 密码
    echo "=========================================="
    echo "  请为 Web 面板 root 用户设置登录密码。"
    echo "=========================================="
    while true; do
        read -s -p "密码: " pw1 && echo
        read -s -p "请再次确认密码: " pw2 && echo
        if [ -z "$pw1" ]; then
            echo "密码不能为空，请重新输入。"
            continue
        fi
        if [ "$pw1" != "$pw2" ]; then
            echo "两次输入不一致，请重试。"
            continue
        fi
        ROOT_PASS="$pw1"
        ROOT_PASS_HASH=$(echo -n "$ROOT_PASS" | sha256sum | awk '{print $1}')
        unset ROOT_PASS
        break
    done
}

# --- 部署阶段 1: 系统更新与依赖安装 ---
install_dependencies() {
    log "==== 更新系统并安装依赖 ===="
    sudo apt update -y &> /dev/null & spinner
    sudo apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4 python3-flask python3-jinja2 &> /dev/null & spinner
    log "依赖安装完成 (Python, Flask, Stunnel4, OpenSSL等)"
}

# --- 部署阶段 2: WSS Python 代理脚本 ---
install_wss_proxy() {
    log "==== 安装 WSS 核心代理脚本 (增强日志) ===="
    # WSS 脚本内容 (增强日志)
    cat > "$WSS_SCRIPT" <<'EOF'
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio, ssl, sys
import time
from datetime import datetime

LISTEN_ADDR = '0.0.0.0'
DEFAULT_TARGET = ('127.0.0.1', 41816) 
BUFFER_SIZE = 65536
TIMEOUT = 3600
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'

# Responses
FIRST_RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK\r\n\r\n'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'
FORBIDDEN_RESPONSE = b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'

def log(peer, message, tls=False):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    protocol = '(TLS)' if tls else '(HTTP)'
    print(f"{timestamp} {protocol} [{peer[0]}:{peer[1]}] {message}")

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, http_port, tls_port, tls=False):
    peer = writer.get_extra_info('peername')
    log(peer, "Connection established.", tls)
    forwarding_started = False
    full_request = b''

    try:
        # --- 1. 握手循环 ---
        while not forwarding_started:
            data = await asyncio.wait_for(reader.read(BUFFER_SIZE), timeout=TIMEOUT)
            if not data:
                log(peer, "Client closed connection during handshake.", tls)
                break
            
            full_request += data
            
            header_end_index = full_request.find(b'\r\n\r\n')
            
            headers = full_request[:header_end_index].decode(errors='ignore') if header_end_index != -1 else full_request.decode(errors='ignore')
            data_to_forward = full_request[header_end_index + 4:] if header_end_index != -1 else b''

            # 检查是否为 WebSocket 升级请求
            is_websocket_request = 'Upgrade: websocket' in headers or 'Connection: Upgrade' in headers or 'GET-RAY' in headers
            
            if header_end_index == -1:
                # 头部不完整，发送 200 OK 响应，诱导客户端发送下一段（Payload）
                writer.write(FIRST_RESPONSE)
                await writer.drain()
                log(peer, "Handshake: Sent 200 OK. Waiting for next payload chunk.", tls)
                full_request = b''
                continue
            
            # 2. 头部解析和转发触发
            if is_websocket_request:
                # 找到了完整的 WebSocket 握手请求
                writer.write(SWITCH_RESPONSE)
                await writer.drain()
                forwarding_started = True
                log(peer, "Handshake: Sent 101 Switching Protocols. Starting forwarding.", tls)
            else:
                # 找到了完整的非 WebSocket 请求 (例如，可能是一个浏览器请求或第一段 Payload)
                writer.write(FIRST_RESPONSE)
                await writer.drain()
                log(peer, "Handshake: Received non-WebSocket request. Sent 200 OK. Waiting for next chunk.", tls)
                full_request = b''
                continue

        # --- 退出握手循环 ---
        
        # 3. 目标解析 (保持默认，因为 SSHD 已经配置为只允许本机登录)
        target = DEFAULT_TARGET

        # 4. 连接目标服务器
        target_reader, target_writer = await asyncio.open_connection(*target)
        log(peer, f"Successfully connected to target: {target[0]}:{target[1]}", tls)

        # 5. 转发初始数据 (SSH 握手)
        if data_to_forward:
            target_writer.write(data_to_forward)
            await target_writer.drain()
            log(peer, f"Forwarded {len(data_to_forward)} bytes of initial payload.", tls)
        
        # 6. 转发后续数据流
        async def pipe(src_reader, dst_writer, direction):
            bytes_forwarded = 0
            try:
                while True:
                    buf = await asyncio.wait_for(src_reader.read(BUFFER_SIZE), timeout=TIMEOUT)
                    if not buf:
                        break
                    dst_writer.write(buf)
                    await dst_writer.drain()
                    bytes_forwarded += len(buf)
            except asyncio.TimeoutError:
                log(peer, f"Pipe timeout ({direction}) after {bytes_forwarded} bytes.", tls)
            except ConnectionResetError:
                log(peer, f"Pipe reset by peer ({direction}). Total bytes: {bytes_forwarded}", tls)
            except Exception as e:
                log(peer, f"Pipe error ({direction}): {e}. Total bytes: {bytes_forwarded}", tls)
            finally:
                dst_writer.close()

        await asyncio.gather(
            pipe(reader, target_writer, "Client -> Target"),
            pipe(target_reader, writer, "Target -> Client")
        )

    except Exception as e:
        log(peer, f"Major connection error: {e}", tls)
    finally:
        writer.close()
        await writer.wait_closed()
        log(peer, "Connection closed.", tls)


async def main():
    # 使用 sys.argv 获取命令行参数。
    try:
        http_port = int(sys.argv[1])
    except (IndexError, ValueError):
        http_port = 80
    
    try:
        tls_port = int(sys.argv[2])
    except (IndexError, ValueError):
        tls_port = 443

    # TLS server setup
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        ssl_ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    except FileNotFoundError:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: TLS certificate not found at {CERT_FILE}. TLS server disabled.")
        return
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR loading certificate: {e}. TLS server disabled.")
        return

    tls_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, http_port, tls_port, tls=True), LISTEN_ADDR, tls_port, ssl=ssl_ctx)
    http_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, http_port, tls_port, tls=False), LISTEN_ADDR, http_port)

    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] WSS Proxy Running.")
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Listening on {LISTEN_ADDR}:{http_port} (HTTP Payload)")
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Listening on {LISTEN_ADDR}:{tls_port} (TLS)")

    async with tls_server, http_server:
        await asyncio.gather(
            tls_server.serve_forever(),
            http_server.serve_forever())

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nService stopped by user.")
    except Exception as e:
        print(f"Fatal error in WSS main loop: {e}")
        time.sleep(5)
EOF

    sudo chmod +x "$WSS_SCRIPT"
}

# --- 部署阶段 3: Stunnel4 和 SSHD 配置 ---
install_stunnel_ssh() {
    log "==== 安装 Stunnel4 并生成自签名证书 ===="
    sudo mkdir -p /etc/stunnel/certs
    sudo openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout /etc/stunnel/certs/stunnel.key \
    -out /etc/stunnel/certs/stunnel.crt \
    -days 3650 \
    -subj "/CN=example.com" &> /dev/null
    sudo sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
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
    
    log "==== 配置 SSHD (仅允许 127.0.0.1 登录) ===="
    cp -a "$SSHD_CONFIG" "${SSHD_CONFIG}${BACKUP_SUFFIX}"
    sed -i '/# WSS_CONFIG_START/,/# WSS_CONFIG_END/d' "$SSHD_CONFIG"
    
    # 优化 2: 增强 SSHD 配置，允许隧道
    cat >> "$SSHD_CONFIG" <<EOF

# WSS_CONFIG_START -- managed by deploy_wss_panel.sh
# 允许来自本机 (WSS/Stunnel 隧道) 的连接使用 SSH 账户/密码
Match Address 127.0.0.1,::1
    PermitTTY yes
    AllowTcpForwarding yes
    PasswordAuthentication yes
    PermitTunnel yes # 优化: 明确允许隧道
# WSS_CONFIG_END -- managed by deploy_wss_panel.sh

EOF
    
    if systemctl list-units --full -all | grep -q "sshd.service"; then
        SSHD_SERVICE="sshd"
    else
        SSHD_SERVICE="ssh"
    fi
    systemctl daemon-reload
    systemctl restart "$SSHD_SERVICE" &> /dev/null & spinner
    log "Stunnel4 和 SSHD 配置完成。Stunnel 端口: $STUNNEL_PORT"
}

# --- 部署阶段 4: UDPGW ---
install_udpgw() {
    log "==== 安装 UDPGW ===="
    local badvpn_dir="/root/badvpn"
    if [ ! -d "$badvpn_dir" ]; then
        git clone https://github.com/ambrop72/badvpn.git "$badvpn_dir" &> /dev/null
    fi
    mkdir -p "$badvpn_dir/badvpn-build"
    cd "$badvpn_dir/badvpn-build"
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 &> /dev/null
    make -j$(nproc) &> /dev/null

    sudo tee /etc/systemd/system/udpgw.service > /dev/null <<EOF
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
    log "UDPGW 编译和配置完成，端口: $UDPGW_PORT"
}

# --- 部署阶段 5: 面板核心和流量统计 ---
install_panel() {
    log "==== 部署 Web 管理面板和流量统计服务 ===="
    mkdir -p "$PANEL_CONFIG_DIR"
    
    # 创建配置文件
    cat > "$PANEL_CONFIG_FILE" <<EOF
{
    "root_hash": "$ROOT_PASS_HASH",
    "panel_port": "$PANEL_PORT"
}
EOF
    
    # 安装 面板脚本 (与上个版本相同，确保功能完整)
    install_wss_panel_script

    # 安装 流量统计脚本 (与上个版本相同，确保功能完整)
    install_wss_accountant_script
    
    # WSS Panel Systemd Service
    sudo tee /etc/systemd/system/wss_panel.service > /dev/null <<EOF
[Unit]
Description=WSS User Management Panel
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $PANEL_SCRIPT
Restart=always
User=root
Environment=PANEL_PORT=$PANEL_PORT \
            WSS_HTTP_PORT=$WSS_HTTP_PORT \
            WSS_TLS_PORT=$WSS_TLS_PORT \
            STUNNEL_PORT=$STUNNEL_PORT \
            UDPGW_PORT=$UDPGW_PORT
WorkingDirectory=$PANEL_CONFIG_DIR

[Install]
WantedBy=multi-user.target
EOF

    # WSS Accountant Systemd Service
    sudo tee /etc/systemd/system/wss_accountant.service > /dev/null <<EOF
[Unit]
Description=WSS Traffic and Expiration Accountant
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $ACCOUNTANT_SCRIPT
Restart=on-failure
User=root
WorkingDirectory=/tmp
StandardOutput=append:/var/log/wss_accountant.log
StandardError=append:/var/log/wss_accountant.log

[Install]
WantedBy=multi-user.target
EOF

    # WSS Accountant Timer (每 5 分钟运行一次)
    sudo tee /etc/systemd/system/wss_accountant.timer > /dev/null <<EOF
[Unit]
Description=Run WSS Accountant every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    log "面板和流量统计服务配置完成。"
}

# --- 部署阶段 6: 启动所有服务 ---
start_all_services() {
    log "==== 启动所有服务 ===="
    
    systemctl enable wss.service stunnel4.service udpgw.service wss_panel.service wss_accountant.timer &> /dev/null
    
    systemctl restart wss.service &> /dev/null & spinner
    systemctl restart stunnel4.service &> /dev/null & spinner
    systemctl restart udpgw.service &> /dev/null & spinner
    systemctl restart wss_panel.service &> /dev/null & spinner
    systemctl start wss_accountant.timer &> /dev/null & spinner
    
    # 强制运行一次 Accountant，初始化流量数据
    systemctl start wss_accountant.service &> /dev/null & spinner
    
    log "所有服务已启动/重启并设置为开机自启。"
}


# --- WSS 核心代理脚本 (重复，保持内联) ---
install_wss_panel_script() {
    cat > "$PANEL_SCRIPT" <<'EOF'
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
# The deployment script now passes these via systemd Environment=

# Configuration loaded from ENV (passed by systemd) or fallback
ROOT_USERNAME = "root"
ROOT_PASSWORD_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" 
PANEL_PORT = os.environ.get('PANEL_PORT', '8080')
WSS_HTTP_PORT = os.environ.get('WSS_HTTP_PORT', '80')
WSS_TLS_PORT = os.environ.get('WSS_TLS_PORT', '443')
STUNNEL_PORT = os.environ.get('STUNNEL_PORT', '444')
UDPGW_PORT = os.environ.get('UDPGW_PORT', '7300')

# Path must be absolute
USER_DB_PATH = "/etc/wss-panel/users.json"

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
    if n < 0: return "N/A"
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
        .connection-info pre { background-color: #ecf0f1; padding: 10px; border-radius: 6px; overflow-x: auto; font-size: 14px; position: relative; }
        .note { color: #888; font-size: 14px; margin-top: 15px; border-left: 3px solid #f39c12; padding-left: 10px; }
        .copy-btn { position: absolute; top: 10px; right: 10px; background-color: #3498db; color: white; border: none; padding: 5px 10px; border-radius: 5px; cursor: pointer; font-size: 12px; }
        .copy-btn:hover { background-color: #2980b9; }
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
            
            <pre id="connection-details">
服务器地址: {{ host_ip }}
WSS HTTP 端口: {{ wss_http_port }}
WSS TLS 端口: {{ wss_tls_port }}
Stunnel 端口: {{ stunnel_port }}
UDPGW 端口: {{ udpgw_port }}
底层认证: SSH 账户/密码
</pre>
            <button class="copy-btn" onclick="copyConnectionDetails()">复制</button>
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
        
        function copyConnectionDetails() {
            const details = document.getElementById('connection-details').innerText;
            // Use execCommand('copy') for better compatibility in iframe/canvas environments
            const textarea = document.createElement('textarea');
            textarea.value = details;
            document.body.appendChild(textarea);
            textarea.select();
            try {
                document.execCommand('copy');
                showStatus('连接信息已复制到剪贴板。', true);
            } catch (err) {
                showStatus('复制失败，请手动复制。', false);
            }
            document.body.removeChild(textarea);
        }
    </script>
</body>
</html>
"""

# 渲染函数 (已修复)
def render_dashboard(users):
    # Load hash from configuration file
    try:
        with open("/etc/wss-panel/panel_config.json", 'r') as f:
            config = json.load(f)
            # ROOT_PASSWORD_HASH is not needed here, only for login logic
    except Exception:
        pass # Use fallback values

    template_env = jinja2.Environment(loader=jinja2.BaseLoader)
    template = template_env.from_string(_DASHBOARD_HTML)
    
    # Attempts to get the real host IP
    host_ip = request.host.split(':')[0]
    if host_ip in ('127.0.0.1', 'localhost', '0.0.0.0'):
         host_ip = '[Your Server IP]'

    # Pre-process user data for display
    processed_users = []
    for user in users:
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
    html_content = render_dashboard(users=users) 
    return make_response(html_content)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    
    # Load hash from configuration file
    current_root_hash = ROOT_PASSWORD_HASH
    try:
        with open("/etc/wss-panel/panel_config.json", 'r') as f:
            config = json.load(f)
            current_root_hash = config.get('root_hash', ROOT_PASSWORD_HASH)
    except Exception:
        pass

    if request.method == 'POST':
        username = request.form.get('username')
        password_raw = request.form.get('password')
        
        if username == ROOT_USERNAME and password_raw:
            password_hash = hashlib.sha256(password_raw.encode('utf-8')).hexdigest()
            if password_hash == current_root_hash:
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
            # Set expiry to the last second of the day
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
    # Load actual root hash from config file
    try:
        with open("/etc/wss-panel/panel_config.json", 'r') as f:
            config = json.load(f)
            ROOT_PASSWORD_HASH = config.get('root_hash', ROOT_PASSWORD_HASH)

    except Exception:
        # If config fails to load, use the fallback hash (which is typically the one passed by the script)
        pass
        
    app.run(host='0.0.0.0', port=int(PANEL_PORT), debug=False)
EOF
}

# --- 流量统计脚本 (重复，保持内联) ---
install_wss_accountant_script() {
    cat > "$ACCOUNTANT_SCRIPT" <<'EOF'
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import json
import time
import subprocess
import os
from datetime import datetime

# --- 配置 ---
USER_DB_PATH = "/etc/wss-panel/users.json"
LOG_PATH = "/var/log/wss_accountant.log"

# 模拟配置：每次运行增加 10MB，总上限 10GB (用于展示流量统计功能)
SIMULATION_INCREMENT = 10485760 # 10MB per cycle (timer runs every 5 minutes)
SIMULATION_CAP = 10737418240 # 10GB total limit for simulation

def log(message):
    """记录日志."""
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    try:
        with open(LOG_PATH, "a") as f:
            f.write(f"{timestamp} {message}\n")
    except Exception as e:
        print(f"Failed to write to log file: {e}")

def load_users():
    """从 JSON 文件加载用户列表."""
    if not os.path.exists(USER_DB_PATH): 
        return []
    try:
        with open(USER_DB_PATH, 'r') as f: return json.load(f)
    except Exception as e:
        log(f"Error loading users.json: {e}")
        return []

def save_users(users):
    """保存用户列表到 JSON 文件."""
    try:
        # 确保目录存在
        os.makedirs(os.path.dirname(USER_DB_PATH), exist_ok=True)
        with open(USER_DB_PATH, 'w') as f: json.dump(users, f, indent=4)
        return True
    except Exception as e: 
        log(f"Error saving users.json: {e}")
        return False

def run_cmd(command):
    """安全执行系统命令."""
    try:
        subprocess.run(command, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except FileNotFoundError:
        return False

def update_traffic_and_check_expiration():
    """更新流量（模拟）和检查过期状态."""
    users = load_users()
    current_time = int(time.time())
    
    log(f"--- Accounting cycle started. Found {len(users)} users. ---")

    for user in users:
        username = user['username']
        
        # 1. 检查过期状态
        expires_at = user.get('expires_at', 0)
        is_expired = expires_at != 0 and expires_at < current_time

        if is_expired:
            if user['status'] != 'expired':
                user['status'] = 'expired'
                log(f"STATUS UPDATE: User {username} is now EXPIRED.")
        
        # 2. **强制执行流量模拟更新 (仅针对活跃用户)**
        if user['status'] == 'active':
            current_usage = user.get('usage_bytes', 0)
            
            if current_usage < SIMULATION_CAP:
                # 累加模拟流量
                user['usage_bytes'] = current_usage + SIMULATION_INCREMENT
                log(f"TRAFFIC: Simulating traffic for {username}. New Usage: {user['usage_bytes'] / 1048576:.2f} MB")
            else:
                log(f"TRAFFIC: User {username} reached simulation limit. Usage: {current_usage / 1048576:.2f} MB")
            
    # 3. 保存更新
    if save_users(users):
        log("UPDATE SUCCESS: Traffic/Expiration data saved.")
    else:
        log("ERROR: Failed to save user data.")


def cleanup_expired_users():
    """清理已过期且已在面板标记为 expired 的用户 (即删除系统账户)."""
    users = load_users()
    users_to_keep = []
    
    log("CLEANUP: Starting cleanup for expired users.")
    
    for user in users:
        if user['status'] == 'expired':
            username = user['username']
            log(f"CLEANUP: Attempting to delete expired system user: {username}")
            
            # 删除系统账户 (-r 删除 home 目录)
            if run_cmd(['userdel', '-r', username]):
                log(f"CLEANUP SUCCESS: Deleted system user {username}. Removing from JSON.")
            else:
                log(f"CLEANUP WARNING: Failed to delete system user {username}. Keeping JSON record for next cycle.")
                users_to_keep.append(user)
        else:
            users_to_keep.append(user)
            
    save_users(users_to_keep)
    log("CLEANUP: Cycle finished.")

if __name__ == '__main__':
    update_traffic_and_check_expiration()
    cleanup_expired_users()
    log("--- Accounting cycle completed. ---")
EOF
}


# --- 主执行流程 ---
main() {
    if [ "$EUID" -ne 0 ]; then
        error "请以 root 或 sudo 权限运行此脚本。"
    fi
    
    read_user_input
    
    install_dependencies
    
    # 部署基础设施
    install_wss_proxy
    install_stunnel_ssh
    install_udpgw
    
    # 部署面板和数据服务
    install_panel
    
    start_all_services
    
    # 清理敏感变量
    unset ROOT_PASS_HASH
    
    echo ""
    echo "=========================================="
    echo "         ✅ WSS 面板部署成功！ ✅"
    echo "=========================================="
    echo "Web 管理面板（登录用户: root）:"
    echo "  - 面板地址: \033[1;32mhttp://[您的服务器IP]:${PANEL_PORT}\033[0m"
    echo ""
    echo "代理服务连接信息:"
    echo "  - WSS (HTTP) 端口: \033[1;32m${WSS_HTTP_PORT}\033[0m"
    echo "  - WSS (TLS) 端口:  \033[1;32m${WSS_TLS_PORT}\033[0m"
    echo "  - Stunnel 端口:    \033[1;32m${STUNNEL_PORT}\033[0m"
    echo "  - UDPGW 端口:      \033[1;32m${UDPGW_PORT}\033[0m"
    echo ""
    echo "故障排查"
    echo "WSS 代理状态: sudo systemctl status wss"
    echo "Stunnel 状态: sudo systemctl status stunnel4"
    echo "Web 面板状态: sudo systemctl status wss_panel"
    echo "用户数据库路径: /etc/wss-panel/users.json (面板通过此文件进行用户查询和管理)"
    echo ""
    echo "重要日志文件:"
    echo "  - WSS 代理日志: \033[1;33msudo journalctl -u wss -f\033[0m"
    echo "  - 面板日志:     \033[1;33msudo journalctl -u wss_panel -f\033[0m"
    echo "  - 流量统计日志: \033[1;33msudo tail -f /var/log/wss_accountant.log\033[0m"
    echo "=========================================="
    echo ""
}

main
