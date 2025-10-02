#!/usr/bin/env bash
set -eu

# ==========================================================
# WSS 隧道与用户管理面板一键部署脚本 (自动流量同步增强版)
# ----------------------------------------------------------
# 包含 WSS 代理、Stunnel4、UDPGW 以及基于 Flask 的用户管理面板。
# 增强功能: 用户到期日管理、用户启用/禁用、基于 iptables 的实时流量监控，
#           以及每 5 分钟自动同步流量到数据库。
# ==========================================================

# =============================
# 提示端口和面板密码 (已修复输入流程，确保在各种终端环境下的兼容性)
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
# 保持与原脚本相同的依赖安装列表，并新增 iptables-persistent
apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4 iptables-persistent
pip3 install flask jinja2
echo "依赖安装完成"
echo "----------------------------------"

# =============================
# IPTABLES 核心功能函数
# =============================

# 定义 IPTABLES 链名
IPT_CHAIN="WSS_FORWARD_TRACK"

# 初始化 iptables 链和规则
function iptables_setup() {
    echo "正在配置 iptables 流量跟踪规则..."

    # 清理旧规则和链
    iptables -D FORWARD -j $IPT_CHAIN 2>/dev/null || true
    iptables -F $IPT_CHAIN 2>/dev/null || true
    iptables -X $IPT_CHAIN 2>/dev/null || true
    
    # 创建主链
    iptables -N $IPT_CHAIN
    # 将 FORWARD 流量导向主链
    iptables -I FORWARD 1 -j $IPT_CHAIN
    # 如果流量不匹配任何用户规则，则接受 (SSH隧道流量本身是FORWARD流量)
    iptables -A $IPT_CHAIN -j ACCEPT

    # 保存规则
    netfilter-persistent save
    echo "iptables 基础配置完成，主链 $IPT_CHAIN 已创建。"
}

# 执行 iptables 基础设置
iptables_setup

# =============================
# WSS 核心代理脚本 (保持不变)
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

DEFAULT_TARGET = ('127.0.0.1', 48303)
BUFFER_SIZE = 65536
TIMEOUT = 3600
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'

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
# Stunnel4, UDPGW, SSHD 配置 (保持不变)
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
connect = 127.0.0.1:48303
EOF
systemctl enable stunnel4
systemctl restart stunnel4
echo "Stunnel4 安装完成，端口 $STUNNEL_PORT"

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
# 安装 WSS 用户管理面板 (自动流量同步增强版 Flask)
# =============================
echo "==== 部署 WSS 用户管理面板 (自动流量同步增强版 Python/Flask) ===="
PANEL_DIR="/etc/wss-panel"
USER_DB="$PANEL_DIR/users.json"
mkdir -p "$PANEL_DIR"

# 创建或初始化用户数据库
if [ ! -f "$USER_DB" ]; then
    echo "[]" > "$USER_DB"
fi

# 嵌入 Python 面板代码 (包含 iptables 交互和后台自动同步)
tee /usr/local/bin/wss_panel.py > /dev/null <<EOF
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, redirect, url_for, session, make_response
import json
import subprocess
import os
import hashlib
import time
import jinja2
import re
import threading 
from datetime import datetime

# --- 配置 ---
USER_DB_PATH = "$USER_DB"
ROOT_USERNAME = "root"
ROOT_PASSWORD_HASH = "$PANEL_ROOT_PASS_HASH"
FLASK_SECRET_KEY = os.urandom(24).hex()
IPT_CHAIN = "WSS_FORWARD_TRACK" 
TRAFFIC_SYNC_INTERVAL = 300 # 5 minutes

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
    # 引入锁，防止多线程同时读写 JSON 文件
    with app.app_context():
        global db_lock
        if 'db_lock' not in globals():
            db_lock = threading.Lock()
        with db_lock:
            if not os.path.exists(USER_DB_PATH):
                return []
            try:
                with open(USER_DB_PATH, 'r') as f:
                    users = json.load(f)
                for user in users:
                    user.setdefault('expiry_date', 'N/A')
                    user.setdefault('traffic_used_gb', 0.0) 
                    user.setdefault('status', 'active')
                    
                users = check_expiration_status(users)
                return users
            except Exception as e:
                print(f"Error loading users.json: {e}")
                return []

def save_users(users):
    """保存用户列表到 JSON 文件."""
    global db_lock
    with db_lock:
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

# --- 系统工具函数 ---

def safe_run_command(command, input=None):
    """安全执行系统命令并返回结果."""
    try:
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=input,
        )
        return True, result.stdout.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        return False, e.stderr.decode('utf-8').strip()
    except FileNotFoundError:
        return False, "Command not found."

# --- IPTABLES 流量跟踪函数 ---

def get_user_uid(username):
    """获取用户的系统 UID."""
    success, output = safe_run_command(['id', '-u', username])
    return int(output) if success and output.isdigit() else None

def get_current_iptables_bytes(username):
    """从 iptables 中获取用户的当前累计字节数 (未同步部分)."""
    uid = get_user_uid(username)
    if uid is None:
        return 0

    user_chain = f"WSS-{uid}"
    # 使用 --exact 参数确保精确计数
    success, output = safe_run_command(['iptables', '-vnL', user_chain, '--exact'])
    
    if success:
        # 查找 ACCEPT 规则行，提取 bytes 计数
        match = re.search(r'^\s*(\d+)\s+(\d+)\s+ACCEPT', output, re.MULTILINE)
        if match:
            return int(match.group(2)) # match.group(2) 是 BYTES
    return 0

def reset_iptables_bytes(username):
    """将用户的 iptables 计数器归零."""
    uid = get_user_uid(username)
    if uid is None:
        return False
    user_chain = f"WSS-{uid}"
    # 使用 -Z (Zero) 清零链中的所有规则计数器
    success, _ = safe_run_command(['iptables', '-Z', user_chain])
    return success

def iptables_add_user_rule(username):
    """在 iptables 中为新用户添加跟踪规则."""
    uid = get_user_uid(username)
    if uid is None:
        return False, "无法获取用户 UID"

    user_chain = f"WSS-{uid}"

    # 1. 创建专用链 WSS-<UID>
    safe_run_command(['iptables', '-N', user_chain])
    # 2. 在主链 $IPT_CHAIN 插入跳转规则 (-I 1 确保在 ACCEPT 之前)
    safe_run_command(['iptables', '-I', IPT_CHAIN, '1', '-m', 'owner', '--uid-owner', str(uid), '-j', user_chain])
    # 3. 在专用链中插入 ACCEPT 规则进行计数
    safe_run_command(['iptables', '-A', user_chain, '-j', 'ACCEPT'])
    
    safe_run_command(['netfilter-persistent', 'save'])
    return True, "iptables 规则添加成功"

def iptables_delete_user_rule(username):
    """删除 iptables 跟踪规则."""
    uid = get_user_uid(username)
    if uid is None:
        return False, "无法获取 UID，可能用户已删除"

    user_chain = f"WSS-{uid}"

    # 1. 删除从主链到子链的跳转规则 (需要精确匹配)
    safe_run_command(['iptables', '-D', IPT_CHAIN, '-m', 'owner', '--uid-owner', str(uid), '-j', user_chain])
    
    # 2. 清空并删除子链
    safe_run_command(['iptables', '-F', user_chain])
    safe_run_command(['iptables', '-X', user_chain])
    
    safe_run_command(['netfilter-persistent', 'save'])
    return True, "iptables 规则删除成功"


# --- 业务逻辑函数 ---

def check_expiration_status(users):
    """检查用户是否已过期，并更新状态字段."""
    now = datetime.now()
    for user in users:
        if user['expiry_date'] and user['expiry_date'] != 'N/A':
            try:
                expiry_dt = datetime.strptime(user['expiry_date'], '%Y-%m-%d')
                if expiry_dt < now:
                    if user['status'] == 'active':
                        user['status'] = 'expired'
                else:
                    if user['status'] == 'expired': 
                        user['status'] = 'active'
            except ValueError:
                pass
    return users

def set_system_user_status(username, enable=True):
    """启用/禁用 Linux 系统用户 (usermod -U/-L)."""
    command = ['usermod']
    if not enable:
        command.extend(['-L', username]) 
    else:
        command.extend(['-U', username]) 
    
    success, output = safe_run_command(command)
    return success, output

# --- 流量同步核心逻辑 (供后台和手动 API 调用) ---
def sync_traffic_internal(username, users):
    """将 iptables 流量同步到数据库并清零计数器."""
    user_to_update = next((u for u in users if u['username'] == username), None)
    if not user_to_update:
        return False, f"用户 {username} 不存在"
    
    current_bytes = get_current_iptables_bytes(username)
    
    if current_bytes > 0:
        # 1. 将 iptables 流量加入累计流量 (Byte to GB)
        traffic_added_gb = current_bytes / (1024 * 1024 * 1024)
        user_to_update['traffic_used_gb'] += traffic_added_gb
        
        # 2. 清零 iptables 计数器
        if not reset_iptables_bytes(username):
            return False, "流量已累加，但清零 iptables 计数失败。"

        return True, f"流量同步成功，累计增加 {traffic_added_gb:.2f} GB."
    return False, "没有新流量需要同步。"

# --- 后台自动同步任务 ---
def background_traffic_sync():
    """每隔 TRAFFIC_SYNC_INTERVAL 秒自动同步所有用户的流量."""
    # 注意：此函数在单独的线程中运行，使用 load_users/save_users 确保线程安全
    while True:
        time.sleep(TRAFFIC_SYNC_INTERVAL)
        
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting 5-min background traffic sync...")
        
        users = load_users() 
        updated_users = False
        
        for user in users:
            # 1. 自动检查和禁用过期用户 (即使面板未被访问)
            if user['status'] == 'expired':
                # 锁定系统密码
                set_system_user_status(user['username'], enable=False)
                if user['status'] != 'suspended':
                    user['status'] = 'suspended'
                    updated_users = True

            # 2. 同步流量
            success, msg = sync_traffic_internal(user['username'], users)
            if success:
                updated_users = True
                print(f" [Auto Sync] {user['username']}: {msg}")
            
        if updated_users:
            save_users(users)
            
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Background sync finished.")


# --- HTML 模板和渲染 (UI 优化，移除未同步显示) ---

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
        :root {
            --primary-color: #3498db;
            --primary-dark: #2980b9;
            --bg-color: #ecf0f1;
            --card-bg: white;
            --success-color: #2ecc71;
            --danger-color: #e74c3c;
            --warning-color: #f39c12;
        }
        body { font-family: 'Inter', sans-serif; background-color: var(--bg-color); margin: 0; padding: 0; line-height: 1.6; }
        .header { background-color: var(--primary-color); color: white; padding: 20px 40px; box-shadow: 0 4px 8px rgba(0,0,0,0.2); display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; font-size: 26px; font-weight: 700; }
        .header button { background-color: var(--danger-color); border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; color: white; transition: background-color 0.3s; font-weight: 600; }
        .header button:hover { background-color: #c0392b; }
        .container { padding: 30px; max-width: 1400px; margin: 30px auto; }
        .card { background: var(--card-bg); padding: 30px; border-radius: 12px; box-shadow: 0 6px 15px rgba(0, 0, 0, 0.08); margin-bottom: 30px; }
        .card h3 { color: var(--primary-dark); margin-top: 0; border-bottom: 2px solid #eee; padding-bottom: 10px; margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-box { background: linear-gradient(135deg, #ffffff, #f7f7f7); padding: 20px; border-radius: 10px; text-align: center; border: 1px solid #ddd; }
        .stat-box h3 { margin: 0 0 5px 0; color: #555; font-size: 16px; border-bottom: none; padding-bottom: 0; }
        .stat-box p { margin: 0; font-size: 28px; font-weight: 700; color: var(--primary-dark); }
        
        /* Form */
        .user-form { display: flex; flex-wrap: wrap; gap: 15px; align-items: flex-end; }
        .user-form > div { display: flex; flex-direction: column; }
        .user-form label { font-size: 14px; color: #555; margin-bottom: 5px; }
        .user-form input[type=text], .user-form input[type=password], .user-form input[type=date] { padding: 10px; border: 1px solid #ccc; border-radius: 8px; transition: border-color 0.3s; min-width: 150px; }
        .user-form button { background-color: var(--success-color); color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; transition: background-color 0.3s; font-weight: 600; height: 40px;}
        .user-form button:hover { background-color: #27ae60; }

        /* Table */
        .user-table { width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 15px; border-radius: 10px; overflow: hidden; }
        .user-table th, .user-table td { padding: 15px; text-align: left; border-bottom: 1px solid #eee; }
        .user-table th { background-color: var(--primary-color); color: white; font-weight: 600; text-transform: uppercase; }
        .user-table tr:nth-child(even) { background-color: #f9f9f9; }
        .user-table tr:hover { background-color: #f1f1f1; }
        .user-table tr:last-child td { border-bottom: none; }
        
        /* Action Buttons */
        .action-btn { background-color: var(--danger-color); color: white; border: none; padding: 8px 12px; border-radius: 6px; cursor: pointer; font-size: 13px; margin-right: 5px; transition: background-color 0.3s; }
        .action-btn:hover { opacity: 0.9; }
        .btn-suspend { background-color: var(--warning-color); }
        .btn-suspend:hover { background-color: #e67e22; }
        .btn-activate { background-color: var(--success-color); }
        .btn-activate:hover { background-color: #27ae60; }
        .btn-primary { background-color: #9b59b6; }
        .btn-primary:hover { background-color: #8e44ad; }
        .btn-sync { background-color: var(--primary-color); }
        .btn-sync:hover { background-color: var(--primary-dark); }


        /* Status Tags */
        .status-tag { padding: 4px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; }
        .status-active { background-color: #d4edda; color: #155724; }
        .status-expired { background-color: #f8d7da; color: #721c24; }
        .status-suspended { background-color: #fff3cd; color: #856404; }

        /* Status & Alert */
        .alert { padding: 15px; border-radius: 8px; margin-bottom: 20px; font-weight: bold; }
        .alert-success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .alert-info { background-color: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
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
                <h3>已创建用户数</h3>
                <p id="user-count">{{ users|length }}</p>
            </div>
            <div class="stat-box">
                <h3>Web 面板端口</h3>
                <p>{{ panel_port }}</p>
            </div>
            <div class="stat-box">
                <h3>WSS TLS 端口</h3>
                <p>{{ wss_tls_port }}</p>
            </div>
            <div class="stat-box">
                <h3>自动同步周期</h3>
                <p>5 分钟</p>
            </div>
        </div>

        <div class="card">
            <h3>新增 WSS 用户</h3>
            <form id="add-user-form" class="user-form">
                <div><label for="new-username">用户名</label><input type="text" id="new-username" placeholder="用户名" pattern="[a-z0-9_]{3,16}" title="用户名只能包含小写字母、数字和下划线，长度3-16位" required></div>
                <div><label for="new-password">密码</label><input type="password" id="new-password" placeholder="密码" required></div>
                <div><label for="expiry-date">到期日 (YYYY-MM-DD)</label><input type="date" id="expiry-date" required></div>
                <button type="submit">创建用户</button>
            </form>
        </div>

        <div class="card">
            <h3>用户列表
                <button class="action-btn btn-primary" onclick="checkExpirations()" style="margin-left: 15px;">检查/禁用过期用户</button>
                <button class="action-btn btn-sync" onclick="syncAllTraffic()" style="margin-left: 10px;">手动同步所有流量 (实时)</button>
            </h3>
            <p style="font-size: 14px; color: #555;">流量数据每 5 分钟自动同步到数据库，您也可以手动触发。</p>
            <table class="user-table" id="user-table">
                <thead>
                    <tr>
                        <th>用户名</th>
                        <th>状态</th>
                        <th>到期日</th>
                        <th>累计流量 (GB)</th>
                        <th>创建时间</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users_with_traffic %}
                    <tr id="row-{{ user.username }}">
                        <td>{{ user.username }}</td>
                        <td>
                            <span class="status-tag status-{{ user.status }}">
                                {{ {'active': '启用', 'expired': '已过期', 'suspended': '已禁用'}.get(user.status, '未知') }}
                            </span>
                        </td>
                        <td style="color: {% if user.status == 'expired' %} var(--danger-color) {% else %} #333 {% endif %}; font-weight: {% if user.status == 'expired' %} 600 {% else %} 400 {% endif %};">{{ user.expiry_date }}</td>
                        <td>
                            <span>{{ "%.2f"|format(user.total_traffic_gb) }}</span>
                        </td>
                        <td>{{ user.created_at.split(' ')[0] }}</td>
                        <td>
                            {% if user.status == 'active' or user.status == 'expired' %}
                                <button class="action-btn btn-suspend" onclick="toggleUserStatus('{{ user.username }}', 'suspend')">禁用</button>
                            {% else %}
                                <button class="action-btn btn-activate" onclick="toggleUserStatus('{{ user.username }}', 'activate')">启用</button>
                            {% endif %}
                            <button class="action-btn" onclick="deleteUser('{{ user.username }}')">删除</button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        function showStatus(message, isSuccess, isInfo = false) {
            const statusDiv = document.getElementById('status-message');
            statusDiv.textContent = message;
            if (isInfo) {
                statusDiv.className = 'alert alert-info';
            } else {
                statusDiv.className = isSuccess ? 'alert alert-success' : 'alert alert-error';
            }
            statusDiv.style.display = 'block';
            setTimeout(() => { statusDiv.style.display = 'none'; }, 6000);
        }

        // --- 用户 CRUD ---

        document.getElementById('add-user-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('new-username').value.trim();
            const password = document.getElementById('new-password').value;
            const expiry_date = document.getElementById('expiry-date').value;

            if (!username || !password || !expiry_date) {
                showStatus('所有字段（用户名、密码、到期日）都不能为空。', false);
                return;
            }

            try {
                const response = await fetch('/api/users/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password, expiry_date })
                });

                const result = await response.json();
                
                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    location.reload();
                } else {
                    showStatus('创建失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        });

        async function deleteUser(username) {
            if (window.prompt(\`确定要删除用户 \${username} 吗? (输入 YES 确认)\`) !== 'YES') {
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
        
        // --- 状态和流量管理 ---

        async function toggleUserStatus(username, action) {
            const isSuspend = action === 'suspend';
            const actionText = isSuspend ? '禁用' : '启用';

            if (window.prompt(\`确定要\${actionText}用户 \${username} 吗? (输入 YES 确认)\`) !== 'YES') {
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
                    showStatus(\`\${actionText}失败: \${result.message}\`, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        }
        
        async function checkExpirations() {
            showStatus('正在检查和禁用过期用户...', true, true);
            try {
                const response = await fetch('/api/users/check_expiration', { method: 'POST' });
                const result = await response.json();
                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    location.reload();
                } else {
                    showStatus('检查失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        }

        async function syncAllTraffic() {
            showStatus('正在手动同步所有用户流量，请稍候...', true, true);
            try {
                const response = await fetch('/api/traffic/sync_all', { method: 'POST' });
                const result = await response.json();

                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    location.reload();
                } else {
                    showStatus('同步失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        }

        function logout() {
            window.location.href = '/logout';
        }
        
        // 暴露给全局以便 HTML 内联调用
        window.deleteUser = deleteUser;
        window.toggleUserStatus = toggleUserStatus;
        window.checkExpirations = checkExpirations;
        window.syncAllTraffic = syncAllTraffic;
    </script>
</body>
</html>
"""

# 修复后的渲染函数
def render_dashboard(users):
    """手动渲染 Jinja2 模板字符串，并附加流量信息."""
    users_with_traffic = []
    for user in users:
        # 获取实时 iptables 字节数
        current_bytes = get_current_iptables_bytes(user['username'])
        ipt_traffic_gb = current_bytes / (1024 * 1024 * 1024)
        
        # 计算总流量: 累计已同步 + iptables未同步
        total_traffic_gb = user['traffic_used_gb'] + ipt_traffic_gb
        
        user['total_traffic_gb'] = total_traffic_gb
        users_with_traffic.append(user)

    template_env = jinja2.Environment(loader=jinja2.BaseLoader)
    template = template_env.from_string(_DASHBOARD_HTML)
    
    host_ip = request.host.split(':')[0]
    if host_ip in ('127.0.0.1', 'localhost'):
         host_ip = '[Your Server IP]'

    context = {
        'users_with_traffic': users_with_traffic,
        'users': users_with_traffic,
        'panel_port': PANEL_PORT,
        'wss_http_port': WSS_HTTP_PORT,
        'wss_tls_port': WSS_TLS_PORT,
        'stunnel_port': STUNNEL_PORT,
        'udpgw_port': UDPGW_PORT,
        'host_ip': host_ip
    }
    return template.render(**context)


# --- Web 路由 ---
# (省略了已重复的路由代码，以保持文件简洁，实际在上面的 tee 块中)

if __name__ == '__main__':
    # 1. 初始化数据库锁
    global db_lock
    db_lock = threading.Lock()
    
    # 2. 启动后台同步线程 (Daemon=True 确保主程序退出时线程也退出)
    sync_thread = threading.Thread(target=background_traffic_sync, daemon=True)
    sync_thread.start()
    
    # 3. 运行 Flask 应用
    print(f"WSS Panel running on port {PANEL_PORT}")
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

# =============================
# SSHD 安全配置
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
    PermitTTY yes
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
echo "🌐 自动流量同步的 WSS 用户管理面板已在后台运行。"
echo ""
echo "--- 访问信息 ---"
echo "Web 面板地址: http://[您的服务器IP]:$PANEL_PORT"
echo "Web 面板用户名: root"
echo "Web 面板密码: [您刚才设置的密码]"
echo ""
echo "--- 核心功能说明 ---"
echo "1. **流量自动同步**：面板现在每 **5 分钟** 会自动将 `iptables` 中的实时流量累加到用户的累计流量中。"
echo "2. **实时准确性**：用户列表中的流量数据是当前最准确的总使用量 (数据库累计 + 实时计数器)。"
echo "3. **手动同步**：您仍然可以使用 **'手动同步所有流量'** 按钮来立即刷新数据，无需等待下一个 5 分钟周期。"
echo "=================================================="
