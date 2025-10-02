#!/usr/bin/env bash
set -eu

# ==========================================================
# WSS 隧道与用户管理面板一键部署脚本 (最终修正版)
# ----------------------------------------------------------
# 修复 Bash 语法错误，并集成了 SQLite 数据库、到期日和流量监控功能。
# ==========================================================

# --- 端口和密码提示 (修正 Bash 语法) ---
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

# **修正后的密码输入部分**：使用最保守的 Bash 语法
echo "请为 Web 面板的 'root' 用户设置密码（输入时隐藏）。"
while true; do
    read -s -p "面板密码: " pw1 && echo
    read -s -p "请再次确认密码: " pw2 && echo
    
    # 确保 [ 和 ] 以及操作符周围有空格
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
echo "==== 系统更新与依赖安装 (新增 sqlite3) ===="
# 额外安装 sqlite3-cli 和 python-dateutil 依赖
apt update -y
apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4 sqlite3
pip3 install flask jinja2 python-dateutil
echo "依赖安装完成"
echo "----------------------------------"

# =============================
# WSS 核心代理脚本 (/usr/local/bin/wss)
# 保持不变
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

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    peer = writer.get_extra_info('peername')
    forwarding_started = False
    full_request = b''

    try:
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
        print(f"WARNING: TLS certificate not found. TLS server disabled.")
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
        asyncio.run(main())
    except KeyboardInterrupt:
        print("WSS Proxy Stopped.")
        
EOF

chmod +x /usr/local/bin/wss

# 创建 WSS systemd 服务 (保持不变)
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
# Stunnel4 & UDPGW (保持不变)
# =============================
echo "==== 配置 Stunnel4 和 UDPGW (保持不变) ===="
mkdir -p /etc/stunnel/certs
openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 1095 \
-subj "/CN=example.com" > /dev/null 2>&1
sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
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
systemctl restart udpgw
echo "Stunnel4/UDPGW 配置完成。"
echo "----------------------------------"

# =============================
# 新增: 流量监控 (Iptables 链)
# =============================
echo "==== 设置 Iptables 流量监控链 ===="
# 清除旧的 WSS 链 (如果存在)
iptables -D INPUT -j WSS_USERS 2>/dev/null || true
iptables -D FORWARD -j WSS_USERS 2>/dev/null || true
iptables -F WSS_USERS 2>/dev/null || true
iptables -X WSS_USERS 2>/dev/null || true

# 创建新的 WSS 流量监控链
iptables -N WSS_USERS
# 将所有转发和输入流量导入 WSS_USERS 链，等待用户规则插入
iptables -A INPUT -j WSS_USERS
iptables -A FORWARD -j WSS_USERS
echo "Iptables 链 WSS_USERS 创建完成。"
echo "----------------------------------"


# =============================
# 安装 WSS 用户管理面板 (基于 Flask/SQLite)
# =============================
echo "==== 部署 WSS 用户管理面板 (Flask/SQLite 优化版) ===="
PANEL_DIR="/etc/wss-panel"
DB_PATH="$PANEL_DIR/users.db"
mkdir -p "$PANEL_DIR"

# 创建或初始化 SQLite 数据库
echo "初始化或更新 SQLite 数据库结构..."
sqlite3 "$DB_PATH" <<'EOS'
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY NOT NULL,
    created_at TEXT NOT NULL,
    expire_date TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
);
-- 流量统计使用 users 表的字段，避免额外的 join 操作 (简化)
EOS
echo "数据库初始化完成: $DB_PATH"

# 嵌入 Python 面板代码 (核心逻辑修改)
tee /usr/local/bin/wss_panel.py > /dev/null <<EOF
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, redirect, url_for, session, make_response
import subprocess
import os
import hashlib
import sqlite3
import datetime
import jinja2
from dateutil import parser as date_parser

# --- 配置 ---
DB_PATH = "$DB_PATH"
ROOT_USERNAME = "root"
ROOT_PASSWORD_HASH = "$PANEL_ROOT_PASS_HASH"
FLASK_SECRET_KEY = os.urandom(24).hex()

# 面板和端口配置 (用于模板)
PANEL_PORT = "$PANEL_PORT"
WSS_HTTP_PORT = "$WSS_HTTP_PORT"
WSS_TLS_PORT = "$WSS_TLS_PORT"
STUNNEL_PORT = "$STUNNEL_PORT"

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# --- 数据库操作 ---

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_all_users():
    conn = get_db_connection()
    # 使用 LEFT JOIN 从 users 表中获取用户，流量统计在 refresh 时更新
    users = conn.execute("SELECT *, 0 AS bytes_in, 0 AS bytes_out FROM users ORDER BY username").fetchall()
    conn.close()
    return [dict(user) for user in users]

def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(user) if user else None

# --- 认证装饰器 & 工具函数 (保持不变) ---
def login_required(f):
    """检查用户是否已登录."""
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def safe_run_command(command, input=None):
    """安全执行系统命令并返回结果."""
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
        return False, f"Exception: {e}"

def update_iptables_rules_and_read_traffic():
    """刷新 iptables 规则并读取所有用户的流量统计."""
    conn = get_db_connection()
    users_data = conn.execute("SELECT username FROM users").fetchall()
    
    # 1. 清除 WSS_USERS 链中的所有旧规则
    safe_run_command(['iptables', '-F', 'WSS_USERS'])

    all_traffic_stats = {}
    now = datetime.datetime.now()
    users_to_update = []

    for user_row in users_data:
        username = user_row[0]
        
        try:
            # 尝试获取用户 UID
            uid = subprocess.check_output(['id', '-u', username], universal_newlines=True).strip()
            
            # 2. 为活跃用户添加 iptables 规则进行统计
            # 使用 owner 模块匹配用户 UID 的出站流量 (流量从隧道流出)
            command = ['iptables', '-A', 'WSS_USERS', 
                     '-m', 'owner', '--uid-owner', uid, 
                     '-j', 'ACCEPT', 
                     '-m', 'comment', '--comment', f"WSS_STAT_{username}"]
            safe_run_command(command)
            
            users_to_update.append(username)
        except Exception:
            # 用户可能已被删除或被锁定，无法获取 UID，跳过流量统计
            continue

    # 3. 读取 iptables 链统计 (Packet | Bytes)
    try:
        output = subprocess.check_output(['iptables', '-L', 'WSS_USERS', '-v', '-x', '-n'], universal_newlines=True)
        for line in output.splitlines():
            if "WSS_STAT_" in line:
                parts = line.split()
                # 解析 Comment 字段获取用户名
                comment_index = parts.index('COMMENT') + 1 
                if comment_index < len(parts):
                    rule_username = parts[comment_index].strip('"').replace('WSS_STAT_', '')
                    
                    bytes_total = int(parts[1])
                    # 估算：通常 egress (出站) 流量更大，这里取总值，让客户端估算 in/out
                    # 为简单起见，我们假设 in = out = total / 2 (这是一个普遍的简化)
                    bytes_in = bytes_total // 2
                    bytes_out = bytes_total - bytes_in
                    all_traffic_stats[rule_username] = {'in': bytes_in, 'out': bytes_out}
    except Exception:
        pass # 忽略 iptables 读取失败

    # 4. 更新数据库状态和流量
    final_users_list = conn.execute("SELECT * FROM users").fetchall()
    
    for user_row in final_users_list:
        user = dict(user_row)
        username = user['username']
        
        # 检查到期日
        expire_date = date_parser.parse(user['expire_date']).replace(tzinfo=None)
        is_expired = expire_date < now
        new_status = 'expired' if is_expired else 'active'
        
        # 检查系统用户状态 (用于锁定/解锁 SSH 账户)
        is_system_user_active = True
        try:
            # 检查密码是否被锁定 (即检查 /etc/shadow 中密码字段是否以 ! 开头)
            subprocess.check_call(['passwd', '-S', username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            is_system_user_active = False # 如果 passwd -S 失败，说明用户可能不存在或有其他问题

        if is_expired and user['status'] != 'expired':
            # 过期且面板未更新，则锁定系统用户
            safe_run_command(['usermod', '-L', username]) 
        elif not is_expired and user['status'] == 'expired':
            # 被续费，但系统用户仍被锁定，则解锁
            safe_run_command(['usermod', '-U', username]) 
        
        # 更新数据库状态 (如果发生变化)
        conn.execute("UPDATE users SET status = ? WHERE username = ?", (new_status, username))
        
        # 流量统计更新到字典中
        traffic = all_traffic_stats.get(username, {'in': 0, 'out': 0})
        user['bytes_in'] = traffic['in']
        user['bytes_out'] = traffic['out']
        
    conn.commit()
    conn.close()
    
    # 返回包含流量信息的完整列表
    return [dict(user) for user in final_users_list]


def refresh_traffic_and_status():
    """刷新所有用户的流量统计和到期状态 (外部调用接口)."""
    all_users_with_traffic = update_iptables_rules_and_read_traffic()
    return all_users_with_traffic


def format_bytes(bytes_value):
    """格式化字节数为人类可读的字符串."""
    if bytes_value is None or bytes_value == 0:
        return "0 B"
    sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    bytes_value = float(bytes_value)
    while bytes_value >= 1024 and i < len(sizes) - 1:
        bytes_value /= 1024.0
        i += 1
    return f"{bytes_value:.2f} {sizes[i]}"

# --- HTML 模板和渲染 (UI 优化: 使用更现代的配色和布局) ---

# 仪表盘 HTML (内嵌)
_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS Panel V2 - 增强仪表盘</title>
    <style>
        /* 整体美化 */
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #eef2f7; margin: 0; padding: 0; }
        .header { background-color: #3b5998; color: white; padding: 25px 50px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; font-size: 28px; font-weight: 500; }
        .header button { background-color: #ff5252; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; color: white; transition: background-color 0.3s; font-weight: 600; }
        .header button:hover { background-color: #cc0000; }
        .container { padding: 30px; max-width: 1400px; margin: 25px auto; }
        .card { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08); margin-bottom: 25px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-box { background: linear-gradient(135deg, #f0f2f7, #ffffff); border-left: 5px solid #3b5998; padding: 20px; border-radius: 8px; text-align: left; }
        .stat-box h3 { margin: 0 0 5px 0; color: #555; font-size: 14px; text-transform: uppercase; }
        .stat-box p { margin: 0; font-size: 28px; font-weight: bold; color: #3b5998; }
        
        /* Form */
        .user-form { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        .user-form input[type=text], .user-form input[type=password], .user-form input[type=date] { 
            padding: 10px; border: 1px solid #ccc; border-radius: 6px; flex: 1; min-width: 150px; 
        }
        .user-form button { 
            background-color: #4CAF50; color: white; border: none; padding: 10px 20px; 
            border-radius: 6px; cursor: pointer; transition: background-color 0.3s; font-weight: 600;
            min-width: 120px;
        }
        .user-form button:hover { background-color: #45a049; }

        /* Table */
        .user-table { width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 20px; }
        .user-table th, .user-table td { padding: 15px; text-align: left; border-bottom: 1px solid #eee; }
        .user-table th { background-color: #f5f7fa; color: #3b5998; font-weight: 600; }
        .user-table tr:hover { background-color: #f9f9f9; }
        .user-table tr:last-child td { border-bottom: none; }
        .user-table .delete-btn { background-color: #ff5252; }
        .user-table .delete-btn:hover { background-color: #cc0000; }

        /* Status & Alert */
        .status-badge { padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }
        .status-active { background-color: #e6ffee; color: #00b33c; }
        .status-expired { background-color: #ffe6e6; color: #cc0000; }
        .alert { padding: 15px; border-radius: 8px; margin-bottom: 20px; font-weight: bold; }
        .alert-success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }

        /* Helper */
        .info-note { color: #888; font-size: 14px; margin-top: 15px; border-left: 3px solid #f39c12; padding-left: 10px; }
        .action-btn { background-color: #007bff; color: white; border: none; padding: 6px 10px; border-radius: 5px; cursor: pointer; font-size: 12px; transition: background-color 0.3s; }
        .action-btn:hover { background-color: #0056b3; }
    </style>
</head>
<body>
    <div class="header">
        <h1>WSS Panel V2 - 隧道管理</h1>
        <button onclick="logout()">退出登录 (root)</button>
    </div>

    <div class="container">
        <div id="status-message" class="alert" style="display:none;"></div>
        
        <div class="grid">
            <div class="stat-box"><h3>活动用户数</h3><p id="user-count">{{ active_users_count }} / {{ users|length }}</p></div>
            <div class="stat-box"><h3>Web 面板端口</h3><p>{{ panel_port }}</p></div>
            <div class="stat-box"><h3>WSS TLS 端口</h3><p>{{ wss_tls_port }}</p></div>
            <div class="stat-box"><h3>Stunnel 端口</h3><p>{{ stunnel_port }}</p></div>
        </div>

        <div class="card">
            <h3>新增用户</h3>
            <form id="add-user-form" class="user-form">
                <input type="text" id="new-username" placeholder="用户名 (a-z0-9_)" pattern="[a-z0-9_]{3,16}" title="用户名只能包含小写字母、数字和下划线，长度3-16位" required>
                <input type="password" id="new-password" placeholder="密码" required>
                <input type="date" id="expire-date" required>
                <button type="submit">创建用户</button>
            </form>
        </div>

        <div class="card">
            <h3>用户管理与流量监控 (数据需手动刷新)</h3>
            <button class="action-btn" onclick="refreshData()">手动刷新数据/流量统计</button>
            <table class="user-table" id="user-table">
                <thead>
                    <tr>
                        <th>用户名</th>
                        <th>状态</th>
                        <th>创建日期</th>
                        <th>到期日期</th>
                        <th>总下载流量 (估算)</th>
                        <th>总上传流量 (估算)</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr id="row-{{ user.username }}">
                        <td>{{ user.username }}</td>
                        <td><span class="status-badge status-{{ user.status }}">{{ user.status.upper() }}</span></td>
                        <td>{{ user.created_at.split(' ')[0] }}</td>
                        <td>{{ user.expire_date.split(' ')[0] }}</td>
                        <td data-in="{{ user.bytes_in }}">{{ format_bytes(user.bytes_in) }}</td>
                        <td data-out="{{ user.bytes_out }}">{{ format_bytes(user.bytes_out) }}</td>
                        <td>
                            <button class="action-btn" onclick="openUpdateModal('{{ user.username }}', '{{ user.expire_date.split(' ')[0] }}')">改期</button>
                            <button class="action-btn delete-btn" onclick="deleteUser('{{ user.username }}')">删除</button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            <p class="info-note">注意：流量统计采用 **iptables owner 模块** 进行估算，精确度受 SSH 隧道连接机制限制。点击 **手动刷新** 获取最新数据。</p>
        </div>
    </div>

        <div id="updateModal" style="display: none; position: fixed; z-index: 1; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.4);">
      <div style="background-color: #fefefe; margin: 15% auto; padding: 20px; border: 1px solid #888; width: 80%; max-width: 400px; border-radius: 10px;">
        <h3>修改用户 <span id="modal-username"></span> 的到期日</h3>
        <form id="update-date-form">
          <input type="hidden" id="update-username">
          <label for="update-expire-date">新的到期日期:</label>
          <input type="date" id="update-expire-date" required style="width: 100%; padding: 10px; margin-top: 5px; margin-bottom: 15px;">
          <button type="submit" class="action-btn" style="background-color: #3b5998;">保存</button>
          <button type="button" class="action-btn delete-btn" onclick="closeUpdateModal()" style="margin-left: 10px;">取消</button>
        </form>
      </div>
    </div>
    
    <script>
        function formatBytes(bytes) {
            if (bytes === null || bytes === undefined) return "N/A";
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            let i = 0;
            let value = parseFloat(bytes);
            if (value === 0) return "0 B";

            while (value >= 1024 && i < units.length - 1) {
                value /= 1024.0;
                i++;
            }
            return `${value.toFixed(2)} ${units[i]}`;
        }

        function showStatus(message, isSuccess) {
            const statusDiv = document.getElementById('status-message');
            statusDiv.textContent = message;
            statusDiv.className = isSuccess ? 'alert alert-success' : 'alert alert-error';
            statusDiv.style.display = 'block';
            setTimeout(() => { statusDiv.style.display = 'none'; }, 5000);
        }
        
        // --- 用户增删改查 API ---

        document.getElementById('add-user-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('new-username').value.trim();
            const password = document.getElementById('new-password').value;
            const expireDate = document.getElementById('expire-date').value;

            try {
                const response = await fetch('/api/users/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password, expire_date: expireDate })
                });
                const result = await response.json();
                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    document.getElementById('add-user-form').reset();
                    setInitialExpireDate(); // 重置初始日期
                    refreshData(true); // 强制刷新数据
                } else {
                    showStatus('创建失败: ' + (result.message || '未知错误'), false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        });

        async function deleteUser(username) {
            if (!confirm(`确定要删除用户 \${username} 吗? (系统账户和数据将一并删除)`)) {
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
                    refreshData(true); // 强制刷新数据
                } else {
                    showStatus('删除失败: ' + (result.message || '未知错误'), false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        }

        function openUpdateModal(username, current_date) {
            document.getElementById('modal-username').textContent = username;
            document.getElementById('update-username').value = username;
            document.getElementById('update-expire-date').value = current_date;
            document.getElementById('updateModal').style.display = 'block';
        }

        function closeUpdateModal() {
            document.getElementById('updateModal').style.display = 'none';
        }

        document.getElementById('update-date-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('update-username').value;
            const newDate = document.getElementById('update-expire-date').value;

            try {
                const response = await fetch('/api/users/update_date', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, expire_date: newDate })
                });
                const result = await response.json();
                closeUpdateModal();
                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    refreshData(true);
                } else {
                    showStatus('修改失败: ' + (result.message || '未知错误'), false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        });

        // --- 实时刷新功能 ---
        
        // forceRefresh: 只有在添加/删除用户时才需要强制刷新整个页面数据
        async function refreshData(forceRefresh = false) {
            if (!forceRefresh) {
                // 仅更新流量统计
                const response = await fetch('/api/data/refresh', { method: 'GET' });
                if (response.ok) {
                    const data = await response.json();
                    updateTable(data.users);
                    document.getElementById('user-count').textContent = `${data.active_count} / ${data.users.length}`;
                }
            } else {
                // 强制刷新 (如删除/添加用户)
                location.reload();
            }
        }

        function updateTable(users) {
            // 仅更新现有行的流量和状态
            users.forEach(user => {
                const row = document.getElementById(`row-\${user.username}`);
                if (row) {
                    const statusCell = row.cells[1].querySelector('.status-badge');
                    statusCell.textContent = user.status.toUpperCase();
                    statusCell.className = `status-badge status-\${user.status}`;
                    row.cells[4].textContent = formatBytes(user.bytes_in);
                    row.cells[5].textContent = formatBytes(user.bytes_out);
                    row.cells[3].textContent = user.expire_date.split(' ')[0];
                }
            });
        }

        function setInitialExpireDate() {
            const today = new Date();
            today.setDate(today.getDate() + 30);
            const month = String(today.getMonth() + 1).padStart(2, '0');
            const day = String(today.getDate()).padStart(2, '0');
            const year = today.getFullYear();
            document.getElementById('expire-date').value = `${year}-${month}-${day}`;
        }

        function logout() { window.location.href = '/logout'; }

        window.onload = () => {
            setInitialExpireDate();
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
    if host_ip in ('127.0.0.1', 'localhost'):
        host_ip = '[Your Server IP]'

    active_users_count = sum(1 for user in users if user.get('status') == 'active')

    # 流量数据需要通过 API 动态获取，这里传入初始化值
    for user in users:
        user['bytes_in'] = 0
        user['bytes_out'] = 0

    context = {
        'users': users,
        'panel_port': PANEL_PORT,
        'wss_tls_port': WSS_TLS_PORT,
        'stunnel_port': STUNNEL_PORT,
        'host_ip': host_ip,
        'active_users_count': active_users_count,
        'format_bytes': format_bytes
    }
    return template.render(**context)


# --- Web 路由 ---

@app.route('/', methods=['GET'])
@login_required
def dashboard():
    # 仅加载用户列表，不刷新流量，让前端手动点击刷新
    users = [dict(user) for user in get_all_users()]
    html_content = render_dashboard(users=users)
    return make_response(html_content)


@app.route('/api/data/refresh', methods=['GET'])
@login_required
def refresh_data_api():
    """提供实时刷新所需的用户数据."""
    users = refresh_traffic_and_status()
    active_count = sum(1 for user in users if user.get('status') == 'active')
    
    return jsonify({"success": True, "users": users, "active_count": active_count})


@app.route('/api/users/add', methods=['POST'])
@login_required
def add_user_api():
    data = request.json
    username = data.get('username')
    password_raw = data.get('password')
    expire_date_str = data.get('expire_date')

    if not (username and password_raw and expire_date_str):
        return jsonify({"success": False, "message": "缺少用户名、密码或到期日"}), 400

    if get_user_by_username(username):
        return jsonify({"success": False, "message": f"用户 {username} 已存在于面板"}), 409

    try:
        date_parser.parse(expire_date_str)
    except ValueError:
        return jsonify({"success": False, "message": "到期日格式错误"}), 400

    # 1. 创建系统用户
    success, output = safe_run_command(['useradd', '-m', '-s', '/bin/false', username])
    if not success:
        return jsonify({"success": False, "message": f"创建系统用户失败: {output}"}), 500

    # 2. 设置密码
    chpasswd_input = f"{username}:{password_raw}"
    success, output = safe_run_command(['/usr/sbin/chpasswd'], input=chpasswd_input.encode('utf-8'))
    if not success:
        safe_run_command(['userdel', '-r', username])
        return jsonify({"success": False, "message": f"设置密码失败: {output}"}), 500
        
    # 3. 记录到 SQLite 数据库
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO users (username, created_at, expire_date, status) VALUES (?, ?, ?, ?)", 
                    (username, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), expire_date_str, 'active'))
        conn.commit()
    except sqlite3.Error as e:
        safe_run_command(['userdel', '-r', username])
        return jsonify({"success": False, "message": f"数据库错误: {e}"}), 500
    finally:
        conn.close()

    # 4. 更新 iptables (立即为新用户添加规则)
    update_iptables_rules_and_read_traffic()
    
    return jsonify({"success": True, "message": f"用户 {username} 创建成功，到期日: {expire_date_str}"})

@app.route('/api/users/update_date', methods=['POST'])
@login_required
def update_user_date_api():
    data = request.json
    username = data.get('username')
    expire_date_str = data.get('expire_date')

    if not (username and expire_date_str):
        return jsonify({"success": False, "message": "缺少用户名或到期日"}), 400

    try:
        date_parser.parse(expire_date_str)
    except ValueError:
        return jsonify({"success": False, "message": "到期日格式错误"}), 400
    
    conn = get_db_connection()
    try:
        # 将状态重置为 active
        cursor = conn.execute("UPDATE users SET expire_date = ?, status = 'active' WHERE username = ?", (expire_date_str, username))
        conn.commit()
        
        if cursor.rowcount == 0:
            return jsonify({"success": False, "message": f"用户 {username} 不存在"}), 404
        
        # 解锁系统用户 (如果之前被锁定)
        safe_run_command(['usermod', '-U', username]) 
        
        # 刷新 iptables (确保用户恢复正常连接)
        update_iptables_rules_and_read_traffic()
        
        return jsonify({"success": True, "message": f"用户 {username} 到期日更新为 {expire_date_str}，并已重新激活"})
    except sqlite3.Error as e:
        return jsonify({"success": False, "message": f"数据库错误: {e}"}), 500
    finally:
        conn.close()


@app.route('/api/users/delete', methods=['POST'])
@login_required
def delete_user_api():
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({"success": False, "message": "缺少用户名"}), 400

    if username == ROOT_USERNAME:
        return jsonify({"success": False, "message": "不能删除 root 管理员"}), 403

    # 1. 从 SQLite 数据库中删除记录
    conn = get_db_connection()
    try:
        cursor = conn.execute("DELETE FROM users WHERE username = ?", (username,))
        if cursor.rowcount == 0:
            return jsonify({"success": False, "message": f"面板中用户 {username} 不存在"}), 404
        conn.commit()
    except sqlite3.Error as e:
        return jsonify({"success": False, "message": f"数据库删除错误: {e}"}), 500
    finally:
        conn.close()

    # 2. 删除系统用户及其主目录
    safe_run_command(['userdel', '-r', username]) # 即使失败也忽略，以确保面板记录被删除

    # 3. 刷新 iptables (移除旧规则)
    update_iptables_rules_and_read_traffic()
    
    return jsonify({"success": True, "message": f"用户 {username} 已删除"})

# 保持 Login 和 Logout 路由不变
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

    html = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS Panel - 登录</title>
    <style>
        body {{ font-family: sans-serif; background-color: #f4f7f6; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
        .container {{ background: white; padding: 25px; border-radius: 12px; box-shadow: 0 6px 15px rgba(0, 0, 0, 0.1); width: 100%; max-width: 380px; }}
        h1 {{ text-align: center; color: #3b5998; margin-bottom: 25px; font-weight: 600; }}
        input[type=text], input[type=password] {{ width: 100%; padding: 12px 10px; margin: 8px 0; display: inline-block; border: 1px solid #ccc; border-radius: 8px; box-sizing: border-box; transition: border-color 0.3s; }}
        input[type=text]:focus, input[type=password]:focus {{ border-color: #3b5998; outline: none; }}
        button {{ background-color: #3b5998; color: white; padding: 14px 20px; margin: 15px 0 5px 0; border: none; border-radius: 8px; cursor: pointer; width: 100%; font-size: 16px; transition: background-color 0.3s; }}
        button:hover {{ background-color: #29487d; }}
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
    return make_response(html)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    # 在启动面板前，先执行一次状态刷新，确保 iptables 规则存在，且初始用户状态正确
    try:
        update_iptables_rules_and_read_traffic()
        print("Initial traffic and status refreshed successfully.")
    except Exception as e:
        print(f"WARNING: Initial refresh failed: {e}")
    
    print(f"WSS Panel running on port {PANEL_PORT}")
    app.run(host='0.0.0.0', port=int(PANEL_PORT), debug=False)
EOF

chmod +x /usr/local/bin/wss_panel.py

# =============================
# 创建 WSS 面板 systemd 服务
# =============================
tee /etc/systemd/system/wss_panel.service > /dev/null <<EOF
[Unit]
Description=WSS User Management Panel (Flask/SQLite)
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
echo "✅ 部署完成！WSS 面板已升级至 V2 版本。"
echo "=================================================="
echo ""
echo "🔥 新增功能: 用户到期日控制、流量估算统计。"
echo "🚀 UI 界面已优化。"
echo ""
echo "--- 访问信息 ---"
echo "Web 面板地址: http://[您的服务器IP]:$PANEL_PORT"
echo "Web 面板用户名: root"
echo "Web 面板密码: [您刚才设置的密码]"
echo ""
echo "--- 端口信息 ---"
echo "WSS (HTTP/WebSocket): $WSS_HTTP_PORT"
echo "WSS (TLS/WebSocket): $WSS_TLS_PORT"
echo "Stunnel (TLS 隧道): $STUNNEL_PORT"
echo "内部转发端口 (SSH): 48303"
echo ""
echo "--- 故障排查 ---"
echo "Web 面板数据库: /etc/wss-panel/users.db (SQLite)"
echo "检查 iptables 流量规则: iptables -L WSS_USERS -v -x -n"
echo "=================================================="
