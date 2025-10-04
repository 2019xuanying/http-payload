#!/usr/bin/env bash
#
# WSS 隧道和用户管理面板部署脚本 (v4.1)
# 新增功能: 活跃 IP/会话查询与单点踢出
#
set -eu

# ==================================
# 1. 通用工具函数和日志
# ==================================

# 打印信息
log_info() {
    echo "💡 [INFO] $1"
}

# 打印成功信息
log_success() {
    echo "✅ [SUCCESS] $1"
}

# 打印错误信息
log_error() {
    echo "❌ [ERROR] $1" >&2
}

# 检查端口是否正在监听
check_port() {
    PORT=$1
    if command -v ss >/dev/null 2>&1; then
        if ss -tuln | grep -q ":$PORT"; then
            echo "   端口 $PORT: 正在监听 (LISTEN)"
        else
            echo "   端口 $PORT: 未监听 (NOT LISTENING)"
        fi
    elif command -v netstat >/dev/null 2>&1; then
         if netstat -tuln | grep -q ":$PORT"; then
            echo "   端口 $PORT: 正在监听 (LISTEN)"
        else
            echo "   端口 $PORT: 未监听 (NOT LISTENING)"
        fi
    else
        echo "   警告: 缺少 'ss' 或 'netstat' 命令，无法检查端口 $PORT 状态。"
    fi
}

# ==================================
# 2. 交互式配置
# ==================================
log_info "==== WSS 基础设施端口配置 ===="
read -p "请输入 WSS HTTP 监听端口 (默认80): " WSS_HTTP_PORT
WSS_HTTP_PORT=${WSS_HTTP_PORT:-80}

read -p "请输入 WSS TLS 监听端口 (默认443): " WSS_TLS_PORT
WSS_TLS_PORT=${WSS_TLS_PORT:-443}

read -p "请输入 Stunnel4 端口 (默认444): " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-444}

read -p "请输入 UDPGW 端口 (默认7300): " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

log_info "----------------------------------"
log_info "==== 管理面板配置 ===="
read -p "请输入 Web 管理面板监听端口 (默认54321): " PANEL_PORT
PANEL_PORT=${PANEL_PORT:-54321}

# 交互式安全输入并确认 ROOT 密码
log_info "请为 Web 面板的 'root' 用户设置密码（输入时隐藏）。"
while true; do
    read -s -p "面板密码: " pw1 && echo
    read -s -p "请再次确认密码: " pw2 && echo
    if [ -z "$pw1" ]; then
        log_error "密码不能为空，请重新输入。"
        continue
    fi
    if [ "$pw1" != "$pw2" ]; then
        log_error "两次输入不一致，请重试。"
        continue
    fi
    PANEL_ROOT_PASS_RAW="$pw1"
    # 对密码进行简单的 HASH
    PANEL_ROOT_PASS_HASH=$(echo -n "$PANEL_ROOT_PASS_RAW" | sha256sum | awk '{print $1}')
    break
done

# ==================================
# 3. 系统更新与依赖安装
# ==================================
log_info "==== 系统更新与依赖安装 ===="
if ! command -v apt >/dev/null 2>&1; then
    log_error "本脚本依赖于 Debian/Ubuntu 的 'apt' 包管理器。请在兼容系统上运行。"
    exit 1
fi

apt update -y
# 确保安装了 openssl-tool (如 openssl), net-tools (如 netstat, 尽管优先使用 ss), procps (如 pkill, ps)
apt install -y python3 python3-pip wget curl git net-tools procps cmake build-essential openssl stunnel4
# 使用 --break-system-packages 避免在较新的 Debian/Ubuntu 上因系统保护而安装失败
pip3 install flask jinja2 requests --break-system-packages 2>/dev/null || pip3 install flask jinja2 requests
log_success "依赖安装完成"

# ==================================
# 4. 部署 WSS 核心代理脚本
# ==================================
log_info "==== 安装 WSS 核心代理脚本 (/usr/local/bin/wss) ===="
tee /usr/local/bin/wss > /dev/null <<'EOF'
#!/usr/bin/python3
# -*- coding: utf-8 -*-
# WSS 核心代理：处理 HTTP/WebSocket 握手并转发到本地 SSH 端口 48303

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

# 客户端握手响应
FIRST_RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK\r\n\r\n'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    """处理单个客户端连接的异步函数"""
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
                # 如果未收到完整头部，回复 OK 并继续等待
                writer.write(FIRST_RESPONSE)
                await writer.drain()
                full_request = b''
                continue

            # 2. 头部解析
            headers_raw = full_request[:header_end_index]
            data_to_forward = full_request[header_end_index + 4:]
            headers = headers_raw.decode(errors='ignore')

            # 识别 WebSocket 或特定隧道请求
            is_websocket_request = 'Upgrade: websocket' in headers or 'Connection: Upgrade' in headers or 'GET-RAY' in headers
            
            # 3. 转发触发
            if is_websocket_request:
                writer.write(SWITCH_RESPONSE)
                await writer.drain()
                forwarding_started = True
            else:
                # 非隧道请求，回复 OK 并关闭
                writer.write(FIRST_RESPONSE)
                await writer.drain()
                full_request = b''
                break
        
        # --- 退出握手循环，开始转发 ---
        if not forwarding_started:
            return

        # 4. 连接目标服务器 (SSH 端口)
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
        # Connection error, silently close
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def main():
    # TLS server setup
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        # 尝试加载证书链
        ssl_ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        tls_server = await asyncio.start_server(
            lambda r, w: handle_client(r, w, tls=True), LISTEN_ADDR, TLS_PORT, ssl=ssl_ctx)
        print(f"Listening on {LISTEN_ADDR}:{TLS_PORT} (TLS)")
        tls_task = tls_server.serve_forever()
    except FileNotFoundError:
        print(f"WARNING: TLS certificate not found at {CERT_FILE}. TLS server disabled.")
        tls_task = asyncio.sleep(86400) # 保持任务运行但禁用

    # HTTP server setup
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
systemctl enable wss || true
systemctl restart wss
log_success "WSS 核心代理已启动/重启，HTTP端口 $WSS_HTTP_PORT, TLS端口 $WSS_TLS_PORT"
log_info "----------------------------------"

# ==================================
# 5. 安装 Stunnel4 并生成证书
# ==================================
log_info "==== 检查/安装 Stunnel4 ===="
mkdir -p /etc/stunnel/certs
if [ ! -f "/etc/stunnel/certs/stunnel.pem" ]; then
    openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout /etc/stunnel/certs/stunnel.key \
    -out /etc/stunnel/certs/stunnel.crt \
    -days 1095 \
    -subj "/CN=wss-tunnel.com" > /dev/null 2>&1
    sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
    chmod 644 /etc/stunnel/certs/*.crt
    chmod 644 /etc/stunnel/certs/*.pem
    log_info "Stunnel 自签名证书已生成。"
fi

tee /etc/stunnel/ssh-tls.conf > /dev/null <<EOF
pid=/var/run/stunnel.pid
setuid=root
setgid=root
client = no
debug = 3
output = /var/log/stunnel4/stunnel.log
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls-gateway]
accept = 0.0.0.0:$STUNNEL_PORT
# Stunnel 转发目标是 127.0.0.1:48303 (SSH 内部端口)
connect = 127.0.0.1:48303
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
EOF

systemctl enable stunnel4 || true
systemctl restart stunnel4
log_success "Stunnel4 配置已更新并重启，端口 $STUNNEL_PORT"
log_info "----------------------------------"

# ==================================
# 6. 安装 UDPGW
# ==================================
log_info "==== 检查/安装 UDPGW ===="
if [ ! -f "/root/badvpn/badvpn-build/udpgw/badvpn-udpgw" ]; then
    if [ ! -d "/root/badvpn" ]; then
        git clone https://github.com/ambrop72/badvpn.git /root/badvpn > /dev/null 2>&1
    fi
    mkdir -p /root/badvpn/badvpn-build
    cd /root/badvpn/badvpn-build
    # 使用 nproc 加速编译
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 > /dev/null 2>&1
    make -j$(nproc) > /dev/null 2>&1
    cd - > /dev/null
    log_info "UDPGW 编译完成。"
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
systemctl restart udpgw
log_success "UDPGW 已启动/重启，端口: $UDPGW_PORT"
log_info "----------------------------------"

# ==================================
# 7. 部署 WSS 用户管理面板 (Flask) V4.1
# ==================================
log_info "==== 部署 WSS 用户管理面板 (Python/Flask) V4.1 活跃 IP 增强版 ===="
PANEL_DIR="/etc/wss-panel"
USER_DB="$PANEL_DIR/users.json"
mkdir -p "$PANEL_DIR"

# 检查/初始化用户数据库 (此处省略升级逻辑，简化初始化)
if [ ! -f "$USER_DB" ]; then
    echo "[]" > "$USER_DB"
fi

# 嵌入 Python 面板代码 (新增活跃 IP 功能)
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
# 使用一个随机密钥，提高安全性
FLASK_SECRET_KEY = os.urandom(24).hex()

# 面板和端口配置 (用于模板)
PANEL_PORT = "$PANEL_PORT"
WSS_HTTP_PORT = "$WSS_HTTP_PORT"
WSS_TLS_PORT = "$WSS_TLS_PORT"
STUNNEL_PORT = "$STUNNEL_PORT"
UDPGW_PORT = "$UDPGW_PORT"
SSH_INTERNAL_PORT = 48303

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

def safe_run_command(command, input_data=None, check=True, timeout=5):
    """安全执行系统命令并返回结果."""
    try:
        result = subprocess.run(
            command,
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=input_data, 
            timeout=timeout
        )
        return True, result.stdout.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        return False, e.stderr.decode('utf-8').strip()
    except Exception as e:
        return False, str(e)

def kill_user_sessions(username):
    """尝试杀死该用户的所有活动进程 (针对 SSH 会话)."""
    success, output = safe_run_command(['pkill', '-u', username], check=False)
    if success:
        print(f"Killed active sessions for user {username}.")
    else:
        # pkill 即使找不到进程也可能返回非零，忽略此警告
        print(f"Warning: pkill for {username} might have failed or no process found: {output}")
    return success, output

# --- 核心用户状态管理函数 (保持同步) ---

def sync_user_status(user):
    """检查并同步用户的到期日和流量配额状态到系统."""
    username = user['username']
    
    # ... (原有 sync_user_status 逻辑保持不变)
    is_expired = False
    if user.get('expiry_date'):
        try:
            expiry_dt = datetime.strptime(user['expiry_date'], '%Y-%m-%d')
            if expiry_dt.date() < datetime.now().date():
                is_expired = True
        except ValueError:
            print(f"Invalid expiry_date format for {username}: {user['expiry_date']}")
    
    is_quota_exceeded = user.get('quota_gb', 0.0) > 0 and user.get('used_traffic_gb', 0.0) >= user['quota_gb']
        
    current_status = user.get('status', 'active')
    should_be_paused = (current_status == 'paused') or is_expired or is_quota_exceeded
    
    system_locked = False
    success_status, output_status = safe_run_command(['passwd', '-S', username], check=False)
    if success_status and output_status and 'L' in output_status.split():
        system_locked = True
            
    # 如果面板要求启用 (active), 且系统是暂停的或已过期, 则解锁并清除到期日
    if not should_be_paused and system_locked:
        safe_run_command(['usermod', '-U', username], check=False) 
        safe_run_command(['chage', '-E', '', username], check=False) 
        user['status'] = 'active'
            
    # 如果面板要求暂停, 且系统是未暂停的
    elif should_be_paused and not system_locked:
        safe_run_command(['usermod', '-L', username], check=False)
        safe_run_command(['chage', '-E', '1970-01-01', username], check=False) 
        kill_user_sessions(username) 
        user['status'] = 'paused' 
            
    # 无论如何，如果到期日字段存在，确保它被设置到系统
    if user.get('expiry_date') and user['expiry_date'] != '1970-01-01' and user['status'] == 'active':
        safe_run_command(['chage', '-E', user['expiry_date'], username], check=False) 
        
    return user


def refresh_all_user_status(users):
    """批量同步用户状态."""
    for user in users:
        # 1. 同步系统状态
        user = sync_user_status(user)
        # 2. 格式化流量信息以便显示
        user['traffic_display'] = f"{user.get('used_traffic_gb', 0.0):.2f} / {user.get('quota_gb', 0.0):.2f} GB"
        
        # 3. 确定显示状态和颜色
        user_status = user.get('status', 'active')
        expiry_date = user.get('expiry_date', '')

        if user.get('quota_gb', 0.0) > 0 and user.get('used_traffic_gb', 0.0) >= user['quota_gb']:
            user['status_text'] = "超额"
            user['status_class'] = "bg-red-500"
        elif user_status == 'paused':
            user['status_text'] = "暂停"
            user['status_class'] = "bg-yellow-500"
        elif expiry_date and datetime.strptime(expiry_date, '%Y-%m-%d').date() < datetime.now().date():
            user['status_text'] = "到期"
            user['status_class'] = "bg-red-500"
        else:
            user['status_text'] = "活跃"
            user['status_class'] = "bg-green-500"
            
    save_users(users)
    return users

# --- 活跃会话管理函数 (NEW) ---

def get_active_sessions(username):
    """通过解析 ss 命令获取用户的活跃连接 IP 和对应的 SSHD 进程 PID。"""
    sessions = []
    
    # 1. 获取用户的 UID
    success_uid, uid_str = safe_run_command(['id', '-u', username], check=False, timeout=2)
    if not success_uid or not uid_str.isdigit():
        return []
    uid = uid_str.strip()

    # 2. 使用 ss -tnp (TCP, numeric, show process) 过滤出连接到 SSH 内部端口的连接
    # ss output example: tcp    ESTAB  0      0      127.0.0.1:48303   127.0.0.1:54321  users:(("sshd",pid=1234,fd=7))
    # Note: Since WSS/Stunnel tunnels from 127.0.0.1, we need to find the user's PID 
    # and then confirm the actual client IP using the PID's connection details.
    
    # 鉴于 WSS/Stunnel 都是连接到 127.0.0.1:48303，我们直接查找属于该 UID 的 'sshd' 进程。
    # 更好的方法是查找该 UID 的所有活动进程，但主要流量是 SSHD
    
    # 查找该 UID 下的所有 SSHD 进程 PID
    success_pids, pids_raw = safe_run_command(['pgrep', '-u', username, 'sshd'], check=False, timeout=2)
    if not success_pids or not pids_raw:
        return []

    pids = pids_raw.split('\n')
    
    # 查找所有到 48303 端口的 ESTABLISHED 连接
    success_ss, ss_output = safe_run_command(['ss', '-tn', 'state', 'established', '( sport = :48303 or dport = :48303 )'], check=False, timeout=2)
    if not success_ss or not ss_output:
        return []

    lines = ss_output.split('\n')[1:] # 跳过头部
    
    # 3. 关联连接和 PID/IP
    # SSHD 工作进程的连接是 *外部IP*:*外部端口* 到 *服务器IP* (例如: *.*.*.*:443 或 *.*.*.*:444)
    # 但是，由于我们是通过 WSS/Stunnel (127.0.0.1) 转发的，sshd 看到的是 127.0.0.1:48303 到 127.0.0.1:* 的连接。
    # 这让直接从 sshd 进程获取外部 IP 变得极其困难且不可靠。
    
    # 更好的方法：监控 WSS 或 Stunnel 的连接，但它们都是转发进程，无法获取最终用户 IP。
    # 我们只能通过解析 /proc/net/tcp 或 lsof 来尝试。
    
    # 鉴于此架构的限制，我们改用一个更可靠的方法：检查当前系统是否有该 UID 的进程连接到 48303，然后尝试解析出外网 IP。
    
    # 遍历该用户的所有 SSHD PID，并尝试找到其外部连接
    for pid in pids:
        pid = pid.strip()
        if not pid.isdigit():
            continue
            
        # 使用 lsof 查找该 PID 打开的文件描述符
        # lsof -i -a -p 1234
        success_lsof, lsof_output = safe_run_command(['lsof', '-i', '-a', f'-p{pid}'], check=False, timeout=2)
        
        if not success_lsof or not lsof_output:
            continue
            
        for line in lsof_output.split('\n'):
            if 'TCP' in line and 'ESTABLISHED' in line:
                # 示例: sshd 1234 user 7u  IPv4 12345 0t0  TCP 127.0.0.1:48303->127.0.0.1:45678 (ESTABLISHED)
                # 这仍然是内网连接。我们必须找 *实际* 监听 80/443/444 的进程连接。
                # 由于 Flask Panel 只能访问 SSHD 进程，而 SSHD 看到的是 127.0.0.1 的连接，
                # **无法可靠地获取外部 IP**。
                
                # 替代方案：检查 WSS/Stunnel 连接 (PID 1)
                # 放弃直接从 SSHD 进程获取外部 IP，因为 WSS/Stunnel 充当了中间人。
                
                # 回退到最可靠的方法：查找所有连接到 SSH 内部端口的连接，并识别出客户端IP。
                # 这种方法虽然不能 "禁用单个 IP"，但可以 "查询活跃 IP"。
                
                # 重新执行 ss -tn | grep 48303 查找所有连接到 48303 的进程
                # 找到连接到 48303 的 TCP 进程 (WSS, Stunnel 或其他程序)
                ss_full_output = safe_run_command(['ss', '-tnp', 'sport = :48303 or dport = :48303'], check=False, timeout=5)[1]
                
                # 遍历所有到 48303 的连接，找到 SSHD 工作进程的内部连接
                # 示例行: tcp    ESTAB  0      0      127.0.0.1:48303   127.0.0.1:54321  users:(("sshd",pid=PID,fd=7))
                if f'users:(("sshd",pid={pid},' in line:
                    
                    # 找到该 PID 对应的连接，这只能是 127.0.0.1 的内部连接。
                    # 无法获取外部 IP，但我们知道这个 PID 是活跃的。
                    # 我们需要找到与这个 PID 关联的 **外部 IP**。
                    # 由于 WSS/Stunnel 的转发，唯一的办法是：
                    # 1. WSS/Stunnel 连接到 48303
                    # 2. SSHD 进程 PID 1234 接受了来自 127.0.0.1 的连接
                    # 3. WSS/Stunnel 的父进程 PID 4567 接受了来自 *外部 IP* 的连接。
                    # 
                    # 结论：在这个架构下，Flask 无法直接知道 SSHD 进程对应的外部 IP。
                    #
                    # 最终的妥协：我们只能展示 SSHD 活跃进程的 PID，并允许 "终止进程"
                    # 这本质上就是终止该用户的一个活跃会话。
                    
                    # 提取连接时间 (近似值, 忽略)
                    
                    # 寻找匹配的 ss 行，提取时间、状态、和 PID
                    ss_process_lines = safe_run_command(['ss', '-tnp', 'sport = :48303 or dport = :48303'], check=False, timeout=5)[1]
                    for ss_line in ss_process_lines.split('\n'):
                        if f'users:(("sshd",pid={pid},' in ss_line:
                            # 格式: State Recv-Q Send-Q Local Address:Port Peer Address:Port
                            parts = ss_line.split()
                            if len(parts) >= 6:
                                # 这是内部连接，但我们可以用一个唯一的ID来表示它
                                # 强制使用外部 IP 地址作为占位符，因为我们无法知道真正的外部 IP
                                # 为了满足用户需求，我们假定 "Peer Address" 是其在 WSS/Stunnel 层的ID
                                # 实际上它只会是 127.0.0.1
                                internal_remote_addr = parts[4] # Local address (127.0.0.1:48303)
                                internal_local_addr = parts[5] # Peer address (127.0.0.1:XXXXX)
                                
                                # 使用进程启动时间作为近似的连接时间
                                try:
                                    success_ps, ps_output = safe_run_command(['ps', '-p', pid, '-o', 'etime,start_time', '--no-headers'], check=False, timeout=1)
                                    if success_ps:
                                        time_parts = ps_output.strip().split()
                                        elapsed_time = time_parts[0] if len(time_parts) > 0 else 'N/A'
                                        start_time = time_parts[1] if len(time_parts) > 1 else 'N/A'
                                    else:
                                        elapsed_time = 'N/A'
                                        start_time = 'N/A'
                                except Exception:
                                    elapsed_time = 'N/A'
                                    start_time = 'N/A'
                                
                                # 使用一个唯一的标识符作为 "IP"
                                unique_ip_identifier = f"Session-ID-{internal_local_addr.split(':')[-1]}"
                                
                                # 检查是否重复 (因为可能一个 PID 有多个 FD)
                                if not any(s['pid'] == pid for s in sessions):
                                    sessions.append({
                                        'ip': unique_ip_identifier, # 无法获取外部 IP，使用内部会话 ID
                                        'pid': pid,
                                        'elapsed_time': elapsed_time,
                                        'start_time': start_time,
                                        'status': 'ESTAB'
                                    })
                            break
                            
    return sessions

# --- HTML 模板和渲染 (更新前端以支持新的活跃 IP 按钮和模态框) ---

# 登录 HTML (保持不变)

# 仪表盘 HTML (内嵌 - 使用 Tailwind)
_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS Panel - 仪表盘 V4.1</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .card { transition: all 0.3s ease; }
        .card:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1); }
        .btn-action { transition: all 0.2s ease; }
        .btn-action:hover { opacity: 0.8; }
        .modal { background-color: rgba(0, 0, 0, 0.5); z-index: 999; }
    </style>
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="bg-indigo-600 text-white shadow-lg">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center">
            <h1 class="text-3xl font-bold">WSS 隧道管理面板 V4.1</h1>
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
            <h3 class="text-xl font-semibold text-gray-800 mb-4 border-b pb-2">连接信息</h3>
            <div class="bg-gray-100 p-4 rounded-lg font-mono text-sm overflow-x-auto">
                <p><span class="font-bold">服务器地址:</span> {{ host_ip }} (请手动替换为你的公网 IP)</p>
                <p><span class="font-bold">WSS (TLS/WebSocket):</span> 端口 {{ wss_tls_port }}</p>
                <p><span class="font-bold">Stunnel (TLS 隧道):</span> 端口 {{ stunnel_port }}</p>
                <p><span class="font-bold text-red-600">注意:</span> 认证方式为 **SSH 账户/密码**。WSS/Stunnel 均转发至本地 SSH 端口 48303。</p>
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
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2 flex items-center">
                                <button onclick="toggleUserStatus('{{ user.username }}', '{{ 'pause' if user.status_text == '活跃' else 'active' }}')" 
                                        class="text-xs px-3 py-1 rounded-full font-bold {{ 'bg-yellow-100 text-yellow-800 hover:bg-yellow-200' if user.status_text == '活跃' else 'bg-green-100 text-green-800 hover:bg-green-200' }} btn-action">
                                    {{ '暂停' if user.status_text == '活跃' else '启用' }}
                                </button>
                                <button onclick="openQuotaModal('{{ user.username }}', '{{ user.quota_gb }}', '{{ user.expiry_date }}')" 
                                        class="text-xs px-3 py-1 rounded-full font-bold bg-blue-100 text-blue-800 hover:bg-blue-200 btn-action">
                                    配额/到期
                                </button>
                                <button onclick="resetTraffic('{{ user.username }}')"
                                        class="text-xs px-3 py-1 rounded-full font-bold bg-purple-100 text-purple-800 hover:bg-purple-200 btn-action">
                                    重置流量
                                </button>
                                <!-- NEW: 活跃 IP 按钮 -->
                                <button onclick="openActiveIPModal('{{ user.username }}')"
                                        class="text-xs px-3 py-1 rounded-full font-bold bg-indigo-100 text-indigo-800 hover:bg-indigo-200 btn-action">
                                    活跃 IP
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
    
    <!-- NEW Modal for Active IP Management -->
    <div id="active-ip-modal" class="modal fixed inset-0 flex items-center justify-center p-4 hidden">
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-xl">
            <div class="p-6">
                <div class="flex justify-between items-center border-b pb-2 mb-4">
                    <h3 class="text-xl font-bold text-gray-800">活跃会话管理 (<span id="modal-ip-username-title"></span>)</h3>
                    <button onclick="closeActiveIPModal()" class="text-gray-500 hover:text-gray-800 text-2xl font-bold">&times;</button>
                </div>
                
                <p id="ip-loading" class="text-center text-indigo-600 font-semibold hidden">正在查询活跃会话...</p>
                <div id="active-ip-list-container" class="max-h-96 overflow-y-auto">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50 sticky top-0">
                            <tr>
                                <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">会话 ID (PID)</th>
                                <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">连接时长</th>
                                <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">操作</th>
                            </tr>
                        </thead>
                        <tbody id="active-ip-list" class="bg-white divide-y divide-gray-200">
                            <!-- IP sessions will be inserted here -->
                        </tbody>
                    </table>
                    <p id="no-active-ips" class="text-center text-gray-500 py-4 hidden">该用户当前没有活跃会话。</p>
                </div>
                
                <p class="mt-4 text-sm text-red-600 bg-red-50 p-3 rounded-lg">
                    <span class="font-bold">注意:</span> 由于隧道架构限制，此处仅显示内部会话ID (**SSH 进程 PID**)而非外部 IP。点击 **断开** 将强制终止对应的 SSH 进程，从而踢出该设备。
                </p>
            </div>
        </div>
    </div>


    <script>
        // ---------------- UTILITIES -----------------
        function showStatus(message, isSuccess) {
            const statusDiv = document.getElementById('status-message');
            statusDiv.textContent = message;
            statusDiv.className = \`\${isSuccess ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'} p-4 mb-4 rounded-lg font-semibold\`;
            statusDiv.classList.remove('hidden');
            setTimeout(() => { statusDiv.classList.add('hidden'); }, 5000);
        }

        function logout() {
            window.location.href = '/logout';
        }

        // ---------------- USER CRUD/QUOTA ACTIONS -----------------

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
                    location.reload(); 
                } else {
                    showStatus('创建失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        });

        // Toggle Status
        async function toggleUserStatus(username, action) {
            const actionText = action === 'active' ? '启用' : '暂停';
            const confirmText = action === 'active' ? 'YES' : 'STOP';
            if (!window.confirm(\`确定要\${actionText}用户 \${username} 吗? (\${actionText}操作将同时终止所有活动会话。)\`)) {
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

        // Delete User
        async function deleteUser(username) {
            if (!window.confirm(\`确定要永久删除用户 \${username} 吗? (此操作将终止所有活动会话并删除系统账户。)\`)) {
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

        // Reset Traffic
        async function resetTraffic(username) {
            if (!window.confirm('确定要将用户 ' + username + ' 的已用流量清零吗?')) {
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
        
        // Quota Modal
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
        
        // ---------------- ACTIVE IP MANAGEMENT (NEW) -----------------
        
        function openActiveIPModal(username) {
            document.getElementById('modal-ip-username-title').textContent = username;
            document.getElementById('active-ip-modal').classList.remove('hidden');
            fetchActiveSessions(username);
        }

        function closeActiveIPModal() {
            document.getElementById('active-ip-modal').classList.add('hidden');
            document.getElementById('active-ip-list').innerHTML = ''; // Clear list on close
            document.getElementById('ip-loading').classList.add('hidden');
            document.getElementById('no-active-ips').classList.add('hidden');
        }
        
        async function fetchActiveSessions(username) {
            const listContainer = document.getElementById('active-ip-list');
            const loadingIndicator = document.getElementById('ip-loading');
            const noActiveIpsMessage = document.getElementById('no-active-ips');
            listContainer.innerHTML = '';
            loadingIndicator.classList.remove('hidden');
            noActiveIpsMessage.classList.add('hidden');
            
            try {
                const response = await fetch(\`/api/users/active_sessions?username=\${username}\`);
                const data = await response.json();
                
                loadingIndicator.classList.add('hidden');

                if (response.ok && data.success) {
                    const sessions = data.sessions;
                    
                    if (sessions.length === 0) {
                        noActiveIpsMessage.classList.remove('hidden');
                    } else {
                        sessions.forEach(session => {
                            const row = document.createElement('tr');
                            row.className = "hover:bg-gray-50";
                            row.innerHTML = \`
                                <td class="px-4 py-2 whitespace-nowrap text-sm font-medium text-gray-900">
                                    \${session.ip} (<span class="text-xs text-gray-500">PID: \${session.pid}</span>)
                                </td>
                                <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-500">
                                    \${session.elapsed_time}
                                </td>
                                <td class="px-4 py-2 whitespace-nowrap text-sm font-medium">
                                    <button onclick="killSession('\${username}', '\${session.pid}', '\${session.ip}')"
                                            class="text-xs px-3 py-1 rounded-full font-bold bg-red-100 text-red-800 hover:bg-red-200 btn-action">
                                        断开 (Kill)
                                    </button>
                                </td>
                            \`;
                            listContainer.appendChild(row);
                        });
                    }
                } else {
                    showStatus('查询活跃 IP 失败: ' + data.message, false);
                }
                
            } catch (error) {
                loadingIndicator.classList.add('hidden');
                showStatus('请求失败，无法连接到 API。', false);
            }
        }
        
        async function killSession(username, pid, identifier) {
             if (!window.confirm(\`确定要终止 \${username} 的会话 ID (\${identifier}, PID: \${pid}) 吗? (这将踢出该设备。)\`)) {
                return;
            }
            
            try {
                const response = await fetch('/api/users/kill_session', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, pid })
                });

                const result = await response.json();

                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    // 重新加载活跃会话列表
                    fetchActiveSessions(username);
                } else {
                    showStatus('断开会话失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        }

    </script>
</body>
</html>
"""

# 修复后的渲染函数
def render_dashboard(users):
    """手动渲染 Jinja2 模板字符串."""
    template_env = jinja2.Environment(loader=jinja2.BaseLoader)
    template = template_env.from_string(_DASHBOARD_HTML)
    
    # 尝试获取服务器IP (这里只是一个猜测，需要用户手动替换)
    host_ip = request.host.split(':')[0]
    if host_ip in ('127.0.0.1', 'localhost', '0.0.0.0'):
        # 尝试通过环境变量或外部命令获取公网IP
        try:
            # 使用 curl -s ifconfig.me 获取外部 IP
            success, public_ip = safe_run_command(['curl', '-s', 'ifconfig.me'], check=False, timeout=1)
            if success and public_ip and public_ip.replace('.', '').isdigit():
                 host_ip = public_ip
            else:
                 host_ip = '[Your Server IP]'
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


# --- Web 路由 (新增/修改) ---

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
                return redirect(url_for('dashboard'))
            else:
                error = '用户名或密码错误。'
        else:
            error = '用户名或密码错误。'

    # 登录页 HTML
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
        <h1 class="text-2xl">WSS 管理面板 V4.1</h1>
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


# --- API 路由 --- (CRUD, Traffic, Settings 路由保持不变，仅列出新增的会话管理 API)

@app.route('/api/users/active_sessions', methods=['GET'])
@login_required
def active_sessions_api():
    """获取用户的活跃 SSH 会话列表 (基于 PID)"""
    username = request.args.get('username')
    
    if not username:
        return jsonify({"success": False, "message": "缺少用户名"}), 400

    user, _ = get_user(username)
    if not user:
        return jsonify({"success": False, "message": f"用户 {username} 不存在"}), 404

    # 调用核心会话查找逻辑
    sessions = get_active_sessions(username)
    
    return jsonify({"success": True, "sessions": sessions})


@app.route('/api/users/kill_session', methods=['POST'])
@login_required
def kill_session_api():
    """终止指定的 SSHD 进程 (会话)"""
    data = request.json
    username = data.get('username')
    pid_str = data.get('pid')

    if not username or not pid_str or not pid_str.isdigit():
        return jsonify({"success": False, "message": "缺少用户名或无效的 PID"}), 400
    
    pid = int(pid_str)

    # 1. 验证 PID 是否属于该用户
    success_uid, uid_str = safe_run_command(['id', '-u', username], check=False, timeout=1)
    if not success_uid or not uid_str.isdigit():
        return jsonify({"success": False, "message": f"无法获取用户 {username} 的 UID"}), 500

    success_check, output_check = safe_run_command(['ps', '-o', 'uid,cmd', '-p', str(pid), '--no-headers'], check=False, timeout=1)
    
    if not success_check or not output_check:
        return jsonify({"success": False, "message": f"进程 {pid} 不存在或已终止"}), 404
    
    # 解析输出，确认 UID 和进程名
    try:
        proc_uid = output_check.strip().split()[0]
        proc_cmd = output_check.strip().split()[-1]
        
        if proc_uid != uid_str or 'sshd' not in proc_cmd:
            return jsonify({"success": False, "message": f"权限错误: PID {pid} 不属于用户 {username} 或不是 SSHD 进程"}), 403
    except Exception:
        return jsonify({"success": False, "message": f"无法解析进程信息 PID {pid}"}), 500


    # 2. 终止进程 (使用 SIGTERM/SIGKILL 确保终止)
    success, output = safe_run_command(['kill', '-9', str(pid)], check=False, timeout=2)
    
    if success:
        return jsonify({"success": True, "message": f"会话 (PID: {pid}) 已成功断开"})
    else:
        # 如果 kill 失败，通常是权限或进程已终止
        return jsonify({"success": False, "message": f"终止进程失败: {output}"}), 500

# --- 其他 CRUD/Traffic/Settings 路由 (此处省略，保持原有逻辑) ---
# ... (add_user_api, delete_user_api, toggle_user_status_api, update_user_traffic_api, update_user_settings_api 路由)
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
    success, output = safe_run_command(['useradd', '-m', '-s', '/bin/false', username], check=False)
    if not success:
        return jsonify({"success": False, "message": f"创建系统用户失败: {output}"}), 500

    # 2. 设置密码
    chpasswd_input = f"{username}:{password_raw}"
    success, output = safe_run_command(['/usr/sbin/chpasswd'], input=chpasswd_input.encode('utf-8'), check=False)
    if not success:
        safe_run_command(['userdel', '-r', username], check=False)
        return jsonify({"success": False, "message": f"设置密码失败: {output}"}), 500
        
    # 3. 记录到 JSON 数据库
    new_user = {
        "username": username,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "status": "active",
        "expiry_date": "", 
        "quota_gb": 0.0,
        "used_traffic_gb": 0.0,
        "last_check": time.time()
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

    # 2. 删除系统用户及其主目录
    success, output = safe_run_command(['userdel', '-r', username], check=False)
    if not success:
        print(f"Warning: Failed to delete system user {username}: {output}")

    # 3. 从 JSON 数据库中删除记录
    users.pop(index)
    save_users(users)

    return jsonify({"success": True, "message": f"用户 {username} 已删除，活动会话已终止"})

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
        success, output = safe_run_command(['usermod', '-L', username], check=False)
        safe_run_command(['chage', '-E', '1970-01-01', username], check=False) 
        kill_user_sessions(username) 
        users[index]['status'] = 'paused'
        message = f"用户 {username} 已暂停，活动会话已终止"
    elif action == 'active':
        success, output = safe_run_command(['usermod', '-U', username], check=False)
        if users[index].get('expiry_date'):
            safe_run_command(['chage', '-E', users[index]['expiry_date'], username], check=False) 
        else:
            safe_run_command(['chage', '-E', '', username], check=False) 
            
        users[index]['status'] = 'active'
        message = f"用户 {username} 已启用"
    else:
        return jsonify({"success": False, "message": "无效的操作参数"}), 400

    if success:
        save_users(users)
        return jsonify({"success": True, "message": message})
    else:
        return jsonify({"success": False, "message": f"系统操作失败: {output}"}), 500

@app.route('/api/users/reset_traffic', methods=['POST'])
@login_required
def reset_user_traffic_api():
    """将用户的已用流量清零 (API)"""
    data = request.json
    username = data.get('username')

    user, index = get_user(username)
    if not user:
        return jsonify({"success": False, "message": f"用户 {username} 不存在"}), 404
        
    users = load_users()
    
    # 清零流量
    users[index]['used_traffic_gb'] = 0.0
    
    # 如果用户超额状态被清除，重新同步状态
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
            datetime.strptime(expiry_date, '%Y-%m-%d') 
    except ValueError:
        return jsonify({"success": False, "message": "配额或日期格式不正确"}), 400

    # 更新面板数据库
    users[index]['quota_gb'] = quota_gb
    users[index]['expiry_date'] = expiry_date
    
    # 重新同步状态 (流量超额或日期已过则暂停)
    users[index] = sync_user_status(users[index])
    
    save_users(users)
    return jsonify({"success": True, "message": f"用户 {username} 设置已更新"})
    
    
@app.route('/api/users/update_traffic', methods=['POST'])
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

# --- 启动 Flask App ---
if __name__ == '__main__':
    print(f"WSS Panel running on port {PANEL_PORT}")
    app.run(host='0.0.0.0', port=int(PANEL_PORT), debug=False)
EOF

chmod +x /usr/local/bin/wss_panel.py

# ==================================
# 8. 创建 WSS 面板 systemd 服务
# ==================================
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
systemctl enable wss_panel || true
systemctl restart wss_panel
log_success "WSS 管理面板 V4.1 已启动/重启，端口 $PANEL_PORT"
log_info "----------------------------------"

# ==================================
# 9. 部署 IPTABLES 流量监控和同步脚本
# ==================================

# IPTABLES 链设置函数 (保持不变)
setup_iptables_chains() {
    log_info "==== 配置 IPTABLES 流量统计链 ===="
    
    iptables -D INPUT -j WSS_USER_TRAFFIC_IN 2>/dev/null || true
    iptables -D OUTPUT -j WSS_USER_TRAFFIC_OUT 2>/dev/null || true
    
    iptables -F WSS_USER_TRAFFIC_IN 2>/dev/null || true
    iptables -X WSS_USER_TRAFFIC_IN 2>/dev/null || true
    iptables -F WSS_USER_TRAFFIC_OUT 2>/dev/null || true
    iptables -X WSS_USER_TRAFFIC_OUT 2>/dev/null || true

    iptables -N WSS_USER_TRAFFIC_IN
    iptables -N WSS_USER_TRAFFIC_OUT

    iptables -I INPUT 1 -j WSS_USER_TRAFFIC_IN
    iptables -I OUTPUT 1 -j WSS_USER_TRAFFIC_OUT
    
    # 保存规则
    if command -v iptables-save >/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi

    log_success "IPTABLES 流量统计链创建/清理完成，已连接到 INPUT/OUTPUT。"
}

# 流量同步 Python 脚本 (保持不变)
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

def safe_run_command(command, input_data=None, timeout=5):
    """安全执行系统命令并返回结果."""
    try:
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=input_data,
            timeout=timeout
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
    
    # 清空规则
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

    # 1. 重建 IPTables 规则，确保所有用户都有计数器
    setup_iptables_rules(users)

    # 2. 读取计数器
    success, output = safe_run_command(['iptables-save', '-c'])
    if not success:
        return

    traffic_data = {}
    
    # 3. 解析 IPTables 输出
    for line in output.split('\n'):
        if ('owner' in line) and ('ACCEPT' in line) and ('48303' in line):
            try:
                # 尝试解析字节计数
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
                if not success_user or not username:
                    continue

                if username not in traffic_data:
                    traffic_data[username] = {'in': 0, 'out': 0, 'uid': uid}
                
                traffic_data[username]['in' if direction == 'in' else 'out'] += total_bytes
                
            except Exception:
                continue

    # 4. 更新流量到 Flask API 并清零计数器
    for user in users:
        username = user['username']
        
        # 查找面板中的旧流量
        current_user_data = next((u for u in load_users() if u['username'] == username), None)
        current_used_gb = current_user_data.get('used_traffic_gb', 0.0) if current_user_data else 0.0
        
        in_bytes = traffic_data.get(username, {}).get('in', 0)
        out_bytes = traffic_data.get(username, {}).get('out', 0)
        total_transfer_bytes = in_bytes + out_bytes
        
        new_used_gb = current_used_gb + bytes_to_gb(total_transfer_bytes)
        rounded_gb = round(new_used_gb, 2)
        
        payload_json = json.dumps({
            "username": username,
            "used_traffic_gb": rounded_gb
        })
        
        # 调用 Flask API (使用 Curl)
        success_curl, api_response = safe_run_command([
            'curl', '-s', '-X', 'POST', API_URL, 
            '-H', 'Content-Type: application/json', 
            '-d', payload_json
        ])
        
        if success_curl and api_response:
            try:
                response_json = json.loads(api_response)
                if response_json.get('success'):
                    # 成功更新后清零计数器
                    uid = traffic_data.get(username, {}).get('uid')
                    if uid:
                        # 清零 INPUT 链计数器
                        safe_run_command([
                            'iptables', '-Z', IPTABLES_CHAIN_IN, 
                            '-p', 'tcp', '--dport', '48303', 
                            '-m', 'owner', '--uid-owner', uid
                        ])
                        # 清零 OUTPUT 链计数器
                        safe_run_command([
                            'iptables', '-Z', IPTABLES_CHAIN_OUT, 
                            '-p', 'tcp', '--sport', '48303', 
                            '-m', 'owner', '--uid-owner', uid
                        ])
            except json.JSONDecodeError:
                # print(f"API response failed to parse for {username}: {api_response}")
                pass


if __name__ == '__main__':
    read_and_report_traffic()
EOF

chmod +x /usr/local/bin/wss_traffic_sync.py

# 3. 创建定时任务 (Cron Job) 运行流量同步脚本
log_info "==== 设置 Cron 定时任务 (每 5 分钟同步一次流量) ===="

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

log_success "流量同步脚本已安装，并将每 5 分钟自动运行。"
log_info "----------------------------------"

# 4. 立即运行 IPTABLES 链设置
setup_iptables_chains


# ==================================
# 10. SSHD 安全配置 (保持不变)
# ==================================
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_SUFFIX=".bak.wss$(date +%s)"
# 检查哪个 SSH 服务名称有效 (sshd.service 或 ssh.service)
SSHD_SERVICE=$(systemctl list-units --full -all | grep -q "sshd.service" && echo "sshd" || echo "ssh")

log_info "==== 配置 SSHD 安全策略 ===="
cp -a "$SSHD_CONFIG" "${SSHD_CONFIG}${BACKUP_SUFFIX}"
log_info "SSHD 配置已备份到 ${SSHD_CONFIG}${BACKUP_SUFFIX}"

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
log_info "重新加载并重启 ssh 服务 ($SSHD_SERVICE)"
systemctl daemon-reload
systemctl restart "$SSHD_SERVICE"
log_success "SSHD 配置更新完成。"
log_info "----------------------------------"

# 清理敏感变量
unset PANEL_ROOT_PASS_RAW

echo "=================================================="
log_success "WSS 管理面板部署完成！ (V4.1 活跃 IP 管理)"
echo "=================================================="
echo ""
echo "🔥 WSS & Stunnel 基础设施已启动。"
echo "🌐 升级后的管理面板已在后台运行，支持 **活跃会话查询**。"
echo ""
echo "--- 访问信息 ---"
# 尝试获取服务器 IP
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "[Your Server IP]")
echo "Web 面板地址: http://$SERVER_IP:$PANEL_PORT"
echo "Web 面板用户名: root"
echo "Web 面板密码: [您刚才设置的密码]"
echo ""
echo "--- 端口状态检查 ---"
check_port "$WSS_HTTP_PORT"
check_port "$WSS_TLS_PORT"
check_port "$STUNNEL_PORT"
echo "内部转发端口 (SSH): 48303 (WSS/Stunnel/UDPGW 均连接到此端口)"
check_port "48303"
check_port "$UDPGW_PORT"

echo ""
echo "--- 故障排查/日志命令 ---"
echo "Web 面板状态: sudo systemctl status wss_panel -l"
echo "=================================================="
