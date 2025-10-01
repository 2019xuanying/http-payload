#!/usr/bin/env bash
set -euo pipefail

# ==================================
# 部署参数配置
# ==================================
WSS_USER_DEFAULT="wssuser"
SSHD_CONFIG="/etc/ssh/sshd_config"
MANAGER_PORT_DEFAULT="54321"

# 隧道转发目标端口 (根据用户反馈修正为 41816)
TUNNEL_TARGET_PORT="41816"

# 检查是否以 root 权限运行
if [ "$EUID" -ne 0 ]; then
    echo "请以 root 或 sudo 权限运行此脚本。"
    exit 1
fi

# ==================================
# 提示端口和密码
# ==================================
echo "--- 隧道端口设置 ---"
read -p "请输入 WSS HTTP 监听端口（默认80）: " WSS_HTTP_PORT
WSS_HTTP_PORT=${WSS_HTTP_PORT:-80}

read -p "请输入 WSS TLS 监听端口（默认443）: " WSS_TLS_PORT
WSS_TLS_PORT=${WSS_TLS_PORT:-443}

read -p "请输入 Stunnel4 端口（默认444）: " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-444}

read -p "请输入 UDPGW 端口（默认7300）: " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

echo ""
echo "--- Web 管理面板设置 ---"
read -p "请输入 Web 管理面板端口（默认54321）: " MANAGER_PORT
MANAGER_PORT=${MANAGER_PORT:-$MANAGER_PORT_DEFAULT}

echo "请设置 Web 管理面板的 root 密码（输入时隐藏）:"
while true; do
    read -s -p "密码: " ADMIN_PASS_RAW && echo
    read -s -p "请再次确认密码: " ADMIN_PASS_CONFIRM && echo
    if [ -z "$ADMIN_PASS_RAW" ]; then
        echo "密码不能为空。"
        continue
    fi
    if [ "$ADMIN_PASS_RAW" != "$ADMIN_PASS_CONFIRM" ]; then
        echo "两次输入不一致，请重试。"
        continue
    fi
    break
done
# 使用 sha256sum 加密存储密码哈希
ADMIN_PASS_HASH=$(echo -n "$ADMIN_PASS_RAW" | sha256sum | awk '{print $1}')
unset ADMIN_PASS_RAW ADMIN_PASS_CONFIRM # 清理敏感变量
SECRET_KEY_PART=$(echo -n "$ADMIN_PASS_HASH" | cut -c 1-24) # 提取部分哈希作为 secret key


# ==================================
# 依赖安装
# ==================================
echo "==== 更新系统并安装依赖 ===="
sudo apt update -y
# 确保安装了 coreutils, build-essential, git, python3-pip
sudo apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4 jq coreutils
sudo pip3 install Flask > /dev/null
echo "依赖安装完成"

# ==================================
# 函数定义
# ==================================

# WSS 隧道脚本安装 (使用修复后的 wss.py, 目标端口 41816)
install_wss_script() {
    echo "==== 安装 WSS 脚本 (/usr/local/bin/wss) ===="
    
    # 写入修复了动态转发漏洞的 WSS 核心脚本
    tee /usr/local/bin/wss > /dev/null <<EOF_WSS
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio, ssl, sys

# WSS/Stunnel 监听地址
LISTEN_ADDR = '0.0.0.0'

# 使用 sys.argv 获取命令行参数。如果未提供，则使用默认值
try:
    HTTP_PORT = int(sys.argv[1])
except (IndexError, ValueError):
    HTTP_PORT = 80        # 默认 HTTP 端口

try:
    TLS_PORT = int(sys.argv[2])
except (IndexError, ValueError):
    TLS_PORT = 443        # 默认 TLS 端口

# 核心安全修复：硬编码转发目标为本地 SSH 端口 41816，防止成为开放代理
DEFAULT_TARGET = ('127.0.0.1', $TUNNEL_TARGET_PORT) 
BUFFER_SIZE = 65536
TIMEOUT = 3600
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'

# HTTP/WebSocket 响应
FIRST_RESPONSE = b'HTTP/1.1 200 OK\\r\\nContent-Type: text/plain\\r\\nContent-Length: 2\\r\\n\\r\\nOK\\r\\n\\r\\n'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\\r\\nUpgrade: websocket\\r\\nConnection: Upgrade\\r\\n\\r\\n'
FORBIDDEN_RESPONSE = b'HTTP/1.1 403 Forbidden\\r\\nContent-Length: 0\\r\\n\\r\\n'

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    peer = writer.get_extra_info('peername')
    print(f"Connection from {peer} {'(TLS)' if tls else ''}")
    forwarding_started = False
    full_request = b''

    try:
        # --- 1. 握手循环 ---
        while not forwarding_started:
            
            # 使用 asyncio.wait_for 实现超时控制
            data = await asyncio.wait_for(reader.read(BUFFER_SIZE), timeout=TIMEOUT)
            if not data:
                break
            
            full_request += data
            
            header_end_index = full_request.find(b'\\r\\n\\r\\n')
            
            # 安全修复: 忽略所有 Host 或 X-Real-Host 头，硬编码转发到 DEFAULT_TARGET
            
            if header_end_index == -1:
                # 如果头部不完整，检查是否是普通的 HTTP Payload 分段
                headers_temp = full_request.decode(errors='ignore')
                
                if 'Upgrade: websocket' not in headers_temp and 'Connection: Upgrade' not in headers_temp:
                    # 如果头部不完整且不是 Upgrade 请求，返回 200 OK 响应，这是 Payload 模式的一部分
                    writer.write(FIRST_RESPONSE)
                    await writer.drain()
                    full_request = b'' # 清空，等待下一段数据
                    continue
                else:
                    # 正在等待完整的 WebSocket 握手头部
                    continue

            # 头部和数据分离
            headers = full_request[:header_end_index].decode(errors='ignore')
            data_to_forward = full_request[header_end_index + 4:] # 分离出 SSH 数据

            is_websocket_request = 'Upgrade: websocket' in headers or 'Connection: Upgrade' in headers or 'GET-RAY' in headers

            # 2. 转发触发
            if is_websocket_request:
                writer.write(SWITCH_RESPONSE)
                await writer.drain()
                forwarding_started = True
            else:
                # 如果是完整的 HTTP 请求但不是 WebSocket，返回 200 OK 并等待更多数据
                writer.write(FIRST_RESPONSE)
                await writer.drain()
                full_request = b'' # 清空，等待下一段数据
                continue
        
        # --- 退出握手循环 ---
        if not forwarding_started:
            # 如果循环提前退出（连接断开）
            return
            
        # 3. 连接目标服务器 (硬编码为本地 SSH 端口 $TUNNEL_TARGET_PORT)
        target = DEFAULT_TARGET
        target_reader, target_writer = await asyncio.open_connection(*target)

        # 4. 转发初始数据 (SSH 握手)
        if data_to_forward:
            target_writer.write(data_to_forward)
            await target_writer.drain()
            
        # 5. 转发后续数据流
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
        writer.close()
        # 注意: 如果 writer 已经关闭，wait_closed() 可能会报错，但通常可以接受
        try:
             await writer.wait_closed()
        except Exception:
             pass
        print(f"Closed {peer}")


async def main():
    # TLS server setup
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        ssl_ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    except FileNotFoundError:
        print(f"ERROR: TLS certificate not found at {CERT_FILE}. TLS server disabled.")
        # 如果 TLS 证书缺失，允许 HTTP 模式继续运行
        http_server = await asyncio.start_server(
            lambda r, w: handle_client(r, w, tls=False), LISTEN_ADDR, HTTP_PORT)

        print(f"Listening on {LISTEN_ADDR}:{HTTP_PORT} (HTTP payload)")
        
        async with http_server:
            await http_server.serve_forever()
        return
        
    except Exception as e:
        print(f"ERROR loading certificate: {e}")
        return

    # Start servers
    tls_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, tls=True), LISTEN_ADDR, TLS_PORT, ssl=ssl_ctx)
    http_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, tls=False), LISTEN_ADDR, HTTP_PORT)

    print(f"Listening on {LISTEN_ADDR}:{HTTP_PORT} (HTTP payload)")
    print(f"Listening on {LISTEN_ADDR}:{TLS_PORT} (TLS)")

    async with tls_server, http_server:
        await asyncio.gather(
            tls_server.serve_forever(),
            http_server.serve_forever())

if __name__ == '__main__':
    asyncio.run(main())
    
EOF_WSS

    sudo chmod +x /usr/local/bin/wss

    sudo tee /etc/systemd/system/wss.service > /dev/null <<EOF
[Unit]
Description=WSS Python Proxy
After=network.target

[Service]
Type=simple
# 确保端口参数正确传递
ExecStart=/usr/bin/python3 /usr/local/bin/wss $WSS_HTTP_PORT $WSS_TLS_PORT
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable wss
    sudo systemctl start wss
    echo "WSS 已启动，HTTP端口 $WSS_HTTP_PORT, TLS端口 $WSS_TLS_PORT"
}

# Stunnel4 / UDPGW 安装函数
install_stunnel_udpgw() {
    echo "==== 安装 Stunnel4 / UDPGW ===="
    # 确保文件夹存在
    sudo mkdir -p /etc/stunnel/certs

    # 仅在证书不存在时才生成，避免重复操作
    if [ ! -f "/etc/stunnel/certs/stunnel.key" ]; then
        echo "生成自签名 TLS 证书..."
        sudo openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout /etc/stunnel/certs/stunnel.key \
        -out /etc/stunnel/certs/stunnel.crt \
        -days 1095 \
        -subj "/CN=tunnel.example.com"
        sudo sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
        sudo chmod 644 /etc/stunnel/certs/*.crt
        sudo chmod 644 /etc/stunnel/certs/*.pem
    fi


    # Stunnel4 配置 - 核心修复：连接目标改为标准 SSH 端口 $TUNNEL_TARGET_PORT
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
connect = 127.0.0.1:$TUNNEL_TARGET_PORT
EOF
    
    # 启用并启动 stunnel4 服务
    sudo systemctl daemon-reload
    sudo systemctl enable stunnel4 || echo "Stunnel4 service not found, skipping enable."
    sudo systemctl restart stunnel4 || sudo systemctl start stunnel4 || echo "Failed to start Stunnel4."
    
    echo "Stunnel4 已启动，端口 $STUNNEL_PORT"

    # 安装 UDPGW
    if [ ! -d "/root/badvpn" ]; then 
        echo "克隆 badvpn 仓库..."
        git clone https://github.com/ambrop72/badvpn.git /root/badvpn
    fi
    mkdir -p /root/badvpn/badvpn-build
    pushd /root/badvpn/badvpn-build > /dev/null # 使用 pushd 安全地切换目录
    echo "编译 UDPGW..."
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 > /dev/null
    make -j$(nproc) > /dev/null

    sudo tee /etc/systemd/system/udpgw.service > /dev/null <<EOF
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
    sudo systemctl daemon-reload
    sudo systemctl enable udpgw
    sudo systemctl start udpgw
    echo "UDPGW 已启动，端口 $UDPGW_PORT"
    popd > /dev/null # 返回到之前的目录
}


# ==================================
# 执行部署
# ==================================

install_wss_script
install_stunnel_udpgw

# --- 2. 安装管理面板 ---
echo "==== 配置 Web 管理面板 ===="

# 写入配置 JSON 文件
sudo tee /etc/wss-manager-config.json > /dev/null <<EOCONF
{
    "ADMIN_PASSWORD_HASH": "$ADMIN_PASS_HASH",
    "MANAGER_PORT": $MANAGER_PORT,
    "WSS_USER_DEFAULT": "$WSS_USER_DEFAULT",
    "SECRET_KEY_PART": "$SECRET_KEY_PART"
}
EOCONF

# 生成修复了安全漏洞和 UI Bug 的 Python Web 面板
sudo tee /usr/local/bin/wss_manager.py > /dev/null <<'EOF_MANAGER'
# -*- coding: utf-8 -*-
import json
import subprocess
import os
import sys
import re # 导入正则模块
from flask import Flask, render_template_string, request, redirect, url_for, session, flash, get_flashed_messages
from datetime import datetime, timedelta
import hashlib
from jinja2 import Markup

# --- 配置参数 ---
CONFIG_FILE = "/etc/wss-manager-config.json"
SSHD_CONFIG = "/etc/ssh/sshd_config"

# 加载配置
try:
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
        MANAGER_PORT = config['MANAGER_PORT']
        ADMIN_PASSWORD_HASH = config.get('ADMIN_PASSWORD_HASH', None)
        SECRET_KEY_PART = config.get('SECRET_KEY_PART', os.urandom(24).hex())
except Exception as e:
    print(f"ERROR: Failed to load configuration from {CONFIG_FILE}. Details: {e}", file=sys.stderr)
    MANAGER_PORT = 54321
    ADMIN_PASSWORD_HASH = ""
    SECRET_KEY_PART = os.urandom(24).hex()

# 修复: 确保 SECRET_KEY 至少有 16 字节
app = Flask(__name__)
app.secret_key = SECRET_KEY_PART if len(SECRET_KEY_PART) >= 16 else os.urandom(24)


# --- 辅助函数 ---

def run_cmd(command):
    """运行 Bash 命令并返回其输出。"""
    try:
        # 使用 /bin/bash 确保命令能被正确执行
        result = subprocess.run(
            ['/bin/bash', '-c', command],
            capture_output=True,
            text=True,
            check=False,
            timeout=10
        )
        if result.returncode != 0:
            # 返回明确的错误信息，包含标准错误输出
            error_message = result.stderr.strip()
            # 过滤掉一些不重要的错误信息
            if 'non-unique name' in error_message:
                 return f"CMD_ERROR: {error_message}"
            return f"CMD_ERROR: {error_message}"
            
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "CMD_ERROR: Command timed out."
    except Exception as e:
        return f"CMD_ERROR: Execution error: {e}"


def check_auth():
    """检查用户是否登录"""
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('login'))
    return None

def hash_password(password):
    """使用 SHA256 对密码进行哈希处理"""
    return hashlib.sha256(password.encode()).hexdigest()

# --- 用户管理逻辑 ---

# 安全修复：严格验证用户名的格式，防止命令注入
def is_valid_username(username):
    # 允许字母、数字、下划线和连字符，长度 1 到 32，必须以字母或下划线开头
    return re.match(r'^[a-z_][a-z0-9_-]{0,31}$', username) is not None

def get_user_status():
    """获取所有隧道用户的状态、流量和在线信息"""
    user_status = []

    # 1. 获取所有 UID >= 1000 的用户列表 (非系统用户)
    try:
        user_list_cmd = "/usr/bin/awk -F: '($3 >= 1000) {print $1}' /etc/passwd"
        all_users = run_cmd(user_list_cmd).split('\n')
    except Exception as e:
        print(f"ERROR reading /etc/passwd: {e}")
        all_users = []
        
    # 2. 获取在线用户列表 (w 命令)
    online_users_output = run_cmd("w -h").split('\n')
    online_list = {line.split()[0]: True for line in online_users_output if line.strip()}
    
    # 3. 构建用户状态列表
    for username in all_users:
        if not username or not is_valid_username(username):
            continue
            
        # 4. 检查该用户是否在 sshd_config 中有配置块
        check_cmd = f"grep -q '# WSSUSER_BLOCK_START_{username}' {SSHD_CONFIG} && echo 'FOUND' || echo 'NOT_FOUND'"
        if run_cmd(check_cmd) != "FOUND":
            continue # 如果没有找到配置块，则跳过
            
        # 流量和时间数据是占位符
        user_data = {
            'username': username,
            'is_online': online_list.get(username, False),
            'last_login': 'Online' if online_list.get(username, False) else 'N/A',
            'data_limit': "50 GB (Placeholder)", 
            'data_used': "0 GB (Placeholder)", 
            'expiry_date': (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"), 
            'status': 'Active'
        }
        user_status.append(user_data)

    return user_status

def manage_user_ssh_config(username, action, password=None):
    """管理用户在 sshd_config 中的配置块"""
    
    # 安全检查：再次验证用户名
    if not is_valid_username(username):
        return f"CMD_ERROR: Invalid username format: {username}"
        
    # 1. 清理所有与该用户相关的旧配置
    cleanup_cmd = f"sudo sed -i '/# WSSUSER_BLOCK_START_{username}/,/# WSSUSER_BLOCK_END_{username}/d' {SSHD_CONFIG}"
    run_cmd(cleanup_cmd)
    
    if action == 'delete':
        # -r 选项用于删除用户主目录
        result = run_cmd(f"sudo userdel -r {username}")
        if 'CMD_ERROR' in result and 'not found' not in result:
             return f"CMD_ERROR: userdel failed: {result}"
        return f"User {username} deleted successfully."
        
    if action == 'create':
        # 2. 创建用户
        if 'No such user' in run_cmd(f"id {username} 2>&1"): # 检查用户是否存在
            run_cmd(f"sudo adduser --disabled-password --gecos 'WSS Tunnel User' {username}")
        
        # 3. 确保没有 sudo 权限
        run_cmd(f"sudo gpasswd -d {username} sudo 2>/dev/null || true")
            
        # 4. 设置/更新密码
        if password:
            password_safe = password.replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')
            run_cmd(f'echo "{username}:{password_safe}" | sudo chpasswd')
            
        # 5. 写入 SSHD 配置块
        config_block = f"""

# WSSUSER_BLOCK_START_{username} -- managed by wss_manager
# 允许 {username} 从本机登录 (WSS/Stunnel)
Match User {username} Address 127.0.0.1,::1
    PermitTTY no
    AllowTcpForwarding yes
    PasswordAuthentication yes
    AuthenticationMethods password,keyboard-interactive
    ChallengeResponseAuthentication yes
# 禁止 {username} 远程登录 (其他地址)
Match User {username} Address *,!127.0.0.1,!::1
    PermitTTY no
    AllowTcpForwarding no
    PasswordAuthentication no
# WSSUSER_BLOCK_END_{username}
"""      
        try:
            with open(SSHD_CONFIG, 'a') as f:
                f.write(config_block)
            
            # 6. 重启 SSHD
            sshd_service = "sshd"
            if 'ubuntu' in run_cmd('lsb_release -i 2>/dev/null || echo ""').lower():
                 sshd_service = "ssh" # Ubuntu 默认是 ssh.service
            
            run_cmd(f"sudo systemctl restart {sshd_service}")
            return f"User {username} created/updated and SSHD restarted successfully."
        except Exception as e:
            return f"CMD_ERROR: Failed to write SSHD config or restart SSHD: {e}"
            
    return "Invalid action."


# --- 路由定义 ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form['password']
        if hash_password(password) == ADMIN_PASSWORD_HASH:
            session['logged_in'] = True
            session['username'] = 'Admin'
            return redirect(url_for('index'))
        else:
            flash("Invalid password", "error")
            return redirect(url_for('login')) 
    return render_template_string(HTML_BASE_TEMPLATE, error=True)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/', methods=['GET', 'POST'])
def index():
    auth_check = check_auth()
    if auth_check:
        return auth_check

    # 处理用户管理动作
    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username')
        
        # 统一进行用户名验证
        if username and not is_valid_username(username):
             flash(f"用户名 **{username}** 格式无效。请使用字母、数字、下划线或连字符，且以字母或下划线开头。", "error")
             return redirect(url_for('index'))
             
        if action == 'create_user':
            password = request.form.get('password')
            if not username or not password:
                flash("用户名和密码是必需的。", "error")
                return redirect(url_for('index'))
            
            result = manage_user_ssh_config(username, 'create', password)
            if 'CMD_ERROR' in result:
                flash(f"创建失败: {result}", "error")
            else:
                flash(f"用户 **{username}** 创建/更新成功! SSHD已重启。", "success")

        elif action == 'delete_user':
            result = manage_user_ssh_config(username, 'delete')
            if 'CMD_ERROR' in result:
                flash(f"删除失败: {result}", "error")
            else:
                flash(f"用户 **{username}** 删除成功。", "success")
        
        return redirect(url_for('index'))

    user_data = get_user_status()
    return render_template_string(HTML_BASE_TEMPLATE, users=user_data, app_name='WSS Manager')


# --- Flask 模板 (内嵌 HTML) ---
@app.template_filter('insecure_html')
def insecure_html(s):
    return Markup(s)

HTML_BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ app_name if app_name is defined else 'WSS Manager' }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; background-color: #0d1117; color: #c9d1d9; }
        .card { background-color: #161b22; border: 1px solid #30363d; border-radius: 8px;}
        .btn-primary { background-color: #238636; color: white; transition: background-color 0.2s; border-radius: 6px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);}
        .btn-primary:hover { background-color: #2ea043; }
        .btn-danger { background-color: #da3633; color: white; transition: background-color 0.2s; border-radius: 6px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);}
        .btn-danger:hover { background-color: #f85149; }
        input[type="text"], input[type="password"] { background-color: #0d1117; border: 1px solid #30363d; color: #c9d1d9; border-radius: 6px; }
        .success { background-color: #23863622; border-left: 4px solid #238636; color: #56d364; }
        .error { background-color: #da363322; border-left: 4px solid #da3633; color: #f85149; }
        .online-dot { background-color: #56d364; }
        .offline-dot { background-color: #f85149; }
        /* 自定义模态框样式 */
        .modal {
            position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            background-color: rgba(0, 0, 0, 0.7);
            z-index: 50;
        }
    </style>
    <script>
        // 修复: 使用自定义模态框替代 alert() 和 confirm()
        function showDeleteModal(username) {
            document.getElementById('modal-username').textContent = username;
            document.getElementById('delete-username-input').value = username;
            document.getElementById('delete-modal').classList.remove('hidden');
        }

        function hideDeleteModal() {
            document.getElementById('delete-modal').classList.add('hidden');
        }
    </script>
</head>
<body>

<div class="container mx-auto p-4 md:p-8">
    <div class="flex justify-between items-center mb-6">
        <h1 class="text-3xl font-bold text-white">{{ app_name if app_name is defined else 'WSS Manager' }}</h1>
        {% if session.logged_in %}
        <a href="{{ url_for('logout') }}" class="text-sm text-gray-400 hover:text-white transition duration-150">退出 (Admin)</a>
        {% endif %}
    </div>

    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            <div class="mb-4">
                {% for category, message in messages %}
                    <div class="p-3 mb-2 rounded-md text-sm {{ 'error' if category == 'error' else 'success' }}">
                        {{ message|insecure_html }}
                    </div>
                {% endfor %}
            </div>
        {% endif %}
    {% endwith %}

    {% if error is defined %}
        <div class="flex items-center justify-center min-h-[calc(100vh-100px)]">
            <div class="card p-8 rounded-lg shadow-xl w-full max-w-md">
                <h2 class="text-2xl font-bold mb-6 text-center text-white">管理员登录</h2>
                <form method="POST">
                    <div class="mb-4">
                        <label for="password" class="block text-sm font-medium mb-1">密码</label>
                        <input type="password" name="password" id="password" required class="w-full p-3 rounded-md focus:outline-none focus:ring-2 focus:ring-[#238636]">
                    </div>
                    <button type="submit" class="btn-primary w-full p-3 rounded-md font-semibold">登录</button>
                </form>
            </div>
        </div>
        {% endif %}

    {% if users is defined %}
        <h2 class="text-xl font-semibold mb-3">隧道用户列表 (UID >= 1000)</h2>
        <div class="overflow-x-auto card rounded-lg shadow-lg mb-8">
            <table class="min-w-full divide-y divide-[#30363d]">
                <thead class="bg-[#161b22]">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">状态</th>
                        <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">用户名</th>
                        <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">最后登录/时长</th>
                        <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">流量限制</th>
                        <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">流量使用</th>
                        <th class="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider">操作</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-[#30363d]">
                    {% for user in users %}
                    <tr class="hover:bg-[#21262d] transition duration-150">
                        <td class="px-6 py-4 whitespace-nowrap">
                            <span class="h-3 w-3 rounded-full inline-block mr-2 {{ 'online-dot' if user.is_online else 'offline-dot' }}"></span>
                            {{ '在线' if user.is_online else '离线' }}
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap font-medium">{{ user.username }}</td>
                        <td class="px-6 py-4 whitespace-nowrap">{{ user.last_login }}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-green-400">{{ user.data_limit }}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-red-400">{{ user.data_used }}</td>
                        <td class="px-6 py-4 whitespace-nowrap">
                            <button onclick="showDeleteModal('{{ user.username }}')" class="btn-danger p-2 text-xs rounded-md">删除</button>
                        </td>
                    </tr>
                    {% else %}
                    <tr>
                        <td colspan="6" class="px-6 py-4 text-center text-gray-500">
                            当前没有隧道用户。请在下方创建。
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="mt-8 card p-6 rounded-lg">
            <h2 class="text-xl font-semibold mb-4">添加/更新隧道用户</h2>
            <form method="POST" class="space-y-4">
                <input type="hidden" name="action" value="create_user">
                <div>
                    <label for="new_username" class="block text-sm font-medium mb-1">用户名 (只能包含字母、数字、下划线和连字符)</label>
                    <input type="text" name="username" id="new_username" required class="w-full p-2 rounded-md focus:outline-none focus:ring-2 focus:ring-[#238636]" pattern="^[a-z_][a-z0-9_-]{0,31}$" title="用户名必须以字母或下划线开头，不能包含特殊字符或大写字母。" placeholder="用户名 (例如: tunnel01)">
                </div>
                <div>
                    <label for="new_password" class="block text-sm font-medium mb-1">密码</label>
                    <input type="password" name="password" id="new_password" required class="w-full p-2 rounded-md focus:outline-none focus:ring-2 focus:ring-[#238636]">
                </div>
                <button type="submit" class="btn-primary p-3 rounded-md font-semibold">创建用户并配置SSH</button>
            </form>
        </div>
        {% endif %}
    
    <!-- 删除确认模态框 (替代 window.confirm) -->
    <div id="delete-modal" class="modal hidden flex items-center justify-center">
        <div class="card p-6 w-full max-w-sm">
            <h3 class="text-lg font-semibold mb-4 text-white">确认删除用户</h3>
            <p class="text-gray-400 mb-6">您确定要删除用户 <span id="modal-username" class="font-bold text-red-400"></span> 吗？这将永久删除其系统账户和所有配置。</p>
            <div class="flex justify-end space-x-3">
                <button onclick="hideDeleteModal()" type="button" class="px-4 py-2 bg-gray-600 rounded-md hover:bg-gray-700 transition">取消</button>
                <form method="POST" class="inline">
                    <input type="hidden" name="action" value="delete_user">
                    <input type="hidden" name="username" id="delete-username-input">
                    <button type="submit" class="btn-danger px-4 py-2 rounded-md font-semibold">确认删除</button>
                </form>
            </div>
        </div>
    </div>
    <!-- 模态框结束 -->

</div>
</body>
</html>
"""

if __name__ == '__main__':
    print(f"Starting WSS Manager on port {MANAGER_PORT}...")
    try:
        app.run(host='0.0.0.0', port=MANAGER_PORT, debug=False)
    except Exception as e:
        print(f"FATAL ERROR: Failed to start Flask app: {e}", file=sys.stderr)
        sys.exit(1)

EOF_MANAGER

# 创建管理面板 systemd 服务
sudo tee /etc/systemd/system/wss-manager.service > /dev/null <<EOF
[Unit]
Description=WSS Manager Web Panel
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/wss_manager.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable wss-manager
sudo systemctl start wss-manager
echo "Web 管理面板已启动，端口: $MANAGER_PORT"

# ==================================
# 最终输出
# ==================================
echo ""
echo "=================================="
echo "✅ 部署完成！(目标端口已修正为 $TUNNEL_TARGET_PORT)"
echo "----------------------------------"
echo "🌐 Web 管理面板访问地址 (Root 登录):"
echo "    http://<您的服务器IP>:$MANAGER_PORT"
echo "    请使用您在脚本开始时设置的面板密码登录。"
echo ""
echo "⚠️ **已应用的修复和优化:**"
echo "1. **目标端口修正:** WSS 和 Stunnel 代理现已正确转发到本地 SSH 端口 **127.0.0.1:$TUNNEL_TARGET_PORT**。"
echo "2. **安全修复:** 移除了 WSS 代理中的动态转发（避免开放代理漏洞），并修复了管理面板中的命令注入漏洞。"
echo "3. **UI 优化:** 替换了 `window.confirm()` 为自定义删除确认模态框。"
echo "----------------------------------"
echo "🔧 隧道基础配置 (转发至 127.0.0.1:$TUNNEL_TARGET_PORT):"
echo "    WSS HTTP Port: $WSS_HTTP_PORT"
echo "    WSS TLS Port: $WSS_TLS_PORT"
echo "    Stunnel Port: $STUNNEL_PORT"
echo "    UDPGW Port: $UDPGW_PORT"
echo "=================================="
