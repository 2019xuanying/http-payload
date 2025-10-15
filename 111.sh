#!/usr/bin/env bash

set -eu

# ==========================================================
# WSS 隧道与用户管理面板一键部署脚本 (终极功能升级版 - Tailwind CSS)
# ----------------------------------------------------------
# Panel 核心功能: 实时监控、服务控制、日志刷新
# 用户管控: 账户有效期 (chage), 带宽限制 (tc + iptables), 流量配额 (iptables)
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

# === 内部转发端口提示 ===
read -p "请输入 WSS/Stunnel 内部 SSH 转发端口 (默认48303, 此为 WSS/Stunnel 连接到 SSH 的端口): " INTERNAL_FORWARD_PORT
INTERNAL_FORWARD_PORT=${INTERNAL_FORWARD_PORT:-48303}
# ==============================

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
# 确保安装了 `iproute2` 包 (tc) 和 `iptables`
apt update -y
apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4 iproute2 iptables
# 额外安装 flask, jinja2, uvloop
pip3 install flask jinja2 uvloop
echo "依赖安装完成"
echo "----------------------------------"


# =============================
# WSS 核心代理脚本
# =============================
echo "==== 安装 WSS 核心代理脚本 (/usr/local/bin/wss) ===="
# 使用 <<'EOF' 避免 Bash 预解析 $INTERNAL_FORWARD_PORT
tee /usr/local/bin/wss > /dev/null <<EOF
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio, ssl, sys
import uvloop # 导入 uvloop, 用于高性能 event loop

LISTEN_ADDR = '0.0.0.0'

try:
    HTTP_PORT = int(sys.argv[1])
except (IndexError, ValueError):
    HTTP_PORT = 80
try:
    TLS_PORT = int(sys.argv[2])
except (IndexError, ValueError):
    TLS_PORT = 443

# 使用用户指定的内部转发端口
DEFAULT_TARGET = ('127.0.0.1', $INTERNAL_FORWARD_PORT)
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
        # 使用 uvloop 作为 event loop 实现，提供性能加速
        uvloop.install() 
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
systemctl start wss
echo "WSS 已启动，HTTP端口 $WSS_HTTP_PORT, TLS端口 $WSS_TLS_PORT"
echo "----------------------------------"


# =============================
# 安装 Stunnel4 并生成证书
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
connect = 127.0.0.1:$INTERNAL_FORWARD_PORT
EOF

systemctl enable stunnel4
systemctl start stunnel4 # 启动服务以便后续检查
echo "Stunnel4 安装完成，端口 $STUNNEL_PORT"
echo "----------------------------------"


# =============================
# 安装 UDPGW
# =============================
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
systemctl start udpgw # 启动服务以便后续检查
echo "UDPGW 已安装并启动，端口: $UDPGW_PORT"
echo "----------------------------------"

# =============================
# Traffic Control 基础配置 (NEW)
# =============================
# 清除旧的 tc 规则，确保环境干净
echo "==== 配置 Traffic Control (tc) 基础环境 ===="
IP_DEV=$(ip route | grep default | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1)

if [ -z "$IP_DEV" ]; then
    echo "警告: 无法找到主网络接口，带宽限制功能可能无效。"
else
    # 销毁所有现有的 qdisc
    tc qdisc del dev "$IP_DEV" root || true
    # 创建 HTB 根 qdisc
    tc qdisc add dev "$IP_DEV" root handle 1: htb default 10
    # 默认类别 (无限制)
    tc class add dev "$IP_DEV" parent 1: classid 1:10 htb rate 1000mbit ceil 1000mbit
    echo "Traffic Control (tc) 已在 $IP_DEV 上初始化。"
fi
echo "----------------------------------"


# =============================
# 安装 WSS 用户管理面板 (基于 Flask)
# =============================
echo "==== 部署 WSS 用户管理面板 (Python/Flask) ===="
PANEL_DIR="/etc/wss-panel"
USER_DB="$PANEL_DIR/users.json"
mkdir -p "$PANEL_DIR"

# 创建或初始化用户数据库
if [ ! -f "$USER_DB" ]; then
    echo "[]" > "$USER_DB"
fi

# 嵌入 Python 面板代码 (关键：所有 $ 都被正确转义或在 Python 内部处理)
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
from datetime import date, timedelta, datetime

# --- 配置 ---
USER_DB_PATH = "$USER_DB"
ROOT_USERNAME = "root"
ROOT_PASSWORD_HASH = "$PANEL_ROOT_PASS_HASH"
FLASK_SECRET_KEY = os.urandom(24).hex()
SSHD_CONFIG = "/etc/ssh/sshd_config"
GIGA_BYTE = 1024 * 1024 * 1024 # 1 GB in bytes

# 面板和端口配置 (用于模板)
PANEL_PORT = "$PANEL_PORT"
WSS_HTTP_PORT = "$WSS_HTTP_PORT"
WSS_TLS_PORT = "$WSS_TLS_PORT"
STUNNEL_PORT = "$STUNNEL_PORT"
UDPGW_PORT = "$UDPGW_PORT"
INTERNAL_FORWARD_PORT = "$INTERNAL_FORWARD_PORT" 

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# --- 系统工具函数 ---

def safe_run_command(command, input=None):
    """安全执行系统命令并返回结果."""
    try:
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=input, # 接受 bytes 输入
            timeout=5 # 增加超时保护
        )
        return True, result.stdout.decode('utf-8', errors='ignore').strip()
    except subprocess.CalledProcessError as e:
        return False, e.stderr.decode('utf-8', errors='ignore').strip()
    except FileNotFoundError:
        return False, "Command not found."
    except subprocess.TimeoutExpired:
        return False, "Command timed out."
        

# ===============================================
# TC (Bandwidth Limit) and Iptables (Quota/Usage) Helpers
# ===============================================

def apply_rate_limit(uid, rate_kbps):
    """Applies or clears download rate limit (KB/s) for a given Linux user UID using tc and iptables."""
    
    # NEW: Robustly determine primary network device using pure Python/subprocess logic
    success, output = safe_run_command(['ip', 'route', 'show', 'default'])
    dev = ''
    if success and output:
        parts = output.split()
        try:
            # Find the interface name after the 'dev' keyword
            dev_index = parts.index('dev') + 1
            dev = parts[dev_index]
        except (ValueError, IndexError):
            pass
    
    if not dev:
        print("Error: Could not determine primary network device for tc. Bandwidth limiting disabled.")
        return False, "无法找到网络接口"
    
    dev = dev.strip()
    tc_handle = f"1:{int(uid)}" # Use HTB class ID 1:UID
    mark = int(uid) # Use UID as the firewall mark

    # IPTables command parts to delete the specific rule
    # Added --wait option for stability
    ipt_del_cmd = ['iptables', '-t', 'mangle', '-D', 'POSTROUTING', 
                   '-m', 'owner', '--uid-owner', str(uid), 
                   '-j', 'MARK', '--set-mark', str(mark),
                   '--wait']

    try:
        rate = int(rate_kbps)
        
        # --- 1. CLEANUP (Critical for reliability) ---
        safe_run_command(ipt_del_cmd)
        safe_run_command(['tc', 'filter', 'del', 'dev', dev, 'parent', '1:', 'protocol', 'ip', 'prio', '100', 'handle', str(mark)]) 
        safe_run_command(['tc', 'class', 'del', 'dev', dev, 'parent', '1:', 'classid', tc_handle])


        if rate > 0:
            rate_mbps = (rate * 8) / 1024.0
            rate_str = "{:.2f}mbit".format(rate_mbps)
            
            # --- 2. ADD TC CLASS (Bandwidth limit container) ---
            tc_class_cmd = ['tc', 'class', 'add', 'dev', dev, 'parent', '1:', 'classid', tc_handle, 'htb', 'rate', rate_str, 'ceil', rate_str]
            
            success_class, output_class = safe_run_command(tc_class_cmd)
            if not success_class:
                return False, f"TC Class error: {output_class}"

            # --- 3. ADD IPTABLES RULE (Mark packets from this UID) ---
            # Added --wait option for stability
            iptables_add_cmd = ['iptables', '-t', 'mangle', '-A', 'POSTROUTING', 
                                '-m', 'owner', '--uid-owner', str(uid), 
                                '-j', 'MARK', '--set-mark', str(mark),
                                '--wait']

            success_ipt, output_ipt = safe_run_command(iptables_add_cmd)
            if not success_ipt:
                safe_run_command(['tc', 'class', 'del', 'dev', dev, 'parent', '1:', 'classid', tc_handle])
                return False, f"IPTables error: {output_ipt}"

            # --- 4. ADD TC FILTER (Match firewall mark) ---
            tc_filter_cmd = ['tc', 'filter', 'add', 'dev', dev, 'parent', '1:', 'protocol', 'ip', 
                             'prio', '100', 'handle', str(mark), 'fw', 'flowid', tc_handle]
            
            success_filter, output_filter = safe_run_command(tc_filter_cmd)
            if not success_filter:
                safe_run_command(['tc', 'class', 'del', 'dev', dev, 'parent', '1:', 'classid', tc_handle])
                safe_run_command(ipt_del_cmd)
                return False, f"TC Filter error: {output_filter}"
                
            return True, f"已限制速度到 {rate_mbps:.2f} Mbit/s (~{rate_kbps} KB/s)"
        
        else:
            return True, "已清除速度限制"
            
    except Exception as e:
        return False, f"TC command execution failed: {e}"

def manage_quota_iptables_rule(username, uid, action='add'):
    """Adds/Deletes the iptables rule used for counting traffic for a user."""
    comment = f"WSS_QUOTA_{username}"
    
    # Rule to be matched/counted in the OUTPUT chain (filter table)
    command = ['iptables', '-t', 'filter', f'-{action.upper()}', 'OUTPUT', 
               '-m', 'owner', '--uid-owner', str(uid), 
               '-m', 'comment', '--comment', comment, 
               '-j', 'ACCEPT', '--wait']
    
    safe_run_command(command)

def get_user_current_usage_bytes(username, uid):
    """Reads the byte counter from the iptables rule associated with the user."""
    comment = f"WSS_QUOTA_{username}"
    
    command = ['iptables', '-t', 'filter', '-nvxL', 'OUTPUT']
    success, output = safe_run_command(command)
    
    if not success: return 0
    
    # Regex to find the line containing the comment and extract the byte count (2nd field)
    pattern = re.compile(r'^\s*\d+\s+(\d+).*COMMENT\s+--\s+.*' + re.escape(comment))
    
    for line in output.split('\n'):
        match = pattern.search(line)
        if match:
            try:
                # The byte count is the second column in -nvxL output
                return int(line.split()[1])
            except (IndexError, ValueError):
                return 0 # Malformed line
    return 0

def reset_iptables_counters(username):
    """Resets the byte counter for a specific user's iptables rule."""
    comment = f"WSS_QUOTA_{username}"
    command = ['iptables', '-t', 'filter', '-Z', 'OUTPUT', '-m', 'comment', '--comment', comment, '--wait']
    safe_run_command(command)

# ===============================================

# --- Status and User Management Functions ---

def get_cpu_usage():
    """Calculates CPU usage percentage using pure Python/proc/stat (avoids Bash errors)."""
    try:
        def get_cpu_times():
            with open('/proc/stat', 'r') as f:
                line = f.readline().split()
                # user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice
                total = sum(int(x) for x in line[1:])
                idle = int(line[4])
                return total, idle

        total1, idle1 = get_cpu_times()
        time.sleep(0.1) # Wait briefly
        total2, idle2 = get_cpu_times()

        total_diff = total2 - total1
        idle_diff = idle2 - idle1
        
        if total_diff == 0:
            return 0.0
            
        cpu_usage = 100.0 * (total_diff - idle_diff) / total_diff
        return round(cpu_usage, 1)

    except Exception:
        return "N/A"

def get_memory_usage():
    """Calculates memory usage percentage and total/used."""
    try:
        success, output = safe_run_command(['free', '-m'])
        if success:
            lines = output.split('\n')
            mem_line = lines[1].split()
            total = int(mem_line[1])
            used = int(mem_line[2])
            
            if total > 0:
                usage = (used / total) * 100
                return {
                    "usage": round(usage, 1),
                    "total_mb": total,
                    "mem_used_mb": used
                }
        return {"usage": "N/A", "total_mb": "N/A", "mem_used_mb": "N/A"}
    except Exception:
        return {"usage": "N/A", "total_mb": "N/A", "mem_used_mb": "N/A"}


def get_disk_usage():
    """Gets root filesystem disk usage."""
    try:
        success, output = safe_run_command(['df', '-h', '/'])
        if success:
            lines = output.split('\n')
            disk_line = lines[-1].split()
            if len(disk_line) >= 5:
                usage_str = disk_line[4].replace('%', '')
                return {"usage": int(usage_str)}
        return {"usage": "N/A"}
    except Exception:
        return {"usage": "N/A"}

def get_service_status_detail(service_name):
    """Returns service status and a descriptive label/color."""
    success, output = safe_run_command(['systemctl', 'is-active', service_name])
    status = output.strip()
    
    if status == 'active':
        return "active", "运行中", "bg-green-500" # Tailwind class
    elif status == 'inactive' or status == 'activating' or status == 'deactivating':
        failed_check = safe_run_command(['systemctl', 'is-failed', service_name])
        if failed_check[0] and failed_check[1] == 'failed':
            return "failed", "失败", "bg-red-500" # Tailwind class
        return "inactive", "已停止", "bg-yellow-500" # Tailwind class
    else:
        return status.capitalize() or "unknown", "未知", "bg-gray-500" # Tailwind class

def get_port_status_detail(port):
    """Checks if a port is listening using 'ss'."""
    port_str = str(port)
    success, output = safe_run_command(['ss', '-tuln'])
    
    if success and (f':{port_str}' in output or f' {port_str}' in output):
        return "监听中", "text-green-500" # Tailwind class
    return "未监听", "text-red-500" # Tailwind class

def get_logs_data(lines=50):
    """Retrieves generic system logs (latest on top)."""
    # Use journalctl to get the last hour's logs for all services, newest first
    success, output = safe_run_command(['journalctl', '-r', f'-n {lines}', '--since', '1 hour ago', '--no-pager', '--utc'])
    return output if success else f"错误: 无法获取系统日志. {output}"


def get_user_expiration_status(username):
    """Checks account status based on Linux 'chage -l' and current date."""
    try:
        success, output = safe_run_command(['bash', '-c', f'LC_ALL=C chage -l {username}'])
        if not success:
            return "inactive", "N/A (系统用户不存在)"

        lines = output.split('\n')
        expiry_info = "N/A"
        
        for line in lines:
            if "Account expires" in line:
                expiry_info = line.split(':')[-1].strip()
                break
        
        passwd_success, passwd_output = safe_run_command(['passwd', '-S', username])
        is_locked = passwd_success and 'L' in passwd_output # 'L' indicates locked account

        if expiry_info.lower() in ("never", "never expires"):
            return "active", "永不"
        
        try:
            expiry_date = datetime.strptime(expiry_info, '%b %d, %Y').date()
            today = date.today()
            expiry_date_str = expiry_date.strftime("%Y-%m-%d")

            if expiry_date <= today:
                if not is_locked:
                    safe_run_command(['usermod', '-L', username]) # Lock account
                return "expired", expiry_date_str
            else:
                return "active", expiry_date_str

        except ValueError:
            if is_locked:
                return "expired", "N/A (已锁定)"
            return "active", "N/A (日期格式错误)"

    except Exception as e:
        print(f"Error checking chage for {username}: {e}")
        return "error", "N/A (检查失败)"


def get_user_uid(username):
    """Retrieves the numeric UID of a Linux user."""
    success, output = safe_run_command(['id', '-u', username])
    return int(output) if success and output.isdigit() else None


def load_users():
    """从 JSON 文件加载用户列表并更新状态和用量."""
    if not os.path.exists(USER_DB_PATH):
        return []
    try:
        with open(USER_DB_PATH, 'r') as f:
            users = json.load(f)
            
        updated_users = []
        for user in users:
            username = user['username']
            uid = get_user_uid(username)
            user['uid'] = uid
            
            # --- 1. Refresh Status/Expiry ---
            status, expiry_date_str = get_user_expiration_status(username)
            user['status'] = status
            user['expiration_date'] = expiry_date_str
            
            # --- 2. Refresh Quota/Usage/Rate ---
            user['quota_gb'] = user.get('quota_gb', 0) # Default to 0 GB limit
            user['rate_limit_kbps'] = user.get('rate_limit_kbps', '0')
            user['created_at'] = user.get('created_at', time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            
            current_bytes_used = get_user_current_usage_bytes(username, uid)
            user['usage_bytes'] = current_bytes_used
            user['usage_gb'] = round(current_bytes_used / GIGA_BYTE, 2)
            
            quota_limit_bytes = user['quota_gb'] * GIGA_BYTE
            
            if uid:
                # Ensure iptables counting rule is present if user is active
                if status == 'active':
                    manage_quota_iptables_rule(username, uid, 'add')
                else:
                    manage_quota_iptables_rule(username, uid, 'delete')
                    
                # Enforcement: Check Quota
                if user['quota_gb'] > 0 and current_bytes_used >= quota_limit_bytes and status == 'active':
                    safe_run_command(['usermod', '-L', username]) # Lock account
                    user['status'] = 'exceeded'
                    print(f"User {username} locked due to quota ({user['usage_gb']} GB / {user['quota_gb']} GB).")
                
                # Ensure TC Rate Limit is applied if needed
                if status == 'active' and int(user['rate_limit_kbps']) > 0:
                    apply_rate_limit(uid, user['rate_limit_kbps'])
                elif status != 'active' or int(user['rate_limit_kbps']) == 0:
                    # Clean up rate limit if account is inactive or limit is 0
                    apply_rate_limit(uid, 0)


            updated_users.append(user)
            
        save_users(updated_users)
        return updated_users
        
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
    """按用户名查找用户."""
    users = load_users()
    for user in users:
        if user['username'] == username:
            return user
    return None

# --- 认证装饰器 ---

def login_required(f):
    """检查用户是否已登录."""
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# --- HTML 模板和渲染 ---

# 仪表盘 HTML (内嵌) - Tailwind CSS 风格 (匹配第二张图片)
_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS Panel - 仪表盘</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* Custom status colors for Jinja/JS use */
        .active { color: #10b981; } /* green-600 */
        .expired, .exceeded { color: #ef4444; } /* red-600 */
        .modal { position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.4); display: none; justify-content: center; align-items: center; }
        /* Log display to reverse order for newest-on-top, relying on server-side reversed log data */
        .log-pre { display: flex; flex-direction: column-reverse; max-height: 250px; overflow-y: scroll; white-space: pre-wrap; }
        /* Smaller rounded indicator dots */
        .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 4px; }
        .grid-custom { grid-template-columns: 1fr 1fr 1fr 1fr 1fr 1fr; }
        @media (max-width: 1024px) {
            .grid-custom { grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); }
        }
    </style>
</head>
<body class="bg-gray-100 min-h-screen">
    <div class="bg-gray-800 text-white p-4 shadow-lg flex justify-between items-center sticky top-0 z-50">
        <h1 class="text-2xl font-semibold">WSS Panel - 仪表盘</h1>
        <button class="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-lg transition" onclick="logout()">退出登录 (root)</button>
    </div>

    <div class="container mx-auto mt-6 px-4">
        <div id="status-message" class="p-4 rounded-lg font-bold mb-6" style="display:none;"></div>
        
        <!-- 实时系统状态 (顶部卡片区) -->
        <div class="mb-6">
            <h3 class="text-xl font-semibold text-gray-700 mb-3">实时系统状态</h3>
            <div class="grid grid-cols-2 md:grid-cols-6 gap-4">
                
                <!-- CPU -->
                <div class="bg-white p-4 rounded-xl shadow-md border-b-4 border-blue-500 text-center">
                    <h4 class="text-sm text-gray-500 font-medium">CPU 使用率</h4>
                    <p id="cpu-usage" class="text-2xl font-extrabold text-blue-700 mt-1">--</p>
                </div>

                <!-- 内存 -->
                <div class="bg-white p-4 rounded-xl shadow-md border-b-4 border-blue-500 text-center">
                    <h4 class="text-sm text-gray-500 font-medium">内存 (用量/总量)</h4>
                    <p id="mem-usage" class="text-xl font-extrabold text-blue-700 mt-1">--</p>
                </div>
                
                <!-- 硬盘 -->
                <div class="bg-white p-4 rounded-xl shadow-md border-b-4 border-blue-500 text-center">
                    <h4 class="text-sm text-gray-500 font-medium">磁盘使用率</h4>
                    <p id="disk-usage" class="text-2xl font-extrabold text-blue-700 mt-1">--</p>
                </div>

                <!-- WSS Proxy 状态 -->
                <div class="bg-white p-4 rounded-xl shadow-md border-b-4 border-gray-400 text-center">
                    <h4 class="text-sm text-gray-500 font-medium">WSS Proxy 状态</h4>
                    <p class="text-base font-bold text-gray-800 mt-1 flex items-center justify-center">
                        <span id="wss-status-indicator" class="status-dot"></span><span id="wss-status-label">--</span>
                    </p>
                </div>

                <!-- Stunnel4 状态 -->
                <div class="bg-white p-4 rounded-xl shadow-md border-b-4 border-gray-400 text-center">
                    <h4 class="text-sm text-gray-500 font-medium">Stunnel4 状态</h4>
                    <p class="text-base font-bold text-gray-800 mt-1 flex items-center justify-center">
                        <span id="stunnel4-status-indicator" class="status-dot"></span><span id="stunnel4-status-label">--</span>
                    </p>
                </div>
                
                <!-- UDPGW 状态 -->
                <div class="bg-white p-4 rounded-xl shadow-md border-b-4 border-gray-400 text-center">
                    <h4 class="text-sm text-gray-500 font-medium">UDPGW 状态</h4>
                    <p class="text-base font-bold text-gray-800 mt-1 flex items-center justify-center">
                        <span id="udpgw-status-indicator" class="status-dot"></span><span id="udpgw-status-label">--</span>
                    </p>
                </div>
            </div>
        </div>

        <!-- 端口状态, 核心操作, 日志区 -->
        <div class="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
            <!-- Port Status and Core Ops (Left Column) -->
            <div class="lg:col-span-1 bg-white p-6 rounded-xl shadow-md">
                <h3 class="text-xl font-semibold text-gray-700 mb-4">服务端口与操作</h3>
                
                <div class="flex flex-col space-y-4">
                    <!-- Port List -->
                    <div class="rounded-lg border border-gray-200 p-4">
                        <h4 class="font-medium text-gray-600 mb-2 border-b pb-1">端口监听状态 (LISTEN)</h4>
                        <table class="min-w-full text-sm">
                            <tbody id="service-port-tbody">
                                <!-- Dynamically populated by JS -->
                            </tbody>
                        </table>
                    </div>

                    <!-- Core Operations -->
                    <div class="rounded-lg bg-red-50 p-4 shadow-inner">
                        <h4 class="font-medium text-red-600 mb-3 border-b border-red-200 pb-1">核心服务操作</h4>
                        <div class="space-y-2">
                            <button class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded-lg transition" onclick="openRestartModal('wss', 'WSS Proxy (HTTP/TLS)')">重启 WSS Proxy ({{ wss_http_port }}/{{ wss_tls_port }})</button>
                            <button class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded-lg transition" onclick="openRestartModal('stunnel4', 'Stunnel4 (TLS Tunnel)')">重启 Stunnel4 ({{ stunnel_port }})</button>
                            <button class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded-lg transition" onclick="openRestartModal('udpgw', 'UDPGW')">重启 UDPGW ({{ udpgw_port }})</button>
                            <button class="w-full bg-red-600 hover:bg-red-700 text-white font-bold py-2 rounded-lg transition" onclick="openRestartModal('wss_panel', 'Web Panel')">重启 Web Panel (慎重操作)</button>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- 实时日志区 (Right Column) -->
            <div class="lg:col-span-1 xl:col-span-2 bg-white p-6 rounded-xl shadow-md">
                <h3 class="text-xl font-semibold text-gray-700 mb-4">实时系统日志 (最新50条, 每10s刷新)</h3>
                <div class="bg-gray-800 p-3 rounded-lg overflow-hidden">
                    <pre id="log-pre-content" class="text-gray-200 text-xs p-1 log-pre">正在加载日志...</pre>
                </div>
            </div>
        </div>


        <!-- 用户管理 - 新增用户 -->
        <div class="bg-white p-6 rounded-xl shadow-md mb-6 mt-6">
            <h3 class="text-xl font-semibold text-gray-700 mb-4">新增 WSS 用户 (SSH 账户)</h3>
            <form id="add-user-form" class="grid grid-cols-2 md:grid-cols-6 gap-4 items-end">
                <input type="text" id="new-username" placeholder="用户名" pattern="[a-z0-9_]{3,16}" title="用户名只能包含小写字母、数字和下划线，长度3-16位" required class="col-span-1 p-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500" value="">
                <input type="password" id="new-password" placeholder="密码" required class="col-span-1 p-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500" value="">
                <input type="number" id="expiration-days" value="365" min="1" placeholder="有效期 (天)" required class="col-span-1 p-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500">
                <input type="number" id="quota-gb" value="0" min="0" placeholder="流量配额 (GB, 0=不限制)" required class="col-span-1 p-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500">
                <input type="number" id="rate-kbps" value="0" min="0" placeholder="最大带宽 (KB/s, 0=不限制)" required class="col-span-1 p-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500">
                <button type="submit" class="col-span-2 md:col-span-1 bg-green-500 text-white font-bold py-2 rounded-lg hover:bg-green-600 transition">创建用户</button>
            </form>
        </div>

        <!-- 用户管理 - 列表 -->
        <div class="bg-white p-6 rounded-xl shadow-md mb-6">
            <h3 class="text-xl font-semibold text-gray-700 mb-4">用户列表</h3>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">用户名</th>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">状态</th>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">到期日期</th>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">用量/配额 (GB)</th>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">带宽 (KB/s)</th>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">操作</th>
                        </tr>
                    </thead>
                    <tbody id="user-list-tbody" class="bg-white divide-y divide-gray-200">
                        {% for user in users %}
                        <tr id="row-{{ user.username }}" class="hover:bg-gray-50">
                            <td class="px-3 py-3 whitespace-nowrap text-sm text-gray-900">{{ user.username }}</td>
                            <td class="px-3 py-3 whitespace-nowrap text-sm font-bold"><span class="{{ user.status }}">{{ user.status.upper() }}</span></td>
                            <td class="px-3 py-3 whitespace-nowrap text-sm text-gray-500">{{ user.expiration_date }}</td>
                            <td class="px-3 py-3 whitespace-nowrap text-sm text-gray-500">{{ user.usage_gb }} / {{ user.quota_gb }} GB</td>
                            <td class="px-3 py-3 whitespace-nowrap text-sm text-gray-500">{{ user.rate_limit_kbps }} KB/s</td>
                            <td class="px-3 py-3 whitespace-nowrap text-sm font-medium space-x-1">
                                <button class="bg-blue-500 hover:bg-blue-600 text-white py-1 px-2 rounded-lg text-xs transition" onclick="openQuotaModal('{{ user.username }}', {{ user.quota_gb }}, '{{ user.rate_limit_kbps }}')">设置</button>
                                <button class="bg-yellow-500 hover:bg-yellow-600 text-white py-1 px-2 rounded-lg text-xs transition" onclick="openResetModal('{{ user.username }}')">重置用量</button>
                                <button class="bg-red-500 hover:bg-red-600 text-white py-1 px-2 rounded-lg text-xs transition" onclick="openDeleteModal('{{ user.username }}')">删除</button>
                            </td>
                        </tr>
                        {% endfor %}
                        </tbody>
                        </table>
                    </div>
                </div>
        </div>
    </div>

    <!-- Modal for Delete Confirmation -->
    <div id="deleteModal" class="modal">
        <div class="bg-white p-6 rounded-xl shadow-2xl w-full max-w-md">
            <h3 class="text-xl font-semibold text-gray-800 mb-4">确认删除用户</h3>
            <p class="text-gray-600">您确定要永久删除用户 <strong id="delete-username-placeholder" class="text-red-500"></strong> 吗？此操作不可逆，将删除系统账户和所有配置。</p>
            <div class="mt-6 text-right">
                <button class="bg-gray-300 hover:bg-gray-400 text-gray-800 font-bold py-2 px-4 rounded-lg mr-2" onclick="closeModal('deleteModal')">取消</button>
                <button class="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-lg" id="confirm-delete-btn">确认删除</button>
            </div>
        </div>
    </div>

    <!-- Modal for Service Restart -->
    <div id="restartModal" class="modal">
        <div class="bg-white p-6 rounded-xl shadow-2xl w-full max-w-md">
            <h3 class="text-xl font-semibold text-gray-800 mb-4">确认重启服务</h3>
            <p class="text-gray-600">您确定要重启 <strong id="restart-service-placeholder" class="text-blue-500"></strong> 吗？这可能会短暂中断隧道服务。</p>
            <div class="mt-6 text-right">
                <button class="bg-gray-300 hover:bg-gray-400 text-gray-800 font-bold py-2 px-4 rounded-lg mr-2" onclick="closeModal('restartModal')">取消</button>
                <button class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-lg" id="confirm-restart-btn">确认重启</button>
            </div>
        </div>
    </div>
    
    <!-- Modal for Reset Usage -->
    <div id="resetModal" class="modal">
        <div class="bg-white p-6 rounded-xl shadow-2xl w-full max-w-md">
            <h3 class="text-xl font-semibold text-gray-800 mb-4">确认重置用量</h3>
            <p class="text-gray-600">您确定要重置用户 <strong id="reset-username-placeholder" class="text-blue-500"></strong> 的流量用量吗？账户将同时解除配额锁定状态（如果已锁定）。</p>
            <div class="mt-6 text-right">
                <button class="bg-gray-300 hover:bg-gray-400 text-gray-800 font-bold py-2 px-4 rounded-lg mr-2" onclick="closeModal('resetModal')">取消</button>
                <button class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-lg" id="confirm-reset-btn">确认重置</button>
            </div>
        </div>
    </div>

    <!-- Modal for Set Quota/Rate Limit -->
    <div id="quotaModal" class="modal">
        <div class="bg-white p-6 rounded-xl shadow-2xl w-full max-w-md">
            <h3 class="text-xl font-semibold text-gray-800 mb-4">设置 <strong id="quota-username-placeholder" class="text-blue-500"></strong> 的配额与带宽</h3>
            <form id="set-quota-form">
                <label for="modal-quota-gb" class="block text-sm font-medium text-gray-700 mb-1">流量配额 (GB, 0=不限制)</label>
                <input type="number" id="modal-quota-gb" class="w-full p-2 border border-gray-300 rounded-lg mb-4" min="0" required>
                <label for="modal-rate-kbps" class="block text-sm font-medium text-gray-700 mb-1">最大带宽 (KB/s, 0=不限制)</label>
                <input type="number" id="modal-rate-kbps" class="w-full p-2 border border-gray-300 rounded-lg mb-4" min="0" required>
                <div class="mt-6 text-right">
                    <button type="button" class="bg-gray-300 hover:bg-gray-400 text-gray-800 font-bold py-2 px-4 rounded-lg mr-2" onclick="closeModal('quotaModal')">取消</button>
                    <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-lg">保存设置</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        // --- Utility Functions ---

        function showStatus(message, isSuccess) {
            const statusDiv = document.getElementById('status-message');
            statusDiv.textContent = message;
            statusDiv.className = isSuccess ? 'bg-green-100 text-green-800 border border-green-400 p-3 rounded-lg font-bold' : 'bg-red-100 text-red-800 border border-red-400 p-3 rounded-lg font-bold';
            statusDiv.style.display = 'block';
            setTimeout(() => { statusDiv.style.display = 'none'; }, 5000);
        }
        
        // --- Modal Logic ---

        function openModal(id) {
            document.getElementById(id).style.display = 'flex';
        }

        function closeModal(id) {
            document.getElementById(id).style.display = 'none';
        }
        
        // --- Real-time Monitoring Functions ---

        async function refreshMonitorData() {
            try {
                const response = await fetch('/api/monitor_data');
                const data = await response.json();
                
                if (response.ok) {
                    renderSystemHealth(data.system_health, data.services);
                    renderServiceAndPortStatus(data.services, data.ports);
                } else {
                    console.error('获取状态失败:', data.message || '未知错误');
                }
            } catch (error) {
                console.error("Monitor data fetch error:", error);
            }
        }
        
        function renderSystemHealth(health, services) {
            document.getElementById('cpu-usage').textContent = health.cpu_usage !== "N/A" ? \`\${health.cpu_usage}%\` : '--';
            
            let memText = health.mem_usage !== "N/A" ? \`\${health.mem_usage}% (\${health.mem_used_mb}/\${health.mem_total_mb}MB)\` : '--';
            document.getElementById('mem-usage').textContent = memText;
            
            document.getElementById('disk-usage').textContent = health.disk_usage !== "N/A" ? \`\${health.disk_usage}%\` : '--';

            // Update core service status indicators
            const serviceMapping = {
                'WSS Proxy': 'wss', 'Stunnel4': 'stunnel4', 'UDPGW': 'udpgw', 'Web Panel': 'wss_panel'
            };
            
            services.forEach(service => {
                const id = serviceMapping[service.name];
                if (!id) return;
                
                const indicator = document.getElementById(\`\${id}-status-indicator\`);
                const label = document.getElementById(\`\${id}-status-label\`);
                
                if (indicator && label) {
                    // Update dot color based on service.color (bg-*)
                    indicator.className = \`status-dot \${service.color}\`;
                    label.textContent = service.label;
                }
            });
        }
        
        function renderServiceAndPortStatus(services, ports) {
            const tableBody = document.getElementById('service-port-tbody');
            tableBody.innerHTML = '';
            
            const servicePortData = [
                { id: 'wss_http', name: 'WSS Proxy (HTTP)', port: '{{ wss_http_port }}', protocol: 'TCP', service: 'wss' },
                { id: 'wss_tls', name: 'WSS Proxy (TLS)', port: '{{ wss_tls_port }}', protocol: 'TCP', service: 'wss' },
                { id: 'stunnel4', name: 'Stunnel4 (TLS)', port: '{{ stunnel_port }}', protocol: 'TCP', service: 'stunnel4' },
                { id: 'udpgw', name: 'UDPGW (UDP)', port: '{{ udpgw_port }}', protocol: 'UDP', service: 'udpgw' },
                { id: 'wss_panel', name: 'Web Panel (Flask)', port: '{{ panel_port }}', protocol: 'TCP', service: 'wss_panel' },
                { id: 'ssh_internal', name: 'SSH (Internal Forward)', port: '{{ internal_forward_port }}', protocol: 'TCP', service: null },
            ];

            servicePortData.forEach(item => {
                const portInfo = ports.find(p => p.port == item.port);
                const status = portInfo ? portInfo.status : 'N/A';
                const color = portInfo ? portInfo.color : 'text-gray-500'; // Tailwind text color class
                
                const row = document.createElement('tr');
                row.className = 'hover:bg-gray-50';
                row.innerHTML = \`
                    <td class="px-3 py-1 text-sm text-gray-900">\${item.name}</td>
                    <td class="px-3 py-1 text-sm text-gray-500">\${item.port} (\${item.protocol})</td>
                    <td class="px-3 py-1 text-sm font-bold \${color}">\${status}</td>
                    <td class="px-3 py-1 text-sm font-medium">
                        \${item.service ? \`<button class="bg-blue-500 hover:bg-blue-600 text-white py-1 px-3 rounded-lg text-xs transition" onclick="openRestartModal('\${item.service}', '\${item.name}')">重启</button>\` : 'N/A'}
                    </td>
                \`;
                tableBody.appendChild(row);
            });
        }

        async function fetchLogs() {
            try {
                const response = await fetch('/api/logs');
                const data = await response.json();
                
                if (response.ok) {
                    const logContent = document.getElementById('log-pre-content');
                    logContent.textContent = data.logs.trim();
                    // Scroll to bottom to view newest logs first (due to flex-direction: column-reverse in CSS)
                    logContent.scrollTop = 0; 
                } else {
                    console.error('获取日志失败:', data.message || '未知错误');
                }
            } catch (error) {
                console.error("Log fetch error:", error);
            }
        }

        // --- User Actions ---

        document.getElementById('add-user-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('new-username').value.trim();
            const password = document.getElementById('new-password').value;
            const expirationDays = document.getElementById('expiration-days').value;
            const quotaGb = document.getElementById('quota-gb').value;
            const rateKbps = document.getElementById('rate-kbps').value;

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
                        expiration_days: expirationDays, // New Field
                        quota_gb: quotaGb, // New Field
                        rate_kbps: rateKbps // New Field
                    })
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

        // --- Delete Modal Logic ---
        function openDeleteModal(username) {
            document.getElementById('delete-username-placeholder').textContent = username;
            const confirmBtn = document.getElementById('confirm-delete-btn');
            confirmBtn.onclick = () => deleteUser(username);
            openModal('deleteModal');
        }

        async function deleteUser(username) {
            closeModal('deleteModal');
            showStatus(\`正在删除用户 \${username}...\`, true);
            
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

        // --- Quota/Rate Limit Modal Logic ---
        function openQuotaModal(username, quota, rate) {
            document.getElementById('quota-username-placeholder').textContent = username;
            document.getElementById('modal-quota-gb').value = quota;
            document.getElementById('modal-rate-kbps').value = rate;
            openModal('quotaModal');
            
            const form = document.getElementById('set-quota-form');
            // Remove old listener before adding new one
            form.onsubmit = (e) => setQuotaAndRate(e, username); 
        }

        async function setQuotaAndRate(e, username) {
            e.preventDefault();
            closeModal('quotaModal');
            
            const quotaGb = document.getElementById('modal-quota-gb').value;
            const rateKbps = document.getElementById('modal-rate-kbps').value;

            showStatus(\`正在为 \${username} 设置配额和带宽...\`, true);
            
            try {
                const response = await fetch('/api/users/set_rate_limit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        username, 
                        quota_gb: quotaGb, 
                        rate_kbps: rateKbps 
                    })
                });

                const result = await response.json();

                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    location.reload();
                } else {
                    showStatus('设置失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
        }

        // --- Reset Usage Modal Logic ---
        function openResetModal(username) {
            document.getElementById('reset-username-placeholder').textContent = username;
            const confirmBtn = document.getElementById('confirm-reset-btn');
            confirmBtn.onclick = () => resetUsage(username);
            openModal('resetModal');
        }

        async function resetUsage(username) {
            closeModal('resetModal');
            showStatus(\`正在重置 \${username} 的用量...\`, true);
            
            try {
                const response = await fetch('/api/users/reset_usage', {
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

        // --- Restart Modal Logic ---
        function openRestartModal(serviceId, serviceName) {
            document.getElementById('restart-service-placeholder').textContent = serviceName;
            const confirmBtn = document.getElementById('confirm-restart-btn');
            confirmBtn.onclick = () => restartService(serviceId);
            openModal('restartModal');
        }

        async function restartService(serviceId) {
            closeModal('restartModal');
            showStatus(\`正在重启 \${serviceId}...\`, true);
            
            try {
                const response = await fetch('/api/restart', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ service: serviceId })
                });

                const result = await response.json();
                
                if (response.ok && result.success) {
                    showStatus(result.message, true);
                    setTimeout(refreshMonitorData, 3000); 
                } else {
                    showStatus('重启失败: ' + (result.message || '未知错误'), false);
                    setTimeout(refreshMonitorData, 3000);
                }
            } catch (error) {
                showStatus('请求重启 API 失败，请检查面板运行状态。', false);
            }
        }
        
        function logout() {
            window.location.href = '/logout';
        }
        
        // --- Polling Setup ---
        // Refresh status every 5 seconds (CPU/Memory/Service Status)
        setInterval(refreshMonitorData, 5000);
        // Refresh logs every 10 seconds
        setInterval(fetchLogs, 10000);
        
        // Initial load
        window.onload = () => {
            refreshMonitorData();
            fetchLogs();
        };
        
    </script>
</body>
</html>
"""

# 修复后的渲染函数
def render_dashboard(users):
    """手动渲染 Jinja2 模板字符串."""
    template_env = jinja2.Environment(loader=jinja2.BaseLoader)
    template = template_env.from_string(_DASHBOARD_HTML)
    
    context = {
        'users': users,
        'panel_port': PANEL_PORT,
        'wss_http_port': WSS_HTTP_PORT,
        'wss_tls_port': WSS_TLS_PORT,
        'stunnel_port': STUNNEL_PORT,
        'udpgw_port': UDPGW_PORT,
        'internal_forward_port': INTERNAL_FORWARD_PORT,
    }
    return template.render(**context)


# --- Web 路由 ---

@app.route('/', methods=['GET'])
@login_required
def dashboard():
    users = load_users()
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

    # Tailwind CSS Login Page
    html = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS Panel - 登录</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 flex justify-center items-center h-screen m-0">
    <div class="bg-white p-8 rounded-xl shadow-2xl w-full max-w-md">
        <h1 class="text-3xl font-bold text-center text-gray-800 mb-6">WSS 管理面板</h1>
        {f'<div class="bg-red-100 text-red-700 p-3 rounded-lg text-center mb-4 font-medium">{error}</div>' if error else ''}
        <form method="POST" class="space-y-4">
            <div>
                <label for="username" class="block text-sm font-medium text-gray-700 mb-1">用户名</label>
                <input type="text" placeholder="输入 {ROOT_USERNAME}" name="username" value="{ROOT_USERNAME}" required class="w-full p-3 border border-gray-300 rounded-lg focus:ring-green-500 focus:border-green-500 transition">
            </div>

            <div>
                <label for="password" class="block text-sm font-medium text-gray-700 mb-1">密码</label>
                <input type="password" placeholder="输入密码" name="password" required class="w-full p-3 border border-gray-300 rounded-lg focus:ring-green-500 focus:border-green-500 transition">
            </div>

            <button type="submit" class="w-full bg-green-600 text-white font-bold py-3 rounded-lg text-lg hover:bg-green-700 transition">登录</button>
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
    # New fields
    expiration_days = data.get('expiration_days')
    quota_gb = data.get('quota_gb')
    rate_kbps = data.get('rate_kbps')
    
    if not username or not password_raw or expiration_days is None or quota_gb is None or rate_kbps is None:
        return jsonify({"success": False, "message": "缺少用户名、密码或配额/有效期/带宽设置"}), 400

    users = load_users()
    if get_user(username):
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
        
    # 3. 设置有效期 (chage)
    try:
        expiry_date = (date.today() + timedelta(days=int(expiration_days))).strftime('%Y-%m-%d')
        safe_run_command(['chage', '-E', expiry_date, username])
    except ValueError:
        safe_run_command(['userdel', '-r', username])
        return jsonify({"success": False, "message": "有效期天数无效"}), 500
        
    # 4. 获取 UID
    uid = get_user_uid(username)
    if not uid:
        safe_run_command(['userdel', '-r', username])
        return jsonify({"success": False, "message": "无法获取用户UID"}), 500
        
    # 5. 记录到 JSON 数据库并应用初始配额/限速
    new_user = {
        "username": username,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "status": "active",
        "expiration_date": expiry_date,
        "quota_gb": int(quota_gb),
        "usage_bytes": 0,
        "rate_limit_kbps": str(int(rate_kbps))
    }
    users.append(new_user)
    save_users(users)
    
    # 6. 应用带宽限制和配额规则
    apply_rate_limit(uid, int(rate_kbps))
    manage_quota_iptables_rule(username, uid, 'add')


    return jsonify({"success": True, "message": f"用户 {username} 创建成功，有效期至 {expiry_date}"})

@app.route('/api/users/delete', methods=['POST'])
@login_required
def delete_user_api():
    """删除用户 (API)"""
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({"success": False, "message": "缺少用户名"}), 400

    users = load_users()
    user_to_delete = get_user(username)
    
    if not user_to_delete:
        return jsonify({"success": False, "message": f"面板中用户 {username} 不存在"}), 404

    # 1. 删除带宽限制 (确保清理)
    uid = get_user_uid(username)
    if uid:
        apply_rate_limit(uid, 0) # Clears TC rules
        manage_quota_iptables_rule(username, uid, 'delete') # Clears Quota rules

    # 2. 删除系统用户及其主目录
    success, output = safe_run_command(['userdel', '-r', username])
    if not success:
        print(f"Warning: Failed to delete system user {username}: {output}")

    # 3. 从 JSON 数据库中删除记录
    users = [user for user in users if user['username'] != username]
    save_users(users)

    return jsonify({"success": True, "message": f"用户 {username} 已删除"})

@app.route('/api/users/set_rate_limit', methods=['POST'])
@login_required
def set_rate_limit_api():
    """API to set user bandwidth rate limit and quota."""
    data = request.json
    username = data.get('username')
    rate_kbps = data.get('rate_kbps')
    quota_gb = data.get('quota_gb')

    if not username or rate_kbps is None or quota_gb is None:
        return jsonify({"success": False, "message": "缺少用户名、速率限制值或配额值"}), 400

    users = load_users()
    user = next((u for u in users if u['username'] == username), None)
    
    if not user:
        return jsonify({"success": False, "message": f"用户 {username} 不存在于面板"}), 404
        
    uid = user['uid']
    if not uid:
        return jsonify({"success": False, "message": f"无法获取用户 {username} 的 UID，无法设置带宽限制。"}), 500
        
    try:
        rate = int(rate_kbps)
        quota = int(quota_gb)

        # 1. 应用 TC 限制
        success, message = apply_rate_limit(uid, rate)
        if not success:
            return jsonify({"success": False, "message": f"带宽限制设置失败: {message}"}), 500

        # 2. 应用 Iptables 配额规则
        if quota > 0:
            manage_quota_iptables_rule(username, uid, 'add') # Ensure rule is present
        else:
            manage_quota_iptables_rule(username, uid, 'delete') # Remove rule if quota is 0

        # 3. 更新面板数据库
        user['rate_limit_kbps'] = str(rate)
        user['quota_gb'] = quota
        
        # 4. 检查是否需要解锁账户 (如果配额被设为 0 / 无限制)
        if quota == 0 and user['status'] in ('exceeded', 'expired'):
            safe_run_command(['usermod', '-U', username])
            # Re-run status check to update expiry date status
            user['status'], user['expiration_date'] = get_user_expiration_status(username)
            
        save_users(users)

        return jsonify({"success": True, "message": f"用户 {username} 设置更新成功。 配额: {quota} GB, 带宽: {message}"})
            
    except ValueError:
        return jsonify({"success": False, "message": "速率/配额值必须是数字"}), 400

@app.route('/api/users/reset_usage', methods=['POST'])
@login_required
def reset_usage_api():
    """API to reset a user's traffic usage counter."""
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({"success": False, "message": "缺少用户名"}), 400

    users = load_users()
    user = next((u for u in users if u['username'] == username), None)
    
    if not user:
        return jsonify({"success": False, "message": f"用户 {username} 不存在于面板"}), 404
    
    # 1. Reset iptables counter
    reset_iptables_counters(username)

    # 2. Reset usage in database
    user['usage_bytes'] = 0
    user['usage_gb'] = 0
    
    # 3. Unlock account if currently locked due to quota
    if user['status'] == 'exceeded':
        safe_run_command(['usermod', '-U', username])
        user['status'] = 'active'
        
    save_users(users)
    
    return jsonify({"success": True, "message": f"用户 {username} 的流量用量已重置，账户已重新激活。"})


@app.route('/api/monitor_data', methods=['GET'])
@login_required
def get_monitor_data_api():
    """API to get system health, service, and port statuses."""
    
    cpu_usage = get_cpu_usage()
    mem_info = get_memory_usage()
    disk_info = get_disk_usage()
    
    system_health = {
        "cpu_usage": cpu_usage,
        "mem_usage": mem_info["usage"],
        "mem_total_mb": mem_info["total_mb"],
        "mem_used_mb": mem_info["mem_used_mb"],
        "disk_usage": disk_info["usage"]
    }
    
    components = {
        'wss': 'WSS Proxy', 
        'stunnel4': 'Stunnel4', 
        'udpgw': 'UDPGW',
        'wss_panel': 'Web Panel', 
    }
    service_statuses = []
    for service_id, service_name in components.items():
        state, label, color = get_service_status_detail(service_id)
        service_statuses.append({
            'id': service_id,
            'name': service_name,
            'state': state,
            'label': label,
            'color': color
        })

    ports = [
        {'name': 'WSS (HTTP Payload)', 'port': WSS_HTTP_PORT, 'protocol': 'TCP'},
        {'name': 'WSS (TLS)', 'port': WSS_TLS_PORT, 'protocol': 'TCP'},
        {'name': 'Stunnel (TLS Tunnel)', 'port': STUNNEL_PORT, 'protocol': 'TCP'},
        {'name': 'UDPGW (UDP Forward)', 'port': UDPGW_PORT, 'protocol': 'UDP'},
        {'name': 'Web Panel (Flask)', 'port': PANEL_PORT, 'protocol': 'TCP'},
        {'name': 'SSH Internal Forward', 'port': INTERNAL_FORWARD_PORT, 'protocol': 'TCP'} 
    ]
    port_statuses = []
    for p in ports:
        status, color = get_port_status_detail(p['port'])
        port_statuses.append({
            'name': p['name'],
            'port': p['port'],
            'protocol': p['protocol'],
            'status': status,
            'color': color
        })
        
    return jsonify({
        "system_health": system_health,
        "services": service_statuses,
        "ports": port_statuses
    })

@app.route('/api/restart', methods=['POST'])
@login_required
def restart_service_api():
    """API to restart a specific service."""
    service_name = request.json.get('service')
    if service_name not in ['wss', 'stunnel4', 'wss_panel', 'udpgw']:
        return jsonify({"success": False, "message": "无效的服务名称。"}), 400
        
    success, output = safe_run_command(['systemctl', 'restart', service_name])
    time.sleep(1) 
    
    if success:
        return jsonify({"success": True, "message": f"服务 {service_name} 重启命令已发送。"})
    else:
        state, _, _ = get_service_status_detail(service_name)
        if state == 'active':
             return jsonify({"success": True, "message": f"服务 {service_name} 重启流程已启动。"})
        return jsonify({"success": False, "message": f"重启 {service_name} 失败: {output}"}), 500


@app.route('/api/logs', methods=['GET'])
@login_required
def get_logs_api():
    """API to get generic system logs (all services, newest on top)."""
    logs_output = get_logs_data()
    return jsonify({"logs": logs_output})


if __name__ == '__main__':
    # 为了简化部署，将 debug 设置为 False
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
systemctl start wss_panel # 启动服务以便后续检查
echo "WSS 管理面板已启动，端口 $PANEL_PORT"
echo "----------------------------------"

# =============================
# SSHD 安全配置 (统一策略)
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


# =============================
# 最终重启所有关键服务 (NEW)
# =============================
echo "==== 最终重启所有关键服务，确保配置生效 ===="
systemctl restart wss stunnel4 udpgw wss_panel
echo "所有服务重启完成：WSS, Stunnel4, UDPGW, Web Panel。"
echo "----------------------------------"


# 清理敏感变量
unset PANEL_ROOT_PASS_RAW

echo "=================================================="
echo "✅ 部署完成！"

echo "=================================================="
echo ""
echo "🔥 WSS & Stunnel 基础设施已启动。"
echo "🌐 WSS 用户管理面板已在后台运行。"
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
echo "UDPGW (内部 UDP 转发): $UDPGW_PORT"
echo "内部 SSH 转发端口: $INTERNAL_FORWARD_PORT (WSS/Stunnel 代理连接到 SSH 的端口)"
echo ""
echo "--- 故障排查 ---"
echo "WSS 代理状态: sudo systemctl status wss"
echo "Stunnel 状态: sudo systemctl status stunnel4"
echo "Web 面板状态: sudo systemctl status wss_panel"
echo "用户数据库路径: /etc/wss-panel/users.json (面板通过此文件进行用户查询和管理)"
echo "=================================================="
