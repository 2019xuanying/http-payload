#!/usr/bin/env bash

set -eu

# ==========================================================
# WSS 隧道与用户管理面板一键部署脚本 (功能升级版)
# ----------------------------------------------------------
# Panel 新功能: 实时服务/端口状态监控, 资源使用率, 服务重启, 自动刷新日志
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
apt update -y
apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4
# 额外安装 flask, jinja2, uvloop, 和 ss (用于端口检查)
pip3 install flask jinja2 uvloop
echo "依赖安装完成"
echo "----------------------------------"


# =============================
# WSS 核心代理脚本
# =============================
echo "==== 安装 WSS 核心代理脚本 (/usr/local/bin/wss) ===="
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
systemctl restart stunnel4
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
systemctl start udpgw
echo "UDPGW 已安装并启动，端口: $UDPGW_PORT"
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

# 嵌入 Python 面板代码 (包含新的API和逻辑)
tee /usr/local/bin/wss_panel.py > /dev/null <<EOF
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, redirect, url_for, session, make_response
import json
import subprocess
import os
import hashlib
import time
import jinja2

# --- 配置 ---
USER_DB_PATH = "$USER_DB"
ROOT_USERNAME = "root"
ROOT_PASSWORD_HASH = "$PANEL_ROOT_PASS_HASH"
FLASK_SECRET_KEY = os.urandom(24).hex()
SSHD_CONFIG = "/etc/ssh/sshd_config"

# 面板和端口配置 (用于模板)
PANEL_PORT = "$PANEL_PORT"
WSS_HTTP_PORT = "$WSS_HTTP_PORT"
WSS_TLS_PORT = "$WSS_TLS_PORT"
STUNNEL_PORT = "$STUNNEL_PORT"
UDPGW_PORT = "$UDPGW_PORT"
INTERNAL_FORWARD_PORT = "$INTERNAL_FORWARD_PORT" 

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# --- 数据库操作/认证装饰器/系统工具函数 (保持不变) ---

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
    """按用户名查找用户."""
    users = load_users()
    for user in users:
        if user['username'] == username:
            return user
    return None

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
        
# --- System Monitoring Functions ---

def get_cpu_usage():
    """Calculates CPU usage percentage."""
    try:
        # Use mpstat for robust CPU usage reading. Requires sysstat if not present, but widely available.
        success, output = safe_run_command(['bash', '-c', "LC_ALL=C mpstat 1 1 | awk '/^Average:/ {print 100 - \$NF}'"])
        if success and output:
            # mpstat output is usually more complex, so we fallback to reading /proc/stat if mpstat is not installed/fails
            if "not found" in output:
                # Simpler approximation by reading /proc/stat
                with open('/proc/stat', 'r') as f:
                    line1 = f.readline().split()
                time.sleep(0.1)
                with open('/proc/stat', 'r') as f:
                    line2 = f.readline().split()

                total1 = sum(int(x) for x in line1[1:])
                idle1 = int(line1[4])
                total2 = sum(int(x) for x in line2[1:])
                idle2 = int(line2[4])

                total_diff = total2 - total1
                idle_diff = idle2 - idle1
                
                if total_diff == 0:
                    return 0.0
                    
                cpu_usage = 100.0 * (total_diff - idle_diff) / total_diff
                return round(cpu_usage, 1)
            
            return round(float(output), 1)
        return "N/A"
    except Exception:
        return "N/A"

def get_memory_usage():
    """Calculates memory usage percentage and total/used."""
    try:
        # Get data from /proc/meminfo
        success, output = safe_run_command(['free', '-m'])
        if success:
            lines = output.split('\n')
            # Look for the Mem line (usually the second line)
            mem_line = lines[1].split()
            total = int(mem_line[1])
            used = int(mem_line[2])
            
            if total > 0:
                usage = (used / total) * 100
                return {
                    "usage": round(usage, 1),
                    "total_mb": total,
                    "used_mb": used
                }
        return {"usage": "N/A", "total_mb": "N/A", "used_mb": "N/A"}
    except Exception:
        return {"usage": "N/A", "total_mb": "N/A", "used_mb": "N/A"}


def get_disk_usage():
    """Gets root filesystem disk usage."""
    try:
        success, output = safe_run_command(['df', '-h', '/'])
        if success:
            lines = output.split('\n')
            # The last line should contain the root partition usage
            disk_line = lines[-1].split()
            if len(disk_line) >= 5:
                # Usage is the 5th column, remove the '%' sign
                usage_str = disk_line[4].replace('%', '')
                return {"usage": int(usage_str)}
        return {"usage": "N/A"}
    except Exception:
        return {"usage": "N/A"}

def get_service_status_detail(service_name):
    """Returns service status and a descriptive label/color."""
    success, output = safe_run_command(['systemctl', 'is-active', service_name])
    status = output.strip()
    
    if success and status == 'active':
        return "active", "运行中", "#2ecc71"
    elif status == 'inactive':
        return "inactive", "已停止", "#f39c12"
    else:
        # Check if failed for better feedback
        failed_check = safe_run_command(['systemctl', 'is-failed', service_name])
        if failed_check[0] and failed_check[1] == 'failed':
            return "failed", "失败", "#e74c3c"
        return status.capitalize() or "unknown", "未知", "#888"

def get_port_status_detail(port):
    """Checks if a port is listening using 'ss'."""
    port_str = str(port)
    # Using 'ss' (better performance than netstat)
    success, output = safe_run_command(['ss', '-tuln'])
    
    # Check for both TCP/UDP on the port (only checking for the port number string)
    if success and (f':{port_str}' in output or f' {port_str}' in output):
        return "监听中", "#2ecc71"
    return "未监听", "#e74c3c"

def get_logs_data(service_name, lines=50):
    """Retrieves journalctl logs."""
    # Using 'journalctl -u' which handles systemd service logs
    success, output = safe_run_command(['journalctl', '-u', service_name, f'-n {lines}', '--no-pager', '--utc'])
    return output if success else f"错误: 无法获取 {service_name} 日志. 请检查服务是否安装或运行. {output}"


# --- API Routes ---

@app.route('/api/monitor_data', methods=['GET'])
@login_required
def get_monitor_data_api():
    """API to get system health, service, and port statuses."""
    
    # 1. System Health
    cpu_usage = get_cpu_usage()
    mem_info = get_memory_usage()
    disk_info = get_disk_usage()
    
    system_health = {
        "cpu_usage": cpu_usage,
        "mem_usage": mem_info["usage"],
        "mem_total_mb": mem_info["total_mb"],
        "mem_used_mb": mem_info["used_mb"],
        "disk_usage": disk_info["usage"]
    }
    
    # 2. Service Status
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

    # 3. Port Status
    ports = [
        {'name': 'WSS (HTTP Payload)', 'port': WSS_HTTP_PORT, 'protocol': 'TCP'},
        {'name': 'WSS (TLS)', 'port': WSS_TLS_PORT, 'protocol': 'TCP'},
        {'name': 'Stunnel (TLS Tunnel)', 'port': STUNNEL_PORT, 'protocol': 'TCP'},
        {'name': 'UDPGW (UDP Forward)', 'port': UDPGW_PORT, 'protocol': 'UDP'},
        {'name': 'Web Panel (Flask)', 'port': PANEL_PORT, 'protocol': 'TCP'},
        # SSH Internal is mainly for checking if SSH is listening on the internal port
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
        
    # Run the restart command
    success, output = safe_run_command(['systemctl', 'restart', service_name])
    
    # Give the system a brief moment to update status
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
    """API to get component logs."""
    logs = {}
    logs['WSS Proxy (wss)'] = get_logs_data('wss')
    logs['Stunnel4 (stunnel4)'] = get_logs_data('stunnel4')
    logs['Web Panel (wss_panel)'] = get_logs_data('wss_panel')
    logs['UDPGW (udpgw)'] = get_logs_data('udpgw')
    return jsonify({"logs": logs})

# --- HTML 模板和渲染 (更新) ---

# 仪表盘 HTML (内嵌)
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
        
        /* Status Grid */
        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .status-box { background: #ecf0f1; padding: 15px; border-radius: 8px; text-align: center; }
        .status-box h4 { margin: 0; font-size: 14px; color: #34495e; font-weight: 500;}
        .status-box p { margin: 5px 0 0; font-size: 18px; font-weight: bold; }
        .status-indicator { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; }

        /* User & Ports Table */
        .user-table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .user-table th, .user-table td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        .user-table th { background-color: #f7f7f7; color: #333; }
        .user-table tr:nth-child(even) { background-color: #f9f9f9; }
        .delete-btn { background-color: #e74c3c; color: white; border: none; padding: 6px 10px; border-radius: 5px; cursor: pointer; font-size: 12px; }
        .delete-btn:hover { background-color: #c0392b; }
        .action-btn { background-color: #3498db; color: white; border: none; padding: 6px 10px; border-radius: 5px; cursor: pointer; font-size: 12px; }
        .action-btn:hover { background-color: #2980b9; }

        /* Logs */
        .log-container-wrapper { 
            background-color: #333; 
            padding: 10px; 
            border-radius: 6px; 
            overflow: hidden; 
        }
        .log-pre { 
            background-color: #333; 
            color: #ecf0f1; 
            margin: 0;
            padding: 5px; 
            overflow-y: scroll; 
            font-size: 12px; 
            max-height: 250px; /* Limit height for scrollable view */
            white-space: pre-wrap;
            scrollbar-width: thin;
        }

        /* Form */
        .user-form input[type=text], .user-form input[type=password] { padding: 10px; margin-right: 10px; border: 1px solid #ccc; border-radius: 6px; }
        .user-form button { background-color: #2ecc71; color: white; border: none; padding: 10px 15px; border-radius: 6px; cursor: pointer; transition: background-color 0.3s; }
        .user-form button:hover { background-color: #27ae60; }

        /* Alerts */
        .alert { padding: 15px; border-radius: 8px; margin-bottom: 20px; font-weight: bold; }
        .alert-success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }

    </style>
</head>
<body>
    <div class="header">
        <h1>WSS Panel - 仪表盘</h1>
        <button onclick="logout()">退出登录 (root)</button>
    </div>

    <div class="container">
        <div id="status-message" class="alert" style="display:none;"></div>
        
        <!-- 实时系统状态 -->
        <div class="card">
            <h3>实时系统状态</h3>
            <div class="status-grid">
                <div class="status-box">
                    <h4>已创建用户数</h4>
                    <p id="user-count">{{ users|length }}</p>
                </div>
                <div class="status-box">
                    <h4>CPU 使用率</h4>
                    <p id="cpu-usage">--</p>
                </div>
                <div class="status-box">
                    <h4>内存使用率</h4>
                    <p id="mem-usage">--</p>
                </div>
                <div class="status-box">
                    <h4>磁盘使用率 (根目录)</h4>
                    <p id="disk-usage">--</p>
                </div>
                <!-- Core Service Status (Inline) -->
                <div class="status-box">
                    <h4>WSS Proxy 状态</h4>
                    <p><span id="wss-status-indicator" class="status-indicator"></span><span id="wss-status-label">--</span></p>
                </div>
                <div class="status-box">
                    <h4>Stunnel4 状态</h4>
                    <p><span id="stunnel4-status-indicator" class="status-indicator"></span><span id="stunnel4-status-label">--</span></p>
                </div>
                <div class="status-box">
                    <h4>UDPGW 状态</h4>
                    <p><span id="udpgw-status-indicator" class="status-indicator"></span><span id="udpgw-status-label">--</span></p>
                </div>
                <div class="status-box">
                    <h4>Web Panel 状态</h4>
                    <p><span id="wss_panel-status-indicator" class="status-indicator"></span><span id="wss_panel-status-label">--</span></p>
                </div>
            </div>
        </div>
        
        <!-- 服务控制与端口状态 -->
        <div class="card">
            <h3>服务控制与端口状态</h3>
            <table class="user-table" id="service-control-table">
                <thead>
                    <tr>
                        <th style="width: 30%;">组件名称</th>
                        <th style="width: 25%;">端口</th>
                        <th style="width: 20%;">监听状态</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody id="service-port-tbody">
                    <!-- Dynamically populated by JS -->
                </tbody>
            </table>
        </div>

        <!-- 实时日志 -->
        <div class="card">
            <h3>实时组件日志 (最新50条)</h3>
            <div class="log-container-wrapper">
                <p style="color:#aaa; font-size:12px; margin-bottom: 5px;">日志自动刷新中 (每10秒)</p>
                <pre id="log-pre-content" class="log-pre">正在加载日志...</pre>
            </div>
        </div>


        <!-- 用户管理 -->
        <div class="card">
            <h3>新增 WSS 用户</h3>
            <form id="add-user-form" class="user-form">
                <input type="text" id="new-username" placeholder="用户名 (小写字母/数字/下划线)" pattern="[a-z0-9_]{3,16}" title="用户名只能包含小写字母、数字和下划线，长度3-16位" required>
                <input type="password" id="new-password" placeholder="密码" required>
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
                        <th>创建时间</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr id="row-{{ user.username }}">
                        <td>{{ user.username }}</td>
                        <td><span style="color:#2ecc71; font-weight: bold;">{{ user.status.upper() }}</span></td>
                        <td>{{ user.created_at }}</td>
                        <td><button class="delete-btn" onclick="deleteUser('{{ user.username }}')">删除</button></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        // --- Utility Functions ---

        function showStatus(message, isSuccess) {
            const statusDiv = document.getElementById('status-message');
            statusDiv.textContent = message;
            statusDiv.className = isSuccess ? 'alert alert-success' : 'alert alert-error';
            statusDiv.style.display = 'block';
            setTimeout(() => { statusDiv.style.display = 'none'; }, 5000);
        }
        
        // --- Real-time Monitoring Functions ---

        async function refreshMonitorData() {
            try {
                const response = await fetch('/api/monitor_data');
                const data = await response.json();
                
                if (response.ok) {
                    renderSystemHealth(data.system_health);
                    renderServiceAndPortStatus(data.services, data.ports);
                } else {
                    showStatus('获取状态失败: ' + (data.message || '未知错误'), false);
                }
            } catch (error) {
                console.error("Monitor data fetch error:", error);
                // showStatus('请求状态 API 失败，请检查面板运行状态。', false); // Silence error for continuous polling
            }
        }
        
        function renderSystemHealth(health) {
            document.getElementById('cpu-usage').textContent = health.cpu_usage !== "N/A" ? \`\${health.cpu_usage}%\` : '--';
            
            let memText = health.mem_usage !== "N/A" ? \`\${health.mem_usage}% (\${health.mem_used_mb}/\${health.mem_total_mb}MB)\` : '--';
            document.getElementById('mem-usage').textContent = memText;
            
            document.getElementById('disk-usage').textContent = health.disk_usage !== "N/A" ? \`\${health.disk_usage}%\` : '--';

            // Update core service status indicators
            health.services.forEach(service => {
                const indicator = document.getElementById(\`\${service.id}-status-indicator\`);
                const label = document.getElementById(\`\${service.id}-status-label\`);
                
                if (indicator && label) {
                    indicator.style.backgroundColor = service.color;
                    label.textContent = service.label;
                }
            });
        }
        
        function renderServiceAndPortStatus(services, ports) {
            const tableBody = document.getElementById('service-port-tbody');
            tableBody.innerHTML = '';
            
            // Map service names to easily find port info
            const portMap = {};
            ports.forEach(p => {
                let key = p.name.split(' ')[0].toLowerCase();
                if (key === 'wss') key = p.name.includes('TLS') ? 'wss_tls' : 'wss_http';
                if (key === 'web') key = 'wss_panel';

                portMap[key] = p;
            });
            
            const servicePortData = [
                { id: 'wss_http', name: 'WSS Proxy (HTTP)', port: '{{ wss_http_port }}', protocol: 'TCP' },
                { id: 'wss_tls', name: 'WSS Proxy (TLS)', port: '{{ wss_tls_port }}', protocol: 'TCP' },
                { id: 'stunnel4', name: 'Stunnel4 (TLS)', port: '{{ stunnel_port }}', protocol: 'TCP' },
                { id: 'udpgw', name: 'UDPGW (UDP)', port: '{{ udpgw_port }}', protocol: 'UDP' },
                { id: 'wss_panel', name: 'Web Panel (Flask)', port: '{{ panel_port }}', protocol: 'TCP' },
                { id: 'ssh_internal', name: 'SSH (Internal Forward)', port: '{{ internal_forward_port }}', protocol: 'TCP' },
            ];

            const serviceComponentMap = {
                'wss_http': 'wss', 'wss_tls': 'wss', 
                'stunnel4': 'stunnel4', 'udpgw': 'udpgw', 'wss_panel': 'wss_panel', 
                'ssh_internal': null // No restart action for SSH daemon via panel
            };

            servicePortData.forEach(item => {
                const portInfo = ports.find(p => p.port == item.port);
                const status = portInfo ? portInfo.status : 'N/A';
                const color = portInfo ? portInfo.color : '#888';
                const serviceId = serviceComponentMap[item.id];
                
                const row = document.createElement('tr');
                row.innerHTML = \`
                    <td>\${item.name}</td>
                    <td>\${item.port} (\${item.protocol})</td>
                    <td><span style="color:\${color}; font-weight: bold;">\${status}</span></td>
                    <td>
                        \${serviceId ? \`<button class="action-btn" onclick="restartService('\${serviceId}')">重启</button>\` : 'N/A'}
                    </td>
                \`;
                tableBody.appendChild(row);
            });
        }

        async function restartService(serviceId) {
            if (window.prompt(\`确定要重启 \${serviceId} 服务吗? (输入 YES 确认)\`) !== 'YES') {
                return;
            }
            
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
                    // Give services time to restart before refreshing status
                    setTimeout(refreshMonitorData, 3000); 
                } else {
                    showStatus('重启失败: ' + (result.message || '未知错误'), false);
                    setTimeout(refreshMonitorData, 3000);
                }
            } catch (error) {
                showStatus('请求重启 API 失败，请检查面板运行状态。', false);
            }
        }
        
        async function fetchLogs() {
            try {
                const response = await fetch('/api/logs');
                const data = await response.json();
                
                if (response.ok) {
                    const logContent = document.getElementById('log-pre-content');
                    logContent.textContent = ''; // Clear previous content
                    
                    // Combine all logs into one scrollable view
                    const logKeys = Object.keys(data.logs);
                    let combinedLog = '';
                    
                    logKeys.forEach(key => {
                        // Prepend a separator for clarity
                        combinedLog += \`\n================= \${key} =================\n\`;
                        // Use slice to ensure last 50 lines focus (already filtered on server side)
                        combinedLog += data.logs[key];
                    });
                    
                    logContent.textContent = combinedLog.trim();
                    logContent.scrollTop = logContent.scrollHeight; // Auto scroll to bottom
                    
                    // showStatus('最新系统日志已加载。', true); // Silence frequent success message
                } else {
                    showStatus('获取日志失败: ' + (data.message || '未知错误'), false);
                }
            } catch (error) {
                console.error("Log fetch error:", error);
                // showStatus('请求日志 API 失败，请检查面板运行状态。', false); // Silence error for continuous polling
            }
        }


        // --- Existing User Management Logic (Kept for completeness) ---

        document.getElementById('add-user-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            const username = document.getElementById('new-username').value.trim();
            const password = document.getElementById('new-password').value;

            if (!username || !password) {
                showStatus('用户名和密码不能为空。', false);
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

        async function deleteUser(username) {
            // 修正: 确保模板字面量在 bash heredoc 中正确转义 \` 和 \$\{
            if (window.prompt(\`确定要删除用户 \$\{username\} 吗? (输入 YES 确认)\`) !== 'YES') { 
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
                    const row = document.getElementById(\`row-\$\{username\}\`);
                    if (row) row.remove();
                    
                    const countEl = document.getElementById('user-count');
                    countEl.textContent = parseInt(countEl.textContent) - 1;
                } else {
                    showStatus('删除失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
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
    return make_response(html)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))


# --- Existing API Routes (Kept for completeness) ---

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
    if get_user(username):
        return jsonify({"success": False, "message": f"用户 {username} 已存在于面板"}), 409

    # 1. 创建系统用户 (使用 -s /bin/false 禁用远程 shell 登录，增加安全性)
    success, output = safe_run_command(['useradd', '-m', '-s', '/bin/false', username])
    if not success:
        return jsonify({"success": False, "message": f"创建系统用户失败: {output}"}), 500

    # 2. 设置密码
    chpasswd_input = f"{username}:{password_raw}"
    # 使用 full path for robustness and pass input as bytes
    success, output = safe_run_command(['/usr/sbin/chpasswd'], input=chpasswd_input.encode('utf-8'))
    if not success:
        # 如果设置密码失败，尝试删除已创建的系统用户
        safe_run_command(['userdel', '-r', username])
        return jsonify({"success": False, "message": f"设置密码失败: {output}"}), 500
        
    # 3. 记录到 JSON 数据库
    new_user = {
        "username": username,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "status": "active"
    }
    users.append(new_user)
    save_users(users)

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
    user_to_delete = get_user(username)

    if not user_to_delete:
        return jsonify({"success": False, "message": f"面板中用户 {username} 不存在"}), 404

    # 1. 删除系统用户及其主目录
    success, output = safe_run_command(['userdel', '-r', username])
    if not success:
        print(f"Warning: Failed to delete system user {username}: {output}")

    # 2. 从 JSON 数据库中删除记录
    users = [user for user in users if user['username'] != username]
    save_users(users)

    return jsonify({"success": True, "message": f"用户 {username} 已删除"})


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
systemctl start wss_panel
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
