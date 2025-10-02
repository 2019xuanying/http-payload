#!/usr/bin/env bash
set -eu

# ==========================================================
# WSS 隧道与用户管理面板一键部署脚本 (V3 - 最终功能修复)
# ----------------------------------------------------------
# FIX: 修复 safe_run_command 中的 TypeError，确保参数正确传递。
# ==========================================================

# =============================
# 提示端口和面板密码 (保留上次设置)
# =============================
echo "----------------------------------"
echo "==== WSS 基础设施端口配置 (使用上次设置) ===="
read -p "请输入 WSS HTTP 监听端口 (默认80): " WSS_HTTP_PORT
WSS_HTTP_PORT=${WSS_HTTP_PORT:-80}

read -p "请输入 WSS TLS 监听端口 (默认443): " WSS_TLS_PORT
WSS_TLS_PORT=${WSS_TLS_PORT:-443}

read -p "请输入 Stunnel4 端口 (默认444): " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-444}

read -p "请输入 UDPGW 端口 (默认7300): " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

echo "----------------------------------"
echo "==== 管理面板配置 (使用上次设置) ===="
read -p "请输入 Web 管理面板监听端口 (默认8080): " PANEL_PORT
PANEL_PORT=${PANEL_PORT:-8080}

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
  PANEL_ROOT_PASS_HASH=$(echo -n "$PANEL_ROOT_PASS_RAW" | sha256sum | awk '{print $1}')
  break
done

echo "----------------------------------"
echo "==== 依赖检查与 IPTables 验证 ===="
apt update -y
apt install -y python3 python3-pip iptables iptables-persistent || true
pip3 install flask jinja2
echo "依赖检查完成"

# IPTables 流量监控初始化 (确保规则存在)
iptables -N WSS_USER_TRAFFIC || true
iptables -F WSS_USER_TRAFFIC || true
if ! iptables -C FORWARD -j WSS_USER_TRAFFIC 2>/dev/null; then
    iptables -I FORWARD -j WSS_USER_TRAFFIC
fi
iptables -A WSS_USER_TRAFFIC -j ACCEPT || true
netfilter-persistent save || true
echo "IPTables 规则检查完成。"
echo "----------------------------------"

# =============================
# 安装 WSS 用户管理面板 (基于 Flask) - V3 核心修复
# =============================
echo "==== 部署 WSS 用户管理面板 (Python/Flask) V3 最终功能修复版 ===="
PANEL_DIR="/etc/wss-panel"
USER_DB="$PANEL_DIR/users.json"
mkdir -p "$PANEL_DIR"

if [ ! -f "$USER_DB" ]; then
    echo "[]" > "$USER_DB"
fi

# 嵌入 Python 面板代码 (修复 safe_run_command)
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
import logging

# --- 配置 ---
USER_DB_PATH = "$USER_DB"
ROOT_USERNAME = "root"
ROOT_PASSWORD_HASH = "$PANEL_ROOT_PASS_HASH"
FLASK_SECRET_KEY = os.urandom(24).hex()
IPTABLES_CHAIN = "WSS_USER_TRAFFIC" 

# 面板和端口配置
PANEL_PORT = "$PANEL_PORT"
WSS_HTTP_PORT = "$WSS_HTTP_PORT"
WSS_TLS_PORT = "$WSS_TLS_PORT"
STUNNEL_PORT = "$STUNNEL_PORT"
UDPGW_PORT = "$UDPGW_PORT"

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# --- 日志配置 ---
LOG_FILE = '/var/log/wss_panel_debug.log'
logging.basicConfig(filename=LOG_FILE, level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')
try:
    if not os.path.exists('/var/log/'):
        os.makedirs('/var/log/')
    open(LOG_FILE, 'a').close()
except Exception as e:
    print(f"WARNING: Could not open log file {LOG_FILE}: {e}")

# --- 认证装饰器 ---

def login_required(f):
    """检查用户是否已登录."""
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# --- 数据库操作 ---

def load_users():
    """从 JSON 文件加载用户列表."""
    if not os.path.exists(USER_DB_PATH):
        return []
    try:
        with open(USER_DB_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []
    except Exception as e:
        logging.error(f"Error loading users.json: {e}")
        return []

def save_users(users):
    """保存用户列表到 JSON 文件."""
    try:
        with open(USER_DB_PATH, 'w') as f:
            json.dump(users, f, indent=4)
    except Exception as e:
        logging.error(f"Error saving users.json: {e}")

def get_user(username):
    """按用户名查找用户对象和索引."""
    users = load_users()
    for i, user in enumerate(users):
        if user['username'] == username:
            return user, i
    return None, -1

# --- 系统工具函数 (FIXED: 接受可选的 check 参数，并默认为 True) ---

def safe_run_command(command, input=None, check=True):
    """安全执行系统命令并返回结果."""
    try:
        result = subprocess.run(
            command,
            check=check, # 传递给 subprocess.run
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=input, 
            timeout=5
        )
        return True, result.stdout.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.decode('utf-8').strip()
        logging.error(f"Command failed: {' '.join(command)}. Exit Code: {e.returncode}. Stderr: {stderr_output}")
        return False, stderr_output
    except Exception as e:
        logging.error(f"Command execution error for {' '.join(command)}: {e}")
        return False, str(e)

def get_user_uid(username):
    """获取系统用户的 UID."""
    success, uid = safe_run_command(['/usr/bin/id', '-u', username], check=False) # 明确不检查，因为用户可能不存在
    return int(uid) if success and uid.isdigit() else None

# --- IPTables 流量管理函数 ---

def apply_iptables_rules(users):
    """根据活动用户动态生成并应用 IPTables 规则."""
    IPTABLES_CMD = ['/sbin/iptables'] 
    
    # 使用 check=False 允许链不存在时跳过
    safe_run_command(IPTABLES_CMD + ['-N', IPTABLES_CHAIN], check=False) 
    safe_run_command(IPTABLES_CMD + ['-F', IPTABLES_CHAIN]) 
    
    for user in users:
        if user.get('status') == 'active':
            uid = get_user_uid(user['username'])
            if uid is not None:
                rule_spec = ['-m', 'owner', '--uid-owner', str(uid), '-j', 'RETURN']
                safe_run_command(IPTABLES_CMD + ['-A', IPTABLES_CHAIN] + rule_spec)

    safe_run_command(IPTABLES_CMD + ['-A', IPTABLES_CHAIN, '-j', 'ACCEPT']) # 接受剩余流量
    safe_run_command(['/usr/sbin/netfilter-persistent', 'save'], check=False) # 尝试保存规则


def get_traffic_usage(username):
    """从 IPTables 中读取用户的实时流量 (GB)."""
    uid = get_user_uid(username)
    if uid is None: return 0.0

    IPTABLES_CMD = ['/sbin/iptables'] 
    cmd = IPTABLES_CMD + ['-L', IPTABLES_CHAIN, '-v', '-x', '-n']
    # 允许此命令失败 (例如链不存在)
    success, output = safe_run_command(cmd, check=False) 

    if success:
        for line in output.split('\n'):
            if f'uid-owner {uid}' in line:
                try:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        bytes_used = int(parts[1])
                        return bytes_used / (1024 * 1024 * 1024) 
                except ValueError:
                    logging.error(f"Failed to parse traffic usage line for {username}: {line}")
                    pass
    return 0.0 


def reset_iptables_counter(username):
    """重置 IPTables 中用户的流量计数器."""
    uid = get_user_uid(username)
    if uid is None: return False

    IPTABLES_CMD = ['/sbin/iptables'] 
    rule_spec = ['-m', 'owner', '--uid-owner', str(uid), '-j', 'RETURN']
    
    # 使用 check=False，因为删除不存在的规则会失败，但这不是致命错误
    safe_run_command(IPTABLES_CMD + ['-D', IPTABLES_CHAIN] + rule_spec, check=False)
    success_add, _ = safe_run_command(IPTABLES_CMD + ['-A', IPTABLES_CHAIN] + rule_spec) # 重新添加必须成功

    return success_add

# --- 核心用户状态管理函数 ---

def sync_user_status(user):
    """检查并同步用户的到期日、流量配额状态到系统 (chage, usermod)."""
    username = user['username']
    
    is_expired = False
    if user.get('expiry_date'):
        try:
            expiry_dt = datetime.strptime(user['expiry_date'], '%Y-%m-%d')
            if expiry_dt.date() < datetime.now().date():
                is_expired = True
        except ValueError:
            logging.error(f"Invalid expiry date format for {username}: {user['expiry_date']}")
            pass
    
    is_quota_exceeded = user.get('quota_gb', 0.0) > 0.0 and user.get('used_traffic_gb', 0.0) >= user.get('quota_gb', 0.0)
        
    current_status = user.get('status', 'active')
    should_be_paused = (current_status == 'paused') or is_expired or is_quota_exceeded
    
    USERMOD_CMD = ['/usr/sbin/usermod']
    CHAGE_CMD = ['/usr/bin/chage']

    if should_be_paused:
        safe_run_command(USERMOD_CMD + ['-L', username], check=False)
        safe_run_command(CHAGE_CMD + ['-E', '1970-01-01', username], check=False)
        user['status'] = 'paused' 
    else:
        safe_run_command(USERMOD_CMD + ['-U', username], check=False) 
        
        if user.get('expiry_date'):
            safe_run_command(CHAGE_CMD + ['-E', user['expiry_date'], username], check=False) 
        else:
            safe_run_command(CHAGE_CMD + ['-E', '', username], check=False) 
        user['status'] = 'active'
        
    return user


def refresh_all_user_status(users):
    """批量同步用户状态，并更新流量数据."""
    
    apply_iptables_rules(users) 

    updated = False
    for i, user in enumerate(users):
        current_usage_gb = get_traffic_usage(user['username'])
        
        if abs(current_usage_gb - user.get('used_traffic_gb', 0.0)) > 0.001:
            users[i]['used_traffic_gb'] = current_usage_gb
            updated = True
            
        users[i] = sync_user_status(users[i])
        
        quota_gb = users[i].get('quota_gb', 0.0)
        used_traffic_gb = users[i].get('used_traffic_gb', 0.0)

        users[i]['traffic_display'] = f"{used_traffic_gb:.2f} / {quota_gb:.2f} GB"
        
        status_text = "Active"
        status_class = "bg-green-500"
        
        if users[i]['status'] == 'paused':
            status_text = "Paused"
            status_class = "bg-yellow-500"
        elif quota_gb > 0 and used_traffic_gb >= quota_gb:
            status_text = "Exceeded"
            status_class = "bg-red-500"
        elif users[i].get('expiry_date'):
            try:
                if datetime.strptime(users[i]['expiry_date'], '%Y-%m-%d').date() < datetime.now().date():
                    status_text = "Expired"
                    status_class = "bg-red-500"
            except:
                pass
            
        users[i]['status_text'] = status_text
        users[i]['status_class'] = status_class
        
    if updated:
        save_users(users)
    return users


# --- HTML 模板和渲染 ---

# 仪表盘 HTML (内嵌 - 使用 Tailwind)
_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS Panel - 仪表盘 V3</title>
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
            <h1 class="text-3xl font-bold">WSS 隧道管理面板 V3</h1>
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
                <p><span class="font-bold text-red-600">注意:</span> 认证方式为 **SSH 账户/密码**。流量通过 IPTables 监控并计费。</p>
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
            <h3 class="text-xl font-semibold text-gray-800 mb-4">用户列表 (实时流量)</h3>
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
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2">
                                <button onclick="toggleUserStatus('{{ user.username }}', '{{ 'pause' if user.status_text == 'Active' else 'active' }}')" 
                                        class="text-xs px-3 py-1 rounded-full font-bold {{ 'bg-yellow-100 text-yellow-800 hover:bg-yellow-200' if user.status_text == 'Active' else 'bg-green-100 text-green-800 hover:bg-green-200' }} btn-action">
                                    {{ '暂停' if user.status_text == 'Active' else '启用' }}
                                </button>
                                <button onclick="openQuotaModal('{{ user.username }}', '{{ user.quota_gb }}', '{{ user.expiry_date }}')" 
                                        class="text-xs px-3 py-1 rounded-full font-bold bg-blue-100 text-blue-800 hover:bg-blue-200 btn-action">
                                    配额/到期
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
            <p class="mt-4 text-sm text-gray-500 border-t pt-2">
                * **流量提示**: 流量数据为 IPTables 实时统计值。每次访问面板时会自动更新和检查配额。
            </p>
        </div>

    </div>
    
    <!-- Modal for Quota and Expiry -->
    <div id="quota-modal" class="modal fixed inset-0 flex items-center justify-center p-4 hidden">
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-lg">
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

                    <div class="flex justify-start space-x-3 mb-4">
                        <button type="button" onclick="resetTraffic()" class="text-xs px-3 py-1 rounded-lg font-bold bg-purple-100 text-purple-800 hover:bg-purple-200 btn-action">
                            重置流量
                        </button>
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

    <script>
        function showStatus(message, isSuccess) {
            const statusDiv = document.getElementById('status-message');
            statusDiv.textContent = message;
            statusDiv.className = \`\${isSuccess ? 'bg-green-100 text-green-800 border border-green-300' : 'bg-red-100 text-red-800 border border-red-300'} p-4 mb-4 rounded-lg font-semibold\`;
            statusDiv.classList.remove('hidden');
            window.scrollTo(0, 0);
            setTimeout(() => { statusDiv.classList.add('hidden'); }, 5000);
        }

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
            if (window.prompt(\`确定要\${actionText}用户 \${username} 吗? (输入 \${actionText.toUpperCase()} 确认)\`) !== actionText.toUpperCase()) {
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

        async function deleteUser(username) {
            if (window.prompt(\`确定要删除用户 \${username} 吗? (输入 DELETE 确认)\`) !== 'DELETE') {
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

        async function resetTraffic() {
            const username = document.getElementById('modal-username').value;
             if (window.prompt(\`确定要重置用户 \${username} 的流量计数吗? (输入 RESET 确认)\`) !== 'RESET') {
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
                    closeQuotaModal();
                    location.reload(); 
                } else {
                    showStatus('重置流量失败: ' + result.message, false);
                }
            } catch (error) {
                showStatus('请求失败，请检查面板运行状态。', false);
            }
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
        
        function logout() {
            window.location.href = '/logout';
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


# --- Web 路由 ---

@app.route('/', methods=['GET'])
@login_required
def dashboard():
    try:
        users = load_users()
        users = refresh_all_user_status(users)
        html_content = render_dashboard(users=users)
        return make_response(html_content)
    except Exception as e:
        # 记录完整的堆栈信息
        logging.exception("Dashboard (/) route failed during execution.")
        # 返回一个包含日志路径的友好提示
        return f"Internal Server Error. The application encountered an error. Please check the debug log at: {LOG_FILE}", 500


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
        <h1 class="text-2xl">WSS 管理面板 V3</h1>
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

    USERADD_CMD = ['/usr/sbin/useradd']
    CHPASSWD_CMD = ['/usr/sbin/chpasswd']
    USERDEL_CMD = ['/usr/sbin/userdel']


    success, output = safe_run_command(USERADD_CMD + ['-m', '-s', '/bin/false', username])
    if not success:
        return jsonify({"success": False, "message": f"创建系统用户失败: {output}"}), 500

    chpasswd_input = f"{username}:{password_raw}"
    success, output = safe_run_command(CHPASSWD_CMD, input=chpasswd_input.encode('utf-8'))
    if not success:
        safe_run_command(USERDEL_CMD + ['-r', username])
        return jsonify({"success": False, "message": f"设置密码失败: {output}"}), 500
        
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
    
    new_user = sync_user_status(new_user) 
    apply_iptables_rules(users) 

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
    
    USERDEL_CMD = ['/usr/sbin/userdel']

    safe_run_command(USERDEL_CMD + ['-r', username], check=False)

    users.pop(index)
    save_users(users)
    
    apply_iptables_rules(users)

    return jsonify({"success": True, "message": f"用户 {username} 已删除"})

@app.route('/api/users/status', methods=['POST'])
@login_required
def toggle_user_status_api():
    """启用/暂停用户 (API)"""
    data = request.json
    username = data.get('username')
    action = data.get('action') 

    user, index = get_user(username)
    if not user:
        return jsonify({"success": False, "message": f"用户 {username} 不存在"}), 404
        
    users = load_users()

    if action == 'pause':
        users[index]['status'] = 'paused'
        message = f"用户 {username} 已暂停"
    elif action == 'active':
        users[index]['status'] = 'active'
        message = f"用户 {username} 已启用"
    else:
        return jsonify({"success": False, "message": "无效的操作参数"}), 400

    users[index] = sync_user_status(users[index])
    save_users(users)
    apply_iptables_rules(users)

    return jsonify({"success": True, "message": message})


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
    
    try:
        quota_gb = max(0.0, float(quota_gb))
        if expiry_date:
            datetime.strptime(expiry_date, '%Y-%m-%d')
    except ValueError:
        return jsonify({"success": False, "message": "配额或日期格式不正确"}), 400

    users[index]['quota_gb'] = quota_gb
    users[index]['expiry_date'] = expiry_date
    
    users[index] = sync_user_status(users[index])
    
    save_users(users)
    apply_iptables_rules(users) 

    return jsonify({"success": True, "message": f"用户 {username} 设置已更新"})
    
@app.route('/api/users/reset_traffic', methods=['POST'])
@login_required
def reset_traffic_api():
    """重置用户流量 (API)"""
    data = request.json
    username = data.get('username')

    user, index = get_user(username)
    if not user:
        return jsonify({"success": False, "message": f"用户 {username} 不存在"}), 404
        
    users = load_users()

    if not reset_iptables_counter(username):
         return jsonify({"success": False, "message": f"重置 IPTables 计数器失败，请检查 IPTables 状态。"}), 500

    users[index]['used_traffic_gb'] = 0.0
    
    if users[index]['status'] == 'paused':
        users[index]['status'] = 'active'
    
    users[index] = sync_user_status(users[index])
    save_users(users)

    return jsonify({"success": True, "message": f"用户 {username} 流量已重置并尝试启用"})


if __name__ == '__main__':
    print(f"WSS Panel running on port {PANEL_PORT}")
    app.run(host='0.0.0.0', port=int(PANEL_PORT), debug=False)
EOF

chmod +x /usr/local/bin/wss_panel.py

# =============================
# 重启 WSS 面板 systemd 服务
# =============================
systemctl daemon-reload
systemctl enable wss_panel || true
systemctl restart wss_panel
echo "WSS 管理面板 V3 最终功能修复版已启动/重启，端口 $PANEL_PORT"
echo "----------------------------------"

echo "=================================================="
echo "✅ 部署完成！"
echo "=================================================="
echo ""
echo "请再次访问 Web 面板进行登录。"
echo ""
echo "如果这次成功，你将看到仪表盘。如果仍有错误，请提供 **新的** 日志内容："
echo "命令: sudo cat /var/log/wss_panel_debug.log"
echo "=================================================="
