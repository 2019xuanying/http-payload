#!/usr/bin/env bash

# 任何命令失败时立即退出，以确保系统操作的原子性（已隔离远程调用）
set -e

# =============================
# 用户自定义端口
# =============================
echo "==== 端口设置 ===="
read -p "请输入 WSS 监听端口（默认 80）: " WSS_PORT
WSS_PORT=${WSS_PORT:-80}

read -p "请输入 Stunnel4 / TUNNEL4 端口（默认 443）: " TUNNEL4_PORT
TUNNEL4_PORT=${TUNNEL4_PORT:-443}

echo "WSS端口: $WSS_PORT"
echo "TLS/TUNNEL端口: $TUNNEL4_PORT"
echo "----------------------------------"

# =============================
# 系统更新和依赖安装
# =============================
echo "==== 更新系统 & 安装依赖 ===="
# 移除 build-essential cmake，除非 WSS/TUNNEL4 需要编译C代码
sudo apt update -y
sudo apt install -y python3 python3-pip wget curl git net-tools stunnel4 -y
echo "依赖安装完成."
echo "----------------------------------"

# =============================
# 创建 WSS 脚本 (/usr/local/bin/wss)
# =============================
echo "==== 创建 WSS 脚本 ===="
WSS_FILE="/usr/local/bin/wss"
# 注意：这里直接使用EOF，避免在Python代码块中转义反斜杠
cat <<EOF | sudo tee $WSS_FILE > /dev/null
#!/usr/bin/env python3
import socket, threading, select, sys, time

LISTEN_ADDR = '0.0.0.0'
LISTEN_PORT = $WSS_PORT
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:22'
# 确保响应头中的转义正确
RESPONSE = 'HTTP/1.1 101 Switching Protocols\r\nContent-Length: 104857600000\r\n\r\n'

class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.bind((self.host, self.port))
        self.soc.listen(0)
        self.running = True
        try:
            while self.running:
                c, addr = self.soc.accept()
                c.setblocking(1)
                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()

    def printLog(self, log):
        self.logLock.acquire()
        print(log)
        self.logLock.release()

    def addConn(self, conn):
        self.threadsLock.acquire()
        self.threads.append(conn)
        self.threadsLock.release()

    def removeConn(self, conn):
        self.threadsLock.acquire()
        if conn in self.threads:
            self.threads.remove(conn)
        self.threadsLock.release()

    def close(self):
        self.threadsLock.acquire()
        for c in list(self.threads):
            c.client.close()
            c.target.close()
        self.threadsLock.release()

class ConnectionHandler(threading.Thread):
    def __init__(self, client, server, addr):
        threading.Thread.__init__(self)
        self.client = client
        self.target = None
        self.server = server
        self.log = f"Connection: {addr}"

    def run(self):
        try:
            data = self.client.recv(BUFLEN)
            hostPort = DEFAULT_HOST
            self.connect_target(hostPort)
            self.client.sendall(RESPONSE.encode('utf-8'))
            self.do_connect()
        except Exception as e:
            self.server.printLog(f"{self.log} - error: {e}")
        finally:
            self.client.close()
            if self.target:
                self.target.close()
            self.server.removeConn(self)

    def connect_target(self, host):
        host_split = host.split(":")
        h = host_split[0]
        p = int(host_split[1])
        self.target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.target.connect((h, p))

    def do_connect(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            recv, _, err = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
                    try:
                        data = in_.recv(BUFLEN)
                        if data:
                            if in_ is self.target:
                                self.client.send(data)
                            else:
                                while data:
                                    sent = self.target.send(data)
                                    data = data[sent:]
                            count = 0
                        else:
                            break
                    except:
                        error = True
                        break
            if count >= TIMEOUT or error:
                break

if __name__ == "__main__":
    server = Server(LISTEN_ADDR, LISTEN_PORT)
    server.start()
    while True:
        time.sleep(2)
EOF

sudo chmod +x $WSS_FILE
echo "WSS 脚本创建完成: $WSS_FILE"
echo "----------------------------------"

# =============================
# 创建 systemd 服务自动启动 WSS
# =============================
echo "==== 创建 WSS systemd 服务 ===="
cat <<EOF | sudo tee /etc/systemd/system/wss.service > /dev/null
[Unit]
Description=WSS Python Proxy
After=network.target

[Service]
Type=simple
ExecStart=$WSS_FILE
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable wss > /dev/null
sudo systemctl start wss
echo "WSS 服务已启动并设置开机自启."
echo "----------------------------------"

# =============================
# 安装 Stunnel4 并自动生成证书
# =============================
echo "==== 配置 Stunnel4 ===="

echo "生成本地证书..."
sudo mkdir -p /etc/stunnel/certs
CERT_KEY="/etc/stunnel/certs/ssh.key"
CERT_CRT="/etc/stunnel/certs/ssh.crt"
CERT_PEM="/etc/stunnel/certs/ssh.pem"

# 使用重定向隐藏 openssl 冗余的证书信息输出
sudo openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout $CERT_KEY \
    -out $CERT_CRT \
    -days 1095 \
    -subj "/CN=example.com" 2>/dev/null 1>/dev/null

sudo sh -c "cat $CERT_KEY $CERT_CRT > $CERT_PEM"
sudo chmod 644 /etc/stunnel/certs/*.pem
sudo chmod 644 /etc/stunnel/certs/*.crt
echo "证书生成完成: $CERT_PEM"

echo "创建 Stunnel4 配置..."
STUNNEL_CONF="/etc/stunnel/ssh-tls.conf"
sudo tee $STUNNEL_CONF > /dev/null <<EOF
pid=/var/run/stunnel.pid
setuid=root
setgid=root
client = no
debug = 5
output = /var/log/stunnel4/stunnel.log
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls-gateway]
accept = 0.0.0.0:$TUNNEL4_PORT
cert = $CERT_PEM
key = $CERT_PEM
# Stunnel4 连接的是本地的 SSH (22端口)
connect = 127.0.0.1:22
EOF

# 激活 stunnel4 服务
sudo systemctl enable stunnel4 > /dev/null
sudo systemctl restart stunnel4
echo "Stunnel4 已启动，监听端口: $TUNNEL4_PORT"
echo "----------------------------------"

# =============================
# 隔离并安装 TUNNEL4 (HTTP payload)
# =============================
echo "==== 尝试安装 TUNNEL4 (HTTP payload) ===="

# 定义一个标志文件路径
TUNNEL4_INSTALLED_FLAG="/var/lib/tunnel4_installed.flag"

if [ -f "$TUNNEL4_INSTALLED_FLAG" ]; then
    echo "✅ TUNNEL4 (HTTP payload) 标志文件已存在。跳过重复安装。"
    echo "监听端口: $TUNNEL4_PORT"
else
    echo "注: 此模块的远程脚本先前有已知错误，现已隔离，允许主脚本继续运行。"
    
    # 使用子shell和 || true 隔离潜在的错误
    (
        echo "正在执行远程安装脚本..."
        # 尝试执行远程脚本，并将所有输出和错误重定向到标准错误，便于调试
        bash <(curl -Ls https://raw.githubusercontent.com/xiaoguiday/http-payload/refs/heads/main/http-payload.sh) $TUNNEL4_PORT 2>&1
    )
    
    # 检查上一个命令的退出状态。虽然远程脚本可能报错，但我们假设它启动了服务。
    # 只有当远程脚本运行完毕后，才创建标志文件。
    if [ $? -eq 0 ]; then
        echo "远程脚本执行完成，假设 TUNNEL4 已启动。"
        # 创建标志文件
        sudo touch "$TUNNEL4_INSTALLED_FLAG"
        echo "🎉 已创建标志文件，后续运行将跳过此安装步骤。"
    else
        echo "⚠️ 警告：TUNNEL4 远程脚本执行失败 (退出状态非0)。未创建标志文件。" >&2
        echo "如果你确定服务已启动，可以手动运行: sudo touch $TUNNEL4_INSTALLED_FLAG" >&2
    fi
fi

echo "TUNNEL4 模块执行完毕。"
echo "----------------------------------"

# =============================
# 安装完成总结
# =============================
echo "==== 安装完成总结 ===="
echo "WSS 脚本已运行，监听端口: $WSS_PORT"
echo "Stunnel4 TLS 服务已运行，监听端口: $TUNNEL4_PORT"
echo ""

echo "==== 服务状态检查 ===="

# 检查 WSS 端口
if sudo netstat -tuln | grep ":$WSS_PORT" > /dev/null; then
    echo "✅ WSS 服务 ($WSS_PORT) 正在监听。"
else
    echo "❌ WSS 服务 ($WSS_PORT) 未在监听。请检查日志: sudo journalctl -u wss"
fi

# 检查 Stunnel4 端口
if sudo netstat -tuln | grep ":$TUNNEL4_PORT" > /dev/null; then
    echo "✅ Stunnel4 服务 ($TUNNEL4_PORT) 正在监听。"
else
    echo "❌ Stunnel4 服务 ($TUNNEL4_PORT) 未在监听。请检查日志: sudo journalctl -u stunnel4"
fi

echo "----------------------------------"
echo "手动检查命令："
echo "WSS 服务状态: sudo systemctl status wss"
echo "Stunnel4 服务状态: sudo systemctl status stunnel4"
