#!/bin/bash
set -e

# =============================
# 提示端口
# =============================
echo "==== 端口配置 (请根据需要输入或使用默认值) ===="
read -p "1. SSH 监听端口（内部转发目标，默认为41816）：" SSH_PORT
SSH_PORT=${SSH_PORT:-41816}

read -p "2. WSS 监听端口（面向公网/SSH-HTTP-Payload，默认80）：" WSS_PORT
WSS_PORT=${WSS_PORT:-80}

read -p "3. Stunnel4 端口（面向公网/SSH-TLS，默认443）：" STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-443}

read -p "4. WSS-TLS 端口（面向公网/SSH-TLS-HTTP-Payload，默认444）：" WSS_TLS_PORT
WSS_TLS_PORT=${WSS_TLS_PORT:-444}

read -p "5. UDPGW 端口（仅本地监听，默认7300）：" UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}
echo "------------------------------------------------"

# =============================
# 权限管理与依赖安装
# =============================
TUNNEL_USER="tunneluser"
echo "==== 配置非特权用户 $TUNNEL_USER ===="
if ! id "$TUNNEL_USER" &>/dev/null; then
    sudo useradd -r -s /sbin/nologin "$TUNNEL_USER"
    echo "创建非特权用户 $TUNNEL_USER 成功."
else
    echo "用户 $TUNNEL_USER 已存在."
fi
echo "----------------------------------"

echo "==== 更新系统并安装依赖 ===="
sudo apt update -y
sudo apt install -y python3 python3-pip wget curl git cmake build-essential openssl stunnel4
echo "依赖安装完成"
echo "----------------------------------"

# =============================
# 1. 安装 WSS 脚本 (已修复 EOF 错误)
# 策略: 使用单引号HereDoc + sed 注入变量，确保Bash解析正确
# =============================
echo "==== 安装 WSS 脚本 (Python) ===="

# 步骤 1: 使用单引号 HereDoc 创建临时文件，阻止 Bash 解析内部语法
sudo tee /usr/local/bin/wss_temp > /dev/null <<'EOF'
#!/usr/bin/python3
# Python Proxy (WSS/HTTP Simulation) - Author: Zink
import socket, threading, select, sys, time

# Configurations
LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80
PASS = ''
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:__SSH_PORT__' # 占位符
RESPONSE = 'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 104857600000\r\n\r\n'

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
        self.soc.settimeout(2)
        try:
            self.soc.bind((self.host, int(self.port)))
            self.soc.listen(0)
            self.running = True
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue
                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        except Exception as e:
            print(f"Server error on port {self.port}: {e}")
        finally:
            self.running = False
            self.soc.close()
    def printLog(self, log):
        self.logLock.acquire()
        print(log)
        self.logLock.release()
    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()
    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()
    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()
            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = b''
        self.server = server
        self.log = 'Connection: ' + str(addr)
    def close(self):
        try:
            if not self.clientClosed:
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True
        try:
            if not self.targetClosed:
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True
    def run(self):
        try:
            self.client.settimeout(TIMEOUT)
            self.client_buffer = self.client.recv(BUFLEN)
            
            head = self.client_buffer.decode('utf-8', errors='ignore')

            hostPort = self.findHeader(head, 'X-Real-Host')
            if hostPort == '':
                hostPort = DEFAULT_HOST
            
            passwd = self.findHeader(head, 'X-Pass')
            if len(PASS) != 0 and passwd != PASS:
                self.client.send(b'HTTP/1.1 400 WrongPass!\r\n\r\n')
                return

            self.method_CONNECT(hostPort)
        except Exception as e:
            self.log += ' - error: ' + str(e)
            self.server.printLog(self.log)
        finally:
            self.close()
            self.server.removeConn(self)
    
    def findHeader(self, head, header):
        aux = head.find(header + ': ')
        if aux == -1:
            return ''
        aux = head.find(':', aux)
        head = head[aux + 2:]
        aux = head.find('\r\n')
        if aux == -1:
            return ''
        return head[:aux].strip()

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i + 1:])
            host = host[:i]
        else:
            port = int(DEFAULT_HOST.split(':')[-1]) 

        self.target = socket.create_connection((host, port), timeout=TIMEOUT)
        self.targetClosed = False

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path
        self.connect_target(path)
        self.client.sendall(RESPONSE.encode('utf-8'))
        self.server.printLog(self.log)
        self.doCONNECT()
    
    def doCONNECT(self):
        socs = [self.client, self.target]
        error = False
        last_activity = time.time()
        
        while time.time() - last_activity < TIMEOUT:
            (recv, _, err) = select.select(socs, [], socs, 1)
            
            if err:
                error = True
                break
            
            if recv:
                last_activity = time.time()
                for in_ in recv:
                    try:
                        data = in_.recv(BUFLEN)
                        if data:
                            if in_ is self.target:
                                self.client.send(data)
                            else:
                                self.target.sendall(data)
                        else:
                            error = True
                            break
                    except Exception as e:
                        error = True
                        break
            
            if error:
                break

def main():
    if len(sys.argv) > 1:
        global LISTENING_PORT
        LISTENING_PORT = int(sys.argv[1])
    
    print("\n:-------PythonProxy WSS-------:")
    print(f"Listening addr: {LISTENING_ADDR}, port: {LISTENING_PORT}, Default Target: {DEFAULT_HOST}\n")
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        print('Stopping...')
    finally:
        server.close()

if __name__ == '__main__':
    main()
EOF

# 步骤 2: 使用 sed 注入 $SSH_PORT 变量到正式文件
sudo sed "s/__SSH_PORT__/$SSH_PORT/g" /usr/local/bin/wss_temp | sudo tee /usr/local/bin/wss > /dev/null
sudo rm /usr/local/bin/wss_temp

sudo chmod +x /usr/local/bin/wss

# WSS Systemd Service
sudo tee /etc/systemd/system/wss.service > /dev/null <<EOF
[Unit]
Description=WSS Python Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wss $WSS_PORT
Restart=on-failure
User=$TUNNEL_USER
Group=$TUNNEL_USER

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable wss
sudo systemctl restart wss
echo "WSS 已启动，端口 $WSS_PORT，转发目标端口 $SSH_PORT"
echo "----------------------------------"

# =============================
# 2. 安装 Stunnel4 (SSH-TLS & SSH-TLS-Payload)
# =============================
echo "==== 安装 Stunnel4 (双模式配置) ===="
COUNTRY="US"
STATE="California"
CITY="Mountain View"
ORG="MyTunnel Service"
CN="$(hostname)"

sudo mkdir -p /etc/stunnel/certs
sudo openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 1095 \
-subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=$CN"

sudo sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
sudo chmod 600 /etc/stunnel/certs/stunnel.key
echo "自签名证书生成完成"

# Stunnel 配置包含两个服务: 
# 1. ssh-tls-raw (SSH-TLS) -> 转发到 $SSH_PORT
# 2. ssh-tls-wss (SSH-TLS-HTTP-Payload) -> 转发到 $WSS_PORT
sudo tee /etc/stunnel/multitunnel.conf > /dev/null <<EOF
pid=/var/run/stunnel.pid
client = no
debug = 5
output = /var/log/stunnel4/stunnel.log
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

# --- 1. SSH-TLS (将 TLS 流量直接转发到 SSH 端口) ---
[ssh-tls-raw]
accept = 0.0.0.0:$STUNNEL_PORT
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
connect = 127.0.0.1:$SSH_PORT

# --- 2. SSH-TLS-HTTP-Payload (将 TLS 流量转发到 WSS 端口) ---
[ssh-tls-wss]
accept = 0.0.0.0:$WSS_TLS_PORT
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
connect = 127.0.0.1:$WSS_PORT
EOF

# 修改 stunnel4 启动配置，使用新的配置文件
sudo systemctl disable stunnel4
sudo sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4
# 确保 FILES 变量设置正确
if ! grep -q "FILES=" /etc/default/stunnel4; then
    sudo sh -c 'echo "FILES=\"/etc/stunnel/multitunnel.conf\"" >> /etc/default/stunnel4'
else
    sudo sed -i 's/^FILES=.*$/FILES="\/etc\/stunnel\/multitunnel.conf"/' /etc/default/stunnel4
fi


sudo systemctl daemon-reload
sudo systemctl enable stunnel4
sudo systemctl restart stunnel4
echo "Stunnel4 配置完成，SSH-TLS 端口 $STUNNEL_PORT，WSS-TLS 端口 $WSS_TLS_PORT"
echo "----------------------------------"

# =============================
# 3. 安装 UDPGW
# =============================
echo "==== 安装 UDPGW (Badvpn) ===="
UDPGW_DIR="/usr/local/src/badvpn"
BUILD_DIR="${UDPGW_DIR}/badvpn-build"

if [ -d "${UDPGW_DIR}" ]; then
    echo "badvpn 源码目录已存在，跳过克隆"
else
    git clone https://github.com/ambrop72/badvpn.git "${UDPGW_DIR}"
fi

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

echo "开始编译 badvpn-udpgw..."
cmake "${UDPGW_DIR}" -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make -j$(nproc)

# 复制可执行文件到标准路径
sudo cp "${BUILD_DIR}/udpgw/badvpn-udpgw" /usr/local/bin/

# 创建 systemd 服务
sudo tee /etc/systemd/system/udpgw.service > /dev/null <<EOF
[Unit]
Description=UDP Gateway (Badvpn)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:$UDPGW_PORT --max-clients 1024 --max-connections-for-client 10
Restart=on-failure
User=$TUNNEL_USER
Group=$TUNNEL_USER

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable udpgw
sudo systemctl start udpgw
echo "UDPGW 已安装并启动，端口: $UDPGW_PORT (仅限本地访问)"
echo "----------------------------------"

echo "所有组件安装完成!"
echo "--- 总结 ---"
echo "SSH 裸协议端口 (sshd): $SSH_PORT"
echo "SSH-HTTP-Payload 端口 (WSS): $WSS_PORT"
echo "SSH-TLS 端口 (Stunnel4): $STUNNEL_PORT"
echo "SSH-TLS-HTTP-Payload 端口 (Stunnel4+WSS): $WSS_TLS_PORT"
echo "UDPGW 端口 (Badvpn): $UDPGW_PORT (仅本地)"
echo ""
echo "请确保防火墙 (ufw/安全组) 已开放端口 $WSS_PORT, $STUNNEL_PORT, 和 $WSS_TLS_PORT。"
