#!/bin/bash
set -e

# =======================================================
# 1. 端口配置提示与输入
# =======================================================

echo "--------------------------------------------------------"
echo "  [配置开始] 请输入 SSH 后端及代理端口"
echo "--------------------------------------------------------"

# 步骤 1: 获取实际的 SSH 后端端口 (REQUIRED)
read -p "请输入 [必需] SSH 裸连接的实际后端端口 (例如 22 或 41816): " ACTUAL_SSH_PORT
if [ -z "$ACTUAL_SSH_PORT" ]; then
    echo "错误: SSH 实际后端端口不能为空。脚本将退出。"
    exit 1
fi

echo "--------------------------------------------------------"
echo "  核心 SSH 后端端口已设置为: ${ACTUAL_SSH_PORT}"
echo "--------------------------------------------------------"

# 步骤 2: 获取 WSS (SSH-Proxy-Payload) 端口
read -p "请输入 WSS (SSH-Proxy-Payload) 监听端口（默认 80）: " WSS_PORT
WSS_PORT=${WSS_PORT:-80}

# 步骤 3: 获取 Stunnel4 (SSH-TLS) 端口
read -p "请输入 Stunnel4 (SSH-TLS) 监听端口（默认 443）: " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-443}

# 步骤 4: 获取 WSS-TLS (SSH-TLS-Proxy-Payload) 端口
# WSS-TLS 将转发到 Stunnel4 端口
read -p "请输入 WSS-TLS 监听端口（用于 SSH-TLS-Payload, 默认 8080）: " WSS_TLS_PORT
WSS_TLS_PORT=${WSS_TLS_PORT:-8080}

# 步骤 5: 获取 UDPGW 端口
read -p "请输入 UDPGW 端口（默认 7300）: " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

echo "--------------------------------------------------------"
echo "  配置信息确认:"
echo "  SSH Backend Port:        ${ACTUAL_SSH_PORT}"
echo "  WSS (SSH-Payload):        ${WSS_PORT}        -> 目标: ${ACTUAL_SSH_PORT}"
echo "  Stunnel4 (SSH-TLS):      ${STUNNEL_PORT}    -> 目标: ${ACTUAL_SSH_PORT}"
echo "  WSS-TLS (SSH-TLS-Payload): ${WSS_TLS_PORT}  -> 目标: ${STUNNEL_PORT}"
echo "  UDPGW (内部转发):        ${UDPGW_PORT}"
echo "--------------------------------------------------------"


# =======================================================
# 2. 系统更新与依赖安装
# =======================================================
echo "==== 2. 更新系统并安装依赖 ===="
sudo apt update -y
sudo apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4 openssh-server
echo "依赖安装完成"
echo "----------------------------------"

# =======================================================
# 3. 安装通用 WSS 脚本 (支持动态目标端口)
# =======================================================
echo "==== 3. 安装通用 WSS 脚本 (/usr/local/bin/wss) ===="

# WSS 脚本内容 (Python) - 现在接收两个参数: LISTENING_PORT 和 TARGET_PORT
sudo tee /usr/local/bin/wss > /dev/null <<EOF
#!/usr/bin/python3
# Python WSS Proxy Script (General Purpose)
import socket, threading, select, sys, time

if len(sys.argv) < 3:
    print("Usage: wss <LISTENING_PORT> <TARGET_PORT>")
    sys.exit(1)

LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = int(sys.argv[1])
TARGET_PORT = int(sys.argv[2])

PASS = ''
BUFLEN = 4096 * 4
TIMEOUT = 60
# *** 转发目标锁定到 127.0.0.1 上的 TARGET_PORT ***
DEFAULT_HOST = '127.0.0.1:' + str(TARGET_PORT)
RESPONSE = 'HTTP/1.1 101 Switching Protocols\\r\\nContent-Length: 104857600000\\r\\n\\r\\n'

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
        except OSError as e:
            self.printLog(f"ERROR: Port {self.port} is already in use or unavailable. {e}")
            self.running = False
            return
        self.soc.listen(0)
        self.running = True
        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue
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
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True
        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True
    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)
            
            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')
            if hostPort == '':
                hostPort = DEFAULT_HOST
            
            passwd = self.findHeader(self.client_buffer, 'X-Pass')
            if len(PASS) != 0 and passwd != PASS:
                self.client.send(b'HTTP/1.1 400 WrongPass!\\r\\n\\r\\n')
                return
            
            self.method_CONNECT(hostPort)
        except Exception as e:
            self.log += ' - error: ' + str(e)
            self.server.printLog(self.log)
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        if isinstance(head, bytes):
            try:
                head = head.decode('utf-8')
            except UnicodeDecodeError:
                return ''
            
        aux = head.find(header + ': ')
        if aux == -1:
            return ''
        
        start_index = aux + len(header) + 2
        end_index = head.find('\r\n', start_index)
        
        if end_index == -1:
            return head[start_index:].strip()
        
        return head[start_index:end_index].strip()

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i + 1:])
            host = host[:i]
        else:
            port = TARGET_PORT # 使用脚本启动时传入的 TARGET_PORT
        
        try:
            (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]
        except socket.gaierror:
            self.server.printLog(f"DNS lookup failed for host: {host}")
            raise
            
        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path
        self.connect_target(path)
        self.client.sendall(RESPONSE.encode('utf-8'))
        self.client_buffer = b''
        self.server.printLog(self.log)
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            
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
                                    byte = self.target.send(data)
                                    data = data[byte:]
                            count = 0
                        else:
                            break
                    except Exception as e:
                        error = True
                        break
            
            if count == TIMEOUT:
                error = True
            
            if error:
                break

def main():
    print(f"\n:-------PythonProxy WSS-------:\n")
    print(f"Listening addr: {LISTENING_ADDR}, port: {LISTENING_PORT}, Target: {DEFAULT_HOST}\n")
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    while True:
        try:
            time.sleep(2)
            if not server.running: 
                print("WSS server failed to start. Check error log above.")
                break
        except KeyboardInterrupt:
            print('Stopping...')
            server.close()
            break

if __name__ == '__main__':
    main()
EOF

sudo chmod +x /usr/local/bin/wss
echo "通用 WSS 脚本安装完成"
echo "----------------------------------"

# =======================================================
# 4. 配置 WSS Systemd 服务 (分为 SSH-Payload 和 SSH-TLS-Payload)
# =======================================================
echo "==== 4. 配置并启动 WSS Systemd 服务 ===="

# 4a. WSS for SSH (SSH-Proxy-Payload)
sudo tee /etc/systemd/system/wss-ssh.service > /dev/null <<EOF
[Unit]
Description=WSS Proxy for SSH (Payload)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wss $WSS_PORT $ACTUAL_SSH_PORT
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

# 4b. WSS for Stunnel (SSH-TLS-Proxy-Payload)
sudo tee /etc/systemd/system/wss-tls.service > /dev/null <<EOF
[Unit]
Description=WSS Proxy for Stunnel (TLS-Payload)
After=network.target stunnel4.service

[Service]
Type=simple
ExecStart=/usr/local/bin/wss $WSS_TLS_PORT $STUNNEL_PORT
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable wss-ssh wss-tls
sudo systemctl restart wss-ssh wss-tls
echo "WSS (SSH-Payload) 已启动，端口 $WSS_PORT"
echo "WSS-TLS (SSH-TLS-Payload) 已启动，端口 $WSS_TLS_PORT"
echo "----------------------------------"


# =======================================================
# 5. 安装 Stunnel4 并生成证书 (支持 SSH-TLS)
# =======================================================
echo "==== 5. 安装 Stunnel4 ===="
sudo mkdir -p /etc/stunnel/certs
# 使用主机名生成证书
sudo openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 1095 \
-subj "/CN=$(hostname -f)"
sudo sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
sudo chmod 644 /etc/stunnel/certs/*.crt
sudo chmod 644 /etc/stunnel/certs/*.pem

# Stunnel 配置
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
# *** 转发目标锁定到实际 SSH 端口 ${ACTUAL_SSH_PORT} ***
connect = 127.0.0.1:${ACTUAL_SSH_PORT}
EOF

sudo systemctl enable stunnel4
sudo systemctl restart stunnel4
echo "Stunnel4 安装完成，端口 $STUNNEL_PORT"
echo "----------------------------------"

# =======================================================
# 6. 安装 UDPGW
# =======================================================
echo "==== 6. 安装 UDPGW ===="
if [ -d "/root/badvpn" ]; then
    echo "/root/badvpn 已存在，跳过克隆"
else
    git clone https://github.com/ambrop72/badvpn.git /root/badvpn
fi

mkdir -p /root/badvpn/badvpn-build
cd /root/badvpn/badvpn-build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make -j$(nproc)

# 创建 systemd 服务（绑定地址 127.0.0.1）
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
echo "UDPGW 已安装并启动，端口: $UDPGW_PORT"
echo "----------------------------------"

echo "=========================================================="
echo "所有组件安装完成!"
echo "----------------------------------------------------------"
echo "支持协议一览:"
echo "1. **SSH (裸连接)**:      服务器IP:${ACTUAL_SSH_PORT}"
echo "2. **SSH-TLS (Stunnel)**:     服务器IP:${STUNNEL_PORT}"
echo "3. **SSH-Proxy-Payload**:    服务器IP:${WSS_PORT}"
echo "4. **SSH-TLS-Proxy-Payload**: 服务器IP:${WSS_TLS_PORT} (WSS 转发到 Stunnel)"
echo "----------------------------------------------------------"
echo "请检查服务状态:"
echo "WSS-SSH 状态: sudo systemctl status wss-ssh"
echo "WSS-TLS 状态: sudo systemctl status wss-tls"
echo "Stunnel4 状态: sudo systemctl status stunnel4"
echo "UDPGW 状态: sudo systemctl status udpgw"
echo "=========================================================="
