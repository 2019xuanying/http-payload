#!/bin/sh

# OpenWrt Shell Script for SSH Tunnel Configuration (WSS/Stunnel4/UDPGW)

# 强制停止脚本在命令失败时继续
# OpenWrt 的 sh 可能不支持 'set -e'，但这是一个好习惯
# 替换为更兼容的方式：检查每一步的关键命令的退出状态
check_exit() {
    if [ $? -ne 0 ]; then
        echo "错误: $1 失败。脚本将退出。" >&2
        exit 1
    fi
}

# =======================================================
# 1. 端口配置提示与输入
# =======================================================
echo "--------------------------------------------------------"
echo "  [配置开始] 请输入 SSH 后端及代理端口 (OpenWrt)"
echo "--------------------------------------------------------"

# 在 OpenWrt 的 sh 环境中，使用 read -p 不一定被所有 shell 支持，
# 尤其是 BusyBox sh。这里使用 echo | read 组合，但为了保持简洁性，
# 且许多 OpenWrt 设备已使用支持 -p 的 shell，我们先保留它。

read -p "请输入 [必需] SSH 裸连接的实际后端端口 (例如 22): " ACTUAL_SSH_PORT
if [ -z "$ACTUAL_SSH_PORT" ]; then
    echo "错误: SSH 实际后端端口不能为空。脚本将退出。"
    exit 1
fi

read -p "请输入 WSS (SSH-Proxy-Payload) 监听端口（默认 80）: " WSS_PORT
WSS_PORT=${WSS_PORT:-80}

read -p "请输入 Stunnel4 (SSH-TLS) 监听端口（默认 443）: " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-443}

read -p "请输入 WSS-TLS 监听端口（用于 SSH-TLS-Payload, 默认 8080）: " WSS_TLS_PORT
WSS_TLS_PORT=${WSS_TLS_PORT:-8080}

read -p "请输入 UDPGW 端口（默认 7300）: " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

echo "--------------------------------------------------------"
echo "  配置信息确认:"
echo "  SSH Backend Port:            ${ACTUAL_SSH_PORT}"
echo "  WSS (SSH-Payload):           ${WSS_PORT}    -> 目标: ${ACTUAL_SSH_PORT}"
echo "  Stunnel4 (SSH-TLS):          ${STUNNEL_PORT}    -> 目标: ${ACTUAL_SSH_PORT}"
echo "  WSS-TLS (SSH-TLS-Payload):   ${WSS_TLS_PORT} -> 目标: ${STUNNEL_PORT}"
echo "  UDPGW (内部转发):            ${UDPGW_PORT}"
echo "--------------------------------------------------------"


# =======================================================
# 2. OpenWrt 包安装 (opkg)
# =======================================================
echo "==== 2. 更新包列表并安装依赖 ===="

# 强制更新包列表
opkg update || check_exit "opkg update"

# OpenWrt 依赖：python3, python3-pip, wget, git, openssl-util, stunnel4, openssh-server
# 注意：openssh-server 经常在 OpenWrt 上被称为 dropbear 或 openssh-server，
# 默认 OpenWrt 使用 dropbear，这里安装 openssh-server 以确保完整的 SSHD 功能（如果需要）
# dos2unix 在 OpenWrt 中是可选的，很多 BusyBox 工具集可以处理。
opkg install python3 python3-pip wget curl git openssl-util stunnel4 openssh-server make cmake gcc || check_exit "依赖安装"

echo "依赖安装完成"
echo "----------------------------------"

# =======================================================
# 3. 安装通用 WSS 脚本 (/usr/bin/wss)
# =======================================================
echo "==== 3. 安装通用 WSS 脚本 (/usr/bin/wss) ===="

# WSS 脚本内容 (Python) - 保持与原脚本一致
# 注意：在 OpenWrt 的 /usr/bin 下比 /usr/local/bin 更常见
WSS_SCRIPT="/usr/bin/wss"

# 使用 cat + EOF 来写入脚本内容，确保 OpenWrt 的 sh 兼容性
cat > "$WSS_SCRIPT" <<EOF
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
DEFAULT_HOST = '127.0.0.1:' + str(TARGET_PORT)
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
            port = TARGET_PORT
        
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
        # 核心修复：清空缓冲区，防止 Payload 头部污染 SSHD
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

# 修复权限
chmod +x "$WSS_SCRIPT"
echo "WSS 脚本安装完成"
echo "----------------------------------"

# =======================================================
# 4. 配置 WSS OpenWrt Init.d 服务
# =======================================================
echo "==== 4. 配置并启动 WSS Init.d 服务 ===="

WSS_INIT_TEMPLATE() {
cat << EOF
#!/bin/sh /etc/rc.common
# OpenWrt init.d script for $1

START=95
STOP=10

start() {
    echo "Starting $1..."
    # 使用 & 符号使进程在后台运行
    $2 &
}

stop() {
    echo "Stopping $1..."
    killall -q $3
}

# 用于 OpenWrt 的 init 脚本标准操作
boot() {
    start
}

restart() {
    stop
    start
}
EOF
}

# 4a. WSS for SSH (SSH-Proxy-Payload)
WSS_INIT_TEMPLATE "wss-ssh" "/usr/bin/python3 $WSS_SCRIPT $WSS_PORT $ACTUAL_SSH_PORT" "python3" > /etc/init.d/wss-ssh
chmod +x /etc/init.d/wss-ssh

# 4b. WSS for Stunnel (SSH-TLS-Proxy-Payload)
WSS_INIT_TEMPLATE "wss-tls" "/usr/bin/python3 $WSS_SCRIPT $WSS_TLS_PORT $STUNNEL_PORT" "python3" > /etc/init.d/wss-tls
chmod +x /etc/init.d/wss-tls

# 启动服务并设置开机自启
/etc/init.d/wss-ssh enable
/etc/init.d/wss-tls enable
/etc/init.d/wss-ssh start
/etc/init.d/wss-tls start
echo "WSS 服务配置并启动完成。"
echo "----------------------------------"


# =======================================================
# 5. 配置 Stunnel4 并生成证书
# =======================================================
echo "==== 5. 配置 Stunnel4 ===="
STUNNEL_CERT_DIR="/etc/stunnel/certs"
mkdir -p $STUNNEL_CERT_DIR
check_exit "mkdir stunnel certs"

# OpenWrt 使用 openssl-util，它通常不支持 -subj 参数，需要分步生成证书
# 生成私钥
/usr/bin/openssl genrsa -out $STUNNEL_CERT_DIR/stunnel.key 2048
check_exit "openssl genrsa"

# 生成 CSR
/usr/bin/openssl req -new -key $STUNNEL_CERT_DIR/stunnel.key -out $STUNNEL_CERT_DIR/stunnel.csr -batch
check_exit "openssl req new"

# 自签名证书
/usr/bin/openssl x509 -req -days 1095 -in $STUNNEL_CERT_DIR/stunnel.csr -signkey $STUNNEL_CERT_DIR/stunnel.key -out $STUNNEL_CERT_DIR/stunnel.crt
check_exit "openssl x509"

# 合并证书和密钥
cat $STUNNEL_CERT_DIR/stunnel.key $STUNNEL_CERT_DIR/stunnel.crt > /etc/stunnel/stunnel.pem

# Stunnel 配置
STUNNEL_CONF="/etc/stunnel/stunnel.conf" # OpenWrt 上 stunnel4 默认配置名可能是 stunnel.conf

cat > "$STUNNEL_CONF" <<EOF
pid=/var/run/stunnel.pid
setuid=root
setgid=root
client = no
debug = 5
output = /var/log/stunnel4.log # 简化日志路径
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls-gateway]
accept = 0.0.0.0:$STUNNEL_PORT
cert = /etc/stunnel/stunnel.pem
key = /etc/stunnel/stunnel.pem
# 核心修复：接受所有密码套件，绕过客户端 SSL_NULL 缺陷
ciphers = ALL
connect = 127.0.0.1:${ACTUAL_SSH_PORT}
EOF

# Stunnel init.d 服务通常由 opkg 自动安装，直接启用并重启即可
/etc/init.d/stunnel4 enable
/etc/init.d/stunnel4 restart
echo "Stunnel4 配置完成，端口 ${STUNNEL_PORT}"
echo "----------------------------------"


# =======================================================
# 6. 安装 UDPGW (在 OpenWrt 上编译)
# =======================================================
echo "==== 6. 安装 UDPGW (需要 Make 和 CMake) ===="
UDPGW_DIR="/root/badvpn"
UDPGW_BUILD_DIR="$UDPGW_DIR/badvpn-build"
UDPGW_BINARY="$UDPGW_BUILD_DIR/udpgw/badvpn-udpgw"
UDPGW_INIT_SCRIPT="/etc/init.d/udpgw"

if [ ! -d "$UDPGW_DIR" ]; then
    git clone https://github.com/ambrop72/badvpn.git $UDPGW_DIR
    check_exit "git clone badvpn"
fi

mkdir -p $UDPGW_BUILD_DIR
cd $UDPGW_BUILD_DIR

# 编译 badvpn-udpgw
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
check_exit "cmake badvpn"
make -j$(nproc)
check_exit "make badvpn-udpgw"

# 检查二进制文件是否存在
if [ ! -f "$UDPGW_BINARY" ]; then
    echo "错误: badvpn-udpgw 二进制文件未找到，编译可能失败。" >&2
    exit 1
fi
chmod +x "$UDPGW_BINARY"

# UDPGW OpenWrt Init.d 服务
cat > "$UDPGW_INIT_SCRIPT" <<EOF
#!/bin/sh /etc/rc.common
# OpenWrt init.d script for UDPGW

START=96
STOP=10
PROG="$UDPGW_BINARY"

start() {
    echo "Starting UDP Gateway..."
    # 使用 & 符号使进程在后台运行
    $PROG --listen-addr 127.0.0.1:$UDPGW_PORT --max-clients 1024 --max-connections-for-client 10 &
}

stop() {
    echo "Stopping UDP Gateway..."
    killall -q badvpn-udpgw
}

boot() {
    start
}

restart() {
    stop
    start
}
EOF
chmod +x "$UDPGW_INIT_SCRIPT"

# 启动服务
/etc/init.d/udpgw enable
/etc/init.d/udpgw start
echo "UDPGW 已安装并启动，端口: ${UDPGW_PORT}"
echo "----------------------------------"

echo "=========================================================="
echo "所有组件安装完成!"
echo "----------------------------------------------------------"
echo "支持协议一览:"
echo "1. SSH (裸连接):             服务器IP:${ACTUAL_SSH_PORT}"
echo "2. SSH-TLS:                  服务器IP:${STUNNEL_PORT}"
echo "3. **SSH-Proxy-Payload**:      服务器IP:${WSS_PORT}"
echo "4. **SSH-TLS-Proxy-Payload**:  服务器IP:${WSS_TLS_PORT}"
echo "----------------------------------------------------------"
echo "请检查服务状态 (使用 init.d 检查):"
echo "查看 WSS 状态: /etc/init.d/wss-ssh status; /etc/init.d/wss-tls status"
echo "查看 Stunnel4 状态: /etc/init.d/stunnel4 status"
echo "查看 UDPGW 状态: /etc/init.d/udpgw status"
echo "=========================================================="
