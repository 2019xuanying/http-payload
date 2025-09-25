#!/usr/bin/env bash

set -e

# =============================
#  用户自定义端口
# =============================
read -p "请输入 WSS 监听端口（默认80）: " WSS_PORT
WSS_PORT=${WSS_PORT:-80}

read -p "请输入 Stunnel 端口（默认443）: " TUNNEL4_PORT
TUNNEL4_PORT=${TUNNEL4_PORT:-443}

echo "WSS端口: $WSS_PORT"
echo "Stunnel端口: $TUNNEL4_PORT"
echo "----------------------------------"

# =============================
#  系统更新和依赖安装 (CentOS 版本)
# =============================
echo "==== 更新系统 & 安装依赖 ===="
sudo yum update -y
# 安装 EPEL 仓库，提供 stunnel 包
sudo yum install -y epel-release
sudo yum install -y python3 python3-pip wget curl git net-tools cmake openssl stunnel
echo "依赖安装完成."
echo "----------------------------------"

# =============================
#  创建 WSS 脚本
# =============================
echo "==== 创建 WSS 脚本 ===="
WSS_FILE="/usr/local/bin/wss"
cat <<EOF | sudo tee $WSS_FILE > /dev/null
#!/usr/bin/env python3
import socket, threading, select, sys, time

LISTEN_ADDR = '0.0.0.0'
LISTEN_PORT = $WSS_PORT
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:22'
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
