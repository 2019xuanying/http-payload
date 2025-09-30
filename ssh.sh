#!/bin/bash
set -e

# =============================
# 提示端口
# =============================
read -p "请输入 WSS HTTP 监听端口（默认80）: " WSS_HTTP_PORT
WSS_HTTP_PORT=${WSS_HTTP_PORT:-80}

read -p "请输入 WSS TLS 监听端口（默认443）: " WSS_TLS_PORT
WSS_TLS_PORT=${WSS_TLS_PORT:-443}

read -p "请输入 Stunnel4 端口（默认444）: " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-444}

read -p "请输入 UDPGW 端口（默认7300）: " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

# =============================
# 系统更新与依赖安装
# =============================
echo "==== 更新系统并安装依赖 ===="
sudo apt update -y
sudo apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4
echo "依赖安装完成"
echo "----------------------------------"

# =============================
# 安装 WSS 脚本
# =============================
echo "==== 安装 WSS 脚本 ===="
sudo tee /usr/local/bin/wss > /dev/null <<'EOF'
#!/usr/bin/python3
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio, ssl
import sys # 导入 sys 模块以处理命令行参数

LISTEN_ADDR = '0.0.0.0'

# 使用 sys.argv 获取命令行参数。如果未提供，则使用默认值
try:
    # 命令行参数从索引 1 开始
    HTTP_PORT = int(sys.argv[1])
except (IndexError, ValueError):
    HTTP_PORT = 80        # 默认 HTTP 端口

try:
    TLS_PORT = int(sys.argv[2])
except (IndexError, ValueError):
    TLS_PORT = 443        # 默认 TLS 端口

# 修正：根据用户的 SSH 端口 41816 修改默认转发目标
DEFAULT_TARGET = ('127.0.0.1', 41816) 
BUFFER_SIZE = 65536
TIMEOUT = 3600
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'
PASS = ''  # 如果需要密码验证，可填

FIRST_RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'
FORBIDDEN_RESPONSE = b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    peer = writer.get_extra_info('peername')
    print(f"Connection from {peer} {'(TLS)' if tls else ''}")
    forwarding_started = False  # 是否进入转发阶段

    try:
        # 循环处理客户端发送的 payload
        while True:
            data = await asyncio.wait_for(reader.read(BUFFER_SIZE), timeout=TIMEOUT)
            if not data:
                break

            headers = data.decode(errors='ignore') # ~ line 55

            # --- VVV 检查转发逻辑的起点 VVV ---
            
            # 使用更灵活的方式检查 WebSocket 握手头部
            is_websocket_request = False
            
            # 检查关键的 WebSocket 头部
            if 'Upgrade: websocket' in headers or 'Connection: Upgrade' in headers or 'GET-RAY' in headers:
                 is_websocket_request = True

            host_header = ''
            passwd_header = ''
            for line in headers.split('\r\n'):
                if line.startswith('X-Real-Host:'):
                    host_header = line.split(':', 1)[1].strip()
                if line.startswith('X-Pass:'):
                    passwd_header = line.split(':', 1)[1].strip()

            # 密码验证
            if PASS and passwd_header != PASS:
                writer.write(b'HTTP/1.1 400 WrongPass!\r\n\r\n')
                await writer.drain()
                break

            # 检查是否触发转发 (~ line 60)
            if not forwarding_started: # 确保这行相对于上一行有正确的缩进
                # 只要检测到是 WebSocket 升级请求，就触发转发
                if is_websocket_request:
                    # 触发转发 (返回 101 Switching Protocols)
                    writer.write(SWITCH_RESPONSE)
                    await writer.drain()
                    forwarding_started = True
                else:
                    # 否则，返回 200 OK 并继续等待下一段 payload
                    writer.write(FIRST_RESPONSE)
                    await writer.drain()
                    continue  # 等待下一次 payload
            else:
                # 已经触发转发，直接转发数据
                # 这一段逻辑实际上是多余的，但保留原脚本结构
                writer.write(SWITCH_RESPONSE)
                await writer.drain()
            
            # 解析目标。如果客户端通过 X-Real-Host 提供了目标，则使用它，否则使用 DEFAULT_TARGET
            if host_header:
                if ':' in host_header:
                    host, port = host_header.split(':')
                    target = (host.strip(), int(port.strip()))
                else:
                    # 如果只提供了主机名，默认端口使用 22
                    target = (host_header.strip(), 22)
            else:
                target = DEFAULT_TARGET # 使用 127.0.0.1:41816

            # ==== 连接目标服务器 ====
            target_reader, target_writer = await asyncio.open_connection(*target)

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

            # 开始双向转发
            await asyncio.gather(
                pipe(reader, target_writer),
                pipe(target_reader, writer)
            )
            break  # 转发完成后退出循环

    except Exception as e:
        print(f"Connection error {peer}: {e}")
    finally:
        writer.close()
        await writer.wait_closed()
        print(f"Closed {peer}")


async def main():
    # TLS server
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    tls_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, tls=True),
        LISTEN_ADDR,
        TLS_PORT, # 使用动态端口
        ssl=ssl_ctx
    )

    # HTTP server
    http_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, tls=False),
        LISTEN_ADDR,
        HTTP_PORT # 使用动态端口
    )

    print(f"Listening on {LISTEN_ADDR}:{HTTP_PORT} (HTTP payload)")
    print(f"Listening on {LISTEN_ADDR}:{TLS_PORT} (TLS)")

    async with tls_server, http_server:
        await asyncio.gather(
            tls_server.serve_forever(),
            http_server.serve_forever()
        )

if __name__ == '__main__':
    asyncio.run(main())
    
EOF

sudo chmod +x /usr/local/bin/wss
echo "WSS 脚本安装完成"
echo "----------------------------------"

# =============================
# 创建 WSS systemd 服务
# =============================
sudo tee /etc/systemd/system/wss.service > /dev/null <<EOF
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

sudo systemctl daemon-reload
sudo systemctl enable wss
sudo systemctl start wss
echo "WSS 已启动，HTTP端口 $WSS_HTTP_PORT, TLS端口 $WSS_TLS_PORT"
echo "----------------------------------"

# =============================
# 安装 Stunnel4 并生成证书
# =============================
echo "==== 安装 Stunnel4 ===="
sudo mkdir -p /etc/stunnel/certs
sudo openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 1095 \
-subj "/CN=example.com"
sudo sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
sudo chmod 644 /etc/stunnel/certs/*.crt
sudo chmod 644 /etc/stunnel/certs/*.pem

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
connect = 127.0.0.1:41816 
EOF

sudo systemctl enable stunnel4
sudo systemctl restart stunnel4
echo "Stunnel4 安装完成，端口 $STUNNEL_PORT"
echo "----------------------------------"

# =============================
# 安装 UDPGW
# =============================
echo "==== 安装 UDPGW ===="
if [ -d "/root/badvpn" ]; then
    echo "/root/badvpn 已存在，跳过克隆"
else
    git clone https://github.com/ambrop72/badvpn.git /root/badvpn
fi
mkdir -p /root/badvpn/badvpn-build
cd /root/badvpn/badvpn-build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make -j$(nproc)

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

echo "所有组件安装完成!"
echo "查看 WSS 状态: sudo systemctl status wss"
echo "查看 Stunnel4 状态: sudo systemctl status stunnel4"
echo "查看 UDPGW 状态: sudo systemctl status udpgw"
