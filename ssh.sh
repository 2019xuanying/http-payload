#!/bin/bash
set -e

# =============================
# 提示端口和配置
# =============================
echo "==== 代理配置输入 ===="
read -p "请输入 WSS HTTP 监听端口 (默认 80): " WSS_HTTP_PORT
WSS_HTTP_PORT=${WSS_HTTP_PORT:-80}

read -p "请输入 WSS TLS 监听端口 (默认 443): " WSS_TLS_PORT
WSS_TLS_PORT=${WSS_TLS_PORT:-443}

read -p "请输入 Stunnel4 监听端口 (WSS 转发目标, 默认 444): " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-444}

read -p "请输入 真实的 SSH 目标端口 (Stunnel4 后端, 默认 41816): " SSH_TARGET_PORT
SSH_TARGET_PORT=${SSH_TARGET_PORT:-41816}

read -p "请输入 UDPGW 端口 (默认 7300): " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

# =============================
# 系统更新与依赖安装
# =============================
echo ""
echo "==== 1/5: 更新系统并安装依赖 ===="
sudo apt update -y
sudo apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4
echo "依赖安装完成"

# =============================
# 安装 WSS 脚本 (使用变量替换)
# =============================
echo ""
echo "==== 2/5: 安装 WSS 脚本 ===="
# 使用 EOF 确保 Shell 变量能被替换
sudo tee /usr/local/bin/wss > /dev/null <<EOF
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio, ssl, sys, os

# === CONFIGURATION (Variables from shell script) ===
LISTEN_ADDR = '0.0.0.0'
HTTP_PORT = ${WSS_HTTP_PORT}
TLS_PORT = ${WSS_TLS_PORT}
DEFAULT_TARGET = ('127.0.0.1', ${STUNNEL_PORT}) # WSS 转发目标是 Stunnel4
BUFFER_SIZE = 65536
TIMEOUT = 60
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'
PASS = '' # 如果需要密码验证，可填

FIRST_RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    peer = writer.get_extra_info('peername')

    try:
        # 读取初始数据包
        data = await asyncio.wait_for(reader.read(BUFFER_SIZE), timeout=TIMEOUT)
        if not data:
            return

        headers = data.decode(errors='ignore')
        
        # 1. 检查密码 (X-Pass)
        passwd_header = ''
        for line in headers.split('\r\n'):
            if line.startswith('X-Pass:'):
                passwd_header = line.split(':', 1)[1].strip()
                break

        if PASS and passwd_header != PASS:
            writer.write(b'HTTP/1.1 400 WrongPass!\r\n\r\n')
            await writer.drain()
            return

        # 2. 检查是否触发转发 (GET-RAY 标识)
        if 'GET-RAY' in headers:
            # 触发转发，发送 101 协议切换响应
            writer.write(SWITCH_RESPONSE)
            await writer.drain()
            target = DEFAULT_TARGET
            
            # 3. ==== 连接目标服务器 (Stunnel4) ====
            print(f"[{peer}] -> Forwarding connection to {target}")
            target_reader, target_writer = await asyncio.open_connection(*target)
            
            # 4. 转发客户端发来的 Payload (GET-RAY 头 + 剩余数据)
            target_writer.write(data)
            await target_writer.drain()

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
                    pass

            # 5. 开始双向转发
            await asyncio.gather(
                pipe(reader, target_writer),
                pipe(target_reader, writer)
            )

        else:
            # 非转发请求，返回 200 OK
            writer.write(FIRST_RESPONSE)
            await writer.drain()
            
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        print(f"Connection error {peer}: {e}")
    finally:
        writer.close() 


async def main():
    # 检查证书文件是否存在
    if not all(os.path.exists(f) for f in [CERT_FILE, KEY_FILE]):
        print(f"Error: Certificate files not found! Please check Stunnel4 setup.", file=sys.stderr)
        sys.exit(1)

    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    # 启动 TLS Server
    tls_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, tls=True),
        LISTEN_ADDR,
        TLS_PORT,
        ssl=ssl_ctx
    )

    # 启动 HTTP Server
    http_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, tls=False),
        LISTEN_ADDR,
        HTTP_PORT
    )

    print(f"WSS Proxy Running:")
    print(f"  HTTP on {LISTEN_ADDR}:{HTTP_PORT} (Payload)")
    print(f"  TLS on {LISTEN_ADDR}:{TLS_PORT}")
    print(f"  Target: {DEFAULT_TARGET[0]}:{DEFAULT_TARGET[1]} (Stunnel4)")

    async with tls_server, http_server:
        await asyncio.gather(
            tls_server.serve_forever(),
            http_server.serve_forever()
        )

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
EOF

sudo chmod +x /usr/local/bin/wss
echo "WSS 脚本安装完成"

# =============================
# 创建 WSS systemd 服务并启动
# =============================
echo ""
echo "==== 3/5: 创建 WSS systemd 服务并启动 ===="
sudo tee /etc/systemd/system/wss.service > /dev/null <<EOF
[Unit]
Description=WSS Python Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wss
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable wss
sudo systemctl restart wss

# =============================
# 安装 Stunnel4 并生成证书
# =============================
echo ""
echo "==== 4/5: 安装 Stunnel4 并生成证书 ===="
sudo mkdir -p /etc/stunnel/certs
# 只有当证书不存在时才重新生成
if [ ! -f "/etc/stunnel/certs/stunnel.pem" ]; then
    sudo openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout /etc/stunnel/certs/stunnel.key \
    -out /etc/stunnel/certs/stunnel.crt \
    -days 1095 \
    -subj "/CN=example.com"
    sudo sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
    sudo chmod 644 /etc/stunnel/certs/*.pem
    echo "Stunnel4 证书生成完成"
fi

# Stunnel4 配置文件
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
accept = 0.0.0.0:${STUNNEL_PORT}
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
connect = 127.0.0.1:${SSH_TARGET_PORT}
EOF

sudo systemctl enable stunnel4
sudo systemctl restart stunnel4
echo "Stunnel4 配置完成，监听端口 ${STUNNEL_PORT} -> 转发到 SSH ${SSH_TARGET_PORT}"

# =============================
# 安装 UDPGW
# =============================
echo ""
echo "==== 5/5: 安装 UDPGW ===="
if [ ! -d "/root/badvpn" ]; then
    git clone https://github.com/ambrop72/badvpn.git /root/badvpn
else
    echo "/root/badvpn 已存在，跳过克隆"
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
ExecStart=/root/badvpn/badvpn-build/udpgw/badvpn-udpgw --listen-addr 127.0.0.1:${UDPGW_PORT} --max-clients 1024 --max-connections-for-client 10
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable udpgw
sudo systemctl restart udpgw
echo "UDPGW 已安装并启动，端口: ${UDPGW_PORT}"

# =============================
# 最终状态检查
# =============================
echo ""
echo "=================================="
echo "所有组件安装完成!"
echo ""
echo "WSS 状态:"
sudo systemctl status wss --no-pager
echo ""
echo "Stunnel4 状态:"
sudo systemctl status stunnel4 --no-pager
echo ""
echo "端口监听状态:"
sudo netstat -tulnp | grep -E ":(${WSS_HTTP_PORT}|${WSS_TLS_PORT}|${STUNNEL_PORT}|${SSH_TARGET_PORT}|${UDPGW_PORT})"
echo "=================================="

echo "请在客户端使用以下配置进行测试:"
echo "WSS 端口: ${WSS_HTTP_PORT} 或 ${WSS_TLS_PORT}"
echo "SSH 端口: ${SSH_TARGET_PORT}"
echo "UDPGW 端口: ${UDPGW_PORT}"
echo "Payload 确保包含 'GET-RAY' 标识"
