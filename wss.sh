#!/bin/bash
set -e
echo "==== 正在应用 WSS 脚本最终修复 (修复缩进) ===="

# 使用 cat 命令确保准确地将修复后的 Python 脚本写入文件
sudo cat > /usr/local/bin/wss <<'EOF'
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio, ssl, sys, os

# === CONFIGURATION (Hardcoded based on confirmed setup) ===
LISTEN_ADDR = '0.0.0.0'
HTTP_PORT = 80             # 外部 WSS HTTP 监听端口
TLS_PORT = 443             # 外部 WSS TLS 监听端口
DEFAULT_TARGET = ('127.0.0.1', 444) # 转发目标：Stunnel4 监听的 444 端口
BUFFER_SIZE = 65536
TIMEOUT = 60
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'
PASS = ''  # 如果需要密码验证，可填

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
        
        # 1. 检查密码
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
        # 修复：确保在 finally 块中关闭 writer
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
echo "WSS 脚本已更新并赋予执行权限。"

### 步骤三：重新加载和启动服务

```bash
sudo systemctl daemon-reload
sudo systemctl restart wss
```

### 步骤四：检查 WSS 状态

**这是最关键的一步。** 请再次运行下面的命令，确认这次服务是否成功启动，并且不再报告 `IndentationError`。

```bash
sudo journalctl -u wss.service -n 50 --no-pager
