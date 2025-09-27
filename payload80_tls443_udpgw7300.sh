#!/bin/bash
set -e

# =======================================================
# Configuration Variables (User-Defined)
# =======================================================

# Your SSH server is listening on this internal port.
SSH_SERVER_PORT="41816"
echo "INFO: Internal SSH server port set to $SSH_SERVER_PORT (User-defined)."

# Internal port for the WSS Python proxy (unexposed, wrapped by Stunnel for TLS)
WSS_INTERNAL_PORT="8080"

# =============================
# Prompt for External Ports
# =============================
read -p "1. Enter WSS HTTP port (for SSH-HTTP-Payload, default 80): " WSS_EXTERNAL_PORT
WSS_EXTERNAL_PORT=${WSS_EXTERNAL_PORT:-80}

read -p "2. Enter Stunnel4 TLS port (for direct SSH-TLS, default 443): " SSH_TLS_PORT
SSH_TLS_PORT=${SSH_TLS_PORT:-443}

read -p "3. Enter Stunnel4 WSS-TLS port (for SSH-TLS-HTTP-Payload, default 8443): " WSS_TLS_PORT
WSS_TLS_PORT=${WSS_TLS_PORT:-8443}

read -p "4. Enter UDPGW port (for UDP forwarding, default 7300): " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

# =============================
# System Update and Dependency Installation
# =============================
echo "==== Updating system and installing dependencies ===="
# Using 'apt-get' instead of 'apt' for better script compatibility
sudo apt update -y
sudo apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4
echo "Dependencies installed successfully."
echo "----------------------------------------------------"

# =============================
# Install WSS Python Script
# This script listens on an internal port and forwards to SSH_SERVER_PORT
# =============================
echo "==== Installing WSS Python Script on internal port $WSS_INTERNAL_PORT ===="
# NOTE: The DEFAULT_HOST is set to your specified SSH port
sudo tee /usr/local/bin/wss > /dev/null <<EOF
#!/usr/bin/python3
import socket, threading, select, sys, time

LISTENING_ADDR = '0.0.0.0'
# Use the internal port for the WSS service
LISTENING_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else $WSS_INTERNAL_PORT 
PASS = ''
BUFLEN = 4096 * 4
TIMEOUT = 60
# Target is the SSH Server Port
DEFAULT_HOST = '127.0.0.1:$SSH_SERVER_PORT' 
# Standard WebSocket/HTTP response for tunneling
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
            self.printLog(f"ERROR: Could not bind to port {self.port}. Is it already in use? ({e})")
            return
            
        self.soc.listen(0)
        self.running = True
        self.printLog(f"WSS Server started on {self.host}:{self.port}, forwarding to {DEFAULT_HOST}")
        
        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue
                except OSError:
                    # Socket closed during accept
                    break
                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()
            self.printLog("WSS Server stopped.")

    def printLog(self, log):
        self.logLock.acquire()
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {log}", flush=True)
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
            if conn in self.threads:
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
        self.log = f'Connection from: {addr[0]}:{addr[1]}'
        self.addr = addr

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
            # Receive initial data
            self.client.settimeout(TIMEOUT)
            self.client_buffer = self.client.recv(BUFLEN)
            
            if not self.client_buffer:
                self.log += " - client disconnected prematurely"
                return

            # Decode buffer for header parsing
            head = self.client_buffer.decode('utf-8', 'ignore')
            
            # Find the actual target (or use default)
            hostPort = self.findHeader(head, 'X-Real-Host')
            if hostPort == '':
                hostPort = DEFAULT_HOST
                
            passwd = self.findHeader(head, 'X-Pass')
            if len(PASS) != 0 and passwd != PASS:
                self.client.sendall(b'HTTP/1.1 400 WrongPass!\r\n\r\n')
                self.log += ' - Blocked: WrongPass'
                return

            self.method_CONNECT(hostPort)
            
        except socket.timeout:
            self.log += ' - error: socket timeout'
        except Exception as e:
            self.log += ' - error: ' + str(e)
        finally:
            self.server.printLog(self.log)
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        # Helper to find a specific header value
        aux = head.find(header + ': ')
        if aux == -1:
            return ''
        start = aux + len(header) + 2
        end = head.find('\r\n', start)
        if end == -1:
            return ''
        return head[start:end].strip()

    def connect_target(self, host):
        # Connect to the target host (SSH port)
        i = host.find(':')
        if i != -1:
            port = int(host[i + 1:])
            host = host[:i]
        else:
            port = 22 # Should never happen if DEFAULT_HOST is correct, but safe fallback
        
        # Use only IPv4 for simplicity unless specific need for IPv6 is determined
        self.target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.target.settimeout(TIMEOUT)
        self.targetClosed = False
        self.target.connect((host, port))
        
    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path
        self.connect_target(path)
        # Send the successful protocol switch response
        self.client.sendall(RESPONSE.encode('utf-8'))
        
        # We need to send any buffered data that came after the headers
        if self.client_buffer:
            # Try to find the end of the HTTP headers to strip them
            header_end = self.client_buffer.find(b'\r\n\r\n')
            if header_end != -1:
                data_after_headers = self.client_buffer[header_end + 4:]
                if data_after_headers:
                    self.target.sendall(data_after_headers)
        
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        while not self.clientClosed and not self.targetClosed:
            count += 1
            # Wait for data on either socket
            (recv, _, err) = select.select(socs, [], socs, 3)
            
            if err:
                # Socket error occurred
                break
            
            if not recv:
                if count >= TIMEOUT:
                    # Timeout if no activity
                    break
                continue

            # Process received data
            for in_ in recv:
                try:
                    data = in_.recv(BUFLEN)
                    if not data:
                        # Peer disconnected gracefully
                        return 
                    
                    if in_ is self.target:
                        # Data from target (SSH) to client (Browser/Client app)
                        self.client.sendall(data)
                    else:
                        # Data from client (Browser/Client app) to target (SSH)
                        self.target.sendall(data)
                    
                    count = 0 # Reset timeout counter on activity
                except socket.error as e:
                    # Connection error (e.g., reset by peer)
                    self.log += f" - socket error during transfer: {e}"
                    return
                except Exception as e:
                    self.log += f" - unexpected transfer error: {e}"
                    return
        
        self.log += " - transfer complete or timed out"


def main():
    print("\n:-------WSS Python Proxy Initializing-------:\n")
    print(f"Internal Bind Port: {LISTENING_PORT}")
    print(f"SSH Target: {DEFAULT_HOST}\n")
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print('Stopping...')
            server.close()
            break

if __name__ == '__main__':
    main()
EOF

sudo chmod +x /usr/local/bin/wss

# WSS Systemd Service (Now using WSS_EXTERNAL_PORT to listen on)
sudo tee /etc/systemd/system/wss.service > /dev/null <<EOF
[Unit]
Description=WSS Python Proxy (HTTP/Payload Backend)
After=network.target

[Service]
Type=simple
# WSS listens on the internal WSS_INTERNAL_PORT (8080) for both HTTP and TLS-wrapped traffic
ExecStart=/usr/local/bin/wss $WSS_INTERNAL_PORT
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable wss
sudo systemctl start wss
echo "WSS Python Proxy (Backend) started on 0.0.0.0:$WSS_INTERNAL_PORT"
echo "----------------------------------------------------"

# =============================
# Install Stunnel4 and Generate Certificate
# Stunnel handles SSH-TLS (443) and SSH-TLS-HTTP-Payload (8443)
# =============================
echo "==== Installing Stunnel4 and generating self-signed certificate ===="
sudo mkdir -p /etc/stunnel/certs
sudo openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 1095 \
-subj "/CN=MultiTunnelServer"
sudo sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
sudo chmod 644 /etc/stunnel/certs/*.pem

# Stunnel Configuration for two separate TLS tunnels
sudo tee /etc/stunnel/multi-tunnel.conf > /dev/null <<EOF
pid=/var/run/stunnel.pid
setuid=root
setgid=root
client = no
debug = 5
output = /var/log/stunnel4/stunnel.log
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
verify = 0

# --- Service 1: SSH-TLS (Direct to SSH port) ---
# Protocol: SSH-TLS
# External Port: $SSH_TLS_PORT
[ssh-tls-direct]
accept = 0.0.0.0:$SSH_TLS_PORT
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
connect = 127.0.0.1:$SSH_SERVER_PORT

# --- Service 2: SSH-TLS-HTTP-Payload (TLS wrapped WSS) ---
# Protocol: SSH-TLS-HTTP-Payload
# External Port: $WSS_TLS_PORT
# Connects to the internal WSS script
[wss-tls-wrapper]
accept = 0.0.0.0:$WSS_TLS_PORT
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
connect = 127.0.0.1:$WSS_INTERNAL_PORT
EOF

# Ensure stunnel4 default config is enabled to load our new config
sudo sed -i 's/^ENABLED=0/ENABLED=1/' /etc/default/stunnel4 || true

# Check stunnel config syntax before restart
sudo stunnel4 /etc/stunnel/multi-tunnel.conf -check 2>/dev/null || echo "WARNING: Stunnel config check failed. Review /etc/stunnel/multi-tunnel.conf manually."

sudo systemctl daemon-reload
sudo systemctl enable stunnel4
sudo systemctl restart stunnel4
echo "Stunnel4 configured for SSH-TLS on $SSH_TLS_PORT and SSH-TLS-HTTP-Payload on $WSS_TLS_PORT."
echo "----------------------------------------------------"

# =============================
# Configure SSH-HTTP-Payload via IPTables Redirection (Optional but common)
# This allows WSS to be accessible on a common port like 80 without dedicated service.
# For simplicity, we will stick to the WSS script directly listening on the external port.
# If WSS_EXTERNAL_PORT is different from WSS_INTERNAL_PORT, we need to handle it.

if [ "$WSS_EXTERNAL_PORT" != "$WSS_INTERNAL_PORT" ]; then
    echo "NOTICE: Setting up simple TCP forwarding for SSH-HTTP-Payload."
    # We will use iptables for redirection if a common port like 80 is requested,
    # but for robustness, let's just create a simple Python forwarder if 80 is used.
    # The simplest is to modify the WSS service to listen on 80.
    # Since the Stunnel service is already connecting to the *internal* WSS port (8080),
    # we need a *separate* simple service to expose 80 -> 8080.
    
    # Let's create a *second* WSS systemd service specifically for the external HTTP port
    sudo tee /etc/systemd/system/wss-http-external.service > /dev/null <<EOF
[Unit]
Description=WSS Python Proxy HTTP External Listener
After=network.target wss.service

[Service]
Type=simple
# This service listens on the external port and connects to the WSS backend (8080)
ExecStart=/usr/local/bin/wss-http-forwarder.sh
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    # Create the forwarder script (to keep WSS single-purpose)
    sudo tee /usr/local/bin/wss-http-forwarder.sh > /dev/null <<EOF
#!/bin/bash
# A simple socat/netcat substitute for redirecting the WSS external port to the internal WSS port.
# Since we only support the Python WSS script, we'll run a second instance on the external port
# that redirects to the *actual* SSH port, effectively achieving the same result as the original script,
# but now we have two WSS instances running, one for HTTP and one for TLS wrapping.
# NOTE: The WSS script logic handles the X-Real-Host/DEFAULT_HOST targeting.

/usr/local/bin/wss $WSS_EXTERNAL_PORT
EOF
    sudo chmod +x /usr/local/bin/wss-http-forwarder.sh
    
    # Start the external WSS listener service
    sudo systemctl daemon-reload
    sudo systemctl enable wss-http-external
    sudo systemctl start wss-http-external
    echo "WSS HTTP External Listener (SSH-HTTP-Payload) started on 0.0.0.0:$WSS_EXTERNAL_PORT"

else
    echo "SSH-HTTP-Payload is accessible on $WSS_EXTERNAL_PORT as it matches WSS internal port ($WSS_INTERNAL_PORT)."
fi
echo "----------------------------------------------------"

# =============================
# Install UDPGW
# =============================
echo "==== Installing UDPGW (for UDP tunneling) ===="
if [ -d "/root/badvpn" ]; then
    echo "/root/badvpn directory found, skipping git clone."
else
    git clone https://github.com/ambrop72/badvpn.git /root/badvpn
fi

mkdir -p /root/badvpn/badvpn-build
cd /root/badvpn/badvpn-build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make -j$(nproc)

# Create systemd service (binds to 127.0.0.1)
sudo tee /etc/systemd/system/udpgw.service > /dev/null <<EOF
[Unit]
Description=UDP Gateway (Badvpn)
After=network.target

[Service]
Type=simple
# UDPGW listens locally, client should connect to it via SSH tunnel's DYNAMIC port forwarding.
ExecStart=/root/badvpn/badvpn-build/udpgw/badvpn-udpgw --listen-addr 127.0.0.1:$UDPGW_PORT --max-clients 1024 --max-connections-for-client 10
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable udpgw
sudo systemctl start udpgw
echo "UDPGW installed and started on 127.0.0.1:$UDPGW_PORT (Access via SSH tunnel)."
echo "----------------------------------------------------"

# =============================
# Summary and Usage
# =============================
echo " "
echo "===================================================="
echo "✅ All tunneling components installed successfully!"
echo "===================================================="
echo " "
echo "Your internal SSH server port: $SSH_SERVER_PORT"
echo " "
echo "--- Service Endpoints ---"
echo "1. SSH-TLS (Standard TLS wrapper for SSH):"
echo "   External Port: $SSH_TLS_PORT (Use for OpenSSH/Tunnelier/Bitvise/etc. with TLS/Stunnel support)"
echo " "
echo "2. SSH-HTTP-Payload (SSH over WebSocket/HTTP):"
echo "   External Port: $WSS_EXTERNAL_PORT (Use for simple HTTP/WS payloads, e.g., KPN Tunnel)"
echo " "
echo "3. SSH-TLS-HTTP-Payload (SSH over WebSocket/HTTP wrapped in TLS):"
echo "   External Port: $WSS_TLS_PORT (Use for secure WS/HTTP payloads, e.g., Stunnel Client -> $WSS_TLS_PORT)"
echo " "
echo "4. UDPGW (For UDP forwarding):"
echo "   Internal Port: $UDPGW_PORT (Access via SOCKS proxy opened through any of the above tunnels)"
echo " "
echo "--- Status Commands ---"
echo "WSS Backend:     sudo systemctl status wss"
echo "WSS HTTP Ext:    sudo systemctl status wss-http-external (If used)"
echo "Stunnel4:        sudo systemctl status stunnel4"
echo "UDPGW:           sudo systemctl status udpgw"
echo "===================================================="

cd /root
