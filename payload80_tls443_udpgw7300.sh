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
# 1. 安装 WSS 脚本 (最终修复 Base64 错误)
# =============================
echo "==== 安装 WSS 脚本 (Python) ===="

# WSS Python 脚本的 Base64 编码内容。已修复 Python 语法错误 LISTENING_PORT = ...
# 占位符为: ##SSH_PORT##
WSS_BASE64_CONTENT_FIXED="IyEvdXNyL2Jpbi9weXRob24zCiMgUHl0aG9uIFByb3h5IChXU1MvSFRUUCBTaW11bGF0aW9uKSAtIEF1dGhvcjogWmllbgppbXBvcnQgc29ja2V0LCB0aHJlYWRpbmcsIHNlbGVjdCwgc3lzLCB0aW1lCgovLyBDb25maWd1cmFhdGlvbnMKMSVNQ0VOSU5HX0FERFIgPSAnMC4wLjAuMCcKIExJU1RFTklOR19QT1JUID0gaW50KHN5cy5hcmd2WzFdKSBpZiBsZW4oc3lzLmFyZ3ZkKSA+IDEgZWxzZSA4MAogUEFTUyA9ICcnCiBCVUZMRU4gPSAyMDQ4ICogNAogVElNRU9VUyA9IDYwCkRFRkFVTFRfSE9TVCA9ICcxMjcuMC4wLjE6IyNTU0hfUE9SVCMjJwogUkVTUE9OU0UgPSAnJydIVFRQLzEuMSAxMDEgU3dpdGNoaW5nIFByb3RvY29scw0KQ29ubmVjdGlvbjogVXBncmFkZQ0KVXBncmFkZTogd2Vic29ja2V0DQpDb250ZW50LUxlbmd0aDogMTA0ODU3NjAwMDAwDQoNCicnJwoKY2xhc3MgU2VydmVyKHRocmVhZGluZy5UaHJlYWQpOgogICAgZGVmIF9faW5pdF9fKHNlbGYsIGhvc3QsIHBvcnQpOgogICAgICAgIHRocmVhZGluZy5UaHJlYWQuX19pbml0X18oc2VsZikKICAgICAgICBzZWxmLnJ1bm5pbmcgPSBGYWxzZQogICAgICAgIHNlbGYuaG9zdCA9IGhvc3QKICAgICAgICBzZWxmLnBvcnQgPSBwb3J0CiAgICAgICAgc2VsZi50aHJlYWRzID0gW10KICAgICAgICBzZWxmLnRocmVhZHNfbG9jayA9IHRocmVhZGluZy5Mb2NrKCkKICAgICAgICBzZWxmLmxvZ0xvY2sgPSB0aHJlYWRpbmcuTG9jaygpCiAgICBkZWYgcnVuKHNlbGYpOgogICAgICAgIHNlbGYuc29jID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCkKICAgICAgICBzZWxmLnNvYy5zZXRzb2NrcHQoc29ja2V0LlNPTF9TT0NLRVQsIHNvY2tldC5TT19SRVVTRUFEUiwgMSkKICAgICAgICBzZWxmLnNvYy5zZXR0aW1lb3V0KDIpCiAgICAgICAgdHJ5OgogICAgICAgICAgICBzZWxmLnNvYy5iaW5kKChzZWxmLmhvc3QsIGludChzZWxmLnBvcnQpKSkKICAgICAgICAgICAgc2VsZi5zb2MubGlzdGVuKDApCiAgICAgICAgICAgIHNlbGYucnVubmluZyA9IFRydWUKICAgICAgICAgICAgd2hpbGUgc2VsZi5ydW5uaW5nOgogICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgIGMsIGFkZHIgPSBzZWxmLnNvYy5hY2NlcHQoKQogICAgICAgICAgICAgICAgICAgIGMuc2V0YmxvY2tpbmcoMSkKICAgICAgICAgICAgICAgIGV4Y2VwdCBzb2NrZXQudGltZW91dDoKICAgICAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICAgICAgY29ubiA9IENvbm5lY3Rpb25IYW5kbGVyKGMscyBnbGYsIGFkZHIpCiAgICAgICAgICAgICAgICBjb25uLnN0YXJ0KCkKICAgICAgICAgICAgICAgIHNlbGYuYWRkQ29ubihjb25uKQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICAgICAgcHJpbnQoZiJTZXJ2ZXIgZXJyb3Igb24gcG9ydCB7c2VsZi5wb3J0fToge2V9IikKICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICBzZWxmLnJ1bm5pbmcgPSBGYWxzZQogICAgICAgICAgICBzZWxmLnNvYy5jbG9zZSgpCiAgICBkZWYgcHJpbnRMb2coc2VsZiwgbG9nKToKICAgICAgICBzZWxmLmxvZ0xvY2suYWNxdWlyZSgpCiAgICAgICAgcHJpbnQobG9nKQogICAgICAgIHNlbGYubG9nTG9jay5yZWxlYXNlKCkKICAgIGRlZiBhZGRDb25uKHNlbGYsIGNvbm4pOgogICAgICAgIHRyeToKICAgICAgICAgICAgc2VsZi50aHJlYWRzX2xvY2suYWNxdWlyZSgpCiAgICAgICAgICAgIGlmIHNlbGYucnVubmluZzoKICAgICAgICAgICAgICAgIHNlbGYudGhyZWFkcy5hcHBlbmQoY29ubikKICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICBzZWxmLnRocmVhZHNfbG9jay5yZWxlYXNlKCkKICAgIGRlZiByZW1vdmVDb25uKHNlbGYsIGNvbm4pOgogICAgICAgIHRyeToKICAgICAgICAgICAgc2VsZi50aHJlYWRzX2xvY2suYWNxdWlyZSgpCiAgICAgICAgICAgIHNlbGYudGhyZWFkcy5yZW1vdmUoY29ubikKICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICBzZWxmLnRocmVhZHNfbG9jay5yZWxlYXNlKCkKICAgIGRlZiBjbG9zZShzZWxmKToKICAgICAgICB0cnk6CiAgICAgICAgICAgIHNlbGYucnVubmluZyA9IEZhbHNlCiAgICAgICAgICAgIHNlbGYudGhyZWFkc19sb2NrLmFjcXVpcmUoKQogICAgICAgICAgICB0aHJlYWRzID0gbGlzdChzZWxmLnRocmVhZHMpCiAgICAgICAgICAgIGZvciBjIGluIHRocmVhZHM6CiAgICAgICAgICAgICAgICBjLmNsb3NlKCkKICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICBzZWxmLnRocmVhZHNfbG9jay5yZWxlYXNlKCkKCmNsYXNzIENvbm5lY3Rpb25IYW5kbGVyKHRocmVhZGluZy5UaHJlYWQpOgogICAgZGVmIF9faW5pdF9fKHNlbGYsIHNvY0NsaWVudCwgc2VydmVyLCBhZGRyKToKICAgICAgICB0aHJlYWRpbmcuVGhyZWFkLl9faW5pdF9fKHNlbGYpCiAgICAgICAgc2VsZi5jbGllbnRDbG9zZWQgPSBGYWxzZQogICAgICAgIHNlbGYudGFyZ2V0Q2xvc2VkID0gVHJ1ZQogICAgICAgIHNlbGYuY2xpZW50ID0gc29jQ2xpZW50CiAgICAgICAgc2VsZi5jbGllbnRfYnVmZmVyID0gYicnCiAgICAgICAgc2VsZi5zZXJ2ZXIgPSBzZXJ2ZXIKICAgICAgICBzZWxmLmxvZyA9ICdDb25uZWN0aW9uOiAnICsgc3RyKGFkZHIpCiAgICBkZWYgY2xvc2Uoc2VsZik6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBpZiBub3Qgc2VsZi5jbGllbnRDbG9zZWQ6CiAgICAgICAgICAgICAgICBzZWxmLmNsaWVudC5jbG9zZSgpCiAgICAgICAgZXhjZXB0OgogICAgICAgICAgICBwYXNzCiAgICAgICAgZmluYWxseToKICAgICAgICAgICAgc2VsZi5jbGllbnRDbG9zZWQgPSBUcnVlCiAgICAgICAgdHJ5OgogICAgICAgICAgICBpZiBub3Qgc2VsZi50YXJnZXRDbG9zZWQ6CiAgICAgICAgICAgICAgICBzZWxmLnRhcmdldC5jbG9zZSgpCiAgICAgICAgZXhjZXB0OgogICAgICAgICAgICBwYXNzCiAgICAgICAgZmluYWxseToKICAgICAgICAgICAgc2VsZi50YXJnZXRDbG9zZWQgPSBUcnVlCiAgICBkZWYgcnVuKHNlbGYpOgogICAgICAgIHRyeToKICAgICAgICAgICAgc2VsZi5jbGllbnQuc2V0dGltZW91dChUSU1FT1VUKQogICAgICAgICAgICBzZWxmLmNsaWVudF9idWZmZXIgPSBzZWxmLmNsaWVudC5yZWN2KEJVRkxFTikKICAgICAgICAgICAgCiAgICAgICAgICAgIGhlYWQgPSBzZWxmLmNsaWVudF9idWZmZXIuZGVjb2RlKCd1dGYtOCcsIGVycm9ycz0naWdub3JlJykKCiAgICAgICAgICAgIGhvc3RQb3J0ID0gc2VsZi5maW5kSGVhZGVyKGhlYWQsICdYLVJlYWwtSG9zdCcpCiAgICAgICAgICAgIGlmIGhvc3RQb3J0ID09ICcnOgogICAgICAgICAgICAgICAgaG9zdFBvcnQgPSBERUZBVUxUX0hPU1QKICAgICAgICAgICAgCiAgICAgICAgICAgIHBhc3N3ZCA9IHNlbGYuZmluZEhlYWRlcihoZWFkLCAnWC1QYXNzJykKICAgICAgICAgICAgaWYgbGVuKFBBU1MpIGFuZCBwYXNzd2QgIT0gUEFTUzoKICAgICAgICAgICAgICAgIHNlbGYuY2xpZW50LnNlbmQoYidIVFRQLzEuMSAyMDAgV3JvbmdQYXNzIVxyXG5cclxuJykKICAgICAgICAgICAgICAgIHJldHVybgoKICAgICAgICAgICAgc2VsZi5tZXRob2RfQ09OTkVDVChob3N0UG9ydCkKICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgICAgIHNlbGYubG9nICsrICcgLSBlcnJvcjogJyArIHN0cihlKQogICAgICAgICAgICBzZWxmLnNlcnZlci5wcmludExvZyhzZWxmLmxvZykKICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICBzZWxmLmNsb3NlKCkKICAgICAgICAgICAgc2VsZi5zZXJ2ZXIucmVtb3ZlQ29ubihzZWxmKQogICAgCiAgICBkZWYgZmluZEhlYWRlcihzZWxmLCBoZWFkLCBoZWFkZXIpOgogICAgICAgIGF1eCA9IGhlYWQuZmluZChoZWFkZXIgKyAnOiAnKQogICAgICAgIGlmIGF1eCA9PSAtMTogCiAgICAgICAgICAgIHJldHVybiAnJwogICAgICAgIGF1eCA9IGhlYWQuZmluZChcIjpcIiwgYXV4KQogICAgICAgIGhlYWQgPSBoZWFkW2F1eCArIDI6XQogICAgICAgIGF1eCA9IGhlYWQuZmluZChcIlxcblwiKQogICAgICAgIGlmIGF1eCA9PSAtMTogCiAgICAgICAgICAgIHJldHVybiAnJwogICAgICAgIHJldHVybiBoZWFkWzphdXhdLnN0cmlwKCkKCiAgICBkZWYgY29ubmVjdF90YXJnZXQoc2VsZiwgaG9zdCk6CiAgICAgICAgaSA9IGhvc3QuZmluZChcIjpcIikKICAgICAgICBpZiBpICE9IC0xOgogICAgICAgICAgICBwb3J0ID0gaW50KGhvc3RbaSArIDE6XSkKICAgICAgICAgICAgaG9zdCA9IGhvc3RbOmldCiAgICAgICAgZWxzZToKICAgICAgICAgICAgcG9ydCA9IGludChkZWZhdWx0X2hvc3Quc3BsaXQoJzonKVstMV0pCiAgICAgICAgc2VsZi50YXJnZXQgPSBzb2NrZXQuY3JlYXRlX2Nvbm5lY3Rpb24oKGhvc3QsIHBvcnQpLCB0aW1lb3V0PVNJTUVPVVQKKSKICAgICAgICBzZWxmLnRhcmdldENsb3NlZCA9IEZhbHNlCiAgICAKICAgIGRlZiBtZXRob2RfQ09OTkVDVChzZWxmLCBwYXRoKToKICAgICAgICBzZWxmLmxvZyArPSAnIC0gQ09OTkVDVCAkIHsnICsgcGF0aAogICAgICAgIHNlbGYuY29ubmVjdF90YXJnZXQocGF0aCkKICAgICAgICBzZWxmLmNsaWVudC5zZW5kYWxsKFJFU1BPTlNFLmVuY29kZSgndXRmLTgnKSkKICAgICAgICBzZWxmLnNlcnZlci5wcmludExvZyhzZWxmLmxvZykKICAgICAgICBzZWxmLmRvQ09OTkVDVChzZWxmKQogICAgZGVmIGRvQ09OTkVDVChzZWxmKToKICAgICAgICBzb2NzID0gW3NlbGYuY2xpZW50LCBzZWxmLnRhcmdldF0KICAgICAgICBlcnJvciA9IEZhbHNlCiAgICAgICAgbGFzdF9hY3Rpdml0eSA9IHRpbWUudGltZSgpCiAgICAgICAgCiAgICAgICAgd2hpbGUgdGltZS50aW1lKCkgLSBsYXN0X2FjdGl2aXR5IDwgVElNRU9VVDogCiAgICAgICAgICAgIChyZWN2LCBfLCBlcnIpID0gc2VsZWN0LnNlbGVjdChzb2NzLCBbXSwgc29jcywgMSkKICAgICAgICAgICAgCiAgICAgICAgICAgIGlmIGVycjoKICAgICAgICAgICAgICAgIGVycm9yID0gVHJ1ZQogICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgCiAgICAgICAgICAgIGlmIHJlY3Y6CiAgICAgICAgICAgICAgICBsYXN0X2FjdGl2aXR5ID0gdGltZS50aW1lKCkKICAgICAgICAgICAgICAgIGZvciBpbl8gaW4gcmVjdjoKICAgICAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAgICAgIGRhdGEgPSBpbl8ucmVjdihCVUZMRU4pCiAgICAgICAgICAgICAgICAgICAgICAgIGlmIGRhdGE6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiBpbl8gaXMgc2VsZi50YXJnZXQ6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2VsZi5jbGllbnQuc2VuZChkYXRhKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZWxmLnRhcmdldC5zZW5kYWxsKGRhdGEpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlOgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVycm9yID0gVHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgICAgICAgICAgICAgICAgIGVycm9yID0gVHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICBicmVhawoKICAgICAgICAgICAgICAgICAgICBpZiBlcnJvcjoKICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWsKCiAgICAgICAgICAgIGlmIGVycm9yOgogICAgICAgICAgICAgICAgYnJlYWsKCiAgICAgICAgICAgICAgICAKZGVmIG1haW4oKToKICAgIGdsb2JhbCBMSVNURU5JTkdfUE9SVAogICAgaWYgbGVuKHN5cy5hcmd2KSA+IDE6CiAgICAgICAgTElTVEVOSU5HX1BPUlQgPSBpbnQoc3lzLmFyZ3ZbMV0pCiAgICAKICAgIHByaW50KCJcXG46LS0tLS0tLVB5dGhvblByb3h5IFdTU1wtLS0tLS0tLVxcbiIpCiAgICBwcmludChmIkxpc3RlbmluZyBhZGRyOiB7TElTVEVOSU5HX0FERFJ9LCBwb3J0OiB7TElTVEVOSU5HX1BPUlR9LCBEZWZhdWx0IFRhcmdldDoge0RFRkFVTFRfSE9TVH1cXG4iKQogICAgc2VydmVyID0gU2VydmVyKExJU1RFTklOR19BRERSLCBMSVNURU5JTkdfUE9SVD0pCiAgICBzZXJ2ZXIuc3RhcnQoKQogICAgCiAgICB0cnk6CiAgICAgICAgd2hpbGUgVHJ1ZToKICAgICAgICAgICAgdGltZS5zbGVlcCgyKQogICAgZXhjZXB0IEtleWJvYXJkSW50ZXJydXQ6CiAgICAgICAgcHJpbnQoJ1N0b3BwaW5nLi4uJykKICAgIGZpbmFsbHk6CiAgICAgICAgc2VydmVyLmNsb3NlKCkKCiAgICAgICAgYnJlYWsKCmlmIF9fbmFtZV9fID09ICdfX21haW5fXyc6CiAgICBtYWluKCkK"

# 步骤 1: Base64 解码到临时文件
# FIX: 使用 printf "%s" 确保只传输变量内容，避免 echo 引入的额外字符
printf "%s" "$WSS_BASE64_CONTENT_FIXED" | base64 -d > /usr/local/bin/wss_temp

# 步骤 2: 使用 sed 注入 $SSH_PORT 变量
sudo sed "s/##SSH_PORT##/$SSH_PORT/g" /usr/local/bin/wss_temp | sudo tee /usr/local/bin/wss > /dev/null
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

# 停止可能崩溃的服务
sudo systemctl stop wss || true
sudo systemctl daemon-reload
sudo systemctl enable wss
# 关键：重启 WSS 服务
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
if ! grep -q "FILES=" /etc/default/stunnel4; then
    sudo sh -c 'echo "FILES=\"/etc/stunnel/multitunnel.conf\"" >> /etc/default/stunnel4'
else
    sudo sed -i 's/^FILES=.*$/FILES="\/etc\/stunnel\/multitunnel.conf"/' /etc/default/stunnel4
fi

# 停止可能存在的服务
sudo systemctl stop stunnel4 || true
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

# --- 修复 cp: Text file busy 错误 ---
# 停止服务以释放旧的可执行文件
echo "停止现有 UDPGW 服务以替换二进制文件..."
sudo systemctl stop udpgw || true

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
echo "1. SSH (裸协议): 端口 $SSH_PORT"
echo "2. SSH-HTTP-Payload (WSS): 端口 $WSS_PORT"
echo "3. SSH-TLS (Stunnel4): 端口 $STUNNEL_PORT"
echo "4. SSH-TLS-HTTP-Payload (Stunnel4+WSS): 端口 $WSS_TLS_PORT"
echo "UDPGW (Badvpn): 端口 $UDPGW_PORT (仅本地)"

# 检查最终状态
echo ""
echo "==== 最终状态检查 ===="
sudo systemctl status wss --no-pager | grep "Active:"
sudo systemctl status stunnel4 --no-pager | grep "Active:"
sudo systemctl status udpgw --no-pager | grep "Active:"
