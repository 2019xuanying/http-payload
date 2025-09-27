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
# 确保安装了 base64 所需的 coreutils 或类似的包 (通常默认已安装)
sudo apt update -y
sudo apt install -y python3 python3-pip wget curl git cmake build-essential openssl stunnel4
echo "依赖安装完成"
echo "----------------------------------"

# =============================
# 1. 安装 WSS 脚本 (使用 Base64 编码，解决 Bash 解析问题)
# =============================
echo "==== 安装 WSS 脚本 (Python) ===="

# WSS Python 脚本的 Base64 编码内容。其中占位符为: ##SSH_PORT##
WSS_BASE64_CONTENT="IyEvdXNyL2Jpbi9weXRob24zCiMgUHl0aG9uIFByb3h5IChXU1MvSFRUUCBTaW11bGF0aW9uKSAtIEF1dGhvcjogWmllbgppbXBvcnQgc29ja2V0LCB0aHJlYWRpbmcsIHNlbGVjdCwgc3lzLCB0aW1lCgovLyBDb25maWd1cmF0aW9ucwpMSVNURU5JTkdfQUREUiA9ICcwLjAuMC4wJwogTElTVEVOSU5HX1BPUlQgPSBpbnQoc3lzLmFyZ3ZbMV0pIGlmIGxlbihzeXMuYXJndikgPiAxIGVsc2UgODAKIFBBU1MgPSAnJwogQlVGTENVNCA9IDQwOTYgKiA0CiBUSU1FT1VUID0gNjAKIERFRkFVTFRfSE9TVCA9ICcxMjcuMC4wLjE6IyNTU0hfUE9SVCMjJwogUkVTUE9OU0UgPSAnSFRUUC8xLjEgMTAxIFN3aXRjaGluZyBQcm90b2NvbHMNCkNvbm5lY3Rpb246IFVwZ3JhZGUNCkVhZGU6IHdlYnNvY2tldA0KQ29udGVudC1MZW5ndGg6IDEwNDg1NzYwMDAwMA0KDQonCgpjbGFzcyBTZXJ2ZXIodGhyZWFkaW5nLlRocmVhZCk6CiAgICBkZWYgX19pbml0X18oc2VsZiwgaG9zdCwgcG9ydCk6CiAgICAgICAgdGhyZWFkaW5nLlRocmVhZC5fX2luaXRfXyhzZWxmKQogICAgICAgIHNlbGYucnVubmluZyA9IEZhbHNlCiAgICAgICAgc2VsZi5ob3N0ID0gaG9zdAogICAgICAgIHNlbGYucG9ydCA9IHBvcnQKICAgICAgICBzZWxmLnRocmVhZHMgPSBbXQogICAgICAgIHNlbGYudGhyZWFkc0xvY2sgPSB0aHJlYWRpbmcuTG9jaygpCiAgICAgICAgc2VsZi5sb2dMb2NrID0gdGhyZWFkaW5nLlVjZCgpCiAgICBkZWYgcnVuKHNlbGYpOgogICAgICAgIHNlbGYuc29jID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCkKICAgICAgICBzZWxmLnNvYy5zZXRzb2NrcHQoc29ja2V0LlNPTF9TT0NLRVQsIHNvY2tldC5TT19SRVVTRUFEUiwgMSkKICAgICAgICBzZWxmLnNvYy5zZXR0aW1lb3V0KDIpCiAgICAgICAgdHJ5OgogICAgICAgICAgICBzZWxmLnNvYy5iaW5kKChzZWxmLmhvc3QsIGludChzZWxmLnBvcnQpKSkKICAgICAgICAgICAgc2VsZi5zb2MucnVubmluZ24obz0wKQogICAgICAgICAgICBzZWxmLnJ1bm5pbmcgPSBUcnVlCiAgICAgICAgICAgIHdoaWxlIHNlbGYucnVubmluZzoKICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICBjLCBhZGRyID0gc2VsZi5zb2MuYWNjZXB0KCkKICAgICAgICAgICAgICAgICAgICBjLnNldGJsb2NraW5nKDEpCiAgICAgICAgICAgICAgICBleGNlcHQgc29ja2V0LnRpbWVvdXQ6CiAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgICAgIGNvbm4gPSBDb25uZWN0aW9uSGFuZGxlcihjLCBzZWxmLCBhZGRyKQogICAgICAgICAgICAgICAgY29ubi5zdGFydCgpCiAgICAgICAgICAgICAgICBzZWxmLmFkZENvbm4oY29ubikKICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgICAgIHByaW50KGYiU2VydmVyIGVycm9yIG9uIHBvcnQge3NlbGYucG9ydH06IHtlfSIpCiAgICAgICAgZmluYWxseToKICAgICAgICAgICAgc2VsZi5ydW5uaW5nID0gRmFsc2UKICAgICAgICAgICAgc2VsZi5zb2MuY2xvc2UoKQogICAgZGVmIHByaW50TG9nKHNlbGYsIGxvZyk6CiAgICAgICAgc2VsZi5sb2dMb2NrLmFjcXVpcmUoKQogICAgICAgIHByaW50KGxvZykKICAgICAgICBzZWxmLmxvZ0xvY2sucmVsZWFzZSgpCiAgICBkZWYgYWRkQ29ubihzZWxmLCBjb25uKToKICAgICAgICB0cnk6CiAgICAgICAgICAgIHNlbGYudGhyZWFkc0xvY2suYWNxdWlyZSgpCiAgICAgICAgICAgIGlmIHNlbGYucnVubmluZzoKICAgICAgICAgICAgICAgIHNlbGYudGhyZWFkcy5hcHBlbmQoY29ubikKICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICBzZWxmLnRocmVhZHNMb2NrLnJlbGVhc2UoKQogICAgZGVmIHJlbW92ZUNvbm4oc2VsZiwgY29ubik6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBzZWxmLnRocmVhZHNMb2NrLmFjcXVpcmUoKQogICAgICAgICAgICBzZWxmLnRocmVhZHMucmVtb3ZlKGNvbm4pCiAgICAgICAgZmluYWxseToKICAgICAgICAgICAgc2VsZi50aHJlYWRzTG9jay5yZWxlYXNlKCkKICAgIGRlZiBjbG9zZShzZWxmKToKICAgICAgICB0cnk6CiAgICAgICAgICAgIHNlbGYucnVubmluZyA9IEZhbHNlCiAgICAgICAgICAgIHNlbGYudGhyZWFkc0xvY2suYWNxdWlyZSgpCiAgICAgICAgICAgIHRocmVhZHMgPSBsaXN0KHNlbGYudGhyZWFkcykKICAgICAgICAgICAgZm9yIGMgZ3JvdXAgdGhyZWFkczoKICAgICAgICAgICAgICAgIGMuY2xvc2UoKQogICAgICAgIGZpbmFsbHk6CiAgICAgICAgICAgIHNlbGYudGhyZWFkc0xvY2sucmVsZWFzZSgpCgpjbGFzcyBDb25uZWN0aW9uSGFuZGxlcih0aHJlYWRpbmcuVGhyZWFkKToKICAgIGRlZiBfX2luaXRfXyhzZWxmLCBzb2NDbGllbnQsIHNlcnZlciwgYWRkcik6CiAgICAgICAgdGhyZWFkaW5nLlRocmVhZC5fX2luaXRfXyhzZWxmKQogICAgICAgIHNlbGYuY2xpZW50Q2xvc2VkID0gRmFsc2UKICAgICAgICBzZWxmLnRhcmdldENsb3NlZCA9IFRydWUKICAgICAgICBzZWxmLmNsaWVudCA9IHNvY0NsaWVudAogICAgICAgIHNlbGYuY2xpZW50X2J1ZmZlciA9IGInJwogICAgICAgIHNlbGYuc2VydmVyID0gc2VydmVyCiAgICAgICAgc2VsZi5sb2cgPSAnQ29ubmVjdGlvbjogJyArIHN0cihhZGRyKQogICAgZGVmIGNsb3NlKHNlbGYpOgogICAgICAgIHRyeToKICAgICAgICAgICAgaWYgbm90IHNlbGYuY2xpZW50Q2xvc2VkOgogICAgICAgICAgICAgICAgc2VsZi5jbGllbnQuY2xvc2UoKQogICAgICAgIGV4Y2VwdDoKICAgICAgICAgICAgcGFzcwogICAgICAgIGZpbmFsbHk6CiAgICAgICAgICAgIHNlbGYuY2xpZW50Q2xvc2VkID0gVHJ1ZQogICAgICAgIHRyeToKICAgICAgICAgICAgaWYgbm90IHNlbGYudGFyZ2V0Q2xvc2VkOgogICAgICAgICAgICAgICAgc2VsZi50YXJnZXQuY2xvc2UoKQogICAgICAgIGV4Y2VwdDoKICAgICAgICAgICAgcGFzcwogICAgICAgIGZpbmFsbHk6CiAgICAgICAgICAgIHNlbGYudGFyZ2V0Q2xvc2VkID0gVHJ1ZQogICAgZGVmIHJ1bihzZWxmKToKICAgICAgICB0cnk6CiAgICAgICAgICAgIHNlbGYuY2xpZW50LnNldHRpbWVvdXQoVElNRU9VVCkKICAgICAgICAgICAgc2VsZi5jbGllbnRfYnVmZmVyID0gc2VsZi5jbGllbnQucmVjdihCVUZMRU4pCiAgICAgICAgICAgIAogICAgICAgICAgICBoZWFkID0gc2VsZi5jbGllbnRfYnVmZmVyLmRlY29kZSgndXRmLTgnLCBlcnJvcnM9J2lnbm9yZScpCgogICAgICAgICAgICBob3N0UG9ydCA9IHNlbGYuZmluZEhlYWRlcihoZWFkLCAnWC1SZWFsLUhvc3QnKQogICAgICAgICAgICBpZiBob3N0UG9ydCA9PSAnJzogCiAgICAgICAgICAgICAgICBob3N0UG9ydCA9IERFRkFVTFRfSE9TVCAKICAgICAgICAgICAgCiAgICAgICAgICAgIHBhc3N3ZCA9IHNlbGYuZmluZEhlYWRlcihoZWFkLCAnWC1QYXNzJykKICAgICAgICAgICAgaWYgbGVuKFBBU1MpICE9IDAgb25nIHBhc3N3ZCAhPSBQQVNTOgogICAgICAgICAgICAgICAgc2VsZi5jbGllbnQuc2VuZChiJ0hUVFEvMS4xIDQwMCBXcm9uZ1Bhc3MhXHIgXG5cclxuaScpCiAgICAgICAgICAgICAgICByZXR1cm4KCiAgICAgICAgICAgIHNlbGYubWV0aG9kX0NPTk5FQ1QoaG9zdFBvcnQpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgICAgICBzZWxmLmxvZyArPSAnIC0gZXJyb3I6ICcgKyBzdHIoZSkKICAgICAgICAgICAgc2VsZi5zZXJ2ZXIucHJpbnRMb2coc2VsZi5sb2cpCiAgICAgICAgZmluYWxseToKICAgICAgICAgICAgc2VsZi5jbG9zZSgpCiAgICAgICAgICAgIHNlbGYuc2VydmVyLnJlbW92ZUNvbm4oc2VsZikKICAgIAogICAgZGVmIGZpbmRIZWFkZXIoc2VsZiwgaGVhZCwgaGVhZGVyKToKICAgICAgICBhdXggPSBoZWFkLmZpbmQoaGVhZGVyICsgJzogJykKICAgICAgICBpZiBhdXggPT0gLTE6CiAgICAgICAgICAgIHJldHVybiAnJwogICAgICAgIGF1eCA9IGhlYWQuZmluZCgnOicsIGF1eCkKICAgICAgICBoZWFkID0gaGVhZFthdXggKyAyOl0KICAgICAgICBhdXggPSBoZWFkLmZpbmQoJ1xyXG5nJykKICAgICAgICBpZiBhdXggPT0gLTE6CiAgICAgICAgICAgIHJldHVybiAnJwogICAgICAgIHJldHVybiBoZWFkWzphdXhdLnN0cmlwKCkKCiAgICBkZWYgY29ubmVjdF90YXJnZXQoc2VsZiwgaG9zdCk6CiAgICAgICAgaSA9IGhvc3QuZmluZChpZGYnKQogICAgICAgIGlmIGkgIT0gLTE6CiAgICAgICAgICAgIHBvcnQgPSBpbnQoaG9zdFtpICsgMToxXSkKICAgICAgICAgICAgaG9zdCA9IGhvc3RbOmldCiAgICAgICAgZWxzZToKICAgICAgICAgICAgcG9ydCA9IGludCERUExURsVFQVVMVF9IT1NULnNwbGl0KCc6JylbLTFdKSENCgogICAgICAgIHNlbGYudGFyZ2V0ID0gc29ja2V0LmNyZWF0ZV9jb25uZWN0aW9uKChob3N0LCBwb3J0KSwgdGltZW91dD1USU1FT1VUKQogICAgICAgIHNlbGYudGFyZ2V0Q2xvc2VkID0gRmFsc2UKCiAgICBkZWYgbWV0aG9kX0NPTk5FQ1Qoc2VsZiwgcGF0aCk6CiAgICAgICAgc2VsZi5sb2cgKz0gJyAtIENPTk5FQ1QgJyArIHBhdGgKICAgICAgICBzZWxmLmNvbm5lY3RfdGFyZ2V0KHBhdGgpCiAgICAgICAgc2VsZi5jbGllbnQuc2VuZGFsbChSRVNQT05TRS5lbmNvZGUoJ3V0Zi04JykpCiAgICAgICAgc2VsZi5zZXJ2ZXIucHJpbnRMb2coc2VsZi5sb2cpCiAgICAgICAgc2VsZi5kb0NPTk5FQ1QoKQogICAgZGVmIGRvQ09OTkVDVChzZWxmKToKICAgICAgICBzb2NzID0gW3NlbGYuY2xpZW50LCBzZWxmLnRhcmdldF0KICAgICAgICBlcnJvciA9IEZhbHNlCiAgICAgICAgbGFzdF9hY3Rpdml0eSA9IHRpbWUudGltZSgpCiAgICAgICAgCiAgICAgICAgd2hpbGUgdGltZS50aW1lKCkgLSBsYXN0X2FjdGl2aXR5IDwgVElNRU9VVDogCiAgICAgICAgICAgIChyZWN2LCBfLCBlcnIpID0gc2VsZWN0LnNlbGVjdChzb2NzLCBbXSwgc29jcywgMSkKICAgICAgICAgICAgCiAgICAgICAgICAgIGlmIGVycjoKICAgICAgICAgICAgICAgIGVycm9yID0gVHJ1ZQogICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgCiAgICAgICAgICAgIGlmIHJlY3Y6CiAgICAgICAgICAgICAgICBsYXN0X2FjdGl2aXR5ID0gdGltZS50aW1lKCkKICAgICAgICAgICAgICAgIGZvciBpbl8gaW4gcmVjdjoKICAgICAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAgICAgIGRhdGEgPSBpbl8ucmVjdihCVUZMRU4pCiAgICAgICAgICAgICAgICAgICAgICAgIGlmIGRhdGE6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiBpbl8gaXMgc2VsZi50YXJnZXQ6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc2VsZi5jbGllbnQuc2VuZChkYXRhKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzZWxmLnRhcmdldC5zZW5kYWxsKGRhdGEpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBlbHNlOgoKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVycm9yID0gVHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgICAgICAgICAgICAgICAgIGVycm9yID0gVHJ1ZQogICAgICAgICAgICAgICAgICAgICAgICBicmVhawoKICAgICAgICAgICAgICAgICAgICBpZiBlcnJvcjoKICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWsKCiAgICAgICAgICAgIGlmIGVycm9yOgogICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgCgpkZWYgbWFpbigpOgogICAgZ2xvYmFsIExJU1RFTklOR19QT1JUCiAgICBpZiBsZW4oc3lzLmFyZ3ZkIWIxKSA+IDE6CiAgICAgICAgTElTVEVOSU5HX1BPUlQgPSBpbnQoc3lzLmFyZ3ZbMV0pCiAgICAKICAgIHByaW50KCJcXG46LS0tLS0tLVB5dGhvblByb3h5IFdTU1wtLS0tLS0tLVxcbiIpCiAgICBwcmludChmIkxpc3RlbmluZyBhZGRyOiB7TElTVEVOSU5HX0FERFJ9LCBwb3J0OiB7TElTVEVOSU5HX1BPUlR9LCBEZWZhdWx0IFRhcmdldDoge0RFRkFVTFRfSE9TVH1cXG4iKQogICAgc2VydmVyID0gU2VydmVyKExJU1RFTklOR19BRERSLCBMSVNURU5JTkdfUE9SVD0pCiAgICBzZXJ2ZXIuc3RhcnQoKQogICAgCiAgICB0cnk6CiAgICAgICAgd2hpbGUgVHJ1ZToKICAgICAgICAgICAgdGltZS5zbGVlcCgyKQogICAgZXhjZXB0IEtleWJvYXJkSW50ZXJydXQ6CiAgICAgICAgcHJpbnQoJ1N0b3BwaW5nLi4uJykKICAgIGZpbmFsbHk6CiAgICAgICAgc2VydmVyLmNsb3NlKCkKCiAgICAgICAgYnJlYWsKCmlmIF9fbmFtZV9fID09ICdfX21haW5fXyc6CiAgICBtYWluKCkK"

# 步骤 1: Base64 解码到临时文件
echo "$WSS_BASE64_CONTENT" | base64 -d > /usr/local/bin/wss_temp

# 步骤 2: 使用 sed 注入 $SSH_PORT 变量
sudo sed "s/##SSH_PORT##/$SSH_PORT/g" /usr/local/bin/wss_temp | sudo tee /usr/local/bin/wss > /dev/null
sudo rm /usr/local/bin/wss_temp

sudo chmod +x /usr/local/bin/wss
echo "WSS 脚本安装完成"
echo "----------------------------------"

# 创建 WSS systemd 服务
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
echo "1. SSH (裸协议): 端口 $SSH_PORT"
echo "2. SSH-HTTP-Payload (WSS): 端口 $WSS_PORT"
echo "3. SSH-TLS (Stunnel4): 端口 $STUNNEL_PORT"
echo "4. SSH-TLS-HTTP-Payload (Stunnel4+WSS): 端口 $WSS_TLS_PORT"
echo "UDPGW (Badvpn): 端口 $UDPGW_PORT (仅本地)"
