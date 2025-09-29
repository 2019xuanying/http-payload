一键部署bash <(curl -Ls https://raw.githubusercontent.com/2019xuanying/http-payload/main/payload80_tls443_udpgw7300.sh)
支持协议一览:
1. **SSH (裸连接)**:      服务器IP:41816
2. **SSH-TLS (Stunnel)**:     服务器IP:443
3. **SSH-Proxy-Payload**:    服务器IP:80
4. **SSH-TLS-Proxy-Payload**: 服务器IP:8080 (WSS 转发到 Stunnel)
----------------------------------------------------------
请检查服务状态:
WSS-SSH 状态: sudo systemctl status wss-ssh
WSS-TLS 状态: sudo systemctl status wss-tls
Stunnel4 状态: sudo systemctl status stunnel4
UDPGW 状态: sudo systemctl status udpgw 
