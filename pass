#!/usr/bin/env bash
set -euo pipefail

# ====== 可修改项 ======
WSS_USER_DEFAULT="wssuser"                # 默认用户名（可用 -u 覆盖）
SSH_HOME_BASE="/home"                     # home 基路径（Debian/Ubuntu 通常是 /home）
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_SUFFIX=".bak.wss$(date +%s)"
# ======================

usage(){
cat <<EOF
用法:
  sudo $0 [ -u username ] [ -p password ]
说明:
  - 交互式运行: sudo $0           -> 会提示输入用户名（回车使用默认 wssuser）和密码（隐藏）
  - 参数传递模式: sudo $0 -u name -p 'pass'
  - 环境变量模式: sudo WSS_PASS='pass' $0
注意:
  - 出于安全，请尽量不要在共享环境下把密码作为命令行参数传入（会被 ps 查看）。
EOF
exit 1
}

# 解析参数
USER_ARG=""
PASS_ARG=""

while getopts ":u:p:h" opt; do
  case ${opt} in
    u ) USER_ARG="$OPTARG" ;;
    p ) PASS_ARG="$OPTARG" ;;
    h ) usage ;;
    \? ) usage ;;
  esac
done
shift $((OPTIND -1))

# 交互获取用户名（可选）
if [ -n "$USER_ARG" ]; then
  WSS_USER="$USER_ARG"
else
  read -p "请输入要创建的 WSS 用户名（回车使用默认: ${WSS_USER_DEFAULT}）: " tmpu
  WSS_USER="${tmpu:-$WSS_USER_DEFAULT}"
fi

# 取得密码来源（优先级：命令行 -p > 环境变量 WSS_PASS > 交互）
if [ -n "$PASS_ARG" ]; then
  WSS_PASS="$PASS_ARG"
elif [ -n "${WSS_PASS:-}" ]; then
  WSS_PASS="$WSS_PASS"
else
  # 交互式安全输入并确认
  echo "请为用户 ${WSS_USER} 输入密码（输入时隐藏）。"
  while true; do
    read -s -p "密码: " pw1 && echo
    read -s -p "请再次确认密码: " pw2 && echo
    if [ -z "$pw1" ]; then
      echo "密码不能为空，请重新输入。"
      continue
    fi
    if [ "$pw1" != "$pw2" ]; then
      echo "两次输入不一致，请重试。"
      continue
    fi
    WSS_PASS="$pw1"
    break
  done
fi

# 确保以 root 执行
if [ "$EUID" -ne 0 ]; then
  echo "请以 root 或 sudo 权限运行此脚本。"
  exit 1
fi

USER_HOME="${SSH_HOME_BASE}/${WSS_USER}"

echo "==> 创建用户 $WSS_USER（如果已存在则跳过创建）"
if id "$WSS_USER" >/dev/null 2>&1; then
  echo "用户 $WSS_USER 已存在，跳过创建。"
else
  adduser --disabled-password --gecos "WSS User" "$WSS_USER"
fi

echo "==> 设置密码（更新/覆盖）"
echo "${WSS_USER}:${WSS_PASS}" | chpasswd

echo "==> 确保用户没有 sudo 权限"
if getent group sudo >/dev/null 2>&1; then
  gpasswd -d "$WSS_USER" sudo >/dev/null 2>&1 || true
fi

echo "==> 创建 home/.ssh 目录（若需，可用于后续扩展）"
mkdir -p "${USER_HOME}/.ssh"
chown "$WSS_USER":"$WSS_USER" "${USER_HOME}/.ssh"
chmod 700 "${USER_HOME}/.ssh"

# 备份 sshd_config
echo "==> 备份 $SSHD_CONFIG -> ${SSHD_CONFIG}${BACKUP_SUFFIX}"
cp -a "$SSHD_CONFIG" "${SSHD_CONFIG}${BACKUP_SUFFIX}"

echo "==> 删除旧的 WSS 用户段"
sed -i '/# WSSUSER_BLOCK_START/,/# WSSUSER_BLOCK_END/d' "$SSHD_CONFIG"

echo "==> 添加新的 WSS 用户段"
cat >> "$SSHD_CONFIG" <<EOF

# WSSUSER_BLOCK_START -- managed by create_wssuser.sh
# 允许 $WSS_USER 从本机登录（用于 WSS payload）
Match User $WSS_USER Address 127.0.0.1,::1
    PermitTTY yes
    AllowTcpForwarding yes
    PasswordAuthentication yes
    AuthenticationMethods password

# 禁止 $WSS_USER 远程登录（其他地址）
Match User $WSS_USER Address *,!127.0.0.1,!::1
    PermitTTY no
    AllowTcpForwarding no
    PasswordAuthentication no
# WSSUSER_BLOCK_END -- managed by create_wssuser.sh

EOF

chmod 600 "$SSHD_CONFIG"

# 重载 sshd
if systemctl list-units --full -all | grep -q "sshd.service"; then
  SSHD_SERVICE="sshd"
else
  SSHD_SERVICE="ssh"
fi

echo "==> 重新加载并重启 ssh 服务 ($SSHD_SERVICE)"
systemctl daemon-reload
systemctl restart "$SSHD_SERVICE"

# 清理敏感变量
unset WSS_PASS
unset PASS_ARG

cat <<EOF

完成 ✅

说明：
- 用户: $WSS_USER
- 主目录: $USER_HOME
- 认证模式: 账户/密码
- 来自本机 (127.0.0.1 或 ::1) 的连接允许使用用户名/密码登录（用于 WSS payload）。
- 来自其他地址的 SSH 登录将被拒绝（PasswordAuthentication=no for non-local）。
- 原 ssh 配置备份为: ${SSHD_CONFIG}${BACKUP_SUFFIX}

测试（示例）:
- 在本机（或经由 WSS 转发到本机）执行:
  ssh -p <WSS本地端口> ${WSS_USER}@127.0.0.1
  然后输入你在本脚本中设置的密码登录。

回滚（如出问题）:
sudo cp -a "${SSHD_CONFIG}${BACKUP_SUFFIX}" "${SSHD_CONFIG}"
sudo systemctl restart ${SSHD_SERVICE}

EOF
