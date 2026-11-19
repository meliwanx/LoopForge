#!/usr/bin/env bash
# 管理能经 SSO 登录 LoopForge 的成员（在 216 上执行）。
#
#   lf-user.sh list
#   lf-user.sh add <工号> <姓名> [部门] [admin]   # 加白名单 + 在 LoopForge 建账号（登录名=工号，显示中文名）
#   lf-user.sh remove <工号>                      # 移出白名单，5 秒内失去访问；LoopForge 里的账号和数据保留
#
# 白名单：/etc/loopforge-gate/access/allowed_jobs（网关每 5 秒检查一次，不用重启）。
set -euo pipefail
ALLOW=/etc/loopforge-gate/access/allowed_jobs
cd /home/LoopForge

sql() {
  docker compose exec -T mysql sh -c 'MYSQL_PWD="$MYSQL_PASSWORD" mysql --default-character-set=utf8mb4 -u loopforge loopforge' <<<"$1"
}
q() { printf "'%s'" "${1//\'/\'\'}"; } # SQL 字符串字面量

cmd=${1:-}
case "$cmd" in
  list)
    echo "== 白名单"; grep -vE '^\s*(#|$)' "$ALLOW" || true
    echo "== LoopForge 账号"
    sql "SELECT login_name AS 工号, chinese_name AS 姓名, dept_name AS 部门, IFNULL(platform_role,'') AS 角色 FROM users WHERE login_name REGEXP '^[0-9A-Za-z_.-]+\$' AND login_name <> 'admin' ORDER BY login_name;"
    ;;
  add)
    job=${2:-}; name=${3:-}; dept=${4:-}; role=${5:-}
    [[ "$job" =~ ^[0-9A-Za-z_.-]{1,64}$ && -n "$name" ]] || { echo "用法: $0 add <工号> <姓名> [部门] [admin]" >&2; exit 2; }
    [[ -z "$role" || "$role" == admin ]] || { echo "第 4 个参数只能是 admin 或留空" >&2; exit 2; }
    grep -qxF "$job" "$ALLOW" || echo "$job" >>"$ALLOW"
    staff=0; [[ "$job" =~ ^[0-9]+$ ]] && staff=$job
    role_sql=NULL; [[ "$role" == admin ]] && role_sql="'admin'"
    sql "INSERT INTO users (staff_id, login_name, chinese_name, dept_name, platform_role, created_at, updated_at)
         VALUES ($staff, $(q "$job"), $(q "$name"), $(q "$dept"), $role_sql, NOW(3), NOW(3))
         ON DUPLICATE KEY UPDATE chinese_name=VALUES(chinese_name), dept_name=VALUES(dept_name),
           platform_role=COALESCE(VALUES(platform_role), platform_role), updated_at=NOW(3);"
    echo "已开通：$job $name ${role:+(管理员)}"
    ;;
  remove)
    job=${2:-}
    [[ "$job" =~ ^[0-9A-Za-z_.-]{1,64}$ ]] || { echo "用法: $0 remove <工号>" >&2; exit 2; }
    tmp=$(mktemp "$ALLOW.XXXX")
    grep -vxF "$job" "$ALLOW" >"$tmp" || true
    chmod 644 "$tmp"; mv "$tmp" "$ALLOW"
    echo "已移出白名单：$job（5 秒内失去访问；LoopForge 账号保留）"
    ;;
  *) sed -n 2,8p "$0"; exit 2 ;;
esac
