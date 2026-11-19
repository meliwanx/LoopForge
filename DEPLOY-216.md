# LoopForge 部署记录：客户内网 216

2026-11-19 部署。上游 `Tencent/LoopForge` → fork `meliwanx/LoopForge`，本分支 `deploy-216` 基于上游提交 `6f606cf`（发布版 0.4.0）。

## 概况

| 项 | 值 |
| --- | --- |
| 机器 | 10.162.47.216（CentOS 8.4，48 核 / 125G / `/home` 3.6T），客户提供，专供我们开发使用 |
| 访问地址（外网，企业 SSO 登录） | **http://120.26.208.161:5270** （2026-11-20 起，见下文「外网访问与 SSO」） |
| 访问地址（客户内网，账号密码） | http://10.162.47.216:8090 （firewalld 已放行 8090/tcp） |
| 访问地址（运维隧道） | `ssh -N -L 18090:127.0.0.1:8090 dev216` 后打开 http://127.0.0.1:18090 |
| 安装目录 | `/home/LoopForge`（只放了部署需要的根目录文件、`scripts/`、`migrations/` 等，前端和 Go 源码不在机器上） |
| 数据目录 | `/home/loopforge-data`（工作区、CLI 缓存、HOME）；MySQL 数据在 Docker 卷 `loopforge_mysql-data` |
| 镜像 | `ghcr.io/tencent/loopforge:0.4.0`（摘要 `sha256:87b6a3e3…bda4`，与 GitHub Release 一致）、`mysql:8.4` |
| 容器 | `loopforge-platform-1`、`loopforge-mysql-1`，均 `restart=unless-stopped` |
| 管理员 | `admin`，密码在 216 `/root/.loopforge-admin.pw`（600） |
| 注册 | `AGENTFLOW_ALLOW_SIGNUP=false`；团队账号由管理员在「平台管理 → 成员账号」创建 |

## SSH

`~/.ssh/config` 里的 `dev216`：经公网中转机 `124.220.110.86:6000`（frp 映射到 216:22），已配免密并开了连接复用（中转机对频繁连接限流）。

## 模型

- 执行器：Claude Code 2.1.300（首次使用时由平台从 npm 装到 `/home/loopforge-data/cli/claude-code`）。
- 管理员的个人凭据：Base URL `https://token-plan.cn-beijing.maas.aliyuncs.com/apps/anthropic`，模型 `qwen4-max-preview`（注意中间的短横线，写成 `qwen4maxpreview` 会报 Model not exist），Key 只存在平台数据库里。
- 每个成员要在「个人设置」里自己填 Key、Base URL 和模型。
- 需求澄清、通知摘要等功能只走 CodeBuddy，没配 CodeBuddy Key 时这几项不可用；对话和 SOP 不受影响。

## 216 上为部署做的系统改动

1. yum 源：CentOS 8 已停更，`CentOS-Linux-*.repo` 改为 `mirrors.aliyun.com/centos-vault/8.5.2111`，原配置备份在 `/root/yum.repos.d.bak-20261119`。
2. 卸载系统自带、未使用的 podman / buildah / runc（与 Docker 冲突），安装 docker-ce 26.1.3 + compose 插件（阿里云源）、git、python39。
3. `/etc/docker/daemon.json`：`data-root=/home/docker`，Docker Hub 镜像源 daocloud / 1ms.run（216 直连 Docker Hub 不通），日志 50m×3。
4. 安装脚本用的 Python 3.9：`/opt/loopforge-bin/python3`（软链，不改系统默认 python3 3.6）。
5. firewalld 放行 8090/tcp。
6. `/home/loopforge-data/home/.npmrc` 设 `registry=https://registry.npmmirror.com`：216 到 npmjs 官方源只有约 20KB/s，平台按需安装 Claude Code 等 CLI 时 10 分钟超时会失败。
7. `/home/LoopForge/compose.override.yaml`：给 mysql 补 `restart: unless-stopped`（上游没设，机器重启后数据库不会自启）；11-20 起还加了 SSO 网关容器和信任身份头的配置（见「外网访问与 SSO」）。
8. frpc 新增 STCP 代理 `lf216-web-stcp`（原配置备份 `/opt/frp/frpc.toml.bak-20261120`）；网关文件在 `/opt/loopforge-gate/`、`/etc/loopforge-gate/`。

原有服务（frpc、DGP 8307、ops-web-react 8310）未改动，部署后检查均正常。

## 外网访问与 SSO（2026-11-20）

```
浏览器 → http://120.26.208.161:5270
  → 120 loopforge-visitor（frp STCP 访问端，只是一个 frpc 进程）
  → 124.220.110.86:7000 frps（TLS）
  → 216 frpc 代理 lf216-web-stcp → 127.0.0.1:8091
  → 容器 loopforge-sso-gate-1（借用 platform 容器网络）→ 127.0.0.1:8080 LoopForge
```

- 网关源码 `deploy/216-sso-gate/`（Go，无外部依赖，`go test -race ./...`），二进制 `/opt/loopforge-gate/lf-sso-gate`，配置 `/etc/loopforge-gate/gate.env`（600，含 SSO 系统密钥和身份头密钥）。
- 未登录的页面请求跳企业 SSO 联邦登录（SSO 系统 code `loopforge`，id 21）；验票后只放行白名单工号，转发时带 `Staffname`/`Staffid`=工号和与 LoopForge 共享的 `X-AgentFlow-Gateway-Secret`。浏览器自带的身份头、代理头一律删掉。
- LoopForge 侧（`compose.override.yaml`）开了 `AGENTFLOW_TRUST_IDENTITY_HEADERS=true` 和 `AGENTFLOW_IDENTITY_HEADER_SECRET`（值在 `.env` 的 `LOOPFORGE_GATE_IDENTITY_SECRET`）。LoopForge 只信任来自回环地址且带正确密钥的身份头，所以网关必须跑在 platform 容器的网络里；内网直连 8090 带伪造身份头只会被当成访客。
- 网关会话在内存里：滑动 12 小时、最长 7 天；网关重启后大家会自动重新走一遍 SSO。每分钟向 SSO 确认一次登录态，别的系统退出后这里 1 分钟内下线。退出入口 `/_gate/logout`（LoopForge 自带的“退出”只清它自己的 cookie，网关会立刻把人重新登录回来）。
- platform 容器重建后，网关连续 1 分钟连不上上游会自行退出，由 Docker 重启并重新加入新网络。
- SSO 回调是 http，网关 cookie 不带 Secure；以后有域名和证书时把 `GATE_PUBLIC_ORIGIN` 和 SSO base_url 一起改成 https。

### 成员管理

```bash
ssh dev216
/opt/loopforge-gate/lf-user.sh list
/opt/loopforge-gate/lf-user.sh add <工号> <姓名> [部门] [admin]   # 姓名部门可从 SSO users 表查
/opt/loopforge-gate/lf-user.sh remove <工号>                      # 5 秒内失去访问，账号数据保留
```

LoopForge 里登录名是工号，显示中文名。每个成员第一次进来后在「个人设置」填自己的模型 Key、Base URL 和模型名。

### 回滚外网访问

- 120：`systemctl disable --now loopforge-visitor`；SSO：`UPDATE systems SET status=0 WHERE code='loopforge'`。
- 216：从 `/opt/frp/frpc.toml` 删掉 `lf216-web-stcp` 段后 `systemctl restart frpc`（会闪断 120 的 DGP 通道几秒）；`compose.override.yaml` 换回 `/root/compose.override.yaml.bak-20261120` 后 `docker compose --profile platform up -d --remove-orphans`。

## 运维

```bash
ssh dev216
cd /home/LoopForge
./start.sh logs        # 平台日志
./start.sh restart     # 重启平台
./start.sh stop        # 停止
docker stats --no-stream
```

216 访问 GitHub 很慢（约 20KB/s），镜像要走南大镜像站。

### 升级

1. 看上游新版本号（`compose.yaml` 里的 `ghcr.io/tencent/loopforge:<版本>`），把本分支 rebase / 合并到上游对应提交。
2. 把根目录文件、`scripts/`、`migrations/` 同步到 216 的 `/home/LoopForge`（保留 `.env` 和 `compose.override.yaml`）。
3. 在 216 执行 `MIRROR=ghcr.nju.edu.cn PATH=/opt/loopforge-bin:$PATH ./start.sh pull`，然后核对镜像摘要是否与 GitHub Release 一致。

### 回滚 / 卸载

- 停服务：`./start.sh down`（数据卷保留）。
- 彻底删除：`docker compose --profile platform down -v`，再删 `/home/LoopForge`、`/home/loopforge-data`。
