# NexaFlow 部署安装运维手册

本文档面向 NexaFlow 的开发验证、服务器部署和日常运维。当前推荐方式是：本地编码，通过 `rsync` 同步到 Ubuntu 服务器，在服务器上用 Docker Compose 构建并运行。

## 1. 系统概览

NexaFlow 当前运行链路：

```text
真实网卡 / PCAP 回放 / Mock 流量
  -> collector 5 秒窗口聚合
  -> ClickHouse 明细与聚合数据
  -> Redis 实时 TopN
  -> Go API
  -> Nginx + Vue 控制台
```

核心服务：

| 服务 | 作用 | 默认暴露 |
| --- | --- | --- |
| `web` | 前端静态资源和 API 反向代理 | `80:80`、`8081:80` |
| `api-server` | Go 后端 API、认证、配置、AI、审计 | 容器内 `8080`，宿主机 `127.0.0.1:8080` |
| `collector` | 流量采集、PCAP 回放、窗口聚合写入 | `network_mode: host` |
| `clickhouse` | 流量窗口、会话、审计、配置版本存储 | 宿主机 `127.0.0.1:8123`、`127.0.0.1:9000` |
| `redis` | 实时 TopN 缓存 | 宿主机 `127.0.0.1:6379` |
| `postgres` | 预留结构化业务库 | 宿主机 `127.0.0.1:5432` |

默认公网访问入口：

```text
http://<server-ip>:8081
```

## 2. 环境要求

### 2.1 Ubuntu 服务器

建议配置：

| 资源 | 最低 | 建议 |
| --- | --- | --- |
| 系统 | Ubuntu 22.04 LTS | Ubuntu 22.04/24.04 LTS |
| CPU | 2 核 | 4 核以上 |
| 内存 | 4 GB | 8-16 GB |
| 磁盘 | 50 GB | 100 GB+ SSD |
| 网络 | 1 个管理口 | 管理口 + 镜像/TAP/业务观测口 |

必须组件：

- Docker Engine
- Docker Compose Plugin
- Git
- `rsync`
- `tcpdump`，用于人工确认网卡是否有流量

安装命令：

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg git rsync tcpdump
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"
newgrp docker
docker version
docker compose version
```

### 2.2 本地开发机

建议：

- macOS 或 Linux
- Git
- Node.js 20+
- Go 1.22+，如本地不具备 Go，可使用服务器容器测试
- SSH key 可登录 Ubuntu 服务器

## 3. 首次部署

### 3.1 获取代码

服务器直接拉代码：

```bash
cd /home/ubuntu
git clone <repo-url> nexaflow
cd /home/ubuntu/nexaflow
```

或本地同步到服务器：

```bash
export NEXAFLOW_REMOTE_HOST=<server-ip>
export NEXAFLOW_REMOTE_USER=ubuntu
export NEXAFLOW_REMOTE_DIR=/home/ubuntu/nexaflow
export NEXAFLOW_SSH_KEY=$HOME/.ssh/nexaflow_ubuntu
./scripts/sync_to_server.sh
```

### 3.2 配置 `.env`

在服务器项目目录创建 `/home/ubuntu/nexaflow/.env`：

```bash
cd /home/ubuntu/nexaflow
cat > .env <<'EOF'
NEXAFLOW_MODE=live_pcap
NEXAFLOW_IFACE=eth0
NEXAFLOW_SOURCE_ID=live-eth0
NEXAFLOW_BPF_FILTER=ip or ip6
NEXAFLOW_SESSION_TOPN=500

# 建议生产环境开启登录保护。
NEXAFLOW_AUTH_PASSWORD=<admin-password>
NEXAFLOW_AUTH_READONLY_PASSWORD=<viewer-password>
NEXAFLOW_AUTH_SECRET=<random-long-secret>

# 默认本地规则摘要；外部大模型可在系统配置页或这里配置。
NEXAFLOW_AI_MODE=local_mock
NEXAFLOW_AI_PROVIDER=local_mock
NEXAFLOW_AI_MODEL=nexaflow-local-summary
NEXAFLOW_AI_BASE_URL=
NEXAFLOW_AI_API_KEY=
NEXAFLOW_AI_MAX_CONTEXT_ROWS=12
EOF
chmod 600 .env
```

说明：

- `NEXAFLOW_AUTH_PASSWORD` 为空时，控制台默认不要求登录。
- `NEXAFLOW_AUTH_SECRET` 用于签名登录会话，生产环境必须配置长随机值。
- 后台系统配置会落盘到 `runtime/system_settings.json`，敏感配置请限制服务器文件权限。
- `.env` 提供启动默认值；如果 `runtime/system_settings.json` 已存在，前端保存过的系统配置会优先生效。需要强制回到 `.env` 默认值时，应先备份并处理对应运行态配置文件。

生成随机密钥示例：

```bash
openssl rand -hex 32
```

### 3.3 启动服务

```bash
cd /home/ubuntu/nexaflow
docker compose -f deploy/docker-compose.yaml up -d --build
docker compose -f deploy/docker-compose.yaml ps
```

首次构建会拉取 Go、Node、ClickHouse、Redis、Postgres、Nginx 镜像，耗时取决于服务器网络。

### 3.4 验证服务

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/api/v1/auth/status
curl -fsS http://<server-ip>:8081/healthz
```

浏览器访问：

```text
http://<server-ip>:8081
```

如服务器安全组或防火墙未开放，需要放行 `8081/tcp`。不建议直接公网暴露 ClickHouse、Redis、Postgres，Compose 已默认绑定到 `127.0.0.1`。

## 4. 本地开发同步到服务器验证

本地修改代码后：

```bash
export NEXAFLOW_REMOTE_HOST=<server-ip>
export NEXAFLOW_REMOTE_USER=ubuntu
export NEXAFLOW_REMOTE_DIR=/home/ubuntu/nexaflow
export NEXAFLOW_SSH_KEY=$HOME/.ssh/nexaflow_ubuntu
./scripts/sync_to_server.sh
```

服务器重建指定服务：

```bash
./scripts/server_compose.sh up -d --build api-server web collector
```

常用快捷命令：

```bash
./scripts/server_compose.sh ps
./scripts/server_compose.sh logs -f api-server
./scripts/server_compose.sh logs -f collector
./scripts/server_compose.sh restart collector
```

如果只改前端：

```bash
./scripts/server_compose.sh up -d --build web
```

如果只改后端 API：

```bash
./scripts/server_compose.sh up -d --build api-server
```

## 5. 采集配置

### 5.1 查看可采集网卡

在服务器：

```bash
ip -o link show
sudo tcpdump -D
sudo tcpdump -i <iface> -nn -c 20
```

或从本地调用脚本：

```bash
export NEXAFLOW_REMOTE_HOST=<server-ip>
./scripts/list_server_interfaces.sh
```

### 5.2 切换真实网卡采集

控制台路径：

```text
采集器 -> 选择采集模式 live_pcap -> 选择网卡 -> 应用采集配置
```

命令行切换：

```bash
export NEXAFLOW_REMOTE_HOST=<server-ip>
./scripts/set_capture_interface.sh eth0 live_pcap 500
```

脚本会写入：

- `.env`
- `runtime/collector_config.json`

并重启 `api-server`、`collector`、`web`。

### 5.3 PCAP 回放

上传 PCAP：

```bash
scp -i ~/.ssh/nexaflow_ubuntu sample.pcap ubuntu@<server-ip>:/home/ubuntu/nexaflow/runtime/replay.pcap
```

切换回放：

```bash
curl -X POST http://<server-ip>:8081/api/v1/collectors/config \
  -H 'Content-Type: application/json' \
  -d '{
    "mode":"pcap_replay",
    "iface":"replay0",
    "source_id":"pcap-replay0",
    "bpf_filter":"ip or ip6",
    "pcap_file":"/var/lib/nexaflow/replay.pcap",
    "replay_speed":5,
    "session_topn":500
  }'
```

### 5.4 Mock 模式

用于功能演示和链路自检：

```bash
cat > .env <<'EOF'
NEXAFLOW_MODE=mock
NEXAFLOW_IFACE=mock0
NEXAFLOW_SOURCE_ID=mock-dev
NEXAFLOW_SESSION_TOPN=500
EOF
docker compose -f deploy/docker-compose.yaml up -d --build collector api-server web
```

## 6. 系统配置与安全

### 6.1 控制台认证

支持两类入口：

- 共享管理员密码：`NEXAFLOW_AUTH_PASSWORD`
- 共享只读密码：`NEXAFLOW_AUTH_READONLY_PASSWORD`
- 独立用户：在前端“系统配置 -> 用户管理”维护

生产建议：

- 开启登录保护。
- 设置 `NEXAFLOW_AUTH_SECRET`。
- 创建独立管理员账号，避免长期使用共享密码。
- 定期轮换密码和会话。
- 在“会话管理”里吊销异常登录会话。

### 6.2 权限角色

| 角色 | 典型权限 |
| --- | --- |
| `admin` | 配置、写入、导出、审计、处置 |
| `analyst` | 分析、调查、部分写入 |
| `auditor` | 审计查看、配置审阅 |
| `viewer` | 只读看板和查询 |

### 6.3 AI 配置

默认：

```bash
NEXAFLOW_AI_MODE=local_mock
```

关闭：

```bash
NEXAFLOW_AI_MODE=disabled
```

外部 OpenAI 兼容网关：

```bash
NEXAFLOW_AI_MODE=openai
NEXAFLOW_AI_PROVIDER=openai
NEXAFLOW_AI_MODEL=<model>
NEXAFLOW_AI_BASE_URL=https://<gateway>/v1
NEXAFLOW_AI_API_KEY=<api-key>
```

也可以在控制台“系统配置 -> 大模型配置”维护。生产环境建议后端保存敏感配置，并限制 `runtime/system_settings.json` 权限。

### 6.4 运行态配置文件

| 文件 | 内容 |
| --- | --- |
| `.env` | Compose 环境变量 |
| `runtime/collector_config.json` | 采集模式、网卡、BPF、PCAP、TopN、告警规则、白名单 |
| `runtime/system_settings.json` | AI、安全、通知、数据保留、用户、会话等系统配置 |
| `runtime/ai_approval_requests.json` | AI 审批请求 |

`runtime` 目录不应提交到 Git。

## 7. 日常运维命令

### 7.1 服务状态

```bash
cd /home/ubuntu/nexaflow
docker compose -f deploy/docker-compose.yaml ps
docker compose -f deploy/docker-compose.yaml logs --tail=200 api-server
docker compose -f deploy/docker-compose.yaml logs --tail=200 collector
docker compose -f deploy/docker-compose.yaml logs --tail=200 web
docker compose -f deploy/docker-compose.yaml logs --tail=200 clickhouse
```

### 7.2 健康检查

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/metrics | head
curl -fsS http://127.0.0.1:8080/api/v1/system/status
```

公网入口：

```bash
curl -fsS http://<server-ip>:8081/healthz
```

### 7.3 查看数据写入

```bash
docker compose -f deploy/docker-compose.yaml exec -T clickhouse \
  clickhouse-client --user default --password nexaflow \
  --query "SELECT max(ts), count() FROM nexaflow.link_traffic_5s"

docker compose -f deploy/docker-compose.yaml exec -T clickhouse \
  clickhouse-client --user default --password nexaflow \
  --query "SELECT ts, source_id, iface, bytes, packets FROM nexaflow.link_traffic_5s ORDER BY ts DESC LIMIT 10"
```

### 7.4 重启服务

```bash
docker compose -f deploy/docker-compose.yaml restart api-server
docker compose -f deploy/docker-compose.yaml restart collector
docker compose -f deploy/docker-compose.yaml restart web
```

### 7.5 停止和启动

```bash
docker compose -f deploy/docker-compose.yaml stop
docker compose -f deploy/docker-compose.yaml start
```

不要在未备份前执行 `down -v`，它会删除命名卷中的 ClickHouse/Postgres 数据。

## 8. 升级发布流程

推荐流程：

1. 本地确认代码已提交。
2. 本地前端构建通过。
3. 服务端 Go 测试通过。
4. 同步代码到服务器。
5. 重建受影响服务。
6. 做健康检查和页面验证。
7. 清理构建缓存。

命令：

```bash
cd /Users/<user>/workspace/nexaflow/web
npm run build

cd /Users/<user>/workspace/nexaflow
export NEXAFLOW_REMOTE_HOST=<server-ip>
./scripts/sync_to_server.sh

ssh -i ~/.ssh/nexaflow_ubuntu ubuntu@<server-ip> '
  cd /home/ubuntu/nexaflow &&
  docker run --rm -v /home/ubuntu/nexaflow:/src -w /src golang:1.22-alpine \
    sh -c "gofmt -w internal/api/server.go internal/api/server_test.go internal/config/config.go && go test ./internal/api ./internal/storage/clickhouse"
'

./scripts/server_compose.sh up -d --build api-server web collector
curl -fsS http://<server-ip>:8081/healthz
```

清理构建缓存：

```bash
ssh -i ~/.ssh/nexaflow_ubuntu ubuntu@<server-ip> \
  'docker builder prune -af >/dev/null && docker image prune -af >/dev/null && df -h / && docker system df'
```

## 9. 备份与恢复

### 9.1 必备备份对象

| 对象 | 位置 |
| --- | --- |
| 运行态配置 | `/home/ubuntu/nexaflow/runtime` |
| 环境变量 | `/home/ubuntu/nexaflow/.env` |
| ClickHouse 数据 | Docker volume `deploy_chdata` |
| Postgres 数据 | Docker volume `deploy_pgdata` |

### 9.2 轻量配置备份

```bash
cd /home/ubuntu/nexaflow
mkdir -p backups
tar -czf backups/nexaflow-config-$(date +%F-%H%M%S).tgz .env runtime
```

恢复：

```bash
cd /home/ubuntu/nexaflow
tar -xzf backups/<file>.tgz
docker compose -f deploy/docker-compose.yaml restart api-server collector
```

### 9.3 ClickHouse 逻辑导出

按表导出示例：

```bash
mkdir -p /home/ubuntu/nexaflow/backups/clickhouse
docker compose -f deploy/docker-compose.yaml exec -T clickhouse \
  clickhouse-client --user default --password nexaflow \
  --query "SELECT * FROM nexaflow.link_traffic_5s FORMAT Native" \
  > /home/ubuntu/nexaflow/backups/clickhouse/link_traffic_5s.native
```

恢复示例：

```bash
docker compose -f deploy/docker-compose.yaml exec -T clickhouse \
  clickhouse-client --user default --password nexaflow \
  --query "INSERT INTO nexaflow.link_traffic_5s FORMAT Native" \
  < /home/ubuntu/nexaflow/backups/clickhouse/link_traffic_5s.native
```

### 9.4 Docker 卷备份

停服后做冷备：

```bash
cd /home/ubuntu/nexaflow
docker compose -f deploy/docker-compose.yaml stop
docker run --rm -v deploy_chdata:/volume -v "$PWD/backups:/backup" alpine \
  tar -czf /backup/chdata-$(date +%F-%H%M%S).tgz -C /volume .
docker run --rm -v deploy_pgdata:/volume -v "$PWD/backups:/backup" alpine \
  tar -czf /backup/pgdata-$(date +%F-%H%M%S).tgz -C /volume .
docker compose -f deploy/docker-compose.yaml start
```

## 10. 磁盘与数据保留

ClickHouse 表当前带 TTL：

| 表类型 | 默认 TTL |
| --- | --- |
| 5 秒流量明细 | 7 天 |
| 告警事件 | 180 天 |
| 操作审计 | 365 天 |
| 配置版本 | 365 天 |

后台“系统配置 -> 数据配置”也提供保留天数参数，后续治理任务应以该配置为准。

查看磁盘：

```bash
df -h /
docker system df
du -h -d 1 /home/ubuntu/nexaflow | sort -h
```

清理 Docker 构建缓存：

```bash
docker builder prune -af
docker image prune -af
```

清理日志建议使用 Docker 日志轮转。创建 `/etc/docker/daemon.json`：

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "5"
  }
}
```

重启 Docker：

```bash
sudo systemctl restart docker
cd /home/ubuntu/nexaflow
docker compose -f deploy/docker-compose.yaml up -d
```

## 11. 监控指标

Prometheus 风格指标：

```text
http://<server-ip>:8081/metrics
```

重点关注：

- `api-server` 是否存活。
- `collector` 最近窗口是否持续写入。
- ClickHouse 查询延迟和磁盘使用率。
- `capture_quality_5s` 中的丢包、错误、队列长度。
- 系统 CPU、内存、磁盘和网络吞吐。

快速检查采集是否在线：

```bash
docker compose -f deploy/docker-compose.yaml logs --tail=50 collector
docker compose -f deploy/docker-compose.yaml exec -T clickhouse \
  clickhouse-client --user default --password nexaflow \
  --query "SELECT now(), max(ts), dateDiff('second', max(ts), now()) AS lag_seconds FROM nexaflow.link_traffic_5s"
```

## 12. 常见故障处理

### 12.1 页面打不开

检查：

```bash
docker compose -f deploy/docker-compose.yaml ps web api-server
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8081/healthz
sudo ss -lntp | grep -E ':80|:8081|:8080'
```

处理：

- 检查安全组是否放行 `8081/tcp`。
- 检查 `web` 容器日志。
- 检查 API 是否健康。

### 12.2 API degraded 或无数据

检查 ClickHouse：

```bash
docker compose -f deploy/docker-compose.yaml ps clickhouse
docker compose -f deploy/docker-compose.yaml logs --tail=200 clickhouse
docker compose -f deploy/docker-compose.yaml exec -T clickhouse \
  clickhouse-client --user default --password nexaflow --query "SHOW DATABASES"
```

处理：

- 重启 ClickHouse。
- 确认 `NEXAFLOW_CLICKHOUSE_URL` 正确。
- 看 API 日志是否提示初始化失败。

### 12.3 真实流量采集为空

检查：

```bash
ip -o link show
sudo tcpdump -i <iface> -nn -c 20
docker compose -f deploy/docker-compose.yaml logs --tail=200 collector
```

常见原因：

- 选错网卡。
- 云服务器网卡没有镜像流量，只能看到本机进出流量。
- 安全策略或容器权限不足。
- BPF 过滤条件过窄。

处理：

```bash
./scripts/set_capture_interface.sh <iface> live_pcap 500
docker compose -f deploy/docker-compose.yaml restart collector
```

### 12.4 SSH 卡顿或断开

检查服务器资源：

```bash
top
free -h
df -h /
docker stats --no-stream
docker system df
```

处理：

- 清理 Docker build cache。
- 降低 `NEXAFLOW_SESSION_TOPN`。
- 优先重启 `collector`，避免大查询和构建同时进行。
- 必要时临时停止前端/构建任务。

### 12.5 磁盘使用率过高

检查：

```bash
df -h /
docker system df
du -h -d 1 /var/lib/docker | sort -h
du -h -d 1 /home/ubuntu/nexaflow | sort -h
```

清理：

```bash
docker builder prune -af
docker image prune -af
```

谨慎操作：

```bash
docker volume prune
```

不要在未确认前清理 volume，可能删除 ClickHouse/Postgres 数据。

### 12.6 登录异常或用户被锁定

前端：

```text
系统配置 -> 用户管理 -> 解锁 / 下线 / 重置密码
```

如果无法登录，可以临时在 `.env` 设置新的共享管理员密码并重启：

```bash
cd /home/ubuntu/nexaflow
sed -i '/^NEXAFLOW_AUTH_PASSWORD=/d' .env
echo 'NEXAFLOW_AUTH_PASSWORD=<new-admin-password>' >> .env
docker compose -f deploy/docker-compose.yaml restart api-server web
```

### 12.7 AI 摘要不可用

检查：

- `NEXAFLOW_AI_MODE`
- `NEXAFLOW_AI_BASE_URL`
- `NEXAFLOW_AI_API_KEY`
- 模型网关是否兼容 `/chat/completions`

如果外部模型失败，系统会回退本地摘要并标记 degraded。

## 13. 生产加固建议

当前 Compose 适合开发验证和小规模部署。进入企业生产前建议补齐：

- 使用 HTTPS 和正式域名。
- Nginx 前置反向代理接入 TLS、访问日志和安全头。
- ClickHouse、Redis、Postgres 使用强密码和独立网络。
- 将 `.env`、`runtime/system_settings.json` 纳入密钥管理或受控备份。
- 建立自动备份和恢复演练。
- 建立 Prometheus/Grafana 监控和告警。
- 将 Docker 日志轮转纳入服务器基线。
- 为采集器规划专用镜像口或 TAP 口。
- 为生产数据设置明确保留策略和容量预估。
- 发布前执行前端构建、后端测试、冒烟测试和回滚预案。

## 14. 标准发布检查清单

发布前：

- [ ] 代码已提交。
- [ ] `web` 目录执行 `npm run build` 通过。
- [ ] Go 后端测试通过。
- [ ] 已备份 `.env` 和 `runtime`。
- [ ] 确认服务器磁盘空间充足。

发布中：

- [ ] 同步代码到服务器。
- [ ] 重建受影响服务。
- [ ] 查看 `docker compose ps`。
- [ ] 检查 `/healthz`、`/readyz`、`/api/v1/auth/status`。
- [ ] 检查 collector 日志和 ClickHouse 最新窗口。

发布后：

- [ ] 前端页面能打开。
- [ ] 图表有数据或 mock 数据正常。
- [ ] 用户登录、权限、会话管理正常。
- [ ] Docker 构建缓存已清理。
- [ ] 记录版本、时间、操作者和变更摘要。
