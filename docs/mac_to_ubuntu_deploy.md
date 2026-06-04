# Mac 本地开发到 Ubuntu 验证部署指南

## 1. 部署目标

NexaFlow v0.1 的开发和验证分两类环境：

- Mac 本地：开发代码、前端联调、mock 数据、pcap 回放。
- Ubuntu Server：验证真实网卡采集、容器权限、系统依赖和链路接入。

建议先在 Mac 用 mock 模式跑通端到端，再部署到 Ubuntu 做 live pcap 验证。

## 2. 推荐环境

### 2.1 Mac 开发机

- macOS 14 或更新版本。
- Go 1.22 或更新版本。
- Node.js 20 或更新版本。
- Docker Desktop。
- Git。
- libpcap，macOS 系统一般已自带。

### 2.2 Ubuntu 验证服务器

建议：

- Ubuntu Server 22.04 LTS 或 24.04 LTS。
- CPU：4 核以上，PoC 推荐 8 核。
- 内存：16GB 以上。
- 磁盘：200GB SSD 以上。
- Docker Engine 和 Docker Compose Plugin。
- 至少一个管理网口。
- 如需真实流量采集，额外准备镜像口、TAP 口或可观察的业务网卡。

## 3. Ubuntu 初始化

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg git make tcpdump libpcap-dev
```

安装 Docker：

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"
newgrp docker
docker version
docker compose version
```

确认网卡：

```bash
ip addr
ip link
sudo tcpdump -D
```

如果要采集镜像口，先用 tcpdump 验证该接口确实有流量：

```bash
sudo tcpdump -i eth1 -nn -c 20
```

## 4. Mac 本地开发流程

### 4.1 启动依赖

在项目根目录：

```bash
docker compose -f deploy/docker-compose.yaml up -d redis postgres clickhouse
```

### 4.2 初始化数据库

```bash
go run ./cmd/migrate
```

### 4.3 启动 mock Collector

```bash
go run ./cmd/collector --config ./config/dev.yaml --mode mock
```

### 4.4 启动 API

```bash
go run ./cmd/api-server --config ./config/dev.yaml
```

### 4.5 启动前端

```bash
cd web
npm install
npm run dev
```

访问：

```text
http://localhost:5173
```

## 5. Mac 到 Ubuntu 的部署方式

v0.1 推荐两种方式。

## 5.1 方式 A：源码同步后在 Ubuntu 构建

适合早期开发，最简单。

在 Mac：

```bash
git add .
git commit -m "nexaflow v0.1 scaffold"
git push
```

在 Ubuntu：

```bash
git clone <your-git-repo-url> nexaflow
cd nexaflow
docker compose -f deploy/docker-compose.yaml up -d
```

如果暂时没有 Git 远端，也可以用 rsync：

```bash
rsync -av --exclude .git --exclude web/node_modules ./ user@ubuntu:/opt/nexaflow/
```

然后在 Ubuntu：

```bash
cd /opt/nexaflow
docker compose -f deploy/docker-compose.yaml up -d
```

## 5.2 方式 B：Mac 构建多架构镜像，Ubuntu 拉取运行

适合部署流程稳定以后。

在 Mac 创建并启用 buildx：

```bash
docker buildx create --use
docker buildx inspect --bootstrap
```

构建并推送 Linux 镜像：

```bash
docker buildx build \
  --platform linux/amd64 \
  -t <registry>/nexaflow-api:v0.1 \
  -f deploy/api-server.Dockerfile \
  --push .

docker buildx build \
  --platform linux/amd64 \
  -t <registry>/nexaflow-collector:v0.1 \
  -f deploy/collector.Dockerfile \
  --push .

docker buildx build \
  --platform linux/amd64 \
  -t <registry>/nexaflow-web:v0.1 \
  -f deploy/web.Dockerfile \
  --push .
```

在 Ubuntu：

```bash
docker compose -f deploy/docker-compose.prod.yaml pull
docker compose -f deploy/docker-compose.prod.yaml up -d
```

## 6. Ubuntu 验证部署建议

### 6.1 mock 模式验证

先不要采真实网卡，确认服务链路正常：

```bash
docker compose -f deploy/docker-compose.yaml up -d
docker compose -f deploy/docker-compose.yaml ps
```

检查 API：

```bash
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/api/v1/dashboard/summary
```

访问 Web：

```text
http://<ubuntu-server-ip>:8081
```

### 6.2 pcap replay 验证

上传 pcap 文件：

```bash
scp ./samples/demo.pcap user@ubuntu:/opt/nexaflow/samples/demo.pcap
```

启动 collector：

```bash
docker compose -f deploy/docker-compose.yaml run --rm collector \
  /nexaflow/collector \
  --config /etc/nexaflow/config.yaml \
  --mode pcap_replay \
  --pcap-file /samples/demo.pcap
```

### 6.3 live pcap 验证

真实网卡采集通常需要容器具备网络抓包权限。

当前 v0.1 已支持通过控制台选择采集网卡：

```text
http://<ubuntu-server-ip>:8081 -> 采集器 -> 选择采集模式和采集网卡 -> 应用采集配置
```

也可以用脚本切换：

```bash
./scripts/list_server_interfaces.sh
./scripts/set_capture_interface.sh eth0 live_pcap
```

当前真实采集实现使用 Linux `AF_PACKET` 原始套接字，不依赖 libpcap/CGO。

Compose 中 collector 建议配置：

```yaml
collector:
  image: nexaflow/collector:v0.1
  network_mode: host
  cap_add:
    - NET_RAW
    - NET_ADMIN
  volumes:
    - ./config/prod.yaml:/etc/nexaflow/config.yaml:ro
  command:
    - /nexaflow/collector
    - --config
    - /etc/nexaflow/config.yaml
    - --mode
    - live_pcap
    - --interface
    - eth1
```

如果权限仍不足，可以在 PoC 阶段临时使用：

```yaml
privileged: true
network_mode: host
```

生产环境不建议长期使用 `privileged: true`，后续应收敛到必要 capabilities。

## 7. 真实采集前检查

确认接口存在：

```bash
ip link show eth1
```

确认接口有流量：

```bash
sudo tcpdump -i eth1 -nn -c 50
```

确认接口不是管理 SSH 唯一入口，避免误操作影响连接。

确认交换机镜像方向：

- ingress。
- egress。
- both。

确认镜像口没有被限速或过载。

## 8. 防火墙端口

Ubuntu 如果启用了 UFW：

```bash
sudo ufw allow 8081/tcp
sudo ufw allow 8080/tcp
```

如果接收 sFlow/IPFIX，后续版本需要开放：

```bash
sudo ufw allow 6343/udp
sudo ufw allow 4739/udp
```

v0.1 暂不启用 sFlow/IPFIX。

## 9. 日志与排错

查看服务状态：

```bash
docker compose -f deploy/docker-compose.yaml ps
```

查看日志：

```bash
docker compose -f deploy/docker-compose.yaml logs -f api-server
docker compose -f deploy/docker-compose.yaml logs -f collector
docker compose -f deploy/docker-compose.yaml logs -f clickhouse
```

检查 ClickHouse：

```bash
curl 'http://127.0.0.1:8123/?query=SELECT%201'
```

检查 Redis：

```bash
docker compose -f deploy/docker-compose.yaml exec redis redis-cli ping
```

检查 PostgreSQL：

```bash
docker compose -f deploy/docker-compose.yaml exec postgres pg_isready -U nexaflow
```

## 10. v0.1 验证顺序

推荐严格按这个顺序推进：

1. Mac mock 模式跑通前后端。
2. Mac pcap replay 跑通聚合和查询。
3. Ubuntu mock 模式跑通容器部署。
4. Ubuntu pcap replay 跑通离线样本。
5. Ubuntu live pcap 跑通指定网卡。
6. 接入交换机 SPAN/TAP 做真实链路验证。
7. 记录 bps、pps、CPU、内存、ClickHouse 写入延迟、API 查询延迟。

## 11. 验证记录模板

```text
服务器：
Ubuntu 版本：
CPU：
内存：
磁盘：
采集接口：
采集模式：
测试时间：
峰值 bps：
峰值 pps：
平均包长：
Collector CPU：
Collector 内存：
ClickHouse 写入延迟：
TopN 查询 P95：
是否丢包：
问题记录：
```
