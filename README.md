# Nuclei-Bridge for Akto

## 概述

Nuclei-Bridge 是基于 Shadow Worker 架构的 Nuclei → Akto 集成微服务。通过 MongoDB 原子抢占机制截获 Akto 测试任务，调用 Nuclei 引擎执行漏洞扫描，将结果按 Akto 的 BSON 数据契约写回 MongoDB，实现 100% 零源码改动集成。

## 快速开始

### 1. 创建 API Collection

在 Akto Dashboard 中创建一个 API Collection，记录其 Collection ID。

### 2. 配置

编辑 `docker-compose.yml`，设置 `NUCLEI_TARGET_COLLECTION_ID` 和目标服务地址。

### 3. 启动

```bash
docker-compose up -d
```

### 4. 触发扫描

在 Akto Dashboard 中针对该 Collection 触发测试。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `MONGO_URI` | `mongodb://localhost:27017/akto` | MongoDB 连接地址 |
| `NUCLEI_TARGET_COLLECTION_ID` | 必填 | Akto API Collection ID |
| `TARGET_SCHEME` | `http` | 目标协议 |
| `TARGET_HOST` | `localhost` | 目标主机 |
| `TARGET_PORT` | `80` | 目标端口 |
| `SCAN_TIMEOUT` | `600` | 总扫描超时（秒） |
| `REQUEST_TIMEOUT` | `10` | 单请求超时（秒） |
| `MAX_CONCURRENCY` | `25` | Nuclei 并发模板数 |
| `POLL_INTERVAL` | `5` | 任务轮询间隔（秒） |
| `DEFAULT_TEMPLATES` | `cves/,misconfiguration/,...` | 扫描模板目录 |
| `LOG_LEVEL` | `INFO` | 日志级别 |
