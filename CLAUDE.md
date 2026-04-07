# CLAUDE.md

## 项目概述

SSL Tools — 极简 SSL/TLS 诊断工具。输入域名或 URL，分时输出诊断结果：概览、证书信息、HTTP 安全头、协议与加密。

## 开发命令

### 构建和运行

```bash
go build -o server ./cmd/server
./server
# 默认端口 18700，访问 http://localhost:18700
./server -port 8080
```

### 测试

```bash
go test ./...
go test ./internal/diagnose/ -v
```

### Docker

```bash
docker-compose up --build -d
# 国内服务器
USE_CN_PROXY=true docker-compose up --build -d
```

## 架构

- `cmd/server/main.go` — 入口，路由，静态文件，区域检测
- `internal/handler/` — SSE 处理器，编排 4 阶段诊断
- `internal/diagnose/` — 诊断引擎（TCP / TLS / 证书 / HTTP / 协议探测 / 问题识别）
- `static/` — 纯静态前端（HTML + CSS + JS）

## API

- `GET /api/diagnose?host=&port=` — SSE 流式诊断
- `GET /api/health` — 健康检查
- `GET /api/regions` — 区域列表

## 设计文档

`docs/superpowers/specs/2026-04-07-ssl-diagnose-design.md`
