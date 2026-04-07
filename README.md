# SSL Tools

极简 SSL/TLS 诊断工具，帮助快速定位 SSL 证书和连接问题。

## 功能

- **TCP 连接探测** — 检测端口是否可达
- **TLS 握手诊断** — 获取证书信息，即使证书有问题也能获取
- **证书分析** — 有效期、域名匹配、链完整性、签发者可信度
- **HTTP 安全头** — HSTS、CSP、X-Frame-Options 等
- **协议与加密** — TLS 版本支持、加密套件、不安全配置检测
- **问题诊断** — 自动识别问题并给出修复建议
- **多区域** — CN/US 区域切换，对比 GFW/CDN 差异

## 快速开始

### 本地运行

```bash
go build -o server ./cmd/server
./server
# 访问 http://localhost:18700
```

### Docker

```bash
docker-compose up --build -d
```

国内服务器：

```bash
USE_CN_PROXY=true docker-compose up --build -d
```

## 技术栈

- Go 1.23+
- crypto/tls（TLS 诊断核心）
- Gorilla Mux（路由）
- SSE（分时推送）
- 纯 HTML + CSS + JS（前端）
