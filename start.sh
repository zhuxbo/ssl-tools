#!/bin/bash

echo "启动 SSL Tools..."

if ! docker info >/dev/null 2>&1; then
    echo "Docker 未运行，请先启动 Docker"
    exit 1
fi

echo "停止现有服务..."
docker compose down 2>/dev/null

echo "构建并启动服务..."
docker compose up --build -d

echo "等待服务启动..."
sleep 3

if curl -s http://localhost:18700/api/health >/dev/null; then
    echo "SSL Tools 启动成功!"
    echo ""
    echo "访问地址: http://localhost:18700"
    echo ""
    docker ps --filter "name=ssl-tools"
else
    echo "服务启动失败，请检查日志:"
    docker compose logs
    exit 1
fi
