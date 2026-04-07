ARG USE_CN_PROXY=false

FROM golang:1.23-alpine AS builder

ARG USE_CN_PROXY
ARG GOPROXY

RUN if [ "$USE_CN_PROXY" = "true" ]; then \
        sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories; \
    fi

RUN apk add --no-cache git

WORKDIR /app

RUN if [ -n "$GOPROXY" ]; then \
        go env -w GOPROXY=$GOPROXY; \
    elif [ "$USE_CN_PROXY" = "true" ]; then \
        go env -w GOPROXY=https://goproxy.cn,direct; \
    fi

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/server

FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata wget

WORKDIR /app

COPY --from=builder /app/server .
COPY --from=builder /app/static ./static
COPY --from=builder /app/regions.json .

EXPOSE 18700

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=30s \
    CMD wget --quiet --tries=1 --spider http://localhost:18700/api/health || exit 1

CMD ["./server"]
