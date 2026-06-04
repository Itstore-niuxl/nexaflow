FROM golang:1.22-alpine AS build
WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go build -o /out/collector ./cmd/collector

FROM alpine:3.20
COPY --from=build /out/collector /nexaflow/collector
ENTRYPOINT ["/nexaflow/collector"]
