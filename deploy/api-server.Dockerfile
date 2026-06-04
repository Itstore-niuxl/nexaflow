FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go build -o /out/api-server ./cmd/api-server

FROM alpine:3.20
COPY --from=build /out/api-server /nexaflow/api-server
EXPOSE 8080
ENTRYPOINT ["/nexaflow/api-server"]

