# syntax=docker/dockerfile:1
FROM golang:1.23 AS build
WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/evergreen-agent ./cmd/agent

FROM registry.fedoraproject.org/fedora:40
RUN useradd --system --home /var/lib/evergreen --shell /sbin/nologin evergreen
COPY --from=build /out/evergreen-agent /usr/bin/evergreen-agent
COPY systemd/evergreen-agent.service /usr/lib/systemd/system/evergreen-agent.service
COPY config/agent.yaml /etc/evergreen/agent/agent.yaml
RUN mkdir -p /var/lib/evergreen /etc/evergreen/agent && \
    chown -R evergreen:evergreen /var/lib/evergreen && \
    chmod 600 /etc/evergreen/agent/agent.yaml
ENTRYPOINT ["/usr/bin/evergreen-agent", "--config", "/etc/evergreen/agent/agent.yaml"]
