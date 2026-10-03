FROM golang:1.25 AS build

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
ARG VERSION=0.1.0
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X github.com/synit-io/forti-intelligence/internal/mcpserver.ServerVersion=${VERSION}" -o /out/forti-intelligence ./cmd/forti-intelligence

# base (not static) ships the CA bundle and zoneinfo. The nonroot tag already
# runs as uid 65532, so the image does not add users.
FROM gcr.io/distroless/base-debian12:nonroot
LABEL org.opencontainers.image.title="Forti Intelligence" \
      org.opencontainers.image.description="Read-only Fortinet troubleshooting MCP server" \
      org.opencontainers.image.source="https://github.com/synit-io/forti-intelligence" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/forti-intelligence /forti-intelligence
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/doc/forti-intelligence/
EXPOSE 8080
# /ready reports whether the first inventory snapshot exists. When
# FORTI_MCP_HTTP_TOKEN is set, the check sends it as a bearer token.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD ["/forti-intelligence", "--healthcheck", "http://127.0.0.1:8080/ready"]
ENV FORTI_INTELLIGENCE_CONFIG=/etc/forti-intelligence/config.yaml
ENTRYPOINT ["/forti-intelligence"]
CMD ["--transport", "http", "--listen", "0.0.0.0:8080"]
