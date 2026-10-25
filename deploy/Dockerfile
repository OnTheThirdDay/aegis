# Rootless AegisNet gateway image (06 §4). No TUN, no NET_ADMIN.
#
# Supply-chain note: pin both base images to reviewed immutable digests
# (FROM image@sha256:...) before producing release artifacts. Tags below are
# development placeholders and are NOT an approved provenance baseline.
FROM rust:1.97.1-slim-bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --locked --release -p aegisd -p aegisctl

FROM debian:bookworm-slim
RUN groupadd --system --gid 10001 aegisnet \
    && useradd --system --uid 10001 --gid 10001 --home-dir /var/lib/aegisnet --shell /usr/sbin/nologin aegisnet \
    && apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o 10001 -g 10001 -m 0700 /var/lib/aegisnet \
    && install -d -m 0755 /etc/aegisnet
COPY --from=build /src/target/release/aegisd /usr/local/bin/aegisd
COPY --from=build /src/target/release/aegisctl /usr/local/bin/aegisctl
USER 10001:10001
VOLUME ["/var/lib/aegisnet"]
# Health uses the owner-only local IPC socket; there is deliberately no
# unauthenticated HTTP health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["/usr/local/bin/aegisctl", "--socket", "/var/lib/aegisnet/aegisd.sock", "health"]
ENTRYPOINT ["/usr/local/bin/aegisd", "--config", "/etc/aegisnet/config.toml"]
