# syntax=docker/dockerfile:1.7

# ── Build ──
# Queries are checked against the committed .sqlx/ data, so no database is
# needed at build time. Templates, static files and migrations are embedded.
FROM rust:1.99-slim-bookworm AS build
WORKDIR /src
ENV SQLX_OFFLINE=true CARGO_TERM_COLOR=never

# Dependencies first, against stub sources, so they're only rebuilt when
# Cargo.toml/Cargo.lock change. The registry and target dir are cache mounts.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && touch src/lib.rs
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && rm -rf src

COPY . .
# COPY keeps the files' original mtimes, which can be older than the stub build;
# touching the crate roots makes cargo rebuild the real code.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    touch src/main.rs src/lib.rs \
    && cargo build --release --locked \
    && cp target/release/monitor /monitor

# ── Run ──
# Distroless: glibc, CA certificates and nothing else (no shell), as a non-root user.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /monitor /usr/local/bin/monitor
ENV BIND_ADDR=0.0.0.0:3000 LOG_FORMAT=json
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/monitor", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/monitor"]
CMD ["all"]
