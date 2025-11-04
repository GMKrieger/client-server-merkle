# Dockerfile
FROM rust:1.74 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/server /usr/local/bin/server
CMD ["server"]
