# ------------------------
# --- Build Stage -------
# ------------------------
FROM rust:1.85 AS builder
WORKDIR /app

# Copy only the necessary files for building.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY .env ./

# Build the release binary.
RUN cargo build --release

# ----------------------
# --- Runtime Stage ---
# ----------------------
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary from the builder stage.
COPY --from=builder /app/target/release/luma-backend-rust .
COPY --from=builder /app/.env .env

# Create a non-root user and switch to it.
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# Run your app by default.
CMD ["./luma-backend-rust"]