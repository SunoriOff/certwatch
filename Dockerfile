# Étape 1 : compilation
FROM rust:1.88-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY assets assets
COPY examples examples
RUN cargo build --release --locked --bin certwatch

# Étape 2 : image d'exécution minimale, sans shell, utilisateur non privilégié
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/certwatch /usr/local/bin/certwatch
WORKDIR /data
EXPOSE 8088
ENTRYPOINT ["/usr/local/bin/certwatch", "-c", "/etc/certwatch/certwatch.toml"]
CMD ["serve"]
