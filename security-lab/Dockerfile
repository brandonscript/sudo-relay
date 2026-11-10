FROM rust@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07 AS broker-build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
COPY ui/test/fixture.json ./ui/test/fixture.json
RUN cargo build --locked --bins && cargo test --locked --no-run

FROM node:24-bookworm-slim@sha256:01d566e8d94d8c619591d78652babfccd3c6992a3dffa9ed5ab39e11cf6c70e9 AS ui-build
WORKDIR /app/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui ./
COPY scripts /app/scripts
RUN npm run check && npm test && npm run build

FROM rust@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07
COPY --from=broker-build /build/target/debug/broker /usr/local/bin/broker
COPY --from=broker-build /build/target/debug /build/target/debug
COPY --from=ui-build /usr/local/bin/node /usr/local/bin/node
COPY --from=ui-build /app/ui /app/ui
COPY security-lab/lab.py /app/lab.py
WORKDIR /app
ENV HOME=/tmp PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python3", "-u", "/app/lab.py"]
