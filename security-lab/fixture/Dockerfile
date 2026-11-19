FROM rust@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07 AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY security-lab/fixture/approval_payload.rs ./examples/approval_payload.rs
RUN cargo build --locked --bin broker --example approval_payload && strip target/debug/broker target/debug/examples/approval_payload

FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/debug/broker /usr/local/bin/broker
COPY --from=build /build/target/debug/examples/approval_payload /usr/local/bin/fixture-approval-payload
COPY security-lab/fixture/init.py security-lab/fixture/rpc.py security-lab/fixture/test_smoke.py security-lab/fixture/test_replay.py security-lab/fixture/test_enrollment.py /fixture/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
WORKDIR /fixture
ENTRYPOINT ["python", "/fixture/init.py"]
