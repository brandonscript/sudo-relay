FROM rust@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07 AS build
WORKDIR /prototype
COPY security-lab/sudo-prototype/Cargo.toml security-lab/sudo-prototype/Cargo.lock ./
COPY security-lab/sudo-prototype/src ./src
RUN cargo build --release --locked && strip target/release/libsudo_relay_pam_prototype.so target/release/approval-gate

FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
RUN apt-get update && apt-get install -y --no-install-recommends sudo openssl && rm -rf /var/lib/apt/lists/* \
    && useradd -u 11001 -M sponsor_a && useradd -u 11002 -M sponsor_b && useradd -u 11003 -M approver
COPY --from=build /prototype/target/release/libsudo_relay_pam_prototype.so /usr/local/lib/pam_relay_prototype.so
COPY --from=build /prototype/target/release/approval-gate /usr/local/bin/approval-gate
COPY security-lab/sudo-prototype/pam-sudo /etc/pam.d/sudo-relay
COPY security-lab/sudo-prototype/test_prototype.py /prototype/test_prototype.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PE_SUDO_PROTOTYPE=1
WORKDIR /prototype
ENTRYPOINT ["python", "/prototype/test_prototype.py"]
