FROM rust@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07 AS build
WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY security-lab/integrated-sudo/controller.rs ./security-lab/integrated-sudo/controller.rs
COPY security-lab/sudo-prototype/Cargo.toml security-lab/sudo-prototype/Cargo.lock ./security-lab/sudo-prototype/
COPY security-lab/sudo-prototype/src ./security-lab/sudo-prototype/src
COPY security-lab/native-execution/bridge-check.rs ./security-lab/native-execution/bridge-check.rs
RUN cargo build --locked --features integrated-sudo-lab,native-execution-lab --bin integrated-sudo-lab --bin mcp-server --bin execution-review-check
RUN cargo build --locked --release --manifest-path security-lab/sudo-prototype/Cargo.toml
FROM python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
RUN apt-get update && apt-get install -y --no-install-recommends sudo openssl openssh-client openssh-server && rm -rf /var/lib/apt/lists/* \
    && useradd -u 11001 -M sponsor_a && useradd -u 11002 -M sponsor_b \
    && useradd -u 11003 -M approver && useradd -u 11004 -M agent \
    && passwd -d approver && usermod -a -G agent approver
COPY --from=build /source/target/debug/execution-review-check /usr/local/bin/execution-review-check
COPY --from=build /source/target/debug/mcp-server /usr/local/bin/mcp-server
COPY --from=build /source/target/debug/integrated-sudo-lab /usr/local/bin/integrated-sudo-lab
COPY --from=build /source/security-lab/sudo-prototype/target/release/libsudo_relay_pam_prototype.so /usr/local/lib/pam_relay_prototype.so
COPY --from=build /source/security-lab/sudo-prototype/target/release/approval-gate /usr/local/bin/approval-gate
COPY security-lab/sudo-prototype/pam-sudo /etc/pam.d/sudo-relay
COPY security-lab/integrated-sudo/launcher.py security-lab/integrated-sudo/test_integration.py /integration/
COPY security-lab/integrated-sudo/test_mcp.py security-lab/integrated-sudo/approver.py security-lab/integrated-sudo/test_ssh.py security-lab/integrated-sudo/human_session.py security-lab/integrated-sudo/ssh_stdio.py /integration/
COPY security-lab/integrated-sudo/output-probe /usr/local/bin/output-probe
RUN chmod 755 /usr/local/bin/output-probe && printf '<p>Automated fixture: no human approval UI.</p>' > /integration/approval.html
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "-I", "/integration/test_integration.py"]
