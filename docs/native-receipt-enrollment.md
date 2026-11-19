# Native receipt enrollment

This record configures native receipt review and submission in disposable tests.
It is not a production installer or permission to execute commands. The root test
controller creates it; the reviewing application cannot enroll itself.

```json
{
  "version": 1,
  "receipt_only": true,
  "machine_id": "00000000-0000-4000-8000-000000000001",
  "socket": "/protected/fixture/broker.sock",
  "approver_uid": 10002,
  "signing_key_id": "native",
  "signing_key": "p256-sha256:<130 hex characters from the enrolled public key>",
  "machine_name": "protected-receipt-fixture",
  "operating_system": "Disposable OS fixture",
  "account": "test-user"
}
```

Replace the signing-key placeholder with the real uncompressed public point;
the placeholder itself is deliberately invalid. No private key belongs here.

The file and its ancestors must be root-owned and not writable by other accounts.
The file is bounded to 4096 bytes. It contains no signing secret; fixture mode 0644
allows the designated ordinary user to read it. The loader rejects another UID,
unknown fields/versions, invalid or non-P-256 public keys, relative socket paths,
invalid machine UUIDs, control
characters and oversized display labels. Only receipt-only records are accepted.

The native model receives this file's path and a request ID. It obtains the socket,
machine pin and subtitle from the record, authenticates the root socket before
sending data, and requires a receipt-only server response. The returned request
must match the reference, machine, canonical bytes and validity window. The loader
returns the verified model and both output-sharing decision payloads; fetching
does not sign or submit them. A separate receipt submission operation consumes
an existing signature. Failure has no caller-data or session-mode fallback.

`approver_uid` identifies the reviewing account, not the sudo sponsor. The `account`
field is currently a fixture display label, not evidence of installer provenance.
UID reuse, protected signing-key persistence, policy update/revocation across a
review, anti-rollback and signed native deployment remain open. The interactive
Touch ID app is not automatically connected to this root fixture.

Local schema/negative checks pass. The root CI fixture covers the actual file,
account and socket boundaries with disposable software keys; the new enrollment
record cases passed full CI run 42943601838. No personal-machine root service is
installed. The headless Swift model and software signature passed the separate
approving-account macOS root job in CI run 42944467261; this does not test a
protected hardware key or interactive UI.

Before signing, the native protected flow compares its loaded public key against
this administrator-provided key. A mismatch fails before signature generation.
The broker remains the final authority for key trust and revocation; this local
check cannot replace its signature verification. The older same-user fixture
constructor has no protected key pin and cannot pass this check. Key persistence,
protected interactive integration and atomic enrollment updates remain open.

Protected receipt decisions use the separate CBOR domain
`sudo-relay/receipt-decision/v1` and the `approve_receipt` wire method. An
execution-mode broker rejects that method; changing it to `approve` still fails
because execution approval uses different signed bytes. Only the receipt-only
socket dispatcher enables receipt verification, which consumes without returning
an execution job. The request envelope and output-sharing choice remain bound
inside the receipt signature. Existing same-user protocol experiments remain
separate and must not be mistaken for this protected receipt path.

The submission bridge accepts only the enrollment path, request ID, signature and
output-sharing choice. It rereads protected enrollment, retrieves the current
pending request from the authenticated socket, and verifies the signature against
the enrolled public key before sending `approve_receipt`. The broker independently
checks its current key/revocation state and consumes once. Key ID comes from the
protected record, never from an agent-supplied submission field.

Success requires a matching receipt-only consumption acknowledgement. Every
other result is treated as unconfirmed; a lost reply can follow consumption. No
automatic signature or submission retry occurs. The enrollment reread is not an
atomic policy-revocation mechanism; broker key revocation still provides the
transactional consumption gate.
