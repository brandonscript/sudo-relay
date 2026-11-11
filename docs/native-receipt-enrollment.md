# Native receipt enrollment

This record configures the read-only native receipt reviewer in disposable tests.
It is not a production installer or permission to execute commands. The root test
controller creates it; the reviewing application cannot enroll itself.

```json
{
  "version": 1,
  "receipt_only": true,
  "machine_id": "00000000-0000-4000-8000-000000000001",
  "socket": "/protected/fixture/broker.sock",
  "approver_uid": 10002,
  "machine_name": "protected-receipt-fixture",
  "operating_system": "Disposable OS fixture",
  "account": "test-user"
}
```

The file and its ancestors must be root-owned and not writable by other accounts.
The file is bounded to 4096 bytes. It contains no signing secret; fixture mode 0644
allows the designated ordinary user to read it. The loader rejects another UID,
unknown fields/versions, relative socket paths, invalid machine UUIDs, control
characters and oversized display labels. Only receipt-only records are accepted.

The native model receives this file's path and a request ID. It obtains the socket,
machine pin and subtitle from the record, authenticates the root socket before
sending data, and requires a receipt-only server response. The returned request
must match the reference, machine, canonical bytes and validity window. The loader
returns the verified model and both output-sharing decision payloads; it cannot
sign or submit them. Failure has no caller-data or session-mode fallback.

`approver_uid` identifies the reviewing account, not the sudo sponsor. The `account`
field is currently a fixture display label, not evidence of installer provenance.
UID reuse, protected signing-key persistence, policy update/revocation across a
review, anti-rollback and signed native deployment remain open. The interactive
Touch ID app is not automatically connected to this root fixture.

Local schema/negative checks pass. The root CI fixture covers the actual file,
account and socket boundaries with disposable software keys; the new enrollment
record cases await their own CI run. No personal-machine root service is installed.
