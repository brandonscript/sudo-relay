# Concurrent approval

Case ID `mcp-linux-software-004`

## Prerequisites

Docker Engine and Compose must be running. Open a terminal in the source checkout. This case executes fixed commands as root inside disposable Linux, with an automated software signer and separate peer identities.

## Procedure

1. Create a unique Compose project and a shortcut in this terminal.
   ```sh
   SUDO_RELAY_CASE="sr-case-$(date +%Y%m%d%H%M%S)-$$"
   fixture() {
     docker compose -p "$SUDO_RELAY_CASE" \
       -f security-lab/integrated-sudo/compose.yaml "$@"
   }
   ```
2. Build the fixture image.
   ```sh
   fixture build
   ```
3. Run this case in a fresh container. The selected test's setup installs its fixture and initializes the role identities.
   ```sh
   fixture run --rm --no-deps --entrypoint python3 integration \
     -I /integration/test_mcp.py McpSudo.test_concurrent_approval_consumes_once
   ```
4. Save the test output and exit status. A passing run ends with `OK` and exits with status 0. Compare the assertions below with the [test implementation](../../security-lab/integrated-sudo/test_mcp.py).

## Expected result

Exactly one succeeds and the launch count increases by one.

## Cleanup

Run this in the same terminal even if the test failed.

```sh
fixture down --volumes --remove-orphans
```

Docker retains the image and build cache. Record cleanup failures before removing the project manually.

## Recorded results

✅ A passing historical run is documented in the [evidence report](../mcp-sudo-milestone.md#acceptance-tests). That report retains its original scope and failure history. This runbook was written from the existing case and source; it has not been rerun as part of this documentation change. Missing historical version or artifact metadata remains unrecorded.

For a new result, record the date, result, exact software/client/OS versions, architectures, source revision, relevant artifact hashes, command output, and cleanup outcome. Include sanitized request IDs and audit counts where applicable. Link that evidence here and update the tables when reviewed. See the [registry](../verification-cases.md#recording-a-run-or-vulnerability) for reporting guidance.
