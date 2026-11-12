# ORBIT App Attest freshness witness

This is a TLS-only Go service for the ORBIT journal freshness witness. It is
research implementation code and is not approved for production deployment
until the security review and device integration checklist are complete.

## Requirements

- Go 1.23 or later
- Apple App Attest root certificate PEM obtained from Apple's official
  developer documentation / certificate publication
- A registered Apple App ID in the form `TEAM_ID.bundle.identifier`
- A production HTTPS certificate and private key
- AWS account with a DynamoDB table dedicated to the ORBIT monotonic anchor
- Durable SQLite storage with backups and operational monitoring

## Configuration

Required environment variables:

- `ORBIT_APP_ID`: exact Apple App ID (Team ID + bundle ID)
- `ORBIT_APP_ATTEST_ENV`: `development` or `production`
- `ORBIT_APP_ATTEST_ROOT_PEM`: path to the trusted Apple App Attest root
  certificate PEM; do not trust a client-supplied root
- `ORBIT_DB_PATH`: SQLite database path on durable storage
- `ORBIT_TLS_CERT`: HTTPS certificate chain
- `ORBIT_TLS_KEY`: matching private key
- `ORBIT_RECOVERY_PEPPER`: at least 32 characters of independently generated random server secret; keep it outside the database, back it up separately, and retain the same value across restarts and restores
- `AWS_REGION`: AWS region containing the independent anchor table
- `ORBIT_ANCHOR_TABLE`: DynamoDB table with partition key `installation_id` (String) and sort key `sequence` (Number)
- `ORBIT_LISTEN`: optional bind address; defaults to `127.0.0.1:8443`

The service refuses to start without TLS credentials and the trust root. Place
it behind a hardened TLS terminator only if the application-to-proxy channel
is also authenticated and the proxy cannot be bypassed. Do not expose the
SQLite file or its WAL files to clients.

## Endpoints

- `GET /v1/orbit/journal/attestation-challenge`
- `POST /v1/orbit/journal/register` (requires a client-generated 32-byte recovery credential)
- `POST /v1/orbit/journal/recovery-challenge`
- `POST /v1/orbit/journal/recover`
- `POST /v1/orbit/journal/head`
- `POST /v1/orbit/journal/compare-and-swap`

The JSON and binary request formats are specified in
`../JOURNAL-WITNESS-SERVICE.md`. The iOS client must use the exact configured
origin and the same App ID/environment as the server.

## Data durability

SQLite is configured for WAL mode, `synchronous=FULL`, foreign keys, a single connection, and a busy timeout. It is now a rebuildable local cache, not the freshness authority. Every registered installation has an independent append-only DynamoDB checkpoint chain. Each accepted assertion advances the chain, including read-only head requests; every checkpoint binds the App Attest key ID/public key, assertion counter, journal revision/digest/tombstone, and previous checkpoint hash. DynamoDB reads are strongly consistent and each append uses a conditional insert at the next sequence. The runtime role needs only `dynamodb:Query` and `dynamodb:PutItem` on this table. It must not have UpdateItem, DeleteItem, DeleteTable, RestoreTableToPointInTime, or table-administration permissions. Use a separate tightly controlled operator role for table lifecycle.

If SQLite is restored behind the external anchor, the service advances its local row to the latest checkpoint before accepting another assertion. If SQLite claims a state ahead of the anchor, the anchor is missing, the anchor is unavailable, or the chain is inconsistent, the service fails closed. A DynamoDB point-in-time restore creates a separate table; never repoint a running deployment to a restored/older table. Preserve the original table as the independent monotonic authority. Keep SQLite/WAL files on local storage with reliable fsync semantics and back them up consistently.

The service currently has no multi-node replication, account authentication,
operator recovery workflow, certificate pinning, or automated backup
verification. It is intended as a single-node reference implementation. A
multi-node deployment requires a strongly consistent transactional store and
a globally serialized assertion counter/head update.

## Local development

```sh
go mod tidy
go test ./...
go vet ./...
```

These commands are intentionally not run as part of the implementation pass.
The service must be tested against real Apple-generated development and
production App Attest objects before use. Synthetic fixtures can test parsing
and state transitions but cannot establish Apple's trust chain.

## Security limitations to resolve

- Review CBOR canonicality, duplicate-key handling, resource limits, and
  extension parsing against Apple's current App Attest validation guide.
- Verify Apple's current root/intermediate certificate rotation process.
- Validate the App Attest validation-category and bundle-version extensions.
- Recovery credentials are now part of enrollment. The client generates and securely preserves a uniformly random 32-byte secret and the device validation host shows it once. The server stores only a domain-separated HMAC verifier using `ORBIT_RECOVERY_PEPPER`; the raw credential is sent only over TLS during enrollment or recovery. Recovery challenges are located by the credential and bind the old and replacement key IDs server-side, expire after five minutes, and are single-use. A successful recovery replaces the App Attest key while preserving the exact journal revision, digest, tombstone, and an append-only key-recovery history row. Existing installations created before this migration have no verifier and cannot self-recover; they require a separately reviewed migration/re-enrollment process.
- The iOS client now generates the credential, stores it in device-only Keychain storage, and sends it during enrollment and recovery. The device validation host displays it once after first enrollment. The user must save it offline: losing both the device-only Keychain copy and the offline credential makes recovery impossible. The server pepper is part of the verifier derivation and must remain stable; changing it without a controlled migration invalidates every stored recovery verifier. Rate limits, production recovery UX, and abuse monitoring remain to be implemented and tested.
- The DynamoDB anchor is a reference implementation of the independent monotonic witness. Production still requires an AWS account/table, least-privilege task role, table deletion/restore protections, independent account-level administration, monitoring, and a tested disaster-recovery plan. The service fails closed if the anchor is unavailable.
- The service checks the App Attest validation-category and bundle-version
  extension structure, but does not yet enforce an operator-configured
  allowlist or bind later assertions to the exact enrolled bundle version.
- Add challenge and installation rate limits and expired-challenge cleanup.
- Add durable audit logs, database backup/restore drills, and operational
  alerting.
- Add account/device recovery without allowing key replacement to reset a
  journal head.
- Add independent service security review and production monitoring.


## Container deployment template

A single-node TLS deployment template is included:

- `Dockerfile`
- `compose.yaml`
- `.dockerignore`

Prepare private persistent data and secret files:

```sh
mkdir -p data secrets
sudo chown 65532:65532 data
chmod 0700 data
chmod 0600 secrets/tls.key secrets/apple-app-attest-root.pem
```

Place the TLS certificate at `secrets/tls.crt`, the private key at
`secrets/tls.key`, and Apple's official App Attest root certificate PEM at
`secrets/apple-app-attest-root.pem`. Do not download a trust root from an
unverified mirror.

Create the DynamoDB table (partition key `installation_id` String, sort key
`sequence` Number) before starting the service. Grant the container an AWS task
role with only `dynamodb:Query` and `dynamodb:PutItem` on that table; do not
inject long-lived AWS access keys into the container. Then configure
`ORBIT_APP_ID`, `ORBIT_APP_ATTEST_ENV`, `AWS_REGION`, `ORBIT_ANCHOR_TABLE`, and a
stable random `ORBIT_RECOVERY_PEPPER` (at least 32 random bytes encoded as
text) in the deployment environment and run:

```sh
docker compose up --build -d
curl --fail https://YOUR-WITNESS-HOST/healthz
```

The container runs as UID/GID 65532 with a read-only root filesystem and
capabilities dropped. The host data directory must remain durable and
accessible only to the service account. Back up the SQLite database using a
consistent SQLite backup procedure; never copy only the main database file
while a WAL is active.

This template is not a substitute for production operations engineering:
TLS renewal, monitoring, verified backup/restore, rate limiting, account
authentication, disaster recovery, and a multi-node consistency design are
still required.
