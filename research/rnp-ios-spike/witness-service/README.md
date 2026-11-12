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
- Durable storage with backups and operational monitoring

## Configuration

Required environment variables:

- `ORBIT_APP_ID`: exact Apple App ID (Team ID + bundle ID)
- `ORBIT_APP_ATTEST_ENV`: `development` or `production`
- `ORBIT_APP_ATTEST_ROOT_PEM`: path to the trusted Apple App Attest root
  certificate PEM; do not trust a client-supplied root
- `ORBIT_DB_PATH`: SQLite database path on durable storage
- `ORBIT_TLS_CERT`: HTTPS certificate chain
- `ORBIT_TLS_KEY`: matching private key
- `ORBIT_RECOVERY_PEPPER`: at least 32 characters of independently generated random server secret; keep it outside the database and back it up separately
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

SQLite is configured for WAL mode, `synchronous=FULL`, foreign keys, a
single connection, and a busy timeout. Keep the database, WAL, and shared
memory files on a local filesystem with reliable fsync semantics. Backups
must preserve transaction consistency. A restored old database is a security
incident: stop serving requests and restore from a verified current backup;
never start with an empty database for an existing App Attest installation.

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
- Recovery credentials are now part of enrollment. The client must generate and securely preserve a uniformly random 32-byte secret and show/export it only once. The server stores only a domain-separated HMAC verifier using `ORBIT_RECOVERY_PEPPER`; the raw credential is sent only over TLS during enrollment or recovery. Recovery challenges bind the old and replacement key IDs, expire after five minutes, and are single-use. A successful recovery replaces the App Attest key while preserving the exact journal revision, digest, tombstone, and an append-only key-recovery history row. Existing installations created before this migration have no verifier and cannot self-recover; they require a separately reviewed migration/re-enrollment process.
- This recovery flow has not yet been integrated into the iOS client, and rate limits, credential display/backup UX, secure local storage, and recovery abuse monitoring remain to be implemented and tested.
- SQLite is durable for process/device crashes but can itself be rolled back
  by restoring an older host/database snapshot. A production deployment needs
  an independently protected monotonic witness or strongly consistent
  externally anchored store; ordinary SQLite backups alone are insufficient.
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

Then configure `ORBIT_APP_ID` and `ORBIT_APP_ATTEST_ENV` in the deployment
environment and run:

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
