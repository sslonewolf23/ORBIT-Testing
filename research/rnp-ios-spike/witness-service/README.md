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
- `ORBIT_LISTEN`: optional bind address; defaults to `127.0.0.1:8443`

The service refuses to start without TLS credentials and the trust root. Place
it behind a hardened TLS terminator only if the application-to-proxy channel
is also authenticated and the proxy cannot be bypassed. Do not expose the
SQLite file or its WAL files to clients.

## Endpoints

- `GET /v1/orbit/journal/attestation-challenge`
- `POST /v1/orbit/journal/register`
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
- Add challenge and installation rate limits and expired-challenge cleanup.
- Add durable audit logs, database backup/restore drills, and operational
  alerting.
- Add account/device recovery without allowing key replacement to reset a
  journal head.
- Add independent service security review and production monitoring.
