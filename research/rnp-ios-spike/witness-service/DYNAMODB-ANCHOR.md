# ORBIT external monotonic anchor — DynamoDB deployment

## Table contract

Create a dedicated table with:

- Partition key: `installation_id` (String)
- Sort key: `sequence` (Number)
- Billing: on-demand or provisioned capacity sized for one append per accepted App Attest assertion (including each read-only head request)
- Point-in-time recovery: enabled for operational recovery, not as a rollback mechanism
- Encryption at rest: enabled (AWS owned key minimum; customer-managed KMS key preferred)
- Deletion protection: enabled
- No TTL on checkpoint items
- No application write path that updates or deletes existing checkpoint rows

Example:

```sh
aws dynamodb create-table \
  --table-name "$ORBIT_ANCHOR_TABLE" \
  --attribute-definitions AttributeName=installation_id,AttributeType=S AttributeName=sequence,AttributeType=N \
  --key-schema AttributeName=installation_id,KeyType=HASH AttributeName=sequence,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST \
  --region "$AWS_REGION"

aws dynamodb update-continuous-backups \
  --table-name "$ORBIT_ANCHOR_TABLE" \
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true \
  --region "$AWS_REGION"

aws dynamodb update-table \
  --table-name "$ORBIT_ANCHOR_TABLE" \
  --deletion-protection-enabled \
  --region "$AWS_REGION"
```

## Runtime role

The witness container must use an instance/task role or workload identity. Do not put long-lived AWS access keys in the container environment or image.

Minimum runtime permissions on the exact table ARN:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AppendAndReadORBITCheckpoints",
      "Effect": "Allow",
      "Action": [
        "dynamodb:Query",
        "dynamodb:PutItem"
      ],
      "Resource": "arn:aws:dynamodb:REGION:ACCOUNT_ID:table/ORBIT_ANCHOR_TABLE"
    }
  ]
}
```

Do not grant the runtime role `UpdateItem`, `DeleteItem`, `BatchWriteItem`,
`DeleteTable`, `UpdateTable`, `RestoreTableToPointInTime`, `CreateTable`,
or IAM permissions. The application performs conditional inserts only and
strongly consistent reads. Every item is keyed by a stable installation ID (SHA-256 of the server-side
recovery verifier) and monotonically increasing sequence. The client supplies
the recovery credential in each signed-request wrapper so the service can
recompute that ID and find the same checkpoint stream after a local SQLite
restore, even when the local key ID or installation row is missing. The checkpoint includes a hash of its
predecessor, and the service rejects non-contiguous writes.

## Administrative separation

Deletion protection and the runtime role are not sufficient against a cloud
account administrator. Protect the table and its role with separate operator
controls:

- Restrict table deletion, replacement, restore, and policy changes to a
  break-glass role with MFA and approval.
- Use an AWS Organizations SCP or equivalent guardrail to deny destructive
  table actions to normal deployment roles.
- Alert on table deletion-protection changes, table deletion, restore, IAM
  policy changes, and runtime role changes.
- Do not repoint `ORBIT_ANCHOR_TABLE` to a restored table after a database
  incident. A point-in-time restore creates a new table and is for forensic or
  recovery use only. The original monotonic table remains authoritative.
- Back up the SQLite cache independently, but never treat a SQLite restore as
  authority over the external checkpoint.
- Retain the DynamoDB table for the full lifetime of the installation records.
  Checkpoints have no TTL and must not be pruned without a separately designed
  checkpoint compaction protocol with an independently protected root.

## Failure semantics

The service appends an anchor checkpoint before committing the matching
SQLite transaction. If SQLite commit fails after the append, the next request
can repair SQLite forward from the latest checkpoint. If DynamoDB is
unavailable, the request fails closed. If SQLite is ahead of DynamoDB, if the
anchor item is malformed, or if a checkpoint hash/sequence does not match,
the service rejects the request and requires operator investigation.

This design protects against restoring an older SQLite database while the
original DynamoDB table and its access controls remain intact. It does not
protect against compromise of the AWS account/runtime role, malicious
administrators, a deliberately restored/repointed anchor table, or a broken
DynamoDB/IAM configuration. Those risks require independent account controls,
monitoring, and security review.
