package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

var errAnchorConflict = errors.New("monotonic anchor conflict")

// anchorCheckpoint is an immutable snapshot. Every accepted assertion advances
// Sequence, including read-only head requests, so assertion counters cannot be
// rolled back independently of journal state.
type anchorCheckpoint struct {
	Sequence uint64       `json:"sequence"`
	KeyID string           `json:"keyID"`
	PublicKey []byte       `json:"publicKey"`
	Counter uint32         `json:"counter"`
	Head witnessHead       `json:"head"`
	PreviousHash [32]byte  `json:"previousHash"`
	Hash [32]byte          `json:"hash"`
}

type anchorStore interface {
	Latest(context.Context, string) (anchorCheckpoint, bool, error)
	Append(context.Context, string, anchorCheckpoint) error
}

func checkpointHash(c anchorCheckpoint) [32]byte {
	// Explicit fixed-width/bounded encoding avoids JSON canonicalization ambiguity.
	buf := make([]byte, 0, 128+len(c.KeyID)+len(c.PublicKey))
	buf = append(buf, []byte("ORBIT-WITNESS-CHECKPOINT-V1\x00")...)
	var n8 [8]byte
	binary.BigEndian.PutUint64(n8[:], c.Sequence)
	buf = append(buf, n8[:]...)
	var n2 [2]byte
	binary.BigEndian.PutUint16(n2[:], uint16(len(c.KeyID)))
	buf = append(buf, n2[:]...)
	buf = append(buf, []byte(c.KeyID)...)
	var n4 [4]byte
	binary.BigEndian.PutUint32(n4[:], uint32(len(c.PublicKey)))
	buf = append(buf, n4[:]...)
	buf = append(buf, c.PublicKey...)
	binary.BigEndian.PutUint32(n4[:], c.Counter)
	buf = append(buf, n4[:]...)
	buf = append(buf, encodeHead(c.Head)...)
	buf = append(buf, c.PreviousHash[:]...)
	return sha256.Sum256(buf)
}

func validateCheckpoint(c anchorCheckpoint) error {
	if c.Sequence == 0 || c.KeyID == "" || len(c.KeyID) > 128 ||
		len(c.PublicKey) == 0 || len(c.PublicKey) > 4096 ||
		c.Hash != checkpointHash(c) {
		return errors.New("invalid monotonic checkpoint")
	}
	return nil
}

func installationAnchorID(verifier []byte) string {
	sum := sha256.Sum256(append([]byte("ORBIT-ANCHOR-ID-V1\x00"), verifier...))
	return hex.EncodeToString(sum[:])
}

type dynamoAnchor struct {
	client *dynamodb.Client
	table string
}

func newDynamoAnchor(client *dynamodb.Client, table string) (*dynamoAnchor, error) {
	if client == nil || table == "" { return nil, errors.New("DynamoDB anchor client and table are required") }
	return &dynamoAnchor{client: client, table: table}, nil
}

func (d *dynamoAnchor) Latest(ctx context.Context, installationID string) (anchorCheckpoint, bool, error) {
	var zero anchorCheckpoint
	out, err := d.client.Query(ctx, &dynamodb.QueryInput{
		TableName: aws.String(d.table),
		KeyConditionExpression: aws.String("installation_id = :id"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":id": &types.AttributeValueMemberS{Value: installationID},
		},
		ScanIndexForward: aws.Bool(false),
		Limit: aws.Int32(1),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil { return zero, false, fmt.Errorf("read monotonic anchor: %w", err) }
	if len(out.Items) == 0 { return zero, false, nil }
	raw, ok := out.Items[0]["checkpoint"].(*types.AttributeValueMemberB)
	if !ok { return zero, false, errors.New("anchor checkpoint field missing") }
	var c anchorCheckpoint
	if err := json.Unmarshal(raw.Value, &c); err != nil { return zero, false, err }
	seq, ok := out.Items[0]["sequence"].(*types.AttributeValueMemberN)
	if !ok { return zero, false, errors.New("anchor sequence field missing") }
	parsed, err := strconv.ParseUint(seq.Value, 10, 64)
	if err != nil || parsed != c.Sequence { return zero, false, errors.New("anchor sequence mismatch") }
	if err := validateCheckpoint(c); err != nil { return zero, false, err }
	hashAttr, ok := out.Items[0]["checkpoint_hash"].(*types.AttributeValueMemberS)
	if !ok || hashAttr.Value != hex.EncodeToString(c.Hash[:]) { return zero,false,errors.New("anchor checkpoint hash index mismatch") }
	return c, true, nil
}

func (d *dynamoAnchor) Append(ctx context.Context, installationID string, c anchorCheckpoint) error {
	if err := validateCheckpoint(c); err != nil { return err }
	latest, found, err := d.Latest(ctx,installationID)
	if err != nil { return err }
	if found {
		if latest.Hash == c.Hash { return nil }
		if latest.Sequence == ^uint64(0) || c.Sequence != latest.Sequence+1 || c.PreviousHash != latest.Hash { return errAnchorConflict }
	} else if c.Sequence != 1 || c.PreviousHash != ([32]byte{}) { return errAnchorConflict }
	raw, err := json.Marshal(c)
	if err != nil { return err }
	_, err = d.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(d.table),
		Item: map[string]types.AttributeValue{
			"installation_id": &types.AttributeValueMemberS{Value: installationID},
			"sequence": &types.AttributeValueMemberN{Value: strconv.FormatUint(c.Sequence, 10)},
			"checkpoint": &types.AttributeValueMemberB{Value: raw},
			"checkpoint_hash": &types.AttributeValueMemberS{Value: hex.EncodeToString(c.Hash[:])},
			"created_at": &types.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Unix(), 10)},
		},
		ConditionExpression: aws.String("attribute_not_exists(installation_id) AND attribute_not_exists(sequence)"),
	})
	var conditional *types.ConditionalCheckFailedException
	if errors.As(err, &conditional) {
		latest, found, readErr := d.Latest(ctx,installationID)
		if readErr == nil && found && latest.Hash == c.Hash { return nil }
		return errAnchorConflict
	}
	if err != nil { return fmt.Errorf("append monotonic anchor: %w", err) }
	return nil
}
