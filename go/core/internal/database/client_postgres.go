package database

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

// Client persists control-plane state in PostgreSQL. Callers define the narrow
// interfaces they need; SQL rows and protobuf encoding stay inside the store.
type Client struct {
	db      *pgxpool.Pool
	crypter PayloadCrypter
}

// ClientOption configures optional Client behavior.
type ClientOption func(*Client)

// WithPayloadCrypter encrypts task and event payloads with crypter before they are
// written and decrypts them after they are read. Omitting this option keeps payloads as
// plaintext, the default; existing plaintext rows keep reading correctly either way.
func WithPayloadCrypter(crypter PayloadCrypter) ClientOption {
	return func(c *Client) { c.crypter = crypter }
}

// NewClient wraps an existing PostgreSQL pool without connecting or migrating. The caller
// owns the pool and must close it.
func NewClient(db *pgxpool.Pool, opts ...ClientOption) *Client {
	c := &Client{db: db}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// encryptPayload serializes msg and, when a PayloadCrypter is configured, encrypts the
// result. taskID and messageID (empty for task-level payloads) bind the ciphertext to the
// row it will be stored in; see payloadAAD. A nil crypter returns the plaintext bytes
// unchanged and a nil key ID, so the row is stored and later read as plaintext.
func (c *Client) encryptPayload(ctx context.Context, msg proto.Message, taskID, messageID string) ([]byte, *string, error) {
	data, err := proto.Marshal(msg)
	if err != nil {
		return nil, nil, err
	}
	if c.crypter == nil {
		return data, nil, nil
	}
	ciphertext, keyID, err := c.crypter.Encrypt(ctx, data, payloadAAD(taskID, messageID))
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt payload: %w", err)
	}
	return ciphertext, &keyID, nil
}

// decryptPayload reverses encryptPayload. keyID is the row's stored encryption_key_id; nil
// means the row is plaintext and data is returned unchanged.
func (c *Client) decryptPayload(ctx context.Context, data []byte, keyID *string, taskID, messageID string) ([]byte, error) {
	if keyID == nil {
		return data, nil
	}
	if c.crypter == nil {
		return nil, fmt.Errorf("row is encrypted with key %q but no PayloadCrypter is configured", *keyID)
	}
	plaintext, err := c.crypter.Decrypt(ctx, *keyID, data, payloadAAD(taskID, messageID))
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}
	return plaintext, nil
}

// withTx commits all callback writes together on success and rolls them back on failure,
// returning callback or transaction errors. The callback must keep external network work
// outside the transaction.
func (c *Client) withTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := c.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// notFoundOr maps pgx.ErrNoRows to ErrNotFound and leaves all other errors, including nil,
// unchanged.
func notFoundOr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// strPtrIfNotEmpty returns nil for an empty string and a pointer to a copy otherwise.
func strPtrIfNotEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// derefStr returns the pointed-to string, or an empty string for nil.
func derefStr(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}
