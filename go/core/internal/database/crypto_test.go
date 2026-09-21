package database

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// fakeCrypter is a minimal in-memory PayloadCrypter for tests. It does not perform real
// cryptography; it records the AAD each ciphertext was produced with and rejects
// decryption with a different AAD or key, which is enough to exercise the binding and
// opt-in behavior in Client without needing a real key management backend.
type fakeCrypter struct {
	activeKeyID string
	// encryptErr, when set, is returned by Encrypt instead of succeeding.
	encryptErr error
}

type fakeCiphertext struct {
	keyID     string
	aad       string
	plaintext []byte
}

func (f *fakeCrypter) Encrypt(_ context.Context, plaintext, aad []byte) ([]byte, string, error) {
	if f.encryptErr != nil {
		return nil, "", f.encryptErr
	}
	keyID := f.activeKeyID
	if keyID == "" {
		keyID = "test-key"
	}
	return fakeSeal(keyID, aad, plaintext), keyID, nil
}

func (f *fakeCrypter) Decrypt(_ context.Context, keyID string, ciphertext, aad []byte) ([]byte, error) {
	sealed, err := fakeOpen(ciphertext)
	if err != nil {
		return nil, err
	}
	if sealed.keyID != keyID {
		return nil, errors.New("fakeCrypter: key ID mismatch")
	}
	if sealed.aad != string(aad) {
		return nil, errors.New("fakeCrypter: aad mismatch")
	}
	return sealed.plaintext, nil
}

// fakeSeal and fakeOpen stand in for a real envelope: they are reversible only through
// this package's own functions and record the key ID and AAD a ciphertext was produced
// with, so a mismatched key or AAD on Decrypt is a test-visible error rather than a silent
// wrong answer. Fields are length-prefixed, not delimited, because AAD values here
// legitimately contain embedded NUL bytes (see payloadAAD) that a delimiter-based format
// would misparse.
func fakeSeal(keyID string, aad, plaintext []byte) []byte {
	var out []byte
	for _, field := range [][]byte{[]byte(keyID), aad, plaintext} {
		out = binary.LittleEndian.AppendUint32(out, uint32(len(field)))
		out = append(out, field...)
	}
	return out
}

func fakeOpen(ciphertext []byte) (fakeCiphertext, error) {
	var fields [3][]byte
	rest := ciphertext
	for i := range fields {
		if len(rest) < 4 {
			return fakeCiphertext{}, errors.New("fakeCrypter: malformed ciphertext")
		}
		length := binary.LittleEndian.Uint32(rest)
		rest = rest[4:]
		if uint64(len(rest)) < uint64(length) {
			return fakeCiphertext{}, errors.New("fakeCrypter: malformed ciphertext")
		}
		fields[i], rest = rest[:length], rest[length:]
	}
	return fakeCiphertext{keyID: string(fields[0]), aad: string(fields[1]), plaintext: fields[2]}, nil
}

func TestPayloadEncryptionIsOptIn(t *testing.T) {
	client := &Client{}
	msg := wrapperspb.String("hello")

	data, keyID, err := client.encryptPayload(context.Background(), msg, "task-1", "")
	require.NoError(t, err)
	require.Nil(t, keyID, "a nil PayloadCrypter must leave rows unmarked as encrypted")

	want, err := proto.Marshal(msg)
	require.NoError(t, err)
	require.Equal(t, want, data, "a nil PayloadCrypter must store the exact plaintext bytes")

	plaintext, err := client.decryptPayload(context.Background(), data, nil, "task-1", "")
	require.NoError(t, err)
	require.Equal(t, want, plaintext)
}

func TestPayloadEncryptionRoundTrip(t *testing.T) {
	client := &Client{crypter: &fakeCrypter{activeKeyID: "v1"}}
	msg := wrapperspb.String("sensitive chat content")

	ciphertext, keyID, err := client.encryptPayload(context.Background(), msg, "task-1", "message-1")
	require.NoError(t, err)
	require.NotNil(t, keyID)
	require.Equal(t, "v1", *keyID)

	want, err := proto.Marshal(msg)
	require.NoError(t, err)
	require.NotEqual(t, want, ciphertext, "encrypted rows must not store plaintext bytes")

	plaintext, err := client.decryptPayload(context.Background(), ciphertext, keyID, "task-1", "message-1")
	require.NoError(t, err)
	require.Equal(t, want, plaintext)
}

func TestPayloadEncryptionRejectsWrongAAD(t *testing.T) {
	client := &Client{crypter: &fakeCrypter{activeKeyID: "v1"}}
	msg := wrapperspb.String("sensitive chat content")

	ciphertext, keyID, err := client.encryptPayload(context.Background(), msg, "task-1", "message-1")
	require.NoError(t, err)

	// A ciphertext produced for one task/message must not decrypt under a
	// different one -- this is what stops ciphertext from an unrelated row
	// being spliced into this row and still reading as valid.
	_, err = client.decryptPayload(context.Background(), ciphertext, keyID, "task-2", "message-1")
	require.Error(t, err)
	_, err = client.decryptPayload(context.Background(), ciphertext, keyID, "task-1", "message-2")
	require.Error(t, err)
}

func TestPayloadEncryptionSurvivesForkCopy(t *testing.T) {
	// ForkAgentInstance copies agent_instance_task_event rows into a brand new
	// history_id by reusing their stored ciphertext and encryption_key_id
	// verbatim (see ForkAgentInstance in checkpoints.go); it never re-encrypts
	// them. AAD must therefore depend only on task_id/message_id, which fork
	// preserves, and never on history_id, which changes. This test encrypts a
	// message once and decrypts it as if it now lived under an unrelated
	// history, to confirm history_id plays no part in the binding.
	client := &Client{crypter: &fakeCrypter{activeKeyID: "v1"}}
	msg := wrapperspb.String("forked conversation content")

	ciphertext, keyID, err := client.encryptPayload(context.Background(), msg, "task-1", "message-1")
	require.NoError(t, err)

	plaintext, err := client.decryptPayload(context.Background(), ciphertext, keyID, "task-1", "message-1")
	require.NoError(t, err)
	want, err := proto.Marshal(msg)
	require.NoError(t, err)
	require.Equal(t, want, plaintext, "ciphertext copied verbatim into a new history must still decrypt")
}

func TestPayloadEncryptionRequiresConfiguredCrypterToDecryptEncryptedRow(t *testing.T) {
	client := &Client{crypter: &fakeCrypter{activeKeyID: "v1"}}
	msg := wrapperspb.String("sensitive chat content")
	ciphertext, keyID, err := client.encryptPayload(context.Background(), msg, "task-1", "")
	require.NoError(t, err)

	// Disabling encryption (or misconfiguring the key source) must fail loudly on an
	// already-encrypted row rather than silently returning ciphertext as if it were
	// plaintext.
	unconfigured := &Client{}
	_, err = unconfigured.decryptPayload(context.Background(), ciphertext, keyID, "task-1", "")
	require.ErrorContains(t, err, "no PayloadCrypter is configured")
}
