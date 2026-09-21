package database

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func testKey(fill byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = fill
	}
	return key
}

func TestLocalKeyCrypterRejectsInvalidConfiguration(t *testing.T) {
	_, err := NewLocalKeyCrypter(nil, "v1")
	require.ErrorContains(t, err, "at least one key")

	_, err = NewLocalKeyCrypter(map[string][]byte{"v1": []byte("too-short")}, "v1")
	require.ErrorContains(t, err, "32 bytes")

	_, err = NewLocalKeyCrypter(map[string][]byte{"v1": testKey(1)}, "v2")
	require.ErrorContains(t, err, "not present in keys")
}

func TestLocalKeyCrypterRoundTrip(t *testing.T) {
	crypter, err := NewLocalKeyCrypter(map[string][]byte{"v1": testKey(1)}, "v1")
	require.NoError(t, err)

	plaintext := []byte("sensitive chat content")
	aad := []byte("task-1\x00message-1")
	ciphertext, keyID, err := crypter.Encrypt(context.Background(), plaintext, aad)
	require.NoError(t, err)
	require.Equal(t, "v1", keyID)
	require.NotEqual(t, plaintext, ciphertext)

	got, err := crypter.Decrypt(context.Background(), keyID, ciphertext, aad)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

func TestLocalKeyCrypterRejectsTamperedCiphertextAndWrongAAD(t *testing.T) {
	crypter, err := NewLocalKeyCrypter(map[string][]byte{"v1": testKey(1)}, "v1")
	require.NoError(t, err)
	ciphertext, keyID, err := crypter.Encrypt(context.Background(), []byte("secret"), []byte("task-1"))
	require.NoError(t, err)

	tampered := append([]byte{}, ciphertext...)
	tampered[len(tampered)-1] ^= 0xff
	_, err = crypter.Decrypt(context.Background(), keyID, tampered, []byte("task-1"))
	require.Error(t, err, "GCM must reject a tampered ciphertext")

	_, err = crypter.Decrypt(context.Background(), keyID, ciphertext, []byte("task-2"))
	require.Error(t, err, "GCM must reject a mismatched AAD")
}

func TestLocalKeyCrypterRotation(t *testing.T) {
	// A row encrypted under an old key must keep decrypting after the active key
	// changes, and new writes must switch to the new key -- this is the whole point
	// of encryption_key_id.
	v1Only, err := NewLocalKeyCrypter(map[string][]byte{"v1": testKey(1)}, "v1")
	require.NoError(t, err)
	plaintext := []byte("encrypted before rotation")
	oldCiphertext, oldKeyID, err := v1Only.Encrypt(context.Background(), plaintext, []byte("task-1"))
	require.NoError(t, err)
	require.Equal(t, "v1", oldKeyID)

	rotated, err := NewLocalKeyCrypter(map[string][]byte{"v1": testKey(1), "v2": testKey(2)}, "v2")
	require.NoError(t, err)

	got, err := rotated.Decrypt(context.Background(), oldKeyID, oldCiphertext, []byte("task-1"))
	require.NoError(t, err, "old key must still decrypt rows written before rotation")
	require.Equal(t, plaintext, got)

	_, newKeyID, err := rotated.Encrypt(context.Background(), []byte("encrypted after rotation"), []byte("task-2"))
	require.NoError(t, err)
	require.Equal(t, "v2", newKeyID, "new writes must use the active key")
}

func TestLoadLocalKeysFromJSON(t *testing.T) {
	v1 := base64.StdEncoding.EncodeToString(testKey(1))
	v2 := base64.StdEncoding.EncodeToString(testKey(2))
	keys, activeKeyID, err := LoadLocalKeysFromJSON([]byte(`{
		"keys": {"v1": "` + v1 + `", "v2": "` + v2 + `"},
		"active_key_id": "v2"
	}`))
	require.NoError(t, err)
	require.Equal(t, "v2", activeKeyID)
	require.Equal(t, testKey(1), keys["v1"])
	require.Equal(t, testKey(2), keys["v2"])

	crypter, err := NewLocalKeyCrypter(keys, activeKeyID)
	require.NoError(t, err)
	ciphertext, keyID, err := crypter.Encrypt(context.Background(), []byte("hello"), nil)
	require.NoError(t, err)
	plaintext, err := crypter.Decrypt(context.Background(), keyID, ciphertext, nil)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), plaintext)
}

func TestLoadLocalKeysFromJSONRejectsMalformedInput(t *testing.T) {
	_, _, err := LoadLocalKeysFromJSON([]byte(`{"keys": {"v1": "not-base64!!"}}`))
	require.Error(t, err)
	_, _, err = LoadLocalKeysFromJSON([]byte(`not json`))
	require.Error(t, err)
}
