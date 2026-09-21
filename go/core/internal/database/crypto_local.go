package database

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// LocalKeyCrypter implements PayloadCrypter with AES-256-GCM using key material supplied
// directly by the caller, for example from a Kubernetes Secret. It has no external
// dependency and is meant as a starting point before adopting a managed key service such
// as AWS KMS; because callers only ever see the PayloadCrypter interface, switching to a
// different implementation later is a config change, not a rewrite of anything that calls
// Client.
type LocalKeyCrypter struct {
	keys        map[string][]byte
	activeKeyID string
}

// NewLocalKeyCrypter validates that every key is a 32-byte AES-256 key and that
// activeKeyID names one of them, then returns a ready-to-use LocalKeyCrypter.
//
// keys must include every key ID that might still be named by a previously encrypted
// row's encryption_key_id. Removing a key before every row that used it has been
// re-encrypted or deleted makes those rows permanently undecryptable. Rotating to a new
// key is: add it to keys, point activeKeyID at it, and keep the old key around for as
// long as old rows may still reference it.
func NewLocalKeyCrypter(keys map[string][]byte, activeKeyID string) (*LocalKeyCrypter, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("local key crypter requires at least one key")
	}
	for id, key := range keys {
		if len(key) != 32 {
			return nil, fmt.Errorf("key %q must be 32 bytes for AES-256, got %d", id, len(key))
		}
	}
	if _, ok := keys[activeKeyID]; !ok {
		return nil, fmt.Errorf("active key ID %q is not present in keys", activeKeyID)
	}
	return &LocalKeyCrypter{keys: keys, activeKeyID: activeKeyID}, nil
}

// Encrypt implements PayloadCrypter using the active key.
func (l *LocalKeyCrypter) Encrypt(_ context.Context, plaintext, aad []byte) ([]byte, string, error) {
	ciphertext, err := aesGCMSeal(l.keys[l.activeKeyID], plaintext, aad)
	if err != nil {
		return nil, "", err
	}
	return ciphertext, l.activeKeyID, nil
}

// Decrypt implements PayloadCrypter using the key identified by keyID, which may be an
// older, no-longer-active key after rotation.
func (l *LocalKeyCrypter) Decrypt(_ context.Context, keyID string, ciphertext, aad []byte) ([]byte, error) {
	key, ok := l.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key %q is not configured", keyID)
	}
	return aesGCMOpen(key, ciphertext, aad)
}

func aesGCMSeal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func aesGCMOpen(key, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext is shorter than a nonce")
	}
	nonce, sealed := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("open AES-GCM: %w", err)
	}
	return plaintext, nil
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("build AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("build AES-GCM: %w", err)
	}
	return gcm, nil
}

// localKeysFile is the JSON shape LoadLocalKeysFromJSON reads, typically mounted from a
// Kubernetes Secret: a map of key ID to base64-encoded 32-byte key, plus which one new
// writes should use.
//
//	{
//	  "keys": {"v1": "<base64>", "v2": "<base64>"},
//	  "active_key_id": "v2"
//	}
type localKeysFile struct {
	Keys        map[string]string `json:"keys"`
	ActiveKeyID string            `json:"active_key_id"`
}

// LoadLocalKeysFromJSON parses the JSON shape documented on localKeysFile and returns
// decoded key material ready for NewLocalKeyCrypter.
func LoadLocalKeysFromJSON(data []byte) (keys map[string][]byte, activeKeyID string, err error) {
	var file localKeysFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, "", fmt.Errorf("parse encryption keys file: %w", err)
	}
	decoded := make(map[string][]byte, len(file.Keys))
	for id, encoded := range file.Keys {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, "", fmt.Errorf("decode key %q: %w", id, err)
		}
		decoded[id] = key
	}
	return decoded, file.ActiveKeyID, nil
}
