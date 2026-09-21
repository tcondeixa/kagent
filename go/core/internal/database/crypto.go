package database

import "context"

// PayloadCrypter encrypts and decrypts stored task and event payloads. A nil
// PayloadCrypter leaves data as plaintext -- the default when encryption is
// not configured, so enabling this feature never changes existing rows and
// disabling it never breaks reading them.
type PayloadCrypter interface {
	// Encrypt returns ciphertext and the ID of the key that produced it. aad
	// must be reproduced exactly on Decrypt; see payloadAAD.
	Encrypt(ctx context.Context, plaintext, aad []byte) (ciphertext []byte, keyID string, err error)
	// Decrypt reverses Encrypt using the exact key identified by keyID and
	// the same aad supplied to Encrypt.
	Decrypt(ctx context.Context, keyID string, ciphertext, aad []byte) (plaintext []byte, err error)
}

// payloadAAD binds a payload's ciphertext to the task (and, for an archived
// message, the message) it belongs to.
//
// It deliberately does not bind to history_id: ForkAgentInstance copies
// agent_instance_task_event rows into a new history_id by reusing their
// stored ciphertext verbatim (see checkpoints.go), so binding to history_id
// would make every forked row undecryptable. task_id and message_id survive
// that copy unchanged, so they are what ciphertext is bound to instead.
func payloadAAD(taskID, messageID string) []byte {
	return []byte(taskID + "\x00" + messageID)
}
