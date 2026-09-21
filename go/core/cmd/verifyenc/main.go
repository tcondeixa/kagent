// Scratch program: manually verifies that AgentInstance task/event payloads are
// stored encrypted in Postgres when a PayloadCrypter is configured, and that they
// decrypt correctly when read back through the normal Client API. Not part of the
// build; delete after use.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"
	a2apb "github.com/a2aproject/a2a-go/v2/a2apb/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	apiv1alpha1 "github.com/kagent-dev/kagent/go/api/gen/kagent/api/v1alpha1"
	"github.com/kagent-dev/kagent/go/core/internal/database"
)

const secretMarker = "TOP-SECRET-MARKER-4f8e2c91"

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(1)
	}
}

func fixture(ctx context.Context, client *database.Client, namespace, revisionID, template, harness string) {
	revision := database.RuntimeRevision{
		Revision: revisionID, Namespace: namespace,
		AgentTemplateName: template, AgentTemplateUID: template + "-uid",
		HarnessName: harness, HarnessUID: harness + "-uid",
		SourceSnapshot: []byte("{}"), AgentCard: &a2apb.AgentCard{}, EgressDestinations: []string{},
		ActorTemplateAtespace: namespace, ActorTemplateName: revisionID + "-actor-template",
		ActorTemplateUID: revisionID + "-actor-uid",
	}
	pair := database.AgentTemplateHarnessPair{
		Namespace: namespace, AgentTemplateName: template, AgentTemplateUID: template + "-uid",
		HarnessName: harness, HarnessUID: harness + "-uid", DesiredRevision: revisionID,
	}
	must(client.UpsertAgentTemplateHarnessPair(ctx, pair))
	must(client.RecordRuntimeRevision(ctx, revision, true))
}

func createReadyInstance(ctx context.Context, client *database.Client, namespace, revisionID, template, harness string) *apiv1alpha1.AgentInstance {
	fixture(ctx, client, namespace, revisionID, template, harness)
	req := &apiv1alpha1.AgentInstance{
		Id: uuid.NewString(), Creator: "verify",
		Harness:       &apiv1alpha1.ResourceReference{Namespace: namespace, Name: harness},
		AgentTemplate: &apiv1alpha1.ResourceReference{Namespace: namespace, Name: template},
	}
	instance, _, err := client.CreateAgentInstance(ctx, req, uuid.NewString())
	must(err)
	instance, err = client.TransitionAgentInstance(ctx, &apiv1alpha1.AgentInstance{
		Id: instance.Id, State: apiv1alpha1.AgentInstanceState_AGENT_INSTANCE_STATE_READY, A2AAuthority: "verify:80",
	}, apiv1alpha1.AgentInstanceState_AGENT_INSTANCE_STATE_CREATING, apiv1alpha1.AgentInstanceOperation_AGENT_INSTANCE_OPERATION_CREATE)
	must(err)
	return instance
}

func main() {
	ctx := context.Background()
	dbURL := os.Getenv("POSTGRES_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://kagent:kagent@localhost:15432/kagent?sslmode=disable"
	}
	pool, err := pgxpool.New(ctx, dbURL)
	must(err)
	defer pool.Close()

	// --- Baseline: no crypter configured, exactly today's default behavior. ---
	plainClient := database.NewClient(pool)
	plainInstance := createReadyInstance(ctx, plainClient, "verify-ns", "plain-revision", "plain-template", "plain-harness")
	plainTask := &a2a.Task{
		ID: a2a.TaskID(uuid.NewString()), ContextID: plainInstance.ContextId,
		Status: a2a.TaskStatus{State: a2a.TaskStateSubmitted},
		History: []*a2a.Message{{
			ID: uuid.NewString(), Role: a2a.MessageRoleUser, TaskID: "", ContextID: plainInstance.ContextId,
			Parts: a2a.ContentParts{a2a.NewTextPart(secretMarker + "-plaintext")},
		}},
	}
	_, _, err = plainClient.CreateAgentInstanceTask(ctx, plainInstance.Id, []byte("req-plain"), plainTask)
	must(err)

	var plainRaw []byte
	must(pool.QueryRow(ctx, `SELECT data FROM agent_instance_task_event WHERE message_id = $1`, plainTask.History[0].ID).Scan(&plainRaw))
	fmt.Println("=== Baseline (no crypter): raw bytes contain marker in plaintext protobuf ===")
	fmt.Println("contains marker:", strings.Contains(string(plainRaw), secretMarker))

	// --- Encrypted: crypter configured. ---
	keys := map[string][]byte{"v1": []byte("01234567890123456789012345678901")}
	crypter, err := database.NewLocalKeyCrypter(keys, "v1")
	must(err)
	encClient := database.NewClient(pool, database.WithPayloadCrypter(crypter))
	encInstance := createReadyInstance(ctx, encClient, "verify-ns", "enc-revision", "enc-template", "enc-harness")
	encMessageID := uuid.NewString()
	encTask := &a2a.Task{
		ID: a2a.TaskID(uuid.NewString()), ContextID: encInstance.ContextId,
		Status: a2a.TaskStatus{State: a2a.TaskStateSubmitted},
		History: []*a2a.Message{{
			ID: encMessageID, Role: a2a.MessageRoleUser, TaskID: "", ContextID: encInstance.ContextId,
			Parts: a2a.ContentParts{a2a.NewTextPart(secretMarker + "-encrypted")},
		}},
	}
	_, _, err = encClient.CreateAgentInstanceTask(ctx, encInstance.Id, []byte("req-enc"), encTask)
	must(err)

	var encRaw []byte
	var encKeyID *string
	must(pool.QueryRow(ctx, `SELECT data, encryption_key_id FROM agent_instance_task_event WHERE message_id = $1`, encMessageID).Scan(&encRaw, &encKeyID))
	fmt.Println()
	fmt.Println("=== Encrypted: raw bytes in Postgres ===")
	fmt.Println("encryption_key_id column:", *encKeyID)
	fmt.Println("contains marker in raw bytes (should be false):", strings.Contains(string(encRaw), secretMarker))
	fmt.Printf("first 32 raw bytes (hex): %x\n", encRaw[:min(32, len(encRaw))])

	// Read back through the normal, decrypting API.
	decoded, err := encClient.GetAgentInstanceTask(ctx, encInstance.Id, string(encTask.ID), nil)
	must(err)
	var decryptedText string
	for _, msg := range decoded.History {
		for _, part := range msg.Parts {
			if text, ok := part.(*a2a.TextPart); ok {
				decryptedText = text.Text
			}
		}
	}
	fmt.Println()
	fmt.Println("=== Decrypted via Client.GetAgentInstanceTask ===")
	fmt.Println("decoded text:", decryptedText)
	fmt.Println("matches original marker:", decryptedText == secretMarker+"-encrypted")

	// Confirm decryption fails loudly if the crypter/key is missing -- never silently
	// returns ciphertext as if it were plaintext.
	unconfigured := database.NewClient(pool)
	_, err = unconfigured.GetAgentInstanceTask(ctx, encInstance.Id, string(encTask.ID), nil)
	fmt.Println()
	fmt.Println("=== Reading an encrypted row with no crypter configured ===")
	fmt.Println("error (expected, not nil):", err)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
