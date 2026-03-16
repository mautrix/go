package bridgev2

import (
	"encoding/json"
	"testing"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func TestNewStreamUpdateContentMarshal(t *testing.T) {
	content, err := newStreamUpdateContent(&PublishStreamRequest{
		RoomID:  "!room:example.com",
		EventID: "$event",
		Content: map[string]any{
			"com.beeper.llm.deltas": []map[string]any{
				{"delta": "hello"},
			},
		},
	})
	if err != nil {
		t.Fatalf("newStreamUpdateContent returned error: %v", err)
	}

	data, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("failed to marshal update content: %v", err)
	}

	var parsed map[string]any
	if err = json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal update content: %v", err)
	}

	if parsed["room_id"] != "!room:example.com" {
		t.Fatalf("unexpected room_id: %#v", parsed["room_id"])
	}
	if parsed["event_id"] != "$event" {
		t.Fatalf("unexpected event_id: %#v", parsed["event_id"])
	}
	if _, ok := parsed["type"]; ok {
		t.Fatalf("unexpected type field: %#v", parsed["type"])
	}
	if _, ok := parsed["content"]; ok {
		t.Fatalf("unexpected nested content field: %#v", parsed["content"])
	}
	if _, ok := parsed["com.beeper.llm.deltas"]; !ok {
		t.Fatalf("missing com.beeper.llm.deltas in marshaled content: %#v", parsed)
	}
}

func TestNewStreamUpdateContentRejectsReservedKeys(t *testing.T) {
	_, err := newStreamUpdateContent(&PublishStreamRequest{
		RoomID:  "!room:example.com",
		EventID: "$event",
		Content: map[string]any{
			"room_id": "override",
		},
	})
	if err == nil {
		t.Fatal("expected room_id override to be rejected")
	}
}

func TestEncryptDecryptStreamPayloadRoundTrip(t *testing.T) {
	key := makeStreamKey()
	content, err := newStreamUpdateContent(&PublishStreamRequest{
		RoomID:  "!room:example.com",
		EventID: "$event",
		Content: map[string]any{
			"com.beeper.llm.deltas": []map[string]any{
				{"delta": "hello"},
			},
		},
	})
	if err != nil {
		t.Fatalf("newStreamUpdateContent returned error: %v", err)
	}

	encrypted, err := encryptStreamPayload(event.ToDeviceBeeperStreamUpdate, content, key)
	if err != nil {
		t.Fatalf("encryptStreamPayload returned error: %v", err)
	}
	if encrypted.Algorithm != id.AlgorithmBeeperStreamAESGCM {
		t.Fatalf("unexpected algorithm: %q", encrypted.Algorithm)
	}
	if encrypted.IV == "" || len(encrypted.StreamCiphertext) == 0 {
		t.Fatalf("encrypted payload missing IV or ciphertext: %#v", encrypted)
	}

	decrypted, err := decryptStreamPayload(encrypted, key)
	if err != nil {
		t.Fatalf("decryptStreamPayload returned error: %v", err)
	}
	if decrypted.Type != event.ToDeviceBeeperStreamUpdate.Type {
		t.Fatalf("unexpected decrypted type: %q", decrypted.Type)
	}

	var parsed map[string]any
	if err = json.Unmarshal(decrypted.Content, &parsed); err != nil {
		t.Fatalf("failed to unmarshal decrypted content: %v", err)
	}
	if parsed["room_id"] != "!room:example.com" || parsed["event_id"] != "$event" {
		t.Fatalf("unexpected decrypted identifiers: %#v", parsed)
	}
	if _, ok := parsed["com.beeper.llm.deltas"]; !ok {
		t.Fatalf("missing com.beeper.llm.deltas in decrypted content: %#v", parsed)
	}
	if _, ok := parsed["type"]; ok {
		t.Fatalf("unexpected type field after decryption: %#v", parsed["type"])
	}
	if _, ok := parsed["content"]; ok {
		t.Fatalf("unexpected nested content field after decryption: %#v", parsed["content"])
	}
}
