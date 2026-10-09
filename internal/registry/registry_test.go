package registry

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fixed test key so the Swift client can verify the same fixture (Core/Tests/FarlinkRegistryTests/Fixtures/servers.json).
var testSeed = []byte("farlink-registry-test-seed-32byt")

func testKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(testSeed) }

func sample() *Registry {
	return &Registry{
		Protocol: 1, RegistryID: "farlink-main", Sequence: 7,
		IssuedAt: 1790000000000, ExpiresAt: 4102444800000, // 2100-01-01
		Mirrors: []string{"https://cdn.jsdelivr.net", "https://flyozzzz.github.io"},
		Servers: []Server{
			{ServerID: "fi1", Roles: []string{"signal", "turn", "relay", "spool"}, APIOrigin: "https://fi1.farlink.app",
				TURNURLs: []string{"turns:fi1.farlink.app:443", "turn:fi1.farlink.app:3478"}, Region: "FI", Priority: 10,
				ProtocolMin: 1, ProtocolMax: 1, FederationIdentity: "fi1", TLSSPKIPins: [][]byte{}},
			{ServerID: "am1", Roles: []string{"signal", "turn", "relay"}, APIOrigin: "https://am1.farlink.app",
				TURNURLs: []string{"turns:am1.farlink.app:443"}, Region: "AM", Priority: 20,
				ProtocolMin: 1, ProtocolMax: 1, FederationIdentity: "am1", TLSSPKIPins: [][]byte{}},
		},
		NextKeys: []NextKey{},
	}
}

func trusted() map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{"test": testKey().Public().(ed25519.PublicKey)}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	data, err := Sign(sample(), "test", testKey())
	if err != nil {
		t.Fatal(err)
	}
	r, err := Verify(data, trusted(), time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Servers[0].ServerID != "am1" || len(r.Servers) != 2 {
		t.Fatalf("servers not sorted or lost: %+v", r.Servers)
	}
	if os.Getenv("FARLINK_WRITE_FIXTURE") != "" {
		if err := os.WriteFile("../../../Core/Tests/FarlinkRegistryTests/Fixtures/servers.json", data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTamperedPayloadRejected(t *testing.T) {
	data, _ := Sign(sample(), "test", testKey())
	var f File
	json.Unmarshal(data, &f)
	r := sample()
	r.Servers[0].APIOrigin = "https://evil.example"
	other, _ := Sign(r, "test", ed25519.NewKeyFromSeed([]byte("another-seed-another-seed-32byte")))
	var g File
	json.Unmarshal(other, &g)
	f.Payload = g.Payload // evil payload, original signature
	bad, _ := json.Marshal(f)
	if _, err := Verify(bad, trusted(), time.Now(), 0); err != ErrSignature {
		t.Fatalf("want ErrSignature, got %v", err)
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	data, _ := Sign(sample(), "test", testKey())
	if _, err := Verify(data, map[string]ed25519.PublicKey{}, time.Now(), 0); err != ErrSignature {
		t.Fatalf("want ErrSignature, got %v", err)
	}
}

func TestExpiryAndRollback(t *testing.T) {
	data, _ := Sign(sample(), "test", testKey())
	if _, err := Verify(data, trusted(), time.UnixMilli(4102444800000), 0); err != ErrExpired {
		t.Fatalf("want ErrExpired, got %v", err)
	}
	if _, err := Verify(data, trusted(), time.Now(), 8); err != ErrRollback {
		t.Fatalf("want ErrRollback, got %v", err)
	}
}

func TestValidation(t *testing.T) {
	r := sample()
	r.Servers[0].APIOrigin = "http://fi1.farlink.app"
	if _, err := Sign(r, "test", testKey()); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected https error, got %v", err)
	}
	r = sample()
	r.Servers[1].ServerID = "fi1"
	if _, err := Sign(r, "test", testKey()); err == nil {
		t.Fatal("expected duplicate id error")
	}
}

var nextSeed = []byte("farlink-registry-next-seed-32byt")

// Rotation: the current key announces the next one; from its activate_sequence a catalog signed by the new key
// alone verifies for a client that saw the announcement, and not before. Also written as fixtures for the Swift
// client (servers-rotation-7.json by the current key, -8 by the new key only).
func TestKeyRotation(t *testing.T) {
	next := ed25519.NewKeyFromSeed(nextSeed)
	r := sample()
	ann := NextKey{KeyID: "next", PublicKey: next.Public().(ed25519.PublicKey), ActivateSequence: 8}
	r.NextKeys = []NextKey{ann}
	f7, err := Sign(r, "test", testKey())
	if err != nil {
		t.Fatal(err)
	}
	r7, err := Verify(f7, trusted(), time.Now(), 0)
	if err != nil || len(r7.NextKeys) != 1 {
		t.Fatalf("%v %+v", err, r7)
	}
	r8 := sample()
	r8.Sequence = 8
	f8, err := Sign(r8, "next", next)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(f8, trusted(), time.Now(), 7); err != ErrSignature {
		t.Fatalf("new key without its announcement: %v", err)
	}
	if _, err := VerifyWith(f8, trusted(), r7.NextKeys, time.Now(), 7); err != nil {
		t.Fatalf("announced key at its sequence: %v", err)
	}
	early := sample() // sequence 7, below the activation
	f7n, _ := Sign(early, "next", next)
	if _, err := VerifyWith(f7n, trusted(), r7.NextKeys, time.Now(), 0); err != ErrSignature {
		t.Fatalf("announced key before its sequence: %v", err)
	}
	both, err := SignWith(sample(), Signer{"test", testKey()}, Signer{"next", next})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(both, trusted(), time.Now(), 0); err != nil {
		t.Fatalf("signed by both, checked with the old key: %v", err)
	}
	bad := sample()
	bad.NextKeys = []NextKey{{KeyID: "next", PublicKey: ann.PublicKey, ActivateSequence: 7}}
	if _, err := Sign(bad, "test", testKey()); err == nil {
		t.Fatal("activate_sequence at the catalog's own sequence accepted")
	}
	if os.Getenv("FARLINK_WRITE_FIXTURE") != "" {
		for name, data := range map[string][]byte{"servers-rotation-7.json": f7, "servers-rotation-8.json": f8} {
			if err := os.WriteFile("../../../Core/Tests/FarlinkRegistryTests/Fixtures/"+name, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestFloorOnlyMovesUpAndSurvivesReopen(t *testing.T) {
	f := Floor{Path: filepath.Join(t.TempDir(), "floor")}
	if v, err := f.Read(); err != nil || v != 0 {
		t.Fatal(v, err)
	}
	for _, seq := range []uint64{5, 3, 9, 9} {
		if err := f.Raise(seq); err != nil {
			t.Fatal(err)
		}
	}
	if v, _ := (Floor{Path: f.Path}).Read(); v != 9 {
		t.Fatalf("floor %d", v)
	}
	os.WriteFile(f.Path, []byte("garbage"), 0o600)
	if _, err := f.Read(); err == nil {
		t.Fatal("a damaged floor was read as a fresh start")
	}
}
