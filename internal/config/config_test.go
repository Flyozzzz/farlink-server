package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDefaultsNeedTLSSource(t *testing.T) {
	if _, err := Parse(nil, env(nil)); err == nil {
		t.Fatal("expected an error without -domain or -cert/-key")
	}
}

func TestDomainAndDefaultRoles(t *testing.T) {
	c, err := Parse([]string{"-domain", "fi1.farlink.app", "-id", "fi1", "-public-ip", "203.0.113.5"}, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []Role{RoleSignal, RoleTURN, RoleRelay, RoleSpool} {
		if !c.Has(r) {
			t.Errorf("role %s should be on by default", r)
		}
	}
	if c.Has(RolePush) {
		t.Error("push needs the APNs key and must be opt-in")
	}
	if c.SpoolTTL != 7*24*time.Hour {
		t.Errorf("spool ttl = %v", c.SpoolTTL)
	}
}

func TestEnvironmentAndFlagsPrecedence(t *testing.T) {
	c, err := Parse([]string{"-roles", "signal"}, env(map[string]string{
		"FARLINK_DOMAIN": "am1.farlink.app", "FARLINK_ROLES": "turn", "FARLINK_ID": "am1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.ServerID != "am1" || c.Domain != "am1.farlink.app" || !c.Has(RoleSignal) || c.Has(RoleTURN) {
		t.Fatalf("got %+v", c)
	}
}

func TestUnknownRoleRejected(t *testing.T) {
	if _, err := Parse([]string{"-domain", "x", "-roles", "signal,vpn"}, env(nil)); err == nil {
		t.Fatal("expected unknown role error")
	}
}

func TestTURNNeedsPublicIP(t *testing.T) {
	if _, err := Parse([]string{"-domain", "x", "-id", "a", "-roles", "turn"}, env(nil)); err == nil {
		t.Fatal("expected public ip error")
	}
}

func TestServerIDIsRequired(t *testing.T) {
	if _, err := Parse([]string{"-domain", "x", "-roles", "signal"}, env(nil)); err == nil {
		t.Fatal("a missing -id must not fall back to the hostname")
	}
}

func TestQuotasOffByDefaultForSelfHosting(t *testing.T) {
	c, err := Parse([]string{"-domain", "x", "-id", "a", "-roles", "relay"}, env(nil))
	if err != nil || c.Quotas {
		t.Fatalf("a self-hosted server must be unlimited by default: %+v %v", c, err)
	}
	c, err = Parse([]string{"-domain", "x", "-id", "a", "-roles", "relay"}, env(map[string]string{"FARLINK_QUOTAS": "on"}))
	if err != nil || !c.Quotas || c.FreeRelayBytes != 10<<30 || c.RelayBytes != 200<<30 || c.RelayMaxBytes != 2<<40 || c.RelaySpoolBytes != 20e9 || c.FreeSpoolBytes != 2e9 || !c.Teams ||
		c.TeamsPersonBytes != 200e9 || len(c.StoreEnvs) != 1 || c.StoreEnvs[0] != "Production" || c.BundleID != "com.flyoz.farlink" {
		t.Fatalf("our servers' tiers = %+v %v", c, err)
	}
	if _, err := Parse([]string{"-domain", "x", "-id", "a", "-quotas", "-free-relay-bytes", "0"}, env(nil)); err == nil {
		t.Fatal("a zero allowance with quotas on is a misconfiguration")
	}
	if _, err := Parse([]string{"-domain", "x", "-id", "a", "-appstore-env", "Production,Staging"}, env(nil)); err == nil {
		t.Fatal("unknown environment accepted")
	}
}

func TestLooksLikeOrigin(t *testing.T) {
	for id, want := range map[string]bool{
		"https://files.example.com": true, "https://203.0.113.5:8443": true, "https://[2001:db8::1]:8443": true,
		"fi1": false, "https://files.example.com/": false, "https://Files.example.com": false, "https://h:443": false,
		"http://files.example.com": false, "https://u@h": false, "https://h?x": false,
	} {
		if LooksLikeOrigin(id) != want {
			t.Errorf("LooksLikeOrigin(%q) = %v", id, !want)
		}
	}
}

// -quotas reads as a plain switch or on/off, in either spelling; a stray word is an error, not ignored.
func TestQuotasFlagForms(t *testing.T) {
	base := []string{"-domain", "x", "-id", "a", "-roles", "relay"}
	for args, want := range map[string]bool{"-quotas": true, "-quotas=on": true, "-quotas on": true, "-quotas=off": false, "-quotas off": false} {
		c, err := Parse(append(append([]string{}, base...), strings.Fields(args)...), env(nil))
		if err != nil || c.Quotas != want {
			t.Fatalf("%s: quotas=%v %v", args, c != nil && c.Quotas, err)
		}
	}
	if c, err := Parse(append(base, "-quotas", "off"), env(map[string]string{"FARLINK_QUOTAS": "on"})); err != nil || c.Quotas {
		t.Fatal("a flag must win over the environment")
	}
	if _, err := Parse(append(base, "-quotas=maybe"), env(nil)); err == nil {
		t.Fatal("unknown -quotas value accepted")
	}
	if _, err := Parse(append(base, "stray"), env(nil)); err == nil {
		t.Fatal("stray argument ignored")
	}
	c, _ := Parse(append(base, "-quotas"), env(nil))
	if c.IPTrafficBytes != 200e9 || c.TotalTrafficBytes != 0 {
		t.Fatalf("anti-abuse traffic defaults %d %d", c.IPTrafficBytes, c.TotalTrafficBytes)
	}
}

func TestFederationFlagsNeedCertAndKeyTogetherAndTrustedKeys(t *testing.T) {
	base := []string{"-domain", "x", "-id", "a", "-roles", "signal"}
	pub := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if _, err := Parse(append(base, "-federation-cert", "c.pem"), env(nil)); err == nil {
		t.Fatal("cert without key accepted")
	}
	if _, err := Parse(append(base, "-federation-cert", "c.pem", "-federation-key", "k.pem"), env(nil)); err == nil {
		t.Fatal("federation without a trusted registry key accepted")
	}
	if _, err := Parse(append(base, "-federation-cert", "c.pem", "-federation-key", "k.pem", "-registry-key", "op=short"), env(nil)); err == nil {
		t.Fatal("malformed registry key accepted")
	}
	c, err := Parse(append(base, "-federation-cert", "c.pem", "-federation-key", "k.pem", "-registry-key", "op="+pub), env(nil))
	if err != nil || len(c.TrustedKeys["op"]) != 32 {
		t.Fatalf("%v %+v", err, c)
	}
	if c, err := Parse(base, env(nil)); err != nil || c.FederationCert != "" {
		t.Fatal("federation must stay off by default")
	}
}

func TestTURNRelayPorts(t *testing.T) {
	base := []string{"-id", "https://203.0.113.5:8443", "-cert", "c", "-key", "k", "-public-ip", "203.0.113.5"}
	c, err := Parse(append(base, "-turn-relay-ports", "50000-54999"), env(nil))
	if err != nil || c.TURNPorts != [2]uint16{50000, 54999} {
		t.Fatalf("got %v %v", c, err)
	}
	for _, bad := range []string{"50000", "0-10", "20-10", "a-b", "1-70000"} {
		if _, err := Parse(append(base, "-turn-relay-ports", bad), env(nil)); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
