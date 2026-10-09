// Package config reads farlink-server settings from flags and FARLINK_* environment variables.
package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Role is one job the server can do; a small VPS may run all of them, a big deployment splits them.
type Role string

const (
	RoleSignal Role = "signal"
	RoleTURN   Role = "turn"
	RoleRelay  Role = "relay"
	RoleSpool  Role = "spool"
	RolePush   Role = "push"
)

var allRoles = []Role{RoleSignal, RoleTURN, RoleRelay, RoleSpool, RolePush}

type Config struct {
	ServerID   string
	Listen     string    // HTTPS, WebSocket and TURN-over-TLS share :443
	TURNListen string    // STUN/TURN over UDP
	TURNPorts  [2]uint16 // UDP ports TURN may relay from (0,0 = any free port); a firewall must allow exactly these
	TURNTLS    string    // TURN over TLS (separate listener from HTTPS, e.g. :5349 or a second IP's :443)
	PublicIP   string    // address relayed TURN candidates carry
	Domain     string    // for Let's Encrypt; empty = use CertFile/KeyFile
	CertFile   string
	KeyFile    string
	DataDir    string // server key, spool, ACME cache
	Roles      map[Role]bool

	SessionTTL         time.Duration
	SpoolTTL           time.Duration
	SpoolMaxBytes      int64 // per owner device
	SpoolIPMaxBytes    int64 // per client address
	SpoolTotalMaxBytes int64 // whole spool

	// Quotas meter relay/TURN/spool bytes by App Store entitlement (our servers). Off = self-hosting: every
	// device is unlimited, bounded only by the abuse caps above, and no purchase is ever needed.
	Quotas bool
	// BillingIdentity turns on the account billing identity endpoints (/v2/billing/identities/*). Off by default.
	BillingIdentity bool
	// BillingAuthority is the server ID that keeps the account counters of the fleet; the others lease bytes from it.
	// Empty: this server keeps its own (a single server, or this one is the authority).
	BillingAuthority string
	FreeRelayBytes   int64 // per device per UTC month
	// Anti-abuse on top of the tiers (quotas on only): fresh keys are free, so free traffic from one client
	// address, and all traffic of the server, have their own monthly caps. 0 = no cap.
	IPTrafficBytes    int64
	TotalTrafficBytes int64
	FreeSpoolBytes    int64 // spool storage per device
	RelayBytes        int64 // Relay subscription, per month, shared by the devices presenting it
	RelayMaxBytes     int64 // Relay Max subscription (2 TiB), 0 = not on sale
	RelaySpoolBytes   int64
	TeamsPersonBytes  int64 // Teams: pooled per network, pack seats × this
	TeamsSpoolBytes   int64
	Teams             bool     // honour Teams packs (on; off leaves them unknown products)
	BundleID          string   // App Store transactions must be for this app
	ProductPrefix     string   // product ids: <prefix>.pro, .relay.monthly, .teams5.yearly…
	StoreEnvs         []string // accepted transaction environments
	StoreRootFile     string   // extra trusted root certificate (DER or PEM), e.g. Xcode's StoreKit testing root

	// Federation (protocol v1 §10.2): with a certificate, this server takes envelopes from the other servers of
	// the signed registry over mutual TLS. TrustedKeys are the operator keys that sign servers.json.
	FederationCert string
	FederationKey  string
	TrustedKeys    map[string][]byte // key id -> Ed25519 public key
}

func (c *Config) Has(r Role) bool { return c.Roles[r] }

// Parse reads args (without the program name) and the environment; flags win over the environment.
func Parse(args []string, getenv func(string) string) (*Config, error) {
	fs := flag.NewFlagSet("farlink-server", flag.ContinueOnError)
	env := func(k, def string) string {
		if v := getenv("FARLINK_" + k); v != "" {
			return v
		}
		return def
	}
	c := &Config{}
	var roles string
	fs.StringVar(&c.ServerID, "id", env("ID", ""), "stable server id as listed in servers.json (the auth audience)")
	fs.StringVar(&c.Listen, "listen", env("LISTEN", ":443"), "TCP address for HTTPS/WebSocket/TURN-TLS")
	fs.StringVar(&c.TURNListen, "turn-listen", env("TURN_LISTEN", ":3478"), "UDP address for STUN/TURN")
	fs.StringVar(&c.TURNTLS, "turn-tls-listen", env("TURN_TLS_LISTEN", ":5349"), "TCP address for TURN over TLS (empty = off)")
	var relayPorts string
	fs.StringVar(&relayPorts, "turn-relay-ports", env("TURN_RELAY_PORTS", ""), "UDP port range for relayed TURN traffic, min-max (default: any free port)")
	fs.StringVar(&c.PublicIP, "public-ip", env("PUBLIC_IP", ""), "public IPv4 of this server (required for the turn role)")
	fs.StringVar(&c.Domain, "domain", env("DOMAIN", ""), "domain for automatic Let's Encrypt certificates")
	fs.StringVar(&c.CertFile, "cert", env("CERT", ""), "TLS certificate file (if no -domain)")
	fs.StringVar(&c.KeyFile, "key", env("KEY", ""), "TLS key file (if no -domain)")
	fs.StringVar(&c.DataDir, "data", env("DATA", "/var/lib/farlink"), "data directory")
	fs.StringVar(&roles, "roles", env("ROLES", "signal,turn,relay,spool"), "comma-separated roles: signal,turn,relay,spool,push")
	fs.DurationVar(&c.SessionTTL, "session-ttl", 15*time.Minute, "device session lifetime (testing)")
	fs.DurationVar(&c.SpoolTTL, "spool-ttl", 7*24*time.Hour, "how long undelivered spool objects are kept")
	fs.Int64Var(&c.SpoolMaxBytes, "spool-max-bytes", 50<<30, "spool size limit per owner device (0 = unlimited)")
	fs.Int64Var(&c.SpoolIPMaxBytes, "spool-ip-max-bytes", 100<<30, "spool size limit per client address (0 = unlimited)")
	fs.Int64Var(&c.SpoolTotalMaxBytes, "spool-total-max-bytes", 200<<30, "spool size limit for the whole server (0 = unlimited)")
	var envs string
	c.Quotas = env("QUOTAS", "") == "on"
	fs.StringVar(&c.BillingAuthority, "billing-authority", "", "server ID of the fleet's billing authority (empty = this server keeps its own counters)")
	fs.BoolVar(&c.BillingIdentity, "billing-identity", false, "serve /v2/billing/identities/*: bind a transport key to the account that proved it (no quota changes)")
	fs.Var((*onOff)(&c.Quotas), "quotas", "on: meter relay/TURN/spool by App Store entitlement (our servers); off (default): self-hosting, unlimited traffic, connection limits stay")
	fs.Int64Var(&c.FreeRelayBytes, "free-relay-bytes", 10<<30, "free: relayed bytes per account per month (10 GiB)")
	fs.Int64Var(&c.FreeSpoolBytes, "free-spool-bytes", 2e9, "free: spool storage per device")
	fs.Int64Var(&c.RelayMaxBytes, "relay-max-bytes", 2<<40, "Relay Max subscription: relayed bytes per account per month (2 TiB)")
	fs.Int64Var(&c.RelayBytes, "relay-bytes", 200<<30, "Relay subscription: relayed bytes per account per month (200 GiB)")
	fs.Int64Var(&c.RelaySpoolBytes, "relay-spool-bytes", 20e9, "Relay subscription: spool storage per device")
	fs.Int64Var(&c.TeamsPersonBytes, "teams-person-bytes", 200e9, "Teams: relayed bytes per person per month, pooled per network")
	fs.Int64Var(&c.TeamsSpoolBytes, "teams-spool-bytes", 20e9, "Teams: spool storage per device")
	fs.BoolVar(&c.Teams, "teams", env("TEAMS", "on") == "on", "honour Farlink Teams packs")
	fs.StringVar(&c.BundleID, "bundle-id", env("BUNDLE_ID", "com.flyoz.farlink"), "App Store bundle id transactions must carry")
	fs.StringVar(&c.ProductPrefix, "product-prefix", env("PRODUCT_PREFIX", "com.flyoz.farlink"), "App Store product id prefix")
	fs.StringVar(&envs, "appstore-env", env("APPSTORE_ENV", "Production"), "accepted transaction environments: Production,Sandbox,Xcode")
	fs.StringVar(&c.StoreRootFile, "appstore-root", env("APPSTORE_ROOT", ""), "extra trusted root certificate for transactions (testing)")
	fs.Int64Var(&c.IPTrafficBytes, "ip-traffic-bytes", 200e9, "with -quotas: free-tier traffic per client address per month, whatever keys it uses (0 = no cap)")
	fs.Int64Var(&c.TotalTrafficBytes, "total-traffic-bytes", 0, "with -quotas: traffic of the whole server per month (0 = no cap)")
	var trusted string
	fs.StringVar(&c.FederationCert, "federation-cert", env("FEDERATION_CERT", ""), "certificate this server presents to other Farlink servers (its pin is federation_identity in servers.json)")
	fs.StringVar(&c.FederationKey, "federation-key", env("FEDERATION_KEY", ""), "private key of -federation-cert")
	fs.StringVar(&trusted, "registry-key", env("REGISTRY_KEY", ""), "operator keys that sign servers.json: keyid=base64pub[,keyid=base64pub]")
	if err := fs.Parse(joinOnOff(args, "quotas")); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 { // a stray word would otherwise be ignored silently
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	for _, e := range strings.Split(envs, ",") {
		switch e = strings.TrimSpace(e); e {
		case "":
		case "Production", "Sandbox", "Xcode":
			c.StoreEnvs = append(c.StoreEnvs, e)
		default:
			return nil, fmt.Errorf("unknown App Store environment %q", e)
		}
	}
	if c.BillingAuthority != "" && (c.FederationCert == "" || !c.Quotas) {
		return nil, errors.New("-billing-authority needs -quotas on and a federation certificate: the servers reach the authority over federation")
	}
	if c.Quotas && (c.FreeRelayBytes <= 0 || c.RelayBytes <= 0 || c.TeamsPersonBytes <= 0) {
		return nil, errors.New("with -quotas, every tier needs a positive relay allowance")
	}
	if (c.FederationCert == "") != (c.FederationKey == "") {
		return nil, errors.New("-federation-cert and -federation-key go together")
	}
	if c.FederationCert != "" {
		keys, err := parseTrustedKeys(trusted)
		if err != nil {
			return nil, err
		}
		c.TrustedKeys = keys
	}
	if relayPorts != "" {
		lo, hi, ok := strings.Cut(relayPorts, "-")
		a, errA := strconv.ParseUint(lo, 10, 16)
		b, errB := strconv.ParseUint(hi, 10, 16)
		if !ok || errA != nil || errB != nil || a == 0 || a > b {
			return nil, fmt.Errorf("-turn-relay-ports: want min-max, e.g. 50000-54999, got %q", relayPorts)
		}
		c.TURNPorts = [2]uint16{uint16(a), uint16(b)}
	}
	c.Roles = map[Role]bool{}
	for _, r := range strings.Split(roles, ",") {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if !validRole(Role(r)) {
			return nil, fmt.Errorf("unknown role %q", r)
		}
		c.Roles[Role(r)] = true
	}
	if len(c.Roles) == 0 {
		return nil, errors.New("no roles enabled")
	}
	if c.ServerID == "" {
		// Clients sign it as the auth audience and compare it with the id they expect, so it must not drift
		// with the hostname of a container or a rebuilt VPS.
		return nil, errors.New("need -id (the server id listed in servers.json)")
	}
	if !LooksLikeOrigin(c.ServerID) {
		// Devices derive a self-hosted server's expected audience from the address the user typed, never from
		// the server; only servers in the signed servers.json may use another id.
		log.Printf("warning: -id %q is not an https origin; a self-hosted server must run with -id set to the address "+
			"users add in Farlink, e.g. https://files.example.com or https://203.0.113.5:8443", c.ServerID)
	}
	if c.Roles[RoleTURN] && c.PublicIP == "" {
		return nil, errors.New("the turn role needs -public-ip")
	}
	if c.Domain == "" && (c.CertFile == "" || c.KeyFile == "") {
		return nil, errors.New("need -domain for Let's Encrypt, or both -cert and -key")
	}
	return c, nil
}

func parseTrustedKeys(list string) (map[string][]byte, error) {
	keys := map[string][]byte{}
	for _, item := range strings.Split(list, ",") {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		id, b64, ok := strings.Cut(item, "=")
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			raw, err = base64.RawURLEncoding.DecodeString(b64)
		}
		if !ok || id == "" || err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("-registry-key: want keyid=base64 Ed25519 public key, got %q", item)
		}
		keys[id] = raw
	}
	if len(keys) == 0 {
		return nil, errors.New("federation needs -registry-key: the operator key that signs servers.json")
	}
	return keys, nil
}

func validRole(r Role) bool {
	for _, x := range allRoles {
		if x == r {
			return true
		}
	}
	return false
}

// LooksLikeOrigin reports whether id is written as devices derive a custom server's audience: https, lower-case
// host, a port only when it isn't 443, nothing else.
func LooksLikeOrigin(id string) bool {
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" ||
		u.Opaque != "" || u.ForceQuery || strings.ToLower(u.Host) != u.Host || u.Port() == "443" || strings.HasSuffix(u.Host, ":") {
		return false
	}
	return true
}

// onOff is a boolean flag that also reads on/off: -quotas, -quotas=on, -quotas off.
type onOff bool

func (b *onOff) String() string {
	if b != nil && *b {
		return "on"
	}
	return "off"
}

func (b *onOff) Set(v string) error {
	switch v {
	case "on", "true", "1":
		*b = true
	case "off", "false", "0":
		*b = false
	default:
		return fmt.Errorf("want on or off, not %q", v)
	}
	return nil
}

func (b *onOff) IsBoolFlag() bool { return true }

// joinOnOff turns "-name on|off" into "-name=on|off": a boolean flag never takes a separate value.
func joinOnOff(args []string, name string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if (a == "-"+name || a == "--"+name) && i+1 < len(args) && (args[i+1] == "on" || args[i+1] == "off") {
			a += "=" + args[i+1]
			i++
		}
		out = append(out, a)
	}
	return out
}
