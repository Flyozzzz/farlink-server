// farlink-server: rendezvous, TURN, relay and encrypted spool for Farlink devices. It never sees file
// contents or names; see docs/specs/farlink-protocol-v1.md.
package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/appstore"
	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/billing"
	"github.com/Flyozzzz/farlink-server/internal/config"
	"github.com/Flyozzzz/farlink-server/internal/drop"
	"github.com/Flyozzzz/farlink-server/internal/invites"
	"github.com/Flyozzzz/farlink-server/internal/meter"
	"github.com/Flyozzzz/farlink-server/internal/relay"
	sig "github.com/Flyozzzz/farlink-server/internal/signal"
	"github.com/Flyozzzz/farlink-server/internal/spool"
	"github.com/Flyozzzz/farlink-server/internal/turn"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

var version = "dev"

func main() {
	cfg, err := config.Parse(os.Args[1:], os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatal(err)
	}
	tlsConfig, err := tlsFor(cfg)
	if err != nil {
		log.Fatal(err)
	}

	a := auth.New(cfg.ServerID)
	a.TTL = cfg.SessionTTL
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		roles := []string{}
		for r, on := range cfg.Roles {
			if on {
				roles = append(roles, string(r))
			}
		}
		wire.Write(w, map[string]any{"server_id": cfg.ServerID, "protocol_versions": []uint64{1}, "roles": roles, "version": version})
	})
	// A mirror of the signed server list: clients verify the operator signature, so serving it needs no trust.
	mux.HandleFunc("GET /servers.json", func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile(filepath.Join(cfg.DataDir, "servers.json"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Write(data)
	})
	mux.HandleFunc("POST /v1/auth/challenges", a.HandleChallenge)
	mux.HandleFunc("POST /v1/auth/sessions", a.HandleSession)
	// Account chains (spec 2026-10-04 §12): public signed data, each link proves itself, so no bearer token.
	accountRegistry, err := accounts.Open(filepath.Join(cfg.DataDir, "accounts"))
	if err != nil {
		log.Fatal(err)
	}
	accountResolver, err := accounts.OpenResolver(accountRegistry, filepath.Join(cfg.DataDir, "account-checkpoints"), nil)
	if err != nil {
		log.Fatal(err)
	}
	accountAPI := &accounts.API{Reg: accountRegistry}
	mux.HandleFunc("POST /v1/accounts", accountAPI.HandleCreate)
	mux.HandleFunc("POST /v1/accounts/{id}/links", accountAPI.HandleLink)
	mux.HandleFunc("GET /v1/accounts/{id}", accountAPI.HandleGet)
	// Deleting an account: one signed request, then every server erases it (see accounts/deletion.go).
	deleter := &accounts.Deleter{Reg: accountRegistry, Resolver: accountResolver, Dir: filepath.Join(cfg.DataDir, "account-deletions")}
	if err := deleter.Open(); err != nil {
		log.Fatal(err)
	}
	mux.HandleFunc("POST /v1/accounts/{id}/delete", deleter.HandleDelete(accountAPI))
	mux.HandleFunc("POST /v1/federation/accounts/delete", deleter.HandlePeer)
	deleter.Finish = append(deleter.Finish, accountResolver.Forget)
	a.Blocked = accountRegistry.OwnerDeleted // with account billing on, keys bound to a deleted account are refused too (below)

	var wake func(dest []byte)
	if cfg.Has(config.RoleSignal) {
		hub := sig.NewHub()
		wake = hub.Nudge
		go func() {
			for range time.Tick(time.Minute) {
				hub.GC()
			}
		}()
		mux.HandleFunc("GET /v1/signal", sig.Handler(hub, a))
		mux.HandleFunc("GET /v1/signal/peers/{tag}", sig.PeersHandler(hub, a))
		inv := invites.New(a)
		deleter.Purge = append(deleter.Purge, inv.PurgeAccount)
		inv.Accounts = accountResolver
		mux.HandleFunc("POST /v1/invites", inv.HandlePut)
		mux.HandleFunc("GET /v1/invites/{lookup}", inv.HandleGet)
		mux.HandleFunc("DELETE /v1/invites/{lookup}", inv.HandleDelete)
	}
	// One meter for every transport, so relay, TURN and spool downloads can't each be spent in full: the
	// billing ledger's tiers plus the free-traffic cap per address and the server's total, both persisted.
	bill := &billing.Service{Auth: a}
	var traffic meter.Meter = meter.Off{}
	var saves []func() error
	if cfg.Quotas {
		if bill.Store, err = billingStore(cfg); err != nil {
			log.Fatal(err)
		}
		if bill.Ledger, err = billing.OpenLedger(bill.Store.Buckets, filepath.Join(cfg.DataDir, "ledger.cbor")); err != nil {
			log.Fatal(err)
		}
		t, err := meter.Open(filepath.Join(cfg.DataDir, "traffic.cbor"))
		if err != nil {
			log.Fatal(err)
		}
		t.Devices, t.IPLimit, t.TotalLimit = bill.Ledger, cfg.IPTrafficBytes, cfg.TotalTrafficBytes
		traffic = t
		saves = append(saves, bill.Ledger.Save, t.Save)
		go func() {
			for range time.Tick(time.Minute) {
				saveMeters(saves)
			}
		}()
		mux.HandleFunc("POST /v1/appstore/notifications", bill.HandleNotification)
	}
	quota := bill.Ledger
	if !cfg.Quotas {
		log.Print("quotas off: traffic is not metered (connection and memory limits stay on)")
	}
	mux.HandleFunc("POST /v1/entitlements/verify", bill.HandleVerify)
	mux.HandleFunc("GET /v1/quota", bill.HandleQuota)
	var bindings *billing.Bindings
	var recountQueues func() // set once the spool exists: a key bound later moves its queue onto its account
	if cfg.BillingIdentity {
		var err error
		bindings, err = billing.OpenBindings(cfg.DataDir)
		if err != nil {
			log.Fatal(err)
		}
		if bill.Store != nil {
			bill.Store.AccountOf = bindings.Lookup
			bill.Store.RequireAccount = true
		}
		identity := &billing.Identity{Auth: a, Accounts: accountResolver, Bindings: bindings, Self: cfg.ServerID,
			OnNewBinding: func() {
				if recountQueues != nil {
					recountQueues()
				}
			}}
		deleter.Expand = func(account []byte, devices [][]byte) [][]byte {
			return append(append([][]byte(nil), devices...), bindings.TransportsOf(account)...)
		}
		a.Blocked = func(device []byte) bool {
			if accountRegistry.OwnerDeleted(device) {
				return true
			}
			account, ok := bindings.Lookup(device)
			return ok && accountRegistry.IsDeleted(account)
		}
		deleter.Finish = append(deleter.Finish, bindings.Remove)
		mux.HandleFunc("POST /v2/billing/identities/bind", identity.HandleBind)
		mux.HandleFunc("GET /v2/billing/identities/me", identity.HandleLookup)
	}
	// Whatever the quotas, a device of a deleted account is refused by every metered transport at its next charge.
	traffic = meter.Guard{Meter: traffic, Blocked: a.IsBlocked}
	if cfg.Has(config.RoleRelay) {
		r := relay.New(a)
		r.Meter = traffic
		r.Blocked = a.IsBlocked
		mux.HandleFunc("POST /v1/relay/sessions", r.HandleCreate)
		mux.HandleFunc("GET /v1/relay/{id}", r.HandleConnect)
	}
	var spoolInfo drop.SpoolInfo
	if cfg.Has(config.RoleSpool) {
		s, err := spool.New(a, filepath.Join(cfg.DataDir, "spool"), cfg.SpoolTTL, cfg.SpoolMaxBytes)
		if err != nil {
			log.Fatal(err)
		}
		s.Accounts = accountResolver
		s.MaxIPBytes, s.MaxTotalBytes = cfg.SpoolIPMaxBytes, cfg.SpoolTotalMaxBytes
		s.Meter = traffic
		if quota != nil {
			s.OwnerMaxBytes = quota.SpoolLimit
		}
		if bindings != nil {
			// The queue allowance belongs to the account: its keys share it.
			ownerKey := func(owner []byte) string {
				if account, ok := bindings.Lookup(owner); ok {
					return "a:" + string(account)
				}
				return "d:" + string(owner)
			}
			s.SetOwnerKey(ownerKey)
			recountQueues = func() { s.SetOwnerKey(ownerKey) }
		}
		spoolInfo = s
		deleter.Purge = append(deleter.Purge, func(_ []byte, devices [][]byte) error { return s.PurgeDevices(devices) })
		mux.HandleFunc("POST /v1/spools", s.HandleCreate)
		mux.HandleFunc("GET /v1/spools", s.HandleList)
		mux.HandleFunc("GET /v1/spools/{id}", s.HandleGet)
		mux.HandleFunc("PUT /v1/spools/{id}/parts/{part}", s.HandlePutPart)
		mux.HandleFunc("GET /v1/spools/{id}/parts/{part}", s.HandleGetPart)
		mux.HandleFunc("POST /v1/spools/{id}/commit", s.HandleCommit)
		mux.HandleFunc("POST /v1/spools/{id}/ack", s.HandleAck)
		mux.HandleFunc("DELETE /v1/spools/{id}", s.HandleDelete)
		go func() {
			for range time.Tick(10 * time.Minute) {
				s.GC()
			}
		}()
	}
	if cfg.Has(config.RoleTURN) {
		secret, err := turn.LoadSecret(cfg.DataDir)
		if err != nil {
			log.Fatal(err)
		}
		host := cfg.Domain
		if host == "" {
			host = cfg.PublicIP
		}
		// The same UDP listener answers STUN Binding without credentials: devices learn their server-reflexive
		// address there for hole punching.
		t := &turn.Service{Auth: a, Secret: secret, Now: time.Now, Meter: traffic, URLs: []string{"stun:" + host + portOf(cfg.TURNListen),
			"turn:" + host + portOf(cfg.TURNListen) + "?transport=udp"}, RelayPorts: cfg.TURNPorts}
		if cfg.TURNTLS != "" {
			t.URLs = append(t.URLs, "turns:"+host+portOf(cfg.TURNTLS)+"?transport=tcp")
		}
		ts, err := t.Listen(cfg.TURNListen, cfg.TURNTLS, tlsConfig, cfg.PublicIP)
		if err != nil {
			log.Fatal(err)
		}
		defer ts.Close()
		mux.HandleFunc("POST /v1/turn/credentials", t.HandleCredentials)
	}

	mountMesh(cfg, a, mux, tlsConfig, spoolInfo, wake, accountResolver, bill.Ledger, deleter, accountAPI)
	go deleter.Run(context.Background()) // every store has registered its purge by now

	srv := &http.Server{Addr: cfg.Listen, Handler: mux, TLSConfig: tlsConfig,
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	go func() {
		log.Printf("farlink-server %s (%s) on %s", version, cfg.ServerID, cfg.Listen)
		if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	saveMeters(saves)
}

func saveMeters(saves []func() error) {
	for _, save := range saves {
		if err := save(); err != nil {
			log.Printf("traffic meter: %v", err)
		}
	}
}

func billingStore(cfg *config.Config) (*billing.Store, error) {
	v := appstore.NewVerifier(cfg.BundleID, cfg.StoreEnvs...)
	if cfg.StoreRootFile != "" {
		b, err := os.ReadFile(cfg.StoreRootFile)
		if err != nil {
			return nil, err
		}
		if blk, _ := pem.Decode(b); blk != nil {
			b = blk.Bytes
		}
		v.Roots = append(v.Roots, appstore.Fingerprint(b))
	}
	l := billing.Limits{FreeRelay: cfg.FreeRelayBytes, FreeSpool: cfg.FreeSpoolBytes, RelayRelay: cfg.RelayBytes, RelayMaxRelay: cfg.RelayMaxBytes,
		RelaySpool: cfg.RelaySpoolBytes, TeamsPerPerson: cfg.TeamsPersonBytes, TeamsSpool: cfg.TeamsSpoolBytes}
	return billing.NewStore(v, billing.Catalog(cfg.ProductPrefix, cfg.Teams), l, filepath.Join(cfg.DataDir, "entitlements.json"))
}

func tlsFor(cfg *config.Config) (*tls.Config, error) {
	if cfg.Domain != "" {
		m := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(cfg.Domain),
			Cache: autocert.DirCache(filepath.Join(cfg.DataDir, "acme"))}
		go http.ListenAndServe(":80", m.HTTPHandler(nil)) // ACME http-01
		c := m.TLSConfig()
		c.MinVersion = tls.VersionTLS12
		return c, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

func portOf(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[i:]
		}
	}
	return ""
}
