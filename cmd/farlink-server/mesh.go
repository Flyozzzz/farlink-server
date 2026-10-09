package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/auth"
	"github.com/Flyozzzz/farlink-server/internal/billing"
	"github.com/Flyozzzz/farlink-server/internal/config"
	"github.com/Flyozzzz/farlink-server/internal/contacts"
	"github.com/Flyozzzz/farlink-server/internal/drop"
	"github.com/Flyozzzz/farlink-server/internal/federation"
	"github.com/Flyozzzz/farlink-server/internal/mailbox"
	"github.com/Flyozzzz/farlink-server/internal/outbox"
	"github.com/Flyozzzz/farlink-server/internal/registry"
	"github.com/Flyozzzz/farlink-server/internal/report"
)

// mountMesh serves this server's mailbox to its own devices and, with a federation certificate, accepts
// envelopes from the other servers of the signed registry. It returns the mailbox for later services.
func mountMesh(cfg *config.Config, a *auth.Service, mux *http.ServeMux, tlsConfig *tls.Config, sp drop.SpoolInfo, wake func(dest []byte), resolver *accounts.Resolver, ledger *billing.Ledger, deleter *accounts.Deleter, accountAPI *accounts.API) *mailbox.Store {
	box, err := mailbox.Open(filepath.Join(cfg.DataDir, "mailbox"))
	if err != nil {
		log.Fatal(err)
	}
	box.OnPut = wake
	box.Deny = a.IsBlocked
	deleter.Purge = append(deleter.Purge, func(_ []byte, devices [][]byte) error { return box.PurgeDevices(devices) })
	api := &mailbox.API{Auth: a, Store: box, Accounts: resolver}
	mux.HandleFunc("GET /v1/mailbox", api.HandleList)
	mux.HandleFunc("POST /v1/mailbox/{id}/ack", api.HandleAck)
	go func() {
		for range time.Tick(10 * time.Minute) {
			box.GC()
		}
	}()
	people, err := contacts.Open(filepath.Join(cfg.DataDir, "contacts"))
	if err != nil {
		log.Fatal(err)
	}
	deleter.Purge = append(deleter.Purge, func(account []byte, _ [][]byte) error { return people.PurgeAccount(account) })
	stateAPI := &contacts.API{Auth: a, Store: people, Accounts: resolver, Self: cfg.ServerID}
	mux.HandleFunc("POST /v1/contacts/state", stateAPI.HandleState)
	reports, err := report.New(a, filepath.Join(cfg.DataDir, "reports"))
	if err != nil {
		log.Fatal(err)
	}
	mux.HandleFunc("POST /v1/reports", reports.HandleReport)
	go func() {
		for range time.Tick(6 * time.Hour) {
			reports.GC()
		}
	}()
	if cfg.FederationCert == "" {
		// A lone server is its own only mailbox: devices of one server still get hints and messages.
		router := &contacts.Router{Self: cfg.ServerID, Store: people, Accounts: resolver}
		out, err := outbox.Open(filepath.Join(cfg.DataDir, "outbox"), cfg.ServerID, noPeers{}, router.Guard(box.Sink()))
		if err != nil {
			log.Fatal(err)
		}
		deleter.Purge = append(deleter.Purge, func(_ []byte, devices [][]byte) error { return out.PurgeDevices(devices) })
		go out.Run(context.Background())
		mux.HandleFunc("POST /v1/mailbox/drop", (&drop.Service{Auth: a, Self: cfg.ServerID, Spool: sp, Outbox: out,
			Accounts: resolver, Authority: router}).HandleDrop)
		return box
	}

	cert, err := tls.LoadX509KeyPair(cfg.FederationCert, cfg.FederationKey)
	if err != nil {
		log.Fatal(err)
	}
	trusted := map[string]ed25519.PublicKey{}
	for id, k := range cfg.TrustedKeys {
		trusted[id] = ed25519.PublicKey(k)
	}
	regPath := filepath.Join(cfg.DataDir, "servers.json")
	floor := registry.Floor{Path: filepath.Join(cfg.DataDir, "servers.floor")}
	load := func() (registry.Registry, error) {
		data, err := os.ReadFile(regPath)
		if err != nil {
			return registry.Registry{}, err
		}
		min, err := floor.Read()
		if err != nil {
			return registry.Registry{}, err
		}
		r, err := registry.Verify(data, trusted, time.Now(), min)
		if err != nil {
			return registry.Registry{}, err
		}
		if err := floor.Raise(r.Sequence); err != nil {
			return registry.Registry{}, err
		}
		return *r, nil
	}
	reg, err := load()
	if err != nil {
		log.Fatalf("federation: %s: %v", regPath, err)
	}
	dir, err := federation.NewDirectory(reg)
	if err != nil {
		log.Fatal(err)
	}
	if _, ok := dir.Peer(cfg.ServerID); !ok {
		log.Printf("federation: %s is not in servers.json with a federation_identity; peers will not accept it", cfg.ServerID)
	}
	watch := &federation.Watch{Dir: dir, Load: load, Grace: 72 * time.Hour}
	watch.Start(reg)
	go func() {
		for range time.Tick(time.Hour) {
			if err := watch.Tick(); err != nil {
				log.Printf("federation: could not refresh the server list: %v", err)
			}
		}
	}()
	client := &federation.Client{Self: cfg.ServerID, Dir: dir, Cert: cert}
	stateAPI.Client = client
	// Account freshness is read with the other servers of the directory (a quorum), never from this server alone.
	resolver.Peers = client.AccountReplicas
	// A deletion is told to every other server, and only they may read a deleted account's chain.
	isPeer := func(r *http.Request) bool { _, ok := federation.AuthenticatePeer(dir, r); return ok }
	deleter.IsPeer, accountAPI.IsPeer = isPeer, isPeer
	deleter.Peers = func() []string {
		var out []string
		for _, id := range dir.IDs() {
			if id != cfg.ServerID {
				out = append(out, id)
			}
		}
		return out
	}
	deleter.Push = func(ctx context.Context, peer string, p accounts.PeerDelete) error {
		var out accounts.DeleteStatus
		return client.Call(ctx, peer, "/v1/federation/accounts/delete", p, &out)
	}
	if ledger != nil && cfg.BillingAuthority != "" && cfg.BillingAuthority != cfg.ServerID {
		// Not the authority: account allowances are asked of it in blocks, never counted here.
		ledger.Remote = &billing.FedRemote{Client: client, Authority: cfg.BillingAuthority}
	} else if ledger != nil && cfg.BillingAuthority == cfg.ServerID {
		authority := &billing.Authority{Dir: dir, Ledger: ledger, Limits: billing.Limits{FreeRelay: cfg.FreeRelayBytes, RelayRelay: cfg.RelayBytes, RelayMaxRelay: cfg.RelayMaxBytes, TeamsPerPerson: cfg.TeamsPersonBytes}}
		mux.HandleFunc("POST "+billing.GrantPath, authority.HandleGrant)
		mux.HandleFunc("POST "+billing.UsedPath, authority.HandleUsed)
	}
	router := &contacts.Router{Self: cfg.ServerID, Store: people, Accounts: resolver, Client: client}
	fed := &federation.Server{Self: cfg.ServerID, Dir: dir, Sink: router.Guard(box.Sink()), Client: client}
	out, err := outbox.Open(filepath.Join(cfg.DataDir, "outbox"), cfg.ServerID, client, router.Guard(box.Sink()))
	if err != nil {
		log.Fatal(err)
	}
	deleter.Purge = append(deleter.Purge, func(_ []byte, devices [][]byte) error { return out.PurgeDevices(devices) })
	go out.Run(context.Background())
	mux.HandleFunc("POST /v1/mailbox/drop", (&drop.Service{Auth: a, Self: cfg.ServerID, Dir: dir, Spool: sp, Outbox: out,
		Accounts: resolver, Authority: router}).HandleDrop)
	contactFederation := &contacts.Federation{Dir: dir, Router: router}
	mux.HandleFunc("POST "+contacts.AdmitPath, contactFederation.HandleAdmit)
	mux.HandleFunc("POST "+contacts.ExportPath, contactFederation.HandleExport)
	mux.HandleFunc("POST "+contacts.ImportPath, contactFederation.HandleImport)
	mux.HandleFunc("POST /v1/federation/forward", fed.HandleForward)
	// Peers present a certificate; ordinary clients don't, and every other route ignores it. The handler checks the
	// certificate's key against the registry, so the chain is not verified here.
	tlsConfig.ClientAuth = tls.RequestClientCert
	return box
}

// noPeers stands in for the federation client on a server that has none.
type noPeers struct{}

func (noPeers) Send(context.Context, string, federation.Request) error {
	return &federation.Error{Status: 404, Code: "UNKNOWN_SERVER"}
}
