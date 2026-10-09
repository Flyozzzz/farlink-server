package contacts

import (
	"context"
	"net/http"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/federation"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

const (
	ExportPath = "/v1/federation/contacts/export"
	ImportPath = "/v1/federation/contacts/import"
)

type migrationRequest struct {
	Account    []byte           `cbor:"account_id"`
	Transition accounts.HeadRef `cbor:"transition"`
}

func (r *Router) ensure(ctx context.Context, recipient []byte, routes []accounts.ContactRoute) error {
	if len(routes) == 0 || routes[len(routes)-1].Server != r.Self {
		return errNotAuthority
	}
	ready, err := r.Store.ready(recipient, routes)
	if err != nil || ready {
		return err
	}
	if len(routes) < 2 || r.Client == nil {
		return ErrMigration
	}
	last := routes[len(routes)-1]
	if err := r.Client.Post(ctx, routes[len(routes)-2].Server, ExportPath, migrationRequest{recipient, last.Head}); err != nil {
		return err
	}
	ready, err = r.Store.ready(recipient, routes)
	if err != nil {
		return err
	}
	if !ready {
		return ErrMigration
	}
	return nil
}

func (f *Federation) HandleExport(w http.ResponseWriter, req *http.Request) {
	peer, ok := federation.AuthenticatePeer(f.Dir, req)
	if !ok {
		wire.WriteError(w, 401, "PEER_UNAUTHORIZED", false)
		return
	}
	var request migrationRequest
	if err := wire.ReadLimit(req, &request, 4<<10); err != nil {
		wire.WriteReadError(w, err)
		return
	}
	current, err := f.Router.Accounts.Current(req.Context(), request.Account)
	if err != nil {
		writeErr(w, AccountError(err))
		return
	}
	routes := current.ContactRoutes()
	index := routeIndex(routes, request.Transition)
	if index < 1 || routes[index].Server != peer.ServerID || routes[index-1].Server != f.Router.Self {
		writeErr(w, errForbidden)
		return
	}
	// An immutable cached export is safe to resend even after the source has itself
	// become authority again. Otherwise catch up earlier handoffs before fencing.
	snapshot, err := f.Router.Store.export(request.Account, routes[index-1], routes[index])
	if err == ErrMigration {
		if err = f.Router.ensure(req.Context(), request.Account, routes[:index]); err == nil {
			snapshot, err = f.Router.Store.export(request.Account, routes[index-1], routes[index])
		}
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	if f.Router.Client == nil {
		writeErr(w, ErrMigration)
		return
	}
	if err := f.Router.Client.Post(req.Context(), peer.ServerID, ImportPath, snapshot); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *Federation) HandleImport(w http.ResponseWriter, req *http.Request) {
	peer, ok := federation.AuthenticatePeer(f.Dir, req)
	if !ok {
		wire.WriteError(w, 401, "PEER_UNAUTHORIZED", false)
		return
	}
	var snapshot AuthoritySnapshot
	if err := wire.ReadLimit(req, &snapshot, 2<<20); err != nil {
		wire.WriteReadError(w, err)
		return
	}
	if snapshot.From != peer.ServerID || snapshot.To != f.Router.Self {
		writeErr(w, errForbidden)
		return
	}
	current, err := f.Router.Accounts.Current(req.Context(), snapshot.Recipient)
	if err != nil {
		writeErr(w, AccountError(err))
		return
	}
	if err := f.Router.Store.importSnapshot(snapshot, current.ContactRoutes()); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
