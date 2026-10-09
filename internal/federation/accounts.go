package federation

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/wire"
)

// AccountReplicas captures one peer-directory revision for a quorum read. The
// local replica is supplied by accounts.Resolver. A missing/expired directory is
// not a standalone deployment and must never shrink its quorum to just self.
func (c *Client) AccountReplicas() ([]accounts.Replica, error) {
	c.Dir.mu.RLock()
	defer c.Dir.mu.RUnlock()
	if _, ok := c.Dir.byID[c.Self]; !ok {
		return nil, accounts.ErrUnreachable
	}
	peers := make([]accounts.Replica, 0, len(c.Dir.byID)-1)
	for id, peer := range c.Dir.byID {
		if id == c.Self {
			continue
		}
		peers = append(peers, accounts.Replica{ID: id, Page: func(ctx context.Context, account []byte, from uint64) ([][]byte, error) {
			return c.accountPage(ctx, peer, account, from)
		}})
	}
	return peers, nil
}

func (c *Client) accountPage(ctx context.Context, peer Peer, account []byte, from uint64) ([][]byte, error) {
	path := fmt.Sprintf("/v1/accounts/%s?journal_from=%d", base64.RawURLEncoding.EncodeToString(account), from)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, peer.APIOrigin+path, nil)
	if err != nil {
		return nil, err
	}
	// Reuse the federation mTLS and leaf-pin policy; never carry a peer's request
	// or certificate to a redirect target outside this directory snapshot.
	client := *c.httpFor(peer)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, accounts.ErrUnreachable
	}
	const maxResponse = accounts.MaxSuffixBytes + 1024
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponse {
		return nil, accounts.ErrTooLong
	}
	var page [][]byte
	if err := wire.Lenient(data, &page); err != nil {
		return nil, err
	}
	if page == nil || len(page) > accounts.MaxSuffixLinks {
		return nil, accounts.ErrMalformed
	}
	return page, nil
}
