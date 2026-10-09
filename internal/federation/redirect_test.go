package federation

import (
	"context"
	"github.com/Flyozzzz/farlink-server/internal/registry"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFederationPostNeverFollowsRedirect(t *testing.T) {
	for _, status := range []int{307, 308} {
		for _, secure := range []bool{false, true} {
			t.Run(http.StatusText(status)+map[bool]string{false: "-http", true: "-tls"}[secure], func(t *testing.T) {
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Error("forwarded CBOR outside peer directory")
					w.WriteHeader(204)
				}))
				defer target.Close()
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, status) })
				var origin *httptest.Server
				if secure {
					origin = httptest.NewTLSServer(handler)
				} else {
					origin = httptest.NewServer(handler)
				}
				defer origin.Close()
				_, pin := mkCert(t, "peer")
				dir, err := NewDirectory(registry.Registry{Servers: []registry.Server{{ServerID: "peer", APIOrigin: origin.URL, FederationIdentity: PinString(pin)}}})
				if err != nil {
					t.Fatal(err)
				}
				c := &Client{Dir: dir, HTTP: origin.Client()}
				if err := c.Post(context.Background(), "peer", "/v1/federation/admit", map[string]string{"secret": "body"}); err == nil {
					t.Fatal("redirect accepted")
				}
			})
		}
	}
}
