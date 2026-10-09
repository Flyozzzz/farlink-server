package spool

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/Flyozzzz/farlink-server/internal/accounts"
	"github.com/Flyozzzz/farlink-server/internal/testutil"
)

func TestContactSpoolForkClosesDescriptorPartsRangeAndACKUntilRecovery(t *testing.T) {
	c := newContactSpool(t)
	f := c.f
	partURL := f.url("parts", enc.EncodeToString(f.part.PartID))
	if status := testutil.Do(t, "PUT", partURL, f.tOwner, f.data, nil); status != 204 {
		t.Fatal(status)
	}
	if status := c.commit(t); status != 204 {
		t.Fatal(status)
	}
	alternate := *c.to
	alternate.Links = append([][]byte(nil), c.to.Links...)
	c.to.Update(t, f.peer, func(s *accounts.State) { s.Nickname = "A" })
	c.to.Publish(t, c.registry)
	alternate.Update(t, f.peer, func(s *accounts.State) { s.Nickname = "B" })
	if _, _, err := c.registry.Submit(alternate.Links[len(alternate.Links)-1]); !errors.Is(err, accounts.ErrFork) {
		t.Fatal(err)
	}
	for _, request := range []struct{ method, url string }{{"GET", f.url()}, {"GET", partURL}, {"POST", f.url("ack")}} {
		if status := testutil.Do(t, request.method, request.url, f.tPeer, nil, nil); status != 503 {
			t.Fatalf("%s: %d", request.method, status)
		}
	}
	request, err := http.NewRequest("GET", partURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+f.tPeer)
	request.Header.Set("Range", "bytes=0-9")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 503 || bytes.Equal(body, f.data[:10]) {
		t.Fatal("forked Range returned data", err)
	}
	c.to.Update(t, c.to.Recovery, func(s *accounts.State) { s.Nickname = "Recovered" })
	c.to.Publish(t, c.registry)
	var descriptor GetResponse
	if status := testutil.Do(t, "GET", f.url(), f.tPeer, nil, &descriptor); status != 200 {
		t.Fatalf("recovered descriptor: %d", status)
	}
	if status := testutil.Do(t, "POST", f.url("ack"), f.tPeer, nil, nil); status != 204 {
		t.Fatalf("recovered ACK: %d", status)
	}
}
