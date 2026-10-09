package spool

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/Flyozzzz/farlink-server/internal/billing"
	"github.com/Flyozzzz/farlink-server/internal/meter"
	"github.com/Flyozzzz/farlink-server/internal/testutil"
)

func TestRangeLengthBoundaries(t *testing.T) {
	// Anything ServeContent answers with 416, or refuses here, is billed nothing.
	for _, tt := range []struct {
		name, header string
		size, want   int64
	}{
		{"whole", "", 1000, 1000},
		{"inclusive", "bytes=100-199", 1000, 100},
		{"single-byte", "bytes=999-999", 1000, 1},
		{"clipped-end", "bytes=990-2000", 1000, 10},
		{"open", "bytes=700-", 1000, 300},
		{"suffix", "bytes=-120", 1000, 120},
		{"oversized-suffix", "bytes=-2000", 1000, 1000},
		{"outside", "bytes=1000-", 1000, 0},
		{"reversed", "bytes=10-9", 1000, 0},
		{"multiple", "bytes=0-9,990-999", 1000, 0},
		{"only-empty-specs", "bytes=", 1000, 1000},
		{"no-prefix", "items=0-9", 1000, 0},
		{"long-leading-zero", "bytes=0000000000000002-0000000000000005", 1000, 4},
		{"zero-suffix", "bytes=-0", 1000, 0},
		{"empty-file", "", 0, 0},
		{"empty-file-range", "bytes=0-0", 0, 0},
		{"empty-file-suffix", "bytes=-1", 0, 0},
		{"overflow-start", "bytes=9223372036854775808-", 1000, 0},
		{"overflow-end", "bytes=0-9223372036854775808", 1000, 0},
		{"overflow-suffix", "bytes=-18446744073709551616", 1000, 0},
		{"max-size-open", "bytes=1-", math.MaxInt64, math.MaxInt64 - 1},
		{"max-size-whole", "bytes=0-", math.MaxInt64, math.MaxInt64},
		{"max-size-suffix", "bytes=-999999999999999", math.MaxInt64, 999999999999999},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := rangeLength(tt.header, tt.size); got != tt.want {
				t.Fatalf("rangeLength(%q,%d) = %d, want %d", tt.header, tt.size, got, tt.want)
			}
		})
	}
}

func TestDownloadRangeMonthlyAccounting(t *testing.T) {
	for _, tt := range []struct {
		name, header string
		size, status int
		spans        [][2]int // inclusive/exclusive ciphertext spans, not MIME framing
	}{
		{"whole", "", 1000, 200, [][2]int{{0, 1000}}},
		{"inclusive", "bytes=100-199", 1000, 206, [][2]int{{100, 200}}},
		{"suffix", "bytes=-120", 1000, 206, [][2]int{{880, 1000}}},
		{"open", "bytes=700-", 1000, 206, [][2]int{{700, 1000}}},
		{"clipped-end", "bytes=990-2000", 1000, 206, [][2]int{{990, 1000}}},
		{"oversized-suffix", "bytes=-2000", 1000, 206, [][2]int{{0, 1000}}},
		{"chunk-boundary", "bytes=123-131211", 150000, 206, [][2]int{{123, 131212}}},
		{"outside", "bytes=1000-", 1000, 416, nil},
		{"reversed", "bytes=10-9", 1000, 416, nil},
		{"multiple", "bytes=0-9,990-999", 1000, 416, nil},
		{"zero-suffix", "bytes=-0", 1000, 206, [][2]int{{1000, 1000}}},
		{"overflow-start", "bytes=9223372036854775808-", 1000, 416, nil},
		{"overflow-end", "bytes=0-9223372036854775808", 1000, 416, nil},
		{"overflow-suffix", "bytes=-18446744073709551616", 1000, 416, nil},
		{"long-leading-zero", "bytes=0000000000000002-0000000000000005", 1000, 206, [][2]int{{2, 6}}},
		{"if-range-mismatch", "bytes=0-9", 1000, 206, [][2]int{{0, 10}}},
		{"if-none-match-star", "", 1000, 200, [][2]int{{0, 1000}}},
		{"if-match-fails", "bytes=5-14", 1000, 206, [][2]int{{5, 15}}},
		{"if-unmodified-since", "", 1000, 200, [][2]int{{0, 1000}}},
		{"head", "", 1000, 200, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			defer f.srv.Close()
			if tt.size != len(f.data) {
				f.data = bytes.Repeat([]byte{0x5a}, tt.size)
				sum := sha256.Sum256(f.data)
				f.part.Size, f.part.CiphertextSHA256 = uint64(tt.size), sum[:]
				var cr CreateResponse
				if code := testutil.Do(t, "POST", f.srv.URL+"/v1/spools", f.tOwner, CreateRequest{Recipients: [][]byte{f.peer.ID}, Parts: []Part{f.part}}, &cr); code != 200 {
					t.Fatalf("reserve: %d", code)
				}
				f.id = cr.SpoolID
			}
			now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
			ledger := billing.NewLedger(func(device []byte) []billing.Bucket { return []billing.Bucket{{Key: string(device), Limit: 1 << 30}} })
			ledger.Now = func() time.Time { return now }
			traffic, err := meter.Open(filepath.Join(t.TempDir(), "traffic"))
			if err != nil {
				t.Fatal(err)
			}
			traffic.Now, traffic.Devices = ledger.Now, ledger
			f.s.Meter = traffic
			url := uploaded(t, f)
			if got := ledger.Balance(f.owner.ID).Used; got != 0 {
				t.Fatalf("upload charged %d relay bytes", got)
			}
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+f.tPeer)
			req.Header.Set("Range", tt.header)
			switch tt.name {
			case "if-range-mismatch":
				req.Header.Set("If-Range", `"not-our-etag"`) // would make ServeContent send the whole, unbilled part
			case "if-none-match-star":
				req.Header.Set("If-None-Match", "*") // would be a 304 after the credit was taken
			case "if-match-fails":
				req.Header.Set("If-Match", `"not-our-etag"`) // would be a 412 after the credit was taken
			case "if-unmodified-since":
				req.Header.Set("If-Unmodified-Since", "Mon, 02 Jan 2006 15:04:05 GMT")
			case "head":
				req.Method = http.MethodHead
			}
			resp, err := f.srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				t.Errorf("read response: %v", readErr)
			}
			if resp.StatusCode != tt.status {
				t.Fatalf("status = %d, want %d; body=%q", resp.StatusCode, tt.status, body)
			}
			var served int
			if len(tt.spans) > 1 {
				typ, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
				if err != nil || typ != "multipart/byteranges" {
					t.Fatalf("multipart content type: %q, %v", typ, err)
				}
				mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
				for _, span := range tt.spans {
					part, err := mr.NextPart()
					if err != nil {
						t.Fatalf("multipart: %v", err)
					}
					data, err := io.ReadAll(part)
					if err != nil {
						t.Fatal(err)
					}
					wantRange := fmt.Sprintf("bytes %d-%d/%d", span[0], span[1]-1, tt.size)
					if got := part.Header.Get("Content-Range"); got != wantRange {
						t.Errorf("part Content-Range = %q, want %q", got, wantRange)
					}
					if !bytes.Equal(data, f.data[span[0]:span[1]]) {
						t.Errorf("part ciphertext differs")
					}
					served += len(data)
				}
				if _, err := mr.NextPart(); err != io.EOF {
					t.Fatalf("unexpected extra multipart data: %v", err)
				}
			} else if len(tt.spans) == 1 {
				span := tt.spans[0]
				if !bytes.Equal(body, f.data[span[0]:span[1]]) {
					t.Errorf("ciphertext = %d bytes, want [%d:%d]", len(body), span[0], span[1])
				}
				served = len(body)
				if tt.status == 206 {
					want := fmt.Sprintf("bytes %d-%d/%d", span[0], span[1]-1, tt.size)
					if got := resp.Header.Get("Content-Range"); got != want {
						t.Errorf("Content-Range = %q, want %q", got, want)
					}
				}
			} // Error response text is not forwarded ciphertext (§13.1).
			f.s.mu.Lock()
			total := f.s.objects[string(f.id)].Total
			f.s.mu.Unlock()
			if served == 0 {
				total = 0 // nothing went out (an error, a HEAD): nothing is billed
			}
			if got := ledger.Balance(f.owner.ID).Used; got != total {
				t.Errorf("owner charged %d for the whole object of %d bytes, served %d ciphertext bytes (wire body %d)", got, total, served, len(body))
			}
			if got := ledger.Balance(f.peer.ID).Used; got != 0 {
				t.Errorf("recipient charged %d", got)
			}
			if got := traffic.IPUsed("127.0.0.1"); got != int64(served) {
				t.Errorf("owner address charged %d, served %d", got, served)
			}
			if err := traffic.Save(); err != nil {
				t.Fatal(err)
			}
			_, counts, err := meter.LoadCounts(traffic.Path)
			if err != nil {
				t.Fatal(err)
			}
			if got := counts["*"]; got != int64(served) {
				t.Errorf("monthly server budget charged %d, served %d", got, served)
			}
		})
	}
}
