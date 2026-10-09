// Package budget bounds what clients hold at the same time — open connections, TURN allocations, request bodies
// being read — per device, per client address and in total. These are anti-abuse limits: they stay on when
// traffic quotas are off, because anyone can make a fresh key.
package budget

import "sync"

// Gate counts units held per device, per client address and in total; a zero cap means no cap at that level.
type Gate struct {
	PerDevice, PerIP, Total int64

	mu      sync.Mutex
	devices map[string]int64
	ips     map[string]int64
	total   int64
}

func NewGate(perDevice, perIP, total int64) *Gate {
	return &Gate{PerDevice: perDevice, PerIP: perIP, Total: total}
}

func over(v, max int64) bool { return max > 0 && v > max }

// Fits reports whether n more units would be admitted now, without taking them.
func (g *Gate) Fits(device, ip string, n int64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.fits(device, ip, n)
}

func (g *Gate) fits(device, ip string, n int64) bool {
	return !over(g.devices[device]+n, g.PerDevice) && !over(g.ips[ip]+n, g.PerIP) && !over(g.total+n, g.Total)
}

// Take holds n units for device and ip, or refuses. release gives them back; calling it more than once is safe.
func (g *Gate) Take(device, ip string, n int64) (release func(), ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.fits(device, ip, n) {
		return func() {}, false
	}
	if g.devices == nil {
		g.devices, g.ips = map[string]int64{}, map[string]int64{}
	}
	g.devices[device] += n
	g.ips[ip] += n
	g.total += n
	var once sync.Once
	return func() { once.Do(func() { g.put(device, ip, n) }) }, true
}

func (g *Gate) put(device, ip string, n int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.devices[device] -= n; g.devices[device] <= 0 {
		delete(g.devices, device)
	}
	if g.ips[ip] -= n; g.ips[ip] <= 0 {
		delete(g.ips, ip)
	}
	g.total -= n
}

// Held is what device, ip and everyone hold now (tests, diagnostics).
func (g *Gate) Held(device, ip string) (dev, addr, total int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.devices[device], g.ips[ip], g.total
}
