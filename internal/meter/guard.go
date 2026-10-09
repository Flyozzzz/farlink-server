package meter

// Guard refuses every metered operation of a blocked device (one whose account was deleted), whatever the quotas are:
// a relay session, a TURN allocation or a download that is already running stops at its next charge.
type Guard struct {
	Meter
	Blocked func(device []byte) bool
}

func (g Guard) Admit(device []byte, ip string) bool {
	return !g.Blocked(device) && g.Meter.Admit(device, ip)
}

func (g Guard) Charge(device []byte, ip string, n int64) bool {
	return !g.Blocked(device) && g.Meter.Charge(device, ip, n)
}

func (g Guard) ChargeAccount(device []byte, id string, n int64) bool {
	return !g.Blocked(device) && g.Meter.ChargeAccount(device, id, n)
}

func (g Guard) ChargeTransit(device []byte, ip string, n int64) bool {
	return !g.Blocked(device) && g.Meter.ChargeTransit(device, ip, n)
}

// BillingUnavailable passes on to the meter underneath.
func (g Guard) BillingUnavailable(device []byte) bool { return BillingUnavailable(g.Meter, device) }
