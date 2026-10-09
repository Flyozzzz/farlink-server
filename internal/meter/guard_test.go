package meter

import "testing"

func TestAGuardRefusesABlockedDeviceEverywhereAndLeavesOthersAlone(t *testing.T) {
	gone, fine := []byte("gone"), []byte("fine")
	g := Guard{Meter: Off{}, Blocked: func(d []byte) bool { return string(d) == "gone" }}
	if g.Admit(gone, "ip") || g.Charge(gone, "ip", 1) || g.ChargeAccount(gone, "id", 1) || g.ChargeTransit(gone, "ip", 1) {
		t.Fatal("a blocked device was served")
	}
	if !g.Admit(fine, "ip") || !g.Charge(fine, "ip", 1) || !g.ChargeAccount(fine, "id", 1) || !g.ChargeTransit(fine, "ip", 1) {
		t.Fatal("another device was refused")
	}
}
