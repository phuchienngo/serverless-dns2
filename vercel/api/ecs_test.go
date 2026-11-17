package handler

import "testing"

func TestECS(t *testing.T) {
	for ip, want := range map[string]string{
		"171.226.135.226": "\x00\x01\x18\x00\xab\xe2\x87",
		"::ffff:1.2.3.4":  "\x00\x01\x18\x00\x01\x02\x03",
		"2001:db8:1:2::1": "\x00\x02\x30\x00\x20\x01\x0d\xb8\x00\x01",
	} {
		o := ecsOption(ip)
		if o == nil || string(o.Data) != want || o.Code != 8 {
			t.Errorf("%s: %+v", ip, o)
		}
	}
	for _, ip := range []string{"", "bad", "1.2.3"} {
		if ecsOption(ip) != nil {
			t.Errorf("%q should be nil", ip)
		}
	}
}
