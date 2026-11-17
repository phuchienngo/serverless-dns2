package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func ask(t *testing.T, name string, typ dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	n, _ := dnsmessage.NewName(name)
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 0x1234, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: typ, Class: dnsmessage.ClassINET}}}
	b, _ := m.Pack()
	req := httptest.NewRequest(http.MethodPost, "https://dns.example.com/dns-query", bytes.NewReader(b))
	req.Header.Set("X-Real-IP", "171.226.135.226")
	rec := httptest.NewRecorder()
	Handler(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var out dnsmessage.Message
	if err := out.Unpack(rec.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if out.ID != 0x1234 {
		t.Fatalf("id %x", out.ID)
	}
	return out
}

func TestResolve(t *testing.T) {
	if m := ask(t, "example.com.", dnsmessage.TypeA); len(m.Answers) == 0 {
		t.Fatal("no answers")
	}
}
func TestRedirect(t *testing.T) {
	m := ask(t, "www.bilibili.tv.", dnsmessage.TypeA)
	if len(m.Answers) == 0 || m.Answers[0].Header.Name.String() != "www.bilibili.tv." {
		t.Fatalf("%+v", m.Answers)
	}
	if m := ask(t, "www.bilibili.tv.", 65); len(m.Answers) != 0 {
		t.Fatal("HTTPS should be NODATA")
	}
}
func TestDDR(t *testing.T) {
	if m := ask(t, "_dns.resolver.arpa.", 64); len(m.Answers) != 1 {
		t.Fatal("no ddr answer")
	}
}
func TestNX(t *testing.T) {
	if m := ask(t, "nonexist-zzq1.phuchien.invalid.", dnsmessage.TypeA); m.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("rcode %v", m.RCode)
	}
}
