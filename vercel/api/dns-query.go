// Minimal DoH gateway for Vercel (Go).
//   - forwards to $UPSTREAM (blocklist lives there)
//   - injects ECS from the client's real IP (/24 v4, /48 v6)
//   - custom CDN redirects (source -> target) for A/AAAA
//   - DDR: answers SVCB for _dns.resolver.arpa and _dns.<this host>
package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	maxQuery        = 512
	upstreamTimeout = 4 * time.Second
	ecsEnabled      = true
)

// "source" -> "target": source resolves to target's A/AAAA answers
var redirects = map[string]string{
	"www.bilibili.tv": "www.bilibili.tv.w.cdngslb.com",
}

var httpClient = &http.Client{Timeout: upstreamTimeout}

func Handler(w http.ResponseWriter, r *http.Request) {
	upstream := os.Getenv("UPSTREAM")
	if upstream == "" {
		http.Error(w, "UPSTREAM not configured", http.StatusInternalServerError)
		return
	}

	wire, status := readQuery(r)
	if status != 0 {
		if status == http.StatusMethodNotAllowed {
			w.Header().Set("Allow", "GET, POST")
		}
		http.Error(w, http.StatusText(status), status)
		return
	}

	var p dnsmessage.Parser
	hdr, err := p.Start(wire)
	if err != nil || hdr.Response {
		http.Error(w, "bad dns message", http.StatusBadRequest)
		return
	}
	q, err := p.Question()
	if err != nil {
		http.Error(w, "bad dns message", http.StatusBadRequest)
		return
	}

	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	host := r.Host
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}

	// DDR
	if q.Type == 64 && (name == "_dns.resolver.arpa" || name == "_dns."+strings.ToLower(host)) {
		reply(w, respond(hdr.ID, q, dnsmessage.RCodeSuccess, ddrAnswer(q, host)), 300)
		return
	}

	target, redirected := redirects[name]
	// HTTPS/SVCB hints would leak the original IPs -> NODATA
	if redirected && (q.Type == 64 || q.Type == 65) {
		reply(w, respond(hdr.ID, q, dnsmessage.RCodeSuccess, nil), 60)
		return
	}

	ecs := ecsOption(clientIP(r))
	ctx := r.Context()

	if redirected && (q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeAAAA) {
		tn, _ := dnsmessage.NewName(target + ".")
		resp, err := forward(ctx, upstream, buildQuery(dnsmessage.Question{Name: tn, Type: q.Type, Class: q.Class}, ecs))
		if err != nil {
			servfail(w, hdr.ID, q)
			return
		}
		var m dnsmessage.Message
		if m.Unpack(resp) != nil {
			servfail(w, hdr.ID, q)
			return
		}
		var rrs []dnsmessage.Resource
		for _, a := range m.Answers {
			if a.Header.Type == dnsmessage.TypeA || a.Header.Type == dnsmessage.TypeAAAA {
				a.Header.Name = q.Name
				rrs = append(rrs, a)
			}
		}
		reply(w, respond(hdr.ID, q, m.RCode, rrs), minTTL(m.Answers))
		return
	}

	resp, err := forward(ctx, upstream, buildQuery(q, ecs))
	if err != nil {
		servfail(w, hdr.ID, q)
		return
	}
	var m dnsmessage.Message
	ttl := uint32(30)
	if m.Unpack(resp) == nil {
		ttl = minTTL(m.Answers)
	}
	resp[0], resp[1] = byte(hdr.ID>>8), byte(hdr.ID)
	reply(w, resp, ttl)
}

// ---------- request / response helpers ----------

func readQuery(r *http.Request) ([]byte, int) {
	switch r.Method {
	case http.MethodPost:
		b, err := io.ReadAll(io.LimitReader(r.Body, maxQuery+1))
		if err != nil {
			return nil, http.StatusBadRequest
		}
		if len(b) > maxQuery {
			return nil, http.StatusRequestEntityTooLarge
		}
		return b, 0
	case http.MethodGet:
		s := r.URL.Query().Get("dns")
		if s == "" {
			return nil, http.StatusMethodNotAllowed
		}
		if len(s) > maxQuery*2 {
			return nil, http.StatusRequestEntityTooLarge
		}
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
		if err != nil {
			return nil, http.StatusBadRequest
		}
		return b, 0
	}
	return nil, http.StatusMethodNotAllowed
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return strings.TrimSpace(strings.Split(v, ",")[0])
	}
	return ""
}

func reply(w http.ResponseWriter, body []byte, ttl uint32) {
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "private, max-age="+strconv.FormatUint(uint64(ttl), 10))
	w.Write(body)
}

func servfail(w http.ResponseWriter, id uint16, q dnsmessage.Question) {
	reply(w, respond(id, q, dnsmessage.RCodeServerFailure, nil), 5)
}

func respond(id uint16, q dnsmessage.Question, rcode dnsmessage.RCode, rrs []dnsmessage.Resource) []byte {
	m := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, Response: true, RecursionDesired: true,
			RecursionAvailable: true, RCode: rcode},
		Questions: []dnsmessage.Question{q},
		Answers:   rrs,
	}
	b, _ := m.Pack()
	return b
}

func minTTL(rrs []dnsmessage.Resource) uint32 {
	if len(rrs) == 0 {
		return 30
	}
	t := uint32(3600)
	for _, r := range rrs {
		if r.Header.TTL < t {
			t = r.Header.TTL
		}
	}
	return t
}

func ddrAnswer(q dnsmessage.Question, host string) []dnsmessage.Resource {
	hn, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil
	}
	path := "/dns-query{?dns}"
	// SvcPriority=1, TargetName, alpn=h2,h3 (key 1), dohpath (key 7); keys ascending
	rd := []byte{0, 1}
	rd = append(rd, wireName(hn.String())...)
	rd = append(rd, 0, 1, 0, 6, 2, 'h', '2', 2, 'h', '3')
	rd = append(rd, 0, 7, byte(len(path)>>8), byte(len(path)))
	rd = append(rd, path...)
	return []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: q.Name, Type: 64, Class: dnsmessage.ClassINET, TTL: 300},
		Body:   &dnsmessage.UnknownResource{Type: 64, Data: rd},
	}}
}

func wireName(n string) []byte {
	var out []byte
	for _, l := range strings.Split(strings.TrimSuffix(n, "."), ".") {
		if l == "" {
			continue
		}
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	return append(out, 0)
}

// ---------- upstream ----------

// returns the ECS EDNS option, or nil when the IP is invalid
func ecsOption(ip string) *dnsmessage.Option {
	if !ecsEnabled || ip == "" {
		return nil
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	a = a.Unmap() // IPv4-mapped IPv6
	var family byte
	var prefix int
	if a.Is4() {
		family, prefix = 1, 24
	} else {
		family, prefix = 2, 48
	}
	p, err := a.Prefix(prefix)
	if err != nil {
		return nil
	}
	raw := p.Addr().AsSlice()[:prefix/8]
	data := append([]byte{0, family, byte(prefix), 0}, raw...)
	return &dnsmessage.Option{Code: 8, Data: data}
}

func buildQuery(q dnsmessage.Question, ecs *dnsmessage.Option) []byte {
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{q},
	}
	var rh dnsmessage.ResourceHeader
	rh.SetEDNS0(4096, dnsmessage.RCodeSuccess, false)
	opt := &dnsmessage.OPTResource{}
	if ecs != nil {
		opt.Options = []dnsmessage.Option{*ecs}
	}
	m.Additionals = []dnsmessage.Resource{{Header: rh, Body: opt}}
	b, _ := m.Pack()
	return b
}

func forward(ctx context.Context, upstream string, wire []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstream, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, http.ErrAbortHandler
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil || len(b) < 12 {
		return nil, http.ErrAbortHandler
	}
	return b, nil
}
