package rcdial

import (
	"net"
	"testing"
)

func mustTokenIP(ipStr string) [16]byte {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		panic("bad ip " + ipStr)
	}
	var b [16]byte
	copy(b[:], ip.To16())
	return b
}

func TestParseTokenIPv4Mapped(t *testing.T) {
	// 192.168.61.50, port 18181 (0x46e5), arbitrary rkey/addr/len.
	tok, err := ParseToken("00000000000000000000ffffc0a83d32:4705:1a2b3c4d:0000000000400200:0000000000100000")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if want := mustTokenIP("192.168.61.50"); tok.ListenIP != want {
		t.Errorf("ip = %v, want %v", tok.ListenIP, want)
	}
	if tok.ListenPort != 18181 {
		t.Errorf("port = %d, want 18181", tok.ListenPort)
	}
	if tok.RKey != 0x1a2b3c4d {
		t.Errorf("rkey = %#x", tok.RKey)
	}
	if tok.RemoteAddr != 0x400200 {
		t.Errorf("addr = %#x", tok.RemoteAddr)
	}
	if tok.Length != 1<<20 {
		t.Errorf("length = %d", tok.Length)
	}
	if got, want := tok.ListenAddr(), "192.168.61.50:18181"; got != want {
		t.Errorf("ListenAddr = %q, want %q", got, want)
	}
}

func TestParseTokenNativeV6(t *testing.T) {
	tok, err := ParseToken("fe800000000000000000000000000001:00b5:00000001:0000000000000000:0000000000000100")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if want := mustTokenIP("fe80::1"); tok.ListenIP != want {
		t.Errorf("ip = %v", tok.ListenIP)
	}
	if tok.ListenPort != 181 {
		t.Errorf("port = %d", tok.ListenPort)
	}
	if got, want := tok.ListenAddr(), "[fe80::1]:181"; got != want {
		t.Errorf("ListenAddr = %q, want %q", got, want)
	}
}

func TestParseTokenAcceptsSchemePrefix(t *testing.T) {
	const body = "00000000000000000000ffffc0a83d32:4705:1a2b3c4d:0000000000400200:0000000000100000"
	prefixed, err := ParseToken("AMD:RC:3:" + body)
	if err != nil {
		t.Fatalf("prefixed parse: %v", err)
	}
	bare, err := ParseToken(body)
	if err != nil {
		t.Fatalf("bare parse: %v", err)
	}
	if prefixed != bare {
		t.Errorf("prefixed %#v != bare %#v", prefixed, bare)
	}
}

func TestParseTokenAllZeroIPFails(t *testing.T) {
	// All-zero address means "unknown" on the wire; the gateway has
	// nowhere to dial, so the parser rejects it outright.
	if _, err := ParseToken("00000000000000000000000000000000:4705:1a2b3c4d:0000000000400200:0000000000100000"); err == nil {
		t.Fatal("all-zero ip accepted")
	}
}

func TestParseTokenZeroPortOrLengthFails(t *testing.T) {
	base := "00000000000000000000ffffc0a83d32:%s:1a2b3c4d:0000000000400200:%s"
	if _, err := ParseToken(sprintf2(base, "0000", "0000000000100000")); err == nil {
		t.Error("zero port accepted")
	}
	if _, err := ParseToken(sprintf2(base, "46e5", "0000000000000000")); err == nil {
		t.Error("zero length accepted")
	}
}

func TestParseTokenWidthAndFieldErrors(t *testing.T) {
	cases := []string{
		"",                       // empty
		"46e5:1a2b3c4d",          // too few fields
		"1:2:3:4:5:6",            // too many fields
		"00000000000000000000ffffc0a83d3:4705:1a2b3c4d:0000000000400200:0000000000100000", // ip width 31
		"00000000000000000000ffffc0a83d32:46e:1a2b3c4d:0000000000400200:0000000000100000", // port width 3
		"00000000000000000000ffffc0a83d32:4705:1a2b3c:0000000000400200:0000000000100000",  // rkey width 7
		"00000000000000000000ffffc0a83d32:4705:1a2b3c4d:000000000400200:0000000000100000", // addr width 15
		"00000000000000000000ffffc0a83d32:4705:1a2b3c4d:0000000000400200:000000000010000", // length width 15
		"00000000000000000000ffffc0a83d32:4705:1a2b3c4d:0000000000400200:000000000010000x", // non-hex
		"00000000000000000000zzffc0a83d32:4705:1a2b3c4d:0000000000400200:0000000000100000", // non-hex ip
	}
	for i, c := range cases {
		if _, err := ParseToken(c); err == nil {
			t.Errorf("case %d accepted: %q", i, c)
		}
	}
}

func TestParseTokenUppercaseHexAccepted(t *testing.T) {
	if _, err := ParseToken("00000000000000000000FFFFC0A83D32:46E5:1A2B3C4D:0000000000400200:0000000000100000"); err != nil {
		t.Fatalf("uppercase parse: %v", err)
	}
}

func TestTokenFormatRoundTrip(t *testing.T) {
	tok := Token{
		ListenIP:   mustTokenIP("10.0.0.7"),
		ListenPort: 18181,
		RKey:       0xdeadbeef,
		RemoteAddr: 0x1234,
		Length:     4096,
	}
	back, err := ParseToken(FormatToken(tok))
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if back != tok {
		t.Errorf("round trip = %#v, want %#v", back, tok)
	}
}

func TestReplyFormatParse(t *testing.T) {
	s := FormatReply(206, 8192)
	if s != "206:0000000000002000" {
		t.Fatalf("format = %q", s)
	}
	r, err := ParseReply(s)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.Status != 206 || r.Bytes != 8192 {
		t.Errorf("reply = %+v", r)
	}
	if _, err := ParseReply("99:0000000000002000"); err == nil {
		t.Error("status below 100 accepted")
	}
	if _, err := ParseReply("200:2000"); err == nil {
		t.Error("short byte field accepted")
	}
}

// sprintf2 is a tiny helper keeping the test file free of fmt for
// the table above.
func sprintf2(format, a, b string) string {
	out := make([]byte, 0, len(format))
	ai, bi := 0, 0
	for i := 0; i < len(format); i++ {
		switch {
		case format[i] == '%' && i+1 < len(format) && format[i+1] == 's' && ai == 0:
			out = append(out, a...)
			ai = 1
			i++
		case format[i] == '%' && i+1 < len(format) && format[i+1] == 's':
			out = append(out, b...)
			bi = 1
			i++
		default:
			out = append(out, format[i])
		}
	}
	_ = bi
	return string(out)
}
