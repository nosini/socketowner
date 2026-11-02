package wine

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestWindowsImage(t *testing.T) {
	for _, tc := range []struct{ input, path, name string }{
		{`\??\C:\Program Files\Browser\tbs_browser.exe`, `C:\Program Files\Browser\tbs_browser.exe`, `tbs_browser.exe`},
		{`\\?\C:\ゲーム\app.exe`, `C:\ゲーム\app.exe`, `app.exe`},
		{`\??\UNC\server\share\app.exe`, `\\server\share\app.exe`, `app.exe`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := utf16.Encode([]rune(tc.input))
			p, n, err := windowsImage(w, uint32(len(w)*2))
			if err != nil || p != tc.path || n != tc.name {
				t.Fatalf("%q %q %v", p, n, err)
			}
		})
	}
	for _, s := range []string{"app.exe", `C:app.exe`, `C:\`, "C:\\a\x00b.exe"} {
		w := utf16.Encode([]rune(s))
		if _, _, err := windowsImage(w, uint32(len(w)*2)); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	for _, w := range [][]uint16{{'C', ':', '\\', 0xd800}, {'C', ':', '\\', 0xdc00}, {'C', ':', '\\', 'a', 0}} {
		if _, _, err := windowsImage(w, uint32(len(w)*2)); err == nil {
			t.Fatal("accepted invalid UTF-16")
		}
	}
	if _, _, err := windowsImage(make([]uint16, 1024), 2048); err == nil {
		t.Fatal("accepted oversized image")
	}
}

func TestUnknownDoesNotLeakPartialIdentity(t *testing.T) {
	for _, status := range []uint32{1, 2, 3, 4, 5} {
		r := rawEvent{Kind: 3, ActorTGID: 44, Owner: rawOwner{SocketID: 1, ServerTGID: 44, ServerStartNS: 42, Status: status, Protocol: 6, WindowsPID: 123, ClientUnixPID: 45, WindowsStartTime: 90, ImageBytes: 5}}
		copy(r.Owner.Image[:], utf16.Encode([]rune(`C:\partial.exe`)))
		var b bytes.Buffer
		if err := binary.Write(&b, binary.NativeEndian, r); err != nil {
			t.Fatal(err)
		}
		e, err := decodeEvent(b.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if e.WindowsImage != "" || e.WindowsName != "" || e.WindowsPID != 0 || e.Status == "known" {
			t.Fatalf("partial identity escaped: %+v", e)
		}
	}
	if _, err := decodeEvent([]byte("short")); err == nil {
		t.Fatal("accepted truncated event")
	}
}

func TestDecodeEgress(t *testing.T) {
	r := rawEvent{Kind: 4, ActorTGID: 44, Owner: rawOwner{SocketID: 1, ServerTGID: 44, ServerStartNS: 42, Status: 1, Protocol: 6, WindowsPID: 123, ClientUnixPID: 45, WindowsStartTime: 90}}
	w := utf16.Encode([]rune(`\??\C:\games\alpha.exe`))
	copy(r.Owner.Image[:], w)
	r.Owner.ImageBytes = uint32(len(w) * 2)
	r.Flow = rawFlow{NetNS: 99, SourcePort: 40000, DestinationPort: 443, Family: 4, Protocol: 6, Valid: 1, TCPFlags: 2}
	r.Flow.Source = [16]byte{10: 255, 11: 255, 12: 127, 15: 1}
	r.Flow.Destination = [16]byte{10: 255, 11: 255, 12: 1, 13: 1, 14: 1, 15: 1}
	var b bytes.Buffer
	binary.Write(&b, binary.NativeEndian, r)
	e, err := decodeEvent(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != "known" || e.WindowsName != "alpha.exe" || e.Source != "127.0.0.1:40000" || e.Destination != "1.1.1.1:443" || e.TCPFlags != 2 {
		t.Fatalf("bad egress decode: %+v", e)
	}
	r.Flow.Valid = 0
	b.Reset()
	binary.Write(&b, binary.NativeEndian, r)
	if _, err := decodeEvent(b.Bytes()); err == nil {
		t.Fatal("accepted invalid tuple")
	}
	if !strings.HasSuffix(e.WindowsImage, `\alpha.exe`) {
		t.Fatal(e.WindowsImage)
	}
}
