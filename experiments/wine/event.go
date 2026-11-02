package wine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf16"
)

const imageBytes = 1024

type rawOwner struct {
	SocketID, ServerStartNS, WindowsStartTime, CapturedBootNS uint64
	ServerTGID, UID, WindowsPID, ClientUnixPID                uint32
	Status, ImageBytes, Protocol, Pad                         uint32
	Image                                                     [imageBytes / 2]uint16
}

type rawFlow struct {
	NetNS                             uint64
	Source, Destination               [16]byte
	SourcePort, DestinationPort       uint16
	Family, Protocol, Valid, TCPFlags uint8
}

type rawEvent struct {
	Kind, ActorTGID uint32
	Flow            rawFlow
	Owner           rawOwner
}

// Event is diagnostic output, not a stable reader contract; routing reads the
// pinned wine_flows map instead. The creator name is
// never reassigned to the latest sender. A send/connect event describes an
// attempted operation, not its successful completion.
type Event struct {
	Type             string `json:"type"`
	Observer         string `json:"observer,omitempty"`
	Profile          string `json:"profile,omitempty"`
	SocketID         uint64 `json:"socket_id,omitempty"`
	Status           string `json:"status,omitempty"`
	ServerTGID       uint32 `json:"server_tgid,omitempty"`
	ServerStartNS    uint64 `json:"server_start_ns,omitempty"`
	ActorTGID        uint32 `json:"actor_tgid,omitempty"`
	UID              uint32 `json:"uid"`
	WindowsPID       uint32 `json:"windows_pid,omitempty"`
	WindowsStartTime uint64 `json:"windows_start_time,omitempty"`
	ClientUnixPID    uint32 `json:"client_unix_pid,omitempty"`
	WindowsImage     string `json:"windows_image,omitempty"`
	WindowsName      string `json:"windows_name,omitempty"`
	CapturedBootNS   uint64 `json:"captured_boot_ns,omitempty"`
	Network          string `json:"network,omitempty"`
	NetNS            uint64 `json:"netns_cookie,omitempty"`
	Source           string `json:"source,omitempty"`
	Destination      string `json:"destination,omitempty"`
	TCPFlags         uint8  `json:"tcp_flags,omitempty"`
	LostEvents       uint64 `json:"lost_events,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

func decodeEvent(data []byte) (Event, error) {
	var r rawEvent
	var e Event
	if len(data) != binary.Size(r) {
		return e, errors.New("unexpected Wine diagnostic event size")
	}
	if err := binary.Read(bytes.NewReader(data), binary.NativeEndian, &r); err != nil {
		return e, err
	}
	name := map[uint32]string{1: "connect", 2: "send", 3: "create", 4: "first-egress", 5: "relay"}[r.Kind]
	if name == "" || r.Owner.SocketID == 0 || r.Owner.ServerTGID == 0 || r.Owner.ServerStartNS == 0 {
		return e, errors.New("invalid Wine diagnostic record")
	}
	o := &r.Owner
	e = Event{Type: name, SocketID: o.SocketID, ActorTGID: r.ActorTGID, ServerTGID: o.ServerTGID,
		ServerStartNS: o.ServerStartNS, UID: o.UID, CapturedBootNS: o.CapturedBootNS}
	switch o.Protocol {
	case 6:
		e.Network = "tcp"
	case 17:
		e.Network = "udp"
	default:
		return e, errors.New("invalid Wine socket protocol")
	}
	e.Status = map[uint32]string{1: "known", 2: "unreadable-request", 3: "invalid-image", 4: "changed-request", 5: "invalid-process",
		6: "ambiguous-relay", 7: "no-inner-flow", 8: "not-wine"}[o.Status]
	if e.Status == "" {
		return e, errors.New("invalid Wine capture status")
	}
	if o.Status == 1 {
		image, basename, err := windowsImage(o.Image[:], o.ImageBytes)
		if err != nil {
			e.Status = "invalid-image"
		} else if o.WindowsPID == 0 || o.ClientUnixPID == 0 || o.WindowsStartTime == 0 {
			e.Status = "invalid-process"
		} else {
			e.WindowsImage, e.WindowsName = image, basename
			e.WindowsPID, e.WindowsStartTime, e.ClientUnixPID = o.WindowsPID, o.WindowsStartTime, o.ClientUnixPID
		}
	}
	if r.Kind == 4 {
		f := &r.Flow
		if f.Valid != 1 || f.NetNS == 0 || f.Protocol != uint8(o.Protocol) || (f.Family != 4 && f.Family != 6) {
			return e, errors.New("invalid Wine egress tuple")
		}
		src, dst := netip.AddrFrom16(f.Source), netip.AddrFrom16(f.Destination)
		if f.Family == 4 {
			if !src.Is4In6() || !dst.Is4In6() {
				return e, errors.New("invalid IPv4-mapped egress address")
			}
			src, dst = src.Unmap(), dst.Unmap()
		}
		e.NetNS, e.TCPFlags = f.NetNS, f.TCPFlags
		e.Source, e.Destination = netip.AddrPortFrom(src, f.SourcePort).String(), netip.AddrPortFrom(dst, f.DestinationPort).String()
	}
	return e, nil
}

// Windows paths use backslashes even when the observer runs on Linux. Reject
// incomplete UTF-16 and partial/relative names instead of manufacturing a name.
func windowsImage(data []uint16, size uint32) (string, string, error) {
	if size == 0 || size%2 != 0 || size > imageBytes || int(size/2) > len(data) {
		return "", "", errors.New("invalid Windows image length")
	}
	w := data[:size/2]
	for i := 0; i < len(w); i++ {
		c := w[i]
		if c == 0 {
			return "", "", errors.New("embedded NUL in Windows image")
		}
		if c >= 0xd800 && c <= 0xdbff {
			if i+1 == len(w) || w[i+1] < 0xdc00 || w[i+1] > 0xdfff {
				return "", "", errors.New("incomplete UTF-16 surrogate")
			}
			i++
		} else if c >= 0xdc00 && c <= 0xdfff {
			return "", "", errors.New("unpaired UTF-16 surrogate")
		}
	}
	s := strings.ReplaceAll(string(utf16.Decode(w)), "/", `\`)
	s = strings.TrimPrefix(strings.TrimPrefix(s, `\??\`), `\\?\`)
	if strings.HasPrefix(s, `UNC\`) {
		s = `\\` + s[4:]
	}
	drive := len(s) >= 3 && (s[0] >= 'A' && s[0] <= 'Z' || s[0] >= 'a' && s[0] <= 'z') && s[1:3] == `:\`
	unc := false
	if strings.HasPrefix(s, `\\`) {
		parts := strings.Split(s[2:], `\`)
		unc = len(parts) >= 3 && parts[0] != "" && parts[1] != ""
	}
	if !drive && !unc {
		return "", "", errors.New("Windows image is not an absolute drive/UNC path")
	}
	i := strings.LastIndexByte(s, '\\')
	base := s[i+1:]
	if base == "" || base == "." || base == ".." {
		return "", "", fmt.Errorf("invalid Windows image basename %q", base)
	}
	return s, base, nil
}
