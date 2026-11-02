// Package wine is an opt-in, diagnostic observer of Windows socket creators in
// an unchanged Wine server. It does not publish a routing authority or change
// socketowner's native process ABI.
package wine

import (
	"bytes"
	"crypto/sha256"
	"debug/dwarf"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const ProfileVersion = 1

type Offsets struct {
	ThreadProcess    uint32 `json:"thread_process"`
	ProcessID        uint32 `json:"process_id"`
	ProcessUnixPID   uint32 `json:"process_unix_pid"`
	ProcessStartTime uint32 `json:"process_start_time"`
	ProcessImageLen  uint32 `json:"process_image_length"`
	ProcessImage     uint32 `json:"process_image"`
}

// Profile is an explicit, trusted layout description for one exact ELF file.
// A matching version string alone never admits a binary.
type Profile struct {
	Version       uint32  `json:"version"`
	ID            string  `json:"id"`
	SHA256        string  `json:"sha256"`
	Architecture  string  `json:"architecture"`
	ELFType       string  `json:"elf_type"`
	CurrentSymbol uint64  `json:"current_symbol"`
	Offsets       Offsets `json:"offsets"`
}

func ReadProfile(r io.Reader) (Profile, error) {
	var p Profile
	data, err := io.ReadAll(io.LimitReader(r, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return p, errors.New("profile exceeds size limit or could not be read")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, fmt.Errorf("profile: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return p, errors.New("profile: expected exactly one JSON document")
	}
	return p, p.Validate()
}

func (p Profile) Validate() error {
	if p.Version != ProfileVersion || p.Architecture != "amd64" || (p.ELFType != "EXEC" && p.ELFType != "DYN") {
		return errors.New("unsupported Wine profile version, architecture or ELF type")
	}
	h, err := hex.DecodeString(p.SHA256)
	if err != nil || len(h) != sha256.Size || hex.EncodeToString(h) != p.SHA256 {
		return errors.New("profile requires a lowercase SHA-256 digest")
	}
	if p.ID == "" || len(p.ID) > 128 || p.CurrentSymbol == 0 || p.CurrentSymbol >= 1<<47 {
		return errors.New("profile has invalid ID or current symbol address")
	}
	o := p.Offsets
	fields := []struct{ off, size uint32 }{
		{o.ProcessID, 4}, {o.ProcessUnixPID, 4}, {o.ProcessStartTime, 8},
		{o.ProcessImageLen, 4}, {o.ProcessImage, 8},
	}
	if o.ThreadProcess == 0 || o.ThreadProcess > 65528 || o.ThreadProcess%8 != 0 {
		return errors.New("invalid thread.process offset")
	}
	for i, f := range fields {
		if f.off == 0 || f.off > 65536-f.size || f.off%f.size != 0 {
			return errors.New("invalid Wine process field offset")
		}
		for _, other := range fields[:i] {
			if f.off < other.off+other.size && other.off < f.off+f.size {
				return errors.New("overlapping Wine process fields")
			}
		}
	}
	return nil
}

func fileDigest(f *os.File) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, 1<<63-1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// GenerateProfile extracts types and symbols from the exact file being hashed.
// It is preparation, not registration: the operator must trust this Wine build.
// Stripped binaries require a separately reviewed matching profile.
func GenerateProfile(f *os.File) (Profile, error) {
	var p Profile
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return p, errors.New("profile input must be a regular ELF file")
	}
	e, err := elf.NewFile(f)
	if err != nil {
		return p, err
	}
	if e.Class != elf.ELFCLASS64 || e.Machine != elf.EM_X86_64 || e.Data != elf.ELFDATA2LSB || (e.Type != elf.ET_EXEC && e.Type != elf.ET_DYN) {
		return p, errors.New("only little-endian amd64 Wine server ELF files are supported")
	}
	symbols, err := e.Symbols()
	if err != nil {
		return p, fmt.Errorf("matching Wine symbols required: %w", err)
	}
	for _, s := range symbols {
		if s.Name == "current" && s.Size == 8 && elf.ST_TYPE(s.Info) == elf.STT_OBJECT && s.Section != elf.SHN_UNDEF {
			if p.CurrentSymbol != 0 {
				return p, errors.New("ambiguous current symbol")
			}
			p.CurrentSymbol = s.Value
		}
	}
	if p.CurrentSymbol == 0 || !writableSymbol(e, p.CurrentSymbol) {
		return p, errors.New("current must be an 8-byte object in a writable ELF load segment")
	}
	d, err := e.DWARF()
	if err != nil {
		return p, fmt.Errorf("matching Wine DWARF required: %w", err)
	}
	want := map[string]map[string]int64{
		"thread":  {"process": 8},
		"process": {"id": 4, "unix_pid": 4, "start_time": 8, "imagelen": 4, "image": 8},
	}
	found := make(map[string]map[string]uint32)
	r := d.Reader()
	for {
		entry, err := r.Next()
		if err != nil {
			return p, err
		}
		if entry == nil {
			break
		}
		name, _ := entry.Val(dwarf.AttrName).(string)
		fields, needed := want[name]
		if entry.Tag != dwarf.TagStructType || !needed || entry.Val(dwarf.AttrDeclaration) == true {
			continue
		}
		t, err := d.Type(entry.Offset)
		if err != nil {
			return p, err
		}
		st, ok := t.(*dwarf.StructType)
		if !ok {
			continue
		}
		layout := make(map[string]uint32)
		for _, f := range st.Field {
			if size, ok := fields[f.Name]; ok {
				if f.ByteOffset <= 0 || f.ByteOffset > 65528 || f.BitSize != 0 || f.Type.Size() != size {
					return p, fmt.Errorf("unsupported %s.%s type/layout", name, f.Name)
				}
				layout[f.Name] = uint32(f.ByteOffset)
			}
		}
		if len(layout) != len(fields) {
			continue
		}
		if previous, ok := found[name]; ok {
			for field, off := range layout {
				if previous[field] != off {
					return p, fmt.Errorf("ambiguous DWARF layout for %s", name)
				}
			}
		}
		found[name] = layout
	}
	if len(found) != len(want) {
		return p, errors.New("DWARF lacks complete Wine thread/process types")
	}
	p.Offsets = Offsets{
		ThreadProcess: found["thread"]["process"], ProcessID: found["process"]["id"],
		ProcessUnixPID: found["process"]["unix_pid"], ProcessStartTime: found["process"]["start_time"],
		ProcessImageLen: found["process"]["imagelen"], ProcessImage: found["process"]["image"],
	}
	p.SHA256, err = fileDigest(f)
	if err != nil {
		return p, err
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return p, errors.New("Wine file changed during profile generation")
	}
	p.Version, p.Architecture, p.ELFType = ProfileVersion, "amd64", e.Type.String()[3:]
	p.ID = "wineserver-" + p.SHA256[:16]
	return p, p.Validate()
}

func writableSymbol(e *elf.File, address uint64) bool {
	for _, p := range e.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_W != 0 && address >= p.Vaddr && address-p.Vaddr <= p.Memsz && p.Memsz-(address-p.Vaddr) >= 8 {
			return true
		}
	}
	return false
}
