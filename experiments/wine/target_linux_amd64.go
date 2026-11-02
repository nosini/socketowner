package wine

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Target retains the original pidfd and executable, rather than reopening an
// arbitrary process with the same numeric PID later.
type Target struct {
	PID     int
	Profile Profile
	pidfd   int
	exe     *os.File
	config  targetConfig
}

type targetConfig struct {
	CurrentAddress uint64
	ExeInode       uint64
	KernelExe      uint64
	NetNS          uint64
	ThreadProcess  uint32
	ProcessID      uint32
	ProcessUnixPID uint32
	ProcessStart   uint32
	ProcessImgLen  uint32
	ProcessImage   uint32
	Active         uint32
	Sends          uint32
}

func (t *Target) Close() {
	if t.exe != nil {
		t.exe.Close()
		t.exe = nil
	}
	if t.pidfd >= 0 {
		unix.Close(t.pidfd)
		t.pidfd = -1
	}
}

func (t *Target) alive() (bool, error) {
	if t.pidfd < 0 {
		return false, errors.New("target closed")
	}
	fds := []unix.PollFd{{Fd: int32(t.pidfd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, 0)
	if err == unix.EINTR {
		return true, nil
	}
	return n == 0, err
}

func Prepare(pid int, profile Profile) (_ *Target, err error) {
	if pid <= 0 {
		return nil, errors.New("a positive wineserver process ID is required")
	}
	if err := profile.Validate(); err != nil {
		return nil, err
	}
	t := &Target{PID: pid, Profile: profile, pidfd: -1}
	defer func() {
		if err != nil {
			t.Close()
		}
	}()
	t.pidfd, err = unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, fmt.Errorf("open wineserver pidfd: %w", err)
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, err
	}
	if !strings.Contains("\n"+string(status), fmt.Sprintf("\nTgid:\t%d\n", pid)) {
		return nil, errors.New("select the wineserver thread-group leader")
	}
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil || len(tasks) != 1 {
		return nil, errors.New("this profile requires a single-threaded wineserver")
	}
	// /proc/PID/exe is intentionally followed: it identifies the running file
	// even in a different mount namespace. Its pathname is not trusted.
	t.exe, err = os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return nil, err
	}
	before, err := t.exe.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return nil, errors.New("target executable must be a regular file")
	}
	digest, err := fileDigest(t.exe)
	if err != nil || digest != profile.SHA256 {
		return nil, errors.New("target wineserver does not match the profile SHA-256")
	}
	e, err := elf.NewFile(t.exe)
	if err != nil {
		return nil, err
	}
	if e.Class != elf.ELFCLASS64 || e.Machine != elf.EM_X86_64 || e.Data != elf.ELFDATA2LSB || e.Type.String() != "ET_"+profile.ELFType || !writableSymbol(e, profile.CurrentSymbol) {
		return nil, errors.New("target ELF layout does not match the profile")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(t.exe.Fd()), &stat); err != nil {
		return nil, err
	}
	major, minor := unix.Major(stat.Dev), unix.Minor(stat.Dev)
	if major >= 1<<12 || minor >= 1<<20 {
		return nil, errors.New("unsupported target device encoding")
	}
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	address, err := currentAddress(e, profile.CurrentSymbol, string(maps), major, minor, stat.Ino)
	if err != nil {
		return nil, err
	}
	after, err := t.exe.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("target executable changed during preparation")
	}
	o := profile.Offsets
	t.config = targetConfig{
		CurrentAddress: address, ExeInode: stat.Ino,
		ThreadProcess: o.ThreadProcess, ProcessID: o.ProcessID, ProcessUnixPID: o.ProcessUnixPID,
		ProcessStart: o.ProcessStartTime, ProcessImgLen: o.ProcessImageLen, ProcessImage: o.ProcessImage,
		Active: 1,
	}
	if err := t.recheck(); err != nil {
		return nil, err
	}
	return t, nil
}

// recheck brackets registration. The BPF hooks also verify mm->exe_file for
// every new capture, and an exec hook revokes registration before new code runs.
func (t *Target) recheck() error {
	alive, err := t.alive()
	if err != nil || !alive {
		return errors.New("target exited during registration")
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", t.PID))
	if err != nil {
		return err
	}
	defer f.Close()
	a, err := f.Stat()
	if err != nil {
		return err
	}
	b, err := t.exe.Stat()
	if err != nil || !os.SameFile(a, b) {
		return errors.New("target executable changed during registration")
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(t.exe.Fd()), &st); err != nil {
		return err
	}
	e, err := elf.NewFile(t.exe)
	if err != nil {
		return err
	}
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", t.PID))
	if err != nil {
		return err
	}
	address, err := currentAddress(e, t.Profile.CurrentSymbol, string(maps), unix.Major(st.Dev), unix.Minor(st.Dev), st.Ino)
	if err != nil || address != t.config.CurrentAddress {
		return errors.New("target executable mappings changed during registration")
	}
	return nil
}

type mapping struct {
	start, end, offset uint64
	major, minor       uint32
	inode              uint64
	perms              string
}

func parseMaps(data string) ([]mapping, error) {
	var result []mapping
	s := bufio.NewScanner(strings.NewReader(data))
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) < 5 || len(f[1]) != 4 {
			return nil, errors.New("invalid process mapping")
		}
		lo, hi, ok := strings.Cut(f[0], "-")
		maj, min, devOK := strings.Cut(f[3], ":")
		if !ok || !devOK {
			return nil, errors.New("invalid mapping address or device")
		}
		parts := []string{lo, hi, f[2], maj, min, f[4]}
		var n [6]uint64
		for i, part := range parts {
			base := 16
			if i == 5 {
				base = 10
			}
			var err error
			n[i], err = strconv.ParseUint(part, base, 64)
			if err != nil {
				return nil, err
			}
		}
		if n[0] >= n[1] || n[3] > 0xffffffff || n[4] > 0xffffffff {
			return nil, errors.New("invalid mapping range")
		}
		result = append(result, mapping{n[0], n[1], n[2], uint32(n[3]), uint32(n[4]), n[5], f[1]})
	}
	return result, s.Err()
}

func currentAddress(e *elf.File, symbol uint64, text string, major, minor uint32, inode uint64) (uint64, error) {
	maps, err := parseMaps(text)
	if err != nil {
		return 0, err
	}
	page := uint64(os.Getpagesize())
	var bias uint64
	found := false
	for _, p := range e.Progs {
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == 0 {
			continue
		}
		va, off := p.Vaddr&^(page-1), p.Off&^(page-1)
		for _, m := range maps {
			if m.major != major || m.minor != minor || m.inode != inode || m.offset != off || m.perms[2] != 'x' || m.start < va {
				continue
			}
			candidate := m.start - va
			if found && candidate != bias {
				return 0, errors.New("ambiguous executable mapping/load bias")
			}
			bias, found = candidate, true
		}
	}
	if !found || e.Type == elf.ET_EXEC && bias != 0 || symbol >= 1<<47 || bias >= 1<<47-symbol {
		return 0, errors.New("target executable mapping does not match profile")
	}
	address := bias + symbol
	for _, m := range maps {
		// BSS may live in an adjacent anonymous mapping. The ELF writable load
		// segment was independently checked; require the runtime address readable.
		if m.end-m.start >= 8 && address >= m.start && address <= m.end-8 && m.perms[0] == 'r' && m.perms[1] == 'w' && (m.inode == 0 || m.inode == inode && m.major == major && m.minor == minor) {
			return address, nil
		}
	}
	return 0, errors.New("current symbol is not mapped read/write")
}
