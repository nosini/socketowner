package wine

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fakeFds stands in for the pidfds the relays hold: open hands out increasing
// numbers, and exit ends the process a fd names while the fd itself stays open,
// as when a process exits and its pidfd is still readable.
type fakeFds struct {
	next    int
	opened  map[int]bool
	alive   map[int]bool
	closed  []int
	doubles []int
}

func newFakeFds() *fakeFds {
	return &fakeFds{opened: map[int]bool{}, alive: map[int]bool{}}
}

func (f *fakeFds) open(pid int) (int, error) {
	f.next++
	f.opened[f.next] = true
	f.alive[f.next] = true
	return f.next, nil
}

func (f *fakeFds) exit(fd int) {
	f.alive[fd] = false
}

func (f *fakeFds) isAlive(fd int) bool { return f.alive[fd] }

func (f *fakeFds) isOpen(fd int) bool { return f.opened[fd] }

func (f *fakeFds) close(fd int) {
	if !f.opened[fd] {
		f.doubles = append(f.doubles, fd)
		return
	}
	delete(f.opened, fd)
	f.closed = append(f.closed, fd)
}

// leaked lists the fds still open, so that a test can require none.
func (f *fakeFds) leaked() []int {
	var fds []int
	for fd := range f.opened {
		fds = append(fds, fd)
	}
	slices.Sort(fds)
	return fds
}

// testRelays returns relays over fake pidfds, which the test closes at its end.
func testRelays(t *testing.T, fds *fakeFds, find func(int) ([]pastaProc, error)) *relays {
	t.Helper()
	r := &relays{
		waiting:    map[int]*waitingServer{},
		find:       find,
		registered: func(int, uint64) bool { return true },
		open:       fds.open,
		alive:      fds.isAlive,
		closeFd:    fds.close,
		logf:       func(string, ...any) {},
		reported:   map[string]bool{},
	}
	t.Cleanup(func() {
		r.close()
		if leaked := fds.leaked(); len(leaked) != 0 {
			t.Errorf("fds %v left open", leaked)
		}
		if len(fds.doubles) != 0 {
			t.Errorf("fds %v closed twice", fds.doubles)
		}
	})
	return r
}

func TestScanBacksOffWithoutPasta(t *testing.T) {
	finds := 0
	fds := newFakeFds()
	r := testRelays(t, fds, func(int) ([]pastaProc, error) { finds++; return nil, nil })
	start := time.Now()
	r.add(10, 7, start)
	var due []time.Duration
	for now := start; now.Sub(start) < 2*time.Minute; now = now.Add(100 * time.Millisecond) {
		before := finds
		if err := r.scan(now, nil); err != nil {
			t.Fatal(err)
		}
		if finds != before {
			due = append(due, now.Sub(start).Round(100*time.Millisecond))
		}
	}
	want := []time.Duration{0, 500 * time.Millisecond, 1500 * time.Millisecond, 3500 * time.Millisecond,
		7500 * time.Millisecond, 15500 * time.Millisecond, 31500 * time.Millisecond, 61500 * time.Millisecond,
		91500 * time.Millisecond}
	if len(due) != len(want) {
		t.Fatalf("scanned at %v, want %v", due, want)
	}
	for i := range want {
		if due[i] != want[i] {
			t.Fatalf("scanned at %v, want %v", due, want)
		}
	}
	if r.waiting[10] == nil {
		t.Fatal("a live wineserver without pasta must stay waiting")
	}
}

func TestScanRetriesExitedPasta(t *testing.T) {
	gone := true
	var events []Event
	fds := newFakeFds()
	r := testRelays(t, fds, func(int) ([]pastaProc, error) {
		pidfd, err := fds.open(20)
		return []pastaProc{{pid: 20, pidfd: pidfd}}, err
	})
	r.register = func(pid, pidfd int, netns uint64) error {
		if gone {
			return errPastaGone
		}
		return nil
	}
	consume := func(e Event) error { events = append(events, e); return nil }
	start := time.Now()
	r.add(10, 7, start)
	if err := r.scan(start, consume); err != nil {
		t.Fatalf("a pasta exiting during registration must not stop the observer: %v", err)
	}
	if r.waiting[10] == nil || len(events) != 0 {
		t.Fatal("an exited pasta was registered")
	}
	if leaked := fds.leaked(); len(leaked) != 1 {
		t.Fatalf("fds %v left open after a failed registration", leaked)
	}
	gone = false
	if err := r.scan(start.Add(scanInterval), consume); err != nil {
		t.Fatal(err)
	}
	w := r.waiting[10]
	if w == nil || len(events) != 1 || events[0].PastaTGID != 20 || events[0].NetNS != 7 {
		t.Fatalf("pasta not registered on retry: %+v", events)
	}
	if rp := w.pastas[20]; rp == nil || !fds.isOpen(rp.fd) || !fds.isAlive(rp.fd) {
		t.Fatalf("registered pasta identity: %+v", w.pastas)
	}
}

func TestScanFailsOnRegistrationError(t *testing.T) {
	failure := errors.New("map full")
	fds := newFakeFds()
	r := testRelays(t, fds, func(int) ([]pastaProc, error) {
		pidfd, err := fds.open(20)
		return []pastaProc{{pid: 20, pidfd: pidfd}}, err
	})
	r.register = func(_, _ int, _ uint64) error { return failure }
	r.add(10, 7, time.Now())
	if err := r.scan(time.Now(), nil); !errors.Is(err, failure) {
		t.Fatalf("got %v", err)
	}
	if leaked := fds.leaked(); len(leaked) != 1 {
		t.Fatalf("fds %v left open after a failed registration", leaked)
	}
}

func TestScanForgetsExitedWineserver(t *testing.T) {
	fds := newFakeFds()
	r := testRelays(t, fds, func(int) ([]pastaProc, error) { return nil, os.ErrNotExist })
	r.add(10, 7, time.Now())
	if err := r.scan(time.Now(), nil); err != nil || len(r.waiting) != 0 {
		t.Fatalf("%v, %v", err, r.waiting)
	}
	if leaked := fds.leaked(); len(leaked) != 0 {
		t.Fatalf("fds %v left open", leaked)
	}
}

// A wineserver event is emitted once, but its pasta may exit and another may
// join the same namespace. The replacement must be registered without a new
// event from the wineserver.
func TestScanRegistersReplacementPasta(t *testing.T) {
	found := 20
	registrations := 0
	var events []Event
	fds := newFakeFds()
	r := testRelays(t, fds, func(int) ([]pastaProc, error) {
		pidfd, err := fds.open(found)
		return []pastaProc{{pid: found, pidfd: pidfd}}, err
	})
	r.register = func(pid, pidfd int, netns uint64) error {
		registrations++
		return nil
	}
	consume := func(e Event) error { events = append(events, e); return nil }
	start := time.Now()
	r.add(10, 7, start)
	if err := r.scan(start, consume); err != nil {
		t.Fatal(err)
	}
	first := r.waiting[10].pastas[20].fd
	found = 21
	if err := r.scan(start.Add(scanInterval), consume); err != nil {
		t.Fatal(err)
	}
	if registrations != 2 || len(events) != 2 || events[1].PastaTGID != 21 {
		t.Fatalf("replacement not registered: registrations %d, events %+v", registrations, events)
	}
	second := r.waiting[10].pastas[21].fd
	if second == first || fds.isOpen(first) || !fds.isOpen(second) {
		t.Fatalf("pasta fd %d not replaced by %d", first, second)
	}
	if err := r.scan(start.Add(2*scanInterval), consume); err != nil {
		t.Fatal(err)
	}
	if registrations != 2 || len(events) != 2 {
		t.Fatalf("same pasta registered twice: registrations %d, events %+v", registrations, events)
	}
	if r.waiting[10].pastas[21].fd != second {
		t.Fatal("the same pasta must keep the fd already held")
	}
	if leaked := fds.leaked(); len(leaked) != 2 {
		t.Fatalf("fds %v left open", leaked)
	}
}

// A scan that found a pasta but could not inspect every process must not
// prune the pastas already held: a live one was missed, not replaced.
func TestScanKeepsLivePastaOnPartialScanError(t *testing.T) {
	live := 20
	fds := newFakeFds()
	r := testRelays(t, fds, func(int) ([]pastaProc, error) {
		pidfd, err := fds.open(live)
		return []pastaProc{{pid: live, pidfd: pidfd}}, err
	})
	r.register = func(_, _ int, _ uint64) error { return nil }
	consume := func(Event) error { return nil }
	start := time.Now()
	r.add(10, 7, start)
	if err := r.scan(start, consume); err != nil {
		t.Fatal(err)
	}
	held := r.waiting[10].pastas[20].fd
	// The next scan finds a new pasta but is denied part of /proc.
	live = 21
	r.find = func(int) ([]pastaProc, error) {
		pidfd, _ := fds.open(live)
		return []pastaProc{{pid: 21, pidfd: pidfd}}, os.ErrPermission
	}
	if err := r.scan(start.Add(scanInterval), consume); err != nil {
		t.Fatal(err)
	}
	w := r.waiting[10]
	if w.pastas[20] == nil || !fds.isOpen(held) {
		t.Fatalf("held pasta dropped after a partial scan error: %+v", w.pastas)
	}
	if w.pastas[21] == nil {
		t.Fatalf("new pasta not registered: %+v", w.pastas)
	}
}

// exec revokes a pasta's registration but leaves its pidfd alive. A pasta that
// exec'd, possibly while a scan missed it, and is found again under the same
// PID must be registered again.
func TestScanReregistersExecedPasta(t *testing.T) {
	registrations := 0
	active := map[int]bool{}
	var events []Event
	fds := newFakeFds()
	r := testRelays(t, fds, func(int) ([]pastaProc, error) {
		pidfd, err := fds.open(20)
		return []pastaProc{{pid: 20, pidfd: pidfd}}, err
	})
	r.register = func(pid, pidfd int, netns uint64) error {
		registrations++
		active[pidfd] = true
		return nil
	}
	r.registered = func(pidfd int, netns uint64) bool { return active[pidfd] && netns == 7 }
	consume := func(e Event) error { events = append(events, e); return nil }
	start := time.Now()
	r.add(10, 7, start)
	if err := r.scan(start, consume); err != nil {
		t.Fatal(err)
	}
	if err := r.scan(start.Add(scanInterval), consume); err != nil {
		t.Fatal(err)
	}
	if registrations != 1 {
		t.Fatalf("active pasta registered again: registrations %d", registrations)
	}
	held := r.waiting[10].pastas[20].fd
	active[held] = false
	if err := r.scan(start.Add(time.Minute), consume); err != nil {
		t.Fatal(err)
	}
	if registrations != 2 || len(events) != 2 || events[1].PastaTGID != 20 {
		t.Fatalf("exec'd pasta not registered again: registrations %d, events %+v", registrations, events)
	}
	if now := r.waiting[10].pastas[20].fd; now == held || fds.isOpen(held) || !fds.isOpen(now) {
		t.Fatalf("pasta fd %d not replaced by %d", held, now)
	}
}

// A wineserver PID can be reused. A held fd whose process has exited must not
// make the new wineserver look like the old one, and the old entry's fds must
// be released.
func TestAddReplacesExitedWineserver(t *testing.T) {
	fds := newFakeFds()
	r := testRelays(t, fds, func(int) ([]pastaProc, error) {
		pidfd, err := fds.open(20)
		return []pastaProc{{pid: 20, pidfd: pidfd}}, err
	})
	r.register = func(_, _ int, _ uint64) error { return nil }
	start := time.Now()
	r.add(10, 7, start)
	if err := r.scan(start, func(Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	old := *r.waiting[10]
	fds.exit(old.serverFd)
	for _, rp := range old.pastas {
		fds.exit(rp.fd)
	}
	r.add(10, 8, start)
	w := r.waiting[10]
	if w == nil || w.netns != 8 || w.serverFd == old.serverFd || len(w.pastas) != 0 {
		t.Fatalf("reused wineserver PID not replaced: %+v", w)
	}
	if fds.isOpen(old.serverFd) {
		t.Fatalf("old server fd %d kept open", old.serverFd)
	}
	for _, rp := range old.pastas {
		if fds.isOpen(rp.fd) {
			t.Fatalf("old pasta fd %d kept open", rp.fd)
		}
	}
}

func TestAddKeepsLiveWineserver(t *testing.T) {
	fds := newFakeFds()
	r := testRelays(t, fds, func(int) ([]pastaProc, error) { return nil, nil })
	start := time.Now()
	r.add(10, 7, start)
	serverFd := r.waiting[10].serverFd
	r.add(10, 8, start)
	if w := r.waiting[10]; w.serverFd != serverFd || w.netns != 8 {
		t.Fatalf("live wineserver replaced: %+v", w)
	}
	if leaked := fds.leaked(); len(leaked) != 1 {
		t.Fatalf("fds %v left open", leaked)
	}
}

func TestScanDropsExitedWineserverFd(t *testing.T) {
	finds := 0
	fds := newFakeFds()
	r := testRelays(t, fds, func(int) ([]pastaProc, error) {
		finds++
		pidfd, err := fds.open(20)
		return []pastaProc{{pid: 20, pidfd: pidfd}}, err
	})
	r.register = func(_, _ int, _ uint64) error { return nil }
	start := time.Now()
	r.add(10, 7, start)
	if err := r.scan(start, func(Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if finds != 1 || r.waiting[10] == nil {
		t.Fatalf("pasta not registered: lookups %d", finds)
	}
	fds.exit(r.waiting[10].serverFd)
	if err := r.scan(start.Add(time.Second), nil); err != nil {
		t.Fatal(err)
	}
	if len(r.waiting) != 0 || finds != 1 {
		t.Fatalf("exited wineserver still waiting: %v, lookups %d", r.waiting, finds)
	}
	if leaked := fds.leaked(); len(leaked) != 0 {
		t.Fatalf("fds %v left open", leaked)
	}
}

func TestCloseReleasesHeldFds(t *testing.T) {
	fds := newFakeFds()
	r := testRelays(t, fds, func(server int) ([]pastaProc, error) {
		if server != 10 {
			return nil, nil
		}
		pidfd, err := fds.open(20)
		return []pastaProc{{pid: 20, pidfd: pidfd}}, err
	})
	r.register = func(_, _ int, _ uint64) error { return nil }
	start := time.Now()
	r.add(10, 7, start)
	r.add(11, 8, start)
	if err := r.scan(start, func(Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if leaked := fds.leaked(); len(leaked) != 3 {
		t.Fatalf("held fds %v", leaked)
	}
	r.close()
	if len(r.waiting) != 0 {
		t.Fatalf("entries left: %v", r.waiting)
	}
	if leaked := fds.leaked(); len(leaked) != 0 {
		t.Fatalf("fds %v left open", leaked)
	}
}

func TestScanReportsDistinctLookupErrorsOnce(t *testing.T) {
	var logged []string
	fds := newFakeFds()
	r := testRelays(t, fds, func(int) ([]pastaProc, error) {
		return nil, errors.New("permission denied")
	})
	r.logf = func(format string, args ...any) {
		logged = append(logged, fmt.Sprintf(format, args...))
	}
	start := time.Now()
	r.add(10, 7, start)
	for _, at := range []time.Time{start, start.Add(scanInterval), start.Add(2 * scanInterval)} {
		if err := r.scan(at, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(logged) != 1 {
		t.Fatalf("logged %d times: %v", len(logged), logged)
	}
}

func TestAliveSeesExit(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		t.Skip(err)
	}
	defer unix.Close(pidfd)
	if !alive(pidfd) {
		t.Fatal("running process reported exited")
	}
	cmd.Process.Kill()
	cmd.Wait()
	if alive(pidfd) {
		t.Fatal("exited process reported alive")
	}
}

func TestDNSTranslation(t *testing.T) {
	forward := netip.MustParseAddr("169.254.1.1").As16()
	host := netip.MustParseAddr("192.0.2.99").As16()
	for _, tc := range []struct {
		name    string
		fields  []string
		want    map[[16]byte][16]byte
		failure string
	}{
		{
			name:   "forward address with host nameserver",
			fields: []string{"pasta.avx2", "--dns-forward", "169.254.1.1", "--dns-host", "192.0.2.99"},
			want:   map[[16]byte][16]byte{forward: host},
		},
		{
			name:   "joined form",
			fields: []string{"pasta", "--dns-forward=169.254.1.1", "--dns-host=192.0.2.99"},
			want:   map[[16]byte][16]byte{forward: host},
		},
		{
			name:   "each family maps its own addresses",
			fields: []string{"pasta", "--dns-forward", "169.254.1.1", "--dns-forward", "fd00::1", "--dns-host", "192.0.2.99", "--dns-host", "fd00::53"},
			want: map[[16]byte][16]byte{
				netip.MustParseAddr("169.254.1.1").As16(): netip.MustParseAddr("192.0.2.99").As16(),
				netip.MustParseAddr("fd00::1").As16():     netip.MustParseAddr("fd00::53").As16(),
			},
		},
		{
			name:   "none unsets an address option",
			fields: []string{"pasta", "--dns-forward", "none", "--dns-forward", "169.254.1.1", "--dns-host", "none", "--dns-host", "192.0.2.99"},
			want:   map[[16]byte][16]byte{forward: host},
		},
		{
			name:   "arguments of the command after -- are not pasta's",
			fields: []string{"pasta", "--dns-forward", "169.254.1.1", "--dns-host", "192.0.2.99", "--", "game", "--dns-host", "fd00::53"},
			want:   map[[16]byte][16]byte{forward: host},
		},
		{
			name:   "map-host-loopback is not a mapping",
			fields: []string{"pasta", "--map-host-loopback", "169.254.2.2", "--dns-forward", "169.254.1.1", "--dns-host", "192.0.2.99"},
			want:   map[[16]byte][16]byte{forward: host},
		},
		{
			name:   "host nameserver without a forward address maps nothing",
			fields: []string{"pasta", "--dns-host", "192.0.2.99"},
			want:   map[[16]byte][16]byte{},
		},
		{
			name:   "no DNS options at all",
			fields: []string{"pasta", "--map-guest-addr", "none"},
			want:   map[[16]byte][16]byte{},
		},
		{
			name:    "forward without a host nameserver",
			fields:  []string{"pasta", "--dns-forward", "169.254.1.1"},
			failure: "--dns-forward 169.254.1.1 without --dns-host",
		},
		{
			name:    "one family's forward without its host nameserver",
			fields:  []string{"pasta", "--dns-forward", "169.254.1.1", "--dns-host", "192.0.2.99", "--dns-forward", "fd00::1"},
			failure: "--dns-forward fd00::1 without --dns-host",
		},
		{
			name:    "forward without an address",
			fields:  []string{"pasta", "--dns-forward"},
			failure: "--dns-forward without an address",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := dnsTranslation(tc.fields)
			if tc.failure != "" {
				if err == nil || !strings.Contains(err.Error(), tc.failure) {
					t.Fatalf("got %v, want %q", err, tc.failure)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("translation %v, want %v", got, tc.want)
			}
			for from, to := range tc.want {
				if got[from] != to {
					t.Fatalf("translation %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// pasta treats none as unsetting an option, including one set earlier.
func TestDNSOptionsNoneClearsEarlierAddress(t *testing.T) {
	got, err := dnsTranslation([]string{"pasta", "--dns-forward", "169.254.1.1", "--dns-forward", "none"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("translation %v, want none", got)
	}
	got, err = dnsTranslation([]string{"pasta", "--dns-forward", "169.254.1.1", "--dns-host", "192.0.2.99", "--dns-host", "none"})
	if err == nil || !strings.Contains(err.Error(), "--dns-forward 169.254.1.1 without --dns-host") {
		t.Fatalf("got %v, want a missing --dns-host error", err)
	}
	if len(got) != 0 {
		t.Fatalf("translation %v, want none", got)
	}
}

// One family without --dns-host must not drop the other family's mapping; the
// valid forward is installed and the missing host is reported once.
func TestDNSRegisterInstallsPartialFamilyAndReportsOnce(t *testing.T) {
	forward := netip.MustParseAddr("169.254.1.1").As16()
	host := netip.MustParseAddr("192.0.2.99").As16()
	translation, dnsErr := dnsTranslation([]string{"pasta", "--dns-forward", "169.254.1.1", "--dns-host", "192.0.2.99", "--dns-forward", "fd00::1"})
	if dnsErr == nil || !strings.Contains(dnsErr.Error(), "--dns-forward fd00::1 without --dns-host") {
		t.Fatalf("got %v, want the IPv6 missing --dns-host error", dnsErr)
	}
	if len(translation) != 1 || translation[forward] != host {
		t.Fatalf("translation %v, want the IPv4 mapping", translation)
	}

	var logged []string
	installed := map[forwardKey]dnsForward{}
	fds := newFakeFds()
	r := testRelays(t, fds, nil)
	r.dns = func(int) (map[[16]byte][16]byte, error) { return translation, dnsErr }
	r.updateForward = func(key forwardKey, value dnsForward) error {
		installed[key] = value
		return nil
	}
	r.deleteForward = func(key forwardKey) error {
		delete(installed, key)
		return nil
	}
	r.logf = func(format string, args ...any) {
		logged = append(logged, fmt.Sprintf(format, args...))
	}
	start := time.Now()
	r.add(10, 7, start)
	fd, ferr := fds.open(20)
	if ferr != nil {
		t.Fatal(ferr)
	}
	rp := &registeredPasta{pid: 20, fd: fd}
	r.waiting[10].pastas = map[int]*registeredPasta{20: rp}
	r.registerDNS(rp, 7)
	key := forwardKey{NetNS: 7, Address: forward}
	if installed[key].Resolver != host || !slices.Contains(rp.forwards, key) {
		t.Fatalf("IPv4 forward not installed: installed %v, forwards %v", installed, rp.forwards)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "--dns-forward fd00::1 without --dns-host") {
		t.Fatalf("reported %v, want the missing IPv6 host once", logged)
	}
	r.registerDNS(rp, 7)
	if len(logged) != 1 {
		t.Fatalf("reported %d times: %v", len(logged), logged)
	}
}

// A replacement pasta on the same namespace takes over the forwards it names,
// and the ones only the old pasta used are deleted.
func TestScanPrunesReplacedPastaForwards(t *testing.T) {
	a := netip.MustParseAddr("169.254.1.1").As16()
	b := netip.MustParseAddr("169.254.2.2").As16()
	host := netip.MustParseAddr("192.0.2.99").As16()
	installed := map[forwardKey]dnsForward{}
	found := 20
	fds := newFakeFds()
	r := testRelays(t, fds, func(int) ([]pastaProc, error) {
		pidfd, err := fds.open(found)
		return []pastaProc{{pid: found, pidfd: pidfd}}, err
	})
	r.register = func(_, _ int, _ uint64) error { return nil }
	r.dns = func(pid int) (map[[16]byte][16]byte, error) {
		if pid == 20 {
			return map[[16]byte][16]byte{a: host}, nil
		}
		return map[[16]byte][16]byte{b: host}, nil
	}
	r.updateForward = func(key forwardKey, value dnsForward) error {
		installed[key] = value
		return nil
	}
	r.deleteForward = func(key forwardKey) error {
		delete(installed, key)
		return nil
	}
	consume := func(Event) error { return nil }
	start := time.Now()
	r.add(10, 7, start)
	if err := r.scan(start, consume); err != nil {
		t.Fatal(err)
	}
	keyA := forwardKey{NetNS: 7, Address: a}
	if _, ok := installed[keyA]; !ok {
		t.Fatalf("forward A not installed: %v", installed)
	}
	found = 21
	if err := r.scan(start.Add(scanInterval), consume); err != nil {
		t.Fatal(err)
	}
	if _, ok := installed[keyA]; ok {
		t.Fatalf("replaced pasta's forward A left behind: %v", installed)
	}
	keyB := forwardKey{NetNS: 7, Address: b}
	if installed[keyB].Resolver != host {
		t.Fatalf("replacement's forward B not installed: %v", installed)
	}
}

// Two pastas on the same namespace each keep their forward while both live; when
// one exits only its own forward is deleted.
func TestScanKeepsForwardsOfOtherPasta(t *testing.T) {
	a := netip.MustParseAddr("169.254.1.1").As16()
	b := netip.MustParseAddr("169.254.2.2").As16()
	host := netip.MustParseAddr("192.0.2.99").As16()
	installed := map[forwardKey]dnsForward{}
	pids := []int{20, 21}
	fds := newFakeFds()
	r := testRelays(t, fds, func(int) ([]pastaProc, error) {
		found := make([]pastaProc, 0, len(pids))
		for _, pid := range pids {
			pidfd, err := fds.open(pid)
			if err != nil {
				return nil, err
			}
			found = append(found, pastaProc{pid: pid, pidfd: pidfd})
		}
		return found, nil
	})
	r.register = func(_, _ int, _ uint64) error { return nil }
	r.dns = func(pid int) (map[[16]byte][16]byte, error) {
		if pid == 20 {
			return map[[16]byte][16]byte{a: host}, nil
		}
		return map[[16]byte][16]byte{b: host}, nil
	}
	r.updateForward = func(key forwardKey, value dnsForward) error {
		installed[key] = value
		return nil
	}
	r.deleteForward = func(key forwardKey) error {
		delete(installed, key)
		return nil
	}
	consume := func(Event) error { return nil }
	start := time.Now()
	r.add(10, 7, start)
	if err := r.scan(start, consume); err != nil {
		t.Fatal(err)
	}
	keyA := forwardKey{NetNS: 7, Address: a}
	keyB := forwardKey{NetNS: 7, Address: b}
	if _, ok := installed[keyA]; !ok {
		t.Fatalf("forward A not installed: %v", installed)
	}
	if _, ok := installed[keyB]; !ok {
		t.Fatalf("forward B not installed: %v", installed)
	}
	fd20, fd21 := r.waiting[10].pastas[20].fd, r.waiting[10].pastas[21].fd
	pids = []int{21}
	if err := r.scan(start.Add(scanInterval), consume); err != nil {
		t.Fatal(err)
	}
	if _, ok := installed[keyA]; ok {
		t.Fatalf("exited pasta's forward A left behind: %v", installed)
	}
	if _, ok := installed[keyB]; !ok {
		t.Fatalf("live pasta's forward B was deleted: %v", installed)
	}
	if fds.isOpen(fd20) || !fds.isOpen(fd21) {
		t.Fatalf("exited pasta fd %d or live pasta fd %d released wrongly", fd20, fd21)
	}
}

// A pasta the observer may not inspect is reported, not silently ignored.
func TestRelaysForPropagatesPermissionError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read a mode 0000 directory")
	}
	proc := t.TempDir()
	const pid = 41
	dir := filepath.Join(proc, strconv.Itoa(pid))
	if err := os.MkdirAll(filepath.Join(dir, "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/run/netns/pasta", filepath.Join(dir, "ns", "net")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "fd"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(dir, "fd"), 0o755) })
	matches, err := relaysForAt(proc, pid, "/run/netns/server")
	if matches || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("relaysForAt = %v, %v; want a permission error", matches, err)
	}

	var logged []string
	fds := newFakeFds()
	r := testRelays(t, fds, func(int) ([]pastaProc, error) {
		if _, err := relaysForAt(proc, pid, "/run/netns/server"); err != nil {
			return nil, err
		}
		return nil, nil
	})
	r.logf = func(format string, args ...any) {
		logged = append(logged, fmt.Sprintf(format, args...))
	}
	start := time.Now()
	r.add(10, 7, start)
	if err := r.scan(start, nil); err != nil {
		t.Fatal(err)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "permission denied") {
		t.Fatalf("logged %v, want one permission error", logged)
	}
	if err := r.scan(start.Add(time.Second), nil); err != nil {
		t.Fatal(err)
	}
	if len(logged) != 1 {
		t.Fatalf("logged %d times: %v", len(logged), logged)
	}
}

// The comm names are globals so their addresses stay valid in a forked child,
// where only raw syscalls may run.
var (
	pastaCommName = [...]byte{'p', 'a', 's', 't', 'a', 0}
	passtCommName = [...]byte{'p', 'a', 's', 's', 't', 0}
)

// hiddenExeChild forks a child that takes name as its comm and turns itself
// non-dumpable: /proc/<pid>/exe then denies its read link to a process without
// CAP_SYS_PTRACE, exactly as a pasta under a hardened policy does, while
// /proc/<pid>/comm stays world-readable. The child lives until killed.
func hiddenExeChild(t *testing.T, name *[6]byte) int {
	t.Helper()
	pid, _, errno := unix.RawSyscall6(unix.SYS_CLONE, uintptr(unix.SIGCHLD), 0, 0, 0, 0, 0)
	if errno != 0 {
		t.Skipf("fork: %v", errno)
	}
	if pid == 0 {
		unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_SET_NAME, uintptr(unsafe.Pointer(&name[0])), 0, 0, 0, 0)
		unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_SET_DUMPABLE, 0, 0, 0, 0, 0)
		for {
			unix.RawSyscall6(unix.SYS_PAUSE, 0, 0, 0, 0, 0, 0)
		}
	}
	child := int(pid)
	t.Cleanup(func() {
		unix.Kill(child, unix.SIGKILL)
		var status unix.WaitStatus
		unix.Wait4(child, &status, 0, nil)
	})
	return child
}

// A pasta the observer may not inspect is not silently ignored: its exe link
// denies reading while comm stays readable, and comm names pasta. A process
// the observer may not inspect whose comm names no pasta is still skipped.
func TestIsPastaReportsUnreadableExe(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read any process's exe link")
	}
	pasta := hiddenExeChild(t, &pastaCommName)
	passt := hiddenExeChild(t, &passtCommName)
	// Wait until both children have their names and deny exe reads, so the
	// assertions cannot race the children's prctls.
	deadline := time.Now().Add(5 * time.Second)
	hidden := func(pid int, comm string) bool {
		got, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil || !strings.HasPrefix(string(got), comm) {
			return false
		}
		_, err = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		return err != nil
	}
	for !hidden(pasta, "pasta") || !hidden(passt, "passt") {
		if time.Now().After(deadline) {
			t.Skip("exe links stayed readable; cannot test an unreadable exe")
		}
		time.Sleep(10 * time.Millisecond)
	}

	found, err := isPastaAt("/proc", pasta)
	if found || err == nil || !errors.Is(err, os.ErrPermission) ||
		!strings.Contains(err.Error(), fmt.Sprintf("pasta %d", pasta)) {
		t.Fatalf("isPastaAt(pasta) = %v, %v; want the exe permission error", found, err)
	}
	found, err = isPastaAt("/proc", passt)
	if found || err != nil {
		t.Fatalf("isPastaAt(passt) = %v, %v; want no error", found, err)
	}

	// findPastasAt reports the unreadable pasta and keeps scanning: the scan
	// of the rest of /proc completes and joins the error into its result.
	_, err = findPastasAt("/proc", os.Getpid())
	if err == nil || !errors.Is(err, os.ErrPermission) ||
		!strings.Contains(err.Error(), fmt.Sprintf("pasta %d", pasta)) {
		t.Fatalf("findPastasAt = %v; want the pasta %d exe permission error", err, pasta)
	}
	if err != nil && strings.Contains(err.Error(), fmt.Sprintf("pasta %d", passt)) {
		t.Fatalf("findPastasAt reported the non-pasta child: %v", err)
	}
}

// One wineserver can own more than one pasta on the same namespace. Each is
// registered and held separately, so one exiting leaves the other in place.
func TestScanRegistersMultiplePastasPerNetns(t *testing.T) {
	var events []Event
	registrations := 0
	pids := []int{20, 21}
	fds := newFakeFds()
	r := testRelays(t, fds, func(int) ([]pastaProc, error) {
		found := make([]pastaProc, 0, len(pids))
		for _, pid := range pids {
			pidfd, err := fds.open(pid)
			if err != nil {
				return nil, err
			}
			found = append(found, pastaProc{pid: pid, pidfd: pidfd})
		}
		return found, nil
	})
	r.register = func(pid, pidfd int, netns uint64) error {
		registrations++
		return nil
	}
	consume := func(e Event) error { events = append(events, e); return nil }
	start := time.Now()
	r.add(10, 7, start)
	if err := r.scan(start, consume); err != nil {
		t.Fatal(err)
	}
	if registrations != 2 || len(events) != 2 || events[0].PastaTGID != 20 || events[1].PastaTGID != 21 {
		t.Fatalf("pastas not both registered: registrations %d, events %+v", registrations, events)
	}
	w := r.waiting[10]
	fd20, fd21 := w.pastas[20].fd, w.pastas[21].fd
	if !fds.isOpen(fd20) || !fds.isOpen(fd21) {
		t.Fatalf("registered fds %d, %d not both open", fd20, fd21)
	}
	if err := r.scan(start.Add(scanInterval), consume); err != nil {
		t.Fatal(err)
	}
	if registrations != 2 || len(events) != 2 {
		t.Fatalf("same pastas registered again: registrations %d, events %+v", registrations, events)
	}
	if w.pastas[20].fd != fd20 || w.pastas[21].fd != fd21 {
		t.Fatalf("live pastas' fds changed: %+v", w.pastas)
	}
	pids = []int{21}
	if err := r.scan(start.Add(2*scanInterval), consume); err != nil {
		t.Fatal(err)
	}
	if registrations != 2 || len(events) != 2 {
		t.Fatalf("exiting pasta registered again: registrations %d, events %+v", registrations, events)
	}
	if w.pastas[20] != nil || !fds.isOpen(fd21) || fds.isOpen(fd20) {
		t.Fatalf("pasta 20 removed wrongly: %+v, fds %d %d", w.pastas, fd20, fd21)
	}
}
