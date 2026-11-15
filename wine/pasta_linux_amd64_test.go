package wine

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"

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
func testRelays(t *testing.T, fds *fakeFds, find func(int) (int, int, error)) *relays {
	t.Helper()
	r := &relays{
		waiting:  map[int]*waitingServer{},
		find:     find,
		open:     fds.open,
		alive:    fds.isAlive,
		closeFd:  fds.close,
		logf:     func(string, ...any) {},
		reported: map[string]bool{},
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
	r := testRelays(t, fds, func(int) (int, int, error) { finds++; return 0, -1, nil })
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
	r := testRelays(t, fds, func(int) (int, int, error) {
		pidfd, err := fds.open(20)
		return 20, pidfd, err
	})
	r.register = func(pidfd int, netns uint64) error {
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
	if w.pastaPid != 20 || !fds.isOpen(w.pastaFd) || !fds.isAlive(w.pastaFd) {
		t.Fatalf("registered pasta identity: pid %d, fd %d", w.pastaPid, w.pastaFd)
	}
}

func TestScanFailsOnRegistrationError(t *testing.T) {
	failure := errors.New("map full")
	fds := newFakeFds()
	r := testRelays(t, fds, func(int) (int, int, error) {
		pidfd, err := fds.open(20)
		return 20, pidfd, err
	})
	r.register = func(int, uint64) error { return failure }
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
	r := testRelays(t, fds, func(int) (int, int, error) { return 0, -1, os.ErrNotExist })
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
	r := testRelays(t, fds, func(int) (int, int, error) {
		pidfd, err := fds.open(found)
		return found, pidfd, err
	})
	r.register = func(pidfd int, netns uint64) error {
		registrations++
		return nil
	}
	consume := func(e Event) error { events = append(events, e); return nil }
	start := time.Now()
	r.add(10, 7, start)
	if err := r.scan(start, consume); err != nil {
		t.Fatal(err)
	}
	first := r.waiting[10].pastaFd
	found = 21
	if err := r.scan(start.Add(scanInterval), consume); err != nil {
		t.Fatal(err)
	}
	if registrations != 2 || len(events) != 2 || events[1].PastaTGID != 21 {
		t.Fatalf("replacement not registered: registrations %d, events %+v", registrations, events)
	}
	second := r.waiting[10].pastaFd
	if second == first || fds.isOpen(first) || !fds.isOpen(second) {
		t.Fatalf("pasta fd %d not replaced by %d", first, second)
	}
	if err := r.scan(start.Add(2*scanInterval), consume); err != nil {
		t.Fatal(err)
	}
	if registrations != 2 || len(events) != 2 {
		t.Fatalf("same pasta registered twice: registrations %d, events %+v", registrations, events)
	}
	if r.waiting[10].pastaFd != second {
		t.Fatal("the same pasta must keep the fd already held")
	}
	if leaked := fds.leaked(); len(leaked) != 2 {
		t.Fatalf("fds %v left open", leaked)
	}
}

// A wineserver PID can be reused. A held fd whose process has exited must not
// make the new wineserver look like the old one, and the old entry's fds must
// be released.
func TestAddReplacesExitedWineserver(t *testing.T) {
	fds := newFakeFds()
	r := testRelays(t, fds, func(int) (int, int, error) {
		pidfd, err := fds.open(20)
		return 20, pidfd, err
	})
	r.register = func(int, uint64) error { return nil }
	start := time.Now()
	r.add(10, 7, start)
	if err := r.scan(start, func(Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	old := *r.waiting[10]
	fds.exit(old.serverFd)
	fds.exit(old.pastaFd)
	r.add(10, 8, start)
	w := r.waiting[10]
	if w == nil || w.netns != 8 || w.serverFd == old.serverFd || w.pastaPid != 0 {
		t.Fatalf("reused wineserver PID not replaced: %+v", w)
	}
	if fds.isOpen(old.serverFd) || fds.isOpen(old.pastaFd) {
		t.Fatalf("old fds %d, %d kept open", old.serverFd, old.pastaFd)
	}
}

func TestAddKeepsLiveWineserver(t *testing.T) {
	fds := newFakeFds()
	r := testRelays(t, fds, func(int) (int, int, error) { return 0, -1, nil })
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
	r := testRelays(t, fds, func(int) (int, int, error) {
		finds++
		pidfd, err := fds.open(20)
		return 20, pidfd, err
	})
	r.register = func(int, uint64) error { return nil }
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
	r := testRelays(t, fds, func(server int) (int, int, error) {
		if server != 10 {
			return 0, -1, nil
		}
		pidfd, err := fds.open(20)
		return 20, pidfd, err
	})
	r.register = func(int, uint64) error { return nil }
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
	r := testRelays(t, fds, func(int) (int, int, error) {
		return 0, -1, errors.New("permission denied")
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
