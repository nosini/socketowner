package wine

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testRelays(find func(int) (int, int, error)) *relays {
	return &relays{
		waiting:  map[int]*waitingServer{},
		find:     find,
		start:    func(int) (uint64, error) { return 100, nil },
		logf:     func(string, ...any) {},
		reported: map[string]bool{},
	}
}

func TestScanBacksOffWithoutPasta(t *testing.T) {
	finds := 0
	r := testRelays(func(int) (int, int, error) { finds++; return 0, -1, nil })
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
	r := testRelays(func(int) (int, int, error) { return 20, -1, nil })
	r.start = func(pid int) (uint64, error) {
		if pid == 10 {
			return 100, nil
		}
		return 200, nil
	}
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
	gone = false
	if err := r.scan(start.Add(scanInterval), consume); err != nil {
		t.Fatal(err)
	}
	if r.waiting[10] == nil || len(events) != 1 || events[0].PastaTGID != 20 || events[0].NetNS != 7 {
		t.Fatalf("pasta not registered on retry: %+v", events)
	}
	if got := r.waiting[10].pasta; got != (process{pid: 20, start: 200}) {
		t.Fatalf("registered pasta identity: %+v", got)
	}
}

func TestScanFailsOnRegistrationError(t *testing.T) {
	failure := errors.New("map full")
	r := testRelays(func(int) (int, int, error) { return 20, -1, nil })
	r.register = func(int, uint64) error { return failure }
	r.add(10, 7, time.Now())
	if err := r.scan(time.Now(), nil); !errors.Is(err, failure) {
		t.Fatalf("got %v", err)
	}
}

func TestScanForgetsExitedWineserver(t *testing.T) {
	r := testRelays(func(int) (int, int, error) { return 0, -1, os.ErrNotExist })
	r.add(10, 7, time.Now())
	if err := r.scan(time.Now(), nil); err != nil || len(r.waiting) != 0 {
		t.Fatalf("%v, %v", err, r.waiting)
	}
}

// A wineserver event is emitted once, but its pasta may exit and another may
// join the same namespace. The replacement must be registered without a new
// event from the wineserver.
func TestScanRegistersReplacementPasta(t *testing.T) {
	found := 20
	registrations := 0
	var events []Event
	r := testRelays(func(int) (int, int, error) { return found, -1, nil })
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
	found = 21
	if err := r.scan(start.Add(scanInterval), consume); err != nil {
		t.Fatal(err)
	}
	if registrations != 2 || len(events) != 2 || events[1].PastaTGID != 21 {
		t.Fatalf("replacement not registered: registrations %d, events %+v", registrations, events)
	}
	if err := r.scan(start.Add(2*scanInterval), consume); err != nil {
		t.Fatal(err)
	}
	if registrations != 2 || len(events) != 2 {
		t.Fatalf("same pasta registered twice: registrations %d, events %+v", registrations, events)
	}
}

// A waiting entry must not follow a reused wineserver PID into another sandbox:
// its recorded network namespace would then go with the wrong pasta.
func TestScanDropsReusedWineserverPID(t *testing.T) {
	finds := 0
	startTime := uint64(100)
	r := testRelays(func(int) (int, int, error) {
		finds++
		return 20, -1, nil
	})
	r.start = func(int) (uint64, error) { return startTime, nil }
	start := time.Now()
	r.add(10, 7, start)
	startTime = 200
	if err := r.scan(start.Add(time.Second), nil); err != nil {
		t.Fatal(err)
	}
	if len(r.waiting) != 0 || finds != 0 {
		t.Fatalf("reused PID still waiting: %v, lookups %d", r.waiting, finds)
	}
}

func TestScanReportsDistinctLookupErrorsOnce(t *testing.T) {
	var logged []string
	r := testRelays(func(int) (int, int, error) {
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

func TestProcessStart(t *testing.T) {
	start, err := processStart(os.Getpid())
	if err != nil || start == 0 {
		t.Fatalf("process start: %d, %v", start, err)
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
