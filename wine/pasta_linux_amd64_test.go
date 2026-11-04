package wine

import (
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestScanBacksOffWithoutPasta(t *testing.T) {
	finds := 0
	r := &relays{waiting: map[int]*waitingServer{},
		find: func(int) (int, int, error) { finds++; return 0, -1, nil },
	}
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
	r := &relays{waiting: map[int]*waitingServer{},
		find: func(int) (int, int, error) { return 20, -1, nil },
		register: func(pidfd int, netns uint64) error {
			if gone {
				return errPastaGone
			}
			return nil
		},
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
	if r.waiting[10] != nil || len(events) != 1 || events[0].PastaTGID != 20 || events[0].NetNS != 7 {
		t.Fatalf("pasta not registered on retry: %+v", events)
	}
}

func TestScanFailsOnRegistrationError(t *testing.T) {
	failure := errors.New("map full")
	r := &relays{waiting: map[int]*waitingServer{},
		find:     func(int) (int, int, error) { return 20, -1, nil },
		register: func(int, uint64) error { return failure },
	}
	r.add(10, 7, time.Now())
	if err := r.scan(time.Now(), nil); !errors.Is(err, failure) {
		t.Fatalf("got %v", err)
	}
}

func TestScanForgetsExitedWineserver(t *testing.T) {
	r := &relays{waiting: map[int]*waitingServer{},
		find: func(int) (int, int, error) { return 0, -1, os.ErrNotExist },
	}
	r.add(10, 7, time.Now())
	if err := r.scan(time.Now(), nil); err != nil || len(r.waiting) != 0 {
		t.Fatalf("%v, %v", err, r.waiting)
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
