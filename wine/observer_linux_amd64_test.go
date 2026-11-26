package wine

import (
	"errors"
	"testing"
	"time"
)

// A blocked diagnostic consumer must not stall event emission, pasta discovery,
// or shutdown, and dropped diagnostics must be counted.
func TestEventSinkDecouplesBlockedConsumer(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	sink := newEventSink("obs-1", 2, func(e Event) error {
		if e.Type == "ready" {
			close(entered)
			<-release
		}
		return nil
	})
	defer close(release)

	if err := sink.emit(Event{Type: "ready"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("consumer never received ready event")
	}

	// Fill the buffer (capacity 2) and emit 5 more events; none may block.
	doneEmit := make(chan struct{})
	go func() {
		for range 7 {
			if err := sink.emit(Event{Type: "create"}); err != nil {
				t.Errorf("emit failed: %v", err)
			}
		}
		close(doneEmit)
	}()
	select {
	case <-doneEmit:
	case <-time.After(time.Second):
		t.Fatal("emit blocked while consumer was stalled")
	}
	if dropped := sink.takeDropped(); dropped != 5 {
		t.Fatalf("dropped = %d, want 5", dropped)
	}
	if again := sink.takeDropped(); again != 0 {
		t.Fatalf("takeDropped did not reset: %d", again)
	}

	// Shutdown must return within the flush timeout even while consume is blocked.
	start := time.Now()
	if err := sink.close(50 * time.Millisecond); err != nil {
		t.Fatalf("close returned unexpected error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("close took %v while consumer was blocked", elapsed)
	}
}

func TestEventSinkPropagatesConsumerError(t *testing.T) {
	want := errors.New("broken pipe")
	sink := newEventSink("obs-2", 4, func(e Event) error {
		return want
	})
	if err := sink.emit(Event{Type: "ready"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for sink.err() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !errors.Is(sink.err(), want) {
		t.Fatalf("err() = %v, want %v", sink.err(), want)
	}
	if err := sink.emit(Event{Type: "create"}); !errors.Is(err, want) {
		t.Fatalf("emit() = %v, want %v", err, want)
	}
	if err := sink.close(100 * time.Millisecond); !errors.Is(err, want) {
		t.Fatalf("close() = %v, want %v", err, want)
	}
}

// A loss event that cannot be queued must not collapse the losses it reports:
// the full count stays pending for the next report.
func TestEventSinkLossNotCollapsedByFullQueue(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	sink := newEventSink("obs-3", 2, func(e Event) error {
		if e.Type == "ready" {
			close(entered)
			<-release
		}
		return nil
	})
	if err := sink.emit(Event{Type: "ready"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("consumer never received ready event")
	}
	// Fill the buffer (capacity 2).
	for range 2 {
		if err := sink.emit(Event{Type: "create"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.emitLoss(700); err != nil {
		t.Fatal(err)
	}
	// The loss event itself is not counted again.
	if dropped := sink.takeDropped(); dropped != 700 {
		t.Fatalf("dropped = %d, want 700", dropped)
	}
	close(release)
	if err := sink.close(time.Second); err != nil {
		t.Fatal(err)
	}
}
