// Command socketowner-wine-observer names the Windows programs behind every
// wineserver's sockets, for as long as it runs. It prints diagnostics, and with
// -pin publishes the identities for mihomo, through each sandbox's pasta.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"sync/atomic"
	"syscall"

	"github.com/nosini/socketowner/wine"
)

func run() error {
	cgroup := flag.String("cgroup", "/sys/fs/cgroup", "cgroup v2 hierarchy for egress observation")
	sends := flag.Bool("sends", false, "also report send operations (diagnostic; may be noisy)")
	noRelay := flag.Bool("no-relay", false, "leave pasta unregistered, as a test's negative control")
	pin := flag.String("pin", "", "publish routing maps in this directory, normally socketowner's maps directory")
	readerGroup := flag.String("reader-group", "", "group given read access to the pinned maps (name or ID)")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	options := wine.Options{Cgroup: *cgroup, Sends: *sends, NoRelay: *noRelay, Pin: *pin, Group: -1}
	if *readerGroup != "" {
		gid, err := groupID(*readerGroup)
		if err != nil {
			return err
		}
		options.Group = gid
	}
	encoder := json.NewEncoder(os.Stdout)
	// SIGHUP, SIGINT and SIGTERM stop cleanly. SIGPIPE is caught so a broken
	// stdout cannot kill the process before it unpins; event output then ends
	// and the process exits non-zero, which systemd's Restart=on-failure sees.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGPIPE)
	defer signal.Stop(signals)
	var brokenPipe atomic.Bool
	go func() {
		select {
		case <-ctx.Done():
		case sig := <-signals:
			if sig == syscall.SIGPIPE {
				brokenPipe.Store(true)
			}
			cancel()
		}
	}()
	err := wine.Observe(ctx, options, func(e wine.Event) error {
		if err := encoder.Encode(e); err != nil {
			if errors.Is(err, syscall.EPIPE) {
				brokenPipe.Store(true)
			}
			return fmt.Errorf("event output: %w", err)
		}
		if e.Type == "ready" {
			return notifyReady()
		}
		return nil
	})
	if brokenPipe.Load() {
		if err == nil {
			err = errors.New("event output closed (SIGPIPE)")
		} else {
			err = fmt.Errorf("%w (event output closed)", err)
		}
	}
	return err
}

// groupID accepts a group name or a numeric ID, including an ID with no entry.
func groupID(group string) (int, error) {
	if gid, err := strconv.Atoi(group); err == nil && gid >= 0 {
		return gid, nil
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		if g, err = user.LookupGroupId(group); err != nil {
			return 0, err
		}
	}
	return strconv.Atoi(g.Gid)
}

// notifyReady also permits direct command-line use without systemd.
func notifyReady() error {
	address := os.Getenv("NOTIFY_SOCKET")
	if address == "" {
		return nil
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: address, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("systemd readiness: %w", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("READY=1")); err != nil {
		return fmt.Errorf("systemd readiness: %w", err)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
