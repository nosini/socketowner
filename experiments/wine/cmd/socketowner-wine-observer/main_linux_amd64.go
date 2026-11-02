// Command socketowner-wine-observer names the Windows programs behind every
// wineserver's sockets, for as long as it runs. It prints diagnostics, and with
// -pin publishes the identities for mihomo, through each sandbox's pasta.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/nosini/socketowner/experiments/wine"
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
		g, err := user.LookupGroup(*readerGroup)
		if err != nil {
			if g, err = user.LookupGroupId(*readerGroup); err != nil {
				return err
			}
		}
		if options.Group, err = strconv.Atoi(g.Gid); err != nil {
			return err
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return wine.Observe(ctx, options, func(e wine.Event) error { return encoder.Encode(e) })
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
