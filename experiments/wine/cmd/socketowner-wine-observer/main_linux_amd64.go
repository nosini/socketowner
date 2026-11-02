// Command socketowner-wine-observer prints diagnostic Windows socket creator
// identities from one explicitly selected, unchanged Wine server. It pins no
// maps and is not connected to mihomo routing.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/nosini/socketowner/experiments/wine"
)

func run() error {
	generate := flag.String("make-profile", "", "generate a profile from this trusted wineserver ELF with matching DWARF; no BPF attachment")
	profileFile := flag.String("profile", "", "reviewed JSON profile for the exact running Wine binary")
	pid := flag.Int("pid", 0, "host PID of one running wineserver")
	cgroup := flag.String("cgroup", "/sys/fs/cgroup", "cgroup v2 hierarchy for first-egress observation")
	sends := flag.Bool("sends", false, "also report send operations (diagnostic; may be noisy)")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	encoder := json.NewEncoder(os.Stdout)
	if *generate != "" {
		if *profileFile != "" || *pid != 0 || *sends {
			return fmt.Errorf("profile generation cannot be combined with observation")
		}
		f, err := os.Open(*generate)
		if err != nil {
			return err
		}
		defer f.Close()
		p, err := wine.GenerateProfile(f)
		if err != nil {
			return err
		}
		encoder.SetIndent("", "  ")
		return encoder.Encode(p)
	}
	if *profileFile == "" || *pid <= 0 {
		return fmt.Errorf("use -make-profile ELF, or -profile JSON -pid HOST_PID")
	}
	f, err := os.Open(*profileFile)
	if err != nil {
		return err
	}
	p, err := wine.ReadProfile(f)
	f.Close()
	if err != nil {
		return err
	}
	t, err := wine.Prepare(*pid, p)
	if err != nil {
		return err
	}
	defer t.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return wine.Observe(ctx, t, wine.Options{Cgroup: *cgroup, Sends: *sends}, func(e wine.Event) error { return encoder.Encode(e) })
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
