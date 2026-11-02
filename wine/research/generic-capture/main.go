//go:build ignore

package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unicode/utf16"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:embed g.o
var object []byte

type ev struct {
	Kind, Server, Client, Status, Bytes, A uint32
	Path                                   [512]uint16
}

func main() {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		panic(err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
	defer coll.Close()
	for _, p := range []string{"perm", "create", "sendmsg"} {
		l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs[p]})
		if err != nil {
			panic(err)
		}
		defer l.Close()
	}
	rd, _ := ringbuf.NewReader(coll.Maps["events"])
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-stop; rd.Close() }()
	fmt.Println(`{"type":"ready"}`)
	out := json.NewEncoder(os.Stdout)
	for {
		rd.SetDeadline(time.Now().Add(time.Second))
		r, err := rd.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			break
		}
		var e ev
		binary.Read(bytes.NewReader(r.RawSample), binary.NativeEndian, &e)
		image := string(utf16.Decode(e.Path[:e.Bytes/2]))
		if e.Status == 6 {
			raw := make([]byte, 0, e.Bytes)
			for _, w := range e.Path[:(e.Bytes+1)/2] {
				raw = append(raw, byte(w), byte(w>>8))
			}
			image = string(raw[:e.Bytes])
		}
		out.Encode(map[string]any{"type": "socket", "server": e.Server, "client": e.Client, "status": e.Status, "stype": e.A,
			"image": image})
	}
	counts := map[string]uint64{}
	for i, n := range []string{"created", "no_client", "no_image", "send_ok", "send_mismatch", "ring_loss", "all_inet"} {
		var v uint64
		coll.Maps["counts"].Lookup(uint32(i), &v)
		counts[n] = v
	}
	for _, p := range []string{"perm", "create", "sendmsg"} {
		if st, err := coll.Programs[p].Stats(); err == nil {
			counts["miss_"+p] = st.RecursionMisses
			counts["runs_"+p] = st.RunCount
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	out.Encode(map[string]any{"type": "counts", "counts": counts})
}
