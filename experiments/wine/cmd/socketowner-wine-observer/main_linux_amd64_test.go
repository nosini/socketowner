package main

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestNotifyReady(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := notifyReady(); err != nil {
		t.Fatal(err)
	}
	address := filepath.Join(t.TempDir(), "notify")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: address, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("NOTIFY_SOCKET", address)
	if err := notifyReady(); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 128)
	n, _, err := listener.ReadFromUnix(data)
	if err != nil {
		t.Fatal(err)
	}
	if string(data[:n]) != "READY=1" {
		t.Fatalf("unexpected notification: %q", data[:n])
	}
	t.Setenv("NOTIFY_SOCKET", filepath.Join(t.TempDir(), "missing"))
	if err := notifyReady(); err == nil {
		t.Fatal("missing notify socket must fail startup")
	}
}
