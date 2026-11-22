package e2ee

import (
	"crypto/rand"
	"io"
	"net"
	"testing"
)

func TestHandshakeAndFraming(t *testing.T) {
	psk := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, psk)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	errCh := make(chan error, 1)
	var guestConn *Conn
	go func() {
		var err error
		guestConn, err = GuestHandshake(c2, psk)
		errCh <- err
	}()

	hostConn, err := HostHandshake(c1, psk)
	if err != nil {
		t.Fatalf("host handshake failed: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("guest handshake failed: %v", err)
	}

	type sample struct {
		Msg string `json:"msg"`
		N   int    `json:"n"`
	}
	go func() {
		_ = hostConn.WriteJSON(sample{Msg: "hello ubuntu 20.04", N: 42})
	}()
	var got sample
	if err := guestConn.ReadJSON(&got); err != nil {
		t.Fatalf("guest read failed: %v", err)
	}
	if got.Msg != "hello ubuntu 20.04" || got.N != 42 {
		t.Fatalf("unexpected payload: %+v", got)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	psk1 := make([]byte, 32)
	psk2 := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, psk1)
	_, _ = io.ReadFull(rand.Reader, psk2)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	done := make(chan error, 1)
	go func() {
		_, err := GuestHandshake(c2, psk2)
		done <- err
	}()
	if _, err := HostHandshake(c1, psk1); err == nil {
		t.Fatal("expected host handshake to reject wrong PSK")
	}
	_ = c1.Close()
	<-done
}
