package main

import (
	"net"
	"testing"
	"time"
)

// Regression test: if second peer fails after pairing, waitAsFirst MUST unblock cleanly via finish().
func TestWaitAsFirstUnblocksOnFinish(t *testing.T) {
	rs := newRelayServer("/dev/null", "00", 2*time.Minute)
	c1, c1Peer := net.Pipe()
	defer c1Peer.Close()

	s := &session{
		ID:          "test1",
		HostDigest:  "h",
		GuestDigest: "g",
		DLDigest:    "d",
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(2 * time.Minute),
		firstConn:   c1,
		pairedCh:    make(chan struct{}),
		firstDoneCh: make(chan struct{}),
		relayDoneCh: make(chan struct{}),
	}
	rs.sessions[s.ID] = s

	done := make(chan struct{})
	go func() {
		rs.waitAsFirst(s, c1)
		close(done)
	}()

	// Simulate second peer pairing, reading 'R' on peer 1, then failing before splice starts.
	close(s.pairedCh)
	buf := make([]byte, 1)
	if _, err := c1Peer.Read(buf); err != nil || buf[0] != 'R' {
		t.Fatalf("expected 'R' byte on first peer, got %q err=%v", buf, err)
	}
	<-s.firstDoneCh

	// Now simulate second peer failing to write its 'R' and calling cleanupSession.
	rs.cleanupSession(s)

	select {
	case <-done:
		// Passed! waitAsFirst exited cleanly with zero goroutine leak.
	case <-time.After(2 * time.Second):
		t.Fatal("waitAsFirst deadlocked / leaked goroutine after cleanupSession")
	}
}
