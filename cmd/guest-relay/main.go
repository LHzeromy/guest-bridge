package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	maxPendingSessions = 16
	maxActiveSessions  = 8
	maxTunnelLifetime  = 4 * time.Hour
	tunnelIdleTimeout  = 30 * time.Minute
)

type session struct {
	ID          string
	Target      string
	AgentFile   string
	HostDigest  string
	GuestDigest string
	DLDigest    string
	CreatedAt   time.Time
	ExpiresAt   time.Time

	mu          sync.Mutex
	hostUsed    bool
	guestUsed   bool
	dlCount     int
	paired      bool
	closed      bool
	firstConn   net.Conn
	secondConn  net.Conn
	pairedCh    chan struct{}
	firstDoneCh chan struct{}
	relayDoneCh chan struct{}
	finishOnce  sync.Once
}

func (s *session) finish() {
	s.finishOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		c1, c2 := s.firstConn, s.secondConn
		s.mu.Unlock()
		if c1 != nil {
			_ = c1.Close()
		}
		if c2 != nil {
			_ = c2.Close()
		}
		close(s.relayDoneCh)
	})
}

var targetFiles = map[string]string{
	"linux-amd64":   "guest-agent-linux-amd64",
	"linux-arm64":   "guest-agent-linux-arm64",
	"windows-amd64": "guest-agent-windows-amd64.exe",
}

type relayServer struct {
	mu           sync.Mutex
	sessions     map[string]*session
	byHostDigest map[string]*session
	byGuestDig   map[string]*session
	byDLDigest   map[string]*session
	binDir       string
	certSHA256   string
	pairTimeout  time.Duration
}

func newRelayServer(binDir, certSHA256 string, pairTimeout time.Duration) *relayServer {
	rs := &relayServer{
		sessions:     make(map[string]*session),
		byHostDigest: make(map[string]*session),
		byGuestDig:   make(map[string]*session),
		byDLDigest:   make(map[string]*session),
		binDir:       binDir,
		certSHA256:   certSHA256,
		pairTimeout:  pairTimeout,
	}
	go rs.sweeper()
	return rs
}

func sha256HexStr(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func (rs *relayServer) removeLocked(s *session) {
	delete(rs.sessions, s.ID)
	delete(rs.byHostDigest, s.HostDigest)
	delete(rs.byGuestDig, s.GuestDigest)
	delete(rs.byDLDigest, s.DLDigest)
}

func (rs *relayServer) cleanupSession(s *session) {
	s.finish()
	rs.mu.Lock()
	rs.removeLocked(s)
	rs.mu.Unlock()
}

func (rs *relayServer) sweeper() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		var expired []*session
		rs.mu.Lock()
		for _, s := range rs.sessions {
			s.mu.Lock()
			isExp := (!s.paired && now.After(s.ExpiresAt)) || s.closed || (s.paired && now.Sub(s.CreatedAt) > maxTunnelLifetime)
			s.mu.Unlock()
			if isExp {
				expired = append(expired, s)
				rs.removeLocked(s)
			}
		}
		rs.mu.Unlock()
		for _, s := range expired {
			s.finish()
		}
	}
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (rs *relayServer) handleAdminSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	if target == "" {
		target = "linux-amd64"
	}
	fname, ok := targetFiles[target]
	if !ok {
		http.Error(w, "unsupported target", http.StatusBadRequest)
		return
	}
	agentPath := filepath.Join(rs.binDir, fname)
	agentHash, err := fileSHA256(agentPath)
	if err != nil {
		http.Error(w, "agent binary missing for "+target, http.StatusInternalServerError)
		return
	}

	rs.mu.Lock()
	pending, active := 0, 0
	for _, s := range rs.sessions {
		s.mu.Lock()
		if !s.closed {
			if s.paired {
				active++
			} else {
				pending++
			}
		}
		s.mu.Unlock()
	}
	if pending >= maxPendingSessions || active >= maxActiveSessions {
		rs.mu.Unlock()
		http.Error(w, "session quota exceeded", http.StatusTooManyRequests)
		return
	}

	now := time.Now()
	hostTok := randomHex(32)
	guestTok := randomHex(32)
	dlTok := randomHex(24)

	s := &session{
		ID:          randomHex(8),
		Target:      target,
		AgentFile:   agentPath,
		HostDigest:  sha256HexStr(hostTok),
		GuestDigest: sha256HexStr(guestTok),
		DLDigest:    sha256HexStr(dlTok),
		CreatedAt:   now,
		ExpiresAt:   now.Add(rs.pairTimeout),
		pairedCh:    make(chan struct{}),
		firstDoneCh: make(chan struct{}),
		relayDoneCh: make(chan struct{}),
	}
	rs.sessions[s.ID] = s
	rs.byHostDigest[s.HostDigest] = s
	rs.byGuestDig[s.GuestDigest] = s
	rs.byDLDigest[s.DLDigest] = s
	rs.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"session_id":   s.ID,
		"target":       target,
		"host_token":   hostTok,
		"guest_token":  guestTok,
		"dl_token":     dlTok,
		"expires_at":   s.ExpiresAt.Format(time.RFC3339),
		"ttl_sec":      int(rs.pairTimeout.Seconds()),
		"cert_sha256":  rs.certSHA256,
		"agent_sha256": agentHash,
	})
}

func (rs *relayServer) handleAdminHealth(w http.ResponseWriter, r *http.Request) {
	rs.mu.Lock()
	pending, active := 0, 0
	for _, s := range rs.sessions {
		s.mu.Lock()
		if !s.closed {
			if s.paired {
				active++
			} else {
				pending++
			}
		}
		s.mu.Unlock()
	}
	rs.mu.Unlock()

	targets := make(map[string]string)
	for t, fname := range targetFiles {
		if h, err := fileSHA256(filepath.Join(rs.binDir, fname)); err == nil {
			targets[t] = h
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":          true,
		"pending":     pending,
		"active":      active,
		"cert_sha256": rs.certSHA256,
		"targets":     targets,
	})
}

func (rs *relayServer) handlePublic(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/dl/") && r.Method == http.MethodGet {
		rs.handleDownload(w, r, strings.TrimPrefix(r.URL.Path, "/dl/"))
		return
	}
	if strings.HasPrefix(r.URL.Path, "/tunnel/host/") {
		rs.handleTunnel(w, r, "host", strings.TrimPrefix(r.URL.Path, "/tunnel/host/"))
		return
	}
	if strings.HasPrefix(r.URL.Path, "/tunnel/guest/") {
		rs.handleTunnel(w, r, "guest", strings.TrimPrefix(r.URL.Path, "/tunnel/guest/"))
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func (rs *relayServer) handleDownload(w http.ResponseWriter, r *http.Request, tok string) {
	if len(tok) != 48 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	dig := sha256HexStr(tok)
	now := time.Now()
	var agentFile string
	rs.mu.Lock()
	if s := rs.byDLDigest[dig]; s != nil {
		s.mu.Lock()
		if !s.closed && now.Before(s.ExpiresAt) && s.dlCount < 2 {
			s.dlCount++
			agentFile = s.AgentFile
			if s.dlCount >= 2 {
				delete(rs.byDLDigest, dig)
			}
		}
		s.mu.Unlock()
	}
	rs.mu.Unlock()

	if agentFile == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	f, err := os.Open(agentFile)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fi.Size()))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, f)
}

func (rs *relayServer) handleTunnel(w http.ResponseWriter, r *http.Request, role, tok string) {
	if len(tok) != 64 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	dig := sha256HexStr(tok)
	now := time.Now()
	var matched *session

	rs.mu.Lock()
	var s *session
	if role == "host" {
		s = rs.byHostDigest[dig]
	} else {
		s = rs.byGuestDig[dig]
	}
	if s != nil {
		s.mu.Lock()
		valid := !s.closed && now.Before(s.ExpiresAt)
		if valid && role == "host" && !s.hostUsed {
			s.hostUsed = true
			delete(rs.byHostDigest, dig)
			matched = s
		} else if valid && role == "guest" && !s.guestUsed {
			s.guestUsed = true
			delete(rs.byGuestDig, dig)
			matched = s
		}
		s.mu.Unlock()
	}
	rs.mu.Unlock()

	if matched == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		rs.cleanupSession(matched)
		return
	}
	_ = conn.SetDeadline(time.Time{})

	if _, err := buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: guest-bridge\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		_ = conn.Close()
		rs.cleanupSession(matched)
		return
	}
	if err := buf.Flush(); err != nil {
		_ = conn.Close()
		rs.cleanupSession(matched)
		return
	}

	// Always lock rs.mu BEFORE session.mu to guarantee consistent global lock ordering.
	rs.mu.Lock()
	matched.mu.Lock()
	if matched.closed {
		matched.mu.Unlock()
		rs.mu.Unlock()
		_ = conn.Close()
		return
	}
	if matched.firstConn == nil {
		matched.firstConn = conn
		matched.mu.Unlock()
		rs.mu.Unlock()
		rs.waitAsFirst(matched, conn)
		return
	}

	// Second side arrived: enforce hard active session quota atomically under rs.mu!
	active := 0
	for _, s := range rs.sessions {
		if s == matched {
			continue
		}
		s.mu.Lock()
		if s.paired && !s.closed {
			active++
		}
		s.mu.Unlock()
	}
	if active >= maxActiveSessions {
		matched.mu.Unlock()
		rs.mu.Unlock()
		_ = conn.Close()
		rs.cleanupSession(matched)
		return
	}
	matched.secondConn = conn
	firstConn := matched.firstConn
	matched.paired = true
	close(matched.pairedCh)
	matched.mu.Unlock()
	rs.mu.Unlock()

	select {
	case <-matched.firstDoneCh:
	case <-time.After(10 * time.Second):
		rs.cleanupSession(matched)
		return
	}

	// Ensure first side didn't fail while writing 'R'.
	matched.mu.Lock()
	alreadyClosed := matched.closed
	matched.mu.Unlock()
	if alreadyClosed {
		rs.cleanupSession(matched)
		return
	}

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte{'R'})
	_ = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		// Guaranteed to unblock waitAsFirst via finish() closing relayDoneCh!
		rs.cleanupSession(matched)
		return
	}

	rs.splice(matched, firstConn, conn)
}

func (rs *relayServer) waitAsFirst(s *session, conn net.Conn) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	timer := time.NewTimer(time.Until(s.ExpiresAt))
	defer timer.Stop()

	for {
		select {
		case <-s.pairedCh:
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err := conn.Write([]byte{'R'})
			_ = conn.SetWriteDeadline(time.Time{})
			if err != nil {
				rs.cleanupSession(s)
				close(s.firstDoneCh)
				return
			}
			close(s.firstDoneCh)
			<-s.relayDoneCh
			return
		case <-s.relayDoneCh:
			return
		case <-ticker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err := conn.Write([]byte{'.'})
			_ = conn.SetWriteDeadline(time.Time{})
			if err != nil {
				rs.cleanupSession(s)
				return
			}
		case <-timer.C:
			rs.cleanupSession(s)
			return
		}
	}
}

func (rs *relayServer) splice(s *session, a, b net.Conn) {
	defer rs.cleanupSession(s)

	// Enforce hard max tunnel lifetime.
	lifeTimer := time.AfterFunc(maxTunnelLifetime, func() {
		rs.cleanupSession(s)
	})
	defer lifeTimer.Stop()

	copyWithIdle := func(dst, src net.Conn) {
		buf := make([]byte, 32*1024)
		for {
			_ = src.SetReadDeadline(time.Now().Add(tunnelIdleTimeout))
			n, rerr := src.Read(buf)
			if n > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyWithIdle(a, b)
		s.finish()
	}()
	go func() {
		defer wg.Done()
		copyWithIdle(b, a)
		s.finish()
	}()
	wg.Wait()
}

func ensureCert(certPath, keyPath, ipStr string) (tls.Certificate, string, error) {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
			return tls.Certificate{}, "", err
		}
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return tls.Certificate{}, "", err
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: ipStr},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			IPAddresses:  []net.IP{net.ParseIP(ipStr)},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
		if err != nil {
			return tls.Certificate{}, "", err
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyDER, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return tls.Certificate{}, "", err
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			return tls.Certificate{}, "", err
		}
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			return tls.Certificate{}, "", err
		}
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return cert, hex.EncodeToString(sum[:]), nil
}

func main() {
	pubAddr := flag.String("addr", ":34434", "public TLS listen address")
	adminSock := flag.String("admin-sock", "/run/guest-relay/admin.sock", "private Unix socket path for admin API (0600)")
	publicIP := flag.String("ip", "", "server public IP for self-signed cert SAN (required on first run)")
	dataDir := flag.String("data", "/var/lib/guest-relay", "directory for TLS cert and guest binaries")
	pairTTL := flag.Duration("ttl", 10*time.Minute, "one-time pairing token TTL")
	flag.Parse()

	if *adminSock == "" {
		log.Fatal("admin-sock is required")
	}
	if *publicIP == "" {
		*publicIP = "127.0.0.1"
	}

	certPath := filepath.Join(*dataDir, "cert.pem")
	keyPath := filepath.Join(*dataDir, "key.pem")
	binDir := filepath.Join(*dataDir, "bin")

	cert, certHash, err := ensureCert(certPath, keyPath, *publicIP)
	if err != nil {
		log.Fatalf("cert setup failed: %v", err)
	}
	log.Printf("guest-relay starting: pub=%s admin_sock=%s cert_sha256=%s", *pubAddr, *adminSock, certHash)

	rs := newRelayServer(binDir, certHash, *pairTTL)

	// Private Unix socket admin API (blocks all other local services & Docker containers)
	if err := os.MkdirAll(filepath.Dir(*adminSock), 0750); err != nil {
		log.Fatalf("mkdir admin sock dir: %v", err)
	}
	_ = os.Remove(*adminSock)
	adminLn, err := net.Listen("unix", *adminSock)
	if err != nil {
		log.Fatalf("listen admin sock: %v", err)
	}
	if err := os.Chmod(*adminSock, 0600); err != nil {
		log.Fatalf("chmod admin sock: %v", err)
	}
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/admin/session", rs.handleAdminSession)
	adminMux.HandleFunc("/admin/health", rs.handleAdminHealth)
	go func() {
		srv := &http.Server{
			Handler:           adminMux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		if err := srv.Serve(adminLn); err != nil {
			log.Fatalf("admin serve error: %v", err)
		}
	}()

	pubTLS := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}
	ln, err := tls.Listen("tcp", *pubAddr, pubTLS)
	if err != nil {
		log.Fatalf("public TLS listen error: %v", err)
	}
	pubSrv := &http.Server{
		Handler:           http.HandlerFunc(rs.handlePublic),
		ReadHeaderTimeout: 10 * time.Second,
		TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	if err := pubSrv.Serve(ln); err != nil {
		log.Fatalf("public serve error: %v", err)
	}
}
