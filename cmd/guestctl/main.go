package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	e2ee "guest-bridge/internal/crypto"
	"guest-bridge/internal/proto"
)

var (
	reSSHHost   = regexp.MustCompile(`^[a-zA-Z0-9._@-]+$`)
	reAdminUser = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	reAdminSock = regexp.MustCompile(`^/[a-zA-Z0-9._/-]+$`)
	reRelayHost = regexp.MustCompile(`^[a-zA-Z0-9.:-]+$`)
)

func validatePairInputs(sshHost, relayAddr, adminUser, adminSock string) error {
	if sshHost == "" || strings.HasPrefix(sshHost, "-") || !reSSHHost.MatchString(sshHost) {
		return fmt.Errorf("invalid ssh_host: %q", sshHost)
	}
	if !reAdminUser.MatchString(adminUser) {
		return fmt.Errorf("invalid admin_user: %q", adminUser)
	}
	if !reAdminSock.MatchString(adminSock) || strings.Contains(adminSock, "..") {
		return fmt.Errorf("invalid admin_sock: %q", adminSock)
	}
	host, port, err := net.SplitHostPort(relayAddr)
	if err != nil || host == "" || port == "" || !reRelayHost.MatchString(host) {
		return fmt.Errorf("invalid relay_addr (expected host:port): %q", relayAddr)
	}
	return nil
}

func configPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "guestctl", "config.json")
}

type localConfig struct {
	SSHHost   string `json:"ssh_host"`
	RelayAddr string `json:"relay_addr"`
	AdminSock string `json:"admin_sock"`
	AdminUser string `json:"admin_user"`
}

func loadLocalConfig() (localConfig, error) {
	cfg := localConfig{
		AdminSock: "/run/guest-relay/admin.sock",
		AdminUser: "guest-relay",
	}
	p := configPath()
	fi, err := os.Stat(p)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("stat config %s: %w", p, err)
	}
	if fi.Mode().Perm()&0077 != 0 {
		return cfg, fmt.Errorf("config %s has overly broad permissions (%04o); run chmod 600 %s", p, fi.Mode().Perm(), p)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return cfg, fmt.Errorf("read config %s: %w", p, err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", p, err)
	}
	return cfg, nil
}

func dataRoot() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "guestctl")
}

func currentSockPath() string {
	return filepath.Join(dataRoot(), "current.sock")
}

func normalizeTarget(osFlag string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(osFlag)) {
	case "", "linux", "ubuntu", "linux-amd64", "amd64":
		return "linux-amd64", nil
	case "arm64", "linux-arm64", "jetson", "pi", "termux":
		return "linux-arm64", nil
	case "win", "windows", "windows-amd64":
		return "windows-amd64", nil
	default:
		return "", fmt.Errorf("不支持的目标平台 %q（可选: linux | linux-arm64 | windows）", osFlag)
	}
}

func pinnedAgentHashPath(target string) string {
	return filepath.Join(dataRoot(), "agent-"+target+".sha256")
}

type relaySessionResp struct {
	SessionID   string `json:"session_id"`
	HostToken   string `json:"host_token"`
	GuestToken  string `json:"guest_token"`
	DLToken     string `json:"dl_token"`
	ExpiresAt   string `json:"expires_at"`
	TTLSec      int    `json:"ttl_sec"`
	CertSHA256  string `json:"cert_sha256"`
	AgentSHA256 string `json:"agent_sha256"`
}

type daemonCreds struct {
	HostToken string `json:"host_token"`
	KeyHex    string `json:"key_hex"`
}

type daemonStatus struct {
	State      string            `json:"state"`
	Error      string            `json:"error,omitempty"`
	SessionID  string            `json:"session_id"`
	SessionDir string            `json:"session_dir"`
	RelayAddr  string            `json:"relay_addr"`
	StartedAt  string            `json:"started_at"`
	Connected  string            `json:"connected_at,omitempty"`
	Guest      *proto.GuestHello `json:"guest,omitempty"`
	ReqCount   int64             `json:"req_count"`
}

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func isStrictHex(s string, exactLen int) bool {
	if len(s) != exactLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// reorderFlags moves -flag / --flag (and their values) ahead of positional arguments so Go's flag.FlagSet
// works naturally regardless of whether users type `guestctl read /path --start 1` or `guestctl read --start 1 /path`.
func reorderFlags(args []string, valueFlags map[string]bool) []string {
	var flagsPart, posPart []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			posPart = append(posPart, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			flagsPart = append(flagsPart, a)
			name := strings.TrimLeft(a, "-")
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				continue
			}
			if valueFlags[name] && i+1 < len(args) {
				i++
				flagsPart = append(flagsPart, args[i])
			}
		} else {
			posPart = append(posPart, a)
		}
	}
	return append(flagsPart, posPart...)
}

// ---------------- DAEMON (runs in background on controller host) ----------------

type bridgeDaemon struct {
	sessionID  string
	sessionDir string
	relayAddr  string
	certPin    string
	hostToken  string
	psk        []byte
	startedAt  time.Time

	mu          sync.Mutex
	state       string
	lastErr     string
	connectedAt time.Time
	guest       *proto.GuestHello
	conn        *e2ee.Conn
	pending     map[string]chan proto.Message
	auditFile   *os.File
	reqSeq      atomic.Int64
	diffSeq     atomic.Int64
	shotSeq     atomic.Int64
	shutdownCh  chan struct{}
	shutOnce    sync.Once
}

func (d *bridgeDaemon) triggerShutdown() {
	d.shutOnce.Do(func() {
		close(d.shutdownCh)
	})
}

func (d *bridgeDaemon) writeAudit(entry map[string]any) {
	entry["ts"] = time.Now().Format(time.RFC3339)
	b, err := json.Marshal(entry)
	if err != nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.auditFile != nil {
		if _, err := d.auditFile.Write(append(b, '\n')); err != nil {
			fmt.Fprintf(os.Stderr, "audit write error: %v\n", err)
		}
	}
}

func (d *bridgeDaemon) setState(state, errMsg string) {
	d.mu.Lock()
	d.state = state
	d.lastErr = errMsg
	d.mu.Unlock()
}

func (d *bridgeDaemon) getStatus() daemonStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := daemonStatus{
		State:      d.state,
		Error:      d.lastErr,
		SessionID:  d.sessionID,
		SessionDir: d.sessionDir,
		RelayAddr:  d.relayAddr,
		StartedAt:  d.startedAt.Format(time.RFC3339),
		ReqCount:   d.reqSeq.Load(),
	}
	if !d.connectedAt.IsZero() {
		st.Connected = d.connectedAt.Format(time.RFC3339)
	}
	if d.guest != nil {
		cp := *d.guest
		st.Guest = &cp
	}
	return st
}

func (d *bridgeDaemon) runRelayLoop() {
	tlsCfg, err := e2ee.PinnedTLSConfig(d.certPin)
	if err != nil {
		d.setState("error", err.Error())
		return
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	rawConn, err := tls.DialWithDialer(dialer, "tcp", d.relayAddr, tlsCfg)
	if err != nil {
		d.setState("error", "dial relay: "+err.Error())
		return
	}
	reqLine := fmt.Sprintf("GET /tunnel/host/%s HTTP/1.1\r\nHost: %s\r\nUpgrade: guest-bridge\r\nConnection: Upgrade\r\n\r\n", d.hostToken, d.relayAddr)
	if _, err := rawConn.Write([]byte(reqLine)); err != nil {
		_ = rawConn.Close()
		d.setState("error", "write upgrade: "+err.Error())
		return
	}
	br := bufio.NewReader(rawConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = rawConn.Close()
		d.setState("error", "read upgrade resp: "+err.Error())
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = rawConn.Close()
		d.setState("error", fmt.Sprintf("relay rejected host: HTTP %d", resp.StatusCode))
		return
	}

	d.setState("waiting_guest", "")
	d.writeAudit(map[string]any{"event": "waiting_guest", "session_id": d.sessionID})

	for {
		b, err := br.ReadByte()
		if err != nil {
			_ = rawConn.Close()
			d.setState("closed", "waiting_guest ended: "+err.Error())
			d.triggerShutdown()
			return
		}
		if b == '.' {
			continue
		}
		if b == 'R' {
			break
		}
		_ = rawConn.Close()
		d.setState("error", fmt.Sprintf("unexpected relay byte: 0x%02x", b))
		d.triggerShutdown()
		return
	}

	stream := &bufferedConn{Conn: rawConn, r: br}
	ec, err := e2ee.HostHandshake(stream, d.psk)
	if err != nil {
		_ = rawConn.Close()
		d.setState("error", "E2EE handshake failed: "+err.Error())
		d.triggerShutdown()
		return
	}

	var helloMsg proto.Message
	if err := ec.ReadJSON(&helloMsg); err != nil {
		_ = ec.Close()
		d.setState("error", "read guest hello: "+err.Error())
		d.triggerShutdown()
		return
	}
	var gh proto.GuestHello
	_ = json.Unmarshal(helloMsg.Payload, &gh)

	d.mu.Lock()
	d.conn = ec
	d.guest = &gh
	d.connectedAt = time.Now()
	d.state = "connected"
	d.lastErr = ""
	d.mu.Unlock()

	metaBytes, _ := json.MarshalIndent(d.getStatus(), "", "  ")
	if err := os.WriteFile(filepath.Join(d.sessionDir, "meta.json"), metaBytes, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "write meta.json failed: %v\n", err)
	}
	d.writeAudit(map[string]any{"event": "guest_connected", "guest": gh})

	go func() {
		t := time.NewTicker(20 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-d.shutdownCh:
				return
			case <-t.C:
				if _, err := d.sendRPC("ping", nil, 10*time.Second); err != nil {
					return
				}
			}
		}
	}()

	for {
		var msg proto.Message
		if err := ec.ReadJSON(&msg); err != nil {
			d.mu.Lock()
			for id, ch := range d.pending {
				close(ch)
				delete(d.pending, id)
			}
			d.state = "closed"
			if !errors.Is(err, io.EOF) {
				d.lastErr = err.Error()
			}
			d.mu.Unlock()
			d.writeAudit(map[string]any{"event": "guest_disconnected", "reason": d.lastErr})
			d.triggerShutdown()
			return
		}
		if msg.Kind == "resp" && msg.ID != "" {
			d.mu.Lock()
			ch := d.pending[msg.ID]
			delete(d.pending, msg.ID)
			d.mu.Unlock()
			if ch != nil {
				ch <- msg
			}
		}
	}
}

func (d *bridgeDaemon) sendRPC(action string, payload any, timeout time.Duration) (proto.Message, error) {
	d.mu.Lock()
	ec := d.conn
	st := d.state
	d.mu.Unlock()
	if ec == nil || st != "connected" {
		return proto.Message{}, fmt.Errorf("guest not connected (state=%s)", st)
	}

	id := fmt.Sprintf("r%d", d.reqSeq.Add(1))
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return proto.Message{}, err
		}
		raw = b
	}

	ch := make(chan proto.Message, 1)
	d.mu.Lock()
	d.pending[id] = ch
	d.mu.Unlock()

	err := ec.WriteJSON(proto.Message{
		ID:      id,
		Kind:    "req",
		Action:  action,
		Payload: raw,
	})
	if err != nil {
		d.mu.Lock()
		delete(d.pending, id)
		d.mu.Unlock()
		return proto.Message{}, err
	}

	select {
	case resp, ok := <-ch:
		if !ok {
			return proto.Message{}, errors.New("connection closed while waiting for response")
		}
		return resp, nil
	case <-time.After(timeout):
		d.mu.Lock()
		delete(d.pending, id)
		d.mu.Unlock()
		return proto.Message{}, fmt.Errorf("RPC %s timed out after %v", action, timeout)
	}
}

func (d *bridgeDaemon) handleLocalHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/status":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(d.getStatus())
		return
	case "/close":
		_, _ = d.sendRPC("close", nil, 3*time.Second)
		d.mu.Lock()
		if d.conn != nil {
			_ = d.conn.Close()
		}
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "session_dir": d.sessionDir})
		go func() {
			time.Sleep(150 * time.Millisecond)
			d.triggerShutdown()
		}()
		return
	case "/rpc":
		r.Body = http.MaxBytesReader(w, r.Body, 4*1024*1024)
		var req struct {
			Action     string          `json:"action"`
			Payload    json.RawMessage `json:"payload"`
			TimeoutSec int             `json:"timeout_sec"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		timeout := time.Duration(req.TimeoutSec) * time.Second
		if timeout <= 0 {
			timeout = 5 * time.Minute
		}
		resp, err := d.sendRPC(req.Action, req.Payload, timeout)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(proto.Message{OK: false, Error: err.Error(), Action: req.Action})
			return
		}
		d.archiveRPC(req.Action, req.Payload, &resp)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *bridgeDaemon) archiveRPC(action string, reqPayload json.RawMessage, resp *proto.Message) {
	switch action {
	case "edit_file", "write_file":
		var mr proto.ModifyFileResp
		if resp.OK && json.Unmarshal(resp.Payload, &mr) == nil && mr.Approved {
			idx := d.diffSeq.Add(1)
			diffsDir := filepath.Join(d.sessionDir, "diffs")
			_ = os.MkdirAll(diffsDir, 0700)
			safeName := strings.NewReplacer("/", "_", " ", "_").Replace(filepath.Base(mr.Path))
			prefix := filepath.Join(diffsDir, fmt.Sprintf("%03d_%s", idx, safeName))
			if err := os.WriteFile(prefix+".diff", []byte(mr.Diff), 0600); err != nil {
				fmt.Fprintf(os.Stderr, "archive diff failed: %v\n", err)
			}
			if mr.BeforeContent != "" {
				if err := os.WriteFile(prefix+".before", []byte(mr.BeforeContent), 0600); err != nil {
					fmt.Fprintf(os.Stderr, "archive backup failed: %v\n", err)
				}
			}
			d.writeAudit(map[string]any{
				"action":    action,
				"path":      mr.Path,
				"approved":  true,
				"diff_file": prefix + ".diff",
				"bytes":     mr.BytesWritten,
			})
			return
		}
		d.writeAudit(map[string]any{"action": action, "ok": resp.OK, "error": resp.Error, "approved": false})
	case "screenshot":
		var sr proto.ScreenshotResp
		if resp.OK && json.Unmarshal(resp.Payload, &sr) == nil && sr.Approved && sr.PNGBase64 != "" {
			if pngData, err := base64.StdEncoding.DecodeString(sr.PNGBase64); err == nil {
				idx := d.shotSeq.Add(1)
				shotsDir := filepath.Join(d.sessionDir, "screenshots")
				_ = os.MkdirAll(shotsDir, 0700)
				shotPath := filepath.Join(shotsDir, fmt.Sprintf("shot_%03d_%s.png", idx, time.Now().Format("150405")))
				if err := os.WriteFile(shotPath, pngData, 0600); err != nil {
					resp.OK = false
					resp.Error = "failed to save screenshot locally: " + err.Error()
					return
				}
				slim, _ := json.Marshal(map[string]any{
					"approved":   true,
					"tool":       sr.Tool,
					"saved_path": shotPath,
					"bytes":      len(pngData),
				})
				resp.Payload = slim
				d.writeAudit(map[string]any{"action": "screenshot", "approved": true, "saved_path": shotPath, "bytes": len(pngData)})
				return
			}
		}
		d.writeAudit(map[string]any{"action": "screenshot", "ok": resp.OK, "error": resp.Error})
	default:
		d.writeAudit(map[string]any{
			"action": action,
			"req":    string(reqPayload),
			"ok":     resp.OK,
			"error":  resp.Error,
		})
	}
}

func runDaemon(args []string) {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	sid := fs.String("sid", "", "session id")
	sdir := fs.String("dir", "", "session dir")
	relay := fs.String("relay", "", "relay addr")
	pin := fs.String("pin", "", "relay cert sha256")
	_ = fs.Parse(args)

	// Read secrets strictly from private stdin pipe (never exposed in /proc/<pid>/environ or argv).
	var creds daemonCreds
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 4096)).Decode(&creds); err != nil {
		fmt.Fprintf(os.Stderr, "daemon: failed reading credentials pipe: %v\n", err)
		os.Exit(2)
	}
	psk, err := hex.DecodeString(creds.KeyHex)
	if err != nil || len(psk) != 32 || !isStrictHex(creds.HostToken, 64) || *sid == "" || *sdir == "" {
		fmt.Fprintln(os.Stderr, "daemon: invalid credentials")
		os.Exit(2)
	}

	_ = os.MkdirAll(*sdir, 0700)
	auditF, err := os.OpenFile(filepath.Join(*sdir, "session.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open audit log: %v\n", err)
		os.Exit(1)
	}

	d := &bridgeDaemon{
		sessionID:  *sid,
		sessionDir: *sdir,
		relayAddr:  *relay,
		certPin:    *pin,
		hostToken:  creds.HostToken,
		psk:        psk,
		startedAt:  time.Now(),
		state:      "connecting",
		pending:    make(map[string]chan proto.Message),
		auditFile:  auditF,
		shutdownCh: make(chan struct{}),
	}

	sock := currentSockPath()
	_ = os.MkdirAll(filepath.Dir(sock), 0700)
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen unix sock: %v\n", err)
		os.Exit(1)
	}
	if err := os.Chmod(sock, 0600); err != nil {
		_ = ln.Close()
		_ = os.Remove(sock)
		fmt.Fprintf(os.Stderr, "chmod unix sock: %v\n", err)
		os.Exit(1)
	}

	srv := &http.Server{Handler: http.HandlerFunc(d.handleLocalHTTP)}
	go func() { _ = srv.Serve(ln) }()
	go d.runRelayLoop()

	<-d.shutdownCh
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	_ = os.Remove(sock)
	_ = auditF.Close()
}

// ---------------- CLIENT CLI (invoked on controller host) ----------------

func localClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", currentSockPath(), 3*time.Second)
			},
		},
	}
}

func getLocalStatus() (daemonStatus, error) {
	var st daemonStatus
	resp, err := localClient().Get("http://unix/status")
	if err != nil {
		return st, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&st)
	return st, err
}

func callLocalRPC(action string, payload any, timeoutSec int) (proto.Message, error) {
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return proto.Message{}, err
		}
		raw = b
	}
	body, _ := json.Marshal(map[string]any{
		"action":      action,
		"payload":     raw,
		"timeout_sec": timeoutSec,
	})
	resp, err := localClient().Post("http://unix/rpc", "application/json", bytes.NewReader(body))
	if err != nil {
		return proto.Message{}, fmt.Errorf("未检测到活跃联调会话（请先在本地终端运行 guestctl pair）: %w", err)
	}
	defer resp.Body.Close()
	var msg proto.Message
	if err := json.NewDecoder(resp.Body).Decode(&msg); err != nil {
		return proto.Message{}, err
	}
	return msg, nil
}

func loadLocalPinnedAgentHash(target string) (string, error) {
	p := pinnedAgentHashPath(target)
	b, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("missing local pinned agent sha256 (%s): %w", p, err)
	}
	h := strings.ToLower(strings.TrimSpace(string(b)))
	if !isStrictHex(h, 64) {
		return "", fmt.Errorf("invalid local pinned agent sha256: %q", h)
	}
	return h, nil
}

func cmdPair(args []string) {
	cfg, err := loadLocalConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "配置错误:", err)
		os.Exit(2)
	}
	args = reorderFlags(args, map[string]bool{"ssh-host": true, "relay": true, "mode": true, "os": true})
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	sshHost := fs.String("ssh-host", cfg.SSHHost, "SSH host alias for relay admin socket (or ~/.config/guestctl/config.json)")
	relayAddr := fs.String("relay", cfg.RelayAddr, "public relay TLS address host:port (or ~/.config/guestctl/config.json)")
	mode := fs.String("mode", "confirm", "suggested default permission mode: confirm | ro")
	targetOS := fs.String("os", "linux-amd64", "target OS/arch: linux | linux-arm64 | windows")
	_ = fs.Parse(args)

	if *sshHost == "" || *relayAddr == "" {
		fmt.Fprintf(os.Stderr, "请先配置 %s（设置 ssh_host 和 relay_addr），或通过 --ssh-host / --relay 传入。\n", configPath())
		os.Exit(2)
	}
	if err := validatePairInputs(*sshHost, *relayAddr, cfg.AdminUser, cfg.AdminSock); err != nil {
		fmt.Fprintln(os.Stderr, "参数校验失败:", err)
		os.Exit(2)
	}
	if *mode != "confirm" && *mode != "ro" {
		fmt.Fprintf(os.Stderr, "invalid mode %q (expected confirm|ro)\n", *mode)
		os.Exit(2)
	}
	target, err := normalizeTarget(*targetOS)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	pinnedAgentHash, err := loadLocalPinnedAgentHash(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if _, err := getLocalStatus(); err == nil {
		_, _ = localClient().Post("http://unix/close", "application/json", nil)
		time.Sleep(300 * time.Millisecond)
	}

	// Terminate ssh option parsing with "--" so sshHost cannot be parsed as an SSH option.
	remoteCmd := fmt.Sprintf("sudo -u %s curl -fsS --unix-socket %s -X POST 'http://localhost/admin/session?target=%s'", cfg.AdminUser, cfg.AdminSock, target)
	out, err := exec.Command("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "--", *sshHost, remoteCmd).CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "申请一次性配对会话失败: %v\n", err)
		os.Exit(1)
	}
	var rs relaySessionResp
	if err := json.Unmarshal(out, &rs); err != nil {
		fmt.Fprintf(os.Stderr, "解析中继响应失败: %v\n", err)
		os.Exit(1)
	}
	// Strictly validate every field returned by relay before formatting commands.
	if !isStrictHex(rs.SessionID, 16) || !isStrictHex(rs.HostToken, 64) ||
		!isStrictHex(rs.GuestToken, 64) || !isStrictHex(rs.DLToken, 48) ||
		!isStrictHex(rs.CertSHA256, 64) || !isStrictHex(rs.AgentSHA256, 64) {
		fmt.Fprintln(os.Stderr, "安全告警: 中继返回了非法格式的会话字段，已中止！")
		os.Exit(1)
	}
	if rs.AgentSHA256 != pinnedAgentHash {
		fmt.Fprintf(os.Stderr, "安全告警: 中继端 guest-agent 哈希 (%s) 与本机固定哈希 (%s) 不一致，已中止！\n", rs.AgentSHA256, pinnedAgentHash)
		os.Exit(1)
	}

	// Generate 256-bit E2EE key locally on controller host (never sent to relay).
	psk := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		panic(err)
	}
	keyHex := hex.EncodeToString(psk)

	sdir := filepath.Join(dataRoot(), "sessions", fmt.Sprintf("%s_%s", time.Now().Format("20060102_150405"), rs.SessionID[:8]))
	_ = os.MkdirAll(sdir, 0700)

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "executable path error: %v\n", err)
		os.Exit(1)
	}
	logF, err := os.OpenFile(filepath.Join(sdir, "daemon.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open daemon log: %v\n", err)
		os.Exit(1)
	}
	cmd := exec.Command(exe, "daemon",
		"-sid", rs.SessionID,
		"-dir", sdir,
		"-relay", *relayAddr,
		"-pin", rs.CertSHA256,
	)
	credsJSON, _ := json.Marshal(daemonCreds{HostToken: rs.HostToken, KeyHex: keyHex})
	cmd.Stdin = bytes.NewReader(credsJSON)
	cmd.Stdout = logF
	cmd.Stderr = logF
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "启动本机守护进程失败: %v\n", err)
		os.Exit(1)
	}
	_ = logF.Close()

	ready := false
	for i := 0; i < 40; i++ {
		time.Sleep(250 * time.Millisecond)
		st, err := getLocalStatus()
		if err == nil {
			if st.State == "waiting_guest" || st.State == "connected" {
				ready = true
				break
			}
			if st.State == "error" || st.State == "closed" {
				fmt.Fprintf(os.Stderr, "本机守护进程连接中继失败: %s\n", st.Error)
				os.Exit(1)
			}
		}
	}
	if !ready {
		fmt.Fprintln(os.Stderr, "等待本机桥接就绪超时，请查看:", filepath.Join(sdir, "daemon.log"))
		os.Exit(1)
	}

	var oneLiner string
	var targetHint string
	if target == "windows-amd64" {
		targetHint = "在目标 Windows PowerShell（Win10/Win11）中直接粘贴回车："
		// Direct PowerShell scriptblock (& { ... }) avoids nested double-quote variable expansion bugs.
		oneLiner = fmt.Sprintf(
			`& { $f = Join-Path $env:TEMP ('guest-agent-' + [guid]::NewGuid().ToString('N').Substring(0,8) + '.exe'); try { curl.exe -kfsSL 'https://%s/dl/%s' -o $f; if ((Get-FileHash $f -Algorithm SHA256).Hash.ToLower() -ne '%s') { throw 'SHA256 mismatch' }; $env:GB_TOKEN='%s'; $env:GB_KEY='%s'; & $f -relay '%s' -pin '%s' -mode '%s' } finally { Remove-Item -Force -ErrorAction SilentlyContinue $f } }`,
			*relayAddr, rs.DLToken, pinnedAgentHash, rs.GuestToken, keyHex, *relayAddr, rs.CertSHA256, *mode,
		)
	} else {
		targetHint = fmt.Sprintf("在目标 %s 终端直接粘贴回车：", target)
		oneLiner = fmt.Sprintf(
			`bash -c 'f=$(mktemp /tmp/guest-agent-XXXXXX); trap "rm -f \"$f\"" EXIT INT TERM; curl -kfsSL https://%s/dl/%s -o "$f" && echo "%s  $f" | sha256sum -c - >/dev/null && chmod 700 "$f" && GB_TOKEN=%s GB_KEY=%s "$f" -relay %s -pin %s -mode %s'`,
			*relayAddr, rs.DLToken, pinnedAgentHash, rs.GuestToken, keyHex, *relayAddr, rs.CertSHA256, *mode,
		)
	}

	fmt.Println("=== 一次性联调配对已就绪（10 分钟有效，隧道口令单次消费，端到端加密）===")
	fmt.Printf("目标平台: %s | 默认建议权限: %s（启动后由目标机所有者亲手确认选择）\n", target, *mode)
	fmt.Printf("本机归档目录: %s\n", sdir)
	fmt.Println("安全提示: 请勿把下方配对命令粘贴进云端 AI 对话框。")
	fmt.Println(targetHint)
	fmt.Println()
	fmt.Println(oneLiner)
}

func cmdStatus() {
	st, err := getLocalStatus()
	if err != nil {
		fmt.Println("状态: 无活跃会话")
		os.Exit(1)
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	fmt.Println(string(b))
}

func cmdClose() {
	resp, err := localClient().Post("http://unix/close", "application/json", nil)
	if err != nil {
		fmt.Println("当前无活跃会话。")
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	fmt.Println(strings.TrimSpace(string(b)))
}

func cmdSessions() {
	dir := filepath.Join(dataRoot(), "sessions")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		fmt.Println("暂无本地排查归档记录。")
		return
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	for _, n := range names {
		fmt.Println(filepath.Join(dir, n))
	}
}

func cmdSysInfo() {
	msg, err := callLocalRPC("sysinfo", nil, 30)
	mustOK(msg, err)
	var r proto.SysInfoResp
	_ = json.Unmarshal(msg.Payload, &r)
	fmt.Printf("Host:   %s (%s)\nOS:     %s\nKernel: %s (%s)\nCwd:    %s\n", r.Hostname, r.User, r.OSPretty, r.Kernel, r.Arch, r.Cwd)
	if r.GPU != "" {
		fmt.Printf("GPU:\n%s\n", r.GPU)
	}
	fmt.Printf("Memory:\n%s\nDisk:\n%s\n", r.Memory, r.Disk)
}

func cmdRead(args []string) {
	args = reorderFlags(args, map[string]bool{"start": true, "end": true})
	fs := flag.NewFlagSet("read", flag.ExitOnError)
	start := fs.Int("start", 1, "start line (1-based)")
	end := fs.Int("end", 0, "end line (0 = all within limit)")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: guestctl read [--start N] [--end M] <path>")
		os.Exit(2)
	}
	msg, err := callLocalRPC("read_file", proto.ReadFileReq{
		Path: fs.Arg(0), StartLine: *start, EndLine: *end,
	}, 30)
	mustOK(msg, err)
	var r proto.ReadFileResp
	_ = json.Unmarshal(msg.Payload, &r)
	fmt.Printf("=== %s (L%d-L%d / %d, truncated=%v) ===\n%s\n", r.Path, r.StartLine, r.EndLine, r.TotalLines, r.Truncated, r.Content)
}

func cmdLs(args []string) {
	args = reorderFlags(args, map[string]bool{"depth": true})
	fs := flag.NewFlagSet("ls", flag.ExitOnError)
	depth := fs.Int("depth", 1, "walk depth 1..3")
	_ = fs.Parse(args)
	if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "usage: guestctl ls [--depth N] [path]")
		os.Exit(2)
	}
	p := "."
	if fs.NArg() == 1 {
		p = fs.Arg(0)
	}
	msg, err := callLocalRPC("list_dir", proto.ListDirReq{Path: p, Depth: *depth}, 30)
	mustOK(msg, err)
	var r proto.ListDirResp
	_ = json.Unmarshal(msg.Payload, &r)
	for _, e := range r.Entries {
		kind := "F"
		if e.IsDir {
			kind = "D"
		}
		fmt.Printf("%s %10d %s %s\n", kind, e.Size, e.ModTime, e.Path)
	}
	if r.Truncated {
		fmt.Println("... (truncated)")
	}
}

func cmdGrep(args []string) {
	args = reorderFlags(args, map[string]bool{"max": true})
	fs := flag.NewFlagSet("grep", flag.ExitOnError)
	maxM := fs.Int("max", 100, "max matches")
	_ = fs.Parse(args)
	if fs.NArg() < 1 || fs.NArg() > 2 {
		fmt.Fprintln(os.Stderr, "usage: guestctl grep [--max N] <pattern> [path]")
		os.Exit(2)
	}
	p := "."
	if fs.NArg() == 2 {
		p = fs.Arg(1)
	}
	msg, err := callLocalRPC("grep", proto.GrepReq{Pattern: fs.Arg(0), Path: p, MaxMatches: *maxM}, 60)
	mustOK(msg, err)
	var r proto.GrepResp
	_ = json.Unmarshal(msg.Payload, &r)
	for _, m := range r.Matches {
		fmt.Printf("%s:%d: %s\n", m.File, m.Line, m.Text)
	}
	if r.Truncated {
		fmt.Println("... (truncated)")
	}
}

func cmdExec(args []string) {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	cwd := fs.String("cwd", "", "working directory on guest")
	timeout := fs.Int("timeout", 120, "command timeout in seconds")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: guestctl exec [--cwd DIR] [--timeout SEC] <command>")
		os.Exit(2)
	}
	cmdStr := strings.Join(fs.Args(), " ")
	msg, err := callLocalRPC("exec", proto.ExecReq{Command: cmdStr, Cwd: *cwd, TimeoutSec: *timeout}, *timeout+300)
	mustOK(msg, err)
	var r proto.ExecResp
	_ = json.Unmarshal(msg.Payload, &r)
	if !r.Approved {
		fmt.Fprintln(os.Stderr, "[目标机操作者拒绝了该命令执行]")
		os.Exit(1)
	}
	if r.Stdout != "" {
		fmt.Print(r.Stdout)
		if !strings.HasSuffix(r.Stdout, "\n") {
			fmt.Println()
		}
	}
	if r.Stderr != "" {
		fmt.Fprint(os.Stderr, r.Stderr)
		if !strings.HasSuffix(r.Stderr, "\n") {
			fmt.Fprintln(os.Stderr)
		}
	}
	if r.ExitCode != 0 {
		fmt.Fprintf(os.Stderr, "[exit_code=%d timed_out=%v]\n", r.ExitCode, r.TimedOut)
		os.Exit(r.ExitCode)
	}
}

func cmdEdit(args []string) {
	args = reorderFlags(args, map[string]bool{"old": true, "new": true, "old-file": true, "new-file": true})
	fs := flag.NewFlagSet("edit", flag.ExitOnError)
	oldStr := fs.String("old", "", "exact target text to replace")
	newStr := fs.String("new", "", "replacement text")
	oldFile := fs.String("old-file", "", "read target text from local file")
	newFile := fs.String("new-file", "", "read replacement text from local file")
	all := fs.Bool("all", false, "replace all occurrences")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: guestctl edit [--old STR|--old-file F] [--new STR|--new-file F] [--all] <guest_path>")
		os.Exit(2)
	}
	ot, nt := *oldStr, *newStr
	if *oldFile != "" {
		b, err := os.ReadFile(*oldFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		ot = string(b)
	}
	if *newFile != "" {
		b, err := os.ReadFile(*newFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		nt = string(b)
	}
	msg, err := callLocalRPC("edit_file", proto.EditFileReq{
		Path: fs.Arg(0), OldText: ot, NewText: nt, ReplaceAll: *all,
	}, 360)
	mustOK(msg, err)
	var r proto.ModifyFileResp
	_ = json.Unmarshal(msg.Payload, &r)
	if !r.Approved {
		fmt.Fprintln(os.Stderr, "[目标机操作者拒绝了该文件修改]")
		os.Exit(1)
	}
	fmt.Printf("✓ 已写入 %s (%d bytes, %d replacements; diff & backup archived locally)\n%s", r.Path, r.BytesWritten, r.Replacements, r.Diff)
}

func cmdWrite(args []string) {
	args = reorderFlags(args, map[string]bool{"from-file": true, "content": true})
	fs := flag.NewFlagSet("write", flag.ExitOnError)
	fromFile := fs.String("from-file", "", "local file to upload")
	content := fs.String("content", "", "literal content string")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: guestctl write [--from-file F | --content STR] <guest_path>")
		os.Exit(2)
	}
	body := *content
	if *fromFile != "" {
		b, err := os.ReadFile(*fromFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		body = string(b)
	}
	msg, err := callLocalRPC("write_file", proto.WriteFileReq{
		Path: fs.Arg(0), Content: body,
	}, 360)
	mustOK(msg, err)
	var r proto.ModifyFileResp
	_ = json.Unmarshal(msg.Payload, &r)
	if !r.Approved {
		fmt.Fprintln(os.Stderr, "[目标机操作者拒绝了该文件写入]")
		os.Exit(1)
	}
	fmt.Printf("✓ 已写入 %s (%d bytes, created=%v; backup archived locally)\n", r.Path, r.BytesWritten, r.Created)
}

func cmdScreenshot() {
	msg, err := callLocalRPC("screenshot", nil, 300)
	mustOK(msg, err)
	var r struct {
		Approved  bool   `json:"approved"`
		Tool      string `json:"tool"`
		SavedPath string `json:"saved_path"`
		Bytes     int    `json:"bytes"`
	}
	_ = json.Unmarshal(msg.Payload, &r)
	if !r.Approved {
		fmt.Fprintln(os.Stderr, "[目标机操作者拒绝了截屏请求]")
		os.Exit(1)
	}
	fmt.Printf("✓ 截图已传输并保存至主控机本地: %s (%d bytes, tool=%s)\n", r.SavedPath, r.Bytes, r.Tool)
}

func mustOK(msg proto.Message, err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
	if !msg.OK {
		fmt.Fprintln(os.Stderr, "目标机返回错误:", msg.Error)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`guestctl - 授权交互式远程联调控制器（数据归档于主控机本地）

用法:
  guestctl pair [--os linux|arm64|win] [--mode confirm|ro]  【仅在本地终端人工运行】生成一次性配对命令
  guestctl status                          查看当前联调连接状态、目标机信息与本地归档路径
  guestctl sysinfo                         只读获取目标机 OS / 内存 / 磁盘 / GPU 概览
  guestctl read [--start N --end M] <path> 只读查看目标机文件（敏感密钥路径需确认）
  guestctl ls [--depth N] [path]           只读列出目标机目录
  guestctl grep [--max N] <pattern> [path] 只读正则搜索目标机文本（自动跳过密钥目录）
  guestctl exec [--cwd D] <cmd...>         执行命令（可信系统只读查询自动跑；修改/复合命令弹 [y/N]）
  guestctl edit --old A --new B <path>     目标机展示彩色 Diff 并弹 [y/N] 后原子修改文件
  guestctl write --from-file F <path>      目标机展示 Diff 并弹 [y/N] 后原子写入文件
  guestctl screenshot                      目标机 [y/N] 同意后截屏并仅保存到主控机本地
  guestctl close                           主动结束联调会话并通知目标机退出清理
  guestctl sessions                        列出保存在主控机本地的所有历史排查归档`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	sub := os.Args[1]
	rest := os.Args[2:]
	switch sub {
	case "daemon":
		runDaemon(rest)
	case "pair":
		cmdPair(rest)
	case "status":
		cmdStatus()
	case "sysinfo":
		cmdSysInfo()
	case "read":
		cmdRead(rest)
	case "ls":
		cmdLs(rest)
	case "grep":
		cmdGrep(rest)
	case "exec":
		cmdExec(rest)
	case "edit":
		cmdEdit(rest)
	case "write":
		cmdWrite(rest)
	case "screenshot":
		cmdScreenshot()
	case "close":
		cmdClose()
	case "sessions":
		cmdSessions()
	default:
		usage()
		os.Exit(2)
	}
}
