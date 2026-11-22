package e2ee

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

const (
	MaxFrameBytes = 16 * 1024 * 1024 // 16 MiB
)

// Conn provides authenticated, replay-protected AES-256-GCM JSON framing over a raw stream.
type Conn struct {
	rw       io.ReadWriteCloser
	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD

	writeMu  sync.Mutex
	writeSeq uint64

	readMu  sync.Mutex
	readSeq uint64
}

// HostHandshake performs mutual authentication as the host controller side.
func HostHandshake(rw io.ReadWriteCloser, psk []byte) (*Conn, error) {
	if len(psk) != 32 {
		return nil, errors.New("e2ee key must be 32 bytes")
	}
	nonceH := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonceH); err != nil {
		return nil, err
	}
	if _, err := rw.Write(nonceH); err != nil {
		return nil, fmt.Errorf("write host nonce: %w", err)
	}

	guestResp := make([]byte, 64)
	if _, err := io.ReadFull(rw, guestResp); err != nil {
		return nil, fmt.Errorf("read guest auth: %w", err)
	}
	nonceG := guestResp[:32]
	guestMAC := guestResp[32:]
	expectedGuestMAC := computeAuthMAC(psk, "guest-auth", nonceH, nonceG)
	if !hmac.Equal(guestMAC, expectedGuestMAC) {
		return nil, errors.New("guest E2EE authentication failed")
	}

	hostMAC := computeAuthMAC(psk, "host-auth", nonceG, nonceH)
	if _, err := rw.Write(hostMAC); err != nil {
		return nil, fmt.Errorf("write host auth: %w", err)
	}

	return newConn(rw, psk, nonceH, nonceG, true)
}

// GuestHandshake performs mutual authentication as the remote guest side.
func GuestHandshake(rw io.ReadWriteCloser, psk []byte) (*Conn, error) {
	if len(psk) != 32 {
		return nil, errors.New("e2ee key must be 32 bytes")
	}
	nonceH := make([]byte, 32)
	if _, err := io.ReadFull(rw, nonceH); err != nil {
		return nil, fmt.Errorf("read host nonce: %w", err)
	}
	nonceG := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonceG); err != nil {
		return nil, err
	}
	guestMAC := computeAuthMAC(psk, "guest-auth", nonceH, nonceG)
	buf := make([]byte, 64)
	copy(buf[:32], nonceG)
	copy(buf[32:], guestMAC)
	if _, err := rw.Write(buf); err != nil {
		return nil, fmt.Errorf("write guest auth: %w", err)
	}

	hostMAC := make([]byte, 32)
	if _, err := io.ReadFull(rw, hostMAC); err != nil {
		return nil, fmt.Errorf("read host auth: %w", err)
	}
	expectedHostMAC := computeAuthMAC(psk, "host-auth", nonceG, nonceH)
	if !hmac.Equal(hostMAC, expectedHostMAC) {
		return nil, errors.New("host E2EE authentication failed")
	}

	return newConn(rw, psk, nonceH, nonceG, false)
}

func computeAuthMAC(psk []byte, label string, a, b []byte) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(label))
	mac.Write(a)
	mac.Write(b)
	return mac.Sum(nil)
}

func deriveDirKey(psk []byte, dir string, nonceH, nonceG []byte) []byte {
	h := sha256.New()
	h.Write(psk)
	h.Write([]byte("|"))
	h.Write([]byte(dir))
	h.Write(nonceH)
	h.Write(nonceG)
	return h.Sum(nil)
}

func newConn(rw io.ReadWriteCloser, psk, nonceH, nonceG []byte, isHost bool) (*Conn, error) {
	h2gKey := deriveDirKey(psk, "h2g", nonceH, nonceG)
	g2hKey := deriveDirKey(psk, "g2h", nonceH, nonceG)

	h2gBlock, err := aes.NewCipher(h2gKey)
	if err != nil {
		return nil, err
	}
	g2hBlock, err := aes.NewCipher(g2hKey)
	if err != nil {
		return nil, err
	}
	h2gAEAD, err := cipher.NewGCM(h2gBlock)
	if err != nil {
		return nil, err
	}
	g2hAEAD, err := cipher.NewGCM(g2hBlock)
	if err != nil {
		return nil, err
	}

	c := &Conn{rw: rw}
	if isHost {
		c.sendAEAD = h2gAEAD
		c.recvAEAD = g2hAEAD
	} else {
		c.sendAEAD = g2hAEAD
		c.recvAEAD = h2gAEAD
	}
	return c, nil
}

func (c *Conn) WriteJSON(v any) error {
	plain, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(plain) > MaxFrameBytes {
		return fmt.Errorf("frame too large: %d", len(plain))
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.writeSeq++
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[:8], c.writeSeq)
	aad := nonce[:8]

	ct := c.sendAEAD.Seal(nil, nonce[:], plain, aad)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(ct)))
	if _, err := c.rw.Write(hdr[:]); err != nil {
		return err
	}
	_, err = c.rw.Write(ct)
	return err
}

func (c *Conn) ReadJSON(v any) error {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	var hdr [4]byte
	if _, err := io.ReadFull(c.rw, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || int(n) > MaxFrameBytes+64 {
		return fmt.Errorf("invalid frame size: %d", n)
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(c.rw, ct); err != nil {
		return err
	}

	c.readSeq++
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[:8], c.readSeq)
	aad := nonce[:8]

	plain, err := c.recvAEAD.Open(nil, nonce[:], ct, aad)
	if err != nil {
		return fmt.Errorf("decrypt frame seq=%d: %w", c.readSeq, err)
	}
	return json.Unmarshal(plain, v)
}

func (c *Conn) Close() error {
	return c.rw.Close()
}

// PinnedTLSConfig returns a TLS 1.3 config that strictly pins the leaf certificate SHA-256 hex digest.
func PinnedTLSConfig(certSHA256Hex string) (*tls.Config, error) {
	clean := strings.ToLower(strings.TrimSpace(certSHA256Hex))
	clean = strings.TrimPrefix(clean, "sha256:")
	want, err := hex.DecodeString(clean)
	if err != nil || len(want) != 32 {
		return nil, fmt.Errorf("invalid cert sha256 pin: %q", certSHA256Hex)
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // strictly replaced by VerifyConnection pin check below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return fmt.Errorf("TLS cert pin mismatch: got %x", got)
			}
			return nil
		},
	}, nil
}
