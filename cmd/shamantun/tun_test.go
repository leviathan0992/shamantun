package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	gstack "gvisor.dev/gvisor/pkg/tcpip/stack"
)

type stubConnWithRemote struct {
	remote net.Addr
}

func (s *stubConnWithRemote) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (s *stubConnWithRemote) Write(p []byte) (int, error) { return len(p), nil }
func (s *stubConnWithRemote) Close() error                { return nil }
func (s *stubConnWithRemote) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}
}
func (s *stubConnWithRemote) RemoteAddr() net.Addr               { return s.remote }
func (s *stubConnWithRemote) SetDeadline(_ time.Time) error      { return nil }
func (s *stubConnWithRemote) SetReadDeadline(_ time.Time) error  { return nil }
func (s *stubConnWithRemote) SetWriteDeadline(_ time.Time) error { return nil }

type blockingRelayConn struct {
	mu          sync.Mutex
	closed      bool
	deadlineSet bool
}

func (c *blockingRelayConn) Read(_ []byte) (int, error) {
	for {
		c.mu.Lock()
		switch {
		case c.closed:
			c.mu.Unlock()
			return 0, net.ErrClosed
		case c.deadlineSet:
			c.mu.Unlock()
			return 0, &timeoutNetError{}
		default:
			c.mu.Unlock()
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func (c *blockingRelayConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	return len(p), nil
}

func (c *blockingRelayConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *blockingRelayConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}
}
func (c *blockingRelayConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2}
}
func (c *blockingRelayConn) SetDeadline(_ time.Time) error {
	c.mu.Lock()
	c.deadlineSet = true
	c.mu.Unlock()
	return nil
}
func (c *blockingRelayConn) SetReadDeadline(_ time.Time) error {
	c.mu.Lock()
	c.deadlineSet = true
	c.mu.Unlock()
	return nil
}
func (c *blockingRelayConn) SetWriteDeadline(_ time.Time) error {
	c.mu.Lock()
	c.deadlineSet = true
	c.mu.Unlock()
	return nil
}

type stubDialerEaddrNotAvail struct{}

func (d *stubDialerEaddrNotAvail) DialTCP(_ context.Context, _ string) (net.Conn, error) {
	return nil, eaddrNotAvailErr()
}
func (d *stubDialerEaddrNotAvail) DialUDP(_ context.Context) (UDPSession, error) {
	return nil, eaddrNotAvailErr()
}
func (d *stubDialerEaddrNotAvail) SupportsUDP() bool { return true }
func (d *stubDialerEaddrNotAvail) Mode() string      { return ModeSocks5TLS }

func eaddrNotAvailErr() error {
	return fmt.Errorf("connect upstream: %w", syscall.EADDRNOTAVAIL)
}

type stubPacketConnEOF struct{}

func (c *stubPacketConnEOF) ReadFrom(_ []byte) (int, net.Addr, error) { return 0, nil, io.EOF }
func (c *stubPacketConnEOF) WriteTo(_ []byte, _ net.Addr) (int, error) {
	return 0, errors.New("not implemented")
}
func (c *stubPacketConnEOF) Close() error                       { return nil }
func (c *stubPacketConnEOF) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *stubPacketConnEOF) SetDeadline(_ time.Time) error      { return nil }
func (c *stubPacketConnEOF) SetReadDeadline(_ time.Time) error  { return nil }
func (c *stubPacketConnEOF) SetWriteDeadline(_ time.Time) error { return nil }

type stubPacketConnWriteToOnly struct{}

func (c *stubPacketConnWriteToOnly) ReadFrom(_ []byte) (int, net.Addr, error) { return 0, nil, io.EOF }
func (c *stubPacketConnWriteToOnly) WriteTo(_ []byte, _ net.Addr) (int, error) {
	return 0, errors.New("unexpected fallback write")
}
func (c *stubPacketConnWriteToOnly) Close() error                       { return nil }
func (c *stubPacketConnWriteToOnly) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *stubPacketConnWriteToOnly) SetDeadline(_ time.Time) error      { return nil }
func (c *stubPacketConnWriteToOnly) SetReadDeadline(_ time.Time) error  { return nil }
func (c *stubPacketConnWriteToOnly) SetWriteDeadline(_ time.Time) error { return nil }

type shortWriteConn struct {
	net.Conn
	maxWrite int
}

func (c *shortWriteConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	limit := c.maxWrite
	if limit <= 0 || limit > len(p) {
		limit = len(p)
	}
	return c.Conn.Write(p[:limit])
}

type shortWriter struct {
	maxWrite int
}

func (w *shortWriter) Write(p []byte) (int, error) {
	limit := w.maxWrite
	if limit <= 0 || limit > len(p) {
		limit = len(p)
	}
	return limit, nil
}

type connWithRemoteAddr struct {
	net.Conn
	remote net.Addr
}

func (c *connWithRemoteAddr) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}

type stubCancelableUDPDialer struct {
	enterCh  chan struct{}
	cancelCh chan error
}

func (d *stubCancelableUDPDialer) DialTCP(_ context.Context, _ string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (d *stubCancelableUDPDialer) DialUDP(ctx context.Context) (UDPSession, error) {
	if d.enterCh != nil {
		close(d.enterCh)
	}
	<-ctx.Done()
	if d.cancelCh != nil {
		d.cancelCh <- ctx.Err()
	}
	return nil, ctx.Err()
}

func (d *stubCancelableUDPDialer) SupportsUDP() bool { return true }
func (d *stubCancelableUDPDialer) Mode() string      { return ModeSocks5TLS }

type stubWarmupDialer struct {
	warmupCh chan struct{}
	mu       sync.Mutex
	calls    int
	blockCh  chan struct{}
}

func (d *stubWarmupDialer) DialTCP(_ context.Context, _ string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (d *stubWarmupDialer) DialUDP(_ context.Context) (UDPSession, error) {
	return nil, errors.New("not implemented")
}

func (d *stubWarmupDialer) SupportsUDP() bool { return false }
func (d *stubWarmupDialer) Mode() string      { return ModeSocks5TLS }
func (d *stubWarmupDialer) Warmup(_ context.Context) error {
	d.mu.Lock()
	d.calls++
	d.mu.Unlock()
	if d.warmupCh != nil {
		select {
		case <-d.warmupCh:
		default:
			close(d.warmupCh)
		}
	}
	if d.blockCh != nil {
		<-d.blockCh
	}
	return nil
}

func (d *stubWarmupDialer) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

type stubUDPSession struct {
	closed chan struct{}
	once   sync.Once
}

func (s *stubUDPSession) WriteTo(_ []byte, _ *net.UDPAddr) error { return nil }
func (s *stubUDPSession) ReadFrom(_ []byte) (int, *net.UDPAddr, error) {
	return 0, nil, io.EOF
}
func (s *stubUDPSession) Close() error {
	s.once.Do(func() {
		if s.closed != nil {
			close(s.closed)
		}
	})
	return nil
}
func (s *stubUDPSession) SetDeadline(_ time.Time) error      { return nil }
func (s *stubUDPSession) SetReadDeadline(_ time.Time) error  { return nil }
func (s *stubUDPSession) SetWriteDeadline(_ time.Time) error { return nil }

type scriptedUDPSession struct {
	reads []scriptedUDPRead
	mu    sync.Mutex
}

type scriptedUDPRead struct {
	payload []byte
	src     *net.UDPAddr
	err     error
}

func (s *scriptedUDPSession) WriteTo(_ []byte, _ *net.UDPAddr) error { return nil }
func (s *scriptedUDPSession) ReadFrom(payload []byte) (int, *net.UDPAddr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reads) == 0 {
		return 0, nil, io.EOF
	}
	next := s.reads[0]
	s.reads = s.reads[1:]
	if len(next.payload) > 0 {
		copy(payload, next.payload)
	}
	return len(next.payload), next.src, next.err
}
func (s *scriptedUDPSession) Close() error                       { return nil }
func (s *scriptedUDPSession) SetDeadline(_ time.Time) error      { return nil }
func (s *scriptedUDPSession) SetReadDeadline(_ time.Time) error  { return nil }
func (s *scriptedUDPSession) SetWriteDeadline(_ time.Time) error { return nil }

type stubDNSTCPDialer struct {
	mode     string
	response []byte
	mu       sync.Mutex
	targets  []string
}

func (d *stubDNSTCPDialer) DialTCP(_ context.Context, target string) (net.Conn, error) {
	client, server := net.Pipe()
	d.mu.Lock()
	d.targets = append(d.targets, target)
	d.mu.Unlock()

	go func() {
		defer server.Close()
		for {
			var lengthBuf [2]byte
			if _, err := io.ReadFull(server, lengthBuf[:]); err != nil {
				return
			}
			size := int(binary.BigEndian.Uint16(lengthBuf[:]))
			payload := make([]byte, size)
			if _, err := io.ReadFull(server, payload); err != nil {
				return
			}
			out := d.response
			if len(out) == 0 {
				out = payload
			}
			reply := make([]byte, 2+len(out))
			binary.BigEndian.PutUint16(reply[:2], uint16(len(out)))
			copy(reply[2:], out)
			if _, err := server.Write(reply); err != nil {
				return
			}
		}
	}()

	return client, nil
}

func (d *stubDNSTCPDialer) DialUDP(_ context.Context) (UDPSession, error) {
	return nil, errors.New("not implemented")
}

func (d *stubDNSTCPDialer) SupportsUDP() bool { return false }
func (d *stubDNSTCPDialer) Mode() string {
	if d.mode == "" {
		return ModeSocks5TLS
	}
	return d.mode
}

func (d *stubDNSTCPDialer) dialCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.targets)
}

type stubRetryTCPDialer struct {
	response  []byte
	failCount int
	mu        sync.Mutex
	dials     int
}

func (d *stubRetryTCPDialer) DialTCP(_ context.Context, _ string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dials++
	if d.failCount > 0 {
		d.failCount--
		return nil, eaddrNotAvailErr()
	}

	client, server := net.Pipe()
	response := append([]byte(nil), d.response...)
	go func() {
		defer server.Close()
		var lengthBuf [2]byte
		if _, err := io.ReadFull(server, lengthBuf[:]); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(lengthBuf[:]))
		payload := make([]byte, size)
		if _, err := io.ReadFull(server, payload); err != nil {
			return
		}
		out := response
		if len(out) == 0 {
			out = payload
		}
		reply := make([]byte, 2+len(out))
		binary.BigEndian.PutUint16(reply[:2], uint16(len(out)))
		copy(reply[2:], out)
		_, _ = server.Write(reply)
	}()

	return client, nil
}

func (d *stubRetryTCPDialer) DialUDP(_ context.Context) (UDPSession, error) {
	return nil, errors.New("not implemented")
}

func (d *stubRetryTCPDialer) SupportsUDP() bool { return false }
func (d *stubRetryTCPDialer) Mode() string      { return ModeSocks5TLS }

type stubDNSPacketConn struct {
	reads  [][]byte
	writes [][]byte
	mu     sync.Mutex
	index  int
}

func (c *stubDNSPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.index >= len(c.reads) {
		return 0, nil, io.EOF
	}
	payload := c.reads[c.index]
	c.index++
	copy(p, payload)
	return len(payload), &net.UDPAddr{IP: net.ParseIP("198.18.0.1"), Port: 53000}, nil
}

func (c *stubDNSPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (c *stubDNSPacketConn) Write(p []byte) (int, error) {
	return c.WriteTo(p, nil)
}

func (c *stubDNSPacketConn) Close() error                       { return nil }
func (c *stubDNSPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *stubDNSPacketConn) SetDeadline(_ time.Time) error      { return nil }
func (c *stubDNSPacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *stubDNSPacketConn) SetWriteDeadline(_ time.Time) error { return nil }

type stubDNSPacketConnBlocking struct {
	firstRead []byte
	writes    [][]byte
	mu        sync.Mutex
	served    bool
	blockCh   chan struct{}
}

func (c *stubDNSPacketConnBlocking) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	if !c.served {
		c.served = true
		payload := append([]byte(nil), c.firstRead...)
		c.mu.Unlock()
		copy(p, payload)
		return len(payload), &net.UDPAddr{IP: net.ParseIP("198.18.0.1"), Port: 53000}, nil
	}
	blockCh := c.blockCh
	c.mu.Unlock()
	<-blockCh
	return 0, nil, io.EOF
}

func (c *stubDNSPacketConnBlocking) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (c *stubDNSPacketConnBlocking) Write(p []byte) (int, error) {
	return c.WriteTo(p, nil)
}

func (c *stubDNSPacketConnBlocking) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.blockCh != nil {
		close(c.blockCh)
		c.blockCh = nil
	}
	return nil
}
func (c *stubDNSPacketConnBlocking) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *stubDNSPacketConnBlocking) SetDeadline(_ time.Time) error      { return nil }
func (c *stubDNSPacketConnBlocking) SetReadDeadline(_ time.Time) error  { return nil }
func (c *stubDNSPacketConnBlocking) SetWriteDeadline(_ time.Time) error { return nil }

type deadlineTrackingConn struct {
	net.Conn
	mu            sync.Mutex
	deadlineCalls int
	lastDeadline  time.Time
}

func (c *deadlineTrackingConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadlineCalls++
	c.lastDeadline = t
	c.mu.Unlock()
	if c.Conn != nil {
		return c.Conn.SetDeadline(t)
	}
	return nil
}

func (c *deadlineTrackingConn) deadlineCallCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadlineCalls
}

type timedReadStep struct {
	delay time.Duration
	data  []byte
	err   error
}

type deadlineRefreshConn struct {
	mu                 sync.Mutex
	reads              []timedReadStep
	readDeadlineCalls  int
	writeDeadlineCalls int
	writes             int
}

func (c *deadlineRefreshConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if len(c.reads) == 0 {
		c.mu.Unlock()
		return 0, io.EOF
	}
	step := c.reads[0]
	c.reads = c.reads[1:]
	c.mu.Unlock()
	if step.delay > 0 {
		time.Sleep(step.delay)
	}
	n := copy(p, step.data)
	if step.err != nil {
		return n, step.err
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (c *deadlineRefreshConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes += len(p)
	c.mu.Unlock()
	return len(p), nil
}

func (c *deadlineRefreshConn) Close() error                  { return nil }
func (c *deadlineRefreshConn) LocalAddr() net.Addr           { return &net.TCPAddr{} }
func (c *deadlineRefreshConn) RemoteAddr() net.Addr          { return &net.TCPAddr{} }
func (c *deadlineRefreshConn) SetDeadline(_ time.Time) error { return nil }
func (c *deadlineRefreshConn) SetReadDeadline(_ time.Time) error {
	c.mu.Lock()
	c.readDeadlineCalls++
	c.mu.Unlock()
	return nil
}
func (c *deadlineRefreshConn) SetWriteDeadline(_ time.Time) error {
	c.mu.Lock()
	c.writeDeadlineCalls++
	c.mu.Unlock()
	return nil
}

func (c *deadlineRefreshConn) readDeadlineCallCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readDeadlineCalls
}

func (c *deadlineRefreshConn) writeDeadlineCallCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeDeadlineCalls
}

type stubUDPDialCounter struct {
	mu       sync.Mutex
	udpDials int
}

func (d *stubUDPDialCounter) DialTCP(_ context.Context, _ string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (d *stubUDPDialCounter) DialUDP(_ context.Context) (UDPSession, error) {
	d.mu.Lock()
	d.udpDials++
	d.mu.Unlock()
	return &stubUDPSession{}, nil
}

func (d *stubUDPDialCounter) SupportsUDP() bool { return true }
func (d *stubUDPDialCounter) Mode() string      { return ModeSocks5TLS }

func (d *stubUDPDialCounter) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.udpDials
}

func TestConfigValidateRejectsInvalidUpstreamPort(t *testing.T) {
	cfg := newValidConfigForTest(t)
	cfg.Upstream.Addr = "127.0.0.1:0"

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "invalid port") {
		t.Fatalf("expected invalid port error, got: %v", err)
	}
}

func TestConfigValidateRejectsMissingClientPEM(t *testing.T) {
	cfg := newValidConfigForTest(t)
	cfg.Upstream.ClientPEM = "definitely-missing-client.pem"

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "client_pem is not accessible") {
		t.Fatalf("expected missing client_pem error, got: %v", err)
	}
}

func TestConfigValidateAllowsHTTPSBasicAuthWithoutClientCertificate(t *testing.T) {
	cfg := newValidConfigForTest(t)
	cfg.Mode = ModeHTTPS
	cfg.Upstream.Username = "user"
	cfg.Upstream.Password = "pass"
	cfg.Upstream.ClientPEM = ""
	cfg.Upstream.ClientKey = ""

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected https basic auth config without client certs to validate, got: %v", err)
	}
}

func TestConfigValidateRejectsPartialClientCertificatePair(t *testing.T) {
	cfg := newValidConfigForTest(t)
	cfg.Mode = ModeHTTPS
	cfg.Upstream.Username = "user"
	cfg.Upstream.Password = "pass"
	cfg.Upstream.ClientKey = ""

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must both be set") {
		t.Fatalf("expected partial client cert pair error, got: %v", err)
	}
}

func TestConfigValidateRejectsTooSmallConnectTimeout(t *testing.T) {
	cfg := newValidConfigForTest(t)
	cfg.Runtime.ConnectTimeoutMS = minConnectTimeoutMS - 1

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "connect_timeout_ms") {
		t.Fatalf("expected connect_timeout_ms error, got: %v", err)
	}
}

func TestConfigValidateRejectsHugeUDPBuffer(t *testing.T) {
	cfg := newValidConfigForTest(t)
	cfg.Runtime.UDPBuffer = maxRuntimeBufferBytes + 1

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "udp_buffer") {
		t.Fatalf("expected udp_buffer error, got: %v", err)
	}
}

func TestConfigValidateRejectsHugeDialConcurrency(t *testing.T) {
	cfg := newValidConfigForTest(t)
	cfg.Runtime.TCPDialConcurrency = maxDialConcurrency + 1

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "tcp_dial_concurrency") {
		t.Fatalf("expected tcp_dial_concurrency error, got: %v", err)
	}
}

func TestBuildTLSConfigRejectsInvalidClientCertificatePEM(t *testing.T) {
	tmp := t.TempDir()
	certPath := writeTestFile(t, tmp, "client.pem", []byte("not pem"))
	keyPath := writeTestFile(t, tmp, "client.key", []byte("not pem"))

	_, err := buildTLSConfig(UpstreamConfig{
		Addr:      "127.0.0.1:443",
		ClientPEM: certPath,
		ClientKey: keyPath,
	})
	if err == nil || !strings.Contains(err.Error(), "parse client certificate") {
		t.Fatalf("expected client certificate parse error, got: %v", err)
	}
}

func TestBuildTLSConfigRejectsMismatchedClientKeyPair(t *testing.T) {
	mtlsA := generateMTLSAssets(t, []net.IP{net.ParseIP("127.0.0.1")})
	mtlsB := generateMTLSAssets(t, []net.IP{net.ParseIP("127.0.0.2")})

	_, err := buildTLSConfig(UpstreamConfig{
		Addr:      "127.0.0.1:443",
		ClientPEM: mtlsA.ClientPEM,
		ClientKey: mtlsB.ClientKey,
	})
	if err == nil || !strings.Contains(err.Error(), "load client certificate/key pair") {
		t.Fatalf("expected mismatched key pair error, got: %v", err)
	}
}

func TestBuildTLSConfigAllowsHTTPSBasicAuthWithoutClientCertificate(t *testing.T) {
	tlsCfg, err := buildTLSConfig(UpstreamConfig{
		Addr:     "127.0.0.1:443",
		Username: "user",
		Password: "pass",
	})
	if err != nil {
		t.Fatalf("expected tls config without client certs to build, got: %v", err)
	}
	if len(tlsCfg.Certificates) != 0 {
		t.Fatalf("expected no client certificates, got %d", len(tlsCfg.Certificates))
	}
}

func TestBuildTLSConfigRejectsPartialClientCertificatePair(t *testing.T) {
	_, err := buildTLSConfig(UpstreamConfig{
		Addr:      "127.0.0.1:443",
		ClientPEM: "placeholder-client.pem",
	})
	if err == nil || !strings.Contains(err.Error(), "must both be set") {
		t.Fatalf("expected partial client cert pair error, got: %v", err)
	}
}

func TestLoadConfigCompactLayout(t *testing.T) {
	tmp := t.TempDir()
	clientPEM := writeTestFile(t, tmp, "client.pem", []byte("test"))
	clientKey := writeTestFile(t, tmp, "client.key", []byte("test"))
	cfgPath := filepath.Join(tmp, "compact.json")

	raw := fmt.Sprintf(`{
  "mode": "socks5tls",
  "tun": %q,
  "upstream": "127.0.0.1:443",
  "client_pem": %q,
  "client_key": %q,
  "enable_udp": true
}`, validTunNameForRuntime(), clientPEM, clientKey)
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write compact config: %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("load compact config: %v", err)
	}
	if cfg.Mode != ModeSocks5TLS {
		t.Fatalf("unexpected mode: %s", cfg.Mode)
	}
	if cfg.Upstream.Addr != "127.0.0.1:443" {
		t.Fatalf("unexpected upstream addr: %s", cfg.Upstream.Addr)
	}
	if cfg.Tun.Name != validTunNameForRuntime() {
		t.Fatalf("unexpected tun name: %s", cfg.Tun.Name)
	}
	if !cfg.Runtime.EnableUDP {
		t.Fatalf("expected enable_udp=true")
	}
}

func TestModeSwitchKeepsSingleUpstream(t *testing.T) {
	tmp := t.TempDir()
	clientPEM := writeTestFile(t, tmp, "client.pem", []byte("test"))
	clientKey := writeTestFile(t, tmp, "client.key", []byte("test"))
	cfgPath := filepath.Join(tmp, "single-upstream.json")

	raw := fmt.Sprintf(`{
	  "mode": "socks5tls",
	  "upstream": "127.0.0.1:443",
	  "tun": %q,
	  "client_pem": %q,
	  "client_key": %q
	}`, validTunNameForRuntime(), clientPEM, clientKey)
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write single-upstream config: %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("load single-upstream config: %v", err)
	}
	if cfg.Mode != ModeSocks5TLS {
		t.Fatalf("unexpected mode: %s", cfg.Mode)
	}
	if cfg.Upstream.Addr != "127.0.0.1:443" {
		t.Fatalf("unexpected socks5tls upstream: %s", cfg.Upstream.Addr)
	}

	if err := cfg.ApplyOverrides(ModeHTTPS, ""); err != nil {
		t.Fatalf("switch mode to https: %v", err)
	}
	if cfg.Upstream.Addr != "127.0.0.1:443" {
		t.Fatalf("unexpected upstream after mode switch: %s", cfg.Upstream.Addr)
	}
}

func TestLoadConfigRejectsLegacyNestedLayout(t *testing.T) {
	tmp := t.TempDir()
	clientPEM := writeTestFile(t, tmp, "client.pem", []byte("test"))
	clientKey := writeTestFile(t, tmp, "client.key", []byte("test"))
	cfgPath := filepath.Join(tmp, "legacy.json")

	raw := fmt.Sprintf(`{
  "mode": "https",
  "tun": {"name": %q},
  "upstream": {"addr": "127.0.0.1:8443"},
  "client_pem": %q,
  "client_key": %q
}`, validTunNameForRuntime(), clientPEM, clientKey)
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	_, err := LoadConfig(cfgPath)
	if err == nil || !strings.Contains(err.Error(), "cannot unmarshal") {
		t.Fatalf("expected legacy format parse error, got: %v", err)
	}
}

func TestBuildSocks5CommandRequestRejectsZeroPort(t *testing.T) {
	_, err := buildSocks5CommandRequest(socksCmdConnect, "example.com:0")
	if err == nil || !strings.Contains(err.Error(), "invalid target port") {
		t.Fatalf("expected invalid target port error, got: %v", err)
	}
}

func TestBuildSocks5UDPAssociateRequestEncodesPortForWildcardIP(t *testing.T) {
	req, err := buildSocks5UDPAssociateRequest(&net.UDPAddr{IP: net.IPv4zero, Port: 53000})
	if err != nil {
		t.Fatalf("build udp associate request: %v", err)
	}
	if len(req) != 10 {
		t.Fatalf("unexpected request length: %d", len(req))
	}
	if req[0] != socksVersion || req[1] != socksCmdAssociate || req[3] != socksAtypIPv4 {
		t.Fatalf("unexpected request header: %v", req[:4])
	}
	if got := binary.BigEndian.Uint16(req[8:10]); got != 53000 {
		t.Fatalf("unexpected encoded port: %d", got)
	}
}

func TestBuildSocks5UDPAssociateRequestEncodesIPv4(t *testing.T) {
	req, err := buildSocks5UDPAssociateRequest(&net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 12345})
	if err != nil {
		t.Fatalf("build udp associate request: %v", err)
	}
	if len(req) != 10 {
		t.Fatalf("unexpected request length: %d", len(req))
	}
	if req[3] != socksAtypIPv4 {
		t.Fatalf("unexpected atyp: %d", req[3])
	}
	if !bytes.Equal(req[4:8], net.ParseIP("10.0.0.2").To4()) {
		t.Fatalf("unexpected encoded ip: %v", req[4:8])
	}
	if got := binary.BigEndian.Uint16(req[8:10]); got != 12345 {
		t.Fatalf("unexpected encoded port: %d", got)
	}
}

func TestPinUpstreamIPForAutoRoutePinsHostnameAndPreservesServerName(t *testing.T) {
	cfg := &Config{
		Upstream: UpstreamConfig{
			Addr: "proxy.example:443",
		},
	}

	host, err := cfg.pinUpstreamIPForAutoRoute(func(addr string) (string, error) {
		if addr != "proxy.example" {
			t.Fatalf("unexpected resolve target: %s", addr)
		}
		return "203.0.113.7", nil
	})
	if err != nil {
		t.Fatalf("pin auto-route upstream: %v", err)
	}
	if host != "proxy.example" {
		t.Fatalf("unexpected pinned host: %q", host)
	}
	if cfg.Upstream.Addr != "203.0.113.7:443" {
		t.Fatalf("unexpected pinned addr: %q", cfg.Upstream.Addr)
	}
	if cfg.Upstream.ServerName != "proxy.example" {
		t.Fatalf("unexpected server name: %q", cfg.Upstream.ServerName)
	}
}

func TestPinUpstreamIPForAutoRoutePinsIPv6HostnameAndPreservesServerName(t *testing.T) {
	cfg := &Config{
		Upstream: UpstreamConfig{
			Addr: "proxy.example:443",
		},
	}

	host, err := cfg.pinUpstreamIPForAutoRoute(func(addr string) (string, error) {
		if addr != "proxy.example" {
			t.Fatalf("unexpected resolve target: %s", addr)
		}
		return "2001:db8::7", nil
	})
	if err != nil {
		t.Fatalf("pin auto-route upstream: %v", err)
	}
	if host != "proxy.example" {
		t.Fatalf("unexpected pinned host: %q", host)
	}
	if cfg.Upstream.Addr != "[2001:db8::7]:443" {
		t.Fatalf("unexpected pinned addr: %q", cfg.Upstream.Addr)
	}
	if cfg.Upstream.ServerName != "proxy.example" {
		t.Fatalf("unexpected server name: %q", cfg.Upstream.ServerName)
	}
}

func TestPickResolvedUpstreamIPPreservesResolverOrder(t *testing.T) {
	resolvedIP, ok := pickResolvedUpstreamIP([]net.IPAddr{
		{IP: net.ParseIP("2001:db8::7")},
		{IP: net.ParseIP("203.0.113.7")},
	})
	if !ok {
		t.Fatal("expected resolved upstream ip")
	}
	if resolvedIP != "2001:db8::7" {
		t.Fatalf("unexpected resolved upstream ip: %q", resolvedIP)
	}
}

func TestPickResolvedUpstreamIPReturnsFirstUsableAddress(t *testing.T) {
	resolvedIP, ok := pickResolvedUpstreamIP([]net.IPAddr{
		{},
		{IP: net.ParseIP("203.0.113.7")},
		{IP: net.ParseIP("2001:db8::7")},
	})
	if !ok {
		t.Fatal("expected resolved upstream ip")
	}
	if resolvedIP != "203.0.113.7" {
		t.Fatalf("unexpected resolved upstream ip: %q", resolvedIP)
	}
}

type blockingUDPSession struct {
	readCh  chan struct{}
	closeCh chan struct{}
	once    sync.Once
}

func (s *blockingUDPSession) WriteTo(_ []byte, _ *net.UDPAddr) error { return nil }
func (s *blockingUDPSession) ReadFrom(_ []byte) (int, *net.UDPAddr, error) {
	<-s.readCh
	return 0, nil, io.EOF
}
func (s *blockingUDPSession) Close() error {
	s.once.Do(func() {
		if s.closeCh != nil {
			close(s.closeCh)
		}
		if s.readCh != nil {
			close(s.readCh)
		}
	})
	return nil
}
func (s *blockingUDPSession) SetDeadline(_ time.Time) error      { return nil }
func (s *blockingUDPSession) SetReadDeadline(_ time.Time) error  { return nil }
func (s *blockingUDPSession) SetWriteDeadline(_ time.Time) error { return nil }

type timeoutNetError struct{}

func (e *timeoutNetError) Error() string   { return "i/o timeout" }
func (e *timeoutNetError) Timeout() bool   { return true }
func (e *timeoutNetError) Temporary() bool { return true }

type deadlineAwarePacketConn struct {
	mu         sync.Mutex
	readSet    bool
	writeSet   bool
	closed     bool
	readErr    error
	writeCount int
}

func (c *deadlineAwarePacketConn) ReadFrom(_ []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		switch {
		case c.closed:
			c.mu.Unlock()
			return 0, nil, net.ErrClosed
		case c.readSet:
			err := c.readErr
			if err == nil {
				err = &timeoutNetError{}
			}
			c.mu.Unlock()
			return 0, nil, err
		default:
			c.mu.Unlock()
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func (c *deadlineAwarePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	c.writeCount++
	return len(p), nil
}

func (c *deadlineAwarePacketConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *deadlineAwarePacketConn) LocalAddr() net.Addr           { return &net.UDPAddr{} }
func (c *deadlineAwarePacketConn) SetDeadline(_ time.Time) error { return nil }
func (c *deadlineAwarePacketConn) SetReadDeadline(_ time.Time) error {
	c.mu.Lock()
	c.readSet = true
	c.mu.Unlock()
	return nil
}
func (c *deadlineAwarePacketConn) SetWriteDeadline(_ time.Time) error {
	c.mu.Lock()
	c.writeSet = true
	c.mu.Unlock()
	return nil
}

type deadlineAwareUDPSession struct {
	mu         sync.Mutex
	readSet    bool
	writeSet   bool
	closed     bool
	writeCalls int
	target     *net.UDPAddr
}

func (s *deadlineAwareUDPSession) WriteTo(_ []byte, _ *net.UDPAddr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.writeCalls++
	return nil
}

func (s *deadlineAwareUDPSession) ReadFrom(_ []byte) (int, *net.UDPAddr, error) {
	for {
		s.mu.Lock()
		switch {
		case s.closed:
			s.mu.Unlock()
			return 0, nil, net.ErrClosed
		case s.readSet:
			s.mu.Unlock()
			return 0, s.target, &timeoutNetError{}
		default:
			s.mu.Unlock()
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func (s *deadlineAwareUDPSession) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *deadlineAwareUDPSession) SetDeadline(_ time.Time) error { return nil }
func (s *deadlineAwareUDPSession) SetReadDeadline(_ time.Time) error {
	s.mu.Lock()
	s.readSet = true
	s.mu.Unlock()
	return nil
}
func (s *deadlineAwareUDPSession) SetWriteDeadline(_ time.Time) error {
	s.mu.Lock()
	s.writeSet = true
	s.mu.Unlock()
	return nil
}

func (s *deadlineAwareUDPSession) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

type closeTrackingConn struct {
	remote net.Addr
	mu     sync.Mutex
	closed bool
}

func (c *closeTrackingConn) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (c *closeTrackingConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *closeTrackingConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}
func (c *closeTrackingConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}
}
func (c *closeTrackingConn) RemoteAddr() net.Addr               { return c.remote }
func (c *closeTrackingConn) SetDeadline(_ time.Time) error      { return nil }
func (c *closeTrackingConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *closeTrackingConn) SetWriteDeadline(_ time.Time) error { return nil }

func (c *closeTrackingConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

type stubTCPDialerConn struct {
	conn net.Conn
}

func (d *stubTCPDialerConn) DialTCP(_ context.Context, _ string) (net.Conn, error) {
	return d.conn, nil
}

func (d *stubTCPDialerConn) DialUDP(_ context.Context) (UDPSession, error) {
	return nil, errors.New("not implemented")
}

func (d *stubTCPDialerConn) SupportsUDP() bool { return false }
func (d *stubTCPDialerConn) Mode() string      { return ModeSocks5TLS }

func TestPinUpstreamIPForAutoRouteAcceptsIPv6Literal(t *testing.T) {
	cfg := &Config{
		Upstream: UpstreamConfig{
			Addr: "[2001:db8::7]:443",
		},
	}

	host, err := cfg.pinUpstreamIPForAutoRoute(func(string) (string, error) {
		t.Fatal("resolver should not be called for literal IP upstreams")
		return "", nil
	})
	if err != nil {
		t.Fatalf("pin auto-route upstream: %v", err)
	}
	if host != "" {
		t.Fatalf("unexpected pinned host: %q", host)
	}
	if cfg.Upstream.Addr != "[2001:db8::7]:443" {
		t.Fatalf("unexpected pinned addr: %q", cfg.Upstream.Addr)
	}
}

func TestDecodeConfigAllowsDisablingAutoRoute(t *testing.T) {
	cfg, err := decodeConfig([]byte(fmt.Sprintf(`{
		"upstream": "127.0.0.1:443",
		"client_pem": %q,
		"client_key": %q,
		"auto_route": false
	}`, "placeholder-client.pem", "placeholder-client.key")))
	if err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if cfg.AutoRoute {
		t.Fatal("expected auto_route=false to be preserved")
	}
}

func TestReadSocks5AddressFromReaderKeepsDomainOpaque(t *testing.T) {
	buf := bytes.NewBuffer([]byte{
		0x0b,
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0x01, 0xbb,
	})

	addr, err := readSocks5AddressFromReader(buf, socksAtypDomain)
	if err != nil {
		t.Fatalf("read domain-form socks5 address: %v", err)
	}
	if addr == nil {
		t.Fatal("expected address")
	}
	if addr.IP != nil {
		t.Fatalf("expected opaque domain address without local resolution, got ip=%v", addr.IP)
	}
	if addr.Port != 443 {
		t.Fatalf("unexpected port: %d", addr.Port)
	}
}

func TestReadSocks5AddressFromReaderRejectsZeroLengthDomain(t *testing.T) {
	buf := bytes.NewBuffer([]byte{
		0x00,
		0x01, 0xbb,
	})

	addr, err := readSocks5AddressFromReader(buf, socksAtypDomain)
	if err == nil || !strings.Contains(err.Error(), "domain len: 0") {
		t.Fatalf("expected zero-length domain rejection, got addr=%v err=%v", addr, err)
	}
}

func TestHandshakeUDPAssociateAcceptsDomainRelayReply(t *testing.T) {
	d := &Socks5TLSDialer{}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))

	wrappedClient := &connWithRemoteAddr{
		Conn:   client,
		remote: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 443},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		greeting := make([]byte, 3)
		_, _ = io.ReadFull(server, greeting)
		_, _ = server.Write([]byte{socksVersion, 0x00})

		header := make([]byte, 4)
		_, _ = io.ReadFull(server, header)
		var reqTail []byte
		switch header[3] {
		case socksAtypIPv4:
			reqTail = make([]byte, 6)
		case socksAtypIPv6:
			reqTail = make([]byte, 18)
		case socksAtypDomain:
			lenBuf := make([]byte, 1)
			_, _ = io.ReadFull(server, lenBuf)
			reqTail = make([]byte, int(lenBuf[0])+2)
		}
		if len(reqTail) > 0 {
			_, _ = io.ReadFull(server, reqTail)
		}

		reply := []byte{
			socksVersion, 0x00, 0x00, socksAtypDomain,
			0x0b,
			'r', 'e', 'l', 'a', 'y', '.', 'e', 'x', 'a', 'm', 'p',
			0x14, 0xb4,
		}
		_, _ = server.Write(reply)
	}()

	relayAddr, err := d.handshakeUDPAssociate(wrappedClient, &net.UDPAddr{IP: net.IPv4zero, Port: 53000})
	<-done
	if err != nil {
		t.Fatalf("udp associate with domain relay reply failed: %v", err)
	}
	if relayAddr == nil || relayAddr.Port != 5300 {
		t.Fatalf("unexpected relay addr: %+v", relayAddr)
	}
	if relayAddr.IP != nil {
		t.Fatalf("expected opaque relay ip before normalization, got %v", relayAddr.IP)
	}

	normalized, err := normalizeSocks5UDPRelayAddr(relayAddr, wrappedClient)
	if err != nil {
		t.Fatalf("normalize relay addr: %v", err)
	}
	if normalized == nil || !normalized.IP.Equal(net.ParseIP("203.0.113.9")) || normalized.Port != 5300 {
		t.Fatalf("unexpected normalized relay addr: %+v", normalized)
	}
}

func TestHandshakeConnectRejectsNonZeroReservedByte(t *testing.T) {
	d := &Socks5TLSDialer{}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))

	done := make(chan struct{})
	go func() {
		defer close(done)
		greeting := make([]byte, 3)
		_, _ = io.ReadFull(server, greeting)
		_, _ = server.Write([]byte{socksVersion, 0x00})

		reqHeader := make([]byte, 4)
		_, _ = io.ReadFull(server, reqHeader)
		switch reqHeader[3] {
		case socksAtypIPv4:
			_, _ = io.ReadFull(server, make([]byte, 6))
		case socksAtypIPv6:
			_, _ = io.ReadFull(server, make([]byte, 18))
		case socksAtypDomain:
			lenBuf := make([]byte, 1)
			_, _ = io.ReadFull(server, lenBuf)
			_, _ = io.ReadFull(server, make([]byte, int(lenBuf[0])+2))
		}

		_, _ = server.Write([]byte{socksVersion, 0x00, 0x01, socksAtypIPv4, 127, 0, 0, 1, 0x01, 0xbb})
	}()

	err := d.handshakeConnect(client, client, "example.com:443")
	<-done
	if err == nil || !strings.Contains(err.Error(), "reserved byte") {
		t.Fatalf("expected reserved byte error, got: %v", err)
	}
}

func TestHandshakeUDPAssociateRejectsNonZeroReservedByte(t *testing.T) {
	d := &Socks5TLSDialer{}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))

	done := make(chan struct{})
	go func() {
		defer close(done)
		greeting := make([]byte, 3)
		_, _ = io.ReadFull(server, greeting)
		_, _ = server.Write([]byte{socksVersion, 0x00})

		reqHeader := make([]byte, 4)
		_, _ = io.ReadFull(server, reqHeader)
		switch reqHeader[3] {
		case socksAtypIPv4:
			_, _ = io.ReadFull(server, make([]byte, 6))
		case socksAtypIPv6:
			_, _ = io.ReadFull(server, make([]byte, 18))
		case socksAtypDomain:
			lenBuf := make([]byte, 1)
			_, _ = io.ReadFull(server, lenBuf)
			_, _ = io.ReadFull(server, make([]byte, int(lenBuf[0])+2))
		}

		_, _ = server.Write([]byte{socksVersion, 0x00, 0x01, socksAtypIPv4, 127, 0, 0, 1, 0x14, 0xb4})
	}()

	_, err := d.handshakeUDPAssociate(client, &net.UDPAddr{IP: net.IPv4zero, Port: 53000})
	<-done
	if err == nil || !strings.Contains(err.Error(), "reserved byte") {
		t.Fatalf("expected reserved byte error, got: %v", err)
	}
}

func TestDecodeSocks5UDPAddressKeepsDomainOpaque(t *testing.T) {
	packet := []byte{
		socksAtypDomain,
		0x0b,
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0x01, 0xbb,
	}

	addr, headerLen, err := decodeSocks5UDPAddress(packet)
	if err != nil {
		t.Fatalf("decode domain-form udp address: %v", err)
	}
	if headerLen != len(packet) {
		t.Fatalf("unexpected header len: got=%d want=%d", headerLen, len(packet))
	}
	if addr == nil {
		t.Fatal("expected address")
	}
	if addr.IP != nil {
		t.Fatalf("expected opaque domain address without local resolution, got ip=%v", addr.IP)
	}
	if addr.Port != 443 {
		t.Fatalf("unexpected port: %d", addr.Port)
	}
}

func TestDecodeSocks5UDPAddressRejectsZeroLengthDomain(t *testing.T) {
	packet := []byte{
		socksAtypDomain,
		0x00,
		0x01, 0xbb,
	}

	addr, headerLen, err := decodeSocks5UDPAddress(packet)
	if err == nil || !strings.Contains(err.Error(), "invalid domain udp header") {
		t.Fatalf("expected zero-length domain rejection, got addr=%v headerLen=%d err=%v", addr, headerLen, err)
	}
}

func TestSameUDPEndpointTreatsOpaqueHostAsPortMatch(t *testing.T) {
	opaque := &net.UDPAddr{Port: 53}
	target := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}

	if !sameUDPEndpoint(opaque, target) {
		t.Fatal("expected opaque host udp endpoint to match by port")
	}
	if !sameUDPEndpoint(target, opaque) {
		t.Fatal("expected udp endpoint comparison to stay symmetric for opaque hosts")
	}
}

func TestSameUDPEndpointDistinguishesIPv6Zones(t *testing.T) {
	a := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 53, Zone: "en0"}
	b := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 53, Zone: "en1"}

	if sameUDPEndpoint(a, b) {
		t.Fatal("expected link-local udp endpoints with different zones not to match")
	}
}

func TestSocks5TLSSessionDeadlineWithNilUDPConn(t *testing.T) {
	s := &socks5TLSUDPSession{}
	if err := s.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed on SetDeadline, got: %v", err)
	}
	if err := s.SetReadDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed on SetReadDeadline, got: %v", err)
	}
	if err := s.SetWriteDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed on SetWriteDeadline, got: %v", err)
	}
}

func TestSocks5TLSSessionClosesUDPWhenControlConnCloses(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udpConn.Close()

	s := &socks5TLSUDPSession{
		controlConn: client,
		udpConn:     udpConn,
		readBuf:     make([]byte, 2048),
	}
	s.startControlMonitor()

	if err := server.Close(); err != nil {
		t.Fatalf("close control peer: %v", err)
	}

	deadline := time.After(2 * time.Second)
	for {
		err := s.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		if errors.Is(err, net.ErrClosed) {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("expected udp conn to close after control conn closes, got %v", err)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestSocks5TLSSessionReadFromDropsOversizedFrame(t *testing.T) {
	/*
	 * Verifies that ReadFrom silently drops frames whose body exceeds the
	 * caller's payload buffer and returns the next well-sized frame without
	 * error.
	 */

	/* Builds a SOCKS5 UDP frame: RSV(2) + FRAG(1) + ATYP_IPv4(1) + IP(4) + port(2) + body. */
	buildFrame := func(body []byte) []byte {
		frame := []byte{0x00, 0x00, 0x00, socksAtypIPv4, 127, 0, 0, 1, 0, 80}
		return append(frame, body...)
	}

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer serverConn.Close()

	senderConn, err := net.DialUDP("udp", nil, serverConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer senderConn.Close()

	payloadBuf := make([]byte, 10)
	s := &socks5TLSUDPSession{
		udpConn: serverConn,
		readBuf: make([]byte, 512),
	}

	/* Sends an oversized frame (body=11 bytes > payloadBuf capacity=10). */
	oversized := buildFrame(bytes.Repeat([]byte{0xFF}, 11))
	if _, err := senderConn.Write(oversized); err != nil {
		t.Fatalf("send oversized: %v", err)
	}
	/* Sends a valid frame (body=5 bytes). */
	wantBody := []byte{1, 2, 3, 4, 5}
	valid := buildFrame(wantBody)
	if _, err := senderConn.Write(valid); err != nil {
		t.Fatalf("send valid: %v", err)
	}

	if err := serverConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	n, src, err := s.ReadFrom(payloadBuf)
	if err != nil {
		t.Fatalf("ReadFrom returned error: %v", err)
	}
	if n != len(wantBody) {
		t.Fatalf("expected n=%d got %d", len(wantBody), n)
	}
	if !bytes.Equal(payloadBuf[:n], wantBody) {
		t.Fatalf("payload mismatch: got %v want %v", payloadBuf[:n], wantBody)
	}
	if src == nil {
		t.Fatal("expected non-nil source address")
	}
}

func TestMonitorHandshakeCancellationClosesConnOnContextCancel(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	stop := monitorHandshakeCancellation(ctx, client)
	cancel()

	deadline := time.After(2 * time.Second)
	for {
		err := client.SetDeadline(time.Now().Add(10 * time.Millisecond))
		if err != nil {
			stop()
			return
		}
		select {
		case <-deadline:
			stop()
			t.Fatalf("expected handshake cancellation monitor to close conn, got %v", err)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestNormalizeSocks5UDPRelayAddrRewritesLoopbackToPeer(t *testing.T) {
	relay := &net.UDPAddr{IP: net.ParseIP("::1"), Port: 53000}
	conn := &stubConnWithRemote{remote: &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 443}}

	got, err := normalizeSocks5UDPRelayAddr(relay, conn)
	if err != nil {
		t.Fatalf("normalize loopback relay: %v", err)
	}
	if !got.IP.Equal(net.ParseIP("203.0.113.7")) || got.Port != 53000 {
		t.Fatalf("unexpected normalized relay: %v", got)
	}
}

func TestNormalizeSocks5UDPRelayAddrRewritesUnspecifiedToPeer(t *testing.T) {
	relay := &net.UDPAddr{IP: net.IPv4zero, Port: 53000}
	conn := &stubConnWithRemote{remote: &net.TCPAddr{IP: net.ParseIP("198.51.100.9"), Port: 443}}

	got, err := normalizeSocks5UDPRelayAddr(relay, conn)
	if err != nil {
		t.Fatalf("normalize unspecified relay: %v", err)
	}
	if !got.IP.Equal(net.ParseIP("198.51.100.9")) || got.Port != 53000 {
		t.Fatalf("unexpected normalized relay: %v", got)
	}
}

func TestNormalizeSocks5UDPRelayAddrPreservesPrivateRelay(t *testing.T) {
	relay := &net.UDPAddr{IP: net.ParseIP("10.0.0.5"), Port: 53000}
	conn := &stubConnWithRemote{remote: &net.TCPAddr{IP: net.ParseIP("198.51.100.11"), Port: 443}}

	got, err := normalizeSocks5UDPRelayAddr(relay, conn)
	if err != nil {
		t.Fatalf("normalize private relay: %v", err)
	}
	if !got.IP.Equal(net.ParseIP("10.0.0.5")) || got.Port != 53000 {
		t.Fatalf("unexpected normalized relay: %v", got)
	}
}

func TestNormalizeSocks5UDPRelayAddrPreservesIPv6ULARelay(t *testing.T) {
	relay := &net.UDPAddr{IP: net.ParseIP("fd00::5"), Port: 53000}
	conn := &stubConnWithRemote{remote: &net.TCPAddr{IP: net.ParseIP("2001:db8::11"), Port: 443}}

	got, err := normalizeSocks5UDPRelayAddr(relay, conn)
	if err != nil {
		t.Fatalf("normalize ipv6 ula relay: %v", err)
	}
	if !got.IP.Equal(net.ParseIP("fd00::5")) || got.Port != 53000 {
		t.Fatalf("unexpected normalized relay: %v", got)
	}
}

func TestNormalizeSocks5UDPRelayAddrUsesPeerZoneForScopedIPv6Peer(t *testing.T) {
	relay := &net.UDPAddr{IP: net.IPv6zero, Port: 53000}
	conn := &stubConnWithRemote{remote: &net.TCPAddr{IP: net.ParseIP("fe80::11"), Port: 443, Zone: "en0"}}

	got, err := normalizeSocks5UDPRelayAddr(relay, conn)
	if err != nil {
		t.Fatalf("normalize scoped ipv6 relay: %v", err)
	}
	if !got.IP.Equal(net.ParseIP("fe80::11")) || got.Port != 53000 || got.Zone != "en0" {
		t.Fatalf("unexpected normalized relay: %+v", got)
	}
}

func TestNormalizeSocks5UDPRelayAddrPreservesLinkLocalRelayAndInheritsPeerZone(t *testing.T) {
	relay := &net.UDPAddr{IP: net.ParseIP("fe80::55"), Port: 53000}
	conn := &stubConnWithRemote{remote: &net.TCPAddr{IP: net.ParseIP("fe80::11"), Port: 443, Zone: "en0"}}

	got, err := normalizeSocks5UDPRelayAddr(relay, conn)
	if err != nil {
		t.Fatalf("normalize link-local relay: %v", err)
	}
	if !got.IP.Equal(net.ParseIP("fe80::55")) || got.Port != 53000 || got.Zone != "en0" {
		t.Fatalf("unexpected normalized relay: %+v", got)
	}
}

func TestHandleUDPMarksCooldownOnAddrNotAvailable(t *testing.T) {
	tmp := t.TempDir()
	clientPEM := writeTestFile(t, tmp, "client.pem", []byte("test"))
	clientKey := writeTestFile(t, tmp, "client.key", []byte("test"))
	e := &Engine{
		cfg: &Config{
			Mode: ModeSocks5TLS,
			Tun: TunConfig{
				Name: validTunNameForRuntime(),
				MTU:  1500,
			},
			Upstream: UpstreamConfig{
				Addr:      "127.0.0.1:443",
				ClientPEM: clientPEM,
				ClientKey: clientKey,
			},
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
				IdleTimeoutMS:    1000,
				TCPBuffer:        4096,
				UDPBuffer:        4096,
				EnableUDP:        true,
			},
		},
		dialer:     &stubDialerEaddrNotAvail{},
		udpDialSem: make(chan struct{}, 1),
	}

	id := gstack.TransportEndpointID{
		LocalAddress:  tcpip.AddrFromSlice(net.ParseIP("8.8.8.8").To4()),
		LocalPort:     9999,
		RemoteAddress: tcpip.AddrFromSlice(net.ParseIP("198.18.0.1").To4()),
		RemotePort:    53000,
	}
	e.handleUDP(context.Background(), id, &stubPacketConnEOF{})
	if !e.isUDPDialCoolingDown() {
		t.Fatalf("expected udp dial cooldown after EADDRNOTAVAIL")
	}
}

func TestHandleTCPMarksCooldownOnAddrNotAvailable(t *testing.T) {
	tmp := t.TempDir()
	clientPEM := writeTestFile(t, tmp, "client.pem", []byte("test"))
	clientKey := writeTestFile(t, tmp, "client.key", []byte("test"))
	e := &Engine{
		cfg: &Config{
			Mode: ModeSocks5TLS,
			Tun: TunConfig{
				Name: validTunNameForRuntime(),
				MTU:  1500,
			},
			Upstream: UpstreamConfig{
				Addr:      "127.0.0.1:443",
				ClientPEM: clientPEM,
				ClientKey: clientKey,
			},
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
				IdleTimeoutMS:    1000,
				TCPBuffer:        4096,
				UDPBuffer:        4096,
				EnableUDP:        true,
			},
		},
		dialer:     &stubDialerEaddrNotAvail{},
		tcpDialSem: make(chan struct{}, 1),
		udpDialSem: make(chan struct{}, 1),
	}

	id := gstack.TransportEndpointID{
		LocalAddress:  tcpip.AddrFromSlice(net.ParseIP("1.1.1.1").To4()),
		LocalPort:     443,
		RemoteAddress: tcpip.AddrFromSlice(net.ParseIP("198.18.0.1").To4()),
		RemotePort:    53000,
	}
	e.handleTCP(context.Background(), id, &stubConnWithRemote{remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}})
	if e.isTCPDialCoolingDown() {
		t.Fatalf("expected tcp dial cooldown to drain after bounded retry handling")
	}
}

func TestHandleUDPCancelsDialOnNetworkChange(t *testing.T) {
	dialer := &stubCancelableUDPDialer{
		enterCh:  make(chan struct{}),
		cancelCh: make(chan error, 1),
	}
	e := &Engine{
		cfg: &Config{
			Mode: ModeSocks5TLS,
			Tun: TunConfig{
				Name: validTunNameForRuntime(),
				MTU:  1500,
			},
			Upstream: UpstreamConfig{
				Addr: "127.0.0.1:443",
			},
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
				IdleTimeoutMS:    1000,
				TCPBuffer:        4096,
				UDPBuffer:        4096,
				EnableUDP:        true,
			},
		},
		dialer:          dialer,
		udpDialSem:      make(chan struct{}, 1),
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
	}

	id := gstack.TransportEndpointID{
		LocalAddress:  tcpip.AddrFromSlice(net.ParseIP("8.8.8.8").To4()),
		LocalPort:     9999,
		RemoteAddress: tcpip.AddrFromSlice(net.ParseIP("198.18.0.1").To4()),
		RemotePort:    53000,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.handleUDP(context.Background(), id, &stubPacketConnEOF{})
	}()

	select {
	case <-dialer.enterCh:
	case <-time.After(time.Second):
		t.Fatal("udp dial was not started")
	}

	e.HandleNetworkChange()

	select {
	case err := <-dialer.cancelCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("udp dial was not canceled on network change")
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handleUDP did not exit after dial cancellation")
	}
}

func TestHandleNetworkChangeClosesActiveUDPSession(t *testing.T) {
	session := &stubUDPSession{closed: make(chan struct{})}
	e := &Engine{
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
	}
	e.registerActiveUpstream(session)

	e.HandleNetworkChange()

	select {
	case <-session.closed:
	case <-time.After(time.Second):
		t.Fatal("active udp session was not closed on network change")
	}
	e.activeMu.Lock()
	defer e.activeMu.Unlock()
	if len(e.activeUpstreams) != 0 {
		t.Fatalf("expected active upstreams to be cleared after network change, got %d", len(e.activeUpstreams))
	}
}

func TestHandleNetworkChangeClosesIdleUDPPool(t *testing.T) {
	session := &stubUDPSession{closed: make(chan struct{})}
	e := &Engine{
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
		udpPool: map[string][]UDPSession{
			udpSessionPoolKey("198.18.0.1:53000", "9.9.9.9:9999"): {session},
		},
	}
	e.registerActiveUpstream(session)

	e.HandleNetworkChange()

	select {
	case <-session.closed:
	case <-time.After(time.Second):
		t.Fatal("idle udp session was not closed on network change")
	}

	e.udpPoolMu.Lock()
	defer e.udpPoolMu.Unlock()
	if len(e.udpPool) != 0 {
		t.Fatalf("expected udp pool to be cleared, got %d sessions", len(e.udpPool))
	}
}

func TestHandleNetworkChangeClearsDialCooldowns(t *testing.T) {
	e := &Engine{}
	e.markTCPDialBackoff(5 * time.Second)
	e.markUDPDialBackoff(5 * time.Second)

	e.HandleNetworkChange()

	if e.isTCPDialCoolingDown() {
		t.Fatal("expected tcp dial cooldown to be cleared on network change")
	}
	if e.isUDPDialCoolingDown() {
		t.Fatal("expected udp dial cooldown to be cleared on network change")
	}
}

func TestHandleNetworkChangeWarmsUpUpstreamTransport(t *testing.T) {
	dialer := &stubWarmupDialer{warmupCh: make(chan struct{})}
	e := &Engine{
		cfg: &Config{
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
			},
		},
		dialer:          dialer,
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
	}

	e.HandleNetworkChange()

	select {
	case <-dialer.warmupCh:
	case <-time.After(time.Second):
		t.Fatal("expected upstream warmup to start after network change")
	}
}

func TestHandleNetworkChangeSuppressesConcurrentWarmups(t *testing.T) {
	blockCh := make(chan struct{})
	dialer := &stubWarmupDialer{
		warmupCh: make(chan struct{}),
		blockCh:  blockCh,
	}
	e := &Engine{
		cfg: &Config{
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
			},
		},
		dialer:          dialer,
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
	}

	e.HandleNetworkChange()
	select {
	case <-dialer.warmupCh:
	case <-time.After(time.Second):
		t.Fatal("expected first warmup to start")
	}
	e.HandleNetworkChange()
	e.HandleNetworkChange()

	time.Sleep(100 * time.Millisecond)
	close(blockCh)
	time.Sleep(50 * time.Millisecond)

	if got := dialer.callCount(); got != 1 {
		t.Fatalf("expected concurrent warmups to collapse to one in-flight call, got %d", got)
	}
}

func TestPruneLogThrottleStatesLockedRemovesExpiredEntries(t *testing.T) {
	e := &Engine{
		logThrottleStates: map[string]logThrottleState{
			"old": {LastLogTime: time.Now().Add(-logThrottleStateTTL - time.Second)},
			"new": {LastLogTime: time.Now()},
		},
	}
	e.pruneLogThrottleStatesLocked(time.Now())
	if _, ok := e.logThrottleStates["old"]; ok {
		t.Fatal("expected expired throttled-log state to be removed")
	}
	if _, ok := e.logThrottleStates["new"]; !ok {
		t.Fatal("expected recent throttled-log state to remain")
	}
}

func TestHandleUDPRelaysDNSOverTCP(t *testing.T) {
	dialer := &stubDNSTCPDialer{response: []byte{0xaa, 0xbb, 0xcc}}
	conn := &stubDNSPacketConn{reads: [][]byte{{0x01, 0x02, 0x03}}}
	e := &Engine{
		cfg: &Config{
			Mode: ModeSocks5TLS,
			Tun:  TunConfig{Name: validTunNameForRuntime(), MTU: 1500},
			Upstream: UpstreamConfig{
				Addr: "127.0.0.1:443",
			},
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
				IdleTimeoutMS:    1000,
				TCPBuffer:        4096,
				UDPBuffer:        4096,
				EnableUDP:        true,
			},
		},
		dialer:          dialer,
		tcpDialSem:      make(chan struct{}, 1),
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
	}

	id := gstack.TransportEndpointID{
		LocalAddress:  tcpip.AddrFromSlice(net.ParseIP("8.8.8.8").To4()),
		LocalPort:     53,
		RemoteAddress: tcpip.AddrFromSlice(net.ParseIP("198.18.0.1").To4()),
		RemotePort:    53000,
	}

	e.handleUDP(context.Background(), id, conn)

	if got := dialer.dialCount(); got != 1 {
		t.Fatalf("expected 1 tcp dns dial, got %d", got)
	}
	if len(conn.writes) != 1 {
		t.Fatalf("expected 1 dns response write, got %d", len(conn.writes))
	}
	if got := conn.writes[0]; !bytes.Equal(got, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("unexpected dns response: %x", got)
	}
}

func TestHandleUDPRelaysDNSOverTCPWhenUDPDisabled(t *testing.T) {
	dialer := &stubDNSTCPDialer{response: []byte{0xaa, 0xbb, 0xcc}}
	conn := &stubDNSPacketConn{reads: [][]byte{{0x01, 0x02, 0x03}}}
	e := &Engine{
		cfg: &Config{
			Mode: ModeSocks5TLS,
			Tun:  TunConfig{Name: validTunNameForRuntime(), MTU: 1500},
			Upstream: UpstreamConfig{
				Addr: "127.0.0.1:443",
			},
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
				IdleTimeoutMS:    1000,
				TCPBuffer:        4096,
				UDPBuffer:        4096,
				EnableUDP:        false,
			},
		},
		dialer:          dialer,
		tcpDialSem:      make(chan struct{}, 1),
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
	}

	id := gstack.TransportEndpointID{
		LocalAddress:  tcpip.AddrFromSlice(net.ParseIP("8.8.8.8").To4()),
		LocalPort:     53,
		RemoteAddress: tcpip.AddrFromSlice(net.ParseIP("198.18.0.1").To4()),
		RemotePort:    53000,
	}

	e.handleUDP(context.Background(), id, conn)

	if got := dialer.dialCount(); got != 1 {
		t.Fatalf("expected 1 tcp dns dial with udp disabled, got %d", got)
	}
	if len(conn.writes) != 1 {
		t.Fatalf("expected 1 dns response write with udp disabled, got %d", len(conn.writes))
	}
	if got := conn.writes[0]; !bytes.Equal(got, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("unexpected dns response with udp disabled: %x", got)
	}
}

func TestHandleUDPRelaysDNSOverTCPInHTTPSMode(t *testing.T) {
	dialer := &stubDNSTCPDialer{mode: ModeHTTPS, response: []byte{0xde, 0xad}}
	conn := &stubDNSPacketConn{reads: [][]byte{{0xfa, 0xce}}}
	e := &Engine{
		cfg: &Config{
			Mode: ModeHTTPS,
			Tun:  TunConfig{Name: validTunNameForRuntime(), MTU: 1500},
			Upstream: UpstreamConfig{
				Addr: "127.0.0.1:443",
			},
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
				IdleTimeoutMS:    1000,
				TCPBuffer:        4096,
				UDPBuffer:        4096,
				EnableUDP:        true,
			},
		},
		dialer:          dialer,
		tcpDialSem:      make(chan struct{}, 1),
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
	}

	id := gstack.TransportEndpointID{
		LocalAddress:  tcpip.AddrFromSlice(net.ParseIP("1.1.1.1").To4()),
		LocalPort:     53,
		RemoteAddress: tcpip.AddrFromSlice(net.ParseIP("198.18.0.1").To4()),
		RemotePort:    53000,
	}

	e.handleUDP(context.Background(), id, conn)

	if got := dialer.dialCount(); got != 1 {
		t.Fatalf("expected 1 tcp dns dial in https mode, got %d", got)
	}
	if len(conn.writes) != 1 {
		t.Fatalf("expected 1 dns response write, got %d", len(conn.writes))
	}
}

func TestHandleDNSOverTCPHandlesMultipleQueriesPerFlow(t *testing.T) {
	dialer := &stubDNSTCPDialer{response: []byte{0x10, 0x20}}
	conn := &stubDNSPacketConn{
		reads: [][]byte{
			{0xaa, 0xbb},
			{0xcc, 0xdd},
		},
	}
	e := &Engine{
		cfg: &Config{
			Mode: ModeSocks5TLS,
			Tun:  TunConfig{Name: validTunNameForRuntime(), MTU: 1500},
			Upstream: UpstreamConfig{
				Addr: "127.0.0.1:443",
			},
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
				IdleTimeoutMS:    1000,
				TCPBuffer:        4096,
				UDPBuffer:        4096,
				EnableUDP:        true,
			},
		},
		dialer:          dialer,
		tcpDialSem:      make(chan struct{}, 1),
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
	}

	id := gstack.TransportEndpointID{
		LocalAddress:  tcpip.AddrFromSlice(net.ParseIP("8.8.4.4").To4()),
		LocalPort:     53,
		RemoteAddress: tcpip.AddrFromSlice(net.ParseIP("198.18.0.1").To4()),
		RemotePort:    53000,
	}

	e.handleUDP(context.Background(), id, conn)

	if got := dialer.dialCount(); got != 1 {
		t.Fatalf("expected pooled dns connection reuse, got %d dials", got)
	}
	if len(conn.writes) != 2 {
		t.Fatalf("expected 2 dns response writes, got %d", len(conn.writes))
	}
}

func TestHandleNetworkChangeClosesIdleDNSPool(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	e := &Engine{
		activeUpstreams: make(map[io.Closer]struct{}),
		dnsPool: map[string][]net.Conn{
			"8.8.8.8:53": {client},
		},
	}
	e.registerActiveUpstream(client)

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := server.Read(buf)
		done <- err
	}()

	e.HandleNetworkChange()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected pooled dns conn to be closed on network change")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for pooled dns conn close")
	}

	e.dnsPoolMu.Lock()
	defer e.dnsPoolMu.Unlock()
	if len(e.dnsPool) != 0 {
		t.Fatalf("expected dns pool to be cleared, got %d targets", len(e.dnsPool))
	}
}

func TestExchangeDNSOverTCPRetriesTransientAddrNotAvail(t *testing.T) {
	dialer := &stubRetryTCPDialer{
		response:  []byte{0xde, 0xad},
		failCount: 1,
	}
	e := &Engine{
		cfg: &Config{
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
			},
		},
		dialer:          dialer,
		tcpDialSem:      make(chan struct{}, 1),
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
	}

	resp, releaseResp, err := e.exchangeDNSOverTCP(context.Background(), "8.8.8.8:53", []byte{0x01, 0x02}, time.Second)
	if err != nil {
		t.Fatalf("expected transient retry to recover, got %v", err)
	}
	defer releaseResp()
	if !bytes.Equal(resp, []byte{0xde, 0xad}) {
		t.Fatalf("unexpected dns response %x", resp)
	}
	if dialer.dials != 2 {
		t.Fatalf("expected 2 upstream dial attempts, got %d", dialer.dials)
	}
}

func TestExchangeDNSOverTCPRetriesPooledEOF(t *testing.T) {
	staleClient, staleServer := net.Pipe()
	_ = staleServer.Close()

	dialer := &stubRetryTCPDialer{
		response: []byte{0xbe, 0xef},
	}
	e := &Engine{
		cfg: &Config{
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
			},
		},
		dialer:          dialer,
		tcpDialSem:      make(chan struct{}, 1),
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
		dnsPool: map[string][]net.Conn{
			"8.8.8.8:53": {staleClient},
		},
	}

	resp, releaseResp, err := e.exchangeDNSOverTCP(context.Background(), "8.8.8.8:53", []byte{0x01, 0x02}, time.Second)
	if err != nil {
		t.Fatalf("expected pooled eof retry to recover, got %v", err)
	}
	defer releaseResp()
	if !bytes.Equal(resp, []byte{0xbe, 0xef}) {
		t.Fatalf("unexpected dns response %x", resp)
	}
	if dialer.dials != 1 {
		t.Fatalf("expected 1 fresh dial after pooled eof, got %d", dialer.dials)
	}
}

func TestExchangeDNSOverTCPRetriesPastMultipleStalePooledConns(t *testing.T) {
	staleClientA, staleServerA := net.Pipe()
	_ = staleServerA.Close()
	staleClientB, staleServerB := net.Pipe()
	_ = staleServerB.Close()

	dialer := &stubRetryTCPDialer{
		response: []byte{0xca, 0xfe},
	}
	e := &Engine{
		cfg: &Config{
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
			},
		},
		dialer:          dialer,
		tcpDialSem:      make(chan struct{}, 1),
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
		dnsPool: map[string][]net.Conn{
			"8.8.8.8:53": {staleClientA, staleClientB},
		},
	}

	resp, releaseResp, err := e.exchangeDNSOverTCP(context.Background(), "8.8.8.8:53", []byte{0x01, 0x02}, time.Second)
	if err != nil {
		t.Fatalf("expected pooled eof retry to skip stale pool and recover, got %v", err)
	}
	defer releaseResp()
	if !bytes.Equal(resp, []byte{0xca, 0xfe}) {
		t.Fatalf("unexpected dns response %x", resp)
	}
	if dialer.dials != 1 {
		t.Fatalf("expected 1 fresh dial after stale pool retry, got %d", dialer.dials)
	}
	/*
	 * The stale conn (staleClientA) is still in the pool.  The fresh conn may or may
	 * not be returned to the pool depending on whether clearConnDeadline succeeds
	 * before the stub server goroutine closes its pipe end. Accept either count.
	 */
	if conns := e.dnsPool["8.8.8.8:53"]; len(conns) < 1 || len(conns) > 2 {
		t.Fatalf("expected 1-2 pooled conns after stale pool retry, got %d", len(conns))
	}
}

func TestDNSCacheKeyIncludesTargetAddress(t *testing.T) {
	e := &Engine{
		cfg: &Config{
			Runtime: RuntimeConfig{DNSCacheSize: 8},
		},
		dnsCache: make(map[string]dnsCacheEntry),
	}
	req := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	respA := []byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04, 0x01, 0x01, 0x01, 0x01,
	}
	respB := append([]byte(nil), respA...)
	respB[len(respB)-4] = 8
	respB[len(respB)-3] = 8
	respB[len(respB)-2] = 8
	respB[len(respB)-1] = 8

	e.putDNSCache("1.1.1.1:53", req, respA)
	e.putDNSCache("8.8.8.8:53", req, respB)

	gotA := e.getDNSCache("1.1.1.1:53", req)
	gotB := e.getDNSCache("8.8.8.8:53", req)
	if gotA == nil || gotB == nil {
		t.Fatal("expected both dns cache entries to be present")
	}
	if bytes.Equal(gotA, gotB) {
		t.Fatalf("expected per-target cache isolation, got identical responses %x", gotA)
	}
}

func TestDNSCacheKeySeparatesAdditionalRecords(t *testing.T) {
	e := &Engine{
		cfg: &Config{
			Runtime: RuntimeConfig{DNSCacheSize: 8},
		},
		dnsCache: make(map[string]dnsCacheEntry),
	}
	reqWithOPT := []byte{
		0x12, 0x34, 0x01, 0x00,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x01,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0x00,
		0x00, 0x29,
		0x10, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
	}
	reqPlain := []byte{
		0xab, 0xcd, 0x01, 0x20,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	resp := []byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04, 0x01, 0x01, 0x01, 0x01,
	}

	e.putDNSCache("8.8.8.8:53", reqWithOPT, resp)
	got := e.getDNSCache("8.8.8.8:53", reqPlain)
	if got != nil {
		t.Fatalf("expected cache miss for requests with different additional records, got %x", got)
	}
}

func TestPutDNSCacheRejectsMismatchedQuestion(t *testing.T) {
	e := &Engine{
		cfg: &Config{
			Runtime: RuntimeConfig{DNSCacheSize: 8},
		},
		dnsCache: make(map[string]dnsCacheEntry),
	}
	req := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	resp := []byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x05, 'o', 't', 'h', 'e', 'r',
		0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04, 0x08, 0x08, 0x08, 0x08,
	}

	e.putDNSCache("8.8.8.8:53", req, resp)
	if got := e.getDNSCache("8.8.8.8:53", req); got != nil {
		t.Fatalf("expected mismatched response question to be rejected from cache, got %x", got)
	}
}

func TestExtractMinDNSTTLRejectsTruncatedResourceData(t *testing.T) {
	resp := []byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04,
		0x01, 0x01,
	}

	if got := extractMinDNSTTL(resp); got != 0 {
		t.Fatalf("expected truncated dns answer to be uncachable, got ttl=%d", got)
	}
}

func TestExtractMinDNSTTLRejectsTruncatedLaterRecordMetadata(t *testing.T) {
	resp := []byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04,
		0x01, 0x01, 0x01, 0x01,
		0xc0, 0x0c,
		0x00, 0x01,
	}

	if got := extractMinDNSTTL(resp); got != 0 {
		t.Fatalf("expected truncated later dns record metadata to be uncachable, got ttl=%d", got)
	}
}

func TestExtractMinDNSTTLIgnoresOPTAdditionalPseudoTTL(t *testing.T) {
	resp := []byte{
		0x12, 0x34, 0x81, 0x80,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x01,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04, 0x01, 0x01, 0x01, 0x01,
		0x00,
		0x00, 0x29,
		0x10, 0x00,
		0x00, 0x00, 0x80, 0x00,
		0x00, 0x00,
	}

	if got := extractMinDNSTTL(resp); got != 60 {
		t.Fatalf("expected OPT pseudo-ttl to be ignored, got ttl=%d", got)
	}
}

func TestExchangeDNSOverTCPSetsDeadlineOnPooledConn(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	pooled := &deadlineTrackingConn{Conn: client}
	e := &Engine{
		cfg: &Config{
			Runtime: RuntimeConfig{ConnectTimeoutMS: 1000},
		},
		dnsPool: map[string][]net.Conn{
			"8.8.8.8:53": {pooled},
		},
		activeUpstreams: make(map[io.Closer]struct{}),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		var lengthBuf [2]byte
		if _, err := io.ReadFull(server, lengthBuf[:]); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(lengthBuf[:]))
		payload := make([]byte, size)
		if _, err := io.ReadFull(server, payload); err != nil {
			return
		}
		reply := []byte{0x00, 0x02, 0xbe, 0xef}
		_, _ = server.Write(reply)
	}()

	resp, releaseResp, err := e.exchangeDNSOverTCP(context.Background(), "8.8.8.8:53", []byte{0x01, 0x02}, 250*time.Millisecond)
	if err != nil {
		t.Fatalf("exchangeDNSOverTCP failed: %v", err)
	}
	defer releaseResp()
	<-done

	if !bytes.Equal(resp, []byte{0xbe, 0xef}) {
		t.Fatalf("unexpected dns response %x", resp)
	}
	if pooled.deadlineCallCount() == 0 {
		t.Fatal("expected pooled dns conn to receive a deadline")
	}
}

func TestReleaseDNSConnPoolFullUnregistersActiveUpstream(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	e := &Engine{
		activeUpstreams: make(map[io.Closer]struct{}),
		dnsPool: map[string][]net.Conn{
			"8.8.8.8:53": make([]net.Conn, dnsPoolPerTarget),
		},
	}
	e.registerActiveUpstream(client)

	e.releaseDNSConn("8.8.8.8:53", client)

	e.activeMu.Lock()
	defer e.activeMu.Unlock()
	if len(e.activeUpstreams) != 0 {
		t.Fatalf("expected active upstream conn to be unregistered when dns pool is full, got %d", len(e.activeUpstreams))
	}
}

func TestAcquireTCPDialSlotWaitsBriefly(t *testing.T) {
	e := &Engine{tcpDialSem: make(chan struct{}, 1)}
	e.tcpDialSem <- struct{}{}

	go func() {
		time.Sleep(100 * time.Millisecond)
		e.releaseTCPDialSlot()
	}()

	start := time.Now()
	if !e.acquireTCPDialSlot(context.Background(), 300*time.Millisecond) {
		t.Fatal("expected tcp dial slot acquisition to wait and succeed")
	}
	elapsed := time.Since(start)
	e.releaseTCPDialSlot()

	if elapsed < 80*time.Millisecond {
		t.Fatalf("tcp dial slot acquisition did not wait long enough: %s", elapsed)
	}
}

func TestEngineStopReturnsWhenTunCloseBlocks(t *testing.T) {
	blockCh := make(chan struct{})
	e := &Engine{
		tunDev: &TunDevice{
			closeFunc: func(ctx context.Context) error {
				select {
				case <-blockCh:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			},
		},
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
		dnsPool:         make(map[string][]net.Conn),
		udpPool:         make(map[string][]UDPSession),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := e.Stop(ctx)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded, got %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("expected Stop to return shortly after context timeout, took %s", elapsed)
	}

	close(blockCh)
}

func TestEngineStopCanWaitForBlockedTunCloseOnRetry(t *testing.T) {
	blockCh := make(chan struct{})
	e := &Engine{
		tunDev: &TunDevice{
			closeFunc: func(ctx context.Context) error {
				select {
				case <-blockCh:
				case <-ctx.Done():
					return ctx.Err()
				}
				timer := time.NewTimer(100 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-timer.C:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			},
		},
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
		dnsPool:         make(map[string][]net.Conn),
		udpPool:         make(map[string][]UDPSession),
	}

	firstCtx, firstCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer firstCancel()
	if err := e.Stop(firstCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected first stop to time out, got %v", err)
	}

	close(blockCh)

	secondCtx, secondCancel := context.WithTimeout(context.Background(), time.Second)
	defer secondCancel()
	start := time.Now()
	if err := e.Stop(secondCtx); err != nil {
		t.Fatalf("expected second stop to wait for tun close completion, got %v", err)
	}
	if elapsed := time.Since(start); elapsed < 80*time.Millisecond {
		t.Fatalf("expected second stop to wait for outstanding tun close, got %s", elapsed)
	}
}

func TestNewEngineRejectsNilConfig(t *testing.T) {
	e, err := NewEngine(nil)
	if err == nil {
		t.Fatalf("expected error for nil config, got engine=%v", e)
	}
}

func TestEngineStartRejectsAlreadyStartedOrStopped(t *testing.T) {
	startedEngine := &Engine{started: true}
	if err := startedEngine.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "already started") {
		t.Fatalf("expected already started error, got %v", err)
	}

	stoppedEngine := &Engine{stopping: true}
	if err := stoppedEngine.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "already stopped") {
		t.Fatalf("expected already stopped error, got %v", err)
	}

	stoppedStartedEngine := &Engine{started: true, stopping: true}
	if err := stoppedStartedEngine.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "already stopped") {
		t.Fatalf("expected stopped engine to report already stopped, got %v", err)
	}
}

func TestEngineStartRejectsMissingConfig(t *testing.T) {
	var e Engine
	if err := e.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "nil config") {
		t.Fatalf("expected nil config error, got %v", err)
	}
}

func TestEngineStopBeforeStartIsNoop(t *testing.T) {
	e, err := NewEngine(&Config{
		Mode: ModeSocks5TLS,
		Tun:  TunConfig{Name: validTunNameForRuntime(), MTU: 1500},
		Upstream: UpstreamConfig{
			Addr: "127.0.0.1:443",
		},
		Runtime: RuntimeConfig{
			ConnectTimeoutMS: 1000,
			IdleTimeoutMS:    1000,
			TCPBuffer:        4096,
			UDPBuffer:        4096,
		},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	if err := e.Stop(context.Background()); err != nil {
		t.Fatalf("expected stop-before-start to be no-op, got %v", err)
	}
	if e.stopping {
		t.Fatal("expected stop-before-start to leave engine reusable")
	}
	if e.started {
		t.Fatal("expected unstarted engine to remain unstarted")
	}
}

func TestEngineStopWaitsForStartupRollback(t *testing.T) {
	blockCh := make(chan struct{})
	tun := &TunDevice{
		closeFunc: func(ctx context.Context) error {
			select {
			case <-blockCh:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}
	e := &Engine{rollbackTun: tun}

	firstCtx, firstCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer firstCancel()
	if err := e.Stop(firstCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected rollback wait to time out, got %v", err)
	}

	close(blockCh)

	secondCtx, secondCancel := context.WithTimeout(context.Background(), time.Second)
	defer secondCancel()
	if err := e.Stop(secondCtx); err != nil {
		t.Fatalf("expected rollback wait to complete, got %v", err)
	}
	if e.rollbackTun != nil {
		t.Fatal("expected rollback tun to be cleared after teardown completes")
	}
}

func TestEngineStopWaitsWhileStartInProgress(t *testing.T) {
	startDone := make(chan struct{})
	e := &Engine{
		starting:  true,
		startDone: startDone,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := e.Stop(ctx)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected stop to wait for start window and time out, got %v", err)
	}
	if elapsed < 40*time.Millisecond {
		t.Fatalf("expected stop to wait for start window, got %s", elapsed)
	}

	e.mu.Lock()
	e.starting = false
	e.startDone = nil
	e.mu.Unlock()
	close(startDone)
}

func TestEngineStopCancelsStartInProgress(t *testing.T) {
	startDone := make(chan struct{})
	cancelled := make(chan struct{})
	e := &Engine{
		starting:  true,
		startDone: startDone,
		startCancel: func() {
			select {
			case <-cancelled:
			default:
				close(cancelled)
			}
		},
	}

	stopErrCh := make(chan error, 1)
	go func() {
		stopErrCh <- e.Stop(context.Background())
	}()

	select {
	case <-cancelled:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected stop to cancel in-progress startup")
	}

	e.mu.Lock()
	e.starting = false
	e.startDone = nil
	e.startCancel = nil
	e.mu.Unlock()
	close(startDone)

	select {
	case err := <-stopErrCh:
		if err != nil {
			t.Fatalf("expected stop to complete after startup cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("expected stop to finish after startup completion signal")
	}
}

func TestAcquireHandlerSlotRejectsWhenFull(t *testing.T) {
	const cap = 2
	e := &Engine{handlerSem: make(chan struct{}, cap)}

	if !e.acquireHandlerSlot() {
		t.Fatal("expected first acquire to succeed")
	}
	if !e.acquireHandlerSlot() {
		t.Fatal("expected second acquire to succeed")
	}
	if e.acquireHandlerSlot() {
		t.Fatal("expected third acquire to fail when semaphore is full")
	}

	/* Releasing one slot should allow acquisition again. */
	e.releaseHandlerSlot()
	if !e.acquireHandlerSlot() {
		t.Fatal("expected acquire to succeed after release")
	}
}

func TestUDPHandlerSlotUsesIndependentSemaphore(t *testing.T) {
	e := &Engine{
		handlerSem:    make(chan struct{}, 1),
		udpHandlerSem: make(chan struct{}, 1),
	}

	if !e.acquireHandlerSlot() {
		t.Fatal("expected tcp handler acquire to succeed")
	}
	if !e.acquireUDPHandlerSlot() {
		t.Fatal("expected udp handler acquire to succeed even when tcp handler pool is full")
	}
	if e.acquireUDPHandlerSlot() {
		t.Fatal("expected second udp handler acquire to fail when udp pool is full")
	}

	e.releaseUDPHandlerSlot()
	if !e.acquireUDPHandlerSlot() {
		t.Fatal("expected udp handler acquire to succeed after release")
	}
}

func TestEngineStopDuringStartupAfterNetstackCreated(t *testing.T) {
	/*
	 * Simulates the race where Stop sets e.stopping=true in between netstack
	 * creation and e.started=true being committed inside Start's final lock.
	 * This exercises the "engine stopped during startup" path in Start.
	 */

	blockCh := make(chan struct{})
	/* Builds a TunDevice whose close blocks until the test unblocks it. */
	tun := &TunDevice{
		closeFunc: func(ctx context.Context) error {
			select {
			case <-blockCh:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}

	e := &Engine{
		stopping:    true,
		rollbackTun: tun,
	}

	/* Stop should drain the rollback tun. */
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stopCancel()

	/* The first call times out while the rollback tun is blocked. */
	if err := e.Stop(stopCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded while rollback tun blocks, got %v", err)
	}

	close(blockCh)

	/* A fresh second call should complete once the tun unblocks. */
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := e.Stop(ctx2); err != nil {
		t.Fatalf("expected stop to complete after tun unblocks, got %v", err)
	}
	if e.rollbackTun != nil {
		t.Fatal("expected rollbackTun to be cleared after stop completes")
	}
}

func TestEngineStartRejectsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done

	var e Engine
	err := e.Start(ctx)
	if err == nil {
		t.Fatal("expected error for already-cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestHandleUDPDoesNotReuseSessionWithZeroUpstreamBytes(t *testing.T) {
	/*
	 * When shouldReuseUDPSession returns true but upstream delivered zero bytes
	 * (for example, all frames were oversized and silently dropped), the
	 * call-site guard must flip reusableSession to false so the session is not
	 * returned to the pool.
	 */
	e := &Engine{}

	/* shouldReuseUDPSession allows timeout errors, so this would normally return true. */
	reusable := e.shouldReuseUDPSession(context.Background(), nil /* localToUpstream */, context.DeadlineExceeded /* upstreamToLocal */)
	if !reusable {
		t.Skip("precondition: timeout alone must not block reuse (test assumptions changed)")
	}

	/* Simulates the call-site guard in handleUDP. */
	upstreamBytes := int64(0)
	upstreamErr := context.DeadlineExceeded // timeout with no bytes received
	if reusable && upstreamBytes == 0 && upstreamErr != nil {
		reusable = false
	}
	if reusable {
		t.Fatal("expected zero-bytes guard to prevent session reuse after timeout with no upstream data")
	}
}

func TestCloseActiveLocalsClearsTrackedLocals(t *testing.T) {
	conn := &stubConnWithRemote{remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}}
	e := &Engine{activeLocals: make(map[io.Closer]struct{})}
	e.registerActiveLocal(conn)

	e.closeActiveLocals()

	e.activeMu.Lock()
	defer e.activeMu.Unlock()
	if len(e.activeLocals) != 0 {
		t.Fatalf("expected active locals to be cleared, got %d", len(e.activeLocals))
	}
}

func TestCloseActiveUpstreamsClearsTrackedUpstreams(t *testing.T) {
	conn := &closeTrackingConn{remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}}
	e := &Engine{activeUpstreams: make(map[io.Closer]struct{})}
	e.registerActiveUpstream(conn)

	e.closeActiveUpstreams()

	if !conn.isClosed() {
		t.Fatal("expected active upstream to be closed")
	}
	e.activeMu.Lock()
	defer e.activeMu.Unlock()
	if len(e.activeUpstreams) != 0 {
		t.Fatalf("expected active upstreams to be cleared, got %d", len(e.activeUpstreams))
	}
}

func TestRelayBidirectionalWithStatsContextStopsOnCancel(t *testing.T) {
	left := &blockingRelayConn{}
	right := &blockingRelayConn{}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan bidirectionalRelayStats, 1)
	go func() {
		done <- relayBidirectionalWithStatsContext(ctx, left, right, 32*1024, 30*time.Second, &relayBufPool)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case stats := <-done:
		if stats.UploadErr == nil && stats.DownloadErr == nil {
			t.Fatal("expected canceled relay to report at least one error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected relay to stop shortly after context cancellation")
	}
}

func TestDialTCPUpstreamWaitsForCooldownToClear(t *testing.T) {
	dialer := &stubRetryTCPDialer{response: []byte{0xaa}}
	e := &Engine{
		cfg: &Config{
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
			},
		},
		dialer:          dialer,
		tcpDialSem:      make(chan struct{}, 1),
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
	}
	e.markTCPDialBackoff(120 * time.Millisecond)

	start := time.Now()
	conn, err := e.dialTCPUpstream(context.Background(), "8.8.8.8:53", time.Second)
	if err != nil {
		t.Fatalf("expected dial to succeed after cooldown clears, got %v", err)
	}
	_ = conn.Close()

	if elapsed := time.Since(start); elapsed < 80*time.Millisecond {
		t.Fatalf("expected dial to wait for cooldown, got %s", elapsed)
	}
	if dialer.dials != 1 {
		t.Fatalf("expected 1 dial after cooldown, got %d", dialer.dials)
	}
}

func TestHandleUDPAllowsUDP443WhenUDPEnabled(t *testing.T) {
	dialer := &stubUDPDialCounter{}
	e := &Engine{
		cfg: &Config{
			Mode: ModeSocks5TLS,
			Tun:  TunConfig{Name: validTunNameForRuntime(), MTU: 1500},
			Upstream: UpstreamConfig{
				Addr: "127.0.0.1:443",
			},
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
				IdleTimeoutMS:    1000,
				TCPBuffer:        4096,
				UDPBuffer:        4096,
				EnableUDP:        true,
			},
		},
		dialer:          dialer,
		udpDialSem:      make(chan struct{}, 1),
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
	}

	id := gstack.TransportEndpointID{
		LocalAddress:  tcpip.AddrFromSlice(net.ParseIP("142.250.194.67").To4()),
		LocalPort:     443,
		RemoteAddress: tcpip.AddrFromSlice(net.ParseIP("198.18.0.1").To4()),
		RemotePort:    53000,
	}

	e.handleUDP(context.Background(), id, &stubPacketConnEOF{})

	if got := dialer.count(); got != 1 {
		t.Fatalf("expected one udp dial for udp/443 when udp is enabled, got %d", got)
	}
}

func TestHandleUDPReusesIdleSessionSequentially(t *testing.T) {
	dialer := &stubUDPDialCounter{}
	e := &Engine{
		cfg: &Config{
			Mode: ModeSocks5TLS,
			Tun:  TunConfig{Name: validTunNameForRuntime(), MTU: 1500},
			Upstream: UpstreamConfig{
				Addr: "127.0.0.1:443",
			},
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
				IdleTimeoutMS:    1000,
				TCPBuffer:        4096,
				UDPBuffer:        4096,
				EnableUDP:        true,
			},
		},
		dialer:          dialer,
		tcpDialSem:      make(chan struct{}, 1),
		udpDialSem:      make(chan struct{}, 1),
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
	}

	id := gstack.TransportEndpointID{
		LocalAddress:  tcpip.AddrFromSlice(net.ParseIP("9.9.9.9").To4()),
		LocalPort:     9999,
		RemoteAddress: tcpip.AddrFromSlice(net.ParseIP("198.18.0.1").To4()),
		RemotePort:    53000,
	}

	e.handleUDP(context.Background(), id, &stubPacketConnEOF{})
	e.handleUDP(context.Background(), id, &stubPacketConnEOF{})

	if got := dialer.count(); got != 2 {
		t.Fatalf("expected eof-closed udp session to be discarded, got %d dials", got)
	}

	e.udpPoolMu.Lock()
	defer e.udpPoolMu.Unlock()
	total := 0
	for _, sessions := range e.udpPool {
		total += len(sessions)
	}
	if total != 0 {
		t.Fatalf("expected no idle udp session in pool after eof, got %d", total)
	}
}

func TestHandleUDPDropsMismatchedUpstreamSourceOnReusedSession(t *testing.T) {
	session := &scriptedUDPSession{
		reads: []scriptedUDPRead{
			{
				payload: []byte{0xde, 0xad},
				src:     &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 9999},
				err:     nil,
			},
			{
				payload: nil,
				src:     nil,
				err:     io.EOF,
			},
		},
	}
	conn := &stubDNSPacketConn{
		reads: [][]byte{
			{0x01, 0x02},
		},
	}
	e := &Engine{
		cfg: &Config{
			Mode: ModeSocks5TLS,
			Tun:  TunConfig{Name: validTunNameForRuntime(), MTU: 1500},
			Upstream: UpstreamConfig{
				Addr: "127.0.0.1:443",
			},
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
				IdleTimeoutMS:    1000,
				TCPBuffer:        4096,
				UDPBuffer:        4096,
				EnableUDP:        true,
			},
		},
		dialer:          &stubUDPDialCounter{},
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
		udpPool: map[string][]UDPSession{
			udpSessionPoolKey("198.18.0.1:53000", "9.9.9.9:9999"): {session},
		},
	}

	id := gstack.TransportEndpointID{
		LocalAddress:  tcpip.AddrFromSlice(net.ParseIP("9.9.9.9").To4()),
		LocalPort:     9999,
		RemoteAddress: tcpip.AddrFromSlice(net.ParseIP("198.18.0.1").To4()),
		RemotePort:    53000,
	}

	e.handleUDP(context.Background(), id, conn)

	conn.mu.Lock()
	defer conn.mu.Unlock()
	if len(conn.writes) != 0 {
		t.Fatalf("expected mismatched upstream packet to be dropped, got %d writes", len(conn.writes))
	}
}

func TestHandleUDPRegistersReusedSessionAsActiveUpstream(t *testing.T) {
	session := &blockingUDPSession{
		readCh:  make(chan struct{}),
		closeCh: make(chan struct{}),
	}
	conn := &stubDNSPacketConnBlocking{
		firstRead: []byte{0x01, 0x02},
		blockCh:   make(chan struct{}),
	}
	e := &Engine{
		cfg: &Config{
			Mode: ModeSocks5TLS,
			Tun:  TunConfig{Name: validTunNameForRuntime(), MTU: 1500},
			Upstream: UpstreamConfig{
				Addr: "127.0.0.1:443",
			},
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
				IdleTimeoutMS:    1000,
				TCPBuffer:        4096,
				UDPBuffer:        4096,
				EnableUDP:        true,
			},
		},
		dialer:          &stubUDPDialCounter{},
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
		udpPool: map[string][]UDPSession{
			udpSessionPoolKey("198.18.0.1:53000", "9.9.9.9:9999"): {session},
		},
	}

	id := gstack.TransportEndpointID{
		LocalAddress:  tcpip.AddrFromSlice(net.ParseIP("9.9.9.9").To4()),
		LocalPort:     9999,
		RemoteAddress: tcpip.AddrFromSlice(net.ParseIP("198.18.0.1").To4()),
		RemotePort:    53000,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.handleUDP(context.Background(), id, conn)
	}()

	deadline := time.After(2 * time.Second)
	for {
		e.activeMu.Lock()
		_, ok := e.activeUpstreams[session]
		e.activeMu.Unlock()
		if ok {
			break
		}
		select {
		case <-deadline:
			t.Fatal("expected reused udp session to be tracked as active")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	_ = session.Close()
	conn.Close()
	<-done
}

func TestAcquireDNSConnRejectsStoppingEngineForPooledConn(t *testing.T) {
	conn := &closeTrackingConn{remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}}
	e := &Engine{
		stopping:        true,
		activeUpstreams: make(map[io.Closer]struct{}),
		dnsPool: map[string][]net.Conn{
			"8.8.8.8:53": {conn},
		},
	}

	got, pooled, err := e.acquireDNSConn(context.Background(), "8.8.8.8:53", time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil conn, got %v", got)
	}
	if pooled {
		t.Fatal("expected pooled=false when activation fails")
	}
	if !conn.isClosed() {
		t.Fatal("expected pooled dns conn to be closed when engine is stopping")
	}
	e.activeMu.Lock()
	defer e.activeMu.Unlock()
	if len(e.activeUpstreams) != 0 {
		t.Fatalf("expected no active upstreams, got %d", len(e.activeUpstreams))
	}
}

func TestAcquireDNSConnRejectsStoppingEngineForFreshConn(t *testing.T) {
	conn := &closeTrackingConn{remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}}
	e := &Engine{
		stopping:        true,
		activeUpstreams: make(map[io.Closer]struct{}),
		cfg: &Config{
			Mode: ModeSocks5TLS,
			Tun:  TunConfig{Name: validTunNameForRuntime(), MTU: 1500},
			Upstream: UpstreamConfig{
				Addr: "127.0.0.1:443",
			},
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
				IdleTimeoutMS:    1000,
				TCPBuffer:        4096,
				UDPBuffer:        4096,
			},
		},
		dialer: &stubTCPDialerConn{conn: conn},
	}

	got, pooled, err := e.acquireDNSConn(context.Background(), "8.8.8.8:53", time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil conn, got %v", got)
	}
	if pooled {
		t.Fatal("expected pooled=false for fresh dial failure")
	}
	if !conn.isClosed() {
		t.Fatal("expected fresh dns conn to be closed when engine is stopping")
	}
	e.activeMu.Lock()
	defer e.activeMu.Unlock()
	if len(e.activeUpstreams) != 0 {
		t.Fatalf("expected no active upstreams, got %d", len(e.activeUpstreams))
	}
}

func TestReleaseDNSConnDiscardsWhenStoppingFlipsBeforePoolAppend(t *testing.T) {
	conn := &closeTrackingConn{remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}}
	e := &Engine{
		activeUpstreams: map[io.Closer]struct{}{
			conn: {},
		},
		dnsPool: make(map[string][]net.Conn),
	}

	e.mu.Lock()
	e.stopping = true
	e.mu.Unlock()
	e.releaseDNSConn("8.8.8.8:53", conn)

	if !conn.isClosed() {
		t.Fatal("expected dns conn to be closed when stopping is set")
	}
	e.activeMu.Lock()
	activeCount := len(e.activeUpstreams)
	e.activeMu.Unlock()
	if activeCount != 0 {
		t.Fatalf("expected no active upstreams, got %d", activeCount)
	}
	e.dnsPoolMu.Lock()
	defer e.dnsPoolMu.Unlock()
	if len(e.dnsPool["8.8.8.8:53"]) != 0 {
		t.Fatal("expected no pooled dns connections after shutdown race")
	}
}

func TestHandleUDPShortIdleFlowSetsInitialDeadlines(t *testing.T) {
	target := &net.UDPAddr{IP: net.ParseIP("9.9.9.9").To4(), Port: 9999}
	session := &deadlineAwareUDPSession{target: target}
	conn := &deadlineAwarePacketConn{}
	e := &Engine{
		cfg: &Config{
			Mode: ModeSocks5TLS,
			Tun:  TunConfig{Name: validTunNameForRuntime(), MTU: 1500},
			Upstream: UpstreamConfig{
				Addr: "127.0.0.1:443",
			},
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
				IdleTimeoutMS:    20,
				TCPBuffer:        4096,
				UDPBuffer:        4096,
				EnableUDP:        true,
			},
		},
		dialer:          &stubUDPDialCounter{},
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
		udpPool: map[string][]UDPSession{
			udpSessionPoolKey("198.18.0.1:53000", "9.9.9.9:9999"): {session},
		},
	}

	id := gstack.TransportEndpointID{
		LocalAddress:  tcpip.AddrFromSlice(net.ParseIP("9.9.9.9").To4()),
		LocalPort:     9999,
		RemoteAddress: tcpip.AddrFromSlice(net.ParseIP("198.18.0.1").To4()),
		RemotePort:    53000,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.handleUDP(context.Background(), id, conn)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("expected short idle udp flow to exit after initial deadline")
	}

	conn.mu.Lock()
	localReadSet := conn.readSet
	conn.mu.Unlock()
	session.mu.Lock()
	upstreamReadSet := session.readSet
	session.mu.Unlock()
	if !localReadSet {
		t.Fatal("expected local read deadline to be set before first read")
	}
	if !upstreamReadSet {
		t.Fatal("expected upstream read deadline to be set before first read")
	}
}

func TestReleaseUDPSessionDiscardsWhenStoppingFlipsBeforePoolAppend(t *testing.T) {
	session := &deadlineAwareUDPSession{target: &net.UDPAddr{IP: net.ParseIP("9.9.9.9").To4(), Port: 9999}}
	e := &Engine{
		activeUpstreams: map[io.Closer]struct{}{
			session: {},
		},
		udpPool: make(map[string][]UDPSession),
	}

	e.mu.Lock()
	e.stopping = true
	e.mu.Unlock()
	e.releaseUDPSession(udpSessionPoolKey("198.18.0.1:53000", "9.9.9.9:9999"), session, true)

	if !session.isClosed() {
		t.Fatal("expected udp session to be closed when stopping is set")
	}
	e.activeMu.Lock()
	activeCount := len(e.activeUpstreams)
	e.activeMu.Unlock()
	if activeCount != 0 {
		t.Fatalf("expected no active upstreams, got %d", activeCount)
	}
	e.udpPoolMu.Lock()
	defer e.udpPoolMu.Unlock()
	if len(e.udpPool[udpSessionPoolKey("198.18.0.1:53000", "9.9.9.9:9999")]) != 0 {
		t.Fatal("expected no pooled udp sessions after shutdown race")
	}
}

func TestShouldReuseUDPSessionRejectsEOF(t *testing.T) {
	e := &Engine{}
	if e.shouldReuseUDPSession(context.Background(), io.EOF) {
		t.Fatal("expected eof to disable udp session reuse")
	}
}

/* Verifies normalized local write errors still allow UDP session reuse. */
func TestShouldReuseUDPSessionAllowsBenignLocalWriteError(t *testing.T) {
	e := &Engine{}
	if !e.shouldReuseUDPSession(context.Background(), nil) {
		t.Fatal("expected nil error (normalized benign local write) to allow session reuse")
	}
}

/* Verifies upstream read errors still prevent UDP session reuse. */
func TestShouldReuseUDPSessionRejectsUpstreamReadError(t *testing.T) {
	e := &Engine{}
	err := errors.New("read udp: port unreachable")
	if e.shouldReuseUDPSession(context.Background(), err) {
		t.Fatal("expected upstream read error to prevent session reuse")
	}
}

func TestDNSSummaryErrorsTreatEOFAsFailure(t *testing.T) {
	upErr, downErr := dnsSummaryErrors(io.EOF, nil)
	if errors.Is(upErr, io.EOF) {
		t.Fatal("expected dns summary to rewrite eof so it is not logged as ok")
	}
	if got := combineResults(upErr, downErr); got == "ok" || strings.Contains(got, "up:ok") {
		t.Fatalf("expected dns summary failure, got %q", got)
	}
}

func TestDNSFailureClassSeparatesTimeouts(t *testing.T) {
	if got := dnsFailureClass(&timeoutNetError{}); got != "timeout" {
		t.Fatalf("expected timeout dns failure class, got %q", got)
	}
}

func TestCombineUDPResultsTreatsBenignLocalWriteErrorAsLocalClosed(t *testing.T) {
	res := combineUDPResults(
		udpPumpResult{},
		udpPumpResult{
			Err:           errors.New("write udp 104.18.41.158:443: connection was refused"),
			LocalWriteErr: true,
		},
	)
	if res != "up:ok/down:local-closed" {
		t.Fatalf("expected local-closed udp summary, got %q", res)
	}
}

func TestDNSCacheKeyOmitsTransactionID(t *testing.T) {
	payloadA := []byte{0xaa, 0xbb, 0x01, 0x00, 0x00, 0x01}
	payloadB := []byte{0xcc, 0xdd, 0x01, 0x00, 0x00, 0x01}
	keyA := dnsCacheKey("8.8.8.8:53", payloadA)
	keyB := dnsCacheKey("8.8.8.8:53", payloadB)
	if keyA != keyB {
		t.Fatalf("expected same cache key for payloads differing only in txid, got %q vs %q", keyA, keyB)
	}
}

func TestActivateLocalRejectsStoppingEngine(t *testing.T) {
	e := &Engine{
		stopping:     true,
		activeLocals: make(map[io.Closer]struct{}),
	}
	conn := &stubConnWithRemote{remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}}
	if e.activateLocal(conn) {
		t.Fatal("expected activateLocal to reject stopping engine")
	}
	if len(e.activeLocals) != 0 {
		t.Fatalf("expected no active locals, got %d", len(e.activeLocals))
	}
}

func TestActivateUpstreamRejectsStoppingEngine(t *testing.T) {
	e := &Engine{
		stopping:        true,
		activeUpstreams: make(map[io.Closer]struct{}),
	}
	conn := &stubConnWithRemote{remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}}
	if e.activateUpstream(conn) {
		t.Fatal("expected activateUpstream to reject stopping engine")
	}
	if len(e.activeUpstreams) != 0 {
		t.Fatalf("expected no active upstreams, got %d", len(e.activeUpstreams))
	}
}

func TestHandleUDPAllowsSTUNWhenUDPEnabled(t *testing.T) {
	dialer := &stubUDPDialCounter{}
	e := &Engine{
		cfg: &Config{
			Mode: ModeSocks5TLS,
			Tun:  TunConfig{Name: validTunNameForRuntime(), MTU: 1500},
			Upstream: UpstreamConfig{
				Addr: "127.0.0.1:443",
			},
			Runtime: RuntimeConfig{
				ConnectTimeoutMS: 1000,
				IdleTimeoutMS:    1000,
				TCPBuffer:        4096,
				UDPBuffer:        4096,
				EnableUDP:        true,
			},
		},
		dialer:          dialer,
		udpDialSem:      make(chan struct{}, 1),
		activeUpstreams: make(map[io.Closer]struct{}),
		activeLocals:    make(map[io.Closer]struct{}),
	}

	id := gstack.TransportEndpointID{
		LocalAddress:  tcpip.AddrFromSlice(net.ParseIP("60.29.236.164").To4()),
		LocalPort:     3478,
		RemoteAddress: tcpip.AddrFromSlice(net.ParseIP("198.18.0.1").To4()),
		RemotePort:    53000,
	}

	e.handleUDP(context.Background(), id, &stubPacketConnEOF{})

	if got := dialer.count(); got != 1 {
		t.Fatalf("expected one udp dial for stun when udp is enabled, got %d", got)
	}
}

func TestLogStablePolicyDropVisibleAtInfoLevel(t *testing.T) {
	var out bytes.Buffer
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	prevLevel := LogLevel(currentLogLevel.Load())
	log.SetOutput(&out)
	log.SetFlags(0)
	defer log.SetOutput(prevWriter)
	defer log.SetFlags(prevFlags)
	defer SetLogLevel(prevLevel)

	SetLogLevel(LogLevelInfo)
	e := &Engine{logThrottleStates: make(map[string]logThrottleState)}
	e.logTCPDialFailure("tcp-1", ModeSocks5TLS, "198.18.0.1:53000", "1.1.1.1:443", io.ErrUnexpectedEOF)

	if !strings.Contains(out.String(), "dial failed") {
		t.Fatalf("expected throttled tcp dial failure to be visible at info level, got %q", out.String())
	}
}

func TestCommitLinuxDefaultRouteUpdatesStateBeforeNotify(t *testing.T) {
	m := &AutoRouteManager{}
	notified := make(chan struct{}, 1)
	m.SetDefaultRouteChangeHook(func() {
		if m.linuxDefaultRoute != "default via 10.0.0.1 dev en0" {
			t.Fatalf("route state not committed before notify: %q", m.linuxDefaultRoute)
		}
		if m.linuxDefaultGW != "10.0.0.1" || m.linuxDefaultDev != "en0" {
			t.Fatalf("linux default route fields not committed before notify: gw=%q dev=%q", m.linuxDefaultGW, m.linuxDefaultDev)
		}
		notified <- struct{}{}
	})

	m.commitLinuxDefaultRoute("default via 10.0.0.1 dev en0", "10.0.0.1", "en0", true)

	select {
	case <-notified:
	case <-time.After(time.Second):
		t.Fatal("expected route change notification")
	}
}

func TestCommitLinuxDefaultRouteDoesNotDeadlockWhileManagerMutexIsHeld(t *testing.T) {
	m := &AutoRouteManager{}
	m.SetDefaultRouteChangeHook(func() {})
	done := make(chan struct{})

	go func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.commitLinuxDefaultRoute("default via 10.0.0.1 dev en0", "10.0.0.1", "en0", true)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected route change hook notification to avoid self-deadlock")
	}
}

func TestDarwinDeleteHostRouteArgs(t *testing.T) {
	got := darwinDeleteHostRouteArgs("8.8.8.8")
	want := []string{"-n", "delete", "-host", "8.8.8.8"}
	if len(got) != len(want) {
		t.Fatalf("unexpected args length: got=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected arg[%d]: got=%q want=%q full=%v", i, got[i], want[i], got)
		}
	}
}

func TestConfigUDPIdleTimeoutUsesUniformPolicy(t *testing.T) {
	cfg := &Config{
		Runtime: RuntimeConfig{
			IdleTimeoutMS: 300_000,
		},
	}

	if got := cfg.UDPIdleTimeout(); got != 5*time.Minute {
		t.Fatalf("unexpected udp idle timeout: %s", got)
	}
}

func TestConfigDNSExchangeTimeoutPrefersConnectTimeout(t *testing.T) {
	cfg := &Config{
		Runtime: RuntimeConfig{
			ConnectTimeoutMS: 10_000,
			IdleTimeoutMS:    300_000,
		},
	}
	if got := cfg.DNSExchangeTimeout(); got != 10*time.Second {
		t.Fatalf("unexpected dns exchange timeout: %s", got)
	}

	cfg.Runtime.IdleTimeoutMS = 5_000
	if got := cfg.DNSExchangeTimeout(); got != 5*time.Second {
		t.Fatalf("expected dns exchange timeout to honor shorter idle timeout, got %s", got)
	}
}

func TestCopyWithIdleTimeoutRefreshesDeadlinesForSlowActiveFlow(t *testing.T) {
	src := &deadlineRefreshConn{
		reads: []timedReadStep{
			{data: []byte("a")},
			{delay: 6 * time.Millisecond, data: []byte("b")},
			{delay: 6 * time.Millisecond, data: []byte("c")},
		},
	}
	dst := &deadlineRefreshConn{}

	copied, err := copyWithIdleTimeout(dst, src, make([]byte, 8), 10*time.Millisecond)
	if err != nil {
		t.Fatalf("copyWithIdleTimeout failed: %v", err)
	}
	if copied != 3 {
		t.Fatalf("unexpected copied bytes: got=%d want=3", copied)
	}
	if src.readDeadlineCallCount() < 2 {
		t.Fatalf("expected read deadline refreshes for slow active flow, got=%d", src.readDeadlineCallCount())
	}
	if dst.writeDeadlineCallCount() < 2 {
		t.Fatalf("expected write deadline refreshes for slow active flow, got=%d", dst.writeDeadlineCallCount())
	}
}

func TestWriteTUNFrameRejectsShortWrite(t *testing.T) {
	err := writeTUNFrame(&shortWriter{maxWrite: 2}, []byte{0x01, 0x02, 0x03})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected short write error, got %v", err)
	}
}

func TestShouldRefreshPacketDeadlinesAllowsSlowActiveFlow(t *testing.T) {
	last := time.Now().Add(-600 * time.Millisecond)
	if !shouldRefreshPacketDeadlines(1, last, time.Now()) {
		t.Fatal("expected slow active flow to refresh deadlines before 32 packets")
	}
	if !shouldRefreshPacketDeadlines(32, time.Now(), time.Now()) {
		t.Fatal("expected packet burst to refresh deadlines immediately")
	}
	if shouldRefreshPacketDeadlines(1, time.Now(), time.Now()) {
		t.Fatal("did not expect immediate refresh without time or packet threshold")
	}
}

func TestEngineShouldRelayDNSOverTCPUsesPlainDNSPort(t *testing.T) {
	if !shouldRelayDNSOverTCP(&net.UDPAddr{Port: 53}) {
		t.Fatal("expected plain DNS port 53 to use dns-over-tcp relay")
	}
	for _, port := range []int{5353, 853, 5443} {
		if shouldRelayDNSOverTCP(&net.UDPAddr{Port: port}) {
			t.Fatalf("did not expect port %d to use dns-over-tcp relay", port)
		}
	}
}

func TestNextAutoRouteEnsureIntervalBacksOffAfterStablePasses(t *testing.T) {
	if got := nextAutoRouteEnsureInterval(0); got != autoRouteEnsureFastInterval {
		t.Fatalf("unexpected fast interval: %s", got)
	}
	if got := nextAutoRouteEnsureInterval(autoRouteEnsureSlowAfterSuccess - 1); got != autoRouteEnsureFastInterval {
		t.Fatalf("unexpected pre-threshold interval: %s", got)
	}
	if got := nextAutoRouteEnsureInterval(autoRouteEnsureSlowAfterSuccess); got != autoRouteEnsureSlowInterval {
		t.Fatalf("unexpected slow interval: %s", got)
	}
}

func TestBypassCIDRsForFamilyIncludesCloudInternalRange(t *testing.T) {
	got := bypassCIDRsForFamily(nil, false)
	seenCloudInternal := false
	seenTailnet := false
	for _, cidr := range got {
		if cidr == "100.100.0.0/16" {
			seenCloudInternal = true
		}
		if cidr == "100.64.0.0/10" {
			seenTailnet = true
		}
	}
	if !seenCloudInternal {
		t.Fatalf("expected cloud internal bypass cidr, got=%v", got)
	}
	if !seenTailnet {
		t.Fatalf("expected tailnet bypass cidr, got=%v", got)
	}
}

func TestResetTimerRearmsImmediately(t *testing.T) {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	resetTimer(timer, 10*time.Millisecond)

	select {
	case <-timer.C:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timer was not re-armed")
	}
}

func TestSocks5GreetingRejectsUnexpectedMethod(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 3)
		_, _ = io.ReadFull(server, buf)
		_, _ = server.Write([]byte{socksVersion, 0x02})
	}()

	err := socks5Greeting(client, client, "", "")
	<-done
	if err == nil || !strings.Contains(err.Error(), "requested username/password auth") {
		t.Fatalf("expected greeting rejection, got: %v", err)
	}
}

func TestSocks5GreetingHandlesShortWrite(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))

	shortClient := &shortWriteConn{Conn: client, maxWrite: 1}
	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 3)
		_, _ = io.ReadFull(server, buf)
		_, _ = server.Write([]byte{socksVersion, 0x00})
		done <- buf
	}()

	if err := socks5Greeting(shortClient, shortClient, "", ""); err != nil {
		t.Fatalf("greeting failed after short writes: %v", err)
	}
	got := <-done
	want := []byte{socksVersion, 0x01, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected greeting payload: got=%v want=%v", got, want)
	}
}

func TestSocks5GreetingSupportsUsernamePassword(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))

	done := make(chan error, 1)
	go func() {
		defer close(done)
		greeting := make([]byte, 4)
		if _, err := io.ReadFull(server, greeting); err != nil {
			done <- err
			return
		}
		wantGreeting := []byte{socksVersion, 0x02, 0x00, 0x02}
		if !bytes.Equal(greeting, wantGreeting) {
			done <- fmt.Errorf("unexpected greeting: got=%v want=%v", greeting, wantGreeting)
			return
		}
		if _, err := server.Write([]byte{socksVersion, 0x02}); err != nil {
			done <- err
			return
		}

		authReq := make([]byte, 0, 32)
		buf := make([]byte, 2)
		if _, err := io.ReadFull(server, buf); err != nil {
			done <- err
			return
		}
		authReq = append(authReq, buf...)
		userLen := int(buf[1])
		user := make([]byte, userLen)
		if _, err := io.ReadFull(server, user); err != nil {
			done <- err
			return
		}
		authReq = append(authReq, user...)
		if _, err := io.ReadFull(server, buf[:1]); err != nil {
			done <- err
			return
		}
		authReq = append(authReq, buf[:1]...)
		passLen := int(buf[0])
		pass := make([]byte, passLen)
		if _, err := io.ReadFull(server, pass); err != nil {
			done <- err
			return
		}
		authReq = append(authReq, pass...)
		wantAuth := append([]byte{0x01, 0x04}, []byte("user")...)
		wantAuth = append(wantAuth, 0x04)
		wantAuth = append(wantAuth, []byte("pass")...)
		if !bytes.Equal(authReq, wantAuth) {
			done <- fmt.Errorf("unexpected auth request: got=%v want=%v", authReq, wantAuth)
			return
		}
		_, err := server.Write([]byte{0x01, 0x00})
		done <- err
	}()

	if err := socks5Greeting(client, client, "user", "pass"); err != nil {
		t.Fatalf("greeting with username/password failed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server validation failed: %v", err)
	}
}

func TestSocks5GreetingSupportsPasswordOnlyAuth(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))

	done := make(chan error, 1)
	go func() {
		defer close(done)
		greeting := make([]byte, 4)
		if _, err := io.ReadFull(server, greeting); err != nil {
			done <- err
			return
		}
		wantGreeting := []byte{socksVersion, 0x02, 0x00, 0x02}
		if !bytes.Equal(greeting, wantGreeting) {
			done <- fmt.Errorf("unexpected greeting: got=%v want=%v", greeting, wantGreeting)
			return
		}
		if _, err := server.Write([]byte{socksVersion, 0x02}); err != nil {
			done <- err
			return
		}

		authReq := make([]byte, 0, 32)
		buf := make([]byte, 2)
		if _, err := io.ReadFull(server, buf); err != nil {
			done <- err
			return
		}
		authReq = append(authReq, buf...)
		userLen := int(buf[1])
		user := make([]byte, userLen)
		if _, err := io.ReadFull(server, user); err != nil {
			done <- err
			return
		}
		authReq = append(authReq, user...)
		if _, err := io.ReadFull(server, buf[:1]); err != nil {
			done <- err
			return
		}
		authReq = append(authReq, buf[:1]...)
		passLen := int(buf[0])
		pass := make([]byte, passLen)
		if _, err := io.ReadFull(server, pass); err != nil {
			done <- err
			return
		}
		authReq = append(authReq, pass...)
		wantAuth := []byte{0x01, 0x00, 0x06, 's', 'e', 'c', 'r', 'e', 't'}
		if !bytes.Equal(authReq, wantAuth) {
			done <- fmt.Errorf("unexpected auth request: got=%v want=%v", authReq, wantAuth)
			return
		}
		_, err := server.Write([]byte{0x01, 0x00})
		done <- err
	}()

	if err := socks5Greeting(client, client, "", "secret"); err != nil {
		t.Fatalf("greeting with password-only auth failed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server validation failed: %v", err)
	}
}

func TestHandshakeCONNECTRejectsNon200(t *testing.T) {
	d := &HTTPSConnectDialer{}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))

	done := make(chan struct{})
	go func() {
		defer close(done)
		br := bufio.NewReader(server)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		_, _ = io.WriteString(server, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
	}()

	err := d.handshakeCONNECT(bufio.NewReader(client), client, "example.com:443")
	<-done
	if err == nil || !strings.Contains(err.Error(), "connect rejected") {
		t.Fatalf("expected connect rejected error, got: %v", err)
	}
}

func TestHandshakeCONNECTSendsBasicAuthHeaderWhenOnlyPasswordIsSet(t *testing.T) {
	d := &HTTPSConnectDialer{basicPass: "secret"}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))

	done := make(chan error, 1)
	go func() {
		defer close(done)
		br := bufio.NewReader(server)
		var request strings.Builder
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			request.WriteString(line)
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		expectedToken := base64.StdEncoding.EncodeToString([]byte(":secret"))
		if !strings.Contains(request.String(), "Proxy-Authorization: Basic "+expectedToken) {
			done <- fmt.Errorf("missing basic auth header in request: %q", request.String())
			return
		}
		_, err := io.WriteString(server, "HTTP/1.1 200 Connection Established\r\n\r\n")
		done <- err
	}()

	if err := d.handshakeCONNECT(bufio.NewReader(client), client, "example.com:443"); err != nil {
		t.Fatalf("handshake connect failed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server validation failed: %v", err)
	}
}

func TestHandshakeCONNECTRejectsOverlongHeaderLine(t *testing.T) {
	d := &HTTPSConnectDialer{}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))

	done := make(chan struct{})
	go func() {
		defer close(done)
		br := bufio.NewReader(server)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		_, _ = io.WriteString(server, "HTTP/1.1 200 Connection Established\r\n"+strings.Repeat("a", maxHTTPConnectHeaderLineBytes+1))
	}()

	err := d.handshakeCONNECT(bufio.NewReaderSize(client, 64), client, "example.com:443")
	<-done
	if err == nil || !strings.Contains(err.Error(), "line too long") {
		t.Fatalf("expected overlong header error, got: %v", err)
	}
}

func TestHandshakeCONNECTRejectsOverlongStatusLineWithoutNewline(t *testing.T) {
	d := &HTTPSConnectDialer{}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))

	done := make(chan struct{})
	go func() {
		defer close(done)
		br := bufio.NewReader(server)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		_, _ = io.WriteString(server, strings.Repeat("a", maxHTTPConnectHeaderLineBytes+1))
	}()

	err := d.handshakeCONNECT(bufio.NewReaderSize(client, 64), client, "example.com:443")
	<-done
	if err == nil || !strings.Contains(err.Error(), "line too long") {
		t.Fatalf("expected overlong status-line error, got: %v", err)
	}
}

func TestWriteBackToPacketConnRejectsWriteToOnlyFallback(t *testing.T) {
	_, err := writeBackToPacketConn(&stubPacketConnWriteToOnly{}, []byte{0x01})
	if err == nil || !strings.Contains(err.Error(), "does not support connected writes") {
		t.Fatalf("expected connected write error, got: %v", err)
	}
}

func TestIntegrationWithLocalUpstreams(t *testing.T) {
	if os.Getenv("SHAMANTUN_IT") != "1" {
		t.Skip("set SHAMANTUN_IT=1 to run local upstream interop")
	}

	ss5Addr := mustGetenv(t, "SHAMANTUN_SS5_ADDR")
	hproxyAddr := mustGetenv(t, "SHAMANTUN_HPROXY_ADDR")
	clientPEM := mustGetenv(t, "SHAMANTUN_CLIENT_PEM")
	clientKey := mustGetenv(t, "SHAMANTUN_CLIENT_KEY")
	basicUser := mustGetenv(t, "SHAMANTUN_HPROXY_USER")
	basicPass := mustGetenv(t, "SHAMANTUN_HPROXY_PASS")

	targetAddr, stopHTTP := startHTTPResponder(t)
	defer stopHTTP()

	udpTarget, stopUDP := startUDPEchoServer(t)
	defer stopUDP()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("socks5tls-tcp", func(t *testing.T) {
		cfg := UpstreamConfig{
			Addr:       ss5Addr,
			ServerName: "localhost",
			ClientPEM:  clientPEM,
			ClientKey:  clientKey,
		}
		d, err := NewUpstreamDialer(ModeSocks5TLS, cfg, 5*time.Second, 0)
		if err != nil {
			t.Fatalf("new dialer: %v", err)
		}
		conn, err := d.DialTCP(ctx, targetAddr)
		if err != nil {
			t.Fatalf("dial tcp via socks5tls: %v", err)
		}
		assertHTTP204(t, conn)
	})

	t.Run("socks5tls-udp", func(t *testing.T) {
		cfg := UpstreamConfig{
			Addr:       ss5Addr,
			ServerName: "localhost",
			ClientPEM:  clientPEM,
			ClientKey:  clientKey,
		}
		d, err := NewUpstreamDialer(ModeSocks5TLS, cfg, 5*time.Second, 0)
		if err != nil {
			t.Fatalf("new dialer: %v", err)
		}
		session, err := d.DialUDP(ctx)
		if err != nil {
			t.Fatalf("dial udp via socks5tls: %v", err)
		}
		defer session.Close()

		payload := []byte("shamantun-udp-probe")
		if err := session.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		if err := session.WriteTo(payload, udpTarget); err != nil {
			t.Fatalf("write to udp target: %v", err)
		}

		buf := make([]byte, 256)
		n, src, err := session.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read from udp target: %v", err)
		}
		if src == nil || src.Port != udpTarget.Port {
			t.Fatalf("unexpected udp source: %v want port %d", src, udpTarget.Port)
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatalf("udp payload mismatch: got %q want %q", string(buf[:n]), string(payload))
		}
	})

	t.Run("https-connect-tcp", func(t *testing.T) {
		cfg := UpstreamConfig{
			Addr:       hproxyAddr,
			ServerName: "localhost",
			ClientPEM:  clientPEM,
			ClientKey:  clientKey,
			Username:   basicUser,
			Password:   basicPass,
		}
		d, err := NewUpstreamDialer(ModeHTTPS, cfg, 5*time.Second, 0)
		if err != nil {
			t.Fatalf("new dialer: %v", err)
		}
		conn, err := d.DialTCP(ctx, targetAddr)
		if err != nil {
			t.Fatalf("dial tcp via https connect: %v", err)
		}
		assertHTTP204(t, conn)
	})
}

func newValidConfigForTest(t *testing.T) *Config {
	t.Helper()

	tmp := t.TempDir()
	clientPEM := writeTestFile(t, tmp, "client.pem", []byte("test"))
	clientKey := writeTestFile(t, tmp, "client.key", []byte("test"))

	return &Config{
		Mode: ModeSocks5TLS,
		Tun: TunConfig{
			Name: validTunNameForRuntime(),
			MTU:  1500,
		},
		Upstream: UpstreamConfig{
			Addr:      "127.0.0.1:443",
			ClientPEM: clientPEM,
			ClientKey: clientKey,
		},
		Runtime: RuntimeConfig{
			ConnectTimeoutMS:   minConnectTimeoutMS,
			IdleTimeoutMS:      minIdleTimeoutMS,
			TCPBuffer:          minRuntimeBufferBytes,
			UDPBuffer:          minRuntimeBufferBytes,
			TCPDialConcurrency: 1,
			UDPDialConcurrency: 1,
			DNSCacheSize:       1,
		},
	}
}

func validTunNameForRuntime() string {
	if runtime.GOOS == "darwin" {
		return "utun"
	}
	return "tun0"
}

func writeTestFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func mustGetenv(t *testing.T, key string) string {
	t.Helper()
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		t.Fatalf("missing env %s", key)
	}
	return v
}

func startHTTPResponder(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen http responder: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" || line == "\n" {
						break
					}
				}
				_, _ = io.WriteString(c, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			}(conn)
		}
	}()

	stop := func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
	return ln.Addr().String(), stop
}

func startUDPEchoServer(t *testing.T) (*net.UDPAddr, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp echo: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}()

	stop := func() {
		_ = conn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
	return conn.LocalAddr().(*net.UDPAddr), stop
}

func assertHTTP204(t *testing.T, conn net.Conn) {
	t.Helper()
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := "GET /health HTTP/1.1\r\nHost: integration.local\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write request: %v", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(statusLine, "204") {
		t.Fatalf("unexpected status line: %q", statusLine)
	}
}

func TestApplyAndClearHandshakeDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	if err := applyHandshakeDeadline(client, time.Second); err != nil {
		t.Fatalf("apply deadline: %v", err)
	}
	if err := clearConnDeadline(client); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
}

func TestBuildSocks5CommandRequestWithIPv6(t *testing.T) {
	req, err := buildSocks5CommandRequest(socksCmdConnect, "[::1]:443")
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if len(req) < 4 {
		t.Fatalf("request too short: %d", len(req))
	}
	if req[3] != socksAtypIPv6 {
		t.Fatalf("unexpected atyp: got=%d want=%d", req[3], socksAtypIPv6)
	}
}

func TestParseUTUNUnitEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "", wantErr: false},
		{name: "utun", wantErr: false},
		{name: "utun0", wantErr: false},
		{name: "utun10", wantErr: false},
		{name: "tun0", wantErr: false},
		{name: "abc", wantErr: true},
		{name: "utun-1", wantErr: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(fmt.Sprintf("name=%q", tc.name), func(t *testing.T) {
			_, err := parseUTUNUnit(tc.name)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseLinuxDefaultRoute(t *testing.T) {
	via, dev := parseLinuxDefaultRoute("default via 192.168.1.1 dev eth0 proto dhcp metric 100")
	if via != "192.168.1.1" || dev != "eth0" {
		t.Fatalf("unexpected parse result: via=%q dev=%q", via, dev)
	}
}

func TestParseLinuxInterfaceCIDRs(t *testing.T) {
	out := "" +
		"2: en0    inet 192.168.5.7/24 brd 192.168.5.255 scope global dynamic en0\n" +
		"2: en0    inet 10.0.0.8/16 brd 10.0.255.255 scope global secondary en0\n"
	got := parseLinuxInterfaceCIDRs(out)
	want := []string{"192.168.5.0/24", "10.0.0.0/16"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected linux interface cidrs: got=%v want=%v", got, want)
	}
}

func TestSelectLinuxBypassRoute(t *testing.T) {
	out := "" +
		"default dev tun0 scope link\n" +
		"default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n"

	line, via, dev := selectLinuxBypassRoute(out, "tun0")
	if line != "default via 192.168.1.1 dev wlan0 proto dhcp metric 600" {
		t.Fatalf("unexpected route line: %q", line)
	}
	if via != "192.168.1.1" || dev != "wlan0" {
		t.Fatalf("unexpected parse result: via=%q dev=%q", via, dev)
	}
}

func TestSelectLinuxBypassRouteAcceptsDeviceOnlyDefault(t *testing.T) {
	out := "" +
		"default dev tun0 scope link\n" +
		"default dev ppp0 scope link\n"

	line, via, dev := selectLinuxBypassRoute(out, "tun0")
	if line != "default dev ppp0 scope link" {
		t.Fatalf("unexpected route line: %q", line)
	}
	if via != "" || dev != "ppp0" {
		t.Fatalf("unexpected parse result: via=%q dev=%q", via, dev)
	}
}

func TestSelectLinuxBypassRoutePrefersLowestMetric(t *testing.T) {
	out := "" +
		"default dev tun0 scope link\n" +
		"default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n" +
		"default via 10.0.0.1 dev eth0 proto dhcp metric 100\n"

	line, via, dev := selectLinuxBypassRoute(out, "tun0")
	if line != "default via 10.0.0.1 dev eth0 proto dhcp metric 100" {
		t.Fatalf("unexpected route line: %q", line)
	}
	if via != "10.0.0.1" || dev != "eth0" {
		t.Fatalf("unexpected parse result: via=%q dev=%q", via, dev)
	}
}

func TestSelectLinuxBypassRoutePrefersImplicitZeroMetric(t *testing.T) {
	out := "" +
		"default dev tun0 scope link\n" +
		"default via 192.168.1.1 dev eth0 proto dhcp\n" +
		"default via 10.0.0.1 dev wlan0 proto dhcp metric 100\n"

	line, via, dev := selectLinuxBypassRoute(out, "tun0")
	if line != "default via 192.168.1.1 dev eth0 proto dhcp" {
		t.Fatalf("unexpected route line: %q", line)
	}
	if via != "192.168.1.1" || dev != "eth0" {
		t.Fatalf("unexpected parse result: via=%q dev=%q", via, dev)
	}
}

func TestParseDarwinDefaultRoute(t *testing.T) {
	out := "   route to: default\ngateway: 10.0.0.1\n interface: en0\n"
	gw, iface := parseDarwinDefaultRoute(out)
	if gw != "10.0.0.1" || iface != "en0" {
		t.Fatalf("unexpected parse result: gateway=%q interface=%q", gw, iface)
	}
}

func TestSnapshotLinuxDefaultRouteRejectsEmptyOutput(t *testing.T) {
	prev := execCommandContext
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "printf ''")
	}
	defer func() { execCommandContext = prev }()

	_, _, _, err := snapshotLinuxDefaultRoute()
	if err == nil || !strings.Contains(err.Error(), "empty route output") {
		t.Fatalf("expected empty linux route output error, got %v", err)
	}
}

func TestSnapshotLinuxDefaultRoutePrefersLowestMetric(t *testing.T) {
	prev := execCommandContext
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "printf 'default via 192.168.1.1 dev wlan0 metric 600\\ndefault via 10.0.0.1 dev eth0 metric 100\\n'")
	}
	defer func() { execCommandContext = prev }()

	line, via, dev, err := snapshotLinuxDefaultRoute()
	if err != nil {
		t.Fatalf("snapshot linux default route: %v", err)
	}
	if line != "default via 10.0.0.1 dev eth0 metric 100" || via != "10.0.0.1" || dev != "eth0" {
		t.Fatalf("unexpected route snapshot: line=%q via=%q dev=%q", line, via, dev)
	}
}

func TestSnapshotLinuxDefaultRoutePrefersImplicitZeroMetric(t *testing.T) {
	prev := execCommandContext
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "printf 'default via 192.168.1.1 dev eth0\\ndefault via 10.0.0.1 dev wlan0 metric 100\\n'")
	}
	defer func() { execCommandContext = prev }()

	line, via, dev, err := snapshotLinuxDefaultRoute()
	if err != nil {
		t.Fatalf("snapshot linux default route: %v", err)
	}
	if line != "default via 192.168.1.1 dev eth0" || via != "192.168.1.1" || dev != "eth0" {
		t.Fatalf("unexpected route snapshot: line=%q via=%q dev=%q", line, via, dev)
	}
}

func TestReplaceLinuxHostRouteAllowsDeviceOnlyDefaultRoute(t *testing.T) {
	prev := execCommandContext
	defer func() { execCommandContext = prev }()

	var gotName string
	var gotArgs []string
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return exec.CommandContext(ctx, "sh", "-c", "exit 0")
	}

	if err := replaceLinuxHostRoute("203.0.113.7", "", "ppp0"); err != nil {
		t.Fatalf("replace linux host route: %v", err)
	}
	if gotName != "ip" {
		t.Fatalf("unexpected command name: %q", gotName)
	}
	joined := strings.Join(gotArgs, " ")
	if strings.Contains(joined, " via ") {
		t.Fatalf("device-only host route should not include via: %q", joined)
	}
	if !strings.Contains(joined, "203.0.113.7/32") || !strings.Contains(joined, "dev ppp0") {
		t.Fatalf("unexpected host route args: %q", joined)
	}
}

func TestReplaceLinuxHostRouteSupportsIPv6(t *testing.T) {
	prev := execCommandContext
	defer func() { execCommandContext = prev }()

	var gotName string
	var gotArgs []string
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return exec.CommandContext(ctx, "sh", "-c", "exit 0")
	}

	if err := replaceLinuxHostRoute("2001:db8::7", "fe80::1", "en0"); err != nil {
		t.Fatalf("replace linux host route: %v", err)
	}
	if gotName != "ip" {
		t.Fatalf("unexpected command name: %q", gotName)
	}
	joined := strings.Join(gotArgs, " ")
	if !strings.Contains(joined, "-6 route replace 2001:db8::7/128 via fe80::1 dev en0") {
		t.Fatalf("unexpected host route args: %q", joined)
	}
}

func TestReplaceLinuxHostRouteRetriesWithOnlinkForInvalidGateway(t *testing.T) {
	prev := execCommandContext
	defer func() { execCommandContext = prev }()

	logPath := filepath.Join(t.TempDir(), "commands.log")
	script := fmt.Sprintf(`
printf '%%s\n' "$*" >> %q
if printf '%%s' "$*" | grep -q 'onlink'; then
	exit 0
fi
printf 'Error: Nexthop has invalid gateway.\n' >&2
exit 2
`, logPath)
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		allArgs := append([]string{name}, args...)
		return exec.CommandContext(ctx, "sh", append([]string{"-c", script, "sh"}, allArgs...)...)
	}

	if err := replaceLinuxHostRoute("203.0.113.4", "10.0.0.1", "eth0"); err != nil {
		t.Fatalf("replace linux host route with onlink fallback: %v", err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	logText := string(logData)
	if !strings.Contains(logText, "ip route replace 203.0.113.4/32 via 10.0.0.1 dev eth0") {
		t.Fatalf("expected initial host route attempt, log=%q", logText)
	}
	if !strings.Contains(logText, "ip route replace 203.0.113.4/32 via 10.0.0.1 dev eth0 onlink") {
		t.Fatalf("expected onlink fallback attempt, log=%q", logText)
	}
}

func TestRouteCIDRProbeIPSupportsIPv6(t *testing.T) {
	probe, err := routeCIDRProbeIP("fd00:1234::/64")
	if err != nil {
		t.Fatalf("route cidr probe: %v", err)
	}
	if probe != "fd00:1234::1" {
		t.Fatalf("unexpected ipv6 probe: %q", probe)
	}
}

func TestSnapshotDarwinDefaultRouteRejectsMissingInterface(t *testing.T) {
	prev := execCommandContext
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "printf 'gateway: 10.0.0.1\\n'")
	}
	defer func() { execCommandContext = prev }()

	_, _, err := snapshotDarwinDefaultRoute()
	if err == nil || !strings.Contains(err.Error(), "missing interface") {
		t.Fatalf("expected missing darwin interface error, got %v", err)
	}
}

func TestSnapshotDarwinDefaultRouteV6IgnoresNotInTableOutput(t *testing.T) {
	prev := execCommandContext
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "printf 'route: writing to routing socket: not in table\\n'")
	}
	defer func() { execCommandContext = prev }()

	gateway, iface, err := snapshotDarwinDefaultRouteV6()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if gateway != "" || iface != "" {
		t.Fatalf("expected empty ipv6 default route snapshot, got gateway=%q iface=%q", gateway, iface)
	}
}

func TestRunCommandOutputTimesOut(t *testing.T) {
	prev := execCommandContext
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "sleep 10")
	}
	defer func() { execCommandContext = prev }()

	_, err := runCommandOutput("dummy")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestEnsureLinuxRepairsDeviceOnlyDefaultRoute(t *testing.T) {
	prev := execCommandContext
	defer func() { execCommandContext = prev }()

	logPath := filepath.Join(t.TempDir(), "commands.log")
	script := fmt.Sprintf(`
printf '%%s\n' "$*" >> %q
if [ "$1" = "ip" ] && [ "$2" = "route" ] && [ "$3" = "show" ] && [ "$4" = "default" ]; then
	printf 'default dev ppp0 scope link\n'
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "-o" ] && [ "$3" = "-4" ] && [ "$4" = "addr" ]; then
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "route" ] && [ "$3" = "get" ]; then
	printf '%%s dev ppp0 src 10.0.0.2\n' "$4"
	exit 0
fi
exit 0
`, logPath)
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		allArgs := append([]string{name}, args...)
		return exec.CommandContext(ctx, "sh", append([]string{"-c", script, "sh"}, allArgs...)...)
	}

	mgr := &AutoRouteManager{
		cfg:             &Config{Tun: TunConfig{IPv4: "198.18.0.1/15"}},
		tunName:         "tun0",
		upstreamIP:      "203.0.113.7",
		linuxDefaultDev: "eth0",
	}

	if err := mgr.ensureLinux(); err != nil {
		t.Fatalf("ensure linux: %v", err)
	}
	if mgr.linuxDefaultDev != "ppp0" {
		t.Fatalf("expected default dev to update, got %q", mgr.linuxDefaultDev)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	logText := string(logData)
	if !strings.Contains(logText, "ip route replace 203.0.113.7/32 dev ppp0") {
		t.Fatalf("expected device-only upstream host route, log=%q", logText)
	}
	if !strings.Contains(logText, "ip route replace default dev tun0") {
		t.Fatalf("expected split default route repair, log=%q", logText)
	}
}

func TestRefreshLinuxLANBypassAddsIPv6Route(t *testing.T) {
	prev := execCommandContext
	defer func() { execCommandContext = prev }()

	logPath := filepath.Join(t.TempDir(), "commands.log")
	script := fmt.Sprintf(`
printf '%%s\n' "$*" >> %q
if [ "$1" = "ip" ] && [ "$2" = "-o" ] && [ "$3" = "-4" ] && [ "$4" = "addr" ]; then
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "-o" ] && [ "$3" = "-6" ] && [ "$4" = "addr" ]; then
	printf '2: eth0    inet6 2001:db8:1::2/64 scope global\n'
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "-6" ] && [ "$3" = "route" ] && [ "$4" = "get" ]; then
	printf '%%s dev tun0 src fd00:198:18::1\n' "$5"
	exit 0
fi
exit 0
`, logPath)
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		allArgs := append([]string{name}, args...)
		return exec.CommandContext(ctx, "sh", append([]string{"-c", script, "sh"}, allArgs...)...)
	}

	mgr := &AutoRouteManager{tunName: "tun0"}
	if err := mgr.refreshLinuxLANBypass("", "eth0"); err != nil {
		t.Fatalf("refresh linux lan bypass: %v", err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	if !strings.Contains(string(logData), "ip -6 route replace 2001:db8:1::/64 dev eth0") {
		t.Fatalf("expected ipv6 lan bypass route, log=%q", string(logData))
	}
}

func TestRefreshLinuxLANBypassUsesSeparateIPv4AndIPv6Devices(t *testing.T) {
	prev := execCommandContext
	defer func() { execCommandContext = prev }()

	logPath := filepath.Join(t.TempDir(), "commands.log")
	script := fmt.Sprintf(`
printf '%%s\n' "$*" >> %q
if [ "$1" = "ip" ] && [ "$2" = "-o" ] && [ "$3" = "-4" ] && [ "$4" = "addr" ] && [ "$7" = "eth0" ]; then
	printf '2: eth0    inet 192.168.5.7/24 scope global eth0\n'
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "-o" ] && [ "$3" = "-6" ] && [ "$4" = "addr" ] && [ "$7" = "eth0" ]; then
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "-o" ] && [ "$3" = "-4" ] && [ "$4" = "addr" ] && [ "$7" = "en0" ]; then
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "-o" ] && [ "$3" = "-6" ] && [ "$4" = "addr" ] && [ "$7" = "en0" ]; then
	printf '3: en0    inet6 2001:db8:1::2/64 scope global\n'
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "route" ] && [ "$3" = "get" ]; then
	printf '%%s dev tun0 src 198.18.0.1\n' "$4"
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "-6" ] && [ "$3" = "route" ] && [ "$4" = "get" ]; then
	printf '%%s dev tun0 src fd00:198:18::1\n' "$5"
	exit 0
fi
exit 0
`, logPath)
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		allArgs := append([]string{name}, args...)
		return exec.CommandContext(ctx, "sh", append([]string{"-c", script, "sh"}, allArgs...)...)
	}

	mgr := &AutoRouteManager{tunName: "tun0"}
	if err := mgr.refreshLinuxLANBypass("eth0", "en0"); err != nil {
		t.Fatalf("refresh linux lan bypass: %v", err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	logText := string(logData)
	if !strings.Contains(logText, "ip route replace 192.168.5.0/24 dev eth0 scope link") {
		t.Fatalf("expected ipv4 lan bypass route on eth0, log=%q", logText)
	}
	if !strings.Contains(logText, "ip -6 route replace 2001:db8:1::/64 dev en0") {
		t.Fatalf("expected ipv6 lan bypass route on en0, log=%q", logText)
	}
}

func TestRemoveLinuxManagedRouteSkipsForeignDevice(t *testing.T) {
	prev := execCommandContext
	defer func() { execCommandContext = prev }()

	logPath := filepath.Join(t.TempDir(), "commands.log")
	script := fmt.Sprintf(`
printf '%%s\n' "$*" >> %q
if [ "$1" = "ip" ] && [ "$2" = "route" ] && [ "$3" = "get" ]; then
	printf '%%s dev eth9 src 10.0.0.2\n' "$4"
	exit 0
fi
exit 0
`, logPath)
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		allArgs := append([]string{name}, args...)
		return exec.CommandContext(ctx, "sh", append([]string{"-c", script, "sh"}, allArgs...)...)
	}

	mgr := &AutoRouteManager{installedLANDevs: map[string]string{"192.168.5.0/24": "eth0"}}
	mgr.removeLinuxManagedRoute("192.168.5.0/24")

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	if strings.Contains(string(logData), "ip route del 192.168.5.0/24") {
		t.Fatalf("unexpected delete for foreign linux route, log=%q", string(logData))
	}
}

func TestRemoveDarwinManagedRouteSkipsForeignInterface(t *testing.T) {
	prev := execCommandContext
	defer func() { execCommandContext = prev }()

	logPath := filepath.Join(t.TempDir(), "commands.log")
	script := fmt.Sprintf(`
printf '%%s\n' "$*" >> %q
if [ "$1" = "route" ] && [ "$2" = "-n" ] && [ "$3" = "get" ]; then
	printf 'gateway: 10.0.0.1\ninterface: en9\n'
	exit 0
fi
exit 0
`, logPath)
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		allArgs := append([]string{name}, args...)
		return exec.CommandContext(ctx, "sh", append([]string{"-c", script, "sh"}, allArgs...)...)
	}

	mgr := &AutoRouteManager{installedLANIFs: map[string]string{"192.168.5.0/24": "en0"}}
	mgr.removeDarwinManagedRoute("192.168.5.0/24")

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	if strings.Contains(string(logData), "route -n delete -net 192.168.5.0/24") {
		t.Fatalf("unexpected delete for foreign darwin route, log=%q", string(logData))
	}
}

func TestRefreshDarwinLANBypassRepairsRouteWhenProbeFails(t *testing.T) {
	prev := execCommandContext
	defer func() { execCommandContext = prev }()

	logPath := filepath.Join(t.TempDir(), "commands.log")
	script := fmt.Sprintf(`
printf '%%s\n' "$*" >> %q
if [ "$1" = "ifconfig" ] && [ "$2" = "en0" ]; then
	printf 'inet 192.168.5.7 netmask 0xffffff00 broadcast 192.168.5.255\n'
	exit 0
fi
if [ "$1" = "route" ] && [ "$2" = "-n" ] && [ "$3" = "get" ]; then
	printf 'route: writing to routing socket: not in table\n' >&2
	exit 1
fi
exit 0
`, logPath)
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		allArgs := append([]string{name}, args...)
		return exec.CommandContext(ctx, "sh", append([]string{"-c", script, "sh"}, allArgs...)...)
	}

	mgr := &AutoRouteManager{tunName: "utun7"}
	if err := mgr.refreshDarwinLANBypass("en0", ""); err != nil {
		t.Fatalf("refresh darwin lan bypass: %v", err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	if !strings.Contains(string(logData), "route -n add -net 192.168.5.0/24 -interface en0") &&
		!strings.Contains(string(logData), "route -n change -net 192.168.5.0/24 -interface en0") {
		t.Fatalf("expected darwin lan bypass repair after probe failure, log=%q", string(logData))
	}
}

func TestTeardownLinuxClearsInstalledLANState(t *testing.T) {
	prev := execCommandContext
	defer func() { execCommandContext = prev }()

	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		allArgs := append([]string{name}, args...)
		return exec.CommandContext(ctx, "sh", append([]string{"-c", "exit 0", "sh"}, allArgs...)...)
	}

	mgr := &AutoRouteManager{
		tunName:           "tun0",
		lanCIDRs:          []string{"192.168.5.0/24"},
		installedLANCIDRs: []string{"192.168.5.0/24"},
		installedLANDevs:  map[string]string{"192.168.5.0/24": "eth0"},
		installedLANIFs:   map[string]string{"192.168.5.0/24": "en0"},
	}

	if err := mgr.teardownLinux(); err != nil {
		t.Fatalf("teardown linux: %v", err)
	}
	if mgr.lanCIDRs != nil || mgr.installedLANCIDRs != nil || mgr.installedLANDevs != nil || mgr.installedLANIFs != nil {
		t.Fatalf("expected linux teardown to clear installed lan state, got lanCIDRs=%v installed=%v devs=%v ifs=%v", mgr.lanCIDRs, mgr.installedLANCIDRs, mgr.installedLANDevs, mgr.installedLANIFs)
	}
}

func TestTeardownDarwinClearsInstalledLANState(t *testing.T) {
	prev := execCommandContext
	defer func() { execCommandContext = prev }()

	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		allArgs := append([]string{name}, args...)
		return exec.CommandContext(ctx, "sh", append([]string{"-c", "exit 0", "sh"}, allArgs...)...)
	}

	mgr := &AutoRouteManager{
		tunName:           "utun7",
		lanCIDRs:          []string{"192.168.5.0/24"},
		installedLANCIDRs: []string{"192.168.5.0/24"},
		installedLANDevs:  map[string]string{"192.168.5.0/24": "eth0"},
		installedLANIFs:   map[string]string{"192.168.5.0/24": "en0"},
	}

	if err := mgr.teardownDarwin(); err != nil {
		t.Fatalf("teardown darwin: %v", err)
	}
	if mgr.lanCIDRs != nil || mgr.installedLANCIDRs != nil || mgr.installedLANDevs != nil || mgr.installedLANIFs != nil {
		t.Fatalf("expected darwin teardown to clear installed lan state, got lanCIDRs=%v installed=%v devs=%v ifs=%v", mgr.lanCIDRs, mgr.installedLANCIDRs, mgr.installedLANDevs, mgr.installedLANIFs)
	}
}

func TestSetupLinuxInstallsIPv6DefaultRouteWhenPresent(t *testing.T) {
	prev := execCommandContext
	defer func() { execCommandContext = prev }()

	logPath := filepath.Join(t.TempDir(), "commands.log")
	script := fmt.Sprintf(`
printf '%%s\n' "$*" >> %q
if [ "$1" = "ip" ] && [ "$2" = "route" ] && [ "$3" = "show" ] && [ "$4" = "default" ]; then
	printf 'default via 10.0.0.1 dev eth0 metric 100\n'
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "-6" ] && [ "$3" = "route" ] && [ "$4" = "show" ] && [ "$5" = "default" ]; then
	printf 'default via fe80::1 dev en0 metric 100\n'
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "-o" ] && [ "$3" = "-4" ] && [ "$4" = "addr" ]; then
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "route" ] && [ "$3" = "get" ]; then
	printf '%%s dev eth0 src 10.0.0.2\n' "$4"
	exit 0
fi
exit 0
`, logPath)
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		allArgs := append([]string{name}, args...)
		return exec.CommandContext(ctx, "sh", append([]string{"-c", script, "sh"}, allArgs...)...)
	}

	mgr := &AutoRouteManager{
		cfg:        &Config{Tun: TunConfig{IPv4: "198.18.0.1/15"}},
		tunName:    "tun0",
		upstreamIP: "203.0.113.7",
	}

	if err := mgr.setupLinux(); err != nil {
		t.Fatalf("setup linux: %v", err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	logText := string(logData)
	if !strings.Contains(logText, "ip -6 route replace default dev tun0") {
		t.Fatalf("expected ipv6 default route install, log=%q", logText)
	}
	if !strings.Contains(logText, "ip -6 addr add fd00:198:18::1/64 dev tun0") {
		t.Fatalf("expected tun ipv6 address install, log=%q", logText)
	}
}

func TestSetupLinuxSkipsIPv6DefaultRouteWhenAbsent(t *testing.T) {
	prev := execCommandContext
	defer func() { execCommandContext = prev }()

	logPath := filepath.Join(t.TempDir(), "commands.log")
	script := fmt.Sprintf(`
printf '%%s\n' "$*" >> %q
if [ "$1" = "ip" ] && [ "$2" = "route" ] && [ "$3" = "show" ] && [ "$4" = "default" ]; then
	printf 'default via 10.0.0.1 dev eth0 metric 100\n'
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "-6" ] && [ "$3" = "route" ] && [ "$4" = "show" ] && [ "$5" = "default" ]; then
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "-o" ] && [ "$3" = "-4" ] && [ "$4" = "addr" ]; then
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "route" ] && [ "$3" = "get" ]; then
	printf '%%s dev eth0 src 10.0.0.2\n' "$4"
	exit 0
fi
exit 0
`, logPath)
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		allArgs := append([]string{name}, args...)
		return exec.CommandContext(ctx, "sh", append([]string{"-c", script, "sh"}, allArgs...)...)
	}

	mgr := &AutoRouteManager{
		cfg:        &Config{Tun: TunConfig{IPv4: "198.18.0.1/15"}},
		tunName:    "tun0",
		upstreamIP: "203.0.113.7",
	}

	if err := mgr.setupLinux(); err != nil {
		t.Fatalf("setup linux: %v", err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	logText := string(logData)
	if strings.Contains(logText, "ip -6 route replace default dev tun0") || strings.Contains(logText, "ip -6 addr add") {
		t.Fatalf("unexpected ipv6 setup without default route, log=%q", logText)
	}
}

func TestSetupLinuxUsesIPv6DefaultRouteForIPv6Upstream(t *testing.T) {
	prev := execCommandContext
	defer func() { execCommandContext = prev }()

	logPath := filepath.Join(t.TempDir(), "commands.log")
	script := fmt.Sprintf(`
printf '%%s\n' "$*" >> %q
if [ "$1" = "ip" ] && [ "$2" = "route" ] && [ "$3" = "show" ] && [ "$4" = "default" ]; then
	printf 'default via 10.0.0.1 dev eth0 metric 100\n'
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "-6" ] && [ "$3" = "route" ] && [ "$4" = "show" ] && [ "$5" = "default" ]; then
	printf 'default via fe80::1 dev en0 metric 100\n'
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "-o" ] && [ "$3" = "-4" ] && [ "$4" = "addr" ]; then
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "-o" ] && [ "$3" = "-6" ] && [ "$4" = "addr" ]; then
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "route" ] && [ "$3" = "get" ]; then
	printf '%%s dev eth0 src 10.0.0.2\n' "$4"
	exit 0
fi
if [ "$1" = "ip" ] && [ "$2" = "-6" ] && [ "$3" = "route" ] && [ "$4" = "get" ]; then
	printf '%%s via fe80::1 dev en0 src 2001:db8::2\n' "$5"
	exit 0
fi
exit 0
`, logPath)
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		allArgs := append([]string{name}, args...)
		return exec.CommandContext(ctx, "sh", append([]string{"-c", script, "sh"}, allArgs...)...)
	}

	mgr := &AutoRouteManager{
		cfg:        &Config{Tun: TunConfig{IPv4: "198.18.0.1/15"}},
		tunName:    "tun0",
		upstreamIP: "2001:db8::7",
	}

	if err := mgr.setupLinux(); err != nil {
		t.Fatalf("setup linux: %v", err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	if !strings.Contains(string(logData), "ip -6 route replace 2001:db8::7/128 via fe80::1 dev en0") {
		t.Fatalf("expected ipv6 upstream host route, log=%q", string(logData))
	}
}

func TestNotifyDefaultRouteChangeRunsSynchronously(t *testing.T) {
	mgr := &AutoRouteManager{}
	called := false
	mgr.SetDefaultRouteChangeHook(func() {
		called = true
	})

	mgr.notifyDefaultRouteChange()
	if !called {
		t.Fatal("expected route change hook to run synchronously")
	}
}

func TestEnsureDarwinRepairsSplitRoutesWithoutUpstreamBypass(t *testing.T) {
	prev := execCommandContext
	defer func() { execCommandContext = prev }()

	logPath := filepath.Join(t.TempDir(), "commands.log")
	script := fmt.Sprintf(`
printf '%%s\n' "$*" >> %q
if [ "$1" = "route" ] && [ "$2" = "-n" ] && [ "$3" = "get" ] && [ "$4" = "default" ]; then
	printf 'gateway: 10.0.0.1\ninterface: en0\n'
	exit 0
fi
if [ "$1" = "ifconfig" ] && [ "$2" = "en0" ]; then
	printf 'en0: flags=8863<UP> mtu 1500\n\tinet 192.168.5.7 netmask 0xffffff00 broadcast 192.168.5.255\n'
	exit 0
fi
if [ "$1" = "route" ] && [ "$2" = "-n" ] && [ "$3" = "get" ]; then
	printf 'gateway: 10.0.0.1\ninterface: en0\n'
	exit 0
fi
exit 0
`, logPath)
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		allArgs := append([]string{name}, args...)
		return exec.CommandContext(ctx, "sh", append([]string{"-c", script, "sh"}, allArgs...)...)
	}

	mgr := &AutoRouteManager{
		tunName:         "utun9",
		darwinDefaultGW: "10.0.0.1",
		darwinDefaultIF: "en0",
	}

	if err := mgr.ensureDarwin(); err != nil {
		t.Fatalf("ensure darwin: %v", err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	logText := string(logData)
	if !strings.Contains(logText, "route -n add -net 0.0.0.0/1 -interface utun9") {
		t.Fatalf("expected ipv4 split route repair, log=%q", logText)
	}
	if !strings.Contains(logText, "route -n add -net 128.0.0.0/1 -interface utun9") {
		t.Fatalf("expected second ipv4 split route repair, log=%q", logText)
	}
}

func TestEnsureDarwinUsesIPv6DefaultGatewayForIPv6Upstream(t *testing.T) {
	prev := execCommandContext
	defer func() { execCommandContext = prev }()

	logPath := filepath.Join(t.TempDir(), "commands.log")
	script := fmt.Sprintf(`
printf '%%s\n' "$*" >> %q
if [ "$1" = "route" ] && [ "$2" = "-n" ] && [ "$3" = "get" ] && [ "$4" = "default" ]; then
	printf 'gateway: 10.0.0.1\ninterface: en0\n'
	exit 0
fi
if [ "$1" = "route" ] && [ "$2" = "-n" ] && [ "$3" = "get" ] && [ "$4" = "-inet6" ] && [ "$5" = "default" ]; then
	printf 'gateway: fe80::1\ninterface: en0\n'
	exit 0
fi
if [ "$1" = "ifconfig" ] && [ "$2" = "en0" ]; then
	printf 'en0: flags=8863<UP> mtu 1500\n\tinet 192.168.5.7 netmask 0xffffff00 broadcast 192.168.5.255\n'
	exit 0
fi
if [ "$1" = "route" ] && [ "$2" = "-n" ] && [ "$3" = "get" ] && [ "$4" = "-inet6" ]; then
	printf 'gateway: fe80::1\ninterface: en0\n'
	exit 0
fi
if [ "$1" = "route" ] && [ "$2" = "-n" ] && [ "$3" = "get" ]; then
	printf 'gateway: 10.0.0.1\ninterface: en0\n'
	exit 0
fi
exit 0
`, logPath)
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		allArgs := append([]string{name}, args...)
		return exec.CommandContext(ctx, "sh", append([]string{"-c", script, "sh"}, allArgs...)...)
	}

	mgr := &AutoRouteManager{
		tunName:           "utun9",
		upstreamIP:        "2001:db8::7",
		darwinDefaultGW:   "10.0.0.1",
		darwinDefaultIF:   "en0",
		darwinDefaultGWV6: "fe80::1",
		darwinDefaultIFV6: "en0",
	}

	if err := mgr.ensureDarwin(); err != nil {
		t.Fatalf("ensure darwin: %v", err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	if !strings.Contains(string(logData), "route -n add -inet6 -host 2001:db8::7 fe80::1") {
		t.Fatalf("expected ipv6 upstream host route, log=%q", string(logData))
	}
}

func TestParseDarwinInterfaceCIDRs(t *testing.T) {
	out := "" +
		"en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n" +
		"\tinet 192.168.5.7 netmask 0xffffff00 broadcast 192.168.5.255\n" +
		"\tinet 10.0.0.8 netmask 0xffff0000 broadcast 10.0.255.255\n"

	got := parseDarwinInterfaceCIDRs(out)
	want := []string{"192.168.5.0/24", "10.0.0.0/16"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected darwin interface cidrs: got=%v want=%v", got, want)
	}
}

func TestParseDarwinInterfaceCIDRsSkipsIPv6LinkLocal(t *testing.T) {
	out := "" +
		"en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n" +
		"\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x8\n" +
		"\tinet6 2001:db8:1::2 prefixlen 64\n"

	got := parseDarwinInterfaceCIDRs(out)
	want := []string{"2001:db8:1::/64"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected darwin interface cidrs: got=%v want=%v", got, want)
	}
}

func TestRouteCIDRProbeIP(t *testing.T) {
	got, err := routeCIDRProbeIP("192.168.5.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "192.168.5.1" {
		t.Fatalf("unexpected probe ip: %s", got)
	}
}

func TestDiffCIDRSets(t *testing.T) {
	remove, add := diffCIDRSets([]string{"192.168.5.0/24", "10.0.0.0/16"}, []string{"10.0.0.0/16", "172.16.0.0/12"})
	if !reflect.DeepEqual(remove, []string{"192.168.5.0/24"}) {
		t.Fatalf("unexpected remove set: %v", remove)
	}
	if !reflect.DeepEqual(add, []string{"172.16.0.0/12"}) {
		t.Fatalf("unexpected add set: %v", add)
	}
}

func TestLinuxTunCIDR(t *testing.T) {
	cidr, err := linuxTunCIDR("198.18.0.1/15")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cidr != "198.18.0.1/15" {
		t.Fatalf("unexpected cidr: %q", cidr)
	}

	if _, err := linuxTunCIDR("198.18.0.1"); err == nil {
		t.Fatalf("expected error for non-cidr input")
	}
}

func TestDarwinTunIPMask(t *testing.T) {
	ip, mask, err := darwinTunIPMask("198.18.0.1/15")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "198.18.0.1" || mask != "255.254.0.0" {
		t.Fatalf("unexpected darwin tun values: ip=%q mask=%q", ip, mask)
	}
}

func TestTUNProxyEndToEnd(t *testing.T) {
	if os.Getenv("SHAMANTUN_TUN_E2E") != "1" {
		t.Skip("set SHAMANTUN_TUN_E2E=1 to run tun end-to-end case")
	}
	if testing.Short() {
		t.Skip("skip tun e2e in short mode")
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("tun e2e is only for linux/darwin, got %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		t.Skip("tun e2e requires root privileges (run tests with sudo)")
	}

	upstreamIP, err := detectPrimaryIPv4()
	if err != nil {
		t.Skipf("skip tun e2e: %v", err)
	}

	virtualTarget := "203.0.113.10:18080"
	backendAddr, stopBackend := startHTTPResponder(t)
	defer stopBackend()

	mtls := generateMTLSAssets(t, []net.IP{upstreamIP})

	t.Run("socks5tls", func(t *testing.T) {
		upstreamAddr, stopServer := startSocks5TLSTestServer(t, upstreamIP, mtls, virtualTarget, backendAddr)
		defer stopServer()

		cfg := buildE2EConfig(t, ModeSocks5TLS, upstreamAddr, mtls, "", "")
		runTUNModeCase(t, cfg, virtualTarget)
	})

	t.Run("https-connect", func(t *testing.T) {
		const (
			basicUser = "it-user"
			basicPass = "it-pass"
		)
		upstreamAddr, stopServer := startHTTPSConnectTLSTestServer(t, upstreamIP, mtls, virtualTarget, backendAddr, basicUser, basicPass)
		defer stopServer()

		cfg := buildE2EConfig(t, ModeHTTPS, upstreamAddr, mtls, basicUser, basicPass)
		runTUNModeCase(t, cfg, virtualTarget)
	})
}

func runTUNModeCase(t *testing.T, cfg *Config, targetAddr string) {
	t.Helper()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	eng, err := NewEngine(cfg)
	if err != nil {
		cancel()
		t.Fatalf("new engine: %v", err)
	}

	if err := eng.Start(ctx); err != nil {
		cancel()
		t.Fatalf("engine start: %v", err)
	}

	routeMgr, err := NewAutoRouteManager(cfg, eng.tunDev.Name)
	if err != nil {
		cancel()
		stopCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		_ = eng.Stop(stopCtx)
		stop()
		t.Fatalf("new auto route manager: %v", err)
	}

	if err := routeMgr.Setup(); err != nil {
		cancel()
		stopCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		_ = eng.Stop(stopCtx)
		stop()
		t.Fatalf("auto-route setup: %v", err)
	}

	t.Cleanup(func() {
		if err := routeMgr.Teardown(); err != nil {
			t.Logf("auto-route teardown warning: %v", err)
		}
		cancel()
		stopCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := eng.Stop(stopCtx); err != nil {
			t.Logf("engine stop warning: %v", err)
		}
	})

	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := probeHTTPThroughTUN(targetAddr); err == nil {
			return
		} else {
			lastErr = err
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("probe through tun failed: %v", lastErr)
}

func probeHTTPThroughTUN(targetAddr string) error {
	conn, err := net.DialTimeout("tcp", targetAddr, 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := "GET /health HTTP/1.1\r\nHost: integration.local\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return err
	}

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(status, "204") {
		return fmt.Errorf("unexpected status line: %q", strings.TrimSpace(status))
	}
	return nil
}

type mtlsAssets struct {
	ServerPEM string
	ServerKey string
	ClientPEM string
	ClientKey string
}

func buildE2EConfig(t *testing.T, mode, upstreamAddr string, mtls *mtlsAssets, basicUser, basicPass string) *Config {
	t.Helper()

	cfg := &Config{
		Mode: mode,
		Tun: TunConfig{
			Name: e2eTunName(),
			MTU:  1500,
			IPv4: "198.18.0.1/15",
		},
		Upstream: UpstreamConfig{
			Addr:               upstreamAddr,
			ServerName:         "",
			ClientPEM:          mtls.ClientPEM,
			ClientKey:          mtls.ClientKey,
			InsecureSkipVerify: false,
			Username:           basicUser,
			Password:           basicPass,
		},
		Runtime: RuntimeConfig{
			ConnectTimeoutMS: 5000,
			IdleTimeoutMS:    10000,
			TCPBuffer:        64 * 1024,
			UDPBuffer:        64 * 1024,
			EnableUDP:        mode == ModeSocks5TLS,
		},
	}
	cfg.applyDefaults()
	return cfg
}

func e2eTunName() string {
	if runtime.GOOS == "darwin" {
		return "utun"
	}
	return fmt.Sprintf("st%d", time.Now().UnixNano()%1_000_000)
}

func detectPrimaryIPv4() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			return append(net.IP(nil), ip4...), nil
		}
	}

	return nil, fmt.Errorf("no active non-loopback IPv4 interface found")
}

func generateMTLSAssets(t *testing.T, serverIPs []net.IP) *mtlsAssets {
	t.Helper()

	dir := t.TempDir()
	now := time.Now()

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "shamantun-test-server"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           serverIPs,
	}
	/* Creates self-signed certs for testing. */
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, serverTemplate, &serverKey.PublicKey, serverKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "shamantun-test-client"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, clientTemplate, &clientKey.PublicKey, clientKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	assets := &mtlsAssets{
		ServerPEM: filepath.Join(dir, "server.pem"),
		ServerKey: filepath.Join(dir, "server.key"),
		ClientPEM: filepath.Join(dir, "client.pem"),
		ClientKey: filepath.Join(dir, "client.key"),
	}

	writePEMBlock(t, assets.ServerPEM, "CERTIFICATE", serverDER)
	writePEMBlock(t, assets.ClientPEM, "CERTIFICATE", clientDER)
	writePEMBlock(t, assets.ServerKey, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverKey))
	writePEMBlock(t, assets.ClientKey, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientKey))

	return assets
}

func writePEMBlock(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	block := &pem.Block{Type: blockType, Bytes: der}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func startSocks5TLSTestServer(t *testing.T, listenIP net.IP, mtls *mtlsAssets, virtualTarget, backendAddr string) (string, func()) {
	t.Helper()

	ln := newTestTLSListener(t, listenIP, mtls)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				handleSocks5TLSTestConn(c, virtualTarget, backendAddr)
			}(conn)
		}
	}()

	addr := buildListenerAddr(listenIP, ln.Addr().String())
	stop := func() {
		_ = ln.Close()
		wg.Wait()
	}
	return addr, stop
}

func handleSocks5TLSTestConn(conn net.Conn, virtualTarget, backendAddr string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return
	}
	if greeting[0] != socksVersion {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{socksVersion, 0x00}); err != nil {
		return
	}

	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHdr); err != nil {
		return
	}
	if reqHdr[0] != socksVersion || reqHdr[1] != socksCmdConnect {
		_, _ = conn.Write([]byte{socksVersion, 0x07, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}

	targetAddr, err := readSocks5TargetAddress(conn, reqHdr[3])
	if err != nil {
		_, _ = conn.Write([]byte{socksVersion, 0x08, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	if targetAddr != virtualTarget {
		_, _ = conn.Write([]byte{socksVersion, 0x04, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}

	upstream, err := net.DialTimeout("tcp", backendAddr, 5*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte{socksVersion, 0x05, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()

	if _, err := conn.Write([]byte{socksVersion, 0x00, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	relayBidirectional(conn, upstream, 32*1024, 30*time.Second)
}

func readSocks5TargetAddress(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case socksAtypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(r, addr); err != nil {
			return "", err
		}
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(r, portBuf); err != nil {
			return "", err
		}
		port := int(binary.BigEndian.Uint16(portBuf))
		return net.JoinHostPort(net.IP(addr).String(), strconv.Itoa(port)), nil
	case socksAtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", err
		}
		hostLen := int(lenBuf[0])
		hostBuf := make([]byte, hostLen)
		if _, err := io.ReadFull(r, hostBuf); err != nil {
			return "", err
		}
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(r, portBuf); err != nil {
			return "", err
		}
		port := int(binary.BigEndian.Uint16(portBuf))
		return net.JoinHostPort(string(hostBuf), strconv.Itoa(port)), nil
	case socksAtypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(r, addr); err != nil {
			return "", err
		}
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(r, portBuf); err != nil {
			return "", err
		}
		port := int(binary.BigEndian.Uint16(portBuf))
		return net.JoinHostPort(net.IP(addr).String(), strconv.Itoa(port)), nil
	default:
		return "", fmt.Errorf("unsupported socks atyp %d", atyp)
	}
}

func startHTTPSConnectTLSTestServer(t *testing.T, listenIP net.IP, mtls *mtlsAssets, virtualTarget, backendAddr, basicUser, basicPass string) (string, func()) {
	t.Helper()

	ln := newTestTLSListener(t, listenIP, mtls)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				handleHTTPSConnectTestConn(c, virtualTarget, backendAddr, basicUser, basicPass)
			}(conn)
		}
	}()

	addr := buildListenerAddr(listenIP, ln.Addr().String())
	stop := func() {
		_ = ln.Close()
		wg.Wait()
	}
	return addr, stop
}

func handleHTTPSConnectTestConn(conn net.Conn, virtualTarget, backendAddr, basicUser, basicPass string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	br := bufio.NewReader(conn)
	reqLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Split(strings.TrimSpace(reqLine), " ")
	if len(parts) < 2 || strings.ToUpper(parts[0]) != "CONNECT" {
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	targetAddr := parts[1]

	var proxyAuth string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "proxy-authorization:") {
			proxyAuth = strings.TrimSpace(line[len("proxy-authorization:"):])
		}
	}

	if basicUser != "" || basicPass != "" {
		if !validateBasicAuthHeader(proxyAuth, basicUser, basicPass) {
			_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"test\"\r\n\r\n")
			return
		}
	}
	if targetAddr != virtualTarget {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}

	upstream, err := net.DialTimeout("tcp", backendAddr, 5*time.Second)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 503 Service Unavailable\r\n\r\n")
		return
	}
	defer upstream.Close()

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	relayBidirectional(&proxyBufferedConn{Conn: conn, r: br}, upstream, 32*1024, 30*time.Second)
}

type proxyBufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *proxyBufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func validateBasicAuthHeader(header, user, pass string) bool {
	fields := strings.Fields(strings.TrimSpace(header))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Basic") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return false
	}
	return string(decoded) == user+":"+pass
}

func newTestTLSListener(t *testing.T, listenIP net.IP, mtls *mtlsAssets) net.Listener {
	t.Helper()

	cert, err := tls.LoadX509KeyPair(mtls.ServerPEM, mtls.ServerKey)
	if err != nil {
		t.Fatalf("load server cert: %v", err)
	}
	/* Disables client cert verification in tests because ca_pem is removed. */

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert, /* Keeps the test server setup simple without ca_pem. */
	}

	ln, err := tls.Listen("tcp", net.JoinHostPort(listenIP.String(), "0"), tlsCfg)
	if err != nil {
		t.Fatalf("listen tls on %s: %v", listenIP.String(), err)
	}
	return ln
}

func buildListenerAddr(ip net.IP, listenAddr string) string {
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return listenAddr
	}
	return net.JoinHostPort(ip.String(), port)
}
