package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

/* ----------------------------------------------------------------------------- */
/* Upstream protocols: SOCKS5-over-TLS and HTTPS CONNECT-over-TLS */
/* ----------------------------------------------------------------------------- */

/* Upstream dialers. */
type UpstreamDialer interface {
	DialTCP(ctx context.Context, targetAddr string) (net.Conn, error)
	DialUDP(ctx context.Context) (UDPSession, error)
	SupportsUDP() bool
	Mode() string
}

type UpstreamWarmer interface {
	Warmup(ctx context.Context) error
}

type UDPSession interface {
	WriteTo(payload []byte, target *net.UDPAddr) error
	ReadFrom(payload []byte) (int, *net.UDPAddr, error)
	Close() error
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

/* Selects the upstream implementation for the configured mode. */
func NewUpstreamDialer(mode string, cfg UpstreamConfig, connectTimeout time.Duration, udpBufSize int) (UpstreamDialer, error) {
	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	switch mode {
	case ModeSocks5TLS:
		return NewSocks5TLSDialer(cfg.Addr, tlsCfg, connectTimeout, cfg.Username, cfg.Password, udpBufSize), nil
	case ModeHTTPS:
		return NewHTTPSConnectDialer(cfg.Addr, tlsCfg, connectTimeout, cfg.Username, cfg.Password), nil
	default:
		return nil, fmt.Errorf("unsupported mode %q", mode)
	}
}

/* Prepares client TLS and mTLS settings shared by both modes. */
func buildTLSConfig(cfg UpstreamConfig) (*tls.Config, error) {
	serverName := strings.TrimSpace(cfg.ServerName)
	if serverName == "" {
		host, _, err := net.SplitHostPort(strings.TrimSpace(cfg.Addr))
		if err == nil && net.ParseIP(strings.TrimSpace(host)) == nil {
			serverName = strings.TrimSpace(host)
		}
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		ClientSessionCache: tls.NewLRUClientSessionCache(128),
	}

	clientPEMPath, clientKeyPath := cfg.trimmedClientCertificatePaths()
	if clientPEMPath != "" || clientKeyPath != "" {
		if clientPEMPath == "" || clientKeyPath == "" {
			return nil, fmt.Errorf("client certificate and key must both be set")
		}
		cert, err := loadClientCertificate(clientPEMPath, clientKeyPath)
		if err != nil {
			return nil, err
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

func loadClientCertificate(certPath, keyPath string) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read client certificate %q: %w", certPath, err)
	}
	if len(certPEM) == 0 {
		return tls.Certificate{}, fmt.Errorf("read client certificate %q: empty file", certPath)
	}
	if block, _ := pem.Decode(certPEM); block == nil {
		return tls.Certificate{}, fmt.Errorf("parse client certificate %q: no PEM block found", certPath)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read client private key %q: %w", keyPath, err)
	}
	if len(keyPEM) == 0 {
		return tls.Certificate{}, fmt.Errorf("read client private key %q: empty file", keyPath)
	}
	if block, _ := pem.Decode(keyPEM); block == nil {
		return tls.Certificate{}, fmt.Errorf("parse client private key %q: no PEM block found", keyPath)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load client certificate/key pair cert=%q key=%q: %w", certPath, keyPath, err)
	}
	return cert, nil
}

type Socks5TLSDialer struct {
	upstreamAddr string
	tlsConfig    *tls.Config
	timeout      time.Duration
	username     string
	password     string
	udpBufSize   int
}

const (
	socksVersion      = 0x05
	socksCmdConnect   = 0x01
	socksCmdAssociate = 0x03
	socksAtypIPv4     = 0x01
	socksAtypDomain   = 0x03
	socksAtypIPv6     = 0x04
)

func NewSocks5TLSDialer(upstreamAddr string, tlsConfig *tls.Config, timeout time.Duration, username, password string, udpBufSize int) *Socks5TLSDialer {
	if udpBufSize <= 0 {
		udpBufSize = 64 * 1024
	}
	return &Socks5TLSDialer{
		upstreamAddr: upstreamAddr,
		tlsConfig:    tlsConfig,
		timeout:      timeout,
		username:     username,
		password:     password,
		udpBufSize:   udpBufSize,
	}
}

func (d *Socks5TLSDialer) Mode() string { return ModeSocks5TLS }

func (d *Socks5TLSDialer) SupportsUDP() bool { return true }

func (d *Socks5TLSDialer) Warmup(ctx context.Context) error {
	conn, err := d.dialControlConn(ctx)
	if err != nil {
		return err
	}
	return conn.Close()
}

func (d *Socks5TLSDialer) DialTCP(ctx context.Context, targetAddr string) (net.Conn, error) {
	conn, err := d.dialControlConn(ctx)
	if err != nil {
		return nil, err
	}
	stopCancelMonitor := monitorHandshakeCancellation(ctx, conn)
	defer stopCancelMonitor()
	if err := applyHandshakeDeadline(conn, d.timeout); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set socks5 tcp handshake deadline: %w", err)
	}

	br := bufio.NewReader(conn)
	if err := d.handshakeConnect(br, conn, targetAddr); err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}

	if err := clearConnDeadline(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("clear socks5 tcp handshake deadline: %w", err)
	}

	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, br: br}, nil
	}
	return conn, nil
}

func (d *Socks5TLSDialer) DialUDP(ctx context.Context) (UDPSession, error) {
	conn, err := d.dialControlConn(ctx)
	if err != nil {
		return nil, err
	}
	stopCancelMonitor := monitorHandshakeCancellation(ctx, conn)
	defer stopCancelMonitor()
	if err := applyHandshakeDeadline(conn, d.timeout); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set socks5 udp handshake deadline: %w", err)
	}

	udpConn, assocAddr, err := prepareSocks5UDPSocket(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	relayAddr, err := d.handshakeUDPAssociate(conn, assocAddr)
	if err != nil {
		_ = udpConn.Close()
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if err := clearConnDeadline(conn); err != nil {
		_ = udpConn.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("clear socks5 udp handshake deadline: %w", err)
	}
	relayAddr, err = normalizeSocks5UDPRelayAddr(relayAddr, conn)
	if err != nil {
		_ = udpConn.Close()
		_ = conn.Close()
		return nil, err
	}

	bufSize := d.udpBufSize + 512
	if bufSize < 64*1024+512 {
		bufSize = 64*1024 + 512
	}

	session := &socks5TLSUDPSession{
		controlConn: conn,
		udpConn:     udpConn,
		relayAddr:   relayAddr,
		readBuf:     make([]byte, bufSize),
	}
	session.startControlMonitor()
	return session, nil
}

/* Rewrites ambiguous SOCKS5 UDP relay addresses to the control connection peer IP. */
func normalizeSocks5UDPRelayAddr(relayAddr *net.UDPAddr, controlConn net.Conn) (*net.UDPAddr, error) {
	if relayAddr == nil || relayAddr.Port == 0 {
		return nil, fmt.Errorf("invalid socks5 udp relay address")
	}

	ip := relayAddr.IP
	if ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() {
		if ip.To4() == nil && ip.IsLinkLocalUnicast() && relayAddr.Zone == "" {
			_, peerZone, err := peerIPFromConn(controlConn)
			if err == nil && peerZone != "" {
				preserved := &net.UDPAddr{IP: append(net.IP(nil), ip...), Port: relayAddr.Port, Zone: peerZone}
				return preserved, nil
			}
		}
		return relayAddr, nil
	}

	peerIP, peerZone, err := peerIPFromConn(controlConn)
	if err != nil {
		return nil, fmt.Errorf("resolve socks5 udp relay peer ip: %w", err)
	}
	if peerIP == nil {
		return nil, fmt.Errorf("resolve socks5 udp relay peer ip: empty peer ip")
	}

	normalized := &net.UDPAddr{IP: append(net.IP(nil), peerIP...), Port: relayAddr.Port}
	if relayAddr.Zone != "" {
		normalized.Zone = relayAddr.Zone
	} else if peerZone != "" {
		normalized.Zone = peerZone
	}
	return normalized, nil
}

/* Extracts the peer IP from a connected control socket. */
func peerIPFromConn(conn net.Conn) (net.IP, string, error) {
	if conn == nil {
		return nil, "", fmt.Errorf("nil control conn")
	}

	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok && tcpAddr != nil && tcpAddr.IP != nil {
		return append(net.IP(nil), tcpAddr.IP...), tcpAddr.Zone, nil
	}

	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, "", err
	}
	zone := ""
	if percent := strings.LastIndex(host, "%"); percent >= 0 {
		zone = host[percent+1:]
		host = host[:percent]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, "", fmt.Errorf("peer host is not ip: %q", host)
	}
	return ip, zone, nil
}

/* Establishes the TLS control channel to the SOCKS5 server. */
func (d *Socks5TLSDialer) dialControlConn(ctx context.Context) (net.Conn, error) {
	netDialer := &net.Dialer{Timeout: d.timeout, KeepAlive: 30 * time.Second}
	tlsDialer := &tls.Dialer{NetDialer: netDialer, Config: d.tlsConfig}

	conn, err := tlsDialer.DialContext(ctx, "tcp", d.upstreamAddr)
	if err != nil {
		return nil, fmt.Errorf("dial upstream tls %s: %w", d.upstreamAddr, err)
	}

	return conn, nil
}

/* Performs SOCKS5 CONNECT negotiation for a TCP destination. */
func (d *Socks5TLSDialer) handshakeConnect(br io.Reader, conn net.Conn, targetAddr string) error {
	if err := socks5Greeting(br, conn, d.username, d.password); err != nil {
		return err
	}

	req, err := buildSocks5CommandRequest(socksCmdConnect, targetAddr)
	if err != nil {
		return err
	}
	if err := writeAll(conn, req); err != nil {
		return fmt.Errorf("write socks5 connect request: %w", err)
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return fmt.Errorf("read socks5 connect response header: %w", err)
	}
	if hdr[0] != socksVersion {
		return fmt.Errorf("invalid socks version in response: %d", hdr[0])
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed, reply code: %d", hdr[1])
	}
	if hdr[2] != 0x00 {
		return fmt.Errorf("invalid socks5 connect reserved byte: %d", hdr[2])
	}

	if _, err := readSocks5AddressFromReader(br, hdr[3]); err != nil {
		return err
	}
	return nil
}

/* Obtains the relay address for SOCKS5 UDP tunneling. */
func (d *Socks5TLSDialer) handshakeUDPAssociate(conn net.Conn, clientAddr *net.UDPAddr) (*net.UDPAddr, error) {
	if err := socks5Greeting(conn, conn, d.username, d.password); err != nil {
		return nil, err
	}

	req, err := buildSocks5UDPAssociateRequest(clientAddr)
	if err != nil {
		return nil, err
	}
	if err := writeAll(conn, req); err != nil {
		return nil, fmt.Errorf("write socks5 udp associate request: %w", err)
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, fmt.Errorf("read socks5 udp associate response header: %w", err)
	}
	if hdr[0] != socksVersion {
		return nil, fmt.Errorf("invalid socks version in udp associate response: %d", hdr[0])
	}
	if hdr[1] != 0x00 {
		return nil, fmt.Errorf("socks5 udp associate failed, reply code: %d", hdr[1])
	}
	if hdr[2] != 0x00 {
		return nil, fmt.Errorf("invalid socks5 udp associate reserved byte: %d", hdr[2])
	}

	relayAddr, err := readSocks5AddressFromReader(conn, hdr[3])
	if err != nil {
		return nil, err
	}
	if relayAddr == nil || relayAddr.Port == 0 {
		return nil, fmt.Errorf("invalid socks5 udp relay address")
	}

	return relayAddr, nil
}

/* Negotiates SOCKS5 authentication and performs username/password auth when configured. */
func socks5Greeting(r io.Reader, w io.Writer, username, password string) error {
	methods := []byte{0x00}
	useUserPass := strings.TrimSpace(username) != "" || strings.TrimSpace(password) != ""
	if useUserPass {
		methods = append(methods, 0x02)
	}
	req := make([]byte, 0, 2+len(methods))
	req = append(req, socksVersion, byte(len(methods)))
	req = append(req, methods...)
	if err := writeAll(w, req); err != nil {
		return fmt.Errorf("write socks5 greeting: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(r, resp); err != nil {
		return fmt.Errorf("read socks5 greeting response: %w", err)
	}
	if resp[0] != socksVersion {
		return fmt.Errorf("invalid socks version in greeting response: %d", resp[0])
	}
	switch resp[1] {
	case 0x00:
		return nil
	case 0x02:
		if !useUserPass {
			return fmt.Errorf("socks5 server requested username/password auth but no credentials are configured")
		}
		if err := socks5UserPassAuth(r, w, username, password); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("socks5 server rejected method: ver=%d method=%d", resp[0], resp[1])
	}
}

/* Performs RFC1929 username and password authentication. */
func socks5UserPassAuth(r io.Reader, w io.Writer, username, password string) error {
	if len(username) > 255 {
		return fmt.Errorf("socks5 username too long")
	}
	if len(password) > 255 {
		return fmt.Errorf("socks5 password too long")
	}
	req := make([]byte, 0, 3+len(username)+len(password))
	req = append(req, 0x01, byte(len(username)))
	req = append(req, username...)
	req = append(req, byte(len(password)))
	req = append(req, password...)
	if err := writeAll(w, req); err != nil {
		return fmt.Errorf("write socks5 username/password auth: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(r, resp); err != nil {
		return fmt.Errorf("read socks5 username/password auth response: %w", err)
	}
	if resp[0] != 0x01 || resp[1] != 0x00 {
		return fmt.Errorf("socks5 username/password auth failed: ver=%d status=%d", resp[0], resp[1])
	}
	return nil
}

func buildSocks5CommandRequest(cmd byte, targetAddr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid target addr %q: %w", targetAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid target port %q", portStr)
	}

	buf := make([]byte, 0, 4+256+2)
	buf = append(buf, socksVersion, cmd, 0x00)

	ip := net.ParseIP(host)
	switch {
	case ip != nil && ip.To4() != nil:
		buf = append(buf, socksAtypIPv4)
		buf = append(buf, ip.To4()...)
	case ip != nil && ip.To16() != nil:
		buf = append(buf, socksAtypIPv6)
		buf = append(buf, ip.To16()...)
	default:
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("invalid domain in target addr: %q", host)
		}
		buf = append(buf, socksAtypDomain, byte(len(host)))
		buf = append(buf, host...)
	}

	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	buf = append(buf, portBytes[:]...)

	return buf, nil
}

func readSocks5AddressFromReader(r io.Reader, atyp byte) (*net.UDPAddr, error) {
	var addrLen int
	switch atyp {
	case socksAtypIPv4:
		addrLen = 4
	case socksAtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return nil, fmt.Errorf("read socks5 domain len: %w", err)
		}
		addrLen = int(lenBuf[0])
		if addrLen == 0 {
			return nil, fmt.Errorf("invalid socks5 domain len: 0")
		}
	case socksAtypIPv6:
		addrLen = 16
	default:
		return nil, fmt.Errorf("unknown socks5 atyp in response: %d", atyp)
	}

	addrBytes := make([]byte, addrLen)
	if addrLen > 0 {
		if _, err := io.ReadFull(r, addrBytes); err != nil {
			return nil, fmt.Errorf("read socks5 bind addr: %w", err)
		}
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return nil, fmt.Errorf("read socks5 bind port: %w", err)
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	switch atyp {
	case socksAtypIPv4, socksAtypIPv6:
		return &net.UDPAddr{IP: net.IP(addrBytes), Port: port}, nil
	case socksAtypDomain:
		return &net.UDPAddr{Port: port}, nil
	default:
		return nil, fmt.Errorf("unknown socks5 atyp in response: %d", atyp)
	}
}

type socks5TLSUDPSession struct {
	controlConn net.Conn
	udpConn     *net.UDPConn
	relayAddr   *net.UDPAddr
	readBuf     []byte
	closeOnce   sync.Once
}

/* Wraps payload into a SOCKS5 UDP frame and sends it to the relay. */
func (s *socks5TLSUDPSession) WriteTo(payload []byte, target *net.UDPAddr) error {
	addrBytes, err := encodeSocks5UDPAddress(target)
	if err != nil {
		return err
	}

	packet := make([]byte, 3+len(addrBytes)+len(payload))
	packet[0], packet[1], packet[2] = 0x00, 0x00, 0x00
	copy(packet[3:], addrBytes)
	copy(packet[3+len(addrBytes):], payload)

	if s.udpConn == nil {
		return net.ErrClosed
	}
	if s.relayAddr != nil {
		n, err := s.udpConn.WriteToUDP(packet, s.relayAddr)
		if err != nil {
			return err
		}
		if n != len(packet) {
			return io.ErrShortWrite
		}
		return nil
	}
	n, err := s.udpConn.Write(packet)
	if err != nil {
		return err
	}
	if n != len(packet) {
		return io.ErrShortWrite
	}
	return nil
}

/* Decapsulates a SOCKS5 UDP frame and returns the source metadata. */
func (s *socks5TLSUDPSession) ReadFrom(payload []byte) (int, *net.UDPAddr, error) {
	if s.udpConn == nil {
		return 0, nil, net.ErrClosed
	}

	for {
		var n int
		var err error
		if s.relayAddr != nil {
			var srcAddr *net.UDPAddr
			n, srcAddr, err = s.udpConn.ReadFromUDP(s.readBuf)
			if err != nil {
				return 0, nil, err
			}
			if !sameUDPEndpoint(srcAddr, s.relayAddr) {
				continue
			}
		} else {
			n, err = s.udpConn.Read(s.readBuf)
			if err != nil {
				return 0, nil, err
			}
		}
		if n < 4 {
			return 0, nil, fmt.Errorf("short udp packet from relay: %d", n)
		}
		if s.readBuf[2] != 0x00 {
			return 0, nil, fmt.Errorf("fragmented udp packet from relay is unsupported")
		}

		src, headerLen, err := decodeSocks5UDPAddress(s.readBuf[3:n])
		if err != nil {
			return 0, nil, err
		}
		totalHeader := 3 + headerLen
		if totalHeader > n {
			return 0, nil, fmt.Errorf("invalid udp packet header length")
		}

		body := s.readBuf[totalHeader:n]
		if len(body) > len(payload) {
			logf(LogLevelDebug, "[DEBUG] [UDP] SOCKS5 relay: dropped oversized frame body=%d payload_cap=%d", len(body), len(payload))
			continue /* oversized frame from relay; drop and read next */
		}
		copy(payload, body)
		return len(body), src, nil
	}
}

func (s *socks5TLSUDPSession) Close() error {
	var udpErr, ctlErr error
	s.closeOnce.Do(func() {
		if s.udpConn != nil {
			udpErr = s.udpConn.Close()
		}
		if s.controlConn != nil {
			ctlErr = s.controlConn.Close()
		}
	})
	if udpErr != nil {
		return udpErr
	}
	return ctlErr
}

func (s *socks5TLSUDPSession) SetDeadline(t time.Time) error {
	if s.udpConn == nil {
		return net.ErrClosed
	}
	return s.udpConn.SetDeadline(t)
}

func (s *socks5TLSUDPSession) SetReadDeadline(t time.Time) error {
	if s.udpConn == nil {
		return net.ErrClosed
	}
	return s.udpConn.SetReadDeadline(t)
}

func (s *socks5TLSUDPSession) SetWriteDeadline(t time.Time) error {
	if s.udpConn == nil {
		return net.ErrClosed
	}
	return s.udpConn.SetWriteDeadline(t)
}

/* Closes the UDP socket as soon as the SOCKS5 control connection terminates. */
func (s *socks5TLSUDPSession) startControlMonitor() {
	if s == nil || s.controlConn == nil || s.udpConn == nil {
		return
	}
	go func() {
		var probe [1]byte
		_, _ = s.controlConn.Read(probe[:])
		s.closeOnce.Do(func() {
			if s.udpConn != nil {
				_ = s.udpConn.Close()
			}
			if s.controlConn != nil {
				_ = s.controlConn.Close()
			}
		})
	}()
}

func prepareSocks5UDPSocket(controlConn net.Conn) (*net.UDPConn, *net.UDPAddr, error) {
	ip := localIPFromConn(controlConn)
	var bindAddr *net.UDPAddr
	if ip != nil && !ip.IsUnspecified() {
		bindAddr = &net.UDPAddr{IP: append(net.IP(nil), ip...), Port: 0}
	}

	udpConn, err := net.ListenUDP("udp", bindAddr)
	if err != nil && bindAddr != nil {
		udpConn, err = net.ListenUDP("udp", nil)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("open local udp socket for socks5 associate: %w", err)
	}

	local, ok := udpConn.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil {
		_ = udpConn.Close()
		return nil, nil, fmt.Errorf("resolve local udp socket addr failed")
	}

	assoc := &net.UDPAddr{Port: local.Port}
	switch {
	case bindAddr != nil && bindAddr.IP != nil && !bindAddr.IP.IsUnspecified():
		assoc.IP = append(net.IP(nil), bindAddr.IP...)
	case local.IP != nil && !local.IP.IsUnspecified():
		assoc.IP = append(net.IP(nil), local.IP...)
	default:
		assoc.IP = net.IPv4zero
	}

	return udpConn, assoc, nil
}

func localIPFromConn(conn net.Conn) net.IP {
	if conn == nil {
		return nil
	}
	if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok && tcpAddr != nil && tcpAddr.IP != nil {
		return append(net.IP(nil), tcpAddr.IP...)
	}
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}

func buildSocks5UDPAssociateRequest(clientAddr *net.UDPAddr) ([]byte, error) {
	if clientAddr == nil || clientAddr.Port < 0 || clientAddr.Port > 65535 {
		return []byte{socksVersion, socksCmdAssociate, 0x00, socksAtypIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, nil
	}

	ip := clientAddr.IP
	if ip == nil || ip.IsUnspecified() {
		out := []byte{socksVersion, socksCmdAssociate, 0x00, socksAtypIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		binary.BigEndian.PutUint16(out[8:10], uint16(clientAddr.Port))
		return out, nil
	}

	if ip4 := ip.To4(); ip4 != nil {
		out := make([]byte, 10)
		out[0], out[1], out[2], out[3] = socksVersion, socksCmdAssociate, 0x00, socksAtypIPv4
		copy(out[4:8], ip4)
		binary.BigEndian.PutUint16(out[8:10], uint16(clientAddr.Port))
		return out, nil
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return nil, fmt.Errorf("invalid client udp associate ip: %v", ip)
	}
	out := make([]byte, 22)
	out[0], out[1], out[2], out[3] = socksVersion, socksCmdAssociate, 0x00, socksAtypIPv6
	copy(out[4:20], ip16)
	binary.BigEndian.PutUint16(out[20:22], uint16(clientAddr.Port))
	return out, nil
}

func sameUDPEndpoint(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	if a.Port != b.Port {
		return false
	}
	if len(a.IP) == 0 || len(b.IP) == 0 {
		return true /* Treats SOCKS5 domain-form addresses as opaque host matches once the port aligns. */
	}
	/* Normalizes both addresses to 16-byte form so IPv4 and IPv4-mapped IPv6 compare consistently. */
	aIP, bIP := a.IP.To16(), b.IP.To16()
	if aIP == nil || bIP == nil {
		return a.IP.Equal(b.IP) && (a.Zone == "" && b.Zone == "" || a.Zone == b.Zone)
	}
	if !aIP.Equal(bIP) {
		return false
	}
	if a.Zone != "" || b.Zone != "" {
		return a.Zone == b.Zone
	}
	return true
}

func encodeSocks5UDPAddress(target *net.UDPAddr) ([]byte, error) {
	if target == nil {
		return nil, fmt.Errorf("nil udp target")
	}
	if ip4 := target.IP.To4(); ip4 != nil {
		out := make([]byte, 1+4+2)
		out[0] = socksAtypIPv4
		copy(out[1:5], ip4)
		binary.BigEndian.PutUint16(out[5:7], uint16(target.Port))
		return out, nil
	}

	ip16 := target.IP.To16()
	if ip16 == nil {
		return nil, fmt.Errorf("invalid udp target ip: %v", target.IP)
	}
	out := make([]byte, 1+16+2)
	out[0] = socksAtypIPv6
	copy(out[1:17], ip16)
	binary.BigEndian.PutUint16(out[17:19], uint16(target.Port))
	return out, nil
}

func decodeSocks5UDPAddress(packet []byte) (*net.UDPAddr, int, error) {
	if len(packet) < 1 {
		return nil, 0, fmt.Errorf("empty udp packet address")
	}

	switch packet[0] {
	case socksAtypIPv4:
		if len(packet) < 7 {
			return nil, 0, fmt.Errorf("short ipv4 udp header")
		}
		ip := make(net.IP, net.IPv4len)
		copy(ip, packet[1:5])
		port := int(binary.BigEndian.Uint16(packet[5:7]))
		return &net.UDPAddr{IP: ip, Port: port}, 7, nil
	case socksAtypIPv6:
		if len(packet) < 19 {
			return nil, 0, fmt.Errorf("short ipv6 udp header")
		}
		ip := make(net.IP, net.IPv6len)
		copy(ip, packet[1:17])
		port := int(binary.BigEndian.Uint16(packet[17:19]))
		return &net.UDPAddr{IP: ip, Port: port}, 19, nil
	case socksAtypDomain:
		if len(packet) < 2 {
			return nil, 0, fmt.Errorf("short domain udp header")
		}
		hostLen := int(packet[1])
		if hostLen == 0 {
			return nil, 0, fmt.Errorf("invalid domain udp header")
		}
		total := 1 + 1 + hostLen + 2
		if len(packet) < total {
			return nil, 0, fmt.Errorf("incomplete domain udp header")
		}
		port := int(binary.BigEndian.Uint16(packet[2+hostLen : total]))
		return &net.UDPAddr{Port: port}, total, nil
	default:
		return nil, 0, fmt.Errorf("unknown udp atyp: %d", packet[0])
	}
}

type HTTPSConnectDialer struct {
	upstreamAddr string
	tlsConfig    *tls.Config
	timeout      time.Duration
	basicUser    string
	basicPass    string
}

func NewHTTPSConnectDialer(upstreamAddr string, tlsConfig *tls.Config, timeout time.Duration, basicUser, basicPass string) *HTTPSConnectDialer {
	return &HTTPSConnectDialer{
		upstreamAddr: upstreamAddr,
		tlsConfig:    tlsConfig,
		timeout:      timeout,
		basicUser:    basicUser,
		basicPass:    basicPass,
	}
}

func (d *HTTPSConnectDialer) Mode() string { return ModeHTTPS }

func (d *HTTPSConnectDialer) SupportsUDP() bool { return false }

func (d *HTTPSConnectDialer) Warmup(ctx context.Context) error {
	netDialer := &net.Dialer{Timeout: d.timeout, KeepAlive: 30 * time.Second}
	tlsDialer := &tls.Dialer{NetDialer: netDialer, Config: d.tlsConfig}
	conn, err := tlsDialer.DialContext(ctx, "tcp", d.upstreamAddr)
	if err != nil {
		return fmt.Errorf("dial https proxy tls %s: %w", d.upstreamAddr, err)
	}
	return conn.Close()
}

func (d *HTTPSConnectDialer) DialUDP(ctx context.Context) (UDPSession, error) {
	_ = ctx
	return nil, errors.New("https connect mode does not support udp")
}

func (d *HTTPSConnectDialer) DialTCP(ctx context.Context, targetAddr string) (net.Conn, error) {
	netDialer := &net.Dialer{Timeout: d.timeout, KeepAlive: 30 * time.Second}
	tlsDialer := &tls.Dialer{NetDialer: netDialer, Config: d.tlsConfig}

	conn, err := tlsDialer.DialContext(ctx, "tcp", d.upstreamAddr)
	if err != nil {
		return nil, fmt.Errorf("dial https proxy tls %s: %w", d.upstreamAddr, err)
	}
	stopCancelMonitor := monitorHandshakeCancellation(ctx, conn)
	defer stopCancelMonitor()
	if err := applyHandshakeDeadline(conn, d.timeout); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set https connect handshake deadline: %w", err)
	}
	br := bufio.NewReader(conn)

	if err := d.handshakeCONNECT(br, conn, targetAddr); err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if err := clearConnDeadline(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("clear https connect handshake deadline: %w", err)
	}

	if br.Buffered() == 0 {
		return conn, nil
	}
	return &bufferedConn{Conn: conn, br: br}, nil
}

/* Upgrades the TLS stream into an HTTP CONNECT tunnel. */
func (d *HTTPSConnectDialer) handshakeCONNECT(br *bufio.Reader, conn net.Conn, targetAddr string) error {
	authHeader := ""
	if strings.TrimSpace(d.basicUser) != "" || strings.TrimSpace(d.basicPass) != "" {
		token := base64.StdEncoding.EncodeToString([]byte(d.basicUser + ":" + d.basicPass))
		authHeader = "Proxy-Authorization: Basic " + token + "\r\n"
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n%s\r\n", targetAddr, targetAddr, authHeader)
	if err := writeAll(conn, []byte(req)); err != nil {
		return fmt.Errorf("write connect request: %w", err)
	}

	statusLine, err := readHTTPConnectLine(br)
	if err != nil {
		return fmt.Errorf("read connect response status: %w", err)
	}
	if !isHTTPConnectSuccessStatusLine(statusLine) {
		return fmt.Errorf("connect rejected: %s", strings.TrimSpace(statusLine))
	}

	linesRead := 0
	for {
		linesRead++
		if linesRead > 64 {
			return fmt.Errorf("connect response header too long (exceeds 64 lines)")
		}
		line, err := readHTTPConnectLine(br)
		if err != nil {
			return fmt.Errorf("read connect response headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	return nil
}

func isHTTPConnectSuccessStatusLine(line string) bool {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return false
	}
	if fields[0] != "HTTP/1.1" && fields[0] != "HTTP/1.0" {
		return false
	}
	return fields[1] == "200"
}

const maxHTTPConnectHeaderLineBytes = 8 * 1024

func readHTTPConnectLine(br *bufio.Reader) (string, error) {
	if br == nil {
		return "", io.EOF
	}

	var line []byte
	for {
		fragment, err := br.ReadSlice('\n')
		if len(fragment) > 0 {
			if len(line)+len(fragment) > maxHTTPConnectHeaderLineBytes {
				return "", fmt.Errorf("http connect response line too long (exceeds %d bytes)", maxHTTPConnectHeaderLineBytes)
			}
			line = append(line, fragment...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return string(line), err
	}
}

func monitorHandshakeCancellation(ctx context.Context, conn net.Conn) func() {
	if ctx == nil || conn == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			now := time.Now()
			_ = conn.SetDeadline(now)
			_ = conn.Close()
		case <-done:
		}
	}()
	return func() {
		close(done)
	}
}

type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.br.Read(p) }

/* Bounds handshake IO and prevents half-open stalls. */
func applyHandshakeDeadline(conn net.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	return conn.SetDeadline(time.Now().Add(timeout))
}

/* Resets a connection back to blocking mode after the handshake. */
func clearConnDeadline(conn net.Conn) error {
	return conn.SetDeadline(time.Time{})
}
