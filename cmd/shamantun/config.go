package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	ModeSocks5TLS = "socks5tls"
	ModeHTTPS     = "https"

	minConnectTimeoutMS   = 1000
	maxConnectTimeoutMS   = 120000
	minIdleTimeoutMS      = 5000
	maxIdleTimeoutMS      = 3600000
	minRuntimeBufferBytes = 4096
	maxRuntimeBufferBytes = 4 * 1024 * 1024
	maxDialConcurrency    = 1024
	maxDNSCacheEntries    = 65536
)

/* Internal runtime configuration assembled from the compact flat JSON payload. */
type Config struct {
	Mode      string
	AutoRoute bool
	Tun       TunConfig
	Upstream  UpstreamConfig
	Runtime   RuntimeConfig
}

/* Local tunnel interface settings. */
type TunConfig struct {
	Name string
	MTU  int
	IPv4 string
	IPv6 string
}

/* Remote proxy and TLS credentials. */
type UpstreamConfig struct {
	Addr               string
	ServerName         string
	ClientPEM          string
	ClientKey          string
	InsecureSkipVerify bool
	Username           string
	Password           string
}

/* Controls timeout and buffer behavior. */
type RuntimeConfig struct {
	ConnectTimeoutMS   int
	IdleTimeoutMS      int
	TCPBuffer          int
	UDPBuffer          int
	EnableUDP          bool
	TCPDialConcurrency int
	UDPDialConcurrency int
	DNSCacheSize       int
}

func (u UpstreamConfig) trimmedClientCertificatePaths() (string, string) {
	return strings.TrimSpace(u.ClientPEM), strings.TrimSpace(u.ClientKey)
}

func (u UpstreamConfig) hasBasicAuthCredentials() bool {
	return strings.TrimSpace(u.Username) != "" || strings.TrimSpace(u.Password) != ""
}

type configPayload struct {
	Mode      string `json:"mode"`
	AutoRoute *bool  `json:"auto_route"`

	Tun     string `json:"tun"`
	TunMTU  int    `json:"tun_mtu"`
	TunIPv4 string `json:"tun_ipv4"`
	TunIPv6 string `json:"tun_ipv6"`

	Upstream string `json:"upstream"`

	ClientPEM          string `json:"client_pem"`
	ClientKey          string `json:"client_key"`
	InsecureSkipVerify *bool  `json:"insecure_skip_verify"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	HTTPBasicUser      string `json:"http_basic_user"`
	HTTPBasicPass      string `json:"http_basic_pass"`

	ConnectTimeoutMS   int   `json:"connect_timeout_ms"`
	IdleTimeoutMS      int   `json:"idle_timeout_ms"`
	TCPBuffer          int   `json:"tcp_buffer"`
	UDPBuffer          int   `json:"udp_buffer"`
	EnableUDP          *bool `json:"enable_udp"`
	TCPDialConcurrency int   `json:"tcp_dial_concurrency"`
	UDPDialConcurrency int   `json:"udp_dial_concurrency"`
	DNSCacheSize       int   `json:"dns_cache_size"`
}

/* Reads, decodes, defaults, and validates the config file. */
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	cfg, err := decodeConfig(data)
	if err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

/* Parses compact JSON fields into the runtime configuration model. */
func decodeConfig(data []byte) (*Config, error) {
	var p configPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}

	cfg := &Config{
		Mode:      p.Mode,
		AutoRoute: true,
		Tun: TunConfig{
			Name: strings.TrimSpace(p.Tun),
			MTU:  p.TunMTU,
			IPv4: strings.TrimSpace(p.TunIPv4),
			IPv6: strings.TrimSpace(p.TunIPv6),
		},
		Upstream: UpstreamConfig{
			Addr:               strings.TrimSpace(p.Upstream),
			ClientPEM:          strings.TrimSpace(p.ClientPEM),
			ClientKey:          strings.TrimSpace(p.ClientKey),
			Username:           strings.TrimSpace(p.Username),
			Password:           strings.TrimSpace(p.Password),
			InsecureSkipVerify: false,
		},
		Runtime: RuntimeConfig{
			ConnectTimeoutMS:   p.ConnectTimeoutMS,
			IdleTimeoutMS:      p.IdleTimeoutMS,
			TCPBuffer:          p.TCPBuffer,
			UDPBuffer:          p.UDPBuffer,
			EnableUDP:          false,
			TCPDialConcurrency: p.TCPDialConcurrency,
			UDPDialConcurrency: p.UDPDialConcurrency,
			DNSCacheSize:       p.DNSCacheSize,
		},
	}

	if p.InsecureSkipVerify != nil {
		cfg.Upstream.InsecureSkipVerify = *p.InsecureSkipVerify
	}
	if p.AutoRoute != nil {
		cfg.AutoRoute = *p.AutoRoute
	}
	if cfg.Upstream.Username == "" {
		cfg.Upstream.Username = strings.TrimSpace(p.HTTPBasicUser)
	}
	if cfg.Upstream.Password == "" {
		cfg.Upstream.Password = strings.TrimSpace(p.HTTPBasicPass)
	}
	if p.EnableUDP != nil {
		cfg.Runtime.EnableUDP = *p.EnableUDP
	}
	return cfg, nil
}

/* Fills missing values with safe operational defaults. */
func (c *Config) applyDefaults() {
	if c.Mode == "" {
		c.Mode = ModeSocks5TLS
	}
	if c.Tun.Name == "" {
		if runtime.GOOS == "darwin" {
			c.Tun.Name = "utun"
		} else {
			c.Tun.Name = "tun0"
		}
	}
	if c.Tun.MTU <= 0 {
		c.Tun.MTU = 1500
	}
	if c.Runtime.ConnectTimeoutMS <= 0 {
		c.Runtime.ConnectTimeoutMS = 10_000
	}
	if c.Runtime.IdleTimeoutMS <= 0 {
		c.Runtime.IdleTimeoutMS = 300_000
	}
	if c.Runtime.TCPBuffer <= 0 {
		c.Runtime.TCPBuffer = 64 * 1024
	}
	if c.Runtime.UDPBuffer <= 0 {
		c.Runtime.UDPBuffer = 64 * 1024
	}
	if c.Runtime.TCPDialConcurrency <= 0 {
		c.Runtime.TCPDialConcurrency = 64
	}
	if c.Runtime.UDPDialConcurrency <= 0 {
		c.Runtime.UDPDialConcurrency = 4
	}
	if c.Runtime.DNSCacheSize <= 0 {
		c.Runtime.DNSCacheSize = 1024
	}
}

/* Applies CLI-level overrides and revalidates the config. */
func (c *Config) ApplyOverrides(mode, tunName string) error {
	if mode != "" {
		c.Mode = mode
	}
	if tunName != "" {
		c.Tun.Name = tunName
	}
	c.applyDefaults()
	return c.Validate()
}

/*
 * Resolves hostname upstreams to a single IP so auto-route bypass and actual
 * dials target the same address.
 */
func (c *Config) PinUpstreamIPForAutoRoute() (string, error) {
	return c.pinUpstreamIPForAutoRoute(resolveUpstreamIP)
}

func (c *Config) pinUpstreamIPForAutoRoute(resolve func(string) (string, error)) (string, error) {
	if c == nil {
		return "", errors.New("nil config")
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(c.Upstream.Addr))
	if err != nil {
		return "", err
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", errors.New("empty upstream host")
	}

	if ip := net.ParseIP(host); ip != nil {
		c.Upstream.Addr = net.JoinHostPort(ip.String(), port)
		return "", nil
	}

	if strings.TrimSpace(c.Upstream.ServerName) == "" {
		c.Upstream.ServerName = host
	}
	resolvedIP, err := resolve(host)
	if err != nil {
		return "", err
	}
	c.Upstream.Addr = net.JoinHostPort(resolvedIP, port)
	return host, nil
}

/* Enforces protocol and credential constraints required by runtime. */
func (c *Config) Validate() error {
	mode := strings.ToLower(strings.TrimSpace(c.Mode))
	switch mode {
	case ModeSocks5TLS, ModeHTTPS:
		c.Mode = mode
	default:
		return fmt.Errorf("unsupported mode %q (want %q or %q)", c.Mode, ModeSocks5TLS, ModeHTTPS)
	}
	if strings.TrimSpace(c.Upstream.Addr) == "" {
		return errors.New("upstream is required")
	}
	host, portStr, err := net.SplitHostPort(c.Upstream.Addr)
	if err != nil {
		return fmt.Errorf("upstream.addr must be host:port, got %q: %w", c.Upstream.Addr, err)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("upstream.addr host is empty: %q", c.Upstream.Addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("upstream.addr has invalid port %q", portStr)
	}
	httpsWithBasicAuth := c.Mode == ModeHTTPS && c.Upstream.hasBasicAuthCredentials()
	clientPEMPath, clientKeyPath := c.Upstream.trimmedClientCertificatePaths()
	if !httpsWithBasicAuth && (clientPEMPath == "" || clientKeyPath == "") {
		return errors.New("upstream.client_pem and upstream.client_key are required")
	}
	if clientPEMPath != "" || clientKeyPath != "" {
		if clientPEMPath == "" || clientKeyPath == "" {
			return errors.New("upstream.client_pem and upstream.client_key must both be set")
		}
		if _, err := os.Stat(clientPEMPath); err != nil {
			return fmt.Errorf("upstream.client_pem is not accessible: %w", err)
		}
		if _, err := os.Stat(clientKeyPath); err != nil {
			return fmt.Errorf("upstream.client_key is not accessible: %w", err)
		}
	}
	tunName := strings.TrimSpace(c.Tun.Name)
	if tunName == "" {
		return errors.New("tun.name is required")
	}
	switch runtime.GOOS {
	case "linux":
		if len(tunName) > 15 {
			return fmt.Errorf("tun.name too long for linux (max 15): %q", tunName)
		}
	case "darwin":
		if _, err := parseUTUNUnit(tunName); err != nil {
			return fmt.Errorf("invalid tun.name for darwin: %w", err)
		}
	default:
		return fmt.Errorf("unsupported runtime os %q (only linux/darwin)", runtime.GOOS)
	}
	if c.Tun.MTU < 576 {
		return fmt.Errorf("tun.mtu too small: %d", c.Tun.MTU)
	}
	if strings.TrimSpace(c.Tun.IPv6) != "" {
		if !strings.Contains(c.Tun.IPv6, "/") {
			ip := net.ParseIP(strings.TrimSpace(c.Tun.IPv6))
			if ip == nil || ip.To16() == nil || ip.To4() != nil {
				return fmt.Errorf("tun.ipv6 must be an IPv6 address or CIDR, got %q", c.Tun.IPv6)
			}
		} else {
			ip, _, err := net.ParseCIDR(strings.TrimSpace(c.Tun.IPv6))
			if err != nil || ip == nil || ip.To16() == nil || ip.To4() != nil {
				return fmt.Errorf("tun.ipv6 must be an IPv6 address or CIDR, got %q", c.Tun.IPv6)
			}
		}
	}
	if c.Runtime.ConnectTimeoutMS < minConnectTimeoutMS || c.Runtime.ConnectTimeoutMS > maxConnectTimeoutMS {
		return fmt.Errorf(
			"runtime.connect_timeout_ms out of range [%d,%d]: %d",
			minConnectTimeoutMS,
			maxConnectTimeoutMS,
			c.Runtime.ConnectTimeoutMS,
		)
	}
	if c.Runtime.IdleTimeoutMS < minIdleTimeoutMS || c.Runtime.IdleTimeoutMS > maxIdleTimeoutMS {
		return fmt.Errorf(
			"runtime.idle_timeout_ms out of range [%d,%d]: %d",
			minIdleTimeoutMS,
			maxIdleTimeoutMS,
			c.Runtime.IdleTimeoutMS,
		)
	}
	if c.Runtime.TCPBuffer < minRuntimeBufferBytes || c.Runtime.TCPBuffer > maxRuntimeBufferBytes {
		return fmt.Errorf(
			"runtime.tcp_buffer out of range [%d,%d]: %d",
			minRuntimeBufferBytes,
			maxRuntimeBufferBytes,
			c.Runtime.TCPBuffer,
		)
	}
	if c.Runtime.UDPBuffer < minRuntimeBufferBytes || c.Runtime.UDPBuffer > maxRuntimeBufferBytes {
		return fmt.Errorf(
			"runtime.udp_buffer out of range [%d,%d]: %d",
			minRuntimeBufferBytes,
			maxRuntimeBufferBytes,
			c.Runtime.UDPBuffer,
		)
	}
	if c.Runtime.TCPDialConcurrency <= 0 || c.Runtime.TCPDialConcurrency > maxDialConcurrency {
		return fmt.Errorf(
			"runtime.tcp_dial_concurrency out of range [1,%d]: %d",
			maxDialConcurrency,
			c.Runtime.TCPDialConcurrency,
		)
	}
	if c.Runtime.UDPDialConcurrency <= 0 || c.Runtime.UDPDialConcurrency > maxDialConcurrency {
		return fmt.Errorf(
			"runtime.udp_dial_concurrency out of range [1,%d]: %d",
			maxDialConcurrency,
			c.Runtime.UDPDialConcurrency,
		)
	}
	if c.Runtime.DNSCacheSize <= 0 || c.Runtime.DNSCacheSize > maxDNSCacheEntries {
		return fmt.Errorf(
			"runtime.dns_cache_size out of range [1,%d]: %d",
			maxDNSCacheEntries,
			c.Runtime.DNSCacheSize,
		)
	}
	return nil
}

/* Returns the effective outbound connect timeout. */
func (c *Config) ConnectTimeout() time.Duration {
	return time.Duration(c.Runtime.ConnectTimeoutMS) * time.Millisecond
}

/* Returns the effective idle timeout for flow relays. */
func (c *Config) IdleTimeout() time.Duration {
	return time.Duration(c.Runtime.IdleTimeoutMS) * time.Millisecond
}

/* Returns the timeout budget used by DNS-over-TCP exchanges. */
func (c *Config) DNSExchangeTimeout() time.Duration {
	connectTimeout := c.ConnectTimeout()
	idleTimeout := c.IdleTimeout()
	if connectTimeout <= 0 {
		return idleTimeout
	}
	if idleTimeout > 0 && idleTimeout < connectTimeout {
		return idleTimeout
	}
	return connectTimeout
}

/* Returns the idle timeout used for generic UDP relay flows. */
func (c *Config) UDPIdleTimeout() time.Duration {
	idle := c.IdleTimeout()
	if idle <= 0 {
		idle = 30 * time.Second
	}
	return idle
}
