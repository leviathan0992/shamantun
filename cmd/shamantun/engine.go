package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	gstack "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

/* ----------------------------------------------------------------------------- */
/* Core engine */
/* ----------------------------------------------------------------------------- */

/* Wires TUN + gVisor stack + upstream dialer. */
type Engine struct {
	cfg    *Config
	dialer UpstreamDialer
	tunDev *TunDevice
	ns     *NetstackRuntime

	mu          sync.Mutex
	started     bool
	starting    bool
	startDone   chan struct{}
	startCancel context.CancelFunc
	stopping    bool
	rollbackTun *TunDevice
	stopOnce    sync.Once
	wg          sync.WaitGroup

	handlerSem          chan struct{}
	udpHandlerSem       chan struct{}
	tcpDialSem          chan struct{}
	tcpDialBackoffUntil int64
	udpDialSem          chan struct{}
	udpDialBackoffUntil int64
	flowSeq             uint64

	activeMu        sync.Mutex
	activeUpstreams map[io.Closer]struct{}
	activeLocals    map[io.Closer]struct{}
	dialCtxMu       sync.Mutex
	dialCtx         context.Context
	dialCancel      context.CancelFunc
	runCancel       context.CancelFunc
	warmupRunning   atomic.Bool

	dnsPoolMu sync.Mutex
	dnsPool   map[string][]net.Conn

	udpPoolMu sync.Mutex
	udpPool   map[string][]UDPSession

	logThrottleMu     sync.Mutex
	logThrottleStates map[string]logThrottleState

	dnsCacheMu sync.RWMutex
	dnsCache   map[string]dnsCacheEntry
}

type dnsCacheEntry struct {
	Response  []byte
	ExpiresAt time.Time
}

const (
	flowSummaryDurationThreshold = 30 * time.Second
	flowSummaryBytesThreshold    = 1 << 20 /* 1MB */
	udpSummaryPacketsThreshold   = 32
	defaultTCPDialConcurrency    = 64
	defaultUDPDialConcurrency    = 4
	defaultTCPHandlerConcurrency = 256
	defaultUDPHandlerConcurrency = 64
	defaultDNSCacheSize          = 1024
	tcpDialAcquireTimeout        = 300 * time.Millisecond
	udpDialAcquireTimeout        = 250 * time.Millisecond
	transientTCPDialBudgetCap    = 1200 * time.Millisecond
	transientTCPDialRetryDelay   = 120 * time.Millisecond
	tcpDialCooldownPollInterval  = 25 * time.Millisecond
	logThrottleInterval          = 5 * time.Second
	logThrottleStateTTL          = 30 * time.Second
	logThrottleStateMaxEntries   = 256
	dnsPoolPerTarget             = 8
	udpPoolMaxIdle               = 16
)

type LogLevel int32

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelSystem
)

var (
	relayBufPool    sync.Pool
	currentLogLevel atomic.Int32 /* LogLevel */
)

type logThrottleState struct {
	LastLogTime time.Time
	Suppressed  int
}

/* Sets the global log filter level. */
func SetLogLevel(level LogLevel) {
	currentLogLevel.Store(int32(level))
}

func logf(level LogLevel, format string, args ...any) {
	if LogLevel(currentLogLevel.Load()) <= level {
		log.Printf(format, args...)
	}
}

func shouldLogTCPSummary(stats bidirectionalRelayStats) bool {
	if stats.UploadErr != nil || stats.DownloadErr != nil {
		return true
	}
	return stats.Duration >= flowSummaryDurationThreshold ||
		stats.UploadBytes+stats.DownloadBytes >= flowSummaryBytesThreshold
}

func shouldLogUDPSummary(up, down udpPumpResult, duration time.Duration) bool {
	if up.Err != nil || down.Err != nil {
		return true
	}
	return duration >= flowSummaryDurationThreshold ||
		up.Packets+down.Packets >= udpSummaryPacketsThreshold
}

/* Reports whether relay packet deadlines should be refreshed. */
func shouldRefreshPacketDeadlines(packetCount int, lastUpdate time.Time, now time.Time) bool {
	return packetCount >= 32 || now.Sub(lastUpdate) > 500*time.Millisecond
}

/* Builds a cache key from the target and the DNS payload with the transaction ID stripped. */
func dnsCacheKey(target string, payload []byte) string {
	if len(payload) <= 2 {
		return target + "|"
	}
	return target + "|" + string(payload[2:])
}

func dnsQuestionIdentity(payload []byte) string {
	offset, ok := dnsQuestionSectionEnd(payload)
	if !ok {
		return ""
	}
	buf := make([]byte, 0, 2+offset-12)
	buf = append(buf, payload[4:6]...)
	buf = append(buf, payload[12:offset]...)
	return string(buf)
}

func dnsQuestionSectionEnd(payload []byte) (int, bool) {
	if len(payload) < 12 {
		return 0, false
	}
	qdcount := int(binary.BigEndian.Uint16(payload[4:6]))
	offset := 12
	for i := 0; i < qdcount; i++ {
		for offset < len(payload) {
			b := payload[offset]
			offset++
			if b == 0 {
				break
			}
			if b&0xC0 == 0xC0 {
				if offset >= len(payload) {
					return 0, false
				}
				offset++
				break
			}
			offset += int(b)
			if offset > len(payload) {
				return 0, false
			}
		}
		if offset+4 > len(payload) {
			return 0, false
		}
		offset += 4
	}
	return offset, true
}

/* Builds the runtime engine from user config. */
func NewEngine(cfg *Config) (*Engine, error) {
	if cfg == nil {
		return nil, errors.New("nil config")
	}
	dialer, err := NewUpstreamDialer(cfg.Mode, cfg.Upstream, cfg.ConnectTimeout(), cfg.Runtime.UDPBuffer)
	if err != nil {
		return nil, err
	}
	tcpConc := cfg.Runtime.TCPDialConcurrency
	if tcpConc <= 0 {
		tcpConc = defaultTCPDialConcurrency
	}
	udpConc := cfg.Runtime.UDPDialConcurrency
	if udpConc <= 0 {
		udpConc = defaultUDPDialConcurrency
	}
	dnsCacheSize := cfg.Runtime.DNSCacheSize
	if dnsCacheSize <= 0 {
		dnsCacheSize = defaultDNSCacheSize
	}
	dialCtx, dialCancel := context.WithCancel(context.Background())
	return &Engine{
		cfg:               cfg,
		dialer:            dialer,
		handlerSem:        make(chan struct{}, defaultTCPHandlerConcurrency),
		udpHandlerSem:     make(chan struct{}, defaultUDPHandlerConcurrency),
		tcpDialSem:        make(chan struct{}, tcpConc),
		udpDialSem:        make(chan struct{}, udpConc),
		activeUpstreams:   make(map[io.Closer]struct{}),
		activeLocals:      make(map[io.Closer]struct{}),
		dnsPool:           make(map[string][]net.Conn),
		dnsCache:          make(map[string]dnsCacheEntry, dnsCacheSize),
		udpPool:           make(map[string][]UDPSession),
		logThrottleStates: make(map[string]logThrottleState),
		dialCtx:           dialCtx,
		dialCancel:        dialCancel,
	}, nil
}

/* Initializes TUN and netstack, then registers flow handlers. */
func (e *Engine) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if e == nil {
		return errors.New("nil engine")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	switch {
	case e.starting:
		e.mu.Unlock()
		return errors.New("engine start already in progress")
	case e.rollbackTun != nil:
		e.mu.Unlock()
		return errors.New("engine cleanup in progress")
	case e.stopping:
		e.mu.Unlock()
		return errors.New("engine already stopped")
	case e.started:
		e.mu.Unlock()
		return errors.New("engine already started")
	}
	e.starting = true
	e.startDone = make(chan struct{})
	startDone := e.startDone
	startCtx, startCancel := context.WithCancel(ctx)
	e.startCancel = startCancel
	e.mu.Unlock()
	if e.cfg == nil {
		e.mu.Lock()
		e.starting = false
		if e.startDone == startDone {
			e.startDone = nil
		}
		e.startCancel = nil
		e.mu.Unlock()
		startCancel()
		close(startDone)
		return errors.New("nil config")
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	started := false
	defer func() {
		if started {
			return
		}
		runCancel()
		e.mu.Lock()
		e.starting = false
		if e.startDone == startDone {
			e.startDone = nil
		}
		e.startCancel = nil
		e.mu.Unlock()
		startCancel()
		close(startDone)
	}()

	tunDev, err := OpenTUN(e.cfg.Tun.Name, e.cfg.Tun.MTU)
	if err != nil {
		return err
	}
	if err := startCtx.Err(); err != nil {
		_ = e.closeStartupTun(startCtx, tunDev)
		return err
	}

	logf(LogLevelSystem, "[SYS] [TUN] tun opened: name=%s mtu=%d", tunDev.Name, tunDev.MTU)
	if e.cfg.Runtime.EnableUDP {
		logf(LogLevelDebug,
			"[DEBUG] [UDP] runtime policy: udp_forwarding=true udp_dial_concurrency=%d tcp_dial_concurrency=%d tcp_handler_concurrency=%d udp_handler_concurrency=%d",
			cap(e.udpDialSem),
			cap(e.tcpDialSem),
			cap(e.handlerSem),
			cap(e.udpHandlerSem),
		)
	}

	ns, err := NewNetstack(tunDev.LinkEndpoint, NetstackOptions{
		EnableUDP: e.cfg.Runtime.EnableUDP,
		TCPHandler: func(id gstack.TransportEndpointID, conn net.Conn) {
			if !e.acquireHandlerSlot() {
				logf(LogLevelSystem, "[SYS] [TCP] handler concurrency limit reached (%d); dropping connection from %s", cap(e.handlerSem), id.RemoteAddress)
				_ = conn.Close()
				return
			}
			defer e.releaseHandlerSlot()
			if !e.beginWorker() {
				_ = conn.Close()
				return
			}
			defer e.wg.Done()
			e.handleTCP(runCtx, id, conn)
		},
		UDPHandler: func(id gstack.TransportEndpointID, conn net.PacketConn) {
			if !e.acquireUDPHandlerSlot() {
				logf(LogLevelSystem, "[SYS] [UDP] handler concurrency limit reached (%d); dropping flow from %s", cap(e.udpHandlerSem), id.RemoteAddress)
				_ = conn.Close()
				return
			}
			defer e.releaseUDPHandlerSlot()
			if !e.beginWorker() {
				_ = conn.Close()
				return
			}
			defer e.wg.Done()
			e.handleUDP(runCtx, id, conn)
		},
	})
	if err != nil {
		_ = e.closeStartupTun(startCtx, tunDev)
		return err
	}
	if err := startCtx.Err(); err != nil {
		if ns != nil && ns.Stack != nil {
			ns.Stack.Close()
		}
		_ = e.closeStartupTun(startCtx, tunDev)
		return err
	}

	e.mu.Lock()
	if e.stopping {
		e.mu.Unlock()
		if ns != nil && ns.Stack != nil {
			ns.Stack.Close()
		}
		_ = e.closeStartupTun(startCtx, tunDev)
		return errors.New("engine stopped during startup")
	}
	e.tunDev = tunDev
	e.ns = ns
	e.runCancel = runCancel
	e.started = true
	e.starting = false
	if e.startDone == startDone {
		e.startDone = nil
	}
	e.startCancel = nil
	e.mu.Unlock()
	startCancel()
	close(startDone)
	started = true

	return nil
}

/* Closes ingress/egress paths and waits for in-flight workers to exit. */
func (e *Engine) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if e == nil {
		return errors.New("nil engine")
	}
	e.mu.Lock()
	rollbackTun := e.rollbackTun
	starting := e.starting
	startDone := e.startDone
	startCancel := e.startCancel
	neverStarted := !e.started && !starting && !e.stopping && e.tunDev == nil && e.ns == nil && rollbackTun == nil
	e.mu.Unlock()
	if starting && startDone != nil {
		e.mu.Lock()
		e.stopping = true
		e.mu.Unlock()
		if startCancel != nil {
			startCancel()
		}
		select {
		case <-startDone:
			return e.Stop(ctx)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if neverStarted {
		return nil
	}
	if rollbackTun != nil {
		err := rollbackTun.CloseContext(ctx)
		if !isContextCancelLike(err) {
			e.clearRollbackTun(rollbackTun)
		}
		return err
	}

	var retErr error
	e.stopOnce.Do(func() {
		e.mu.Lock()
		e.stopping = true
		runCancel := e.runCancel
		e.mu.Unlock()
		if runCancel != nil {
			runCancel()
		}
		e.resetDialContext()
		e.closeIdleDNSPool()
		e.closeIdleUDPPool()
		e.closeActiveLocals()
		e.closeActiveUpstreams()

		if e.ns != nil && e.ns.Stack != nil {
			e.ns.Stack.Close()
		}
	})

	e.mu.Lock()
	tunDev := e.tunDev
	e.mu.Unlock()
	if tunDev != nil {
		if err := tunDev.CloseContext(ctx); err != nil {
			if retErr != nil {
				retErr = errors.Join(retErr, err)
			} else {
				retErr = err
			}
			if ctx.Err() != nil {
				return retErr
			}
		}
	}

	waitDone := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
	case <-ctx.Done():
		if retErr != nil {
			retErr = errors.Join(retErr, ctx.Err())
		} else {
			retErr = ctx.Err()
		}
	}

	return retErr
}

func (e *Engine) closeStartupTun(ctx context.Context, tunDev *TunDevice) error {
	if e == nil || tunDev == nil {
		return nil
	}
	e.mu.Lock()
	e.rollbackTun = tunDev
	e.mu.Unlock()

	err := tunDev.CloseContext(ctx)
	if isContextCancelLike(err) {
		/* The caller's context expired before the TUN device closed. Kick cleanup into a
		   background goroutine so the engine is not permanently wedged in "cleanup in
		   progress". Note: if the kernel blocks file.Close() (e.g. TUN driver bug),
		   this goroutine will hang and rollbackTun will remain set until the process exits.
		   The TUN file is opened in blocking mode so no deadline shortcut is available. */
		go func(dev *TunDevice) {
			_ = dev.CloseContext(context.Background())
			e.clearRollbackTun(dev)
		}(tunDev)
		return err
	}
	e.clearRollbackTun(tunDev)
	return err
}

func (e *Engine) clearRollbackTun(tunDev *TunDevice) {
	if e == nil || tunDev == nil {
		return
	}
	e.mu.Lock()
	if e.rollbackTun == tunDev {
		e.rollbackTun = nil
	}
	e.mu.Unlock()
}

func isContextCancelLike(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

/* Guards worker scheduling during shutdown. */
func (e *Engine) beginWorker() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopping {
		return false
	}
	e.wg.Add(1)
	return true
}

/* Claims a handler concurrency slot without blocking; returns false if all slots are in use. */
func (e *Engine) acquireHandlerSlot() bool {
	select {
	case e.handlerSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (e *Engine) releaseHandlerSlot() {
	select {
	case <-e.handlerSem:
	default:
	}
}

func (e *Engine) acquireUDPHandlerSlot() bool {
	select {
	case e.udpHandlerSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (e *Engine) releaseUDPHandlerSlot() {
	select {
	case <-e.udpHandlerSem:
	default:
	}
}

func (e *Engine) activateLocal(closer io.Closer) bool {
	if closer == nil {
		return false
	}
	e.mu.Lock()
	stopping := e.stopping
	e.mu.Unlock()
	if stopping {
		_ = closer.Close()
		return false
	}
	e.registerActiveLocal(closer)
	e.mu.Lock()
	stopping = e.stopping
	e.mu.Unlock()
	if stopping {
		e.unregisterActiveLocal(closer)
		_ = closer.Close()
		return false
	}
	return true
}

func (e *Engine) activateUpstream(closer io.Closer) bool {
	if closer == nil {
		return false
	}
	e.mu.Lock()
	stopping := e.stopping
	e.mu.Unlock()
	if stopping {
		_ = closer.Close()
		return false
	}
	e.registerActiveUpstream(closer)
	e.mu.Lock()
	stopping = e.stopping
	e.mu.Unlock()
	if stopping {
		e.unregisterActiveUpstream(closer)
		_ = closer.Close()
		return false
	}
	return true
}

/* Bridges one TCP flow between local netstack and upstream proxy. */
func (e *Engine) handleTCP(ctx context.Context, id gstack.TransportEndpointID, localConn net.Conn) {
	defer localConn.Close()
	if !e.activateLocal(localConn) {
		return
	}
	defer e.unregisterActiveLocal(localConn)

	flowID := e.nextFlowID("tcp")
	target := tcpDestination(id)
	source := tcpSource(id)
	if isUpstreamLoopTarget(target, e.cfg.Upstream.Addr) {
		logf(LogLevelWarn, "[WARN] [TCP] [%s] dropped: detected upstream route loop %s -> %s | hint: check auto-route upstream bypass", flowID, source, target)
		return
	}
	upConn, err := e.dialTCPUpstream(ctx, target, e.transientTCPDialBudget())
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			logf(LogLevelDebug, "[DEBUG] [TCP] %s -> %s (%s) id=%s | dial aborted during shutdown", source, target, e.dialer.Mode(), flowID)
		} else if errors.Is(err, errTCPDialCooldown) {
			logf(LogLevelDebug, "[DEBUG] [TCP] %s -> %s (%s) id=%s | dropped: dial cooldown", source, target, e.dialer.Mode(), flowID)
		} else if errors.Is(err, errTCPDialThrottle) {
			logf(LogLevelDebug, "[DEBUG] [TCP] %s -> %s (%s) id=%s | dropped: dial throttle", source, target, e.dialer.Mode(), flowID)
		} else {
			e.logTCPDialFailure(flowID, e.dialer.Mode(), source, target, err)
		}
		return
	}
	if !e.activateUpstream(upConn) {
		return
	}
	defer e.unregisterActiveUpstream(upConn)
	logf(LogLevelDebug, "[DEBUG] [TCP] %s -> %s (%s) id=%s | relay start", source, target, e.dialer.Mode(), flowID)
	stats := relayBidirectionalWithStatsContext(ctx, localConn, upConn, e.cfg.Runtime.TCPBuffer, e.cfg.IdleTimeout(), &relayBufPool)
	if shouldLogTCPSummary(stats) {
		logf(LogLevelInfo,
			"[INFO] [TCP] %s -> %s (%s) id=%s | %s | up %s / down %s | %s",
			source, target, e.dialer.Mode(), flowID,
			formatDuration(stats.Duration),
			formatBytes(stats.UploadBytes), formatBytes(stats.DownloadBytes),
			combineResults(stats.UploadErr, stats.DownloadErr),
		)
	}
}

/* Bridges one UDP flow when the selected upstream supports it. */
func (e *Engine) handleUDP(ctx context.Context, id gstack.TransportEndpointID, localConn net.PacketConn) {
	defer localConn.Close()
	if !e.activateLocal(localConn) {
		return
	}
	defer e.unregisterActiveLocal(localConn)

	flowID := e.nextFlowID("udp")
	target := udpDestination(id)
	targetStr := udpDestinationString(id)
	sourceStr := udpSourceString(id)
	if target == nil || len(target.IP) == 0 || target.Port <= 0 {
		logf(LogLevelWarn, "[WARN] [UDP] [%s] dropped: invalid target | mode=%s %s -> %s", flowID, e.dialer.Mode(), sourceStr, targetStr)
		return
	}
	if shouldRelayDNSOverTCP(target) {
		e.handleDNSOverTCP(ctx, flowID, sourceStr, target, targetStr, localConn)
		return
	}
	if !e.cfg.Runtime.EnableUDP {
		logf(LogLevelDebug, "[DEBUG] [UDP] [%s] dropped: udp disabled | %s -> %s", flowID, sourceStr, targetStr)
		return
	}
	poolKey := udpSessionPoolKey(sourceStr, targetStr)
	if !e.dialer.SupportsUDP() || e.cfg.Mode == ModeHTTPS {
		logf(LogLevelInfo, "[INFO] [UDP] [%s] dropped: policy restriction | mode=%s %s -> %s", flowID, e.dialer.Mode(), sourceStr, targetStr)
		return
	}

	session := e.takeIdleUDPSession(poolKey)
	if session == nil {
		if e.isUDPDialCoolingDown() {
			logf(LogLevelDebug, "[DEBUG] [UDP] %s -> %s (%s) id=%s | dropped: dial cooldown", sourceStr, targetStr, e.dialer.Mode(), flowID)
			return
		}
		if !e.acquireUDPDialSlot(ctx, udpDialAcquireTimeout) {
			logf(LogLevelDebug, "[DEBUG] [UDP] %s -> %s (%s) id=%s | dropped: dial throttle", sourceStr, targetStr, e.dialer.Mode(), flowID)
			return
		}

		dialCtx, cancelDial := e.bindDialContext(ctx)
		var err error
		session, err = e.dialer.DialUDP(dialCtx)
		cancelDial()
		e.releaseUDPDialSlot()
		if err != nil {
			if isAddrNotAvailableError(err) {
				e.markUDPDialBackoff(500 * time.Millisecond)
			}
			logf(LogLevelError, "[ERROR] [UDP] %s -> %s (%s) id=%s | dial failed | err=%v", sourceStr, targetStr, e.dialer.Mode(), flowID, err)
			return
		}
		if !e.activateUpstream(session) {
			return
		}
	} else if !e.activateUpstream(session) {
		return
	}
	reusableSession := false
	defer func() {
		e.releaseUDPSession(poolKey, session, reusableSession)
	}()

	logf(LogLevelDebug, "[DEBUG] [UDP] %s -> %s (%s) id=%s | relay start", sourceStr, targetStr, e.dialer.Mode(), flowID)

	idleTimeout := e.cfg.UDPIdleTimeout()
	resultCh := make(chan udpPumpResult, 2)
	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			_ = session.SetDeadline(time.Now())
			_ = localConn.Close()
		})
	}

	udpBufSize := e.cfg.Runtime.UDPBuffer
	go func() {
		res := udpPumpResult{Direction: "local_to_upstream"}
		defer func() { resultCh <- res }()
		buf := getPooledBuf(&relayBufPool, udpBufSize)
		defer putPooledBuf(&relayBufPool, buf)
		lastDeadlineUpdate := time.Now()
		var packetCount int
		if idleTimeout > 0 {
			now := time.Now()
			_ = localConn.SetReadDeadline(now.Add(idleTimeout))
			_ = session.SetWriteDeadline(now.Add(idleTimeout))
			lastDeadlineUpdate = now
		}

		for {
			if ctx.Err() != nil {
				res.Err = ctx.Err()
				return
			}
			if idleTimeout > 0 {
				packetCount++
				now := time.Now()
				if shouldRefreshPacketDeadlines(packetCount, lastDeadlineUpdate, now) {
					_ = localConn.SetReadDeadline(now.Add(idleTimeout))
					_ = session.SetWriteDeadline(now.Add(idleTimeout))
					lastDeadlineUpdate = now
					packetCount = 0
				}
			}
			n, _, err := localConn.ReadFrom(buf)
			if n > 0 {
				res.Bytes += int64(n)
				res.Packets++
				if idleTimeout > 0 {
					_ = session.SetWriteDeadline(time.Now().Add(idleTimeout))
				}
				if wErr := session.WriteTo(buf[:n], target); wErr != nil {
					logf(LogLevelError, "[ERROR] [UDP] %s -> %s (%s) id=%s | write upstream failed | err=%v", sourceStr, targetStr, e.dialer.Mode(), flowID, wErr)
					res.Err = wErr
					return
				}
			}
			if err != nil {
				if isTimeoutError(err) {
					logf(LogLevelInfo, "[INFO] [UDP] %s -> %s (%s) id=%s | idle timeout (local->upstream)", sourceStr, targetStr, e.dialer.Mode(), flowID)
					res.Err = err
					return
				}
				if !isClosedConnError(err) { /* ignore expected closure */
					logf(LogLevelError, "[ERROR] [UDP] %s -> %s (%s) id=%s | read local failed | err=%v", sourceStr, targetStr, e.dialer.Mode(), flowID, err)
				}
				res.Err = err
				return
			}
		}
	}()

	go func() {
		res := udpPumpResult{Direction: "upstream_to_local"}
		defer func() { resultCh <- res }()
		buf := getPooledBuf(&relayBufPool, udpBufSize)
		defer putPooledBuf(&relayBufPool, buf)
		lastDeadlineUpdate := time.Now()
		var packetCount int
		if idleTimeout > 0 {
			now := time.Now()
			_ = session.SetReadDeadline(now.Add(idleTimeout))
			_ = localConn.SetWriteDeadline(now.Add(idleTimeout))
			lastDeadlineUpdate = now
		}

		for {
			if ctx.Err() != nil {
				res.Err = ctx.Err()
				return
			}
			if idleTimeout > 0 {
				packetCount++
				now := time.Now()
				if shouldRefreshPacketDeadlines(packetCount, lastDeadlineUpdate, now) {
					_ = session.SetReadDeadline(now.Add(idleTimeout))
					_ = localConn.SetWriteDeadline(now.Add(idleTimeout))
					lastDeadlineUpdate = now
					packetCount = 0
				}
			}
			n, src, err := session.ReadFrom(buf)
			if n > 0 {
				if !sameUDPEndpoint(src, target) {
					logf(LogLevelDebug, "[DEBUG] [UDP] %s -> %s (%s) id=%s | dropped: mismatched upstream source=%v", sourceStr, targetStr, e.dialer.Mode(), flowID, src)
					continue
				}
				res.Bytes += int64(n)
				res.Packets++
				if idleTimeout > 0 {
					_ = localConn.SetWriteDeadline(time.Now().Add(idleTimeout))
				}
				if _, wErr := writeBackToPacketConn(localConn, buf[:n]); wErr != nil {
					if isBenignLocalPacketWriteError(wErr) {
						logf(LogLevelInfo, "[INFO] [UDP] %s -> %s (%s) id=%s | local receiver closed | err=%v", sourceStr, targetStr, e.dialer.Mode(), flowID, wErr)
					} else {
						logf(LogLevelError, "[ERROR] [UDP] %s -> %s (%s) id=%s | write local failed | err=%v", sourceStr, targetStr, e.dialer.Mode(), flowID, wErr)
					}
					res.Err = wErr
					res.LocalWriteErr = true
					return
				}
			}
			if err != nil {
				if isTimeoutError(err) {
					logf(LogLevelInfo, "[INFO] [UDP] %s -> %s (%s) id=%s | idle timeout (upstream->local)", sourceStr, targetStr, e.dialer.Mode(), flowID)
					res.Err = err
					return
				}
				if !isClosedConnError(err) {
					logf(LogLevelError, "[ERROR] [UDP] %s -> %s (%s) id=%s | read upstream failed | err=%v", sourceStr, targetStr, e.dialer.Mode(), flowID, err)
				}
				res.Err = err
				return
			}
		}
	}()

	start := time.Now()
	completed := 0
	localToUpstream := udpPumpResult{Direction: "local_to_upstream"}
	upstreamToLocal := udpPumpResult{Direction: "upstream_to_local"}
	select {
	case <-ctx.Done():
	case res := <-resultCh:
		if res.Direction == "local_to_upstream" {
			localToUpstream = res
		} else {
			upstreamToLocal = res
		}
		completed = 1
	}
	closeAll()
	for completed < 2 {
		select {
		case res := <-resultCh:
			if res.Direction == "local_to_upstream" {
				localToUpstream = res
			} else {
				upstreamToLocal = res
			}
			completed++
		case <-time.After(2 * time.Second):
			duration := time.Since(start)
			if shouldLogUDPSummary(localToUpstream, upstreamToLocal, duration) {
				logf(LogLevelInfo,
					"[INFO] [UDP] %s -> %s (%s) id=%s | %s | up %s (%dp) / down %s (%dp) | %s | drain=timeout",
					sourceStr, targetStr, e.dialer.Mode(), flowID,
					formatDuration(duration),
					formatBytes(localToUpstream.Bytes), localToUpstream.Packets,
					formatBytes(upstreamToLocal.Bytes), upstreamToLocal.Packets,
					combineUDPResults(localToUpstream, upstreamToLocal),
				)
			}
			return
		}
	}
	duration := time.Since(start)
	/* Normalizes benign local write errors before deciding whether to reuse the UDP session. */
	u2lErrForReuse := upstreamToLocal.Err
	if upstreamToLocal.LocalWriteErr {
		u2lErrForReuse = nil
	}
	reusableSession = e.shouldReuseUDPSession(ctx, localToUpstream.Err, u2lErrForReuse)
	if reusableSession && upstreamToLocal.Bytes == 0 && u2lErrForReuse != nil {
		/* Rejects session reuse when upstream returned an error without sending any bytes. */
		reusableSession = false
	}
	if shouldLogUDPSummary(localToUpstream, upstreamToLocal, duration) {
		logf(LogLevelInfo,
			"[INFO] [UDP] %s -> %s (%s) id=%s | %s | up %s (%dp) / down %s (%dp) | %s",
			sourceStr, targetStr, e.dialer.Mode(), flowID,
			formatDuration(duration),
			formatBytes(localToUpstream.Bytes), localToUpstream.Packets,
			formatBytes(upstreamToLocal.Bytes), upstreamToLocal.Packets,
			combineUDPResults(localToUpstream, upstreamToLocal),
		)
	}
}

/* Relays DNS over a transient proxied TCP connection instead of UDP associate. */
func (e *Engine) handleDNSOverTCP(ctx context.Context, flowID, sourceStr string, target *net.UDPAddr, targetStr string, localConn net.PacketConn) {
	logf(LogLevelDebug, "[DEBUG] [DNS] %s -> %s (%s) id=%s | relay start (upstream=tcp)", sourceStr, targetStr, e.dialer.Mode(), flowID)

	idleTimeout := e.cfg.DNSExchangeTimeout()
	buf := getPooledBuf(&relayBufPool, e.cfg.Runtime.UDPBuffer)
	defer putPooledBuf(&relayBufPool, buf)
	upstream := udpPumpResult{Direction: "local_to_upstream"}
	downstream := udpPumpResult{Direction: "upstream_to_local"}
	start := time.Now()
	hadSuccess := false

	for {
		if ctx.Err() != nil {
			if upstream.Err == nil {
				upstream.Err = ctx.Err()
			}
			if downstream.Err == nil {
				downstream.Err = ctx.Err()
			}
			break
		}

		_ = localConn.SetReadDeadline(time.Now().Add(idleTimeout))
		n, _, err := localConn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if isTimeoutError(err) {
				if hadSuccess {
					upstream.Err = nil
					downstream.Err = nil
					break
				}
				upstream.Err = err
				downstream.Err = err
				break
			}
			if !isClosedConnError(err) {
				logf(LogLevelError, "[ERROR] [DNS] %s -> %s (%s) id=%s | read local failed | err=%v", sourceStr, targetStr, e.dialer.Mode(), flowID, err)
			}
			upstream.Err = err
			downstream.Err = err
			break
		}
		if n == 0 {
			continue
		}

		payload := buf[:n]
		upstream.Bytes += int64(len(payload))
		upstream.Packets++

		if cachedResp := e.getDNSCache(targetStr, payload); cachedResp != nil {
			downstream.Bytes += int64(len(cachedResp))
			downstream.Packets++
			_ = localConn.SetWriteDeadline(time.Now().Add(idleTimeout))
			if _, err := writeBackToPacketConn(localConn, cachedResp); err != nil {
				downstream.Err = err
				if isBenignLocalPacketWriteError(err) {
					logf(LogLevelInfo, "[INFO] [DNS] %s -> %s (%s) id=%s | local receiver closed (cached) | err=%v", sourceStr, targetStr, e.dialer.Mode(), flowID, err)
				} else {
					logf(LogLevelError, "[ERROR] [DNS] %s -> %s (%s) id=%s | write cached local failed | err=%v", sourceStr, targetStr, e.dialer.Mode(), flowID, err)
				}
				break
			}
			hadSuccess = true
			upstream.Err = nil
			downstream.Err = nil
			continue
		}

		response, releaseResponse, dnsErr := e.exchangeDNSOverTCP(ctx, targetStr, payload, idleTimeout)
		if dnsErr != nil {
			if upstream.Err == nil {
				upstream.Err = dnsErr
			}
			if downstream.Err == nil {
				downstream.Err = dnsErr
			}
			e.logDNSExchangeFailure(flowID, e.dialer.Mode(), sourceStr, targetStr, dnsErr)
			break
		}

		e.putDNSCache(targetStr, payload, response)

		downstream.Bytes += int64(len(response))
		downstream.Packets++
		_ = localConn.SetWriteDeadline(time.Now().Add(idleTimeout))
		if _, err := writeBackToPacketConn(localConn, response); err != nil {
			releaseResponse()
			downstream.Err = err
			if isBenignLocalPacketWriteError(err) {
				logf(LogLevelInfo, "[INFO] [DNS] %s -> %s (%s) id=%s | local receiver closed | err=%v", sourceStr, targetStr, e.dialer.Mode(), flowID, err)
			} else {
				logf(LogLevelError, "[ERROR] [DNS] %s -> %s (%s) id=%s | write local failed | err=%v", sourceStr, targetStr, e.dialer.Mode(), flowID, err)
			}
			break
		}
		releaseResponse()
		hadSuccess = true
		upstream.Err = nil
		downstream.Err = nil
		continue
	}

	duration := time.Since(start)
	if shouldLogUDPSummary(upstream, downstream, duration) {
		summaryUpErr, summaryDownErr := dnsSummaryErrors(upstream.Err, downstream.Err)
		logf(LogLevelInfo,
			"[INFO] [DNS] %s -> %s (%s) id=%s | %s | up %s (%dp) / down %s (%dp) | %s",
			sourceStr, targetStr, e.dialer.Mode(), flowID,
			formatDuration(duration),
			formatBytes(upstream.Bytes), upstream.Packets,
			formatBytes(downstream.Bytes), downstream.Packets,
			combineResults(summaryUpErr, summaryDownErr),
		)
	}
}

/* Performs one DNS-over-TCP request-response exchange through the configured upstream proxy. */
func (e *Engine) exchangeDNSOverTCP(ctx context.Context, targetAddr string, payload []byte, timeout time.Duration) ([]byte, func(), error) {
	var lastErr error
	forceFreshDial := false
	for attempt := 0; attempt < 2; attempt++ {
		var (
			upConn net.Conn
			pooled bool
			err    error
		)
		if forceFreshDial {
			upConn, err = e.dialTCPUpstream(ctx, targetAddr, e.transientTCPDialBudget())
			if err == nil && !e.activateUpstream(upConn) {
				err = context.Canceled
			}
		} else {
			upConn, pooled, err = e.acquireDNSConn(ctx, targetAddr, e.transientTCPDialBudget())
		}
		if err != nil {
			if attempt == 0 && isTransientUpstreamDialError(err) {
				lastErr = err
				continue
			}
			return nil, func() {}, err
		}
		reuseConn := false /* connection persists in pool if exchange succeeds */

		response, releaseResponse, err := func() ([]byte, func(), error) {
			defer func() {
				if reuseConn {
					e.releaseDNSConn(targetAddr, upConn)
					return
				}
				e.discardDNSConn(upConn)
			}()

			if timeout > 0 {
				if err := upConn.SetDeadline(time.Now().Add(timeout)); err != nil {
					return nil, func() {}, err
				}
			}

			frame := getPooledBuf(&relayBufPool, 2+len(payload))
			frame = frame[:2+len(payload)]
			defer putPooledBuf(&relayBufPool, frame)
			binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
			copy(frame[2:], payload)
			if err := writeAll(upConn, frame); err != nil {
				return nil, func() {}, err
			}

			var lengthBuf [2]byte
			if _, err := io.ReadFull(upConn, lengthBuf[:]); err != nil {
				return nil, func() {}, err
			}
			size := int(binary.BigEndian.Uint16(lengthBuf[:]))
			if size == 0 {
				return nil, func() {}, errors.New("empty dns tcp response")
			}
			response := getPooledBuf(&relayBufPool, size)
			response = response[:size]
			if _, err := io.ReadFull(upConn, response); err != nil {
				putPooledBuf(&relayBufPool, response)
				return nil, func() {}, err
			}
			reuseConn = true
			return response, func() { putPooledBuf(&relayBufPool, response) }, nil
		}()
		if err == nil {
			return response, releaseResponse, nil
		}
		lastErr = err
		if pooled {
			forceFreshDial = true
		}
		if attempt == 0 && (pooled || isRetryableDNSExchangeError(err)) {
			continue
		}
		return nil, func() {}, err
	}
	return nil, func() {}, lastErr
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return false
}

func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "closed pipe")
}

/* Reports whether the error is a benign local packet write failure. */
func isBenignLocalPacketWriteError(err error) bool {
	if err == nil {
		return false
	}
	var sysErr syscall.Errno
	if errors.As(err, &sysErr) {
		return sysErr == syscall.ECONNREFUSED
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection was refused") ||
		strings.Contains(msg, "port unreachable")
}

func isRetryableDNSExchangeError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "reset by peer") ||
		strings.Contains(msg, "use of closed network connection")
}

func (e *Engine) logDNSExchangeFailure(flowID, mode, source, target string, err error) {
	if err == nil || (!isRetryableDNSExchangeError(err) && !errors.Is(err, errTCPDialCooldown) && !isTransientUpstreamDialError(err)) {
		logf(LogLevelError, "[ERROR] [DNS] %s -> %s (%s) id=%s | exchange failed | err=%v", source, target, mode, flowID, err)
		return
	}
	/* Groups failures by mode, target, and error class to prevent log flooding. */
	key := mode + "|dns|" + target + "|" + dnsFailureClass(err)
	now := time.Now()

	e.logThrottleMu.Lock()
	if e.logThrottleStates == nil {
		e.logThrottleStates = make(map[string]logThrottleState)
	}
	if len(e.logThrottleStates) >= logThrottleStateMaxEntries {
		e.pruneLogThrottleStatesLocked(now)
	}
	if _, ok := e.logThrottleStates[key]; !ok && len(e.logThrottleStates) >= logThrottleStateMaxEntries {
		e.logThrottleMu.Unlock()
		logf(LogLevelError, "[ERROR] [DNS] %s -> %s (%s) id=%s | exchange failed | err=%v", source, target, mode, flowID, err)
		return
	}
	state := e.logThrottleStates[key]
	if !state.LastLogTime.IsZero() && now.Sub(state.LastLogTime) < logThrottleInterval {
		state.Suppressed++
		e.logThrottleStates[key] = state
		e.logThrottleMu.Unlock()
		return
	}
	repeats := state.Suppressed
	state.LastLogTime = now
	state.Suppressed = 0
	e.logThrottleStates[key] = state
	e.logThrottleMu.Unlock()

	if repeats > 0 {
		logf(LogLevelError, "[ERROR] [DNS] %s -> %s (%s) id=%s | exchange failed | err=%v | repeats=%d", source, target, mode, flowID, err, repeats)
		return
	}
	logf(LogLevelError, "[ERROR] [DNS] %s -> %s (%s) id=%s | exchange failed | err=%v", source, target, mode, flowID, err)
}

func dnsFailureClass(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case errors.Is(err, errTCPDialCooldown):
		return "cooldown"
	case isAddrNotAvailableError(err):
		return "eaddrnotavail"
	case isTransientUpstreamDialError(err):
		return "transient"
	case isTimeoutError(err):
		return "timeout"
	case isRetryableDNSExchangeError(err):
		return "retryable"
	default:
		return "other"
	}
}

func writeBackToPacketConn(conn net.PacketConn, payload []byte) (int, error) {
	if writer, ok := conn.(interface{ Write([]byte) (int, error) }); ok {
		return writer.Write(payload)
	}
	return 0, fmt.Errorf("packet conn %T does not support connected writes", conn)
}

/* Checks whether the target port matches a known DNS port. */
func shouldRelayDNSOverTCP(target *net.UDPAddr) bool {
	return target != nil && target.Port == 53
}

func isUpstreamLoopTarget(target, upstream string) bool {
	tHost, tPort, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil {
		return false
	}
	uHost, uPort, err := net.SplitHostPort(strings.TrimSpace(upstream))
	if err != nil {
		return false
	}
	if tPort != uPort {
		return false
	}

	tIP := net.ParseIP(tHost)
	uIP := net.ParseIP(uHost)
	if tIP != nil && uIP != nil {
		return tIP.Equal(uIP)
	}
	return strings.EqualFold(strings.TrimSpace(tHost), strings.TrimSpace(uHost))
}

type udpPumpResult struct {
	Direction     string
	Bytes         int64
	Packets       int64
	Err           error
	LocalWriteErr bool /* true when Err came from writing back to the local TUN socket (not from reading upstream) */
}

type relayCopyResult struct {
	Bytes int64
	Err   error
}

type bidirectionalRelayStats struct {
	UploadBytes   int64
	DownloadBytes int64
	UploadErr     error
	DownloadErr   error
	Duration      time.Duration
}

/* Copies bytes both ways and enforces per-direction idle timeout. */
func relayBidirectional(left, right net.Conn, bufSize int, idleTimeout time.Duration) {
	_ = relayBidirectionalWithStatsContext(context.Background(), left, right, bufSize, idleTimeout, &relayBufPool)
}

func relayBidirectionalWithStatsContext(ctx context.Context, left, right net.Conn, bufSize int, idleTimeout time.Duration, pool *sync.Pool) bidirectionalRelayStats {
	start := time.Now()
	if bufSize <= 0 {
		bufSize = 64 * 1024
	}

	var wg sync.WaitGroup
	wg.Add(2)
	uploadCh := make(chan relayCopyResult, 1)
	downloadCh := make(chan relayCopyResult, 1)
	var interruptOnce sync.Once
	interruptRelay := func() {
		interruptOnce.Do(func() {
			now := time.Now()
			_ = left.SetDeadline(now)
			_ = right.SetDeadline(now)
			halfCloseRead(left)
			halfCloseWrite(left)
			halfCloseRead(right)
			halfCloseWrite(right)
			_ = left.Close()
			_ = right.Close()
		})
	}
	if ctx != nil {
		relayDone := make(chan struct{})
		defer close(relayDone)
		go func() {
			select {
			case <-ctx.Done():
				interruptRelay()
			case <-relayDone:
			}
		}()
	}

	go func() {
		defer wg.Done()
		buf := getPooledBuf(pool, bufSize)
		n, err := copyWithIdleTimeout(right, left, buf, idleTimeout)
		putPooledBuf(pool, buf)
		uploadCh <- relayCopyResult{Bytes: n, Err: err}
		halfCloseWrite(right)
		halfCloseRead(left)
	}()

	go func() {
		defer wg.Done()
		buf := getPooledBuf(pool, bufSize)
		n, err := copyWithIdleTimeout(left, right, buf, idleTimeout)
		putPooledBuf(pool, buf)
		downloadCh <- relayCopyResult{Bytes: n, Err: err}
		halfCloseWrite(left)
		halfCloseRead(right)
	}()

	wg.Wait()
	interruptRelay()
	upload := <-uploadCh
	download := <-downloadCh
	return bidirectionalRelayStats{
		UploadBytes:   upload.Bytes,
		DownloadBytes: download.Bytes,
		UploadErr:     upload.Err,
		DownloadErr:   download.Err,
		Duration:      time.Since(start),
	}
}

func copyWithIdleTimeout(dst, src net.Conn, buf []byte, idleTimeout time.Duration) (int64, error) {
	var copied int64
	var lastDeadlineUpdate int64
	var lastDeadlineTime time.Time
	const deadlineUpdateInterval = 128 * 1024 /* updates deadlines every 128 KB */

	for {
		if idleTimeout > 0 {
			refreshInterval := idleTimeout / 2
			if refreshInterval <= 0 {
				refreshInterval = idleTimeout
			}
			if refreshInterval > 500*time.Millisecond {
				refreshInterval = 500 * time.Millisecond
			}
			if copied == 0 || (copied-lastDeadlineUpdate) >= deadlineUpdateInterval || time.Since(lastDeadlineTime) >= refreshInterval {
				now := time.Now()
				if err := src.SetReadDeadline(now.Add(idleTimeout)); err != nil {
					return copied, err
				}
				if err := dst.SetWriteDeadline(now.Add(idleTimeout)); err != nil {
					return copied, err
				}
				lastDeadlineUpdate = copied
				lastDeadlineTime = now
			}
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			if err := writeAll(dst, buf[:n]); err != nil {
				return copied, err
			}
			copied += int64(n)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return copied, nil
			}
			return copied, readErr
		}
	}
}

func writeAll(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := w.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func (e *Engine) acquireUDPDialSlot(ctx context.Context, wait time.Duration) bool {
	if e.udpDialSem == nil {
		return true
	}
	if wait <= 0 {
		wait = udpDialAcquireTimeout
	}
	slotCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()

	select {
	case e.udpDialSem <- struct{}{}:
		return true
	case <-slotCtx.Done():
		return false
	}
}

func (e *Engine) acquireTCPDialSlot(ctx context.Context, wait time.Duration) bool {
	if e.tcpDialSem == nil {
		return true
	}
	if wait <= 0 {
		wait = tcpDialAcquireTimeout
	}
	slotCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()

	select {
	case e.tcpDialSem <- struct{}{}:
		return true
	case <-slotCtx.Done():
		return false
	}
}

func (e *Engine) releaseUDPDialSlot() {
	if e.udpDialSem == nil {
		return
	}
	select {
	case <-e.udpDialSem:
	default:
	}
}

func (e *Engine) releaseTCPDialSlot() {
	if e.tcpDialSem == nil {
		return
	}
	select {
	case <-e.tcpDialSem:
	default:
	}
}

func (e *Engine) isUDPDialCoolingDown() bool {
	until := atomic.LoadInt64(&e.udpDialBackoffUntil)
	if until == 0 {
		return false
	}
	return time.Now().UnixNano() < until
}

func (e *Engine) isTCPDialCoolingDown() bool {
	until := atomic.LoadInt64(&e.tcpDialBackoffUntil)
	if until == 0 {
		return false
	}
	return time.Now().UnixNano() < until
}

var (
	errTCPDialCooldown = errors.New("tcp upstream dial cooldown")
	errTCPDialThrottle = errors.New("tcp upstream dial throttle")
)

func (e *Engine) markUDPDialBackoff(d time.Duration) {
	if d <= 0 {
		return
	}
	next := time.Now().Add(d).UnixNano()
	for {
		cur := atomic.LoadInt64(&e.udpDialBackoffUntil)
		if cur >= next {
			return
		}
		if atomic.CompareAndSwapInt64(&e.udpDialBackoffUntil, cur, next) {
			return
		}
	}
}

func (e *Engine) markTCPDialBackoff(d time.Duration) {
	if d <= 0 {
		return
	}
	next := time.Now().Add(d).UnixNano()
	for {
		cur := atomic.LoadInt64(&e.tcpDialBackoffUntil)
		if cur >= next {
			return
		}
		if atomic.CompareAndSwapInt64(&e.tcpDialBackoffUntil, cur, next) {
			return
		}
	}
}

/* Clears transient dial cooldown so fresh routes can rebuild upstream sessions immediately. */
func (e *Engine) clearDialBackoff() {
	atomic.StoreInt64(&e.tcpDialBackoffUntil, 0)
	atomic.StoreInt64(&e.udpDialBackoffUntil, 0)
}

func (e *Engine) pruneLogThrottleStatesLocked(now time.Time) {
	if len(e.logThrottleStates) == 0 {
		return
	}
	for key, state := range e.logThrottleStates {
		if state.LastLogTime.IsZero() || now.Sub(state.LastLogTime) > logThrottleStateTTL {
			delete(e.logThrottleStates, key)
		}
	}
}

/* Throttles logs for transient TCP dial failures to reduce IO overhead during network storms. */
func (e *Engine) logTCPDialFailure(flowID, mode, source, target string, err error) {
	if errors.Is(err, errTCPDialCooldown) || errors.Is(err, errTCPDialThrottle) {
		/* These are already "quiet" errors, we don't need to log them if dial throttling is active */
		/* unless we want a summary. For now, just skip. */
		return
	}

	key := mode + "|tcp-fail|" + target
	now := time.Now()

	e.logThrottleMu.Lock()
	if e.logThrottleStates == nil {
		e.logThrottleStates = make(map[string]logThrottleState)
	}
	if len(e.logThrottleStates) >= logThrottleStateMaxEntries {
		e.pruneLogThrottleStatesLocked(now)
	}
	if _, ok := e.logThrottleStates[key]; !ok && len(e.logThrottleStates) >= logThrottleStateMaxEntries {
		e.logThrottleMu.Unlock()
		logf(LogLevelError, "[ERROR] [TCP] %s -> %s (%s) id=%s | dial failed | err=%v", source, target, mode, flowID, err)
		return
	}
	state := e.logThrottleStates[key]
	if !state.LastLogTime.IsZero() && now.Sub(state.LastLogTime) < logThrottleInterval {
		state.Suppressed++
		e.logThrottleStates[key] = state
		e.logThrottleMu.Unlock()
		return
	}

	repeats := state.Suppressed
	state.LastLogTime = now
	state.Suppressed = 0
	e.logThrottleStates[key] = state
	e.logThrottleMu.Unlock()

	if repeats > 0 {
		logf(LogLevelError, "[ERROR] [TCP] %s -> %s (%s) id=%s | dial failed | err=%v | repeats=%d", source, target, mode, flowID, err, repeats)
		return
	}
	logf(LogLevelError, "[ERROR] [TCP] %s -> %s (%s) id=%s | dial failed | err=%v", source, target, mode, flowID, err)
}

/* Derives a bounded retry window for transient upstream dial failures. */
func (e *Engine) transientTCPDialBudget() time.Duration {
	if e == nil || e.cfg == nil {
		return transientTCPDialBudgetCap
	}
	timeout := e.cfg.ConnectTimeout()
	switch {
	case timeout <= 0:
		return transientTCPDialBudgetCap
	case timeout < transientTCPDialBudgetCap:
		return timeout
	default:
		return transientTCPDialBudgetCap
	}
}

/* Dials the upstream TCP path with bounded retries for short route churn windows. */
func (e *Engine) dialTCPUpstream(ctx context.Context, target string, budget time.Duration) (net.Conn, error) {
	if budget <= 0 {
		budget = transientTCPDialBudgetCap
	}
	deadline := time.Now().Add(budget)
	var lastErr error

	for attempt := 0; ; attempt++ {
		if err := e.waitForTCPDialCooldown(ctx, deadline); err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}

		wait := tcpDialAcquireTimeout
		if remaining := time.Until(deadline); remaining > 0 && remaining < wait {
			wait = remaining
		}
		if !e.acquireTCPDialSlot(ctx, wait) {
			if time.Now().Before(deadline) && e.sleepWithContext(ctx, tcpDialCooldownPollInterval) == nil {
				lastErr = errTCPDialThrottle
				continue
			}
			return nil, errTCPDialThrottle
		}

		dialCtx, cancelDial := e.bindDialContext(ctx)
		upConn, err := e.dialer.DialTCP(dialCtx, target)
		cancelDial()
		e.releaseTCPDialSlot()
		if err == nil {
			return upConn, nil
		}
		lastErr = err

		if !isTransientUpstreamDialError(err) || time.Now().After(deadline) || ctx.Err() != nil {
			return nil, err
		}
		if isAddrNotAvailableError(err) {
			e.markTCPDialBackoff(transientTCPDialRetryDelay)
		}
		if e.sleepWithContext(ctx, transientTCPDialRetryDelay) != nil {
			return nil, err
		}
	}
}

/* Waits for a transient global tcp cooldown to clear before attempting a fresh dial. */
func (e *Engine) waitForTCPDialCooldown(ctx context.Context, deadline time.Time) error {
	for e.isTCPDialCoolingDown() {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return errTCPDialCooldown
		}
		if err := e.sleepWithContext(ctx, tcpDialCooldownPollInterval); err != nil {
			return err
		}
	}
	return nil
}

/* Sleeps while still honoring caller cancellation. */
func (e *Engine) sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

/* Classifies route-churn dial failures that merit a bounded retry. */
func isTransientUpstreamDialError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EADDRNOTAVAIL) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "can't assign requested address") ||
		strings.Contains(msg, "no route to host") ||
		strings.Contains(msg, "network is unreachable")
}

func isAddrNotAvailableError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.EADDRNOTAVAIL) || strings.Contains(strings.ToLower(err.Error()), "can't assign requested address")
}

func (e *Engine) nextFlowID(prefix string) string {
	n := atomic.AddUint64(&e.flowSeq, 1)
	return prefix + strconv.FormatUint(n, 10)
}

/* Aggressively tears down stale upstream state after the host default route changes. */
func (e *Engine) HandleNetworkChange() {
	e.clearDialBackoff()
	e.resetDialContext()
	e.closeIdleDNSPool()
	e.closeIdleUDPPool()
	e.closeActiveUpstreams()
	e.clearLogThrottleStates()
	logf(LogLevelSystem, "[SYS] [NET] network change detected: reset upstream dials and closed active upstream sessions")
	e.warmupUpstreamTransport()
}

func (e *Engine) bindDialContext(parent context.Context) (context.Context, context.CancelFunc) {
	e.dialCtxMu.Lock()
	if e.dialCtx == nil || e.dialCancel == nil {
		e.dialCtx, e.dialCancel = context.WithCancel(context.Background())
	}
	routeCtx := e.dialCtx
	e.dialCtxMu.Unlock()

	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(routeCtx, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

func (e *Engine) resetDialContext() {
	e.dialCtxMu.Lock()
	defer e.dialCtxMu.Unlock()
	if e.dialCancel != nil {
		e.dialCancel()
	}
	e.dialCtx, e.dialCancel = context.WithCancel(context.Background())
}

/* Opportunistically re-establishes the upstream transport after a route change. */
func (e *Engine) warmupUpstreamTransport() {
	if e == nil || e.dialer == nil || e.cfg == nil {
		return
	}
	warmer, ok := e.dialer.(UpstreamWarmer)
	if !ok {
		return
	}

	e.mu.Lock()
	stopping := e.stopping
	e.mu.Unlock()
	if stopping {
		return
	}
	if !e.warmupRunning.CompareAndSwap(false, true) {
		return
	}

	timeout := e.cfg.ConnectTimeout()
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}

	go func(mode string) {
		defer e.warmupRunning.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		dialCtx, cancelDial := e.bindDialContext(ctx)
		err := warmer.Warmup(dialCtx)
		cancelDial()
		if err == nil {
			logf(LogLevelSystem, "[SYS] upstream warmup succeeded | mode=%s", mode)
			return
		}
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || isClosedConnError(err) {
			return
		}
		logf(LogLevelWarn, "[WARN] [SYS] upstream warmup failed | mode=%s err=%v", mode, err)
	}(e.dialer.Mode())
}

func (e *Engine) registerActiveUpstream(closer io.Closer) {
	if closer == nil {
		return
	}
	e.activeMu.Lock()
	if e.activeUpstreams == nil {
		e.activeUpstreams = make(map[io.Closer]struct{})
	}
	e.activeUpstreams[closer] = struct{}{}
	e.activeMu.Unlock()
}

func (e *Engine) unregisterActiveUpstream(closer io.Closer) {
	if closer == nil {
		return
	}
	e.activeMu.Lock()
	delete(e.activeUpstreams, closer)
	e.activeMu.Unlock()
}

func (e *Engine) registerActiveLocal(closer io.Closer) {
	if closer == nil {
		return
	}
	e.activeMu.Lock()
	if e.activeLocals == nil {
		e.activeLocals = make(map[io.Closer]struct{})
	}
	e.activeLocals[closer] = struct{}{}
	e.activeMu.Unlock()
}

func (e *Engine) unregisterActiveLocal(closer io.Closer) {
	if closer == nil {
		return
	}
	e.activeMu.Lock()
	delete(e.activeLocals, closer)
	e.activeMu.Unlock()
}

func (e *Engine) closeActiveLocals() {
	e.activeMu.Lock()
	closers := make([]io.Closer, 0, len(e.activeLocals))
	for closer := range e.activeLocals {
		closers = append(closers, closer)
	}
	if len(closers) > 0 {
		clear(e.activeLocals)
	}
	e.activeMu.Unlock()

	now := time.Now()
	for _, closer := range closers {
		/* Unblocks pending reads and writes before closing. */
		if conn, ok := closer.(net.Conn); ok {
			_ = conn.SetDeadline(now)
		}
		_ = closer.Close()
	}
}

func (e *Engine) closeActiveUpstreams() {
	e.activeMu.Lock()
	closers := make([]io.Closer, 0, len(e.activeUpstreams))
	for closer := range e.activeUpstreams {
		closers = append(closers, closer)
	}
	if len(closers) > 0 {
		clear(e.activeUpstreams)
	}
	e.activeMu.Unlock()

	now := time.Now()
	for _, closer := range closers {
		/* Unblocks pending reads and writes before closing. */
		if conn, ok := closer.(net.Conn); ok {
			_ = conn.SetDeadline(now)
		}
		_ = closer.Close()
	}
}

func (e *Engine) acquireDNSConn(ctx context.Context, target string, budget time.Duration) (net.Conn, bool, error) {
	e.dnsPoolMu.Lock()
	if e.dnsPool != nil {
		if conns := e.dnsPool[target]; len(conns) > 0 {
			conn := conns[len(conns)-1]
			if len(conns) == 1 {
				delete(e.dnsPool, target)
			} else {
				e.dnsPool[target] = conns[:len(conns)-1]
			}
			e.dnsPoolMu.Unlock()
			if !e.activateUpstream(conn) {
				return nil, false, context.Canceled
			}
			return conn, true, nil
		}
	}
	e.dnsPoolMu.Unlock()

	conn, err := e.dialTCPUpstream(ctx, target, budget)
	if err != nil {
		return nil, false, err
	}
	if !e.activateUpstream(conn) {
		return nil, false, context.Canceled
	}
	return conn, false, nil
}

/* Returns a DNS connection to the idle pool or discards it if the pool is full. */
func (e *Engine) releaseDNSConn(target string, conn net.Conn) {
	if conn == nil {
		return
	}
	if err := clearConnDeadline(conn); err != nil {
		e.discardDNSConn(conn)
		return
	}

	e.mu.Lock()
	stopping := e.stopping
	e.mu.Unlock()
	if stopping {
		e.discardDNSConn(conn)
		return
	}

	e.dnsPoolMu.Lock()
	if e.dnsPool == nil {
		e.dnsPool = make(map[string][]net.Conn)
	}
	conns := e.dnsPool[target]
	if len(conns) >= dnsPoolPerTarget {
		e.dnsPoolMu.Unlock()
		e.discardDNSConn(conn)
		return
	}
	e.unregisterActiveUpstream(conn)
	e.dnsPool[target] = append(conns, conn)
	e.dnsPoolMu.Unlock()
}

func (e *Engine) discardDNSConn(conn net.Conn) {
	if conn == nil {
		return
	}
	e.unregisterActiveUpstream(conn)
	_ = conn.Close()
}

func (e *Engine) getDNSCache(target string, payload []byte) []byte {
	if len(payload) < 12 {
		return nil
	}
	key := dnsCacheKey(target, payload)

	e.dnsCacheMu.RLock()
	entry, ok := e.dnsCache[key]
	e.dnsCacheMu.RUnlock()

	if !ok {
		return nil
	}
	if time.Now().After(entry.ExpiresAt) {
		e.dnsCacheMu.Lock()
		/* Avoids deleting an entry that was refreshed after the read-side expiry check. */
		if current, exists := e.dnsCache[key]; exists && time.Now().After(current.ExpiresAt) {
			delete(e.dnsCache, key)
		}
		e.dnsCacheMu.Unlock()
		return nil
	}

	/* Reuses the cached response and restores the caller transaction ID. */
	logf(LogLevelDebug, "[DEBUG] [DNS] %s | cache hit", target)
	resp := append([]byte(nil), entry.Response...)
	if len(resp) >= 2 {
		resp[0] = payload[0]
		resp[1] = payload[1]
	}
	return resp
}

func (e *Engine) putDNSCache(target string, reqPayload, respPayload []byte) {
	if len(reqPayload) < 12 || len(respPayload) < 12 {
		return
	}
	reqQuestionKey := dnsQuestionIdentity(reqPayload)
	if reqQuestionKey == "" || reqQuestionKey != dnsQuestionIdentity(respPayload) {
		return /* Skips mismatched or malformed responses so they cannot poison the request-scoped cache. */
	}
	key := dnsCacheKey(target, reqPayload)
	ttlSeconds := extractMinDNSTTL(respPayload)
	if ttlSeconds <= 0 {
		return /* Skips uncachable responses. */
	}
	if ttlSeconds > 3600 {
		ttlSeconds = 3600 /* Caps cached TTL at one hour. */
	}
	expiresAt := time.Now().Add(time.Duration(ttlSeconds) * time.Second)

	e.dnsCacheMu.Lock()
	defer e.dnsCacheMu.Unlock()

	if e.dnsCache == nil {
		e.dnsCache = make(map[string]dnsCacheEntry)
	}

	/* Evicts one entry when the cache is full, preferring expired entries. */
	maxDNSCacheSize := defaultDNSCacheSize
	if e.cfg != nil && e.cfg.Runtime.DNSCacheSize > 0 {
		maxDNSCacheSize = e.cfg.Runtime.DNSCacheSize
	}
	if len(e.dnsCache) >= maxDNSCacheSize {
		now := time.Now()
		evicted := false
		for k, entry := range e.dnsCache {
			if now.After(entry.ExpiresAt) {
				delete(e.dnsCache, k)
				evicted = true
				break
			}
		}
		if !evicted {
			for k := range e.dnsCache {
				delete(e.dnsCache, k)
				break
			}
		}
	}

	e.dnsCache[key] = dnsCacheEntry{
		Response:  append([]byte(nil), respPayload...),
		ExpiresAt: expiresAt,
	}
}

func (e *Engine) closeIdleDNSPool() {
	e.dnsPoolMu.Lock()
	if len(e.dnsPool) == 0 {
		e.dnsPoolMu.Unlock()
		return
	}
	var closers []io.Closer
	for _, conns := range e.dnsPool {
		for _, c := range conns {
			closers = append(closers, c)
		}
	}
	e.dnsPool = make(map[string][]net.Conn)
	e.dnsPoolMu.Unlock()

	for _, c := range closers {
		_ = c.Close()
	}
}

/* Extracts the smallest cacheable TTL from a DNS response. */
func extractMinDNSTTL(payload []byte) int {
	if len(payload) < 12 {
		return 0
	}
	/* Accepts only complete responses. */
	if payload[2]&0x80 == 0 || payload[2]&0x02 != 0 {
		return 0
	}
	/* Accepts only NOERROR and NXDOMAIN for caching. */
	rcode := payload[3] & 0x0F
	if rcode != 0 && rcode != 3 {
		return 0
	}

	qdcount := int(binary.BigEndian.Uint16(payload[4:6]))
	ancount := int(binary.BigEndian.Uint16(payload[6:8]))
	nscount := int(binary.BigEndian.Uint16(payload[8:10]))
	arcount := int(binary.BigEndian.Uint16(payload[10:12]))

	offset := 12
	/* Advances past the question section. */
	for i := 0; i < qdcount; i++ {
		for offset < len(payload) {
			b := payload[offset]
			if b == 0 {
				offset++
				break
			} else if b&0xC0 == 0xC0 {
				offset += 2
				break
			}
			labelLen := int(b)
			if offset+labelLen+1 > len(payload) {
				return 0 /* Rejects malformed question labels. */
			}
			offset += labelLen + 1
		}
		if offset+4 > len(payload) {
			return 0 /* Rejects truncated question metadata. */
		}
		offset += 4 /* Advances past QTYPE and QCLASS. */
	}

	minTTL := -1

	/* Scans answer, authority, and additional records, but only answer/authority TTLs are cache-significant. */
	totalRecords := ancount + nscount + arcount
	for i := 0; i < totalRecords; i++ {
		if offset >= len(payload) {
			return 0 /* Rejects truncated responses that stop before all declared records. */
		}
		/* Advances past the record name. */
		if payload[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(payload) {
				b := payload[offset]
				if b == 0 {
					offset++
					break
				} else if b&0xC0 == 0xC0 {
					offset += 2
					break
				}
				labelLen := int(b)
				if offset+labelLen+1 > len(payload) {
					return 0 /* Rejects malformed record names. */
				}
				offset += labelLen + 1
			}
		}

		if offset+10 > len(payload) {
			return 0 /* Rejects truncated resource-record metadata. */
		}
		rrType := binary.BigEndian.Uint16(payload[offset : offset+2])
		ttl := int(int32(binary.BigEndian.Uint32(payload[offset+4 : offset+8])))
		rdlength := int(binary.BigEndian.Uint16(payload[offset+8 : offset+10]))
		if offset+10+rdlength > len(payload) {
			return 0 /* Rejects truncated record payloads so malformed responses are never cached. */
		}
		offset += 10 + rdlength

		/* Keeps the smallest positive TTL. */
		if i < ancount+nscount && rrType != 41 && ttl > 0 {
			if minTTL == -1 || ttl < minTTL {
				minTTL = ttl
			}
		}
	}

	/* Uses a short cap for negative caching. */
	if rcode == 3 {
		if minTTL == -1 || minTTL > 60 {
			return 60 /* Caps NXDOMAIN caching at 60 seconds. */
		}
		return minTTL
	}

	if minTTL == -1 {
		return 0
	}
	return minTTL
}

func (e *Engine) takeIdleUDPSession(target string) UDPSession {
	e.udpPoolMu.Lock()
	defer e.udpPoolMu.Unlock()
	if e.udpPool == nil {
		return nil
	}
	sessions := e.udpPool[target]
	n := len(sessions)
	if n == 0 {
		return nil
	}
	session := sessions[n-1]
	if n == 1 {
		delete(e.udpPool, target)
	} else {
		e.udpPool[target] = sessions[:n-1]
	}
	return session
}

func udpSessionPoolKey(source, target string) string {
	if source == "" {
		return target
	}
	if target == "" {
		return source
	}
	return source + "|" + target
}

/* Returns a UDP session to the idle pool or discards it if the pool is full. */
func (e *Engine) releaseUDPSession(target string, session UDPSession, reusable bool) {
	if session == nil {
		return
	}
	if !reusable {
		e.discardUDPSession(session)
		return
	}
	if err := session.SetDeadline(time.Time{}); err != nil {
		e.discardUDPSession(session)
		return
	}

	e.mu.Lock()
	stopping := e.stopping
	e.mu.Unlock()
	if stopping {
		e.discardUDPSession(session)
		return
	}

	e.udpPoolMu.Lock()
	if e.udpPool == nil {
		e.udpPool = make(map[string][]UDPSession)
	}
	totalIdle := 0
	for _, sessions := range e.udpPool {
		totalIdle += len(sessions)
	}
	if totalIdle >= udpPoolMaxIdle {
		e.udpPoolMu.Unlock()
		e.discardUDPSession(session)
		return
	}
	e.unregisterActiveUpstream(session)
	e.udpPool[target] = append(e.udpPool[target], session)
	e.udpPoolMu.Unlock()
}

func (e *Engine) discardUDPSession(session UDPSession) {
	if session == nil {
		return
	}
	e.unregisterActiveUpstream(session)
	_ = session.Close()
}

func (e *Engine) closeIdleUDPPool() {
	e.udpPoolMu.Lock()
	if len(e.udpPool) == 0 {
		e.udpPoolMu.Unlock()
		return
	}
	var sessions []UDPSession
	for _, idle := range e.udpPool {
		sessions = append(sessions, idle...)
	}
	e.udpPool = nil
	e.udpPoolMu.Unlock()

	for _, session := range sessions {
		e.discardUDPSession(session)
	}
}

func (e *Engine) shouldReuseUDPSession(ctx context.Context, errs ...error) bool {
	if ctx.Err() != nil {
		return false
	}
	for _, err := range errs {
		if err == nil || isClosedConnError(err) || isTimeoutError(err) {
			continue
		}
		return false
	}
	return true
}

func flowResultString(err error) string {
	if err == nil || errors.Is(err, io.EOF) || isClosedConnError(err) {
		return "ok"
	}
	if isTimeoutError(err) {
		return "timeout"
	}
	return err.Error()
}

func dnsSummaryErrors(upErr, downErr error) (error, error) {
	if errors.Is(upErr, io.EOF) {
		upErr = io.ErrUnexpectedEOF
	}
	if errors.Is(downErr, io.EOF) {
		downErr = io.ErrUnexpectedEOF
	}
	return upErr, downErr
}

func combineResults(upErr, downErr error) string {
	up := flowResultString(upErr)
	down := flowResultString(downErr)
	if up == "ok" && down == "ok" {
		return "ok"
	}
	return "up:" + up + "/down:" + down
}

func combineUDPResults(upRes, downRes udpPumpResult) string {
	up := flowResultString(upRes.Err)
	if upRes.LocalWriteErr && isBenignLocalPacketWriteError(upRes.Err) {
		up = "local-closed"
	}
	down := flowResultString(downRes.Err)
	if downRes.LocalWriteErr && isBenignLocalPacketWriteError(downRes.Err) {
		down = "local-closed"
	}
	if up == "ok" && down == "ok" {
		return "ok"
	}
	return "up:" + up + "/down:" + down
}

type closeWriter interface{ CloseWrite() error }
type closeReader interface{ CloseRead() error }

func halfCloseWrite(conn net.Conn) {
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func halfCloseRead(conn net.Conn) {
	if cr, ok := conn.(closeReader); ok {
		_ = cr.CloseRead()
	}
}

func (e *Engine) clearLogThrottleStates() {
	e.logThrottleMu.Lock()
	e.logThrottleStates = make(map[string]logThrottleState)
	e.logThrottleMu.Unlock()
}

func getPooledBuf(pool *sync.Pool, size int) []byte {
	if pool == nil {
		return make([]byte, size)
	}
	if v := pool.Get(); v != nil {
		if buf, ok := v.(*[]byte); ok && cap(*buf) >= size {
			return (*buf)[:size]
		}
	}
	return make([]byte, size)
}

func putPooledBuf(pool *sync.Pool, buf []byte) {
	if pool == nil || cap(buf) == 0 {
		return
	}
	buf = buf[:cap(buf)]
	pool.Put(&buf)
}

/* ----------------------------------------------------------------------------- */
/* gVisor netstack wiring */
/* ----------------------------------------------------------------------------- */

/* Netstack integration. */
type NetstackOptions struct {
	TCPHandler func(id gstack.TransportEndpointID, conn net.Conn)
	UDPHandler func(id gstack.TransportEndpointID, conn net.PacketConn)
	EnableUDP  bool
}

type NetstackRuntime struct {
	Stack *gstack.Stack
	NICID tcpip.NICID
}

/* Creates a single NIC stack and attaches TCP/UDP forwarders. */
func NewNetstack(linkEP gstack.LinkEndpoint, opts NetstackOptions) (*NetstackRuntime, error) {
	s := gstack.New(gstack.Options{
		NetworkProtocols: []gstack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []gstack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})

	nicID := tcpip.NICID(1)
	if err := s.CreateNICWithOptions(nicID, linkEP, gstack.NICOptions{}); err != nil {
		return nil, fmt.Errorf("create nic: %s", err)
	}
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("set promiscuous mode: %s", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("set spoofing: %s", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	installTCPForwarder(s, opts.TCPHandler)
	if opts.EnableUDP {
		installUDPForwarder(s, opts.UDPHandler)
	}

	return &NetstackRuntime{Stack: s, NICID: nicID}, nil
}

/* Accepts TCP flows from netstack and delegates handling. */
func installTCPForwarder(s *gstack.Stack, handle func(id gstack.TransportEndpointID, conn net.Conn)) {
	fwd := tcp.NewForwarder(s, 0, 2048, func(req *tcp.ForwarderRequest) {
		if handle == nil {
			req.Complete(true)
			return
		}

		var wq waiter.Queue
		ep, err := req.CreateEndpoint(&wq)
		if err != nil {
			logf(LogLevelError, "[ERROR] [TCP] tcp create endpoint failed: %v", err)
			req.Complete(true)
			return
		}
		id := req.ID()
		req.Complete(false)

		conn := gonet.NewTCPConn(&wq, ep)
		go handle(id, conn)
	})

	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
}

/* Accepts UDP flows from netstack and delegates handling. */
func installUDPForwarder(s *gstack.Stack, handle func(id gstack.TransportEndpointID, conn net.PacketConn)) {
	fwd := udp.NewForwarder(s, func(req *udp.ForwarderRequest) bool {
		if handle == nil {
			return false
		}

		var wq waiter.Queue
		ep, err := req.CreateEndpoint(&wq)
		if err != nil {
			logf(LogLevelError, "[ERROR] [UDP] udp create endpoint failed: %v", err)
			return false
		}
		id := req.ID()
		conn := gonet.NewUDPConn(&wq, ep)
		go handle(id, conn)

		return true
	})

	s.SetTransportProtocolHandler(udp.ProtocolNumber, fwd.HandlePacket)
}

func tcpDestination(id gstack.TransportEndpointID) string {
	host := ipString(id.LocalAddress.AsSlice())
	return net.JoinHostPort(host, strconv.Itoa(int(id.LocalPort)))
}

func tcpSource(id gstack.TransportEndpointID) string {
	host := ipString(id.RemoteAddress.AsSlice())
	return net.JoinHostPort(host, strconv.Itoa(int(id.RemotePort)))
}

func udpDestination(id gstack.TransportEndpointID) *net.UDPAddr {
	ip := append(net.IP(nil), id.LocalAddress.AsSlice()...)
	return &net.UDPAddr{IP: ip, Port: int(id.LocalPort)}
}

func udpDestinationString(id gstack.TransportEndpointID) string {
	host := ipString(id.LocalAddress.AsSlice())
	return net.JoinHostPort(host, strconv.Itoa(int(id.LocalPort)))
}

func udpSourceString(id gstack.TransportEndpointID) string {
	host := ipString(id.RemoteAddress.AsSlice())
	return net.JoinHostPort(host, strconv.Itoa(int(id.RemotePort)))
}

func ipString(raw []byte) string {
	if len(raw) == 0 {
		return "0.0.0.0"
	}
	ip := net.IP(make([]byte, len(raw)))
	copy(ip, raw)
	return ip.String()
}

func formatBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	if n < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	}
	if n < 1024*1024*1024 {
		return fmt.Sprintf("%.2f MB", float64(n)/(1024*1024))
	}
	return fmt.Sprintf("%.2f GB", float64(n)/(1024*1024*1024))
}

func formatDuration(d time.Duration) string {
	return d.Round(time.Millisecond).String()
}
