package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	autoRouteEnsureFastInterval     = 1 * time.Second
	autoRouteEnsureSlowInterval     = 3 * time.Second
	autoRouteEnsureSlowAfterSuccess = 5
)

/* ----------------------------------------------------------------------------- */
/* Application lifecycle */
/* ----------------------------------------------------------------------------- */

/* Process lifecycle manager. */
type App struct {
	version string
}

/* Creates an application instance with build/version metadata. */
func NewApp(version string) *App {
	return &App{version: version}
}

/* Loads config, starts the engine, and blocks until a shutdown signal. */
func (a *App) Run(cfgPath, tunOverride string, debug bool) error {
	level := LogLevelInfo
	if debug {
		level = LogLevelDebug
	}
	SetLogLevel(level)

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	if err := cfg.ApplyOverrides("", tunOverride); err != nil {
		return err
	}
	if cfg.AutoRoute {
		pinnedHost, err := cfg.PinUpstreamIPForAutoRoute()
		if err != nil {
			return err
		}
		if pinnedHost != "" {
			logf(
				LogLevelSystem,
				"[SYS] [NET] auto-route pinned upstream host=%s addr=%s",
				pinnedHost,
				cfg.Upstream.Addr,
			)
		}
	}

	logf(
		LogLevelSystem,
		"[SYS] shamantun version=%s mode=%s tun=%s upstream=%s",
		a.version,
		cfg.Mode,
		cfg.Tun.Name,
		cfg.Upstream.Addr,
	)
	if debug {
		logf(LogLevelDebug, "[DEBUG] verbose per-flow logging enabled")
	}
	if cfg.Upstream.InsecureSkipVerify {
		logf(LogLevelWarn, "[WARN] upstream tls verification is disabled (insecure_skip_verify=true)")
	}
	if cfg.AutoRoute && cfg.Mode == ModeSocks5TLS && !cfg.Runtime.EnableUDP {
		logf(LogLevelWarn, "[WARN] mode=%s with auto-route and enable_udp=false may break DNS on systems that use UDP resolvers", cfg.Mode)
	}
	if cfg.Mode == ModeHTTPS {
		logf(LogLevelWarn, "[WARN] mode=%s only proxies TCP; UDP traffic such as classic DNS will not pass through the tunnel", cfg.Mode)
	}

	eng, err := NewEngine(cfg)
	if err != nil {
		return fmt.Errorf("create engine: %w", err)
	}
	logf(LogLevelSystem, "[SYS] config: connect_timeout=%s idle_timeout=%s tcp_buffer=%s udp_buffer=%s dns_cache=%d tcp_concurrency=%d udp_concurrency=%d enable_udp=%v",
		cfg.ConnectTimeout(),
		cfg.IdleTimeout(),
		formatBytes(int64(cfg.Runtime.TCPBuffer)),
		formatBytes(int64(cfg.Runtime.UDPBuffer)),
		cfg.Runtime.DNSCacheSize,
		cfg.Runtime.TCPDialConcurrency,
		cfg.Runtime.UDPDialConcurrency,
		cfg.Runtime.EnableUDP,
	)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := eng.Start(ctx); err != nil {
		return err
	}

	var routeMgr *AutoRouteManager
	var ensureDone chan struct{}
	if cfg.AutoRoute {
		routeMgr, err = NewAutoRouteManager(cfg, eng.tunDev.Name)
		if err != nil {
			stopCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			_ = eng.Stop(stopCtx)
			stop()
			return err
		}
		if err := routeMgr.Setup(); err != nil {
			_ = routeMgr.Teardown()
			stopCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			_ = eng.Stop(stopCtx)
			stop()
			return err
		}
		routeChangeCh := make(chan struct{}, 1)
		routeMgr.SetDefaultRouteChangeHook(func() {
			select {
			case routeChangeCh <- struct{}{}:
			default:
			}
		})
		if routeMgr.upstreamIP == "" {
			logf(LogLevelSystem, "[SYS] [NET] auto-route enabled for tun=%s upstream-bypass=skipped (local upstream route is handled by host)", eng.tunDev.Name)
		} else {
			logf(LogLevelSystem, "[SYS] [NET] auto-route enabled for tun=%s upstream-ip=%s", eng.tunDev.Name, routeMgr.upstreamIP)
		}

		ensureDone = make(chan struct{})
		go func() {
			defer close(ensureDone)
			stablePasses := 0
			timer := time.NewTimer(nextAutoRouteEnsureInterval(stablePasses))
			defer timer.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-routeChangeCh:
					eng.HandleNetworkChange()
					stablePasses = 0
					resetTimer(timer, nextAutoRouteEnsureInterval(stablePasses))
				case <-timer.C:
					if err := routeMgr.Ensure(); err != nil {
						logf(LogLevelWarn, "[WARN] [NET] auto-route ensure warning: tun=%s upstream=%s err=%v", eng.tunDev.Name, routeMgr.upstreamIP, err)
						stablePasses = 0
					} else if stablePasses < autoRouteEnsureSlowAfterSuccess {
						stablePasses++
					}
					resetTimer(timer, nextAutoRouteEnsureInterval(stablePasses))
				}
			}
		}()
	} else {
		logf(LogLevelSystem, "[SYS] [NET] auto-route disabled")
	}

	<-ctx.Done()
	logf(LogLevelSystem, "[SYS] shutdown signal received")

	/* Shortens shutdown waits after a second shutdown signal without skipping route teardown. */
	forceQuit := make(chan os.Signal, 1)
	signal.Notify(forceQuit, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(forceQuit)
	forcedShutdown := make(chan struct{})
	var forceOnce sync.Once
	go func() {
		<-forceQuit
		forceOnce.Do(func() {
			logf(LogLevelSystem, "[SYS] forced shutdown")
			close(forcedShutdown)
		})
	}()

	if routeMgr != nil {
		routeMgr.SetDefaultRouteChangeHook(nil)
	}

	if ensureDone != nil {
		select {
		case <-ensureDone:
		case <-forcedShutdown:
			timer := time.NewTimer(250 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-ensureDone:
			case <-timer.C:
				_, _ = fmt.Fprintln(os.Stderr, "shutdown warning: continuing to route teardown before ensure loop fully drained")
			}
		}
	}
	if routeMgr != nil {
		if err := routeMgr.Teardown(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "route teardown warning: %v\n", err)
		}
	}

	shutdownTimeout := cfg.ConnectTimeout()
	if shutdownTimeout <= 0 || shutdownTimeout > 5*time.Second {
		shutdownTimeout = 5 * time.Second
	}
	shutdownCtx, stop := context.WithTimeout(context.Background(), shutdownTimeout)
	defer stop()
	go func() {
		select {
		case <-forcedShutdown:
			stop()
		case <-shutdownCtx.Done():
		}
	}()
	if err := eng.Stop(shutdownCtx); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "shutdown warning: %v\n", err)
	}

	return nil
}

func nextAutoRouteEnsureInterval(stablePasses int) time.Duration {
	if stablePasses >= autoRouteEnsureSlowAfterSuccess {
		return autoRouteEnsureSlowInterval
	}
	return autoRouteEnsureFastInterval
}

func resetTimer(timer *time.Timer, d time.Duration) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}
