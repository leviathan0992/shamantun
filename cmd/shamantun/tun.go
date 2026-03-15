package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	gstack "gvisor.dev/gvisor/pkg/tcpip/stack"
)

/* ----------------------------------------------------------------------------- */
/* Cross-platform TUN plumbing (Linux + macOS) */
/* ----------------------------------------------------------------------------- */

/* Wraps a cross-platform TUN device behind the channel endpoint path. */
type TunDevice struct {
	Name         string
	MTU          int
	File         *os.File
	LinkEndpoint gstack.LinkEndpoint
	closeFunc    func(context.Context) error
}

func (d *TunDevice) Close() error {
	return d.CloseContext(context.Background())
}

func (d *TunDevice) CloseContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if d == nil {
		return nil
	}
	if d.closeFunc != nil {
		return d.closeFunc(ctx)
	}
	if d.LinkEndpoint != nil {
		d.LinkEndpoint.Close()
	}
	if d.File != nil {
		return d.File.Close()
	}
	return nil
}

type tunStyle int

const (
	tunStyleLinuxNoPI tunStyle = iota + 1
	tunStyleDarwinUTUN
)

const (
	linuxIFFTUN      = 0x0001
	linuxIFFNoPI     = 0x1000
	linuxTUNSetIFF   = 0x400454ca
	darwinAFSystem   = 32
	darwinAFSysCtl   = 2
	darwinCtlIOCGInf = 0xc0644e03
	darwinProtoCtl   = 2
	darwinUTUNIfName = 2
	sockaddrCtlSize  = 32
	utunHeaderSize   = 4
	tunOutQueueLen   = 8192
)

var tunBufPool sync.Pool

func getTunBuf(size int) []byte {
	if v := tunBufPool.Get(); v != nil {
		if buf, ok := v.(*[]byte); ok && cap(*buf) >= size {
			return (*buf)[:size]
		}
	}
	return make([]byte, size)
}

func putTunBuf(buf []byte) {
	if cap(buf) == 0 {
		return
	}
	buf = buf[:cap(buf)]
	tunBufPool.Put(&buf)
}

type linuxIfreq struct {
	Name  [16]byte
	Flags uint16
	Pad   [22]byte
}

type ctlInfo struct {
	ID   uint32
	Name [96]byte
}

type sockaddrCtl struct {
	Len      uint8
	Family   uint8
	Sysaddr  uint16
	ID       uint32
	Unit     uint32
	Reserved [5]uint32
}

/* Opens a platform-specific TUN handle and bridges it through the channel endpoint. */
func OpenTUN(name string, mtu int) (*TunDevice, error) {
	if mtu <= 0 {
		mtu = 1500
	}

	var (
		file       *os.File
		actualName string
		style      tunStyle
		err        error
	)

	switch runtime.GOOS {
	case "linux":
		file, actualName, err = openLinuxTUNFile(name)
		style = tunStyleLinuxNoPI
	case "darwin":
		file, actualName, err = openDarwinUTUNFile(name)
		style = tunStyleDarwinUTUN
	default:
		return nil, fmt.Errorf("tun open is currently supported on linux and darwin only")
	}
	if err != nil {
		return nil, err
	}

	ep := channel.New(tunOutQueueLen, uint32(mtu), "")
	ctx, cancel := context.WithCancel(context.Background())

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		closed   bool
		closeErr error
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		readTUNLoop(ctx, file, ep, mtu, style)
	}()
	go func() {
		defer wg.Done()
		writeTUNLoop(ctx, file, ep, style)
	}()

	done := make(chan struct{})
	closeFunc := func(ctx context.Context) error {
		if ctx == nil {
			ctx = context.Background()
		}

		mu.Lock()
		if !closed {
			closed = true
			go func() {
				cancel()
				ep.Close()
				if err := file.Close(); err != nil && !isClosedFileError(err) {
					mu.Lock()
					closeErr = err
					mu.Unlock()
				}
				wg.Wait()
				close(done)
			}()
		}
		mu.Unlock()

		select {
		case <-done:
			mu.Lock()
			err := closeErr
			mu.Unlock()
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return &TunDevice{
		Name:         actualName,
		MTU:          mtu,
		File:         file,
		LinkEndpoint: ep,
		closeFunc:    closeFunc,
	}, nil
}

/* Opens /dev/net/tun in IFF_TUN|IFF_NO_PI mode. */
func openLinuxTUNFile(name string) (*os.File, string, error) {
	if strings.TrimSpace(name) == "" {
		name = "tun0"
	}
	if len(name) > 15 {
		return nil, "", fmt.Errorf("linux tun name too long (max 15): %q", name)
	}

	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return nil, "", fmt.Errorf("open /dev/net/tun: %w (run with sudo/root)", err)
		}
		return nil, "", fmt.Errorf("open /dev/net/tun: %w", err)
	}

	var ifr linuxIfreq
	copy(ifr.Name[:], name)
	ifr.Flags = linuxIFFTUN | linuxIFFNoPI

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(linuxTUNSetIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		_ = file.Close()
		if errno == syscall.EPERM || errno == syscall.EACCES {
			return nil, "", fmt.Errorf("ioctl TUNSETIFF failed: %v (run with sudo/root)", errno)
		}
		return nil, "", fmt.Errorf("ioctl TUNSETIFF failed: %v", errno)
	}

	actualName := string(bytes.TrimRight(ifr.Name[:], "\x00"))
	if actualName == "" {
		actualName = name
	}

	return file, actualName, nil
}

/* Creates or attaches a utun interface through the control socket. */
func openDarwinUTUNFile(name string) (*os.File, string, error) {
	unit, err := parseUTUNUnit(name)
	if err != nil {
		return nil, "", err
	}

	fd, err := syscall.Socket(darwinAFSystem, syscall.SOCK_DGRAM, darwinProtoCtl)
	if err != nil {
		return nil, "", fmt.Errorf("open utun socket: %w", err)
	}
	syscall.CloseOnExec(fd)

	cleanupFD := true
	defer func() {
		if cleanupFD {
			_ = syscall.Close(fd)
		}
	}()

	var info ctlInfo
	copy(info.Name[:], []byte("com.apple.net.utun_control"))
	if err := ioctlCtlInfo(fd, &info); err != nil {
		return nil, "", fmt.Errorf("ioctl CTLIOCGINFO failed: %w", err)
	}

	addr := sockaddrCtl{
		Len:     uint8(sockaddrCtlSize),
		Family:  uint8(darwinAFSystem),
		Sysaddr: darwinAFSysCtl,
		ID:      info.ID,
		Unit:    unit,
	}
	if err := connectSockaddrCtl(fd, &addr); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return nil, "", fmt.Errorf("connect utun control failed: %w (run with sudo/root)", err)
		}
		return nil, "", fmt.Errorf("connect utun control failed: %w", err)
	}

	actualName, err := getsockoptString(fd, darwinProtoCtl, darwinUTUNIfName)
	if err != nil {
		actualName = fallbackUTUNName(unit)
	} else {
		actualName = strings.TrimRight(actualName, "\x00")
		if actualName == "" {
			actualName = fallbackUTUNName(unit)
		}
	}

	file := os.NewFile(uintptr(fd), actualName)
	if file == nil {
		return nil, "", fmt.Errorf("create os.File from utun fd failed")
	}
	cleanupFD = false
	return file, actualName, nil
}

func parseUTUNUnit(name string) (uint32, error) {
	n := strings.TrimSpace(name)
	switch n {
	case "", "utun":
		return 0, nil
	case "tun0":
		return 1, nil
	}

	if !strings.HasPrefix(n, "utun") {
		return 0, fmt.Errorf("darwin tun name must be empty, \"utun\", or \"utunN\" (got %q)", name)
	}

	idxStr := strings.TrimPrefix(n, "utun")
	if idxStr == "" {
		return 0, nil
	}
	idx, err := strconv.Atoi(idxStr)
	if err != nil || idx < 0 {
		return 0, fmt.Errorf("invalid utun index in %q", name)
	}
	return uint32(idx + 1), nil
}

func fallbackUTUNName(unit uint32) string {
	if unit > 0 {
		return fmt.Sprintf("utun%d", int(unit)-1)
	}
	return "utun"
}

func ioctlCtlInfo(fd int, info *ctlInfo) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(darwinCtlIOCGInf),
		uintptr(unsafe.Pointer(info)),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func connectSockaddrCtl(fd int, addr *sockaddrCtl) error {
	_, _, errno := syscall.RawSyscall(
		syscall.SYS_CONNECT,
		uintptr(fd),
		uintptr(unsafe.Pointer(addr)),
		uintptr(sockaddrCtlSize),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func getsockoptString(fd, level, name int) (string, error) {
	buf := make([]byte, 64)
	size := uint32(len(buf))

	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(name),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return "", errno
	}
	if size == 0 {
		return "", nil
	}

	n := int(size)
	if n > len(buf) {
		n = len(buf)
	}
	if i := bytes.IndexByte(buf[:n], 0); i >= 0 {
		n = i
	}
	return string(buf[:n]), nil
}

/* Pushes packets from the OS TUN file descriptor into the gVisor link endpoint. */
func readTUNLoop(ctx context.Context, file *os.File, ep *channel.Endpoint, mtu int, style tunStyle) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	bufSize := mtu
	if style == tunStyleDarwinUTUN {
		bufSize += utunHeaderSize
	}
	if bufSize <= 0 {
		bufSize = 1500
	}

	for {
		buf := getTunBuf(bufSize)
		n, err := file.Read(buf)
		if err != nil {
			putTunBuf(buf)
			if ctx.Err() != nil || isClosedFileError(err) {
				return
			}
			logf(LogLevelError, "[ERROR] [TUN] read failed: %v", err)
			return
		}
		if n <= 0 {
			putTunBuf(buf)
			continue
		}

		proto, payload := parseInboundFrame(buf[:n], style)
		if proto == 0 || len(payload) == 0 {
			putTunBuf(buf)
			continue
		}

		/* buffer.MakeWithData copies payload into gVisor-owned storage. */
		payloadData := buffer.MakeWithData(payload)
		putTunBuf(buf)
		pkt := gstack.NewPacketBuffer(gstack.PacketBufferOptions{Payload: payloadData})
		ep.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
}

/* Drains packets from gVisor and writes them back to the OS TUN file descriptor. */
func writeTUNLoop(ctx context.Context, file *os.File, ep *channel.Endpoint, style tunStyle) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	for {
		pkt := ep.ReadContext(ctx)
		if pkt == nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}

		view := pkt.ToView()
		payload := view.AsSlice()

		var out []byte
		var pooled []byte
		if style == tunStyleDarwinUTUN {
			family := utunFamily(pkt.NetworkProtocolNumber, payload)
			if family != 0 {
				needed := utunHeaderSize + len(payload)
				pooled = getTunBuf(needed)
				pooled[0], pooled[1], pooled[2] = 0, 0, 0
				pooled[3] = family
				copy(pooled[utunHeaderSize:], payload)
				out = pooled
			}
		} else {
			out = payload
		}

		if len(out) == 0 {
			view.Release()
			pkt.DecRef()
			if pooled != nil {
				putTunBuf(pooled)
			}
			continue
		}
		if err := writeTUNFrame(file, out); err != nil {
			view.Release()
			pkt.DecRef()
			if pooled != nil {
				putTunBuf(pooled)
			}
			if ctx.Err() != nil || isClosedFileError(err) {
				return
			}
			logf(LogLevelError, "[ERROR] [TUN] write failed: %v", err)
			return
		}
		view.Release()
		pkt.DecRef()
		if pooled != nil {
			putTunBuf(pooled)
		}
	}
}

/* Writes one full TUN frame or returns an error. */
func writeTUNFrame(w io.Writer, frame []byte) error {
	if len(frame) == 0 {
		return nil
	}
	n, err := w.Write(frame)
	if err != nil {
		return err
	}
	if n != len(frame) {
		return io.ErrShortWrite
	}
	return nil
}

/* Strips platform framing and returns the IP payload plus protocol. */
func parseInboundFrame(frame []byte, style tunStyle) (tcpip.NetworkProtocolNumber, []byte) {
	if style == tunStyleDarwinUTUN {
		if len(frame) <= utunHeaderSize {
			return 0, nil
		}
		switch frame[3] {
		case syscall.AF_INET:
			return header.IPv4ProtocolNumber, frame[utunHeaderSize:]
		case syscall.AF_INET6:
			return header.IPv6ProtocolNumber, frame[utunHeaderSize:]
		default:
			payload := frame[utunHeaderSize:]
			return protocolFromPayload(payload), payload
		}
	}

	return protocolFromPayload(frame), frame
}

/* Infers IPv4 or IPv6 from the version nibble. */
func protocolFromPayload(payload []byte) tcpip.NetworkProtocolNumber {
	if len(payload) == 0 {
		return 0
	}
	switch payload[0] >> 4 {
	case 4:
		return header.IPv4ProtocolNumber
	case 6:
		return header.IPv6ProtocolNumber
	default:
		return 0
	}
}

/* Maps gVisor protocol numbers to Darwin utun AF markers. */
func utunFamily(proto tcpip.NetworkProtocolNumber, payload []byte) byte {
	switch proto {
	case header.IPv4ProtocolNumber:
		return byte(syscall.AF_INET)
	case header.IPv6ProtocolNumber:
		return byte(syscall.AF_INET6)
	default:
		switch protocolFromPayload(payload) {
		case header.IPv4ProtocolNumber:
			return byte(syscall.AF_INET)
		case header.IPv6ProtocolNumber:
			return byte(syscall.AF_INET6)
		default:
			return 0
		}
	}
}

func isClosedFileError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrClosed) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "closed") || strings.Contains(msg, "bad file descriptor")
}
