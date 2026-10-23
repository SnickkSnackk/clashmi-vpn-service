package clashmicore

import (
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// PackageNameResolver returns the package that owns the connection, or an
// empty string when the owner is unknown. On Android the owner lookup returns
// nothing for apps the VPN does not apply to, which lets rules reject traffic
// that an excluded app forced into the tun interface with SO_BINDTODEVICE.
type PackageNameResolver interface {
	FindPackageName(network string, srcIP string, srcPort int, dstIP string, dstPort int) string
}

func SetPackageNameResolver(resolver PackageNameResolver) {
	mu.Lock()
	defer mu.Unlock()

	if resolver == nil {
		process.DefaultPackageNameResolver = nil
		log.Warnln("[ClashMiCore] Android package name resolver cleared")
		return
	}
	process.DefaultPackageNameResolver = func(metadata *C.Metadata) (string, error) {
		return resolvePackageName(resolver, metadata)
	}
	log.Infoln("[ClashMiCore] Android package name resolver installed")
}

func ClearPackageNameResolver() {
	SetPackageNameResolver(nil)
}

func resolvePackageName(resolver PackageNameResolver, metadata *C.Metadata) (string, error) {
	var network string
	switch metadata.NetWork {
	case C.TCP:
		network = "tcp"
	case C.UDP:
		network = "udp"
	default:
		return "", process.ErrInvalidNetwork
	}

	src, ok := addrPortFromNetAddr(metadata.RawSrcAddr)
	if !ok {
		src = netip.AddrPortFrom(metadata.SrcIP, metadata.SrcPort)
	}
	dst, ok := addrPortFromNetAddr(metadata.RawDstAddr)
	if !ok {
		dst = netip.AddrPortFrom(metadata.DstIP, metadata.DstPort)
	}
	if !src.Addr().IsValid() || !dst.Addr().IsValid() {
		return "", process.ErrInvalidNetwork
	}

	packageName := resolver.FindPackageName(
		network,
		src.Addr().Unmap().String(),
		int(src.Port()),
		dst.Addr().Unmap().String(),
		int(dst.Port()),
	)
	if packageName == "" {
		return "", process.ErrNotFound
	}
	return packageName, nil
}

func addrPortFromNetAddr(addr net.Addr) (netip.AddrPort, bool) {
	switch value := addr.(type) {
	case *net.TCPAddr:
		if value == nil {
			return netip.AddrPort{}, false
		}
		addrPort := value.AddrPort()
		return addrPort, addrPort.Addr().IsValid()
	case *net.UDPAddr:
		if value == nil {
			return netip.AddrPort{}, false
		}
		addrPort := value.AddrPort()
		return addrPort, addrPort.Addr().IsValid()
	default:
		return netip.AddrPort{}, false
	}
}
