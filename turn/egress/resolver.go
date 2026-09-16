package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// ErrDenied matches every DeniedError via errors.Is.
var ErrDenied = errors.New("egress policy denied")

// DeniedError is returned when a destination is rejected by the egress
// policy during DNS resolution or dialing.
type DeniedError struct {
	Host   string
	Addr   netip.Addr
	Reason string
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("egress policy denied %s (%s): %s", e.Host, e.Addr, e.Reason)
}

// Is allows errors.Is(err, ErrDenied) to match every DeniedError.
func (e *DeniedError) Is(target error) bool {
	return target == ErrDenied
}

// LookupFunc resolves a hostname to IP addresses. It mirrors
// net.Resolver.LookupNetIP so a custom resolver can be injected.
type LookupFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

// Resolver guards hostname resolution with an egress policy.
//
// It defends against DNS based SSRF bypasses:
//   - every record (not just the first one) is validated, so a response that
//     mixes a public address with 169.254.169.254 is rejected as a whole;
//   - callers receive concrete, already validated addresses and should dial
//     them directly (see GuardedDialer), which pins the checked result and
//     prevents the classic check-then-resolve TOCTOU / DNS rebinding gap.
type Resolver struct {
	policy *Policy
	lookup LookupFunc
}

// NewResolver creates a guarded resolver using the given lookup function.
// If lookup is nil the net.DefaultResolver is used.
func NewResolver(p *Policy, lookup LookupFunc) *Resolver {
	if lookup == nil {
		lookup = net.DefaultResolver.LookupNetIP
	}
	return &Resolver{policy: p, lookup: lookup}
}

// Resolve validates an IP literal or resolves a hostname and enforces the
// policy on every returned address. network must be "ip", "ip4" or "ip6".
func (r *Resolver) Resolve(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if err := checkNetwork(network); err != nil {
		return nil, err
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		if err := familyMatches(network, addr); err != nil {
			return nil, err
		}
		d := r.policy.EvaluateAddr(addr)
		if !d.Allowed {
			return nil, &DeniedError{Host: host, Addr: d.Addr, Reason: d.Reason}
		}
		return []netip.Addr{d.Addr}, nil
	}

	addrs, err := r.lookup(ctx, network, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}

	validated := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		d := r.policy.EvaluateAddr(addr)
		if !d.Allowed {
			return nil, &DeniedError{Host: host, Addr: d.Addr, Reason: d.Reason}
		}
		validated = append(validated, d.Addr)
	}
	return validated, nil
}

func checkNetwork(network string) error {
	switch network {
	case "ip", "ip4", "ip6":
		return nil
	default:
		return fmt.Errorf("egress resolver: unsupported network %q", network)
	}
}

func familyMatches(network string, addr netip.Addr) error {
	switch network {
	case "ip4":
		if !addr.Is4() {
			return fmt.Errorf("egress resolver: %s is not an IPv4 address", addr)
		}
	case "ip6":
		if !addr.Is6() {
			return fmt.Errorf("egress resolver: %s is not an IPv6 address", addr)
		}
	}
	return nil
}

// DialFunc dials a validated IP literal, matching net.Dialer.DialContext.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// GuardedDialer resolves hostnames through the policy and dials only the
// concrete validated IP addresses, never re-resolving the hostname. This
// pins the address that was checked at resolution time and closes the DNS
// rebinding window between validation and connection.
type GuardedDialer struct {
	Resolver *Resolver
	Dial     DialFunc
}

// DialContext implements net.Dialer-like dialing behind the egress policy.
func (d *GuardedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	dialNetwork, ipNetwork := splitNetwork(network)
	dial := d.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	addrs, err := d.Resolver.Resolve(ctx, ipNetwork, host)
	if err != nil {
		return nil, err
	}

	var errs []string
	for _, addr := range addrs {
		target := net.JoinHostPort(addr.String(), port)
		conn, dialErr := dial(ctx, dialNetwork, target)
		if dialErr == nil {
			return conn, nil
		}
		errs = append(errs, dialErr.Error())
	}
	return nil, fmt.Errorf("egress dialer: all %d validated addresses failed for %s: %s",
		len(addrs), host, strings.Join(errs, "; "))
}

// splitNetwork maps a dial network (tcp, tcp4, udp6, ...) to the network
// used for dialing and the address family used for resolution.
func splitNetwork(network string) (string, string) {
	switch network {
	case "tcp4", "udp4", "ip4":
		return network, "ip4"
	case "tcp6", "udp6", "ip6":
		return network, "ip6"
	default:
		return network, "ip"
	}
}
