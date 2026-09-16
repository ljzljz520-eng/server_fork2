// Package egress implements a dynamic egress policy for TURN relay peers.
//
// A static CIDR deny list (SCREEGO_TURN_DENY_PEERS) cannot fully prevent
// SSRF through the TURN relay: cloud metadata endpoints live in link-local
// or even public-looking ranges, IPv4-mapped/compatible IPv6 addresses and
// tunneling prefixes (6to4, Teredo, NAT64) can be used to disguise an
// internal address, and hostnames may resolve to different addresses at
// check time and connect time.
//
// The Policy evaluates every requested peer address dynamically by first
// canonicalizing it (unwrapping IPv4-in-IPv6 representations) and then
// classifying it into an address category. A default-deny mode decides
// whether the category may leave the relay, while explicit deny and allow
// CIDRs always take precedence.
package egress

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
)

// Mode selects the default egress decision for peer addresses.
type Mode string

const (
	// ModePublic (default) only relays traffic to global unicast addresses.
	// Loopback, link-local, cloud metadata, private/RFC1918, multicast,
	// reserved and tunneled addresses are blocked unless explicitly allowed.
	ModePublic Mode = "public"

	// ModePrivate additionally permits relaying to private LAN ranges
	// (RFC1918, RFC4193, CGNAT) while loopback, link-local, metadata,
	// multicast, reserved and tunneled addresses stay blocked.
	ModePrivate Mode = "private"

	// ModeAllowAll restores the legacy behavior: only addresses matching
	// SCREEGO_TURN_DENY_PEERS are blocked. It is unsafe and must be opted
	// into explicitly.
	ModeAllowAll Mode = "allow-all"
)

// kind describes how a mode treats an address category.
type kind int

const (
	// kindDangerous categories are blocked in both public and private modes:
	// they are never valid destinations for an internet-facing TURN relay.
	kindDangerous kind = iota
	// kindPrivate categories are blocked in public mode but permitted in
	// private mode (internal/LAN deployments).
	kindPrivate
)

type rule struct {
	prefix netip.Prefix
	cat    string
	kind   kind
}

// builtinRules classifies all non-global addresses. It is sorted by prefix
// length in init so the most specific match wins (e.g. the Alibaba metadata
// endpoint 100.100.100.200/32 must win over the CGNAT range 100.64.0.0/10).
var builtinRules = []rule{
	// Cloud metadata endpoints that are not covered by a wider category.
	{mustPrefix("100.100.100.200/32"), "cloud metadata endpoint (Alibaba 100.100.100.200)", kindDangerous},
	{mustPrefix("fd00:ec2::254/128"), "cloud metadata endpoint (AWS IMDS over IPv6)", kindDangerous},

	// IPv4 special-use ranges, https://www.iana.org/assignments/iana-ipv4-special-registry/
	{mustPrefix("0.0.0.0/8"), "unspecified address range", kindDangerous},
	{mustPrefix("10.0.0.0/8"), "private network (RFC1918)", kindPrivate},
	{mustPrefix("100.64.0.0/10"), "carrier-grade NAT (RFC6598)", kindPrivate},
	{mustPrefix("127.0.0.0/8"), "loopback", kindDangerous},
	{mustPrefix("169.254.0.0/16"), "link-local / cloud metadata (169.254.0.0/16)", kindDangerous},
	{mustPrefix("172.16.0.0/12"), "private network (RFC1918)", kindPrivate},
	{mustPrefix("192.0.0.0/24"), "reserved (IETF protocol assignments)", kindDangerous},
	{mustPrefix("192.0.2.0/24"), "documentation range TEST-NET-1", kindDangerous},
	{mustPrefix("192.88.99.0/24"), "reserved (deprecated 6to4 anycast relay)", kindDangerous},
	{mustPrefix("192.168.0.0/16"), "private network (RFC1918)", kindPrivate},
	{mustPrefix("198.18.0.0/15"), "benchmark testing range", kindDangerous},
	{mustPrefix("198.51.100.0/24"), "documentation range TEST-NET-2", kindDangerous},
	{mustPrefix("203.0.113.0/24"), "documentation range TEST-NET-3", kindDangerous},
	{mustPrefix("224.0.0.0/4"), "multicast", kindDangerous},
	{mustPrefix("240.0.0.0/4"), "reserved (future use / class E)", kindDangerous},
	{mustPrefix("255.255.255.255/32"), "limited broadcast", kindDangerous},

	// IPv6 special-use ranges.
	{mustPrefix("::/128"), "unspecified address", kindDangerous},
	{mustPrefix("::1/128"), "loopback", kindDangerous},
	{mustPrefix("64:ff9b::/96"), "NAT64 well-known prefix (embeds IPv4 destination)", kindDangerous},
	{mustPrefix("64:ff9b:1::/48"), "local-use NAT64 prefix (embeds IPv4 destination)", kindDangerous},
	{mustPrefix("100::/64"), "discard-only prefix (RFC6666)", kindDangerous},
	{mustPrefix("2001::/32"), "Teredo tunnel (embeds IPv4 destination)", kindDangerous},
	{mustPrefix("2001:10::/28"), "deprecated ORCHID prefix", kindDangerous},
	{mustPrefix("2001:20::/28"), "ORCHID prefix (not routable)", kindDangerous},
	{mustPrefix("2001:db8::/32"), "documentation prefix", kindDangerous},
	{mustPrefix("2001::/23"), "reserved IETF prefix", kindDangerous},
	{mustPrefix("2002::/16"), "6to4 tunnel (embeds IPv4 destination)", kindDangerous},
	{mustPrefix("fc00::/7"), "unique-local network (RFC4193)", kindPrivate},
	{mustPrefix("fec0::/10"), "deprecated site-local prefix", kindDangerous},
	{mustPrefix("fe80::/10"), "link-local", kindDangerous},
	{mustPrefix("ff00::/8"), "multicast", kindDangerous},
}

func init() {
	sort.Slice(builtinRules, func(i, j int) bool {
		return builtinRules[i].prefix.Bits() > builtinRules[j].prefix.Bits()
	})
}

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p.Masked()
}

// Policy is a dynamic egress policy for TURN peer connections.
type Policy struct {
	mode  Mode
	deny  []netip.Prefix
	allow []netip.Prefix
}

// Decision is the result of a policy evaluation.
type Decision struct {
	// Allowed reports whether traffic to the peer address is permitted.
	Allowed bool
	// Reason is a human readable explanation, useful for audit logs.
	Reason string
	// Addr is the canonical form of the evaluated address.
	Addr netip.Addr
}

// New parses the policy mode and explicit deny/allow CIDRs.
//
// Deny CIDRs are always enforced (even in allow-all mode) and take
// precedence over everything else. Allow CIDRs exempt addresses from the
// mode based defaults. Warnings are returned for allow CIDRs that overlap
// categories that remain dangerous in private mode, as such an exemption
// is usually an SSRF footgun.
func New(modeName string, denyCIDRs, allowCIDRs []string) (*Policy, []string, error) {
	mode := Mode(modeName)
	if mode != ModePublic && mode != ModePrivate && mode != ModeAllowAll {
		return nil, nil, fmt.Errorf("invalid egress policy %q: must be one of %s, %s, %s",
			modeName, ModePublic, ModePrivate, ModeAllowAll)
	}

	deny, err := parsePrefixes(denyCIDRs, "SCREEGO_TURN_DENY_PEERS")
	if err != nil {
		return nil, nil, err
	}
	allow, err := parsePrefixes(allowCIDRs, "SCREEGO_TURN_ALLOW_PEERS")
	if err != nil {
		return nil, nil, err
	}

	p := &Policy{mode: mode, deny: deny, allow: allow}

	var warnings []string
	for _, a := range allow {
		for _, r := range builtinRules {
			if r.kind == kindDangerous && a.Overlaps(r.prefix) {
				warnings = append(warnings, fmt.Sprintf(
					"SCREEGO_TURN_ALLOW_PEERS %s exempts %s addresses; this can enable SSRF through TURN",
					a, r.cat))
			}
		}
	}
	return p, warnings, nil
}

func parsePrefixes(cidrs []string, setting string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid %s %q: %w", setting, cidr, err)
		}
		prefixes = append(prefixes, p.Masked())
	}
	return prefixes, nil
}

// Mode returns the configured egress mode.
func (p *Policy) Mode() Mode {
	return p.mode
}

// AllowsIP reports whether traffic to the given IP is permitted.
func (p *Policy) AllowsIP(ip net.IP) bool {
	return p.Evaluate(ip).Allowed
}

// Evaluate canonicalizes the given IP and applies the policy to it.
func (p *Policy) Evaluate(ip net.IP) Decision {
	addr, ok := canonicalize(ip)
	if !ok {
		return Decision{Allowed: false, Reason: "invalid peer address", Addr: netip.Addr{}}
	}
	return p.evaluate(addr)
}

// EvaluateAddr applies the policy to an already parsed address.
func (p *Policy) EvaluateAddr(addr netip.Addr) Decision {
	canonical, _ := canonicalize(addr.AsSlice())
	return p.evaluate(canonical)
}

func (p *Policy) evaluate(addr netip.Addr) Decision {
	for _, prefix := range p.deny {
		if prefix.Contains(addr) {
			return Decision{false, fmt.Sprintf("matched deny CIDR %s", prefix), addr}
		}
	}

	if p.mode == ModeAllowAll {
		return Decision{true, "allowed (allow-all mode)", addr}
	}

	for _, prefix := range p.allow {
		if prefix.Contains(addr) {
			return Decision{true, fmt.Sprintf("matched allow CIDR %s", prefix), addr}
		}
	}

	for _, r := range builtinRules {
		if r.prefix.Contains(addr) {
			if p.mode == ModePrivate && r.kind == kindPrivate {
				return Decision{true, fmt.Sprintf("private destination allowed (%s)", r.cat), addr}
			}
			return Decision{false, fmt.Sprintf("%s mode forbids %s destinations", p.mode, r.cat), addr}
		}
	}

	return Decision{true, "global unicast destination", addr}
}

// canonicalize converts an IP into the address representation that is
// actually classified. IPv4-mapped (::ffff:a.b.c) and deprecated
// IPv4-compatible (::a.b.c) IPv6 addresses are unwrapped to their embedded
// IPv4 address so they cannot bypass IPv4 rules; this is the canonical
// defense against the ::ffff:169.254.169.254 style of SSRF obfuscation.
func canonicalize(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()

	// Unwrap deprecated IPv4-compatible IPv6 addresses (::/96 except :: and
	// ::1, which are already classified on their own).
	if addr.Is6() && !addr.Is4In6() && !addr.IsUnspecified() && !addr.IsLoopback() {
		raw := addr.As16()
		if isZero(raw[:12]) {
			inner, ok := netip.AddrFromSlice(raw[12:])
			if ok {
				return inner.Unmap(), true
			}
		}
	}
	return addr, true
}

func isZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// Description renders an effective-policy summary for startup logs.
func (p *Policy) Description() string {
	return fmt.Sprintf("mode=%s deny=%d allow=%d", p.mode, len(p.deny), len(p.allow))
}
