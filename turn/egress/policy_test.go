package egress

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicy(t *testing.T) {
	type tc struct {
		ip      string
		public  bool
		private bool
		all     bool
		reason  string // substring expected when public/private denies
	}

	cases := []tc{
		// Global unicast is always permitted.
		{"8.8.8.8", true, true, true, ""},
		{"1.1.1.1", true, true, true, ""},
		{"2606:4700:4700::1111", true, true, true, ""},

		// SSRF basics: loopback / unspecified are blocked everywhere.
		{"127.0.0.1", false, false, true, "loopback"},
		{"127.255.255.255", false, false, true, "loopback"},
		{"0.0.0.0", false, false, true, "unspecified"},
		{"::1", false, false, true, "loopback"},
		{"::", false, false, true, "unspecified"},

		// Cloud metadata endpoints are blocked unless explicitly unsafe.
		{"169.254.169.254", false, false, true, "metadata"},
		{"169.254.1.2", false, false, true, "link-local"},
		{"100.100.100.200", false, false, true, "metadata"},
		{"fd00:ec2::254", false, false, true, "metadata"},
		{"fe80::1", false, false, true, "link-local"},

		// Private networks only in private mode.
		{"10.0.0.5", false, true, true, "private"},
		{"172.16.0.1", false, true, true, "private"},
		{"172.31.255.255", false, true, true, "private"},
		{"192.168.1.1", false, true, true, "private"},
		{"fd12:3456:789a::1", false, true, true, "unique-local"},
		{"100.64.0.1", false, true, true, "carrier-grade"},

		// Other special ranges are blocked in both safe modes.
		{"224.0.0.1", false, false, true, "multicast"},
		{"ff02::1", false, false, true, "multicast"},
		{"240.0.0.1", false, false, true, "reserved"},
		{"255.255.255.255", false, false, true, "broadcast"},
		{"198.18.0.1", false, false, true, "benchmark"},
		{"192.0.2.10", false, false, true, "documentation"},
		{"198.51.100.10", false, false, true, "documentation"},
		{"203.0.113.10", false, false, true, "documentation"},
		{"192.0.0.1", false, false, true, "reserved"},
		{"192.88.99.1", false, false, true, "reserved"},
		{"2001:db8::1", false, false, true, "documentation"},
		{"100::1", false, false, true, "discard"},
		{"fec0::1", false, false, true, "site-local"},
		{"2001:20::1", false, false, true, "ORCHID"},

		// IPv4-mapped IPv6 must be classified as the embedded IPv4.
		{"::ffff:169.254.169.254", false, false, true, "metadata"},
		{"::ffff:127.0.0.1", false, false, true, "loopback"},
		{"::ffff:10.0.0.1", false, true, true, "private"},
		{"::ffff:8.8.8.8", true, true, true, ""},

		// Deprecated IPv4-compatible IPv6 representation.
		{"::127.0.0.1", false, false, true, "loopback"},
		{"::169.254.169.254", false, false, true, "metadata"},
		{"::192.168.0.1", false, true, true, "private"},

		// Tunneling prefixes that embed/translate IPv4 destinations.
		{"2002:7f00:1::", false, false, true, "6to4"},
		{"2001:0:1234::1", false, false, true, "Teredo"},
		{"64:ff9b::a9fe:a9fe", false, false, true, "NAT64"}, // embedded 169.254.169.254
		{"64:ff9b:1::1", false, false, true, "NAT64"},
	}

	policies := map[Mode]*Policy{}
	for _, m := range []Mode{ModePublic, ModePrivate, ModeAllowAll} {
		p, warns, err := New(string(m), nil, nil)
		require.NoError(t, err)
		require.Empty(t, warns)
		policies[m] = p
	}

	for _, c := range cases {
		t.Run(c.ip, func(t *testing.T) {
			ip := net.ParseIP(c.ip)
			require.NotNil(t, ip)

			d := policies[ModePublic].Evaluate(ip)
			assert.Equal(t, c.public, d.Allowed, "public mode decision: %s", d.Reason)
			if !c.public {
				assert.Contains(t, d.Reason, c.reason)
			}
			assert.True(t, d.Addr.IsValid())

			d = policies[ModePrivate].Evaluate(ip)
			assert.Equal(t, c.private, d.Allowed, "private mode decision: %s", d.Reason)

			d = policies[ModeAllowAll].Evaluate(ip)
			assert.Equal(t, c.all, d.Allowed, "allow-all mode decision: %s", d.Reason)
		})
	}
}

func TestPolicyDenyAndAllowLists(t *testing.T) {
	p, _, err := New("public", []string{"8.8.8.8/32"}, []string{"10.0.0.0/8"})
	require.NoError(t, err)

	assert.False(t, p.AllowsIP(net.ParseIP("8.8.8.8")), "deny must win even for global addresses")
	assert.True(t, p.AllowsIP(net.ParseIP("10.0.0.1")), "allow must exempt private range in public mode")
	assert.False(t, p.AllowsIP(net.ParseIP("172.16.0.1")), "unlisted private range must still be blocked")
}

func TestPolicyAllowCannotOverrideDeny(t *testing.T) {
	p, _, err := New("public", []string{"10.0.0.0/24"}, []string{"10.0.0.0/24"})
	require.NoError(t, err)
	assert.False(t, p.AllowsIP(net.ParseIP("10.0.0.1")))
}

func TestNewValidation(t *testing.T) {
	_, _, err := New("bogus", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid egress policy")

	_, _, err = New("public", []string{"not-a-cidr"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SCREEGO_TURN_DENY_PEERS")

	_, _, err = New("public", nil, []string{"10.0.0.0/8", "bad"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SCREEGO_TURN_ALLOW_PEERS")
}

func TestAllowOverlapWarning(t *testing.T) {
	_, warns, err := New("public", nil, []string{"169.254.0.0/16"})
	require.NoError(t, err)
	require.Len(t, warns, 1)
	assert.Contains(t, warns[0], "SSRF")

	// Allowing ordinary private ranges is a supported use case, no warning.
	_, warns, err = New("public", nil, []string{"10.0.0.0/8"})
	require.NoError(t, err)
	assert.Empty(t, warns)
}

func TestEvaluateAddrAcceptsMapped(t *testing.T) {
	p, _, err := New("public", nil, nil)
	require.NoError(t, err)

	// netip.ParseAddr keeps the mapped form; EvaluateAddr must canonicalize.
	d := p.EvaluateAddr(netip.MustParseAddr("::ffff:169.254.169.254"))
	assert.False(t, d.Allowed)
	assert.True(t, d.Addr.Is4())
	assert.Equal(t, "169.254.169.254", d.Addr.String())

	d = p.EvaluateAddr(netip.MustParseAddr("2606:4700:4700::1111"))
	assert.True(t, d.Allowed)
}

func TestInvalidIP(t *testing.T) {
	p, _, err := New("public", nil, nil)
	require.NoError(t, err)

	d := p.Evaluate(net.IP{})
	assert.False(t, d.Allowed)
	assert.Contains(t, d.Reason, "invalid")
}
