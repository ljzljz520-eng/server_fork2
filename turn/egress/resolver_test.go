package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestResolverLiteral(t *testing.T) {
	p, _, err := New("public", nil, nil)
	require.NoError(t, err)
	r := NewResolver(p, nil)

	addrs, err := r.Resolve(context.Background(), "ip", "8.8.8.8")
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{addr("8.8.8.8")}, addrs)

	// IPv4-mapped literal must be canonicalized and then blocked.
	_, err = r.Resolve(context.Background(), "ip", "::ffff:169.254.169.254")
	require.Error(t, err)
	var denied *DeniedError
	require.True(t, errors.As(err, &denied))
	assert.True(t, errors.Is(err, ErrDenied))
	assert.Equal(t, "169.254.169.254", denied.Addr.String())

	_, err = r.Resolve(context.Background(), "ip", "169.254.169.254")
	require.True(t, errors.Is(err, ErrDenied))

	_, err = r.Resolve(context.Background(), "ip4", "2606:4700:4700::1111")
	require.Error(t, err)

	_, err = r.Resolve(context.Background(), "ip6", "8.8.8.8")
	require.Error(t, err)
}

func TestResolverHostname(t *testing.T) {
	good := []netip.Addr{addr("1.2.3.4"), addr("5.6.7.8")}
	mixed := []netip.Addr{addr("1.2.3.4"), addr("169.254.169.254")}
	allBad := []netip.Addr{addr("127.0.0.1")}

	p, _, err := New("public", nil, nil)
	require.NoError(t, err)

	r := NewResolver(p, func(_ context.Context, _, host string) ([]netip.Addr, error) {
		switch host {
		case "good.example":
			return good, nil
		case "mixed.example":
			return mixed, nil
		case "bad.example":
			return allBad, nil
		case "empty.example":
			return nil, nil
		default:
			return nil, &net.DNSError{IsNotFound: true, Name: host}
		}
	})

	addrs, err := r.Resolve(context.Background(), "ip", "good.example")
	require.NoError(t, err)
	assert.Equal(t, good, addrs)

	// Fail closed when a single record points at a blocked destination.
	for _, host := range []string{"mixed.example", "bad.example"} {
		_, err = r.Resolve(context.Background(), "ip", host)
		require.Error(t, err, host)
		assert.True(t, errors.Is(err, ErrDenied), host)
	}

	_, err = r.Resolve(context.Background(), "ip", "unknown.example")
	require.Error(t, err)

	_, err = r.Resolve(context.Background(), "ip", "empty.example")
	require.Error(t, err)
}

func TestGuardedDialerPinsValidatedIP(t *testing.T) {
	p, _, err := New("public", nil, nil)
	require.NoError(t, err)

	var dialed []string
	r := NewResolver(p, func(_ context.Context, network, host string) ([]netip.Addr, error) {
		assert.Equal(t, "ip4", network)
		assert.Equal(t, "internal.example", host)
		return []netip.Addr{addr("1.2.3.4"), addr("8.8.8.8")}, nil
	})

	d := &GuardedDialer{
		Resolver: r,
		Dial: func(_ context.Context, network, address string) (net.Conn, error) {
			assert.Equal(t, "tcp4", network)
			dialed = append(dialed, address)
			if len(dialed) == 1 {
				return nil, errors.New("first endpoint down")
			}
			return nil, nil // nil conn is enough for this test's bookkeeping
		},
	}

	_, _ = d.DialContext(context.Background(), "tcp4", "internal.example:443")

	// The dialer must dial validated IP literals and must never hand the
	// hostname back to a resolver during dialing.
	require.Equal(t, []string{"1.2.3.4:443", "8.8.8.8:443"}, dialed)
}

func TestGuardedDialerBlocksMetadataLiteral(t *testing.T) {
	p, _, err := New("public", nil, nil)
	require.NoError(t, err)

	d := &GuardedDialer{Resolver: NewResolver(p, nil)}
	_, err = d.DialContext(context.Background(), "tcp", "169.254.169.254:80")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDenied))
}

func TestGuardedDialerRejectsRebindingHostname(t *testing.T) {
	p, _, err := New("public", nil, nil)
	require.NoError(t, err)

	r := NewResolver(p, func(_ context.Context, _, _ string) ([]netip.Addr, error) {
		return []netip.Addr{addr("1.1.1.1"), addr("100.100.100.200")}, nil
	})

	called := false
	d := &GuardedDialer{
		Resolver: r,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			called = true
			return nil, nil
		},
	}
	_, err = d.DialContext(context.Background(), "tcp", "rebind.example:80")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDenied))
	assert.False(t, called, "no dial attempt must happen for a denied record set")
}
