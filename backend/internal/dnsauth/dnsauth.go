package dnsauth

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const QueryTimeout = 8 * time.Second

func BootstrapResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 4 * time.Second}
			var last error
			for _, dns := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
				c, err := d.DialContext(ctx, network, dns)
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		},
	}
}

func ResolverDialing(ips []string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 4 * time.Second}
			var last error
			for _, ip := range ips {
				c, err := d.DialContext(ctx, network, net.JoinHostPort(ip, "53"))
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		},
	}
}

type AuthDNS struct {
	Zone    string
	NSHosts []string
	NSIPs   []string
}

func (a *AuthDNS) NSLabel() string {
	if a == nil || len(a.NSHosts) == 0 {
		return ""
	}
	out := make([]string, 0, len(a.NSHosts))
	for _, h := range a.NSHosts {
		out = append(out, strings.TrimSuffix(h, "."))
	}
	return strings.Join(out, ", ")
}

func New(zone string) (*AuthDNS, error) {
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	if zone == "" {
		return nil, fmt.Errorf("empty zone")
	}
	ctx, cancel := context.WithTimeout(context.Background(), QueryTimeout)
	defer cancel()
	boot := BootstrapResolver()
	nsList, err := boot.LookupNS(ctx, zone)
	if err != nil {
		return nil, err
	}
	if len(nsList) == 0 {
		return nil, fmt.Errorf("no NS for %s", zone)
	}
	a := &AuthDNS{Zone: zone}
	seenIP := map[string]struct{}{}
	for _, ns := range nsList {
		host := strings.TrimSuffix(strings.ToLower(ns.Host), ".")
		if host == "" {
			continue
		}
		a.NSHosts = append(a.NSHosts, host)
		addrs, err := boot.LookupIPAddr(ctx, host)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := addr.IP.String()
			if ip == "" {
				continue
			}
			if _, ok := seenIP[ip]; ok {
				continue
			}
			seenIP[ip] = struct{}{}
			a.NSIPs = append(a.NSIPs, ip)
		}
	}
	if len(a.NSIPs) == 0 {
		return nil, fmt.Errorf("no NS addresses for %s", zone)
	}
	return a, nil
}

func (a *AuthDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if a != nil && len(a.NSIPs) > 0 {
		txts, err := ResolverDialing(a.NSIPs).LookupTXT(ctx, name)
		if err == nil {
			return txts, nil
		}
	}
	return BootstrapResolver().LookupTXT(ctx, name)
}

func (a *AuthDNS) LookupCNAME(ctx context.Context, name string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if a != nil && len(a.NSIPs) > 0 {
		cname, err := ResolverDialing(a.NSIPs).LookupCNAME(ctx, name)
		if err == nil {
			return cname, nil
		}
	}
	return BootstrapResolver().LookupCNAME(ctx, name)
}

func (a *AuthDNS) LookupIP(ctx context.Context, name string) ([]net.IP, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if a != nil && len(a.NSIPs) > 0 {
		addrs, err := ResolverDialing(a.NSIPs).LookupIPAddr(ctx, name)
		if err == nil {
			out := make([]net.IP, 0, len(addrs))
			for _, addr := range addrs {
				out = append(out, addr.IP)
			}
			return out, nil
		}
	}
	return BootstrapResolver().LookupIP(ctx, "ip", name)
}

func LookupTXT(ctx context.Context, zone, name string) ([]string, error) {
	a, err := New(zone)
	if err != nil {
		if ctx == nil {
			ctx = context.Background()
		}
		ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
		defer cancel()
		return BootstrapResolver().LookupTXT(ctx, strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), "."))
	}
	return a.LookupTXT(ctx, name)
}
