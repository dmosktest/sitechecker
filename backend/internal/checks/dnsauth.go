package checks

import "sitechecker/internal/dnsauth"

type authDNS = dnsauth.AuthDNS

func newAuthDNS(zone string) (*authDNS, error) {
	return dnsauth.New(zone)
}
