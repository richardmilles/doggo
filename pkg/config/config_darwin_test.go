//go:build darwin

package config

import (
	"reflect"
	"testing"
)

const sampleScutilOutput = `
DNS configuration

resolver #1
  search domain[0] : dove-climb.ts.net
  nameserver[0] : 100.100.100.100
  if_index : 34 (utun12)
  flags    : Supplemental, Request A records, Request AAAA records
  reach    : 0x00000003 (Reachable,Transient Connection)
  order    : 101200

resolver #2
  nameserver[0] : 1.1.1.1
  nameserver[1] : 8.8.8.8
  if_index : 14 (en0)
  flags    : Request A records
  reach    : 0x00000002 (Reachable)
  order    : 200000

resolver #3
  domain   : dove-climb.ts.net.
  nameserver[0] : 100.100.100.100
  if_index : 34 (utun12)
  flags    : Supplemental, Request A records, Request AAAA records
  reach    : 0x00000003 (Reachable,Transient Connection)
  order    : 101201

resolver #4
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

resolver #5
  domain   : 254.169.in-addr.arpa
  options  : mdns
  timeout  : 5
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)
  order    : 300200

resolver #6
  domain   : 8.e.f.ip6.arpa
  options  : mdns
  timeout  : 5
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)
  order    : 300400

resolver #7
  domain   : 9.e.f.ip6.arpa
  options  : mdns
  timeout  : 5
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)
  order    : 300600

resolver #8
  domain   : a.e.f.ip6.arpa
  options  : mdns
  timeout  : 5
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)
  order    : 300800

resolver #9
  domain   : b.e.f.ip6.arpa
  options  : mdns
  timeout  : 5
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)
  order    : 301000

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 1.1.1.1
  nameserver[1] : 8.8.8.8
  if_index : 14 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00000002 (Reachable)

resolver #2
  search domain[0] : dove-climb.ts.net
  nameserver[0] : 100.100.100.100
  if_index : 34 (utun12)
  flags    : Scoped, Request A records, Request AAAA records
  reach    : 0x00000003 (Reachable,Transient Connection)
`

func TestParseScutilOutputStopsAtScoped(t *testing.T) {
	resolvers, err := parseScutilOutput(sampleScutilOutput)
	if err != nil {
		t.Fatalf("parseScutilOutput error: %v", err)
	}

	if len(resolvers) != 9 {
		t.Fatalf("expected 9 resolvers before scoped section, got %d", len(resolvers))
	}

	if resolvers[8].number != 9 {
		t.Fatalf("expected last resolver to be #9, got #%d", resolvers[8].number)
	}
}

func TestFilterScutilResolvers(t *testing.T) {
	resolvers, err := parseScutilOutput(sampleScutilOutput)
	if err != nil {
		t.Fatalf("parseScutilOutput error: %v", err)
	}

	valid := make([]scutilResolver, 0)
	for _, r := range resolvers {
		if !isMDNS(r) && !isSupplemental(r) && !isDomainSpecific(r) && len(r.nameservers) > 0 {
			valid = append(valid, r)
		}
	}

	if len(valid) != 1 {
		t.Fatalf("expected 1 valid resolver, got %d", len(valid))
	}

	if valid[0].number != 2 {
		t.Fatalf("expected resolver #2 to remain, got #%d", valid[0].number)
	}

	gotNameservers := valid[0].nameservers
	wantNameservers := []string{"1.1.1.1", "8.8.8.8"}
	if !reflect.DeepEqual(gotNameservers, wantNameservers) {
		t.Fatalf("nameservers mismatch: got %v want %v", gotNameservers, wantNameservers)
	}
}

// TestParseScutilOutputIncludeSupplemental mirrors a Tailscale split-DNS layout
// (the same shape reported on real machines): the private 100.100.100.100 /
// fd7a:... resolvers are flagged Supplemental, while the only general resolver
// is public 8.8.8.8. With includeSupplemental, the Supplemental resolvers must
// survive (so the "internal" strategy can find them) while mDNS stays excluded.
func TestParseScutilOutputIncludeSupplemental(t *testing.T) {
	const tailscaleScutil = `
DNS configuration

resolver #1
  search domain[0] : tailedcc0.ts.net
  search domain[1] : home
  nameserver[0] : 100.100.100.100
  nameserver[1] : fd7a:115c:a1e0::53
  if_index : 19 (utun4)
  flags    : Supplemental, Request A records, Request AAAA records
  reach    : 0x00000003 (Reachable,Transient Connection)
  order    : 101200

resolver #2
  nameserver[0] : 8.8.8.8
  flags    : Request A records, Request AAAA records
  reach    : 0x00000002 (Reachable)
  order    : 200000

resolver #3
  domain   : tailedcc0.ts.net.
  nameserver[0] : 100.100.100.100
  nameserver[1] : fd7a:115c:a1e0::53
  if_index : 19 (utun4)
  flags    : Supplemental, Request A records, Request AAAA records
  reach    : 0x00000003 (Reachable,Transient Connection)
  order    : 101201

resolver #4
  domain   : local
  options  : mdns
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

DNS configuration (for scoped queries)
`
	resolvers, err := parseScutilOutput(tailscaleScutil)
	if err != nil {
		t.Fatalf("parseScutilOutput error: %v", err)
	}

	// Default (general queries only): just the public resolver #2 survives.
	general := filterResolvers(resolvers, false)
	if len(general) != 1 || general[0].number != 2 {
		t.Fatalf("includeSupplemental=false: expected only resolver #2, got %+v", general)
	}

	// Internal strategy source: Supplemental and domain-scoped resolvers are
	// kept (#1, #2, #3); only the mDNS resolver #4 is dropped.
	all := filterResolvers(resolvers, true)
	gotNumbers := make([]int, 0, len(all))
	for _, r := range all {
		gotNumbers = append(gotNumbers, r.number)
	}
	wantNumbers := []int{1, 2, 3}
	if !reflect.DeepEqual(gotNumbers, wantNumbers) {
		t.Fatalf("includeSupplemental=true: expected resolvers %v, got %v", wantNumbers, gotNumbers)
	}
}

func TestFilterDomainSpecificWithoutSupplementalFlag(t *testing.T) {
	input := `
DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 8.8.8.8
  nameserver[1] : 1.1.1.1
  flags    : Request A records
  reach    : 0x00000002 (Reachable)

resolver #2
  domain   : test
  nameserver[0] : 127.0.0.1
  flags    : Request A records, Request AAAA records
  reach    : 0x00030002 (Reachable,Local Address,Directly Reachable Address)

DNS configuration (for scoped queries)
`
	resolvers, err := parseScutilOutput(input)
	if err != nil {
		t.Fatalf("parseScutilOutput error: %v", err)
	}

	valid := make([]scutilResolver, 0)
	for _, r := range resolvers {
		if !isMDNS(r) && !isSupplemental(r) && !isDomainSpecific(r) && len(r.nameservers) > 0 {
			valid = append(valid, r)
		}
	}

	if len(valid) != 1 {
		t.Fatalf("expected 1 valid resolver (resolver #2 with domain:test should be filtered), got %d", len(valid))
	}

	if valid[0].number != 1 {
		t.Fatalf("expected resolver #1 to remain, got #%d", valid[0].number)
	}

	gotNameservers := valid[0].nameservers
	wantNameservers := []string{"8.8.8.8", "1.1.1.1"}
	if !reflect.DeepEqual(gotNameservers, wantNameservers) {
		t.Fatalf("nameservers mismatch: got %v want %v", gotNameservers, wantNameservers)
	}
}

// issue49Scutil mirrors the corporate split-DNS layout from #49: general
// resolvers would NXDOMAIN the private name, while Supplemental resolver #2
// for foo.tld answers via 10.100.0.2.
const issue49Scutil = `
DNS configuration

resolver #1
  search domain[0] : foo.tld
  search domain[3] : hq
  nameserver[0] : 192.168.1.87
  nameserver[1] : 192.168.1.1
  nameserver[2] : 8.8.8.8
  nameserver[3] : 1.1.1.1
  if_index : 13 (en4)
  flags    : Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : foo.tld
  nameserver[0] : 10.100.0.2
  flags    : Supplemental, Request A records
  reach    : 0x00000002 (Reachable)
  order    : 102600

DNS configuration (for scoped queries)

resolver #1
  search domain[0] : hq
  nameserver[0] : 192.168.1.87
  nameserver[1] : 192.168.1.1
  nameserver[2] : 8.8.8.8
  nameserver[3] : 1.1.1.1
  if_index : 13 (en4)
  flags    : Scoped, Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #3
  search domain[0] : foo.tld
  nameserver[0] : 10.100.0.2
  if_index : 26 (utun10)
  flags    : Scoped, Request A records
  reach    : 0x00000002 (Reachable)
`

func TestMatchDomainNameserversIssue49(t *testing.T) {
	resolvers, err := parseScutilOutput(issue49Scutil)
	if err != nil {
		t.Fatalf("parseScutilOutput error: %v", err)
	}

	ns, domains, ok := matchDomainNameservers([]string{"logikal.test.record.foo.tld"}, resolvers)
	if !ok {
		t.Fatal("expected domain match for foo.tld query")
	}
	if !reflect.DeepEqual(domains, []string{"foo.tld"}) {
		t.Fatalf("matched domains = %v, want [foo.tld]", domains)
	}
	if !reflect.DeepEqual(ns, []string{"10.100.0.2"}) {
		t.Fatalf("nameservers = %v, want [10.100.0.2]", ns)
	}

	// Scoped-section servers must never be selected via this path.
	for _, s := range ns {
		if s == "192.168.1.87" || s == "8.8.8.8" {
			t.Fatalf("unexpected general/scoped nameserver selected: %s", s)
		}
	}

	_, _, ok = matchDomainNameservers([]string{"example.com"}, resolvers)
	if ok {
		t.Fatal("example.com should not match foo.tld domain resolver")
	}
}

func TestMatchDomainNameserversLongestWins(t *testing.T) {
	input := `
DNS configuration

resolver #1
  nameserver[0] : 8.8.8.8
  flags    : Request A records

resolver #2
  domain   : example.com
  nameserver[0] : 10.0.0.1
  flags    : Supplemental, Request A records

resolver #3
  domain   : corp.example.com
  nameserver[0] : 10.0.0.2
  flags    : Supplemental, Request A records

DNS configuration (for scoped queries)
`
	resolvers, err := parseScutilOutput(input)
	if err != nil {
		t.Fatalf("parseScutilOutput error: %v", err)
	}

	ns, domains, ok := matchDomainNameservers([]string{"app.corp.example.com"}, resolvers)
	if !ok {
		t.Fatal("expected domain match")
	}
	if !reflect.DeepEqual(domains, []string{"corp.example.com"}) {
		t.Fatalf("matched domains = %v, want [corp.example.com]", domains)
	}
	if !reflect.DeepEqual(ns, []string{"10.0.0.2"}) {
		t.Fatalf("nameservers = %v, want [10.0.0.2]", ns)
	}
}
