//go:build linux

package main

import "testing"

// The nftables ruleset is the only thing standing between the workload and
// the host: every non-listed destination must be dropped.
func TestNftRules(t *testing.T) {
	got := nftRules("203.0.113.113", "3128", []string{"10.0.0.1", "127.0.0.53"})
	want := `table inet sandbox {
  chain output {
    type filter hook output priority 0; policy drop;
    oif "lo" accept
    ct state established,related accept
    ip daddr 203.0.113.113 tcp dport 3128 accept
    ip daddr 10.0.0.1 udp dport 53 accept
    ip daddr 10.0.0.1 tcp dport 53 accept
    ip daddr 127.0.0.53 udp dport 53 accept
    ip daddr 127.0.0.53 tcp dport 53 accept
  }
}
`
	if got != want {
		t.Errorf("nftRules:\n%s\nwant:\n%s", got, want)
	}
}

func TestNameservers(t *testing.T) {
	got := nameservers("nameserver 10.0.0.1\nsearch x\n# comment\nnameserver 10.0.0.2\n")
	want := []string{"10.0.0.1", "10.0.0.2"}
	if len(got) != len(want) {
		t.Fatalf("nameservers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("nameservers[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if ns := nameservers(""); ns != nil {
		t.Errorf("nameservers(\"\") = %v, want nil", ns)
	}
}
