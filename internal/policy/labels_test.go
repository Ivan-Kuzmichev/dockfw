package policy

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestParseLabelsValid(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   Spec
	}{
		{
			name:   "no labels",
			labels: map[string]string{"com.docker.compose.service": "x"},
			want:   Spec{Mode: ModeEnforce},
		},
		{
			name:   "enable only",
			labels: map[string]string{"fw.enable": "true"},
			want:   Spec{Enabled: true, Mode: ModeEnforce, HasLabels: true},
		},
		{
			name:   "enable false",
			labels: map[string]string{"fw.enable": "false"},
			want:   Spec{Mode: ModeEnforce, HasLabels: true},
		},
		{
			name: "full",
			labels: map[string]string{
				"fw.enable":           "TRUE",
				"fw.allow.containers": " qbittorrent , torrents/jackett,,qbittorrent ",
				"fw.allow.domains":    "API.themoviedb.org., *.tmdb.org",
				"fw.allow.internet":   "false",
				"fw.allow.cidrs":      "192.168.1.5/32, 10.8.0.7/24, 192.168.1.9",
				"fw.inbound":          "192.168.1.0/24:8787, any:54890/udp, ANY:53/TCP, 10.0.0.1:22",
				"fw.mode":             "Audit",
			},
			want: Spec{
				Enabled:    true,
				HasLabels:  true,
				Containers: []Ref{{Name: "qbittorrent"}, {Project: "torrents", Name: "jackett"}},
				Domains:    []string{"*.tmdb.org", "api.themoviedb.org"},
				CIDRs: []netip.Prefix{
					netip.MustParsePrefix("10.8.0.0/24"),
					netip.MustParsePrefix("192.168.1.5/32"),
					netip.MustParsePrefix("192.168.1.9/32"),
				},
				Inbound: []Inbound{
					{Source: netip.MustParsePrefix("10.0.0.1/32"), Port: 22, Proto: ProtoAny},
					{Source: netip.MustParsePrefix("192.168.1.0/24"), Port: 8787, Proto: ProtoAny},
					{Any: true, Port: 53, Proto: ProtoTCP},
					{Any: true, Port: 54890, Proto: ProtoUDP},
				},
				Mode: ModeAudit,
			},
		},
		{
			name:   "internet, boundary ports",
			labels: map[string]string{"fw.enable": "1", "fw.allow.internet": "true", "fw.inbound": "0.0.0.0/0:1,any:65535"},
			want: Spec{
				Enabled: true, HasLabels: true, Internet: true, Mode: ModeEnforce,
				Inbound: []Inbound{
					{Source: netip.MustParsePrefix("0.0.0.0/0"), Port: 1, Proto: ProtoAny},
					{Any: true, Port: 65535, Proto: ProtoAny},
				},
			},
		},
		{
			name:   "empty lists",
			labels: map[string]string{"fw.enable": "true", "fw.allow.containers": "", "fw.inbound": " , "},
			want:   Spec{Enabled: true, HasLabels: true, Mode: ModeEnforce},
		},
		{
			name:   "other prefix ignored",
			labels: map[string]string{"fwx.enable": "true", "traefik.enable": "true"},
			want:   Spec{Mode: ModeEnforce},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseLabels("fw.", tt.labels)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestParseLabelsInvalid(t *testing.T) {
	tests := []struct {
		label, value, wantErr string
	}{
		{"fw.enable", "yes", "must be true or false"},
		{"fw.allow.containers", "foo bar", "invalid container reference"},
		{"fw.allow.containers", "a/b/c", "invalid container reference"},
		{"fw.allow.containers", "a;rm -rf", "invalid container reference"},
		{"fw.allow.domains", "exa_mple.com", "invalid domain"},
		{"fw.allow.domains", "-bad.com", "invalid domain"},
		{"fw.allow.domains", "*", "invalid domain"},
		{"fw.allow.domains", "*.*.com", "invalid domain"},
		{"fw.allow.domains", "a..com", "invalid domain"},
		{"fw.allow.domains", "\"; drop", "invalid domain"},
		{"fw.allow.domains", strings.Repeat("a", 64) + ".com", "invalid domain"},
		{"fw.allow.internet", "sure", "must be true or false"},
		{"fw.allow.cidrs", "10.0.0.0/33", "invalid CIDR"},
		{"fw.allow.cidrs", "fc00::/7", "only IPv4"},
		{"fw.allow.cidrs", "printer", "invalid CIDR"},
		{"fw.inbound", "8080", "want <cidr|any>:<port>"},
		{"fw.inbound", "any:0", "invalid port"},
		{"fw.inbound", "any:65536", "invalid port"},
		{"fw.inbound", "any:http", "invalid port"},
		{"fw.inbound", "any:-1", "invalid port"},
		{"fw.inbound", "any:80/sctp", "invalid protocol"},
		{"fw.inbound", "lan:80", "invalid source"},
		{"fw.inbound", "::1:80", "invalid source"},
		{"fw.mode", "permissive", "must be \"enforce\" or \"audit\""},
		{"fw.allow.domain", "example.com", "unknown label"},
	}
	for _, tt := range tests {
		t.Run(tt.label+"="+tt.value, func(t *testing.T) {
			spec, err := ParseLabels("fw.", map[string]string{"fw.enable": "true", tt.label: tt.value})
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) || !strings.Contains(err.Error(), tt.label) {
				t.Errorf("error %q must mention %q and %q", err, tt.label, tt.wantErr)
			}
			if !spec.Enabled {
				t.Error("an invalid label must not disable protection")
			}
		})
	}
}

func TestParseLabelsCustomPrefix(t *testing.T) {
	spec, err := ParseLabels("dockfw.", map[string]string{"dockfw.enable": "true", "fw.enable": "garbage"})
	if err != nil || !spec.Enabled {
		t.Fatalf("spec=%+v err=%v", spec, err)
	}
}
