package enrich

import "testing"

func TestIdentifyService(t *testing.T) {
	cases := []struct {
		port     uint16
		proto    uint8
		name     string
		category string
		risk     string
	}{
		{port: 443, proto: 6, name: "HTTPS", category: "Web", risk: "low"},
		{port: 22, proto: 6, name: "SSH", category: "远程管理", risk: "high"},
		{port: 53, proto: 17, name: "DNS", category: "基础网络", risk: "low"},
		{port: 49152, proto: 6, name: "业务/动态端口", category: "业务服务", risk: "observe"},
	}
	for _, tc := range cases {
		got := IdentifyService(tc.port, tc.proto)
		if got.Name != tc.name || got.Category != tc.category || got.Risk != tc.risk {
			t.Fatalf("IdentifyService(%d, %d) = %+v", tc.port, tc.proto, got)
		}
	}
}
