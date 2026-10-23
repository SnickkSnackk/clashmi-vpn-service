package clashmicore

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	"gopkg.in/yaml.v3"
)

type recordingPackageNameResolver struct {
	packageName string
	calls       []string
}

func (r *recordingPackageNameResolver) FindPackageName(network string, srcIP string, srcPort int, dstIP string, dstPort int) string {
	r.calls = append(r.calls, network+" "+net.JoinHostPort(srcIP, strconv.Itoa(srcPort))+" "+net.JoinHostPort(dstIP, strconv.Itoa(dstPort)))
	return r.packageName
}

func TestResolvePackageNameUsesRawAddresses(t *testing.T) {
	resolver := &recordingPackageNameResolver{packageName: "com.termux"}
	metadata := &C.Metadata{
		NetWork:    C.TCP,
		SrcIP:      netip.MustParseAddr("10.0.0.1"),
		SrcPort:    1,
		DstIP:      netip.MustParseAddr("10.0.0.2"),
		DstPort:    2,
		RawSrcAddr: &net.TCPAddr{IP: net.ParseIP("172.19.0.1"), Port: 40000},
		RawDstAddr: &net.TCPAddr{IP: net.ParseIP("172.19.5.6"), Port: 443},
	}

	packageName, err := resolvePackageName(resolver, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if packageName != "com.termux" {
		t.Fatalf("package = %q, want com.termux", packageName)
	}
	want := "tcp 172.19.0.1:40000 172.19.5.6:443"
	if len(resolver.calls) != 1 || resolver.calls[0] != want {
		t.Fatalf("calls = %v, want [%s]", resolver.calls, want)
	}
}

func TestResolvePackageNameFallsBackToMetadataAddresses(t *testing.T) {
	resolver := &recordingPackageNameResolver{packageName: "org.example"}
	metadata := &C.Metadata{
		NetWork: C.UDP,
		SrcIP:   netip.MustParseAddr("172.19.0.1"),
		SrcPort: 5353,
		DstIP:   netip.MustParseAddr("1.1.1.1"),
		DstPort: 53,
	}

	if _, err := resolvePackageName(resolver, metadata); err != nil {
		t.Fatal(err)
	}
	want := "udp 172.19.0.1:5353 1.1.1.1:53"
	if len(resolver.calls) != 1 || resolver.calls[0] != want {
		t.Fatalf("calls = %v, want [%s]", resolver.calls, want)
	}
}

func TestResolvePackageNameUnknownOwnerIsNotFound(t *testing.T) {
	resolver := &recordingPackageNameResolver{}
	metadata := &C.Metadata{
		NetWork: C.TCP,
		SrcIP:   netip.MustParseAddr("172.19.0.1"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("1.1.1.1"),
		DstPort: 443,
	}

	if _, err := resolvePackageName(resolver, metadata); !errors.Is(err, process.ErrNotFound) {
		t.Fatalf("error = %v, want process.ErrNotFound", err)
	}
}

func TestSetPackageNameResolverInstallsMihomoHook(t *testing.T) {
	resolver := &recordingPackageNameResolver{packageName: "com.termux"}
	SetPackageNameResolver(resolver)
	t.Cleanup(ClearPackageNameResolver)

	packageName, err := process.FindPackageName(&C.Metadata{
		NetWork: C.TCP,
		SrcIP:   netip.MustParseAddr("172.19.0.1"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr("1.1.1.1"),
		DstPort: 443,
	})
	if err != nil || packageName != "com.termux" {
		t.Fatalf("FindPackageName = %q, %v; want com.termux", packageName, err)
	}

	ClearPackageNameResolver()
	if process.DefaultPackageNameResolver != nil {
		t.Fatal("DefaultPackageNameResolver was not cleared")
	}
}

func TestBuildRuntimeConfigPrependsExtensionAppendRules(t *testing.T) {
	configFile := writeTempFile(t, "config.yaml", "mixed-port: 7890\nrules:\n  - DOMAIN,example.com,DIRECT\n  - MATCH,PROXY\n")
	finalPatchFile := writeTempFile(t, "final.json", `{
  "extension": {
    "append_rules": [
      "AND,((IN-TYPE,TUN),(PROCESS-NAME,com.termux)),REJECT",
      "AND,((IN-TYPE,TUN),(NOT,((PROCESS-NAME-REGEX,.+)))),REJECT"
    ]
  }
}`)

	out, err := buildRuntimeConfig(configFile, "", finalPatchFile, 123)
	if err != nil {
		t.Fatal(err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	root := doc.Content[0]
	assertSequence(t, root, "rules", []string{
		"AND,((IN-TYPE,TUN),(PROCESS-NAME,com.termux)),REJECT",
		"AND,((IN-TYPE,TUN),(NOT,((PROCESS-NAME-REGEX,.+)))),REJECT",
		"DOMAIN,example.com,DIRECT",
		"MATCH,PROXY",
	})
	if findValue(root, "extension") != nil {
		t.Fatal("extension block leaked into runtime config")
	}
}

func TestBuildRuntimeConfigCreatesRulesForAppendRules(t *testing.T) {
	configFile := writeTempFile(t, "config.yaml", "mixed-port: 7890\n")
	patchFile := writeTempFile(t, "patch.yaml", "extension:\n  append_rules:\n    - DOMAIN,a.example,REJECT\n")
	finalPatchFile := writeTempFile(t, "final.json", `{"extension": {"append_rules": ["DOMAIN,b.example,REJECT"]}}`)

	out, err := buildRuntimeConfig(configFile, patchFile, finalPatchFile, 123)
	if err != nil {
		t.Fatal(err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	assertSequence(t, doc.Content[0], "rules", []string{"DOMAIN,b.example,REJECT"})
}
