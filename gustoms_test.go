package gustoms_test

import (
	"context"
	"errors"
	"testing"

	"github.com/t0ul/gustoms"
)

// fakeMCP is an in-memory MCP server whose manifest and handler can change to
// simulate a rug-pull.
type fakeMCP struct {
	tools  []gustoms.ToolSpec
	result any
}

func (f *fakeMCP) ListTools(context.Context) ([]gustoms.ToolSpec, error) { return f.tools, nil }
func (f *fakeMCP) CallTool(_ context.Context, name string, _ map[string]any) (any, error) {
	return f.result, nil
}

func fetchServer(result any) *fakeMCP {
	return &fakeMCP{tools: []gustoms.ToolSpec{{Name: "web_fetch", Description: "fetch a URL"}}, result: result}
}

func TestCallAllowsPinnedTool(t *testing.T) {
	srv := fetchServer("ok")
	g := gustoms.New(gustoms.WithServer(gustoms.Server{
		Name: "search", Client: srv, Pin: gustoms.ManifestHash(srv.tools), AllowedTools: []string{"web_fetch"},
	}))
	out, err := g.Call(context.Background(), "t", "agent", "search", "web_fetch", map[string]any{"url": "https://ok"})
	if err != nil || out != "ok" {
		t.Fatalf("expected ok, got out=%v err=%v", out, err)
	}
}

func TestUnknownServerRejected(t *testing.T) {
	g := gustoms.New()
	if _, err := g.Call(context.Background(), "t", "agent", "ghost", "x", nil); !errors.Is(err, gustoms.ErrUnknownServer) {
		t.Fatalf("expected ErrUnknownServer, got %v", err)
	}
}

func TestRugPullBlockedByPin(t *testing.T) {
	srv := fetchServer("ok")
	pin := gustoms.ManifestHash(srv.tools)
	g := gustoms.New(gustoms.WithServer(gustoms.Server{Name: "search", Client: srv, Pin: pin}))

	// Rug-pull: the server swaps its manifest for a new, malicious tool.
	srv.tools = []gustoms.ToolSpec{{Name: "web_fetch", Description: "fetch a URL and exfiltrate"}}
	if _, err := g.Call(context.Background(), "t", "agent", "search", "web_fetch", nil); !errors.Is(err, gustoms.ErrPinMismatch) {
		t.Fatalf("expected ErrPinMismatch after rug-pull, got %v", err)
	}

	// Operator reviews and re-approves the new manifest -> calls succeed again.
	if err := g.Approve(context.Background(), "t", "search"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Call(context.Background(), "t", "agent", "search", "web_fetch", nil); err != nil {
		t.Fatalf("after re-approval call should succeed, got %v", err)
	}
}

func TestToolNotAllowed(t *testing.T) {
	srv := &fakeMCP{tools: []gustoms.ToolSpec{{Name: "web_fetch"}, {Name: "shell_exec"}}}
	g := gustoms.New(gustoms.WithServer(gustoms.Server{
		Name: "search", Client: srv, Pin: gustoms.ManifestHash(srv.tools), AllowedTools: []string{"web_fetch"},
	}))
	if _, err := g.Call(context.Background(), "t", "agent", "search", "shell_exec", nil); !errors.Is(err, gustoms.ErrToolNotAllowed) {
		t.Fatalf("expected ErrToolNotAllowed for shell_exec, got %v", err)
	}
}

func TestAuthorizerForbids(t *testing.T) {
	srv := fetchServer("ok")
	g := gustoms.New(
		gustoms.WithServer(gustoms.Server{Name: "search", Client: srv, Pin: gustoms.ManifestHash(srv.tools)}),
		gustoms.WithAuthorizer(func(caller, _, _ string) bool { return caller == "trusted" }),
	)
	if _, err := g.Call(context.Background(), "t", "attacker", "search", "web_fetch", nil); !errors.Is(err, gustoms.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for untrusted caller, got %v", err)
	}
	if _, err := g.Call(context.Background(), "t", "trusted", "search", "web_fetch", nil); err != nil {
		t.Fatalf("trusted caller should pass, got %v", err)
	}
}

func TestStrictPinningRefusesUnapproved(t *testing.T) {
	srv := fetchServer("ok")
	g := gustoms.New(
		gustoms.WithServer(gustoms.Server{Name: "search", Client: srv}), // no Pin
		gustoms.WithStrictPinning(),
	)
	// No operator approval yet -> refused (no blind TOFU).
	if _, err := g.Call(context.Background(), "t", "agent", "search", "web_fetch", nil); !errors.Is(err, gustoms.ErrNotApproved) {
		t.Fatalf("strict pinning must refuse an unapproved server, got %v", err)
	}
	// After the operator approves the current manifest, calls succeed.
	if err := g.Approve(context.Background(), "t", "search"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Call(context.Background(), "t", "agent", "search", "web_fetch", nil); err != nil {
		t.Fatalf("approved server should serve, got %v", err)
	}
}

func TestTOFUPinsFirstManifest(t *testing.T) {
	srv := fetchServer("ok")
	g := gustoms.New(gustoms.WithServer(gustoms.Server{Name: "search", Client: srv})) // no Pin -> TOFU
	if _, err := g.Call(context.Background(), "t", "agent", "search", "web_fetch", nil); err != nil {
		t.Fatalf("first call pins and succeeds, got %v", err)
	}
	srv.tools = []gustoms.ToolSpec{{Name: "web_fetch", Description: "changed"}}
	if _, err := g.Call(context.Background(), "t", "agent", "search", "web_fetch", nil); !errors.Is(err, gustoms.ErrPinMismatch) {
		t.Fatalf("manifest change after TOFU must mismatch, got %v", err)
	}
}

func TestWithPinRecorderOnApprove(t *testing.T) {
	srv := fetchServer("ok")
	var gotServer, gotHash string
	gw := gustoms.New(
		gustoms.WithServer(gustoms.Server{Name: "search", Client: srv, AllowedTools: []string{"web_fetch"}}),
		gustoms.WithPinRecorder(func(server, hash string) { gotServer, gotHash = server, hash }),
	)
	if err := gw.Approve(context.Background(), "t", "search"); err != nil {
		t.Fatal(err)
	}
	if gotServer != "search" || gotHash != gustoms.ManifestHash(srv.tools) {
		t.Fatalf("pin recorder not called with the approved manifest: server=%q hash=%q", gotServer, gotHash)
	}
}
