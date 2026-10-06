// Package gustoms is an MCP (Model Context Protocol) gateway: the tool-plane
// twin of the LLM gateway. An agent never calls an MCP server directly; it calls
// through gustoms, which enforces a registry allowlist of approved servers, a
// content-hash pin on each server's tool manifest (so a silently changed tool —
// a rug-pull — is blocked until an operator re-approves), per-tool authorization
// at call time, and an audit record of every decision.
//
// The gateway is transport-agnostic: an MCP server is any Client (ListTools /
// CallTool). A concrete JSON-RPC-over-HTTP transport lives with the caller, so
// the policy logic here stays pure and testable.
package gustoms

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ToolSpec is one entry of an MCP server's advertised manifest (tools/list).
type ToolSpec struct {
	Name        string
	Description string
}

// Client is the minimal MCP surface the gateway drives.
type Client interface {
	ListTools(ctx context.Context) ([]ToolSpec, error)
	CallTool(ctx context.Context, name string, args map[string]any) (any, error)
}

// Server registers one approved MCP server.
type Server struct {
	Name         string
	Client       Client
	Pin          string   // expected manifest hash (hex); empty = trust-on-first-use, then locked
	AllowedTools []string // nil/empty = every tool the server advertises is allowed
}

// Authorizer decides whether caller may invoke tool on server. nil allows all.
type Authorizer func(caller, server, tool string) bool

// Auditor receives structured decisions (*gledger.AuditLog satisfies it).
type Auditor interface {
	Emit(traceID, span, event string, fields map[string]any) string
}

var (
	ErrUnknownServer  = errors.New("gustoms: server not in the allowlist")
	ErrPinMismatch    = errors.New("gustoms: tool manifest changed since approval (possible rug-pull); re-approval required")
	ErrToolNotAllowed = errors.New("gustoms: tool not permitted for this server")
	ErrForbidden      = errors.New("gustoms: caller not authorized for this tool")
)

// Gateway brokers calls to approved MCP servers.
type Gateway struct {
	mu      sync.Mutex
	servers map[string]*entry
	authz   Authorizer
	auditor Auditor
}

type entry struct {
	srv     Server
	pin     string
	allowed map[string]bool
}

// Option configures a Gateway.
type Option func(*Gateway)

// WithServer registers an approved MCP server.
func WithServer(s Server) Option {
	return func(g *Gateway) {
		allow := map[string]bool{}
		for _, t := range s.AllowedTools {
			allow[t] = true
		}
		g.servers[s.Name] = &entry{srv: s, pin: s.Pin, allowed: allow}
	}
}

// WithAuthorizer sets the call-time authorization check.
func WithAuthorizer(a Authorizer) Option { return func(g *Gateway) { g.authz = a } }

// WithAuditor attaches an audit sink.
func WithAuditor(a Auditor) Option { return func(g *Gateway) { g.auditor = a } }

// New builds a Gateway.
func New(opts ...Option) *Gateway {
	g := &Gateway{servers: map[string]*entry{}}
	for _, o := range opts {
		o(g)
	}
	return g
}

// ManifestHash is a deterministic hash of a tool manifest: the pin a server is
// approved against. Reordering tools does not change it; adding, removing, or
// re-describing a tool does.
func ManifestHash(tools []ToolSpec) string {
	lines := make([]string, len(tools))
	for i, t := range tools {
		lines[i] = t.Name + "\x1f" + t.Description
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\x1e")))
	return hex.EncodeToString(sum[:])
}

// Call is the only path to an MCP tool: allowlist -> manifest pin -> tool-allow
// -> authorize -> forward. Every outcome is audited under traceID.
func (g *Gateway) Call(ctx context.Context, traceID, caller, server, tool string, args map[string]any) (any, error) {
	g.mu.Lock()
	e, ok := g.servers[server]
	g.mu.Unlock()
	if !ok {
		g.audit(traceID, "deny", map[string]any{"reason": "unknown_server", "server": server, "caller": caller})
		return nil, fmt.Errorf("%w: %q", ErrUnknownServer, server)
	}

	tools, err := e.srv.Client.ListTools(ctx)
	if err != nil {
		g.audit(traceID, "error", map[string]any{"server": server, "error": err.Error()})
		return nil, fmt.Errorf("gustoms: list tools from %q: %w", server, err)
	}
	h := ManifestHash(tools)

	g.mu.Lock()
	if e.pin == "" {
		e.pin = h // trust-on-first-use: lock the manifest we first saw
		g.audit(traceID, "pin", map[string]any{"server": server, "hash": h[:12], "mode": "tofu"})
	}
	pinned := e.pin
	g.mu.Unlock()

	if h != pinned {
		g.audit(traceID, "deny", map[string]any{"reason": "pin_mismatch", "server": server, "want": pinned[:12], "got": h[:12]})
		return nil, ErrPinMismatch
	}

	if len(e.allowed) > 0 && !e.allowed[tool] {
		g.audit(traceID, "deny", map[string]any{"reason": "tool_not_allowed", "server": server, "tool": tool})
		return nil, fmt.Errorf("%w: %s/%s", ErrToolNotAllowed, server, tool)
	}
	// The tool must also actually exist in the (pinned) manifest.
	found := false
	for _, t := range tools {
		if t.Name == tool {
			found = true
			break
		}
	}
	if !found {
		g.audit(traceID, "deny", map[string]any{"reason": "unknown_tool", "server": server, "tool": tool})
		return nil, fmt.Errorf("%w: %s/%s", ErrToolNotAllowed, server, tool)
	}

	if g.authz != nil && !g.authz(caller, server, tool) {
		g.audit(traceID, "deny", map[string]any{"reason": "forbidden", "server": server, "tool": tool, "caller": caller})
		return nil, fmt.Errorf("%w: %s on %s/%s", ErrForbidden, caller, server, tool)
	}

	res, err := e.srv.Client.CallTool(ctx, tool, args)
	if err != nil {
		g.audit(traceID, "error", map[string]any{"server": server, "tool": tool, "error": err.Error()})
		return nil, err
	}
	g.audit(traceID, "call", map[string]any{"server": server, "tool": tool, "caller": caller})
	return res, nil
}

// Approve re-pins a server to its current manifest, the operator step after
// reviewing a legitimate tool change (rug-pull recovery).
func (g *Gateway) Approve(ctx context.Context, traceID, server string) error {
	g.mu.Lock()
	e, ok := g.servers[server]
	g.mu.Unlock()
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownServer, server)
	}
	tools, err := e.srv.Client.ListTools(ctx)
	if err != nil {
		return err
	}
	h := ManifestHash(tools)
	g.mu.Lock()
	e.pin = h
	g.mu.Unlock()
	g.audit(traceID, "approve", map[string]any{"server": server, "hash": h[:12]})
	return nil
}

func (g *Gateway) audit(traceID, event string, fields map[string]any) {
	if g.auditor != nil {
		g.auditor.Emit(traceID, "gustoms", event, fields)
	}
}
