# MCP Tooling — Chrome & Burp

Two optional MCP servers extend the workspace beyond VPS CLI + WebFetch. Both run
**locally** on the user's machine. The VPS CLI stays the default workhorse; these are
role-specific.

---

## Usage policy (how we use them)

- **Chrome MCP — only when a real browser is genuinely needed.** Before using it, check
  whether the task actually requires a DOM + JS engine. Yes for: DOM XSS / postMessage /
  prototype-pollution / DOM-clobbering validation, SPA route & state discovery, and
  complex SSO/OAuth/MFA login flows. No for plain HTTP work — use curl/httpx on the VPS.
  Runs locally.
- **Burp MCP — for testing *possible* bugs.** When validating a candidate hypothesis
  needs hands-on request tampering (Repeater-style), drive it through Burp. **When a bug
  is confirmed, send its request/response to Burp** as the organized artifact.
- **Do NOT log everything to Burp.** Keep Burp to candidate and confirmed requests — not
  the recon firehose. The stored artifact in `raw/` / `findings/` remains the source of
  truth for every FACT (system prompt §2).
- Egress note: because these run locally, their traffic exits the **local IP**, not the
  VPS. The user has accepted this for interactive testing. If VPS-IP egress is ever
  required for a specific target, tunnel Burp/Chrome's upstream proxy through the VPS
  (`ssh -D 9090 <vps>` → SOCKS) — optional, not default.

---

## (a) Installation

### Burp MCP (official PortSwigger MCP server)
1. In Burp Suite: **Extensions → BApp Store → "MCP Server" → Install** (or enable it from
   Burp's settings if your version ships it built-in).
2. Open the **MCP** tab in Burp, **enable the server**, and note the local endpoint it
   shows (default is an SSE URL like `http://127.0.0.1:9876/sse` — confirm the exact
   port in the UI).
3. Register it with Claude Code (SSE transport):
   ```
   claude mcp add --transport sse burp http://127.0.0.1:9876/sse
   ```
   (If your Burp build exposes only a stdio proxy jar instead, use
   `claude mcp add burp java -jar /path/to/mcp-proxy.jar` per PortSwigger's docs.)

### Chrome MCP (Playwright MCP — drives a real Chromium)
```
claude mcp add chrome npx @playwright/mcp@0.0.78
```
- First run downloads the browser. It can run headed (visible, "simulate a human") or
  headless — pass Playwright MCP's `--headed` / viewport args if you want it visible.
- The workspace pins the reviewed version in `.mcp.json`. Upgrade deliberately after checking the
  upstream changelog; do not replace it with a floating `latest` tag in a published workspace.
- Alternative: Google's Chrome-DevTools MCP can be configured separately after pinning a reviewed
  version of that package.

### Scope
Add with `-s user` to make them available in every project, or `-s local` (default) for
just this workspace. Verify with `claude mcp list`; check health inside a session with
`/mcp`. Package names / Burp endpoint may change between versions — confirm against the
current PortSwigger and Playwright-MCP docs.

---

## Availability

If a session has neither connected, I fall back to VPS CLI + WebFetch and say so rather
than pretend a browser/Burp step ran. I check what's actually wired up before relying on
either (via tool discovery), never assume.
