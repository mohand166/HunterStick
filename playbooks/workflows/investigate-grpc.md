# Investigate a gRPC / protobuf Surface — the lens

> *A **lens**, not a vuln class. gRPC is a binary RPC transport over HTTP/2: it changes how you
> **address** the surface and how you **read the answer**, not what the bugs are. Every finding here
> belongs to a class file in `playbooks/vulns/`. Formerly the `grpc` **class** file; demoted to a
> lens because a vuln filed under a transport is only findable by someone who already knew to look
> there.*
>
> **What this file is for:** finding the surface, recovering the contract, the **`grpc-status`
> trailer oracle**, and **transcoding drift**. Then hand off. Work the actual class with
> `playbooks/vulns/_master-vuln-hunting.md` + that class's file.
>
> The crowd under-tests gRPC because of tooling friction. That is the opportunity — but it means a
> well-evidenced finding here has to be *evidenced*, since fewer people will recognise the shape.

---

## 1. Find the surface

Signals: `content-type: application/grpc` (also `-web`, `-web+proto`), HTTP/2-only hosts,
`grpc-status` trailers, ports like 50051, `envoy`/`linkerd` in `technologies.md`, `grpc-web` client
code in JS bundles, `.proto`-defined APIs behind mobile or desktop clients.

## 2. Recover the contract

- **Server reflection on** — enumerate services and methods **read-only**. Like GraphQL
  introspection this is a context probe, not a finding; "reflection enabled" alone is a weak,
  often-duplicate info leak. Its value is what it reveals as *callable from your position*.
- **Reflection off** — pull `.proto` files or descriptors from mobile app bundles, JS `grpc-web`
  stubs, repos (`repository-and-secret-recon`), or the transcoding gateway's generated OpenAPI.
- **Align your descriptor before you conclude anything.** Encoding and proto-mismatch errors are
  noise, not signal, and they are the single easiest way to mistake a working control for a broken
  one.

## 3. What is actually gRPC-specific

| mechanic | why it matters |
|---|---|
| **The `grpc-status` trailer is the oracle** | gRPC returns **HTTP 200 with an error trailer**. "200" means nothing here. A `PERMISSION_DENIED` / `UNAUTHENTICATED` trailer means authz is *working*. Read the trailer, always, and store it — it is the evidence. |
| **Per-*service* vs per-*method* authz** | a connection-level interceptor authenticates once; whether it authorizes *each method* is the whole question. This is the characteristic gRPC gap. |
| **Transcoding drift** | grpc-gateway / Envoy `grpc_json_transcoder` exposes the same methods over REST with a *different* middleware chain. Send the same logical call on both edges with the same low-priv identity; a difference in what's allowed is the bug. |
| **Unary vs streaming** | an interceptor may cover one call shape and not the other. |
| **`grpc-web` runs as the user** | requests you observe in the browser carry the user's own token. Seeing a field accepted there does **not** mean the server trusts it — reproduce deliberately. |

**Message fields are an input surface.** Every field in the request message is a candidate: ids,
tenant/role selectors, `is_admin`-style flags, resource paths, unexpected enum or `oneof` values.
Read the message definitions as you would a JSON body.

## 4. Route to the class

The `fix_locus` is the **individual RPC method or interceptor**, never "the gRPC service".

| you observe | class file |
|---|---|
| a method returns another tenant's or user's object for an id you supplied | `idor-bola.md` (**§I8** covers the transport specifics) |
| an internal/admin/provisioning method is reachable at all from the edge | `function-level-authorization.md` |
| the boundary that breaks is org/workspace | `multi-tenant-isolation.md` |
| a message field the server believes rather than re-validates (`role`, `is_admin`, `account_id`) | `mass-assignment.md` · `privilege-escalation.md` |
| a field reaching a query, shell, template or URL fetch | the matching injection class · `ssrf.md` |
| an unauthenticated caller reaching an authenticated method | `authentication-bypass.md` |
| the REST edge and the native edge disagree on who may call what | still an authz class — file it under the class the *gap* produces, with the drift as the root cause |

## 5. Safety specific to this transport

- **Never** send malformed floods, giant messages, or deeply nested protobufs to crash the server.
  Establishing a missing size/validation limit is the finding; DoS is off-limits.
- Prefer read-only methods. One record. Never enumerate or mutate at scale to size impact.
- **Store the trailer.** The artifact is the method name, the request message, the response
  *including `grpc-status`*, and the identity used. Without the trailer you cannot prove the call
  succeeded rather than being silently denied.
- **Ship the exact `grpcurl` invocation** (or the transcoded `curl`) **plus the role-correct control
  call** — reproducible in one action from a clean session.

## 6. Log it

Log to `tested.md` under the **class you tested**, with the entrypoint as the **RPC method** and the
principal column carrying the weight (low-priv · unauthenticated · role-correct). Do not log "grpc"
as a vuln class — it isn't one. Add `grpc` to that entrypoint's `properties` in `attack-surface.md`.
