# Patch inventory

Adopted base: `671b9a956eb4aaba42760b7eda754b9ba56191cd`.

This list is the set of paths that differ from that commit. License and notice files are unchanged and are not listed. A newer upstream SHA needs this inventory and the managed-mode coverage tests to be run again.

| Path | Status | Purpose |
| --- | --- | --- |
| `FREEDOM.md` | new | Fork bookkeeping: upstream relationship, managed versus standalone mode, visible AGPL obligations, and the statement that no Freedom release exists yet. |
| `freedom/patch-inventory.json` | new | Machine-readable list of paths changed from the adopted base, with purpose and new-or-modified status. |
| `freedom/patch-inventory.md` | new | Readable patch inventory for the same paths as patch-inventory.json. |
| `freedom/upstream.lock.json` | new | Pins the upstream repository, research pin, adopted base, license expression, and preserved notice files. |
| `packages/browseros-agent/apps/claw-server-rust/src/api/http/mod.rs` | modified | Runs the managed-mode HTTP gate before handlers, adds loopback `/freedom/v1/status`, and stops wildcard CORS in managed mode. |
| `packages/browseros-agent/apps/claw-server-rust/src/api/http/settings.rs` | modified | Rejects settings writes that try to switch or relax managed mode, without applying the rest of that write. |
| `packages/browseros-agent/apps/claw-server-rust/src/api/mcp/dispatch.rs` | modified | Sends managed tool calls through the Freedom pipeline before the upstream guards, and denies raw `run`/`evaluate` again inside execution. |
| `packages/browseros-agent/apps/claw-server-rust/src/api/mcp/helper_runtime.rs` | modified | Denies nested helper execution in managed mode and skips helper preload and discovery. |
| `packages/browseros-agent/apps/claw-server-rust/src/api/mcp/mod.rs` | modified | Re-exports server-local MCP tool names so the coverage registry can see them. |
| `packages/browseros-agent/apps/claw-server-rust/src/api/mcp/script_hook.rs` | modified | Denies nested script primitives, helper reads, and page claims while the process is managed. |
| `packages/browseros-agent/apps/claw-server-rust/src/api/mcp/service.rs` | modified | Prechecks every MCP tool call before session resolution, and runs server-local tools through the same pipeline. |
| `packages/browseros-agent/apps/claw-server-rust/src/app.rs` | modified | Holds the process Freedom runtime, refuses to open a managed profile in standalone mode, and builds a managed state in its own directory. |
| `packages/browseros-agent/apps/claw-server-rust/src/config.rs` | modified | Adds the startup-only `--freedom-managed` and `--freedom-profile` flags and the default standalone directory helper. |
| `packages/browseros-agent/apps/claw-server-rust/src/freedom/context.rs` | new | Verifying constructor for `FreedomRunContext`. No `Default`, no public fields, and no deserializer. |
| `packages/browseros-agent/apps/claw-server-rust/src/freedom/guard.rs` | new | Managed-mode pipeline: auth, bound attempt, schema, target guard, begin, execute, observation, and receipt. |
| `packages/browseros-agent/apps/claw-server-rust/src/freedom/local_api.rs` | new | Loopback peer, Host, Origin, per-process native token, and single-use nonce checks for `/freedom/v1`. |
| `packages/browseros-agent/apps/claw-server-rust/src/freedom/mod.rs` | new | Process-wide Freedom runtime. Mode is fixed after startup and the journal never records business acceptance. |
| `packages/browseros-agent/apps/claw-server-rust/src/freedom/mode.rs` | new | Resolves managed versus standalone from the CLI and sidecar, and enforces a distinct managed profile. |
| `packages/browseros-agent/apps/claw-server-rust/src/freedom/registry.rs` | new | Coverage registry of HTTP routes, MCP tools, and native entry points with managed-mode treatment. |
| `packages/browseros-agent/apps/claw-server-rust/src/lib.rs` | modified | Declares the freedom module. |
| `packages/browseros-agent/apps/claw-server-rust/src/main.rs` | modified | Selects managed mode only at process start, binds `127.0.0.1`, and publishes the bound port for the Host allowlist. |
| `packages/browseros-agent/apps/claw-server-rust/tests/dependency_boundaries.rs` | modified | Admits `src/freedom` as its own layer. HTTP and MCP may call it. The guard cannot depend on HTTP, MCP, services, or the database. |
| `packages/browseros-agent/apps/claw-server-rust/tests/freedom_coverage.rs` | new | NEO-08 registry drift checks and the property test that every effect surface is denied without a context. |
| `packages/browseros-agent/apps/claw-server-rust/tests/freedom_managed.rs` | new | NEO-01, NEO-02, NEO-03, NEO-04, NEO-05, NEO-06, NEO-07, and NEO-12 integration cases, plus standalone unchanged. |
| `packages/browseros-agent/apps/claw-server-rust/tests/freedom_patch_inventory.rs` | new | Fails when the git diff against the adopted base and this inventory disagree. Uses local git only. |
