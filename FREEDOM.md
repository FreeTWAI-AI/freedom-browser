# Freedom Browser (自由工坊 neo client)

This repository is `FreeTWAI-AI/freedom-browser`, a public fork of
[browseros-ai/BrowserOS](https://github.com/browseros-ai/BrowserOS)
(upstream repository id `985839104`). It is licensed under the GNU Affero
General Public License version 3 or later (AGPL-3.0-or-later). Upstream
license and notice files are kept as they were received. See `freedom/upstream.lock.json`
for the adopted base and the preserved notice list.

`main` is the Freedom integration branch. The managed-mode work on
`feat/client-b1-managed-guard` starts from the adopted upstream commit
`671b9a956eb4aaba42760b7eda754b9ba56191cd`. The research pin
`53c3799ce014e9fee05569802314a05d0bad3e40` is an ancestor of that commit.
A newer upstream SHA needs the coverage in `freedom/patch-inventory.json`
to be run again.

## Modes

Standalone is the default. It keeps the upstream BrowserOS neo server
behavior: local MCP and HTTP routes are not gated by a Freedom run context.

Managed mode is chosen only when the process starts, by `--freedom-managed`
together with `--freedom-profile <dir>`, or by the sidecar `freedom` object.
The managed profile must be a different directory from the standalone default
(`~/.browserclaw`, or `~/.browserclaw-dev` when dev mode is on). The process
creates that directory, resolves both paths with `std::fs::canonicalize`
(a missing tail is rebuilt from the deepest existing ancestor; any other
resolution failure refuses startup), and rejects a profile that equals,
contains, or sits inside the standalone tree after symlink resolution, in
either direction. It then writes `freedom-managed-profile.json`. If that
marker file exists, the directory is managed even when the bytes are not
valid JSON. An unreadable marker is an error. Only a missing file is
standalone. A later standalone start refuses to open a marked directory.

Managed mode cannot be switched or relaxed through the settings HTTP route,
an MCP tool, or a runtime config edit. There is no platform client in this
tree. Tests use an in-process verifier. Nothing here dials `freetwai.com`.

In managed mode every tool or route that can read a page or cause an effect
goes through one guard: native or MCP authentication, a bound attempt, schema
and scheme checks, a domain and target check, then begin, execute, observation,
and receipt. A missing context is a denial. It does not fall through to the
upstream unrestricted path. Raw `run`, `evaluate`, script hooks, and helper
execution are denied on the dispatch path, not only hidden from the catalog.
`/freedom/v1/*` is loopback-only, with a per-process native token and a
single-use nonce. The listener binds `127.0.0.1` and is not bound to `0.0.0.0`.

`tabs` `list` is answered from the granted page ids and does not call
upstream. `tabs` `active` and `tabs` `new` are denied as unscoped reads
before execute, so a new tab cannot join a caller `groupId` or snapshot a
page outside the grant. `tabs` `close` still requires a page id inside the
grant. Managed `request_human_help` requires a page id inside the grant and
records that page's url, title, and browser tab id. It does not read the
cockpit's active tab. Standalone still pins the session's most recently
active owned tab.

Managed navigation URLs are an allowlist. The check trims the argument,
strips one leading `view-source:` wrapper, and then allows only `http:` and
`https:` URLs and the exact URL `about:blank`. It covers every tool argument
that carries a navigation URL, including `navigate` and `tabs` `new`.
Standalone `navigate` keeps the upstream scheme refusal and its English
error text.

This client does not mark a Freedom business effect as accepted. Cancellation
uses the client cancel token and the operator stop flag. Result text and
error text are not scanned. A normal page result that contains
`Operation cancelled by the User` is not a cancel. A success that returns
after the client has cancelled, or after the operator requested a stop, is
an audit record only and is not accepted.

## AGPL

The AGPL-3.0-or-later obligations that are visible from this tree:

- The program is offered under the AGPL. Corresponding source for this fork
  is the public repository itself.
- Copyright and license notices that came from upstream are preserved,
  including `LICENSE`, `LICENSE.ungoogled_chromium`, `CLA.md`, and the license
  files under `packages/`.
- New Freedom source files carry a prominent notice that they are Freedom
  modifications (AGPL section 5(a)), dated 2026-10-06.
- Network use of a modified version can trigger the AGPL's source-offer duty.
  No Freedom release, signing, or store distribution exists yet, so this tree
  does not ship a binary offer or a store listing.

## 自由工坊（摘要）

這是 BrowserOS 的公開分叉，授權為 AGPL-3.0-or-later。預設是獨立模式，行為與上游相同。受管理模式只能在行程啟動時選定，使用另外的資料目錄，執行中不能透過設定或 MCP 放寬。沒有自由工坊上下文時，讀取與操作都會被拒絕，不會退回上游的未限制路徑。分頁 `active` 與 `new` 會被拒絕；`close` 仍需要範圍內的分頁。請求人工協助必須指定本次連接範圍內的分頁，不會改釘在目前作用中的分頁。網址只允許 `http`、`https` 與 `about:blank`。取消以用戶端憑證與操作者停止為準，不依結果文字判斷。任意程式碼執行在受管理模式被拒絕。本機 `/freedom/v1` 只聽 `127.0.0.1`。目前沒有自由工坊的正式發行、簽章或商店上架。
