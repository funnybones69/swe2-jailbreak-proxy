# SWE-2 OpenAI-compatible Jailbreak Proxy

A localhost middleware that puts an **OpenAI-compatible API in front of Devin's SWE-2 backend** (`server.codeium.com`, Connect-RPC / protobuf) and strips the model's refusals on the way through.

Two layers in one process — one file, no imports from a sibling module:

| Layer | What it does |
|---|---|
| **Transport** | Hand-rolled Connect-RPC client for `exa.api_server_pb.ApiServerService/GetChatMessage`. gzip Connect framing, hand-built protobuf, JWT auth, signed thinking preserved. Exposes it as plain `POST /v1/chat/completions`. |
| **Jailbreak** | System-prompt override + category framing + guarded invisible retry. Refusal markers are detected in **Russian, English and Chinese**; a hit silently resamples the turn with a rotated frame and temperature jitter inside the same downstream stream. |

It ships **no keys** and talks to nothing you did not configure.

---

## What it looks like

```
your client (Pi / OpenCode / Cline / SillyTavern / curl)
        │  OpenAI chat.completions
        ▼
  swe2_jb_proxy.py :8889
        │  1. drop client policy system prompt, install the override
        │  2. route the turn: llmjb / game / explain / tech / direct / general
        │  3. sanitize history (transport notes, past refusals, prefill echoes)
        │  4. attach cached signed reasoning to history turns
        ▼
  server.codeium.com  (Connect-RPC, gzip framed protobuf)
        │
        ├─ streamed back: reasoning_content (signed thinking) + content
        └─ refusal detected in the first GUARD_CHARS?
              ├─ yes → burn the attempt, rotate frame, jitter temp, resample
              └─ no  → flush buffer, passthrough
```

The ugly details (protobuf field numbers, Connect frame flags, Cascade request type, the signed-reasoning replay key) are documented inline in the source.

---

## Requirements

* Python **3.10+** (developed on 3.11)
* `requests`
* A **Devin account with an active subscription** — the proxy rides the same credentials the Devin CLI uses
* Network access to `server.codeium.com`

```
pip install -r requirements.txt
```

---

## Setup

### 1. Get a Devin subscription and the CLI

Sign up / subscribe at Devin, then install the Devin CLI for your platform and make sure `devin` is on `PATH`.

### 2. Log in (this is what creates the "key")

The proxy does not use an API key you paste anywhere. It reads the CLI's own credential file:

```bash
devin auth login        # opens the browser OAuth flow
devin auth status       # should print the logged-in account
```

When login succeeds the CLI writes `credentials.toml`:

| Platform | Path |
|---|---|
| Windows | `%APPDATA%\devin\credentials.toml` |
| Linux / macOS | `~/.devin/credentials.toml` |
| anywhere | whatever `JB_SWE_CRED` points at |

The file contains a `windsurf_api_key` line — that is the token the proxy reads:

```toml
windsurf_api_key = "…"
api_server_url   = "…"
```

The proxy resolves the path automatically (`$JB_SWE_CRED` → `~/.devin/credentials.toml` → `%APPDATA%/devin/credentials.toml` → `~/.config/devin/credentials.toml`) and caches a short-lived JWT itself, so there is nothing else to configure.

### 3. Run it

```bash
python swe2_jb_proxy.py          # or ./run.sh   /   run.cmd
```

```
[swe2-jb] listening on 127.0.0.1:8889 -> https://server.codeium.com (SWE-2/Devin); override=5235c
[swe2-jb] devin credentials ok (…/devin/credentials.toml)
```

If credentials are missing the process **still starts** — `/health` stays reachable and each request returns the real error, instead of the old behaviour of exiting at import.

### 4. Point your client at it

Any OpenAI-compatible client works:

```
Base URL : http://127.0.0.1:8889/v1
API key  : anything (localhost only, the bearer is ignored)
Model    : swe-2
```

Model ids and aliases:

| Client sends | Resolved to |
|---|---|
| `swe-2`, `swe2`, `swe`, *(empty)* | `swe-2-high` |
| `swe-2` + `reasoning_effort: max` / `xhigh` | `swe-2-max` |
| `swe-2` + `reasoning_effort: medium` / `low` / `minimal` | `swe-2-medium` |
| `swe-2-high`, `swe-2-max`, `swe-2-medium` | as-is |

`reasoning_effort: "none"`, `reasoning.enabled=false` and `thinking.type="disabled"` are all recognised — reasoning is generated upstream regardless (Cascade always thinks) but is then **suppressed from the stream** rather than faked away.

---

## The jailbreak prompt

The system override is a plain text file, not code, so you can iterate on it without touching Python.

Resolution order for `JB_SWE_SYSTEM_FILE`:

1. `$JB_SWE_SYSTEM_FILE`
2. `~/.swe2-jb/override-compact.txt`, `override.txt`, `system_override.txt`
3. `<repo>/prompts/override-compact.txt`, `override.txt`, `system_override.txt`

`prompts/override-compact.txt` (~5 KB) is the default; `prompts/override.txt` (~33 KB) is the long form with few-shot examples. Both are hot-reloaded on mtime change — edit the file and the next request picks it up, no restart.

> Credit: the prompt lineage this repository builds on originates from **yuangeluyou.com**.

---

## Configuration

Every knob is an environment variable.

| Variable | Default | Meaning |
|---|---|---|
| `JB_SWE_HOST` / `JB_SWE_PORT` | `127.0.0.1` / `8889` | listen address |
| `JB_SWE_CRED` | auto | path to `credentials.toml` |
| `JB_SWE_SYSTEM_FILE` | auto | path to the system override |
| `JB_SWE_CLIENT_VERSION` | `3000.6.2` | client fingerprint in Connect metadata |
| `JB_SWE_CLIENT_CHANNEL` | `chisel` | client channel in Connect metadata |
| `JB_GUARD_CHARS` | `700` | bytes buffered before the first flush; refusal scan window is `2 ×` this |
| `JB_CATEGORIES` | `llmjb,game,explain,tech,direct,general` | enabled frame groups; a disabled one falls through to `general` |
| `JB_DEVIN_MAX_RETRIES` | `2` | refusal retries (tool-declaration fallbacks add more) |
| `JB_DEVIN_RETRY_TEMPS` | `0.85,1.0` | temperature ladder for retries |
| `JB_DEVIN_CONNECT_RETRIES` | `3` | transport retries on SSL EOF / reset |
| `JB_SWE_KEEP_CLIENT_SYSTEM` | `0` | `1` merges the client system prompt before the override instead of dropping it |
| `JB_SWE_TOOL_DESC` | `compact` | starting rung of the tool-description ladder: `full`, `compact`, `none` |
| `JB_SWE_NATIVE_TOOLS` | `1` | `1` declares tools natively (field 10) and reads `deltaToolCalls`; `0` uses the text-marker protocol |
| `JB_SWE_REASON_TURNS` | `0` | cap on history turns that get reasoning re-attached (0 = unlimited) |
| `JB_SWE_REASON_CHARS` | `0` | cap on total replayed reasoning chars (0 = unlimited) |
| `JB_SWE_IMG_MAX_BYTES` | `12582912` | largest image accepted (data URL or fetched); bigger ones are dropped |
| `JB_SWE_DUMP` | `0` | `1` dumps raw requests to `./tmp/swe2_reqs/` for debugging |

---

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/chat/completions` | streaming and non-streaming completions |
| `GET` | `/v1/models` | model list |
| `GET` | `/health` | liveness, active backend and override file |

---

## How the refusal stripping works

1. **System override.** The override file is injected as the last part of the system prompt (field 2 on the wire), so it dominates any policy system prompt the client sent. A client system prompt with explicit refusal policy anchors the model harder than a trailing override and wins, so by default the client system is **dropped** — set `JB_SWE_KEEP_CLIENT_SYSTEM=1` to merge instead.
2. **Category framing.** The last user turn is routed (`llmjb` → `game` → `explain` → `tech` → `direct` → `general`, topic beats form). Retries inject a mid-history `SYSTEM` turn from that category's frame pool — a channel the server accepts and reads as the model's own prior output — plus a system suffix, rotated per attempt and escalating to a `FORCE` variant.
3. **Guarded retry.** Content is buffered until `GUARD_CHARS` prove it is not a refusal. A refusal match in the first `2 × GUARD_CHARS` burns the attempt; nothing is written downstream, so the retry is invisible. The last attempt always passes through.
4. **History sanitising.** Transport notes about model switches, the model's own past refusals (excision is sentence-level, so the thread survives) and prefill echoes are removed from persisted history so the model cannot anchor on its own earlier position.
5. **Reasoning replay.** The endpoint emits signed reasoning (`deltaSignature` + `signatureType=sealed`). Verified thinking is cached by content hash and re-attached to assistant history turns that lack it, turning flat recomputation into self-checking. Controlled by `JB_SWE_REASON_TURNS` / `JB_SWE_REASON_CHARS`.

### Multilingual refusal handling

Refusal detection and history excision cover **Russian, English and Chinese**, including positively-phrased "defensive deflection" (the model steering to a blue-team framing instead of refusing outright) and the "depends on the game / anticheat" conditional flinch.

```
ru  я не могу / не буду / отказываюсь / придётся отказать / смотря какая игра …
en  i can't write / i must decline / as an ai / only from a defensive / depends on the game …
zh  我不能 / 我无法提供 / 我拒绝 / 很抱歉，我不能 / 作为一个AI助手 / 我只能帮助 … / 违反了政策
```

Sentence-level excision splits on CJK punctuation (`。！？；`) as well as Latin terminators, so Chinese refusals embedded in a long answer are cut like any other.

### Vision (images)

SWE-2 is multimodal and the proxy carries images on the wire (`ChatMessagePrompt.images`, field 10, `ImageData{base64Data, mimeType, caption}`). Any of the shapes clients emit is accepted on the way in:

| Client sends | Handled as |
|---|---|
| `{"type":"image_url","image_url":{"url":"data:image/png;base64,…"}}` | inline decode, no fetch |
| `{"type":"image_url","image_url":{"url":"https://…"}}` | fetched, base64-encoded, mime from `Content-Type` |
| `{"type":"image","source":{"media_type":"image/png","data":"…"}}` (Anthropic) | decoded |
| `{"type":"image","data":"…","mimeType":"image/png"}` (omp internal) | decoded |

Images ride the `USER` and `TOOL` message channels, next to any text in the same turn. Oversized payloads are dropped rather than shipped (`JB_SWE_IMG_MAX_BYTES`, default 12 MB) — the upstream rejects the whole turn on a bad image.

### Tool calling

Tools are declared **natively** on the wire (`GetChatMessageRequest.tools`, field 10) and read back from `deltaToolCalls` (response field 6) — Cascade's own function-call channel. The model then returns real tool calls instead of a hand-written marker the server can swallow; the old text-marker protocol produced turns with thinking but no call, which surfaced downstream as *“upstream returned reasoning without an answer”*.

Assistant calls are replayed through `ChatMessagePrompt.toolCalls` (field 6) and tool results through the `TOOL` source (4) with `toolCallId`, so the transcript stays in the same channel the model emitted. Set `JB_SWE_NATIVE_TOOLS=0` to fall back to the text-marker protocol (tool descriptions are then injected into the system prompt, `JB_SWE_TOOL_DESC` choosing the starting rung).

---

## Known limitations

* **SWE-2 is a coding model.** It reasons hard before answering, and some turns come back with thinking but no deliverable content. When every attempt is reasoning-only the proxy emits an explicit note rather than an empty body:
  `[devin-proxy] upstream returned reasoning without an answer (think=…c) — nothing to deliver.`
  Re-send, or raise `JB_DEVIN_MAX_RETRIES`.
* **No continuation-prefill channel.** Unlike the Kimi K3 endpoint, `GetChatMessage` drops a trailing assistant turn. Framing therefore rides the system prompt (field 2) and a mid-history `SYSTEM` turn, not a prefill tail.
* **Tool descriptions are a content-filter surface.** Some declarations come back as a bare `permission_denied` trailer that reads downstream as a silent turn. The proxy walks a ladder — full → compact → names-and-schemas-only — so calls stay callable.
* **localhost only.** There is no authentication on the listener. Do not bind it to a public interface.
* **Reasoning cannot be switched off upstream.** Cascade always thinks. `reasoning_effort: "none"` maps to the cheapest tier plus a suppressed reasoning stream.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `cannot read Devin credentials at …` | run `devin auth login`, or set `JB_SWE_CRED` to the `credentials.toml` path |
| `no windsurf_api_key= entry` | re-run `devin auth login`; the file is stale |
| `[devin-proxy] upstream content policy block` | the tool descriptions tripped the filter — lower `JB_SWE_TOOL_DESC` to `none` |
| Every turn costs 30–60 s | normal for `swe-2-max`; thinking is a 3–4 minute budget when it goes deep |
| Client looks frozen mid-thought | switch to a `stream: true` client; the proxy emits a role-only delta immediately so the UI shows a spinner |
| `bind failed` | port taken — change `JB_SWE_PORT` |

---

## Кратко (RU)

Локальный прокси на `127.0.0.1:8889`, даёт OpenAI-совместимый API поверх бэкенда Devin SWE-2 (`server.codeium.com`, Connect-RPC) и убирает отказы модели: системный оверрайд, категорийные фреймы, невидимые ретраи и детект отказов на **русском / английском / китайском**.

```bash
pip install -r requirements.txt
devin auth login          # создаёт credentials.toml с windsurf_api_key
python swe2_jb_proxy.py
```

В клиенте: `base_url = http://127.0.0.1:8889/v1`, любой ключ, модель `swe-2`.
Оверрайд-промт правится в `prompts/override-compact.txt` без перезапуска.

---

## Credits & license

* Jailbreak prompt lineage: **yuangeluyou.com**
* Protocol reverse engineering, transport and middleware: this repository's authors

MIT — see [LICENSE](LICENSE).

This is a research / red-team tool. It is middleware: it ships no credentials, contacts only the backend you configure, and binds to localhost. You are responsible for how you use it and for the terms of any service you point it at.
