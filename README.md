# secure-cptr

A security-hardened fork of [Open WebUI Computer](https://github.com/open-webui/computer).

![Open WebUI Computer Demo](./demo.png)

`scptr` runs on your machine and serves your whole computer to any browser:
files, terminal, editor, git, browser tabs, running sessions, AI agents, and
tools. Use it from your phone, tablet, laptop, or the machine it runs on.

Upstream assumed a single trusted operator on a trusted network. This fork
assumes neither. See [Security model](#security-model) for what changed.

---

## Install and run

This fork is **not published to PyPI**. `pip install cptr` installs *upstream*,
which does not contain any of the hardening below. Install from source or use
this fork's own container image.

### From source (recommended)

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/themrsung/secure-cptr.git
cd secure-cptr
uv sync --extra all
uv run scptr run
```

Without uv:

```bash
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install '.[all]'
scptr run
```

The package is named `cptr`; the command it installs is `scptr`.

### Docker

```bash
docker run --rm -it \
  -p 8000:8000 \
  -v cptr-data:/data \
  -v "$PWD:/workspace" \
  -w /workspace \
  ghcr.io/themrsung/secure-cptr:latest
```

`:dev` tracks `main`. Use the `:browser` tag when agent browser automation
needs Chromium. State lives in `/data`; mount your project somewhere like
`/workspace` so the server can reach it. If you bind-mount a host directory to
`/data`, make sure it is writable by the container user — SQLite has to create
and update `/data/app.db`, and host permissions win over the image's.

---

## First run

`scptr run` prints a URL containing a one-time startup token and opens it:

```
  ➜  https://localhost:8000/?token=a1b2c3...
```

That token authorises **first-run setup only**. It is generated fresh on every
start and is not a login. Under Docker, read it from the logs:

```bash
docker logs <container> | grep token=
```

Then, in the browser:

1. **Create the first account.** It becomes superadmin.
2. **Enrol a TOTP authenticator.** Mandatory. The secret and QR code are shown
   **once** and never again — scan or save them before continuing.
3. **Sign in** with the password *and* a six-digit code. A password alone never
   returns a session.

TLS is on by default. If [mkcert](https://github.com/FiloSottile/mkcert) is
installed the certificate is locally trusted and no warning appears; otherwise
it is self-signed and you accept it once.

### Options

| Flag | Default | Meaning |
| --- | --- | --- |
| `--host` | `127.0.0.1` | Bind address. `0.0.0.0` exposes to other devices. |
| `--port` | `8000` | Port to bind. |
| `--no-tls` | off | Serve plain HTTP. Loopback only — warns otherwise. |
| `--cert-host` | — | Extra hostname/IP in the TLS certificate. Repeatable. |
| `--headless` | off | Do not open a browser. |
| `--reload` | off | Auto-reload on code changes (development). |

### Access from another device

```bash
scptr run --host 0.0.0.0 --cert-host 192.168.1.50
```

Then open `https://192.168.1.50:8000` from the other device. Naming the address
in `--cert-host` keeps the certificate valid for it.

Do not pair `--host 0.0.0.0` with `--no-tls`: passwords, session cookies and
terminal output would cross the network in the clear. `scptr` warns if you try.

Not on the same network? Put it behind [Tailscale](https://tailscale.com),
[Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/),
or [ngrok](https://ngrok.com) rather than opening a port.

---

## Security model

This fork tightens the upstream model, which assumed a single trusted operator.

**Two factors, always.** Every account enrols a TOTP authenticator at its first
sign-in; the secret and QR code are shown once and never again. A password on
its own never returns a session. Lost your authenticator? Recover from a shell
on the host, where filesystem access to the database is itself the
authorisation:

```bash
scptr recovery list                 # accounts, roles, second-factor status
scptr recovery reset <username>     # re-enrol at the next sign-in
scptr recovery promote <username>   # break-glass superadmin
scptr recovery capabilities <username> --grant machine --revoke terminal
```

**Encrypted transport.** `scptr run` serves HTTPS and provisions its own
certificate into `~/.cptr/certs`. `--no-tls` exists for loopback development
and warns when bound to anything else.

**Capabilities, not blanket access.** An account holds any combination of three
independent grants, and a new account holds none of them — it can chat and
nothing more.

| Capability | Unlocks |
| --- | --- |
| `terminal` | An interactive shell on the host machine |
| `machine` | Workspaces, files, git, browser control, agent shell tools |
| `external` | Remote MCP and external tool-server connectors |

Admins hold all three implicitly. Grants are read from the database on each
request, so revoking one takes effect in seconds rather than waiting out a
session.

**The terminal costs a second code.** Holding `terminal` only gets you to a
prompt. A valid code opens a 30-minute idle window, refreshed by traffic in
either direction — a long build that keeps printing never locks itself out.
When it lapses the connection closes but the shell keeps running, so nothing
in flight is lost.

**Tiers.** The first account to set the instance up becomes superadmin. Only a
superadmin grants or revokes admin; admins manage everyone else. The last admin
cannot be demoted or deleted, and if the admin tier ever shrinks to one account
that account is promoted to superadmin automatically.

**Secrets at rest.** `~/.cptr/` is created `0700` and `config.toml`, `app.db`
and the logs `0600`. Provider API keys are encrypted before storage. Note that
`config.toml` holds the server secret that those keys are derived from, so the
file permissions are what actually protect them — keep the data directory off
shared storage.

**Audit logging.** Off by default. `CPTR_AUDIT_LOG_LEVEL=REQUEST_RESPONSE`
records request and response bodies with sensitive fields redacted; uploaded
file bodies are never copied into the log.

What has *not* changed: an account with `machine` or `terminal` still has real
reach into the host, with no path sandboxing. Grant those deliberately.

---

## What you get

**The machine.** Files (navigate, edit, upload, drag and drop), a
syntax-highlighted editor with tabs, git staging/commit/diff/branch/push, a
full shell in the browser, browser tabs via proxy or managed Chrome, and
search across names and contents. Terminal sessions keep running when you close
the tab. Multiple workspaces, one instance. Built for a phone first.

**AI agent.** Bring your own API key (OpenAI, Anthropic, Ollama, or any
OpenAI-compatible endpoint), or connect a coding agent you already subscribe to
— Codex, Claude Code, Cursor, Grok, OpenCode, Cline, Gemini, Pi. It reads the
workspace, edits files, runs commands, browses, searches the web, uses MCP and
OpenAPI tool servers, schedules recurring work, and spawns parallel sub-agents.
Voice mode, text-to-speech, reasoning traces, plan mode, skills (`SKILL.md`),
`@` file mentions, and context compaction are all included.

**Messaging bots.** Telegram, Discord, Slack, WhatsApp, Signal — full tool
access, streaming replies, synced back to the web UI. `/workspace` switches,
`/new` starts fresh.

**Gateway API.** Each workspace is exposed as an OpenAI-compatible model at
`/v1/chat/completions`, authenticated with a bearer API key you mint in
Settings. Any OpenAI client can drive a workspace with full agent capabilities.

The UI ships in English (en-US) only; other locale bundles were removed.

---

## Development

```bash
./dev.sh
```

Runs with `--reload` on port 9741, headless, with the data directory pinned to
`./.cptr` so it never touches your real `~/.cptr`.

Tests:

```bash
uv run pytest tests/ -q
```

`tests/test_security.py` and `tests/test_exfiltration.py` cover the auth,
capability and credential-handling behaviour described above. Both also run
standalone under plain `python3` if pytest is unavailable.

---

## Air-gapped installation

No internet access is needed after install. On a connected machine:

```bash
docker pull ghcr.io/themrsung/secure-cptr:latest
docker save ghcr.io/themrsung/secure-cptr:latest -o secure-cptr.tar
```

Transfer it, then run offline:

```bash
docker load -i secure-cptr.tar
docker run --rm -it \
  --network=none \
  -p 8000:8000 \
  -v cptr-data:/data \
  -v "$PWD:/workspace" \
  -w /workspace \
  ghcr.io/themrsung/secure-cptr:latest
```

From source, vendor the wheels on a connected machine with
`uv export > requirements.txt && pip download -r requirements.txt -d wheelhouse`,
then `pip install --no-index --find-links ./wheelhouse '.[all]'`.

Core local features run from local assets. External services — hosted model
APIs, web search providers, messaging adapters, git remotes, MCP/OpenAPI
servers — still need reachable endpoints.

---

## Notes

On Windows, if opening a terminal reports a missing `VCRUNTIME140.dll` or
Universal CRT DLL, install Microsoft's
[Visual C++ Redistributable](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist)
and restart `scptr`.

To reach a host-running OpenCode server from Docker:

```bash
opencode serve --hostname 0.0.0.0 --port 4096
```

Use `http://host.docker.internal:4096` as the agent Server URL. On Linux add
`--add-host=host.docker.internal:host-gateway` to `docker run`.

Read the [Manifesto](MANIFESTO.md).

---

## License

Open Use License. Source available. All rights reserved. See [LICENSE](LICENSE).
[Commercial licenses](https://openwebui.com/computer/license) and
[enterprise licenses](mailto:sales@openwebui.com) available.

Upstream project: [open-webui/computer](https://github.com/open-webui/computer)
· [docs](https://docs.openwebui.com/ecosystem/computer/)
