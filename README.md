# openclaw-local-user-sandbox

An OpenClaw sandbox backend (`local-user`) that runs exec and file tools **on the Gateway host as an unprivileged local user**. No Docker, no second machine, no workspace copies.

Community plugin, not affiliated with OpenClaw or Anthropic. Tested on OpenClaw 2026.10.10 (official Docker image, Debian 12) on Railway.

## Why

On hosts without a container runtime (Railway, Render and similar PaaS), the built-in options for keeping tools away from the Gateway's secrets are limited:

- **No sandbox**: `exec` runs as the Gateway user, so it can read the Gateway's environment (`/proc/<pid>/environ`) and state directory, including model API keys and channel tokens.
- **SSH backend**: needs a second host. Its remote workspace becomes the source of truth after the first seed, while bootstrap-file injection and memory search keep reading the host workspace. In our tests, a fact the agent saved to `MEMORY.md` from a sandboxed session never reached later sessions until we added an external sync loop.

This backend keeps the agent workspace where it is and only changes **who** runs the tools.

## How it works

- Registers the sandbox backend `local-user` with `registerSandboxBackend`.
- Uses OpenClaw's own remote-shell backend (`createRemoteShellSandboxBackend` and `createRemoteShellSandboxSession` from `openclaw/plugin-sdk/sandbox`) for file operations, workdir validation, skills and exec staging. The plugin only supplies how one shell command is launched:

  ```
  setpriv --reuid=<uid> --regid=<gid> --clear-groups --no-new-privs -- \
    env -i PATH=... HOME=... LANG=C.UTF-8 /bin/sh -c <command>
  ```

- Sets `preprovisionedWorkdir` to the agent workspace, so nothing is seeded or copied: memory and bootstrap edits made by tools are what the Gateway reads on the next turn.
- The uid needs no `/etc/passwd` entry, so nothing is installed and the container start command stays unchanged.

Each time a sandbox is provisioned the plugin:

1. Refuses to run unless the Gateway is root (switching users needs it).
2. Creates the sandbox `HOME` (mode 700, owned by the sandbox uid) outside the OpenClaw state directory.
3. Hands workspace files that are not owned by the sandbox uid over to it (`chown -h`, symlinks are not followed), so files the Gateway wrote as root stay usable.
4. The first time per workspace, removes group/other access from root-owned OpenClaw directories (state directory, `<state>.update-captures`, the OpenClaw temp/log directory), then runs a self-test **as the sandbox user**: if it can read the Gateway's process environment or any of those directories, or cannot write the workspace, the backend refuses to start.

## Security model

What it blocks (verified on 2026.10.10): reading the Gateway process environment, the OpenClaw state directory (config, credentials, session database), doctor pre-repair captures, and Gateway logs. Commands see only `PATH`, `HOME`, `LANG` plus OpenClaw's own exec variables.

What it does not do:

- It is user separation on one kernel, not a VM or container. A local privilege-escalation bug would cross it.
- Network access is not restricted.
- Other users' processes are visible with `ps` (environments are not).
- World-readable files elsewhere on the host remain readable.
- With `scope: "agent"`, every sandboxed session shares the one agent workspace, so anyone allowed to talk to the agent can read and change its workspace files.

Also set Code Mode to the QuickJS executor. The default Node executor runs guest JavaScript inside the Gateway process and is not a security boundary, even for sandboxed sessions.

## Requirements

- Linux Gateway running as **root** (the official image runs as `node`; on Railway set `RAILWAY_RUN_UID=0`).
- `setpriv` (util-linux), `env`, `/bin/sh`, `python3`, GNU `stat`/`readlink`. All are in the official image.
- `workspaceAccess: "rw"`, or a `sandbox.workspaceRoot` outside the OpenClaw state directory. The default per-session sandbox root lives inside the state directory, which the sandbox user cannot reach.

## Install

```bash
openclaw plugins install <package or npm-pack:path/to/openclaw-local-user-sandbox-0.1.1.tgz> --force --accept-capabilities
```

```json5
{
  agents: {
    defaults: {
      sandbox: { mode: "all", backend: "local-user", scope: "agent", workspaceAccess: "rw" },
    },
  },
  tools: {
    codeMode: { enabled: "auto", executor: "quickjs" },
    // The default sandbox tool policy omits these; add the ones you use.
    sandbox: { tools: { alsoAllow: ["memory_search", "memory_get", "web_search", "web_fetch", "message"] } },
  },
}
```

Check with `openclaw sandbox explain --session <key>`: it should show `backend: local-user` and `runtimeWorkdir: (direct host)`.

## Configuration

`plugins.entries.local-user-sandbox.config`:

| Key | Default | Meaning |
|---|---|---|
| `uid` | `10001` | Numeric uid tools run as. Must not be 0. |
| `gid` | same as `uid` | Numeric gid tools run as. |
| `home` | `/data/.sandbox-home` | `HOME` for sandboxed commands. Must be outside the state directory. |
| `path` | `/usr/local/bin:/usr/bin:/bin` | `PATH` for sandboxed commands. |

## Known limitations

- A standalone CLI process (`openclaw sandbox list`, `openclaw sandbox recreate`) does not load this plugin, so it reports `Sandbox backend "local-user" is unavailable` or shows the runtime as stopped. Nothing is lost: there is no runtime to remove, and removal is a no-op that never touches the workspace.
- The plugin changes ownership of the workspace to the sandbox uid and tightens permissions on the OpenClaw directories listed above. The root Gateway is unaffected.

## Tested

OpenClaw 2026.10.10 on Railway with a Discord channel, Claude Opus and Haiku, Code Mode on QuickJS:

- `id` inside the sandbox: `uid=10001 gid=10001`, working directory `/data/workspace`; environment limited to `HOME LANG OLDPWD OPENCLAW_SHELL PATH PWD`.
- `/proc/1/environ` and the state directory: not readable.
- A fact saved to `MEMORY.md` in one session was in the next session's context with no tools and no sync step.
- A root-owned `0600` file in the workspace was handed over and edited by the agent.
- Directories set to `755` for the test were tightened to `700` and blocked.

## License

MIT
